use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{error, info, warn};

use crate::config::ServeConfig;
use crate::mastodon::MastodonClient;
use crate::slack::{
    ButtonValue, DELETE_ACTION_ID, SUSPEND_ACTION_ID, TEXT_MAX_CHARS, delete_actions_block,
    truncate_chars,
};

/// Maximum allowed clock skew for Slack request timestamps (replay attack prevention).
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
/// Maximum time to wait for in-flight suspend tasks during shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

struct AppState {
    mastodon: MastodonClient,
    signing_secret: String,
    http: reqwest::Client,
    /// Account IDs currently being processed (prevents double-clicks and allows graceful shutdown).
    in_flight: Mutex<HashSet<String>>,
    note_writer: Option<crate::postgres::ModerationNoteWriter>,
}

impl AppState {
    /// Acquires the in_flight lock. Even if the lock is poisoned (panic while held),
    /// the HashSet remains consistent, so recover and continue rather than propagating the panic.
    fn lock_in_flight(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

enum ButtonAction {
    Suspend,
    Delete,
}

struct Interaction {
    kind: ButtonAction,
    value: ButtonValue,
    /// Raw JSON string of the button value, passed through unchanged when replacing with the delete button.
    raw_value: String,
    user_id: String,
    response_url: String,
    /// Blocks from the original message, used to insert the result and call replace_original.
    blocks: Vec<Value>,
}

pub async fn run(config: ServeConfig) -> Result<()> {
    let mastodon = MastodonClient::new(&config.mastodon_base_url, &config.mastodon_access_token);

    let note_writer = match config.postgres {
        Some(ref pg) => Some(
            crate::postgres::ModerationNoteWriter::connect(
                &pg.database_url,
                pg.moderator_account_id,
            )
            .await?,
        ),
        None => None,
    };

    let state = Arc::new(AppState {
        http: mastodon.http_client(),
        mastodon,
        signing_secret: config.slack_signing_secret,
        in_flight: Mutex::new(HashSet::new()),
        note_writer,
    });

    let app = Router::new()
        .route("/slack/interactions", post(handle_interaction))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind to {}", config.listen_addr))?;
    info!(addr = %config.listen_addr, "Slack interaction server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Wait for in-flight suspend tasks to finish before exiting, so we don't terminate
    // while Mastodon is suspended but the Slack message is not yet updated.
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while !state.lock_in_flight().is_empty() {
        if Instant::now() >= deadline {
            warn!("shutting down with suspend tasks still in flight");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

async fn shutdown_signal() {
    // If SIGTERM handler registration fails, do not panic the server; fall back to Ctrl-C only.
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to install SIGTERM handler, falling back to Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    info!("shutdown signal received");
}

async fn handle_interaction(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if let Err(e) = verify_signature(&state.signing_secret, &headers, &body) {
        warn!(error = %e, "signature verification failed, rejecting request");
        return StatusCode::UNAUTHORIZED;
    }

    let interaction = match parse_payload(&body).and_then(extract_interaction) {
        Ok(Some(i)) => i,
        // Acknowledge and ignore unrecognised events or buttons.
        Ok(None) => return StatusCode::OK,
        Err(e) => {
            warn!(error = %e, "invalid interaction payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    if !state.lock_in_flight().insert(interaction.value.id.clone()) {
        info!(account_id = %interaction.value.id, "action already in progress, ignoring click");
        return StatusCode::OK;
    }

    // Slack requires a response within 3 seconds, so spawn the real work and return 200 immediately.
    tokio::spawn(process_action(state, interaction));

    StatusCode::OK
}

/// Extracts the target button action from a block_actions payload.
/// Returns Ok(None) for unrecognised events or buttons; Err for missing or malformed required fields.
fn extract_interaction(mut payload: Value) -> Result<Option<Interaction>> {
    if payload["type"] != "block_actions" {
        return Ok(None);
    }

    let Some((kind, action)) = payload["actions"].as_array().and_then(|arr| {
        arr.iter().find_map(|a| {
            let kind = match a["action_id"].as_str()? {
                SUSPEND_ACTION_ID => ButtonAction::Suspend,
                DELETE_ACTION_ID => ButtonAction::Delete,
                _ => return None,
            };
            Some((kind, a))
        })
    }) else {
        return Ok(None);
    };

    let raw_value = action["value"]
        .as_str()
        .map(String::from)
        .context("action has no value")?;
    let value: ButtonValue = serde_json::from_str(&raw_value).context("invalid button value")?;

    // Mastodon account IDs are numeric only. Validate before embedding in URL paths
    // to ensure a tampered value cannot be routed to a different endpoint.
    if value.id.is_empty() || !value.id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("account id is not numeric: {}", value.id);
    }

    let response_url = payload["response_url"]
        .as_str()
        .map(String::from)
        .context("payload has no response_url")?;
    let user_id = payload["user"]["id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let mut blocks: Vec<Value> = payload
        .get_mut("message")
        .and_then(|m| m.get_mut("blocks"))
        .map(Value::take)
        .and_then(|b| match b {
            Value::Array(blocks) => Some(blocks),
            _ => None,
        })
        .unwrap_or_default();
    // If blocks are missing, restore the original notification content from text
    // so replace_original does not blank the entire message.
    if blocks.is_empty()
        && let Some(text) = payload["message"]["text"]
            .as_str()
            .filter(|t| !t.is_empty())
    {
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": text }
        }));
    }

    Ok(Some(Interaction {
        kind,
        value,
        raw_value,
        user_id,
        response_url,
        blocks,
    }))
}

/// Calls the appropriate Mastodon API for the button action and updates the Slack message via response_url.
async fn process_action(state: Arc<AppState>, interaction: Interaction) {
    let Interaction {
        kind,
        value,
        raw_value,
        user_id,
        response_url,
        mut blocks,
    } = interaction;

    // Remove any previous context blocks that would accumulate unboundedly on retries.
    // On success, each branch also removes or replaces the button to prevent re-execution (left on failure to allow retry).
    blocks.retain(|b| b["type"] != "context");

    let result_text = match kind {
        ButtonAction::Suspend => {
            // If already suspended (e.g. via manual action or a button on another notification),
            // skip the suspend API call, show a notice, and replace the button with the delete button.
            // A failed check does not block suspension (the suspend API is idempotent).
            let already_suspended = match state.mastodon.is_account_suspended(&value.id).await {
                Ok(suspended) => suspended,
                Err(e) => {
                    warn!(account_id = %value.id, error = %e, "failed to check suspension state, proceeding to suspend");
                    false
                }
            };

            if already_suspended {
                info!(account_id = %value.id, acct = %value.acct, "account already suspended, skipping");
                replace_buttons_with_delete(&mut blocks, &raw_value, &value.acct);
                format!(":information_source: `{}` は既に停止済みです", value.acct)
            } else {
                match state.mastodon.suspend_account(&value.id).await {
                    Ok(()) => {
                        info!(account_id = %value.id, acct = %value.acct, "account suspended");
                        replace_buttons_with_delete(&mut blocks, &raw_value, &value.acct);
                        if let Some(ref writer) = state.note_writer {
                            let note = format!(
                                "[Mastodon Spam Checker] Slack 経由でアカウントを停止 (操作者: <@{}>)",
                                user_id,
                            );
                            if let Err(e) = writer.add_note(&value.id, &note).await {
                                error!(error = %e, "failed to add moderation note");
                            }
                        }
                        format!(
                            ":white_check_mark: <@{user_id}> が `{}` を停止しました",
                            value.acct
                        )
                    }
                    Err(e) => {
                        error!(account_id = %value.id, error = %e, "failed to suspend account");
                        format!(":x: `{}` の停止に失敗しました: {e}", value.acct)
                    }
                }
            }
        }
        // Deletion is irreversible, so do not rely solely on the button being present in the Slack message;
        // verify server-side that the account is suspended before proceeding.
        // This guards against a stale button being clicked after the suspension was manually lifted.
        ButtonAction::Delete => match state.mastodon.is_account_suspended(&value.id).await {
            Ok(true) => match state.mastodon.delete_account(&value.id).await {
                Ok(()) => {
                    info!(account_id = %value.id, acct = %value.acct, "account data deleted");
                    blocks.retain(|b| b["type"] != "actions");
                    format!(
                        ":wastebasket: <@{user_id}> が `{}` のデータを削除しました",
                        value.acct
                    )
                }
                Err(e) => {
                    error!(account_id = %value.id, error = %e, "failed to delete account");
                    format!(":x: `{}` の削除に失敗しました: {e}", value.acct)
                }
            },
            Ok(false) => {
                warn!(account_id = %value.id, "account is not suspended, refusing to delete");
                format!(
                    ":x: `{}` は停止されていないため削除を中止しました(停止が解除された可能性があります)",
                    value.acct
                )
            }
            Err(e) => {
                error!(account_id = %value.id, error = %e, "failed to check suspension state, aborting delete");
                format!(
                    ":x: `{}` の停止状態を確認できなかったため削除を中止しました: {e}",
                    value.acct
                )
            }
        },
    };

    blocks.push(context_block(&result_text));
    let update = json!({
        "replace_original": true,
        "text": result_text,
        "blocks": blocks,
    });
    post_to_slack(&state.http, &response_url, &update).await;

    state.lock_in_flight().remove(&value.id);
}

fn replace_buttons_with_delete(blocks: &mut Vec<Value>, value_json: &str, acct: &str) {
    blocks.retain(|b| b["type"] != "actions");
    blocks.push(delete_actions_block(value_json, acct));
}

fn context_block(text: &str) -> Value {
    json!({
        "type": "context",
        // Truncate to avoid invalid_blocks errors when Mastodon error bodies or other content
        // would exceed the limit and cause the entire update to be silently dropped.
        "elements": [{ "type": "mrkdwn", "text": truncate_chars(text, TEXT_MAX_CHARS) }]
    })
}

async fn post_to_slack(http: &reqwest::Client, url: &str, payload: &Value) {
    match http.post(url).json(payload).send().await {
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            error!(%status, body = %body, "failed to update Slack message");
        }
        Ok(_) => {}
        Err(e) => error!(error = %e, "Slack message update request failed"),
    }
}

fn parse_payload(body: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    struct Form {
        payload: String,
    }
    let form: Form = serde_urlencoded::from_bytes(body).context("failed to parse form body")?;
    serde_json::from_str(&form.payload).context("failed to parse payload JSON")
}

/// Verifies a Slack request signature (v0=HMAC-SHA256).
/// https://api.slack.com/authentication/verifying-requests-from-slack
fn verify_signature(secret: &str, headers: &HeaderMap, body: &[u8]) -> Result<()> {
    let timestamp = headers
        .get("x-slack-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .context("missing X-Slack-Request-Timestamp header")?;
    let signature = headers
        .get("x-slack-signature")
        .and_then(|v| v.to_str().ok())
        .context("missing X-Slack-Signature header")?;

    let ts: i64 = timestamp.parse().context("timestamp is not a number")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?
        .as_secs() as i64;
    if (now - ts).abs() > MAX_TIMESTAMP_SKEW_SECS {
        bail!("timestamp outside allowed window (possible replay)");
    }

    let sig = signature
        .strip_prefix("v0=")
        .and_then(hex_decode)
        .context("malformed signature")?;

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut base = format!("v0:{timestamp}:").into_bytes();
    base.extend_from_slice(body);

    // ring::hmac::verify performs a constant-time comparison.
    ring::hmac::verify(&key, &base, &sig).map_err(|_| anyhow!("signature mismatch"))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|c| Some(val(c[0])? << 4 | val(c[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let mut base = format!("v0:{timestamp}:").into_bytes();
        base.extend_from_slice(body);
        let hex: String = ring::hmac::sign(&key, &base)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("v0={hex}")
    }

    fn headers(timestamp: &str, signature: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-slack-request-timestamp", timestamp.parse().unwrap());
        h.insert("x-slack-signature", signature.parse().unwrap());
        h
    }

    fn now_ts() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[test]
    fn valid_signature_is_accepted() {
        let ts = now_ts();
        let body = b"payload=%7B%7D";
        let sig = sign("secret", &ts, body);
        assert!(verify_signature("secret", &headers(&ts, &sig), body).is_ok());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let ts = now_ts();
        let body = b"payload=%7B%7D";
        let sig = sign("other-secret", &ts, body);
        assert!(verify_signature("secret", &headers(&ts, &sig), body).is_err());
    }

    #[test]
    fn tampered_body_is_rejected() {
        let ts = now_ts();
        let sig = sign("secret", &ts, b"payload=%7B%7D");
        assert!(verify_signature("secret", &headers(&ts, &sig), b"payload=evil").is_err());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let ts = "1000000000"; // year 2001
        let body = b"payload=%7B%7D";
        let sig = sign("secret", ts, body);
        assert!(verify_signature("secret", &headers(ts, &sig), body).is_err());
    }

    #[test]
    fn payload_form_is_parsed() {
        let body = b"payload=%7B%22type%22%3A%22block_actions%22%7D";
        let v = parse_payload(body).unwrap();
        assert_eq!(v["type"], "block_actions");
    }

    #[test]
    fn interaction_is_extracted_from_suspend_click() {
        let payload = json!({
            "type": "block_actions",
            "response_url": "https://hooks.slack.com/actions/xxx",
            "user": { "id": "U123" },
            "message": {
                "text": "notice",
                "blocks": [{ "type": "section" }]
            },
            "actions": [{
                "action_id": SUSPEND_ACTION_ID,
                "value": r#"{"id":"42","acct":"alice@example.com"}"#
            }]
        });
        let i = extract_interaction(payload).unwrap().unwrap();
        assert!(matches!(i.kind, ButtonAction::Suspend));
        assert_eq!(i.value.id, "42");
        assert_eq!(i.value.acct, "alice@example.com");
        assert_eq!(i.raw_value, r#"{"id":"42","acct":"alice@example.com"}"#);
        assert_eq!(i.user_id, "U123");
        assert_eq!(i.response_url, "https://hooks.slack.com/actions/xxx");
        assert_eq!(i.blocks.len(), 1);
    }

    #[test]
    fn unrelated_events_and_buttons_are_ignored() {
        let none = extract_interaction(json!({ "type": "view_submission" })).unwrap();
        assert!(none.is_none());

        let payload = json!({
            "type": "block_actions",
            "actions": [{ "action_id": "other_button", "value": "{}" }]
        });
        assert!(extract_interaction(payload).unwrap().is_none());
    }

    #[test]
    fn non_numeric_account_id_is_rejected() {
        let payload = json!({
            "type": "block_actions",
            "response_url": "https://hooks.slack.com/actions/xxx",
            "actions": [{
                "action_id": SUSPEND_ACTION_ID,
                "value": r#"{"id":"42/action","acct":"alice@example.com"}"#
            }]
        });
        assert!(extract_interaction(payload).is_err());
    }

    #[test]
    fn missing_blocks_are_restored_from_text() {
        let payload = json!({
            "type": "block_actions",
            "response_url": "https://hooks.slack.com/actions/xxx",
            "user": { "id": "U1" },
            "message": { "text": "original notice" },
            "actions": [{
                "action_id": DELETE_ACTION_ID,
                "value": r#"{"id":"7","acct":"bob@example.com"}"#
            }]
        });
        let i = extract_interaction(payload).unwrap().unwrap();
        assert!(matches!(i.kind, ButtonAction::Delete));
        assert_eq!(i.blocks.len(), 1);
        assert_eq!(i.blocks[0]["text"]["text"], "original notice");
    }
}
