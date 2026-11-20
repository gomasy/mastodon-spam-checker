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

use rust_i18n::t;

use crate::chain;
use crate::config::ServeConfig;
use crate::ids::is_numeric_id;
use crate::mastodon::MastodonClient;
use crate::postgres::{self, ModerationAction, ModerationNoteWriter};
use crate::redis::{JobStatus, StateStore};
use crate::slack::{
    ButtonValue, CONFIRM_SPAM_ACTION_ID, DELETE_ACTION_ID, FALSE_POSITIVE_ACTION_ID,
    SUSPEND_ACTION_ID, TEXT_MAX_CHARS, delete_actions_block, sanitize_mrkdwn, truncate_mrkdwn,
};

/// Replay protection window for Slack request timestamps.
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

struct AppState {
    mastodon: MastodonClient,
    signing_secret: String,
    http: reqwest::Client,
    in_flight: Arc<InFlight>,
    note_writer: Option<ModerationNoteWriter>,
    store: StateStore,
}

/// Accounts whose button click is still being handled.
#[derive(Default)]
struct InFlight(Mutex<HashSet<String>>);

impl InFlight {
    /// A poisoned set is still consistent, so the poison is ignored.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Claims `account_id` until the guard drops, or `None` if it is already claimed.
    fn claim(self: &Arc<Self>, account_id: &str) -> Option<InFlightGuard> {
        self.lock()
            .insert(account_id.to_string())
            .then(|| InFlightGuard {
                in_flight: Arc::clone(self),
                account_id: account_id.to_string(),
            })
    }
}

struct InFlightGuard {
    in_flight: Arc<InFlight>,
    account_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.in_flight.lock().remove(&self.account_id);
    }
}

enum ButtonAction {
    Suspend,
    Delete,
    ConfirmSpam,
    FalsePositive,
}

struct Interaction {
    kind: ButtonAction,
    value: ButtonValue,
    /// Carried unchanged into the delete button.
    raw_value: String,
    user_id: String,
    response_url: String,
    /// The original message's blocks, edited and sent back with `replace_original`.
    blocks: Vec<Value>,
}

pub async fn run(config: ServeConfig) -> Result<()> {
    let mastodon = MastodonClient::new(&config.mastodon_base_url, &config.mastodon_access_token)?;
    let note_writer = postgres::writer_for(config.postgres.as_ref()).await?;
    let state = Arc::new(AppState {
        http: mastodon.http_client(),
        mastodon,
        signing_secret: config.slack_signing_secret,
        in_flight: Arc::new(InFlight::default()),
        note_writer,
        store: StateStore::new(&config.redis_url).await?,
    });

    let app = Router::new()
        .route("/slack/interactions", post(handle_interaction))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("failed to bind to {}", config.listen_addr))?;
    info!(addr = %config.listen_addr, "Slack interaction server listening");

    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    // Drained even on error, so a suspension is not left unreported in Slack.
    drain_in_flight(&state.in_flight).await;
    served.context("Slack interaction server failed")
}

async fn drain_in_flight(in_flight: &InFlight) {
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while !in_flight.is_empty() {
        if Instant::now() >= deadline {
            warn!("shutting down with suspend tasks still in flight");
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn shutdown_signal() {
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
        warn!(error = %chain(&e), "signature verification failed, rejecting request");
        return StatusCode::UNAUTHORIZED;
    }

    let interaction = match parse_payload(&body).and_then(extract_interaction) {
        Ok(Some(i)) => i,
        Ok(None) => return StatusCode::OK,
        Err(e) => {
            warn!(error = %chain(&e), "invalid interaction payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    let Some(guard) = state.in_flight.claim(&interaction.value.id) else {
        info!(account_id = %interaction.value.id, "action already in progress, ignoring click");
        return StatusCode::OK;
    };

    // Slack expects a response within 3 seconds.
    tokio::spawn(process_action(state, interaction, guard));

    StatusCode::OK
}

/// `Ok(None)` for events or buttons this server does not handle.
fn extract_interaction(mut payload: Value) -> Result<Option<Interaction>> {
    if payload["type"] != "block_actions" {
        return Ok(None);
    }

    let Some((kind, action)) = payload["actions"].as_array().and_then(|arr| {
        arr.iter().find_map(|a| {
            let kind = match a["action_id"].as_str()? {
                SUSPEND_ACTION_ID => ButtonAction::Suspend,
                DELETE_ACTION_ID => ButtonAction::Delete,
                CONFIRM_SPAM_ACTION_ID => ButtonAction::ConfirmSpam,
                FALSE_POSITIVE_ACTION_ID => ButtonAction::FalsePositive,
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

    if !is_numeric_id(&value.id) {
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
    // Rebuilt from the text so `replace_original` does not blank the message.
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

struct ActionContext<'a> {
    state: &'a AppState,
    value: &'a ButtonValue,
    raw_value: &'a str,
    user_id: &'a str,
    /// Already sanitized.
    safe_acct: &'a str,
    blocks: &'a mut Vec<Value>,
}

impl ActionContext<'_> {
    /// Refuses a destructive action on an account marked false positive, or whose feedback cannot
    /// be read. Returns the message to show, or `None` to proceed.
    async fn refuse_if_cleared(
        &mut self,
        refused_key: &str,
        check_failed_key: &str,
    ) -> Option<String> {
        match self.state.store.is_false_positive(&self.value.id).await {
            Ok(false) => None,
            Ok(true) => {
                warn!(account_id = %self.value.id, refusal = refused_key, "refusing to act on an account marked as a false positive");
                remove_actions(self.blocks);
                Some(t!(refused_key, acct = self.safe_acct).to_string())
            }
            Err(e) => {
                error!(account_id = %self.value.id, error = %chain(&e), "failed to check moderator feedback");
                Some(failure_message(check_failed_key, self.safe_acct, &e))
            }
        }
    }

    /// Logged on failure: the Mastodon action already happened and must still be reported.
    async fn record_action(&self, status: JobStatus) {
        if let Err(e) = self.state.store.record_action(&self.value.id, status).await {
            error!(account_id = %self.value.id, error = %chain(&e), status = status.as_str(), "failed to record moderation action");
        }
    }
}

/// Runs the action and rewrites the Slack message, holding the in-flight claim throughout.
async fn process_action(state: Arc<AppState>, interaction: Interaction, _guard: InFlightGuard) {
    let Interaction {
        kind,
        value,
        raw_value,
        user_id,
        response_url,
        mut blocks,
    } = interaction;
    let safe_acct = sanitize_mrkdwn(&value.acct);

    // Drop earlier results; buttons are removed only on success so failures can be retried.
    blocks.retain(|b| b["type"] != "context");

    let mut ctx = ActionContext {
        state: &state,
        value: &value,
        raw_value: &raw_value,
        user_id: &user_id,
        safe_acct: &safe_acct,
        blocks: &mut blocks,
    };

    let result_text = match kind {
        ButtonAction::Suspend => handle_suspend(&mut ctx).await,
        ButtonAction::Delete => handle_delete(&mut ctx).await,
        ButtonAction::ConfirmSpam => handle_confirm_spam(&mut ctx).await,
        ButtonAction::FalsePositive => handle_false_positive(&mut ctx).await,
    };

    blocks.push(context_block(&result_text));
    let update = json!({
        "replace_original": true,
        "text": result_text,
        "blocks": blocks,
    });
    post_to_slack(&state.http, &response_url, &update).await;
}

async fn handle_suspend(ctx: &mut ActionContext<'_>) -> String {
    if let Some(refusal) = ctx
        .refuse_if_cleared("suspend_refused_false_positive", "feedback_check_failed")
        .await
    {
        return refusal;
    }

    // A failed check falls through to the suspend call, which is idempotent.
    let already_suspended = match ctx.state.mastodon.is_account_suspended(&ctx.value.id).await {
        Ok(suspended) => suspended,
        Err(e) => {
            warn!(account_id = %ctx.value.id, error = %chain(&e), "failed to check suspension state, proceeding to suspend");
            false
        }
    };

    if already_suspended {
        info!(account_id = %ctx.value.id, acct = %ctx.value.acct, "account already suspended, skipping");
        ctx.record_action(JobStatus::Suspended).await;
        replace_buttons_with_delete(ctx.blocks, ctx.raw_value, ctx.safe_acct);
        return t!("already_suspended", acct = ctx.safe_acct).to_string();
    }

    match ctx.state.mastodon.suspend_account(&ctx.value.id).await {
        Ok(()) => {
            info!(account_id = %ctx.value.id, acct = %ctx.value.acct, "account suspended");
            ctx.record_action(JobStatus::Suspended).await;
            replace_buttons_with_delete(ctx.blocks, ctx.raw_value, ctx.safe_acct);
            let note = t!("note_suspended", user_id = ctx.user_id);
            postgres::after_action(
                ctx.state.note_writer.as_ref(),
                ModerationAction::Suspend,
                &ctx.value.id,
                Some(&note),
            )
            .await;
            t!("suspended", user_id = ctx.user_id, acct = ctx.safe_acct).to_string()
        }
        Err(e) => {
            error!(account_id = %ctx.value.id, error = %chain(&e), "failed to suspend account");
            failure_message("suspend_failed", ctx.safe_acct, &e)
        }
    }
}

/// Re-checks the suspension first, in case it was lifted after the message was sent.
async fn handle_delete(ctx: &mut ActionContext<'_>) -> String {
    if let Some(refusal) = ctx
        .refuse_if_cleared(
            "delete_refused_false_positive",
            "feedback_check_failed_delete",
        )
        .await
    {
        return refusal;
    }

    match ctx.state.mastodon.is_account_suspended(&ctx.value.id).await {
        Ok(false) => {
            warn!(account_id = %ctx.value.id, "account is not suspended, refusing to delete");
            return t!("not_suspended", acct = ctx.safe_acct).to_string();
        }
        Err(e) => {
            error!(account_id = %ctx.value.id, error = %chain(&e), "failed to check suspension state, aborting delete");
            return failure_message("check_failed", ctx.safe_acct, &e);
        }
        Ok(true) => {}
    }

    match ctx.state.mastodon.delete_account(&ctx.value.id).await {
        Ok(()) => {
            info!(account_id = %ctx.value.id, acct = %ctx.value.acct, "account data deleted");
            ctx.record_action(JobStatus::Deleted).await;
            remove_actions(ctx.blocks);
            postgres::after_action(
                ctx.state.note_writer.as_ref(),
                ModerationAction::Delete,
                &ctx.value.id,
                None,
            )
            .await;
            t!("deleted", user_id = ctx.user_id, acct = ctx.safe_acct).to_string()
        }
        Err(e) => {
            error!(account_id = %ctx.value.id, error = %chain(&e), "failed to delete account");
            failure_message("delete_failed", ctx.safe_acct, &e)
        }
    }
}

async fn handle_confirm_spam(ctx: &mut ActionContext<'_>) -> String {
    apply_feedback(
        ctx,
        JobStatus::ConfirmedSpam,
        "feedback_confirmed",
        remove_feedback_buttons,
    )
    .await
}

async fn handle_false_positive(ctx: &mut ActionContext<'_>) -> String {
    apply_feedback(
        ctx,
        JobStatus::FalsePositive,
        "feedback_false_positive",
        remove_actions,
    )
    .await
}

/// Records a moderator's verdict; `prune_buttons` drops the buttons it made meaningless.
async fn apply_feedback(
    ctx: &mut ActionContext<'_>,
    status: JobStatus,
    success_key: &str,
    prune_buttons: fn(&mut Vec<Value>),
) -> String {
    match ctx
        .state
        .store
        .record_feedback(&ctx.value.id, status, ctx.user_id)
        .await
    {
        Ok(replaced) => {
            match replaced.filter(|replaced| *replaced != status) {
                Some(replaced) => {
                    warn!(account_id = %ctx.value.id, user_id = %ctx.user_id, verdict = status.as_str(), replaced = replaced.as_str(), "moderator feedback recorded, reversing an earlier verdict");
                }
                None => {
                    info!(account_id = %ctx.value.id, user_id = %ctx.user_id, verdict = status.as_str(), "moderator feedback recorded");
                }
            }
            prune_buttons(ctx.blocks);
            t!(success_key, user_id = ctx.user_id, acct = ctx.safe_acct).to_string()
        }
        Err(e) => {
            error!(account_id = %ctx.value.id, error = %chain(&e), verdict = status.as_str(), "failed to record moderator feedback");
            failure_message("feedback_failed", ctx.safe_acct, &e)
        }
    }
}

/// `safe_acct` must already be sanitized; the error is sanitized here.
fn failure_message(key: &str, safe_acct: &str, error: &anyhow::Error) -> String {
    t!(
        key,
        acct = safe_acct,
        error = sanitize_mrkdwn(&chain(error))
    )
    .to_string()
}

fn remove_actions(blocks: &mut Vec<Value>) {
    blocks.retain(|block| block["type"] != "actions");
}

fn replace_buttons_with_delete(blocks: &mut Vec<Value>, value_json: &str, safe_acct: &str) {
    remove_actions(blocks);
    blocks.push(delete_actions_block(value_json, safe_acct));
}

fn remove_feedback_buttons(blocks: &mut Vec<Value>) {
    blocks.retain_mut(|block| {
        let is_actions = block["type"] == "actions";
        // Not `block["elements"]`: mutable indexing would insert a null, which Slack rejects.
        let Some(elements) = block.get_mut("elements").and_then(Value::as_array_mut) else {
            return true;
        };
        elements.retain(|element| {
            !matches!(
                element["action_id"].as_str(),
                Some(CONFIRM_SPAM_ACTION_ID | FALSE_POSITIVE_ACTION_ID)
            )
        });
        // Slack also rejects an empty actions block.
        !is_actions || !elements.is_empty()
    });
}

fn context_block(text: &str) -> Value {
    json!({
        "type": "context",
        "elements": [{ "type": "mrkdwn", "text": truncate_mrkdwn(text, TEXT_MAX_CHARS) }]
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

/// <https://api.slack.com/authentication/verifying-requests-from-slack>
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
    // Saturating: `ts` is attacker-supplied.
    if now.saturating_sub(ts).saturating_abs() > MAX_TIMESTAMP_SKEW_SECS {
        bail!("timestamp outside allowed window (possible replay)");
    }

    let sig = signature
        .strip_prefix("v0=")
        .and_then(hex_decode)
        .context("malformed signature")?;

    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut base = format!("v0:{timestamp}:").into_bytes();
    base.extend_from_slice(body);
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
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if pairs.is_empty() || !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[hi, lo]| Some(val(hi)? << 4 | val(lo)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    fn sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let mut base = format!("v0:{timestamp}:").into_bytes();
        base.extend_from_slice(body);
        let hex =
            ring::hmac::sign(&key, &base)
                .as_ref()
                .iter()
                .fold(String::new(), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                });
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
    fn locale_keys_passed_as_variables_still_resolve() {
        // Checked via interpolation so the test is locale-independent.
        for key in [
            "feedback_confirmed",
            "feedback_false_positive",
            "suspend_refused_false_positive",
            "delete_refused_false_positive",
        ] {
            let rendered = t!(key, user_id = "U1", acct = "alice@example.com").to_string();
            assert!(rendered.contains("alice@example.com"), "{key}: {rendered}");
        }
        for key in [
            "feedback_failed",
            "feedback_check_failed",
            "feedback_check_failed_delete",
        ] {
            let rendered = t!(key, acct = "alice@example.com", error = "boom").to_string();
            assert!(rendered.contains("alice@example.com"), "{key}: {rendered}");
            assert!(rendered.contains("boom"), "{key}: {rendered}");
        }
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
    fn extreme_timestamps_are_rejected_without_overflow() {
        let body = b"payload=%7B%7D";
        for ts in [i64::MIN.to_string(), i64::MAX.to_string()] {
            let sig = sign("secret", &ts, body);
            assert!(
                verify_signature("secret", &headers(&ts, &sig), body).is_err(),
                "accepted timestamp {ts}"
            );
        }
    }

    #[test]
    fn hex_decode_accepts_only_even_length_hex() {
        assert_eq!(hex_decode("0a_FF"), None);
        assert_eq!(hex_decode("0aFF"), Some(vec![0x0a, 0xff]));
        assert_eq!(hex_decode(""), None);
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("f"), None);
        assert_eq!(hex_decode("zz"), None);
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
    fn feedback_interaction_is_extracted() {
        let payload = json!({
            "type": "block_actions",
            "response_url": "https://hooks.slack.com/actions/xxx",
            "user": { "id": "U123" },
            "message": { "blocks": [{ "type": "actions" }] },
            "actions": [{
                "action_id": FALSE_POSITIVE_ACTION_ID,
                "value": r#"{"id":"42","acct":"alice@example.com"}"#
            }]
        });
        let interaction = extract_interaction(payload).unwrap().unwrap();
        assert!(matches!(interaction.kind, ButtonAction::FalsePositive));
        assert_eq!(interaction.value.id, "42");
        assert_eq!(interaction.user_id, "U123");
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
    fn a_second_click_is_rejected_while_the_first_is_in_flight() {
        let in_flight = Arc::new(InFlight::default());
        let first = in_flight
            .claim("42")
            .expect("first click claims the account");
        assert!(
            in_flight.claim("42").is_none(),
            "double-click was not rejected"
        );
        // A different account is unaffected.
        let other = in_flight.claim("43");
        assert!(other.is_some());

        drop(first);
        assert!(
            in_flight.claim("42").is_some(),
            "claim was not released when the guard dropped"
        );
    }

    #[test]
    fn a_panicking_action_still_releases_its_claim() {
        let in_flight = Arc::new(InFlight::default());
        let panicked = std::panic::catch_unwind({
            let in_flight = Arc::clone(&in_flight);
            move || {
                let _guard = in_flight.claim("42").expect("claim");
                panic!("action handler blew up");
            }
        });

        assert!(panicked.is_err());
        assert!(
            in_flight.is_empty(),
            "a panicking handler leaked its claim, permanently deadening the account's buttons"
        );
    }

    #[test]
    fn removing_feedback_buttons_leaves_the_other_blocks_untouched() {
        // A section that grew an "elements" key would fail the update as invalid_blocks.
        let section = json!({ "type": "section", "text": { "type": "mrkdwn", "text": "spam" } });
        let mut blocks = vec![
            section.clone(),
            json!({
                "type": "actions",
                "elements": [
                    { "action_id": SUSPEND_ACTION_ID },
                    { "action_id": CONFIRM_SPAM_ACTION_ID },
                    { "action_id": FALSE_POSITIVE_ACTION_ID },
                ]
            }),
        ];
        remove_feedback_buttons(&mut blocks);

        assert_eq!(blocks[0], section);
        assert_eq!(
            blocks[1]["elements"],
            json!([{ "action_id": SUSPEND_ACTION_ID }])
        );
    }

    #[test]
    fn an_actions_block_left_without_buttons_is_dropped() {
        // Slack rejects an empty actions block too, and the rejection is silent.
        let mut blocks = vec![
            json!({ "type": "section" }),
            json!({
                "type": "actions",
                "elements": [{ "action_id": CONFIRM_SPAM_ACTION_ID }]
            }),
        ];
        remove_feedback_buttons(&mut blocks);

        assert_eq!(blocks, vec![json!({ "type": "section" })]);
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
