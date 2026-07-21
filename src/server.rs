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

/// Slack の署名タイムスタンプの許容ずれ(リプレイ攻撃対策)
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
/// シャットダウン時に進行中の停止処理を待つ上限
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

struct AppState {
    mastodon: MastodonClient,
    signing_secret: String,
    http: reqwest::Client,
    /// 処理中のアカウント ID(多重クリック抑止と shutdown 時の完了待ちに使う)
    in_flight: Mutex<HashSet<String>>,
    note_writer: Option<crate::postgres::ModerationNoteWriter>,
}

impl AppState {
    /// in_flight のロックを取得する。poisoning(ロック保持中のパニック)が起きても
    /// HashSet 自体は不整合にならないため、パニックを連鎖させず回復して続行する
    fn lock_in_flight(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Slack メッセージ上のボタンに対応する操作
enum ButtonAction {
    Suspend,
    Delete,
}

/// ボタンクリックのペイロードから取り出した、処理に必要な情報一式
struct Interaction {
    kind: ButtonAction,
    value: ButtonValue,
    /// 削除ボタンへの差し替え時に value をそのまま引き継ぐための生 JSON 文字列
    raw_value: String,
    user_id: String,
    response_url: String,
    /// 元メッセージの blocks(結果表示を差し込んで replace_original に使う)
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

    // 「Mastodon では停止済みなのに Slack が未更新」で中断しないよう、
    // 進行中の停止処理の完了を待ってから終了する
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
    // SIGTERM ハンドラの登録に失敗してもパニックでサーバを道連れにせず、Ctrl-C のみで継続する
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
        // 関知しないイベント・ボタンは正常応答して無視する
        Ok(None) => return StatusCode::OK,
        Err(e) => {
            warn!(error = %e, "invalid interaction payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    // 同一アカウントへの処理が既に走っていれば無視する(二重クリック対策)
    if !state.lock_in_flight().insert(interaction.value.id.clone()) {
        info!(account_id = %interaction.value.id, "action already in progress, ignoring click");
        return StatusCode::OK;
    }

    // Slack は 3 秒以内の応答を要求するため、実処理は別タスクで行い即座に 200 を返す
    tokio::spawn(process_action(state, interaction));

    StatusCode::OK
}

/// block_actions ペイロードから処理対象のボタン操作を取り出す。
/// 関知しないイベント・ボタンは Ok(None)、必須情報の欠落・不正は Err
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

    // Mastodon のアカウント ID は数値のみ。URL パスに埋め込むため、
    // 万一改変された値が届いても別エンドポイントに向かわないよう検証する
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
    // blocks が欠けていた場合、replace_original で元の通知内容が
    // 丸ごと消えないよう text から最低限復元する
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

/// ボタンに応じた Mastodon API を呼び、response_url 経由で元の Slack メッセージを結果で更新する
async fn process_action(state: Arc<AppState>, interaction: Interaction) {
    let Interaction {
        kind,
        value,
        raw_value,
        user_id,
        response_url,
        mut blocks,
    } = interaction;

    // 過去の結果表示(context)はリトライで無制限に蓄積するため毎回除去する。
    // 成功時は各分岐でボタンも除去・差し替えして再実行を防ぐ(失敗時は再試行できるよう残す)
    blocks.retain(|b| b["type"] != "context");

    let result_text = match kind {
        ButtonAction::Suspend => {
            // 手動操作や別の通知メッセージのボタンで既に停止済みの場合は、
            // 停止 API を呼ばずにその旨を表示して削除ボタンに差し替える。
            // チェック自体の失敗は停止処理を妨げない(停止 API は冪等)
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
        // 削除は取り返しがつかないため、Slack メッセージ上のボタンの存在だけを信用せず、
        // 停止済みであることをサーバ側でも確認してから実行する
        // (停止後に手動で停止解除された古いボタンが押されるケースへの防御)
        ButtonAction::Delete => match state.mastodon.is_account_suspended(&value.id).await {
            Ok(true) => match state.mastodon.delete_account(&value.id).await {
                Ok(()) => {
                    info!(account_id = %value.id, acct = %value.acct, "account data deleted");
                    // 削除は最後の操作なのでボタンを除去する
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

/// 停止完了後: 停止ボタンを除去し、削除ボタンに差し替える
fn replace_buttons_with_delete(blocks: &mut Vec<Value>, value_json: &str, acct: &str) {
    blocks.retain(|b| b["type"] != "actions");
    blocks.push(delete_actions_block(value_json, acct));
}

fn context_block(text: &str) -> Value {
    json!({
        "type": "context",
        // Mastodon のエラーボディ等で上限を超えると invalid_blocks で
        // 更新ごと失われるため、必ず切り詰める
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

/// `payload=<JSON>` 形式のフォームボディをパースする
fn parse_payload(body: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    struct Form {
        payload: String,
    }
    let form: Form = serde_urlencoded::from_bytes(body).context("failed to parse form body")?;
    serde_json::from_str(&form.payload).context("failed to parse payload JSON")
}

/// Slack の署名 (v0=HMAC-SHA256) を検証する
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

    // ring::hmac::verify は定数時間比較
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
        let ts = "1000000000"; // 2001 年
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
        // block_actions 以外のイベント
        let none = extract_interaction(json!({ "type": "view_submission" })).unwrap();
        assert!(none.is_none());

        // 関知しない action_id のボタン
        let payload = json!({
            "type": "block_actions",
            "actions": [{ "action_id": "other_button", "value": "{}" }]
        });
        assert!(extract_interaction(payload).unwrap().is_none());
    }

    #[test]
    fn non_numeric_account_id_is_rejected() {
        // URL パスに埋め込まれるため、数値以外(パストラバーサル等)は拒否する
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
