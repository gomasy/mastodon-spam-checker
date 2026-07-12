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
use crate::slack::{ButtonValue, SUSPEND_ACTION_ID};

/// Slack の署名タイムスタンプの許容ずれ(リプレイ攻撃対策)
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;
/// シャットダウン時に進行中の停止処理を待つ上限
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

struct AppState {
    mastodon: MastodonClient,
    signing_secret: String,
    http: reqwest::Client,
    /// 停止処理中のアカウント ID(多重クリック抑止と shutdown 時の完了待ちに使う)
    in_flight: Mutex<HashSet<String>>,
}

pub async fn run(config: ServeConfig) -> Result<()> {
    let mastodon = MastodonClient::new(&config.mastodon_base_url, &config.mastodon_access_token);
    let state = Arc::new(AppState {
        http: mastodon.http_client(),
        mastodon,
        signing_secret: config.slack_signing_secret,
        in_flight: Mutex::new(HashSet::new()),
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
    while !state.in_flight.lock().unwrap().is_empty() {
        if Instant::now() >= deadline {
            warn!("shutting down with suspend tasks still in flight");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

async fn shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
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

    let mut payload = match parse_payload(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "failed to parse payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    if payload["type"] != "block_actions" {
        return StatusCode::OK;
    }

    let Some(action) = payload["actions"]
        .as_array()
        .and_then(|a| a.iter().find(|a| a["action_id"] == SUSPEND_ACTION_ID))
    else {
        return StatusCode::OK;
    };

    let value: ButtonValue = match action["value"]
        .as_str()
        .ok_or_else(|| anyhow!("action has no value"))
        .and_then(|v| serde_json::from_str(v).context("failed to parse button value"))
    {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "invalid button value");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Mastodon のアカウント ID は数値のみ。URL パスに埋め込むため、
    // 万一改変された値が届いても別エンドポイントに向かわないよう検証する
    if value.id.is_empty() || !value.id.bytes().all(|b| b.is_ascii_digit()) {
        warn!(id = %value.id, "account id is not numeric, rejecting");
        return StatusCode::BAD_REQUEST;
    }

    let Some(response_url) = payload["response_url"].as_str().map(String::from) else {
        warn!("payload has no response_url");
        return StatusCode::BAD_REQUEST;
    };
    let user_id = payload["user"]["id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let mut original_blocks: Vec<Value> = payload
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
    if original_blocks.is_empty()
        && let Some(text) = payload["message"]["text"]
            .as_str()
            .filter(|t| !t.is_empty())
    {
        original_blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": text }
        }));
    }

    // 同一アカウントへの停止処理が既に走っていれば無視する(二重クリック対策)
    if !state.in_flight.lock().unwrap().insert(value.id.clone()) {
        info!(account_id = %value.id, "suspension already in progress, ignoring click");
        return StatusCode::OK;
    }

    // Slack は 3 秒以内の応答を要求するため、停止処理は別タスクで行い即座に 200 を返す
    tokio::spawn(async move {
        process_suspend(state, value, user_id, response_url, original_blocks).await;
    });

    StatusCode::OK
}

/// アカウントを停止し、response_url 経由で元の Slack メッセージを結果で更新する
async fn process_suspend(
    state: Arc<AppState>,
    value: ButtonValue,
    user_id: String,
    response_url: String,
    mut blocks: Vec<Value>,
) {
    let result = state.mastodon.suspend_account(&value.id).await;

    let result_text = match &result {
        Ok(()) => {
            info!(account_id = %value.id, acct = %value.acct, "account suspended");
            format!(
                ":white_check_mark: <@{user_id}> が `{}` を停止しました",
                value.acct
            )
        }
        Err(e) => {
            error!(account_id = %value.id, error = %e, "failed to suspend account");
            format!(":x: `{}` の停止に失敗しました: {e}", value.acct)
        }
    };

    // 過去の結果表示(context)はリトライで無制限に蓄積するため毎回除去し、
    // 成功時はボタンも除去して再実行を防ぐ(失敗時は再試行できるよう残す)
    blocks.retain(|b| b["type"] != "context");
    if result.is_ok() {
        blocks.retain(|b| b["type"] != "actions");
    }
    blocks.push(json!({
        "type": "context",
        "elements": [{ "type": "mrkdwn", "text": result_text }]
    }));

    let update = json!({
        "replace_original": true,
        "text": result_text,
        "blocks": blocks,
    });

    match state.http.post(&response_url).json(&update).send().await {
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            error!(%status, body = %body, "failed to update Slack message");
        }
        Ok(_) => {}
        Err(e) => error!(error = %e, "Slack message update request failed"),
    }

    state.in_flight.lock().unwrap().remove(&value.id);
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
        .expect("system clock is before the UNIX epoch")
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
}
