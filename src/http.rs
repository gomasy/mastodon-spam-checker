use std::time::Duration;

use anyhow::{Result, bail};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::warn;

/// 共通設定(User-Agent、タイムアウト)の HTTP クライアントを生成する
pub fn client(timeout: Duration) -> Client {
    Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(timeout)
        .build()
        .expect("failed to build HTTP client")
}

/// 成功ステータスでなければ、レスポンスボディを含むエラーにする
pub async fn ensure_success(resp: Response, what: &str) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    bail!("{what} error (HTTP {status}): {body}")
}

/// 指数バックオフ付きリトライの設定
#[derive(Clone, Copy)]
pub struct RetryConfig {
    /// 最初の試行後に許容する再試行回数(0 ならリトライしない)
    pub max_retries: u32,
    /// 1 回目のバックオフ待機時間(以降 2 倍ずつ増える)
    pub base_delay: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
        }
    }
}

impl RetryConfig {
    /// attempt 回目(0 始まり)の再試行前に待つ時間。base_delay * 2^attempt。
    fn backoff(&self, attempt: u32) -> Duration {
        self.base_delay
            .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
    }
}

/// 一時的な障害としてリトライすべきステータスか(429 と 5xx)
fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// リトライすべきネットワークエラーか(タイムアウト・接続失敗など)。
/// リクエスト構築エラー(is_request)は設定不備など永続的な原因のためリトライしない。
fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

/// `Retry-After` ヘッダ(秒指定のみ対応)を待機時間として解釈する
fn retry_after(resp: &Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// 指数バックオフ付きでリクエストを送信し、成功レスポンスを返す。
///
/// `build` は試行のたびに新しい `RequestBuilder` を生成するクロージャ。
/// 429 / 5xx とタイムアウト等の一時障害を `retry.max_retries` 回まで再試行する。
/// リトライ不能な失敗・回数超過時は [`ensure_success`] 相当のボディ付きエラーになる。
pub async fn send_with_retry<F>(build: F, what: &str, retry: RetryConfig) -> Result<Response>
where
    F: Fn() -> RequestBuilder,
{
    let resp = send_with_retry_raw(build, what, retry).await?;
    ensure_success(resp, what).await
}

/// [`send_with_retry`] と同じくリトライするが、ステータスの成否判定は呼び出し側に委ねる。
///
/// ネットワークエラーと 429 / 5xx のみを再試行し、最終的なレスポンスを
/// ステータスに関わらずそのまま返す。404 等を独自に処理したい場合に使う。
pub async fn send_with_retry_raw<F>(build: F, what: &str, retry: RetryConfig) -> Result<Response>
where
    F: Fn() -> RequestBuilder,
{
    let mut attempt = 0;
    loop {
        match build().send().await {
            Ok(resp) => {
                let status = resp.status();
                if is_retryable_status(status) && attempt < retry.max_retries {
                    let delay = retry_after(&resp).unwrap_or_else(|| retry.backoff(attempt));
                    warn!(
                        %what,
                        %status,
                        attempt = attempt + 1,
                        max = retry.max_retries,
                        delay_ms = delay.as_millis(),
                        "retryable HTTP status, backing off",
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                if is_retryable_error(&e) && attempt < retry.max_retries {
                    let delay = retry.backoff(attempt);
                    warn!(
                        %what,
                        error = %e,
                        attempt = attempt + 1,
                        max = retry.max_retries,
                        delay_ms = delay.as_millis(),
                        "retryable request error, backing off",
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(anyhow::Error::new(e).context(format!("{what} request failed")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_each_attempt() {
        let retry = RetryConfig {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
        };
        assert_eq!(retry.backoff(0), Duration::from_millis(100));
        assert_eq!(retry.backoff(1), Duration::from_millis(200));
        assert_eq!(retry.backoff(2), Duration::from_millis(400));
    }

    #[test]
    fn backoff_saturates_without_overflow() {
        let retry = RetryConfig {
            max_retries: 100,
            base_delay: Duration::from_secs(1),
        };
        // 極端な attempt でもパニックせず飽和する
        let _ = retry.backoff(64);
        let _ = retry.backoff(u32::MAX);
    }

    #[test]
    fn retryable_status_classification() {
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::OK));
    }
}
