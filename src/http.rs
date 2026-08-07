use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::warn;

const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// An HTTP client with the shared User-Agent and the given timeout.
pub fn client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")
}

pub async fn ensure_success(resp: Response, what: &str) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    bail!("{what} error (HTTP {status}): {body}")
}

#[derive(Clone, Copy)]
pub struct RetryConfig {
    /// Retries after the first attempt; 0 means none.
    pub max_retries: u32,
    /// Wait before the first retry, doubling on each subsequent one.
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
    /// `base_delay * 2^attempt`, with `attempt` 0-based.
    fn backoff(&self, attempt: u32) -> Duration {
        self.base_delay
            .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Timeouts and connection failures are worth retrying; request-builder errors are not, since they
/// point at a configuration problem.
fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

/// The `Retry-After` header as a wait duration. Integer seconds only.
fn retry_after(resp: &Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .map(|duration| duration.min(MAX_RETRY_AFTER))
}

/// [`send_with_retry_raw`] plus [`ensure_success`]: anything but a success status, whether
/// non-retryable or left after the retries ran out, becomes a body-bearing error.
pub async fn send_with_retry<F>(build: F, what: &str, retry: RetryConfig) -> Result<Response>
where
    F: Fn() -> RequestBuilder,
{
    let resp = send_with_retry_raw(build, what, retry).await?;
    ensure_success(resp, what).await
}

/// Retries network errors and 429 / 5xx up to `retry.max_retries` times, then returns the final
/// response whatever its status. `build` must return a fresh `RequestBuilder` for each attempt.
///
/// Judging the status is left to the caller, for the paths that handle 404 or 410 themselves.
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
