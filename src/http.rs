use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Client, ClientBuilder, RequestBuilder, Response, StatusCode};
use tracing::warn;

const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

pub fn client(timeout: Duration) -> Result<Client> {
    client_builder(timeout)
        .build()
        .context("failed to build HTTP client")
}

pub fn client_builder(timeout: Duration) -> ClientBuilder {
    Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(timeout)
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

fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

/// `Retry-After` in integer seconds, capped at [`MAX_RETRY_AFTER`].
fn retry_after(resp: &Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .map(|duration| duration.min(MAX_RETRY_AFTER))
}

/// [`send_with_retry_raw`] plus [`ensure_success`].
pub async fn send_with_retry<F>(build: F, what: &str, retry: RetryConfig) -> Result<Response>
where
    F: Fn() -> RequestBuilder,
{
    let resp = send_with_retry_raw(build, what, retry).await?;
    ensure_success(resp, what).await
}

/// Retries network errors and 429/5xx, then returns the final response whatever its status.
pub async fn send_with_retry_raw<F>(build: F, what: &str, retry: RetryConfig) -> Result<Response>
where
    F: Fn() -> RequestBuilder,
{
    let mut attempt = 0;
    loop {
        let result = build().send().await;
        let retryable = match &result {
            Ok(resp) if is_retryable_status(resp.status()) => Some((
                retry_after(resp).unwrap_or_else(|| retry.backoff(attempt)),
                resp.status().to_string(),
            )),
            Err(e) if is_retryable_error(e) => Some((retry.backoff(attempt), e.to_string())),
            _ => None,
        };
        let Some((delay, reason)) = retryable.filter(|_| attempt < retry.max_retries) else {
            return result.with_context(|| format!("{what} request failed"));
        };
        warn!(
            %what,
            %reason,
            attempt = attempt + 1,
            max = retry.max_retries,
            delay_ms = delay.as_millis(),
            "retryable HTTP failure, backing off",
        );
        tokio::time::sleep(delay).await;
        attempt += 1;
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
