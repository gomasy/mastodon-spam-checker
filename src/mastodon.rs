use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use tracing::{info, warn};

use crate::http;

#[derive(Debug, Deserialize)]
pub struct AdminAccount {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
    pub account: Account,
}

#[derive(Debug, Deserialize)]
pub struct Account {
    pub display_name: String,
    pub note: String,
    pub avatar: String,
    pub url: String,
    pub followers_count: u64,
    pub following_count: u64,
    pub statuses_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct Status {
    pub content: String,
}

pub struct MastodonClient {
    client: Client,
    base_url: String,
    access_token: String,
    retry: http::RetryConfig,
}

impl MastodonClient {
    pub fn new(base_url: &str, access_token: &str) -> Self {
        Self {
            client: http::client(Duration::from_secs(30)),
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
            retry: http::RetryConfig::default(),
        }
    }

    /// Returns a clone of the inner HTTP client (clones share the connection pool).
    pub fn http_client(&self) -> Client {
        self.client.clone()
    }

    /// Send an authenticated request and return an error with the response body on non-success status (no retry).
    /// Use for write operations with side effects (suspend, delete).
    async fn send(&self, req: RequestBuilder, what: &str) -> Result<Response> {
        let resp = req
            .bearer_auth(&self.access_token)
            .send()
            .await
            .with_context(|| format!("{what} request failed"))?;
        http::ensure_success(resp, what).await
    }

    /// Send an authenticated request with exponential-backoff retry on transient failures.
    /// Use for idempotent read operations (GET). `build` must return a fresh `RequestBuilder` on each call.
    async fn send_retry<F>(&self, build: F, what: &str) -> Result<Response>
    where
        F: Fn() -> RequestBuilder,
    {
        http::send_with_retry(|| build().bearer_auth(&self.access_token), what, self.retry).await
    }

    pub async fn fetch_remote_accounts(&self, min_id: Option<&str>) -> Result<Vec<AdminAccount>> {
        let mut url = format!(
            "{}/api/v2/admin/accounts?origin=remote&limit=100",
            self.base_url
        );
        if let Some(id) = min_id {
            url.push_str(&format!("&min_id={id}"));
        }

        info!(url = %url, "fetching accounts");

        let resp = self
            .send_retry(|| self.client.get(&url), "Admin accounts API")
            .await?;
        let mut accounts: Vec<AdminAccount> = resp
            .json()
            .await
            .context("failed to parse admin accounts response")?;

        info!(count = accounts.len(), "fetched");

        // IDs are numeric strings; sort by length first, then lexicographically to get numeric order.
        accounts.sort_by(|a, b| a.id.len().cmp(&b.id.len()).then_with(|| a.id.cmp(&b.id)));
        Ok(accounts)
    }

    /// Returns whether the account is suspended (requires admin:read:accounts scope).
    pub async fn is_account_suspended(&self, account_id: &str) -> Result<bool> {
        let url = format!("{}/api/v1/admin/accounts/{}", self.base_url, account_id);

        let resp = self
            .send_retry(|| self.client.get(&url), "Admin account API")
            .await?;

        // Treat missing or null suspended field as unsuspended to tolerate version differences.
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            suspended: Option<bool>,
        }
        let account: Resp = resp
            .json()
            .await
            .context("failed to parse admin account response")?;
        Ok(account.suspended.unwrap_or(false))
    }

    /// Suspends the account (requires admin:write:accounts scope).
    pub async fn suspend_account(&self, account_id: &str) -> Result<()> {
        let url = format!(
            "{}/api/v1/admin/accounts/{}/action",
            self.base_url, account_id
        );

        info!(account_id = %account_id, "suspending account");

        let req = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "type": "suspend" }));
        self.send(req, "Admin action API").await?;

        Ok(())
    }

    /// Permanently deletes data for a suspended account (requires admin:write:accounts scope).
    /// Mastodon rejects this request if the account is not already suspended.
    pub async fn delete_account(&self, account_id: &str) -> Result<()> {
        let url = format!("{}/api/v1/admin/accounts/{}", self.base_url, account_id);

        info!(account_id = %account_id, "deleting account data");

        self.send(self.client.delete(&url), "Admin account delete API")
            .await?;

        Ok(())
    }

    pub async fn fetch_statuses(&self, account_id: &str) -> Result<Vec<Status>> {
        let url = format!(
            "{}/api/v1/accounts/{}/statuses?limit=10&exclude_reblogs=true",
            self.base_url, account_id
        );

        info!(account_id = %account_id, "fetching statuses");

        let resp = http::send_with_retry_raw(
            || self.client.get(&url).bearer_auth(&self.access_token),
            "Statuses API",
            self.retry,
        )
        .await?;

        // Treat permanent errors (e.g. account deleted) as "no posts"
        // and continue with profile-only classification (do not abort the caller).
        let status = resp.status();
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            warn!(account_id = %account_id, %status, "statuses unavailable, treating as no posts");
            return Ok(Vec::new());
        }

        let resp = http::ensure_success(resp, "Statuses API").await?;
        let statuses: Vec<Status> = resp
            .json()
            .await
            .context("failed to parse statuses response")?;

        Ok(statuses)
    }
}
