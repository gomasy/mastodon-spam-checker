use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use tracing::{info, warn};

use crate::http;
use crate::ids::numeric_id_cmp;

#[derive(Clone, Debug, Deserialize)]
pub struct AdminAccount {
    pub id: String,
    pub username: String,
    pub domain: Option<String>,
    pub account: Account,
}

impl AdminAccount {
    /// `username@domain` as shown to moderators; local accounts have no domain.
    pub fn acct(&self) -> String {
        format!(
            "{}@{}",
            self.username,
            self.domain.as_deref().unwrap_or("(local)")
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Account {
    pub display_name: String,
    pub note: String,
    pub avatar: String,
    pub url: String,
    pub followers_count: u64,
    pub following_count: u64,
    pub statuses_count: u64,
    #[serde(default)]
    pub bot: bool,
    #[serde(default)]
    pub group: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_status_at: Option<String>,
    #[serde(default)]
    pub fields: Vec<ProfileField>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProfileField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub verified_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Status {
    pub content: String,
    #[serde(default)]
    pub spoiler_text: String,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub media_attachments: Vec<MediaAttachment>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MediaAttachment {
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone)]
pub struct MastodonClient {
    client: Client,
    base_url: String,
    access_token: String,
    retry: http::RetryConfig,
}

impl MastodonClient {
    pub fn new(base_url: &str, access_token: &str) -> Result<Self> {
        Ok(Self {
            client: http::client(Duration::from_secs(30))?,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
            retry: http::RetryConfig::default(),
        })
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

    pub async fn fetch_remote_accounts(
        &self,
        min_id: Option<&str>,
        max_id: Option<&str>,
        max_accounts: usize,
    ) -> Result<Vec<AdminAccount>> {
        let page_limit = max_accounts.min(200);
        let mut accounts = Vec::new();
        let forward = min_id.is_some();
        let mut page_min_id = min_id.map(str::to_string);
        let mut page_max_id = max_id.map(str::to_string);
        while accounts.len() < max_accounts {
            let remaining = max_accounts - accounts.len();
            let limit = page_limit.min(remaining);
            let mut url = format!(
                "{}/api/v2/admin/accounts?origin=remote&limit={limit}",
                self.base_url
            );
            if let Some(id) = &page_min_id {
                url.push_str(&format!("&min_id={id}"));
            }
            if let Some(id) = &page_max_id {
                url.push_str(&format!("&max_id={id}"));
            }
            info!(url = %url, "fetching accounts");
            let resp = self
                .send_retry(|| self.client.get(&url), "Admin accounts API")
                .await?;
            let mut page: Vec<AdminAccount> = resp
                .json()
                .await
                .context("failed to parse admin accounts response")?;
            // Whether the page was full decides if another one exists, so measure it before
            // de-duplication: a repeated ID within a page would otherwise end pagination early
            // and silently leave the remaining accounts unchecked.
            let page_was_full = page.len() >= limit;
            page.sort_by(|a, b| numeric_id_cmp(&a.id, &b.id));
            page.dedup_by(|a, b| a.id == b.id);
            let next_min_id = page.last().map(|account| account.id.clone());
            let next_max_id = page.first().map(|account| account.id.clone());
            accounts.extend(page);
            if !page_was_full || accounts.len() >= max_accounts {
                break;
            }
            if forward {
                if next_min_id == page_min_id {
                    warn!(min_id = ?page_min_id, "account pagination made no progress");
                    break;
                }
                page_min_id = next_min_id;
            } else {
                if next_max_id == page_max_id {
                    warn!(max_id = ?page_max_id, "account pagination made no progress");
                    break;
                }
                page_max_id = next_max_id;
            }
        }

        info!(count = accounts.len(), "fetched accounts across pages");

        // IDs are numeric strings; sort by length first, then lexicographically to get numeric order.
        accounts.sort_by(|a, b| numeric_id_cmp(&a.id, &b.id));
        accounts.dedup_by(|a, b| a.id == b.id);
        Ok(accounts)
    }

    pub async fn fetch_admin_account(&self, account_id: &str) -> Result<AdminAccount> {
        self.fetch_admin_account_optional(account_id)
            .await?
            .with_context(|| format!("admin account {account_id} was not found"))
    }

    pub async fn fetch_admin_account_optional(
        &self,
        account_id: &str,
    ) -> Result<Option<AdminAccount>> {
        let url = format!("{}/api/v1/admin/accounts/{account_id}", self.base_url);
        let resp = http::send_with_retry_raw(
            || self.client.get(&url).bearer_auth(&self.access_token),
            "Admin account API",
            self.retry,
        )
        .await?;
        if matches!(resp.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
            return Ok(None);
        }
        let account = http::ensure_success(resp, "Admin account API")
            .await?
            .json()
            .await
            .context("failed to parse admin account response")?;
        Ok(Some(account))
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
