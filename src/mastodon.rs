use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use tracing::{info, warn};

use crate::http;
use crate::ids::{is_numeric_id, numeric_id_cmp, validate_account_id};

/// The admin accounts API's maximum page size.
pub const ADMIN_PAGE_LIMIT: usize = 200;

/// How many recent posts a check reads.
pub const STATUSES_LIMIT: usize = 10;

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
    /// The ActivityPub actor ID. Mastodon 4.2 and later.
    #[serde(default)]
    pub uri: Option<String>,
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

fn sort_unique_by_id(accounts: &mut Vec<AdminAccount>) {
    accounts.sort_by(|a, b| numeric_id_cmp(&a.id, &b.id));
    accounts.dedup_by(|a, b| a.id == b.id);
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

    /// The instance's Mastodon version, as `Mastodon::Version.to_s` renders it.
    pub async fn fetch_version(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Instance {
            version: String,
        }

        let url = format!("{}/api/v2/instance", self.base_url);
        let Instance { version } =
            http::send_with_retry(|| self.client.get(&url), "Instance API", self.retry)
                .await?
                .json()
                .await
                .context("failed to parse instance response")?;
        Ok(version)
    }

    pub fn http_client(&self) -> Client {
        self.client.clone()
    }

    /// Authenticated and not retried, for writes with side effects.
    async fn send(&self, req: RequestBuilder, what: &str) -> Result<Response> {
        let resp = req
            .bearer_auth(&self.access_token)
            .send()
            .await
            .with_context(|| format!("{what} request failed"))?;
        http::ensure_success(resp, what).await
    }

    /// Authenticated and retried, for idempotent reads; the status is left to the caller.
    async fn send_retry_raw<F>(&self, build: F, what: &str) -> Result<Response>
    where
        F: Fn() -> RequestBuilder,
    {
        http::send_with_retry_raw(|| build().bearer_auth(&self.access_token), what, self.retry)
            .await
    }

    async fn send_retry<F>(&self, build: F, what: &str) -> Result<Response>
    where
        F: Fn() -> RequestBuilder,
    {
        let resp = self.send_retry_raw(build, what).await?;
        http::ensure_success(resp, what).await
    }

    pub async fn fetch_remote_accounts(
        &self,
        min_id: Option<&str>,
        max_id: Option<&str>,
        max_accounts: usize,
    ) -> Result<Vec<AdminAccount>> {
        let page_limit = max_accounts.min(ADMIN_PAGE_LIMIT);
        let mut accounts = Vec::new();
        let forward = min_id.is_some();
        let mut page_min_id = min_id.map(str::to_string);
        let mut page_max_id = max_id.map(str::to_string);
        while accounts.len() < max_accounts {
            let remaining = max_accounts - accounts.len();
            let limit = page_limit.min(remaining);
            let limit_param = limit.to_string();
            let mut query = vec![("origin", "remote"), ("limit", limit_param.as_str())];
            query.extend(page_min_id.as_deref().map(|id| ("min_id", id)));
            query.extend(page_max_id.as_deref().map(|id| ("max_id", id)));
            let mut page: Vec<AdminAccount> = self.admin_accounts_page(&query).await?;
            // Measured before de-duplication, which could otherwise end pagination early.
            let page_was_full = page.len() >= limit;
            sort_unique_by_id(&mut page);
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
        sort_unique_by_id(&mut accounts);
        Ok(accounts)
    }

    /// IDs of suspended remote accounts, newest first by account ID (not suspension time).
    pub async fn fetch_suspended_remote_account_ids(&self, max: usize) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Suspended {
            id: String,
        }

        let mut ids: Vec<String> = Vec::new();
        let mut max_id: Option<String> = None;
        while ids.len() < max {
            let limit = (max - ids.len()).min(ADMIN_PAGE_LIMIT);
            let limit_param = limit.to_string();
            let mut query = vec![
                ("origin", "remote"),
                ("status", "suspended"),
                ("limit", limit_param.as_str()),
            ];
            query.extend(max_id.as_deref().map(|id| ("max_id", id)));
            let page: Vec<Suspended> = self.admin_accounts_page(&query).await?;
            let page_was_full = page.len() >= limit;
            let page: Vec<String> = page
                .into_iter()
                .map(|account| account.id)
                .filter(|id| is_numeric_id(id))
                .collect();
            let next_max_id = page.iter().min_by(|a, b| numeric_id_cmp(a, b)).cloned();
            ids.extend(page);
            if !page_was_full || next_max_id.is_none() || next_max_id == max_id {
                break;
            }
            max_id = next_max_id;
        }
        ids.truncate(max);
        Ok(ids)
    }

    async fn admin_accounts_page<T: DeserializeOwned>(
        &self,
        query: &[(&str, &str)],
    ) -> Result<Vec<T>> {
        let query = serde_urlencoded::to_string(query).context("failed to build account query")?;
        let url = format!("{}/api/v2/admin/accounts?{query}", self.base_url);
        info!(url = %url, "fetching accounts");
        self.send_retry(|| self.client.get(&url), "Admin accounts API")
            .await?
            .json()
            .await
            .context("failed to parse admin accounts response")
    }

    /// `lookup` is called anonymously, since the token carries only admin scopes.
    pub async fn fetch_admin_account_by_acct(&self, acct: &str) -> Result<Option<AdminAccount>> {
        #[derive(Deserialize)]
        struct Lookup {
            id: String,
        }

        let query = serde_urlencoded::to_string([("acct", acct)])
            .context("failed to build lookup query")?;
        let url = format!("{}/api/v1/accounts/lookup?{query}", self.base_url);
        let resp =
            http::send_with_retry_raw(|| self.client.get(&url), "Account lookup API", self.retry)
                .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let Lookup { id } = http::ensure_success(resp, "Account lookup API")
            .await?
            .json()
            .await
            .context("failed to parse account lookup response")?;
        validate_account_id(&id)?;
        self.fetch_admin_account_optional(&id).await
    }

    pub async fn fetch_admin_account(&self, account_id: &str) -> Result<AdminAccount> {
        self.fetch_admin_account_optional(account_id)
            .await?
            .with_context(|| format!("admin account {account_id} was not found"))
    }

    /// `account_id` must already be validated as numeric.
    fn admin_account_url(&self, account_id: &str) -> String {
        format!("{}/api/v1/admin/accounts/{account_id}", self.base_url)
    }

    pub async fn fetch_admin_account_optional(
        &self,
        account_id: &str,
    ) -> Result<Option<AdminAccount>> {
        let url = self.admin_account_url(account_id);
        let resp = self
            .send_retry_raw(|| self.client.get(&url), "Admin account API")
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

    pub async fn is_account_suspended(&self, account_id: &str) -> Result<bool> {
        #[derive(Deserialize)]
        struct SuspensionState {
            #[serde(default)]
            suspended: Option<bool>,
        }

        let url = self.admin_account_url(account_id);
        let account: SuspensionState = self
            .send_retry(|| self.client.get(&url), "Admin account API")
            .await?
            .json()
            .await
            .context("failed to parse admin account response")?;
        Ok(account.suspended.unwrap_or(false))
    }

    pub async fn suspend_account(&self, account_id: &str) -> Result<()> {
        info!(account_id, "suspending account");
        let req = self
            .client
            .post(format!("{}/action", self.admin_account_url(account_id)))
            .json(&serde_json::json!({ "type": "suspend" }));
        self.send(req, "Admin action API").await?;
        Ok(())
    }

    /// Mastodon rejects this unless the account is already suspended.
    pub async fn delete_account(&self, account_id: &str) -> Result<()> {
        info!(account_id, "deleting account data");
        let req = self.client.delete(self.admin_account_url(account_id));
        self.send(req, "Admin account delete API").await?;
        Ok(())
    }

    pub async fn fetch_statuses(&self, account_id: &str) -> Result<Vec<Status>> {
        let url = format!(
            "{}/api/v1/accounts/{account_id}/statuses?limit={STATUSES_LIMIT}&exclude_reblogs=true",
            self.base_url
        );
        info!(account_id, "fetching statuses");

        // Anonymous: a user token would include private posts; an admin token fails the scope check.
        let resp =
            http::send_with_retry_raw(|| self.client.get(&url), "Statuses API", self.retry).await?;

        let status = resp.status();
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            warn!(account_id, %status, "statuses unavailable, treating as no posts");
            return Ok(Vec::new());
        }

        http::ensure_success(resp, "Statuses API")
            .await?
            .json()
            .await
            .context("failed to parse statuses response")
    }
}
