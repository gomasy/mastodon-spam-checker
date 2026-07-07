use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tracing::info;

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
}

impl MastodonClient {
    pub fn new(base_url: &str, access_token: &str) -> Self {
        let client = Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
            ))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
        }
    }

    pub async fn fetch_remote_accounts(
        &self,
        min_id: Option<&str>,
    ) -> Result<Vec<AdminAccount>> {
        let mut url = format!(
            "{}/api/v2/admin/accounts?origin=remote&limit=100",
            self.base_url
        );
        if let Some(id) = min_id {
            url.push_str(&format!("&min_id={id}"));
        }

        info!(url = %url, "アカウント一覧を取得中");

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .context("Mastodon Admin API リクエスト失敗")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Admin API エラー (HTTP {status}): {body}");
        }

        let mut accounts: Vec<AdminAccount> = resp
            .json()
            .await
            .context("Admin accounts レスポンスのパース失敗")?;

        info!(count = accounts.len(), "取得完了");

        // ID は数値文字列なので、桁数→辞書順の順で比較して数値順にする
        accounts.sort_by(|a, b| a.id.len().cmp(&b.id.len()).then_with(|| a.id.cmp(&b.id)));
        Ok(accounts)
    }

    pub async fn fetch_statuses(&self, account_id: &str) -> Result<Vec<Status>> {
        let url = format!(
            "{}/api/v1/accounts/{}/statuses?limit=10&exclude_reblogs=true",
            self.base_url, account_id
        );

        info!(account_id = %account_id, "投稿を取得中");

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .context("Statuses API リクエスト失敗")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Statuses API エラー (HTTP {status}): {body}");
        }

        let statuses: Vec<Status> = resp
            .json()
            .await
            .context("Statuses レスポンスのパース失敗")?;

        Ok(statuses)
    }
}
