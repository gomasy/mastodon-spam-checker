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
}

impl MastodonClient {
    pub fn new(base_url: &str, access_token: &str) -> Self {
        Self {
            client: http::client(Duration::from_secs(30)),
            base_url: base_url.trim_end_matches('/').to_string(),
            access_token: access_token.to_string(),
        }
    }

    /// 内部の HTTP クライアントを共有する(clone はコネクションプールを共有)
    pub fn http_client(&self) -> Client {
        self.client.clone()
    }

    /// 認証を付けて送信し、非成功ステータスはボディ付きエラーにする
    async fn send(&self, req: RequestBuilder, what: &str) -> Result<Response> {
        let resp = req
            .bearer_auth(&self.access_token)
            .send()
            .await
            .with_context(|| format!("{what} request failed"))?;
        http::ensure_success(resp, what).await
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
            .send(self.client.get(&url), "Admin accounts API")
            .await?;
        let mut accounts: Vec<AdminAccount> = resp
            .json()
            .await
            .context("failed to parse admin accounts response")?;

        info!(count = accounts.len(), "fetched");

        // ID は数値文字列なので、桁数→辞書順の順で比較して数値順にする
        accounts.sort_by(|a, b| a.id.len().cmp(&b.id.len()).then_with(|| a.id.cmp(&b.id)));
        Ok(accounts)
    }

    /// アカウントが停止済みかどうかを返す(要 admin:read:accounts スコープ)
    pub async fn is_account_suspended(&self, account_id: &str) -> Result<bool> {
        let url = format!("{}/api/v1/admin/accounts/{}", self.base_url, account_id);

        let resp = self
            .send(self.client.get(&url), "Admin account API")
            .await?;

        // suspended が欠落・null のバージョン差異でもエラーにせず「未停止」として扱う
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

    /// アカウントを停止する(要 admin:write:accounts スコープ)
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

    /// 停止済みアカウントのデータを完全に削除する(要 admin:write:accounts スコープ)
    /// 停止していないアカウントに対しては Mastodon 側が拒否する
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

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .context("Statuses API request failed")?;

        // アカウント削除済み等の恒久的エラーは「投稿なし」として扱い、
        // プロフィールのみで判定を続行する(呼び出し側で中断させない)
        let status = resp.status();
        if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
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
