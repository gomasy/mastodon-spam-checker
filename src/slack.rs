use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Serialize;

use crate::llm::SpamVerdict;
use crate::mastodon::AdminAccount;

const APP_NAME: &str = "Mastodon Spam Checker";

#[derive(Serialize)]
struct SlackMessage {
    text: String,
    username: &'static str,
    icon_emoji: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
}

pub struct SlackNotifier {
    client: Client,
    webhook_url: String,
    channel: Option<String>,
}

impl SlackNotifier {
    pub fn new(webhook_url: &str, channel: Option<String>) -> Self {
        let client = Client::builder()
            .user_agent(concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            webhook_url: webhook_url.to_string(),
            channel,
        }
    }

    pub async fn notify_spam(
        &self,
        account: &AdminAccount,
        verdict: &SpamVerdict,
    ) -> Result<()> {
        let domain = account.domain.as_deref().unwrap_or("(local)");
        let text = format!(
            ":warning: *スパムアカウント検出*\n\
             • アカウント: `{}@{}`\n\
             • 表示名: {}\n\
             • URL: {}\n\
             • 確信度: {:.0}%\n\
             • 理由: {}",
            account.username,
            domain,
            account.account.display_name,
            account.account.url,
            verdict.confidence * 100.0,
            verdict.reason,
        );

        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&SlackMessage {
                text,
                username: APP_NAME,
                icon_emoji: ":scales:",
                channel: self.channel.clone(),
            })
            .send()
            .await
            .context("Slack Webhook 送信失敗")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Slack Webhook エラー (HTTP {status}): {body}");
        }

        Ok(())
    }
}
