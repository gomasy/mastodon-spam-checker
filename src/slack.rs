use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use rust_i18n::t;

use crate::http;
use crate::llm::SpamVerdict;
use crate::mastodon::AdminAccount;

const APP_NAME: &str = "Mastodon Spam Checker";

/// Action ID for the suspend button (shared with the serve-mode handler).
pub const SUSPEND_ACTION_ID: &str = "suspend_account";
/// Action ID for the delete button (appears only in post-suspension messages).
pub const DELETE_ACTION_ID: &str = "delete_account";

/// Character limit for Block Kit mrkdwn text objects (shared by section and context blocks).
pub(crate) const TEXT_MAX_CHARS: usize = 3000;
/// Character limit for the Block Kit confirm dialog text.
const CONFIRM_TEXT_MAX_CHARS: usize = 300;

/// Information embedded in the suspend button value (shared between the notifier and the serve-mode handler).
#[derive(Serialize, Deserialize)]
pub struct ButtonValue {
    pub id: String,
    pub acct: String,
}

#[derive(Serialize)]
struct SlackMessage {
    // When blocks are used, text serves as a notification/preview fallback.
    text: String,
    blocks: Value,
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
        Self {
            client: http::client(Duration::from_secs(30)),
            webhook_url: webhook_url.to_string(),
            channel,
        }
    }

    pub async fn notify_spam(&self, account: &AdminAccount, verdict: &SpamVerdict) -> Result<()> {
        let domain = account.domain.as_deref().unwrap_or("(local)");
        let acct = format!("{}@{}", account.username, domain);
        let text = t!(
            "spam_detected",
            acct = &acct,
            display_name = &account.account.display_name,
            url = &account.account.url,
            confidence = format!("{:.0}", verdict.confidence * 100.0),
            reason = &verdict.reason,
        )
        .to_string();

        let value = serde_json::to_string(&ButtonValue {
            id: account.id.clone(),
            acct: acct.clone(),
        })
        .context("failed to serialize button value")?;
        let blocks = json!([
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": truncate_chars(&text, TEXT_MAX_CHARS) }
            },
            confirm_actions_block(
                SUSPEND_ACTION_ID,
                &t!("btn_suspend"),
                &value,
                &t!("btn_suspend_title"),
                &t!("btn_suspend_confirm", acct = &acct),
                &t!("btn_suspend_do"),
            ),
        ]);

        let resp = self
            .client
            .post(&self.webhook_url)
            .json(&SlackMessage {
                text,
                blocks,
                username: APP_NAME,
                icon_emoji: ":scales:",
                channel: self.channel.clone(),
            })
            .send()
            .await
            .context("Slack webhook request failed")?;
        http::ensure_success(resp, "Slack webhook").await?;

        Ok(())
    }
}

/// Builds an actions block containing the "Delete Account" button for post-suspension messages.
/// (DELETE /api/v1/admin/accounts/:id is only valid for suspended accounts.)
/// Pass the suspend button's value JSON (ButtonValue) as value_json.
pub fn delete_actions_block(value_json: &str, acct: &str) -> Value {
    confirm_actions_block(
        DELETE_ACTION_ID,
        &t!("btn_delete"),
        value_json,
        &t!("btn_delete_title"),
        &t!("btn_delete_confirm", acct = acct),
        &t!("btn_delete_do"),
    )
}

fn confirm_actions_block(
    action_id: &str,
    label: &str,
    value: &str,
    confirm_title: &str,
    confirm_text: &str,
    confirm_label: &str,
) -> Value {
    json!({
        "type": "actions",
        "elements": [{
            "type": "button",
            "action_id": action_id,
            "style": "danger",
            "text": { "type": "plain_text", "text": label },
            "value": value,
            "confirm": {
                "style": "danger",
                "title": { "type": "plain_text", "text": confirm_title },
                "text": {
                    "type": "mrkdwn",
                    "text": truncate_chars(confirm_text, CONFIRM_TEXT_MAX_CHARS)
                },
                "confirm": { "type": "plain_text", "text": confirm_label },
                "deny": { "type": "plain_text", "text": t!("btn_cancel").to_string() }
            }
        }]
    })
}

pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut truncated: String = s.chars().take(max_chars - 1).collect();
        truncated.push('…');
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_keeps_short_strings() {
        assert_eq!(truncate_chars("abc", 3), "abc");
        assert_eq!(truncate_chars("", 10), "");
    }

    #[test]
    fn truncate_chars_truncates_by_chars_not_bytes() {
        assert_eq!(truncate_chars("あいうえお", 3), "あい…");
        assert_eq!(truncate_chars("あいうえお", 3).chars().count(), 3);
    }
}
