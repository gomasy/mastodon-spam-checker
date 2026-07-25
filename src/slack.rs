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
    retry: http::RetryConfig,
}

impl SlackNotifier {
    pub fn new(webhook_url: &str, channel: Option<String>) -> Result<Self> {
        Ok(Self {
            client: http::client(Duration::from_secs(30))?,
            webhook_url: webhook_url.to_string(),
            channel,
            retry: http::RetryConfig::default(),
        })
    }

    pub async fn notify_spam(&self, account: &AdminAccount, verdict: &SpamVerdict) -> Result<()> {
        let acct = account.acct();
        let safe_acct = sanitize_mrkdwn(&acct);
        let text = t!(
            "spam_detected",
            acct = &safe_acct,
            display_name = sanitize_mrkdwn(&account.account.display_name),
            url = sanitize_mrkdwn(&account.account.url),
            confidence = format!("{:.0}", verdict.confidence * 100.0),
            reason = sanitize_mrkdwn(&verdict.reason),
        )
        .to_string();
        let text = truncate_mrkdwn(&text, TEXT_MAX_CHARS);

        let value = serde_json::to_string(&ButtonValue {
            id: account.id.clone(),
            acct,
        })
        .context("failed to serialize button value")?;
        let blocks = json!([
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": text.clone() }
            },
            confirm_actions_block(
                SUSPEND_ACTION_ID,
                &t!("btn_suspend"),
                &value,
                &t!("btn_suspend_title"),
                &t!("btn_suspend_confirm", acct = &safe_acct),
                &t!("btn_suspend_do"),
            ),
        ]);

        let message = SlackMessage {
            // Doubles as the notification/preview fallback; already within Slack's limit for it.
            text,
            blocks,
            username: APP_NAME,
            icon_emoji: ":scales:",
            channel: self.channel.clone(),
        };

        // Retry transient failures: the caller aborts the whole run on a notification error,
        // so a momentary blip would otherwise stall the checker on this account.
        http::send_with_retry(
            || self.client.post(&self.webhook_url).json(&message),
            "Slack webhook",
            self.retry,
        )
        .await?;

        Ok(())
    }
}

/// Builds an actions block containing the "Delete Account" button for post-suspension messages.
/// (DELETE /api/v1/admin/accounts/:id is only valid for suspended accounts.)
/// Pass the suspend button's value JSON (ButtonValue) as value_json, and an account handle
/// already run through [`sanitize_mrkdwn`] — this does not escape it again.
pub fn delete_actions_block(value_json: &str, safe_acct: &str) -> Value {
    confirm_actions_block(
        DELETE_ACTION_ID,
        &t!("btn_delete"),
        value_json,
        &t!("btn_delete_title"),
        &t!("btn_delete_confirm", acct = safe_acct),
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
                    "text": truncate_mrkdwn(confirm_text, CONFIRM_TEXT_MAX_CHARS)
                },
                "confirm": { "type": "plain_text", "text": confirm_label },
                "deny": { "type": "plain_text", "text": t!("btn_cancel").to_string() }
            }
        }]
    })
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut truncated: String = s.chars().take(max_chars - 1).collect();
    truncated.push('…');
    truncated
}

/// Truncates text that has been through [`sanitize_mrkdwn`], without cutting a trailing
/// `&...;` entity in half (a bare `&am` would render as literal text).
pub(crate) fn truncate_mrkdwn(s: &str, max_chars: usize) -> String {
    let truncated = truncate_chars(s, max_chars);
    // Only a shortened string can end mid-entity, and the ellipsis is what marks that case.
    if !truncated.ends_with('…') {
        return truncated;
    }
    match truncated.rfind('&') {
        Some(pos) if !truncated[pos..].contains(';') => format!("{}…", &truncated[..pos]),
        _ => truncated,
    }
}

/// Prepares untrusted text for embedding in an mrkdwn template.
///
/// Escapes the three characters Slack treats as control sequences, so the content cannot inject
/// links, user mentions, or broadcasts such as `<!channel>`, and folds line breaks so it cannot
/// forge extra lines in the notification (mrkdwn offers no way to escape a newline). Every
/// account-, LLM-, or error-derived value interpolated into a locale template goes through this.
///
/// Not idempotent: applying it twice renders the escapes literally.
pub(crate) fn sanitize_mrkdwn(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
        assert_eq!(truncate_chars("abc", 0), "");
    }

    #[test]
    fn truncate_mrkdwn_does_not_split_an_escaped_entity() {
        // "A&amp;B" cut at 6 chars would end in "&am" without the entity guard.
        assert_eq!(truncate_mrkdwn(&sanitize_mrkdwn("A&B"), 6), "A…");
        assert_eq!(truncate_mrkdwn("a&amp;bcd", 8), "a&amp;b…");
        // Untruncated text is returned untouched.
        assert_eq!(truncate_mrkdwn("a&amp;b", 8), "a&amp;b");
    }

    #[test]
    fn mrkdwn_control_sequences_are_escaped() {
        assert_eq!(
            sanitize_mrkdwn("A & B <!channel> <https://example.com>"),
            "A &amp; B &lt;!channel&gt; &lt;https://example.com&gt;"
        );
    }

    #[test]
    fn sanitized_text_cannot_forge_extra_lines() {
        assert_eq!(
            sanitize_mrkdwn("spammer\n• Account: `admin@example.com`"),
            "spammer • Account: `admin@example.com`"
        );
        assert_eq!(sanitize_mrkdwn("  padded\tname  "), "padded name");
    }
}
