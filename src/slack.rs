use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use rust_i18n::t;

use crate::auto_moderation::{AutoModerationOutcome, AutoModerationResult};
use crate::http;
use crate::llm::SpamVerdict;
use crate::mastodon::AdminAccount;
use crate::text::truncate_chars;

const APP_NAME: &str = "Mastodon Spam Checker";

// Action IDs, shared with the serve-mode handler that receives the clicks.
pub const SUSPEND_ACTION_ID: &str = "suspend_account";
/// Appears only in post-suspension messages.
pub const DELETE_ACTION_ID: &str = "delete_account";
pub const CONFIRM_SPAM_ACTION_ID: &str = "confirm_spam";
pub const FALSE_POSITIVE_ACTION_ID: &str = "false_positive";

/// Character limit for Block Kit mrkdwn text objects (shared by section and context blocks).
pub(crate) const TEXT_MAX_CHARS: usize = 3000;
/// Character limit for the Block Kit confirm dialog text.
const CONFIRM_TEXT_MAX_CHARS: usize = 300;

/// What a button carries back to the serve-mode handler when it is clicked.
#[derive(Serialize, Deserialize)]
pub struct ButtonValue {
    pub id: String,
    pub acct: String,
}

#[derive(Serialize)]
struct SlackMessage {
    /// With blocks present, this is the notification and preview fallback.
    text: String,
    blocks: Value,
    username: &'static str,
    icon_emoji: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<String>,
}

#[derive(Clone)]
pub struct SlackNotifier {
    client: Client,
    webhook_url: String,
    mastodon_base_url: String,
    channel: Option<String>,
    retry: http::RetryConfig,
}

impl SlackNotifier {
    pub fn new(
        webhook_url: &str,
        channel: Option<String>,
        mastodon_base_url: &str,
    ) -> Result<Self> {
        Ok(Self {
            client: http::client(Duration::from_secs(30))?,
            webhook_url: webhook_url.to_string(),
            mastodon_base_url: mastodon_base_url.trim_end_matches('/').to_string(),
            channel,
            retry: http::RetryConfig::default(),
        })
    }

    pub async fn notify_spam(
        &self,
        account: &AdminAccount,
        verdict: &SpamVerdict,
        auto: Option<&AutoModerationOutcome>,
    ) -> Result<()> {
        let acct = account.acct();
        let safe_acct = sanitize_mrkdwn(&acct);
        let admin_url = format!("{}/admin/accounts/{}", self.mastodon_base_url, account.id);
        let text = t!(
            "spam_detected",
            acct = &safe_acct,
            display_name = sanitize_mrkdwn(&account.account.display_name),
            url = sanitize_mrkdwn(&account.account.url),
            confidence = format!("{:.0}", verdict.confidence * 100.0),
            reason = sanitize_mrkdwn(&verdict.reason),
            admin_url = &admin_url,
        )
        .to_string();
        let text = match auto {
            Some(auto) => format!("{}\n{text}", auto_moderation_line(auto)),
            None => text,
        };
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
            actions_block(auto, &value, &safe_acct),
        ]);

        let message = SlackMessage {
            text,
            blocks,
            username: APP_NAME,
            icon_emoji: ":scales:",
            channel: self.channel.clone(),
        };

        // Retried, because the caller aborts the whole run on a notification error: a momentary
        // blip would otherwise stall the checker on this account.
        http::send_with_retry(
            || self.client.post(&self.webhook_url).json(&message),
            "Slack webhook",
            self.retry,
        )
        .await?;

        Ok(())
    }
}

/// The "Delete Account" button, for a message whose account has just been suspended — the endpoint
/// behind it rejects anything else. `value_json` is the suspend button's [`ButtonValue`], and
/// `safe_acct` must already be through [`sanitize_mrkdwn`]; this does not escape it again.
pub fn delete_actions_block(value_json: &str, safe_acct: &str) -> Value {
    json!({
        "type": "actions",
        "elements": [delete_button(value_json, safe_acct)]
    })
}

fn delete_button(value_json: &str, safe_acct: &str) -> Value {
    confirm_button(
        DELETE_ACTION_ID,
        &t!("btn_delete"),
        value_json,
        &t!("btn_delete_title"),
        &t!("btn_delete_confirm", acct = safe_acct),
        &t!("btn_delete_do"),
    )
}

/// The headline for an auto-moderated account, placed above the usual details.
fn auto_moderation_line(auto: &AutoModerationOutcome) -> String {
    let matched = sanitize_mrkdwn(&auto.matched.describe());
    match &auto.result {
        AutoModerationResult::Suspended => t!("auto_suspended", matched = matched),
        AutoModerationResult::Deleted => t!("auto_deleted", matched = matched),
        AutoModerationResult::DeleteFailed(error) => t!(
            "auto_delete_failed",
            matched = matched,
            error = sanitize_mrkdwn(error)
        ),
        AutoModerationResult::Failed(error) => t!(
            "auto_failed",
            matched = matched,
            error = sanitize_mrkdwn(error)
        ),
    }
    .to_string()
}

/// The buttons that still make sense after what auto-moderation did: none that would repeat it,
/// and the feedback buttons always, so a false positive can still be recorded.
fn actions_block(auto: Option<&AutoModerationOutcome>, value_json: &str, safe_acct: &str) -> Value {
    let primary = match auto.map(|auto| &auto.result) {
        None | Some(AutoModerationResult::Failed(_)) => Some(suspend_button(value_json, safe_acct)),
        Some(AutoModerationResult::Suspended | AutoModerationResult::DeleteFailed(_)) => {
            Some(delete_button(value_json, safe_acct))
        }
        Some(AutoModerationResult::Deleted) => None,
    };
    let feedback = [
        (CONFIRM_SPAM_ACTION_ID, t!("btn_confirm_spam")),
        (FALSE_POSITIVE_ACTION_ID, t!("btn_false_positive")),
    ]
    .map(|(action_id, label)| {
        json!({
            "type": "button",
            "action_id": action_id,
            "text": { "type": "plain_text", "text": label.to_string() },
            "value": value_json,
        })
    });
    let elements: Vec<Value> = primary.into_iter().chain(feedback).collect();
    json!({ "type": "actions", "elements": elements })
}

fn suspend_button(value_json: &str, safe_acct: &str) -> Value {
    confirm_button(
        SUSPEND_ACTION_ID,
        &t!("btn_suspend"),
        value_json,
        &t!("btn_suspend_title"),
        &t!("btn_suspend_confirm", acct = safe_acct),
        &t!("btn_suspend_do"),
    )
}

fn confirm_button(
    action_id: &str,
    label: &str,
    value: &str,
    confirm_title: &str,
    confirm_text: &str,
    confirm_label: &str,
) -> Value {
    json!({
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
    })
}

/// Truncates text that has been through [`sanitize_mrkdwn`], without cutting a trailing
/// `&...;` entity in half (a bare `&am` would render as literal text).
pub(crate) fn truncate_mrkdwn(s: &str, max_chars: usize) -> String {
    let truncated = truncate_chars(s, max_chars);
    // Only a shortened string can end mid-entity, and the ellipsis marks that case.
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
/// links, mentions, or broadcasts such as `<!channel>`, and folds line breaks, which mrkdwn offers
/// no way to escape, so it cannot forge extra lines. Every account-, LLM-, or error-derived value
/// interpolated into a locale template goes through this.
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

    fn action_ids(block: &Value) -> Vec<String> {
        block["elements"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|element| element["action_id"].as_str().map(str::to_string))
            .collect()
    }

    #[test]
    fn auto_moderated_messages_offer_only_what_is_left_to_do() {
        use crate::auto_moderation::KnownSpamMatch;
        let value = r#"{"id":"42","acct":"alice@example.com"}"#;
        let outcome = |result| AutoModerationOutcome {
            matched: KnownSpamMatch::Bio { accounts: 1 },
            result,
        };
        let ids = |result| action_ids(&actions_block(Some(&outcome(result)), value, "alice"));
        for result in [
            AutoModerationResult::Suspended,
            AutoModerationResult::DeleteFailed("x".into()),
        ] {
            assert_eq!(
                ids(result),
                [
                    DELETE_ACTION_ID,
                    CONFIRM_SPAM_ACTION_ID,
                    FALSE_POSITIVE_ACTION_ID
                ]
            );
        }
        assert_eq!(
            ids(AutoModerationResult::Deleted),
            [CONFIRM_SPAM_ACTION_ID, FALSE_POSITIVE_ACTION_ID]
        );
        assert_eq!(
            ids(AutoModerationResult::Failed("x".into())),
            [
                SUSPEND_ACTION_ID,
                CONFIRM_SPAM_ACTION_ID,
                FALSE_POSITIVE_ACTION_ID
            ]
        );
    }

    #[test]
    fn spam_actions_include_feedback_and_suspension() {
        let block = actions_block(
            None,
            r#"{"id":"42","acct":"alice@example.com"}"#,
            "alice@example.com",
        );
        let action_ids: Vec<&str> = block["elements"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|element| element["action_id"].as_str())
            .collect();
        assert_eq!(
            action_ids,
            [
                SUSPEND_ACTION_ID,
                CONFIRM_SPAM_ACTION_ID,
                FALSE_POSITIVE_ACTION_ID
            ]
        );
    }
}
