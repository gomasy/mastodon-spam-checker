use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::http;
use crate::llm::SpamVerdict;
use crate::mastodon::AdminAccount;

const APP_NAME: &str = "Mastodon Spam Checker";

/// 停止ボタンの action_id(serve モードのハンドラと共有)
pub const SUSPEND_ACTION_ID: &str = "suspend_account";
/// 削除ボタンの action_id(停止後のメッセージにのみ現れる)
pub const DELETE_ACTION_ID: &str = "delete_account";

/// Block Kit の text オブジェクト(mrkdwn)の文字数上限(section / context 共通)
pub(crate) const TEXT_MAX_CHARS: usize = 3000;
/// Block Kit の confirm ダイアログ text の文字数上限
const CONFIRM_TEXT_MAX_CHARS: usize = 300;

/// 停止ボタンの value に埋め込む情報(生成側と serve モードのハンドラで共有)
#[derive(Serialize, Deserialize)]
pub struct ButtonValue {
    pub id: String,
    pub acct: String,
}

#[derive(Serialize)]
struct SlackMessage {
    // blocks 使用時、text は通知やプレビューのフォールバックとして使われる
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
        let text = format!(
            ":warning: *スパムアカウント検出*\n\
             • アカウント: `{}`\n\
             • 表示名: {}\n\
             • URL: {}\n\
             • 確信度: {:.0}%\n\
             • 理由: {}",
            acct,
            account.account.display_name,
            account.account.url,
            verdict.confidence * 100.0,
            verdict.reason,
        );

        // serve モードのハンドラが停止処理に使う情報を value に埋め込む
        let value = serde_json::to_string(&ButtonValue {
            id: account.id.clone(),
            acct: acct.clone(),
        })
        .context("failed to serialize button value")?;
        let blocks = json!([
            {
                "type": "section",
                // LLM の reason やプロフィール由来の文字列は無制限のため、
                // 上限超過で invalid_blocks になり通知ごと失われるのを防ぐ
                "text": { "type": "mrkdwn", "text": truncate_chars(&text, TEXT_MAX_CHARS) }
            },
            {
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "action_id": SUSPEND_ACTION_ID,
                    "style": "danger",
                    "text": { "type": "plain_text", "text": "アカウントを停止" },
                    "value": value,
                    "confirm": {
                        "style": "danger",
                        "title": { "type": "plain_text", "text": "アカウント停止" },
                        "text": {
                            "type": "mrkdwn",
                            "text": truncate_chars(
                                &format!("`{acct}` を停止します。よろしいですか?"),
                                CONFIRM_TEXT_MAX_CHARS,
                            )
                        },
                        "confirm": { "type": "plain_text", "text": "停止する" },
                        "deny": { "type": "plain_text", "text": "キャンセル" }
                    }
                }]
            }
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

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Slack webhook error (HTTP {status}): {body}");
        }

        Ok(())
    }
}

/// 停止後のメッセージに差し込む「アカウントを削除」ボタンの actions ブロック
/// (DELETE /api/v1/admin/accounts/:id は停止済みアカウントにのみ有効)
/// value_json には停止ボタンの value(ButtonValue の JSON)をそのまま渡す
pub fn delete_actions_block(value_json: &str, acct: &str) -> Value {
    json!({
        "type": "actions",
        "elements": [{
            "type": "button",
            "action_id": DELETE_ACTION_ID,
            "style": "danger",
            "text": { "type": "plain_text", "text": "アカウントを削除" },
            "value": value_json,
            "confirm": {
                "style": "danger",
                "title": { "type": "plain_text", "text": "アカウント削除" },
                "text": {
                    "type": "mrkdwn",
                    "text": truncate_chars(
                        &format!("`{acct}` のデータを完全に削除します。この操作は取り消せません。よろしいですか?"),
                        CONFIRM_TEXT_MAX_CHARS,
                    )
                },
                "confirm": { "type": "plain_text", "text": "削除する" },
                "deny": { "type": "plain_text", "text": "キャンセル" }
            }
        }]
    })
}

/// 文字数(chars)で切り詰め、超過時は末尾を … にする
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
        // マルチバイト文字でもバイト境界でパニックしない
        assert_eq!(truncate_chars("あいうえお", 3), "あい…");
        assert_eq!(truncate_chars("あいうえお", 3).chars().count(), 3);
    }
}
