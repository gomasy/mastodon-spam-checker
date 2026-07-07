mod config;
mod llm;
mod mastodon;
mod redis;
mod slack;

use anyhow::Result;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mastodon_spam_checker=info".parse()?),
        )
        .init();
    let config = config::Config::from_env()?;
    info!("設定読み込み完了");

    let mut cursor_store = redis::CursorStore::new(&config.redis_url).await?;
    let mastodon = mastodon::MastodonClient::new(
        &config.mastodon_base_url,
        &config.mastodon_access_token,
    );
    let llm = llm::LlmClient::new(
        &config.openai_api_base,
        &config.openai_api_key,
        &config.openai_model,
    );
    let slack = slack::SlackNotifier::new(&config.slack_webhook_url, config.slack_channel);

    let cursor = cursor_store.get_cursor().await?;
    info!(cursor = cursor.as_deref().unwrap_or("(none)"), "前回カーソル");

    let accounts = mastodon
        .fetch_remote_accounts(cursor.as_deref())
        .await?;

    if accounts.is_empty() {
        info!("新しいリモートアカウントはありません");
        return Ok(());
    }

    info!(count = accounts.len(), "新規リモートアカウント取得");

    let mut last_id: Option<String> = None;
    let mut spam_count = 0u32;

    for account in &accounts {
        let domain = account.domain.as_deref().unwrap_or("?");

        if is_system_account(&account.username, domain) {
            info!(
                username = %account.username,
                domain = %domain,
                "システムアカウント、スキップ"
            );
            last_id = Some(account.id.clone());
            continue;
        }

        info!(
            username = %account.username,
            domain = %domain,
            id = %account.id,
            "チェック中"
        );

        let statuses = match mastodon.fetch_statuses(&account.id).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    username = %account.username,
                    error = %e,
                    "投稿取得失敗、スキップ"
                );
                last_id = Some(account.id.clone());
                continue;
            }
        };

        match llm.check_spam(account, &statuses).await {
            Ok(verdict) => {
                if verdict.spam {
                    spam_count += 1;
                    warn!(
                        username = %account.username,
                        domain = %domain,
                        confidence = verdict.confidence,
                        reason = %verdict.reason,
                        "スパム検出"
                    );
                    if let Err(e) = slack.notify_spam(account, &verdict).await {
                        error!(error = %e, "Slack 通知失敗");
                    }
                } else {
                    info!(
                        username = %account.username,
                        domain = %domain,
                        "正常"
                    );
                }
            }
            Err(e) => {
                error!(
                    username = %account.username,
                    error = %e,
                    "LLM 判定失敗、スキップ"
                );
            }
        }

        last_id = Some(account.id.clone());
    }

    if let Some(ref id) = last_id {
        cursor_store.set_cursor(id).await?;
        info!(cursor = %id, "カーソル保存完了");
    }

    info!(
        total = accounts.len(),
        spam = spam_count,
        "チェック完了"
    );

    Ok(())
}

const SYSTEM_USERNAMES: &[&str] = &["mastodon.internal", "internal.fetch", "system.actor"];

fn is_system_account(username: &str, domain: &str) -> bool {
    SYSTEM_USERNAMES.contains(&username) || username == domain
}
