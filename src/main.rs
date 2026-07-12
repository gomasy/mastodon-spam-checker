mod config;
mod http;
mod llm;
mod mastodon;
mod redis;
mod server;
mod slack;

use anyhow::{Result, bail};
use tracing::{error, info, warn};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // reqwest を rustls-no-provider で使うため、TLS 初回利用前にプロバイダの登録が必須
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    dotenvy::dotenv().ok();

    // EnvFilter は regex を引き込みバイナリが肥大化するため、軽量な Targets で代替。
    // RUST_LOG が設定されていればそれを優先、なければ本クレートのみ info。
    let filter: Targets = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            Targets::new().with_target("mastodon_spam_checker", tracing::Level::INFO)
        });
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    match std::env::args().nth(1).as_deref() {
        None => check().await,
        Some("serve") => server::run(config::ServeConfig::from_env()?).await,
        Some(cmd) => bail!("unknown subcommand: {cmd} (usage: mastodon-spam-checker [serve])"),
    }
}

/// 新規リモートアカウントを取得してスパム判定する(デフォルトの一発実行モード)
async fn check() -> Result<()> {
    let config = config::Config::from_env()?;
    info!("configuration loaded");

    let mut cursor_store = redis::CursorStore::new(&config.redis_url).await?;
    let mastodon =
        mastodon::MastodonClient::new(&config.mastodon_base_url, &config.mastodon_access_token);
    let llm = llm::LlmClient::new(
        &config.openai_api_base,
        &config.openai_api_key,
        &config.openai_model,
        config.openai_json_mode,
    );
    let slack = slack::SlackNotifier::new(&config.slack_webhook_url, config.slack_channel);

    let cursor = cursor_store.get_cursor().await?;
    info!(
        cursor = cursor.as_deref().unwrap_or("(none)"),
        "previous cursor"
    );

    let accounts = mastodon.fetch_remote_accounts(cursor.as_deref()).await?;

    if accounts.is_empty() {
        info!("no new remote accounts");
        return Ok(());
    }

    info!(count = accounts.len(), "fetched new remote accounts");

    let mut last_id: Option<String> = None;
    let mut spam_count = 0u32;

    for account in &accounts {
        let domain = account.domain.as_deref().unwrap_or("?");

        if is_system_account(&account.username, domain) {
            info!(
                username = %account.username,
                domain = %domain,
                "system account, skipping"
            );
            last_id = Some(account.id.clone());
            continue;
        }

        info!(
            username = %account.username,
            domain = %domain,
            id = %account.id,
            "checking"
        );

        // リトライ可能なエラーではカーソルを進めず中断し、次回実行でこのアカウントから再開する
        let statuses = match mastodon.fetch_statuses(&account.id).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    username = %account.username,
                    error = %e,
                    "failed to fetch statuses; aborting, next run resumes from this account"
                );
                break;
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
                        "spam detected"
                    );
                    if let Err(e) = slack.notify_spam(account, &verdict).await {
                        error!(error = %e, "failed to send Slack notification");
                    }
                } else {
                    info!(
                        username = %account.username,
                        domain = %domain,
                        "not spam"
                    );
                }
            }
            Err(e) => {
                error!(
                    username = %account.username,
                    error = %e,
                    "LLM check failed; aborting, next run resumes from this account"
                );
                break;
            }
        }

        last_id = Some(account.id.clone());
    }

    if let Some(ref id) = last_id {
        cursor_store.set_cursor(id).await?;
        info!(cursor = %id, "cursor saved");
    }

    info!(total = accounts.len(), spam = spam_count, "check finished");

    Ok(())
}

const SYSTEM_USERNAMES: &[&str] = &["mastodon.internal", "internal.fetch", "system.actor"];

fn is_system_account(username: &str, domain: &str) -> bool {
    SYSTEM_USERNAMES.contains(&username) || username == domain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_accounts_are_detected() {
        assert!(is_system_account("mastodon.internal", "example.com"));
        assert!(is_system_account("internal.fetch", "example.com"));
        assert!(is_system_account("system.actor", "example.com"));
        // インスタンスアクター(ユーザー名 == ドメイン)
        assert!(is_system_account("example.com", "example.com"));
        assert!(!is_system_account("alice", "example.com"));
    }
}
