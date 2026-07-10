mod config;
mod llm;
mod mastodon;
mod redis;
mod slack;

use anyhow::Result;
use tracing::{error, info, warn};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // reqwest を rustls-no-provider で使うため、TLS 初回利用前にプロバイダの登録が必須
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls 暗号プロバイダの登録に失敗");

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
    let config = config::Config::from_env()?;
    info!("設定読み込み完了");

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
        "前回カーソル"
    );

    let accounts = mastodon.fetch_remote_accounts(cursor.as_deref()).await?;

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

        // リトライ可能なエラーではカーソルを進めず中断し、次回実行でこのアカウントから再開する
        let statuses = match mastodon.fetch_statuses(&account.id).await {
            Ok(s) => s,
            Err(e) => {
                error!(
                    username = %account.username,
                    error = %e,
                    "投稿取得失敗、中断して次回このアカウントから再開"
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
                    "LLM 判定失敗、中断して次回このアカウントから再開"
                );
                break;
            }
        }

        last_id = Some(account.id.clone());
    }

    if let Some(ref id) = last_id {
        cursor_store.set_cursor(id).await?;
        info!(cursor = %id, "カーソル保存完了");
    }

    info!(total = accounts.len(), spam = spam_count, "チェック完了");

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
