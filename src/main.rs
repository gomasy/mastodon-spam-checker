mod config;
mod http;
mod llm;
mod mastodon;
mod postgres;
mod redis;
mod server;
mod slack;
mod text;

use anyhow::{Context, Result, bail};
use rust_i18n::t;
use tracing::{error, info, warn};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

rust_i18n::i18n!("locales", fallback = "en");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Required before TLS is first used because reqwest is built with rustls-no-provider.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        bail!("failed to install rustls crypto provider");
    }

    dotenvy::dotenv().ok();

    let locale = std::env::var("APP_LANG").unwrap_or_else(|_| "en".to_string());
    rust_i18n::set_locale(&locale);

    // Use the lightweight Targets filter instead of EnvFilter to avoid pulling in the regex crate.
    // Honour RUST_LOG if set; otherwise default to INFO for this crate only.
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
        None => check(false).await,
        Some("serve") => server::run(config::ServeConfig::from_env()?).await,
        Some("dry-run") => check(true).await,
        Some(cmd) => {
            bail!("unknown subcommand: {cmd} (usage: mastodon-spam-checker [serve|dry-run])")
        }
    }
}

/// Fetch new remote accounts and run spam checks (default one-shot mode).
///
/// When `dry_run` is true, skips Slack notifications and cursor updates (classification only).
async fn check(dry_run: bool) -> Result<()> {
    let config = config::Config::from_env()?;
    info!(
        dry_run,
        threshold = config.spam_confidence_threshold,
        "configuration loaded"
    );

    let mut cursor_store = redis::CursorStore::new(&config.redis_url).await?;
    let mastodon =
        mastodon::MastodonClient::new(&config.mastodon_base_url, &config.mastodon_access_token)?;
    let llm = llm::LlmClient::new(
        &config.openai_api_base,
        &config.openai_api_key,
        &config.openai_model,
        config.openai_json_mode,
        http::RetryConfig::default(),
    )?;
    let slack = slack::SlackNotifier::new(&config.slack_webhook_url, config.slack_channel)?;
    let note_writer = match config.postgres {
        Some(ref pg) => Some(
            postgres::ModerationNoteWriter::connect(&pg.database_url, pg.moderator_account_id)
                .await?,
        ),
        None => None,
    };

    // Extract the threshold (Copy type) before the slack_channel is moved into SlackNotifier.
    let threshold = config.spam_confidence_threshold;

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
    let mut spam_detected = 0u32;
    let mut spam_notified = 0u32;
    let mut undetermined = 0u32;
    let mut check_failure = None;

    for account in &accounts {
        let domain = account.domain.as_deref().unwrap_or("?");

        if is_system_account(&account.username, domain) {
            info!(
                username = %account.username,
                domain = %domain,
                "system account, skipping"
            );
        } else {
            info!(
                username = %account.username,
                domain = %domain,
                id = %account.id,
                "checking"
            );

            match check_account(
                &mastodon,
                &llm,
                &slack,
                account,
                threshold,
                dry_run,
                note_writer.as_ref(),
            )
            .await
            {
                Ok(AccountCheckOutcome::Spam { notified }) => {
                    spam_detected += 1;
                    if notified {
                        spam_notified += 1;
                    }
                }
                Ok(AccountCheckOutcome::NotSpam) => {}
                // Already logged at the point of the decision, with the offending reply.
                Ok(AccountCheckOutcome::Undetermined) => undetermined += 1,
                // Reported by the caller rather than logged here, so the failure surfaces exactly once.
                Err(e) => {
                    check_failure = Some(e.context(format!(
                        "check failed for {} (account {}); next run resumes from this account",
                        account.acct(),
                        account.id
                    )));
                    break;
                }
            }
        }

        last_id = Some(account.id.clone());
    }

    if !dry_run {
        if let Some(ref id) = last_id {
            match cursor_store.set_cursor(id).await {
                Ok(()) => info!(cursor = %id, "cursor saved"),
                // A pending check failure is the root cause, so report that one and only log this.
                Err(e) if check_failure.is_some() => {
                    error!(error = format!("{e:#}"), "failed to save cursor");
                }
                Err(e) => return Err(e).context("failed to save cursor"),
            }
        }
    } else {
        info!("dry-run: cursor not updated");
    }

    if let Some(error) = check_failure {
        return Err(error);
    }

    info!(
        total = accounts.len(),
        spam_detected, spam_notified, undetermined, dry_run, "check finished"
    );

    Ok(())
}

enum AccountCheckOutcome {
    NotSpam,
    Spam {
        notified: bool,
    },
    /// The LLM returned no usable verdict. Skipped rather than retried, because retrying would
    /// stall the cursor on this account forever — see [`llm::UnparseableVerdict`].
    Undetermined,
}

/// Fetch one account's posts, run the spam check, and notify Slack if spam confidence meets the threshold.
///
/// `Err` signals a failure; the caller stops without advancing past this account.
async fn check_account(
    mastodon: &mastodon::MastodonClient,
    llm: &llm::LlmClient,
    slack: &slack::SlackNotifier,
    account: &mastodon::AdminAccount,
    threshold: f64,
    dry_run: bool,
    note_writer: Option<&postgres::ModerationNoteWriter>,
) -> Result<AccountCheckOutcome> {
    let statuses = mastodon
        .fetch_statuses(&account.id)
        .await
        .context("failed to fetch statuses")?;

    let domain = account.domain.as_deref().unwrap_or("?");
    let verdict = match llm.check_spam(account, &statuses).await {
        Ok(verdict) => verdict,
        // Aborting here would leave the cursor pointing before this account, so every later run
        // would re-check it and fail the same way. Skip it and keep the run going instead.
        Err(e) if llm::is_unparseable_verdict(&e) => {
            warn!(
                username = %account.username,
                domain = %domain,
                error = format!("{e:#}"),
                "no usable LLM verdict, skipping account"
            );
            return Ok(AccountCheckOutcome::Undetermined);
        }
        Err(e) => return Err(e).context("LLM check failed"),
    };

    if !verdict.spam {
        info!(
            username = %account.username,
            domain = %domain,
            "not spam"
        );
        return Ok(AccountCheckOutcome::NotSpam);
    }

    if verdict.confidence < threshold {
        info!(
            username = %account.username,
            domain = %domain,
            confidence = verdict.confidence,
            threshold = threshold,
            reason = %verdict.reason,
            "spam detected but below confidence threshold, skipping notification"
        );
        return Ok(AccountCheckOutcome::Spam { notified: false });
    }

    warn!(
        username = %account.username,
        domain = %domain,
        confidence = verdict.confidence,
        reason = %verdict.reason,
        "spam detected"
    );

    if dry_run {
        info!(username = %account.username, "dry-run: skip Slack notification");
        return Ok(AccountCheckOutcome::Spam { notified: false });
    }

    slack
        .notify_spam(account, &verdict)
        .await
        .context("failed to send Slack notification")?;

    if let Some(writer) = note_writer {
        let note = t!(
            "note_spam",
            confidence = format!("{:.0}", verdict.confidence * 100.0),
            reason = &verdict.reason,
        );
        if let Err(e) = writer.add_note(&account.id, &note).await {
            error!(error = %e, "failed to add moderation note");
        }
    }

    Ok(AccountCheckOutcome::Spam { notified: true })
}

const SYSTEM_USERNAMES: &[&str] = &["mastodon.internal", "internal.fetch", "system.actor"];

fn is_system_account(username: &str, domain: &str) -> bool {
    SYSTEM_USERNAMES.contains(&username) || username == domain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i18n_keys_resolve() {
        rust_i18n::set_locale("en");
        let val = t!("btn_suspend");
        assert_ne!(
            val, "btn_suspend",
            "EN key 'btn_suspend' was not found (returned raw key)"
        );
        assert!(val.contains("Suspend"), "unexpected EN value: {val}");

        rust_i18n::set_locale("ja");
        let val = t!("btn_suspend");
        assert_ne!(
            val, "btn_suspend",
            "JA key 'btn_suspend' was not found (returned raw key)"
        );
        assert!(val.contains("停止"), "unexpected JA value: {val}");
    }

    #[test]
    fn system_accounts_are_detected() {
        assert!(is_system_account("mastodon.internal", "example.com"));
        assert!(is_system_account("internal.fetch", "example.com"));
        assert!(is_system_account("system.actor", "example.com"));
        // Instance actor (username == domain).
        assert!(is_system_account("example.com", "example.com"));
        assert!(!is_system_account("alice", "example.com"));
    }
}
