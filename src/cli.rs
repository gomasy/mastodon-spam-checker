//! Command-line entry points.
//!
//! Each subcommand assembles what it needs from the environment and hands the work to
//! [`crate::check`]. The ones that write shared state run under a Redis lease.

use std::future::Future;

use anyhow::{Context, Result, bail};
use tracing::{error, info, warn};

use crate::chain;
use crate::check::{self, CheckServices, ServiceOptions};
use crate::config::{self, Config, DetectionConfig, parse_positive_usize};
use crate::ids::{numeric_id_cmp, validate_account_id};
use crate::redis::{CampaignContext, StateStore};
use crate::{server, signals};

pub fn usage() -> &'static str {
    "usage: mastodon-spam-checker [serve|dry-run|check-account <ID>|cursor|retry-failed [--max N]|backfill --from ID [--to ID] [--max N] [--notify]]"
}

pub async fn dispatch(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        None => exclusive_run(|store| check(store, false)).await,
        Some("serve") if args.len() == 1 => server::run(config::ServeConfig::from_env()?).await,
        Some("dry-run") if args.len() == 1 => check(connect_store().await?, true).await,
        Some("check-account") => check_account_command(&args[1..]).await,
        Some("cursor") => cursor_command(&args[1..]).await,
        Some("retry-failed") => {
            let max = parse_optional_max(&args[1..], 100)?;
            exclusive_run(|store| retry_failed_command(store, max)).await
        }
        Some("backfill") => {
            let options = BackfillOptions::parse(&args[1..])?;
            exclusive_run(|store| backfill_command(store, options)).await
        }
        _ => bail!(usage()),
    }
}

async fn connect_store() -> Result<StateStore> {
    StateStore::new(&config::redis_url_env()?).await
}

/// Runs `operation` as the only checker touching shared state, handing it the store the lease is
/// held on so the run opens one Redis connection rather than two.
///
/// A renewal task keeps the lease past its own expiry. Losing it aborts the operation: a second run
/// may already have started on the strength of the expired lease.
async fn exclusive_run<F, Fut>(operation: F) -> Result<()>
where
    F: FnOnce(StateStore) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let store = connect_store().await?;
    let token = store.acquire_run_lease().await?;
    let renewal_store = store.clone();
    let renewal_token = token.clone();
    let renewal = async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                renewal_store.renew_run_lease(&renewal_token),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => break Err(error),
                Err(_) => break Err(anyhow::anyhow!("timed out renewing run lease")),
            }
        }
    };
    let operation = operation(store.clone());
    tokio::pin!(operation);
    tokio::pin!(renewal);
    let result = tokio::select! {
        result = &mut operation => result,
        lease_result = &mut renewal => lease_result,
    };
    if let Err(error) = store.release_run_lease(&token).await {
        if result.is_ok() {
            return Err(error);
        }
        error!(error = %chain(&error), "failed to release run lease");
    }
    result
}

async fn check(store: StateStore, dry_run: bool) -> Result<()> {
    let config = Config::from_env(!dry_run)?;
    info!(
        dry_run,
        threshold = config.detection.spam_confidence_threshold,
        max_accounts = config.max_accounts_per_run,
        concurrency = config.check_concurrency,
        "configuration loaded"
    );

    if !dry_run {
        let retention_applied = store.cleanup_expired_records().await?;
        if retention_applied > 0 {
            info!(retention_applied, "applied Redis state retention");
        }
    }
    let cursor = store.get_cursor().await?;
    info!(
        cursor = cursor.as_deref().unwrap_or("(none)"),
        "previous cursor"
    );

    let services = CheckServices::build(
        &config,
        store.clone(),
        ServiceOptions {
            notify: !dry_run,
            persist: !dry_run,
            retry_pending: false,
        },
    )
    .await?;
    let accounts = services
        .mastodon()
        .fetch_remote_accounts(cursor.as_deref(), None, config.max_accounts_per_run)
        .await?;
    if accounts.is_empty() {
        info!("no new remote accounts");
        return Ok(());
    }

    let summary = check::process_accounts(accounts, services, config.check_concurrency).await;
    if dry_run {
        info!("dry-run: cursor and account jobs not updated");
    } else if let Some(id) = summary.last_contiguous_id() {
        store
            .set_cursor(id)
            .await
            .context("failed to save cursor")?;
        info!(cursor = %id, "cursor saved");
    }

    summary.finish(dry_run)
}

async fn check_account_command(args: &[String]) -> Result<()> {
    let [account_id] = args else {
        bail!("usage: mastodon-spam-checker check-account <ID>");
    };
    validate_account_id(account_id)?;
    let (mastodon, llm) = check::detection_clients(&DetectionConfig::from_env()?)?;
    let account = mastodon.fetch_admin_account(account_id).await?;
    let statuses = mastodon.fetch_statuses(account_id).await?;
    let signals = signals::analyze(&account, &statuses);
    // A one-off inspection touches no state, so it carries no campaign history.
    let verdict = llm
        .check_spam(&account, &statuses, &signals, &CampaignContext::default())
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "account_id": account.id,
            "acct": account.acct(),
            "spam": verdict.spam,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        }))?
    );
    Ok(())
}

async fn cursor_command(args: &[String]) -> Result<()> {
    if !args.is_empty() {
        bail!("usage: mastodon-spam-checker cursor");
    }
    let store = connect_store().await?;
    println!(
        "{}",
        store.get_cursor().await?.as_deref().unwrap_or("(none)")
    );
    Ok(())
}

async fn retry_failed_command(store: StateStore, max: usize) -> Result<()> {
    let config = Config::from_env(true)?;
    // Walked well past `max`: entries a moderator has since resolved are dropped as they are
    // found, rather than counting against the batch.
    let ids = store.failed_ids(max.saturating_mul(10)).await?;
    if ids.is_empty() {
        info!("retry queue is empty");
        return Ok(());
    }
    let services = CheckServices::build(
        &config,
        store.clone(),
        ServiceOptions {
            notify: true,
            persist: true,
            retry_pending: true,
        },
    )
    .await?;

    let mut accounts = Vec::with_capacity(max.min(ids.len()));
    let mut unavailable = 0usize;
    let mut fetch_failures = 0usize;
    for id in ids {
        match services.mastodon().fetch_admin_account_optional(&id).await {
            Ok(Some(account)) => accounts.push(account),
            Ok(None) => {
                warn!(account_id = %id, "queued account no longer exists, marking terminal");
                store.mark_unavailable(&id).await?;
                unavailable += 1;
            }
            Err(error) => {
                warn!(account_id = %id, error = %chain(&error), "failed to fetch queued account, leaving it queued");
                fetch_failures += 1;
            }
        }
        if accounts.len() == max {
            break;
        }
    }
    if accounts.is_empty() {
        if fetch_failures > 0 {
            bail!("no queued account could be fetched from Mastodon");
        }
        info!(
            unavailable,
            "retry queue contained only unavailable accounts"
        );
        return Ok(());
    }
    check::process_accounts(accounts, services, config.check_concurrency)
        .await
        .finish(false)
}

async fn backfill_command(store: StateStore, options: BackfillOptions) -> Result<()> {
    let config = Config::from_env(options.notify)?;
    let services = CheckServices::build(
        &config,
        store,
        ServiceOptions {
            notify: options.notify,
            // Backfills persist results even when notifications are intentionally disabled.
            persist: true,
            retry_pending: false,
        },
    )
    .await?;
    let accounts = services
        .mastodon()
        .fetch_remote_accounts(Some(&options.from), options.to.as_deref(), options.max)
        .await?;
    check::process_accounts(accounts, services, config.check_concurrency)
        .await
        .finish(false)
}

struct BackfillOptions {
    from: String,
    to: Option<String>,
    max: usize,
    notify: bool,
}

impl BackfillOptions {
    fn parse(args: &[String]) -> Result<Self> {
        let mut from = None;
        let mut to = None;
        let mut max = 1_000;
        let mut notify = false;
        // Each flag takes its value in the arm that matched it, so no already-decided flag is
        // matched a second time.
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--from" => {
                    let id = value()?;
                    validate_account_id(id)?;
                    from = Some(id.clone());
                }
                "--to" => {
                    let id = value()?;
                    validate_account_id(id)?;
                    to = Some(id.clone());
                }
                "--max" => max = parse_positive_usize(value()?, "--max")?,
                "--notify" => notify = true,
                unknown => bail!("unknown backfill option: {unknown}"),
            }
        }
        let from = from.context("backfill requires --from <ID>")?;
        if let Some(to) = &to
            && numeric_id_cmp(&from, to) != std::cmp::Ordering::Less
        {
            bail!("backfill requires --from to be less than --to");
        }
        Ok(Self {
            from,
            to,
            max,
            notify,
        })
    }
}

fn parse_optional_max(args: &[String], default: usize) -> Result<usize> {
    match args {
        [] => Ok(default),
        [flag, value] if flag == "--max" => parse_positive_usize(value, "--max"),
        _ => bail!("usage: mastodon-spam-checker retry-failed [--max N]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backfill_options_are_parsed() {
        let options = BackfillOptions::parse(&[
            "--from".into(),
            "10".into(),
            "--to".into(),
            "20".into(),
            "--max".into(),
            "5".into(),
            "--notify".into(),
        ])
        .unwrap();
        assert_eq!(options.from, "10");
        assert_eq!(options.to.as_deref(), Some("20"));
        assert_eq!(options.max, 5);
        assert!(options.notify);
        assert!(
            BackfillOptions::parse(&["--from".into(), "20".into(), "--to".into(), "10".into(),])
                .is_err()
        );
    }

    #[test]
    fn backfill_rejects_malformed_options() {
        let parse = |args: &[&str]| {
            BackfillOptions::parse(&args.iter().map(|a| (*a).to_string()).collect::<Vec<_>>())
        };
        assert!(parse(&["--from"]).is_err(), "--from without a value");
        assert!(parse(&["--to", "10"]).is_err(), "--to without --from");
        assert!(parse(&["--from", "abc"]).is_err(), "non-numeric ID");
        assert!(parse(&["--from", "1", "--max", "0"]).is_err(), "--max 0");
        assert!(parse(&["--wat"]).is_err(), "unknown flag");
        // --notify takes no value, so it must not swallow the flag that follows it.
        let options = parse(&["--notify", "--from", "10"]).unwrap();
        assert!(options.notify);
        assert_eq!(options.from, "10");
    }

    #[test]
    fn retry_max_is_optional_and_validated() {
        assert_eq!(parse_optional_max(&[], 100).unwrap(), 100);
        assert_eq!(
            parse_optional_max(&["--max".into(), "25".into()], 100).unwrap(),
            25
        );
        assert!(parse_optional_max(&["--max".into(), "0".into()], 100).is_err());
        assert!(parse_optional_max(&["--max".into()], 100).is_err());
        assert!(parse_optional_max(&["--wat".into(), "1".into()], 100).is_err());
    }
}
