mod config;
mod http;
mod ids;
mod llm;
mod mastodon;
mod postgres;
mod redis;
mod server;
mod signals;
mod slack;
mod text;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rust_i18n::t;
use tracing::{error, info, warn};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::parse_positive_usize;
use crate::ids::{numeric_id_cmp, validate_account_id};
use crate::redis::{CampaignContext, JobRecord, JobStatus, StateStore};

rust_i18n::i18n!("locales", fallback = "en");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        bail!("failed to install rustls crypto provider");
    }

    dotenvy::dotenv().ok();
    let locale = std::env::var("APP_LANG").unwrap_or_else(|_| "en".to_string());
    rust_i18n::set_locale(&locale);
    init_logging();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => exclusive_run(check(false)).await,
        Some("serve") if args.len() == 1 => server::run(config::ServeConfig::from_env()?).await,
        Some("dry-run") if args.len() == 1 => check(true).await,
        Some("check-account") => check_account_command(&args[1..]).await,
        Some("cursor") => cursor_command(&args[1..]).await,
        Some("retry-failed") => exclusive_run(retry_failed_command(&args[1..])).await,
        Some("backfill") => exclusive_run(backfill_command(&args[1..])).await,
        _ => bail!(usage()),
    }
}

async fn exclusive_run(operation: impl Future<Output = Result<()>>) -> Result<()> {
    let store = StateStore::new(&config::redis_url_env()?).await?;
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

fn init_logging() {
    let filter: Targets = std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| {
            Targets::new().with_target("mastodon_spam_checker", tracing::Level::INFO)
        });
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();
}

/// Renders an error together with the causes its context wraps.
///
/// `anyhow`'s plain `Display` — what `%error` in a log line reaches for — prints only the
/// outermost context, so a failure arrives as "failed to read account job from Redis" with the
/// Redis error that actually explains it dropped. Every logged failure goes through this instead.
/// The errors that reach `main` need no help: returning them prints the chain already.
pub fn chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

fn usage() -> &'static str {
    "usage: mastodon-spam-checker [serve|dry-run|check-account <ID>|cursor|retry-failed [--max N]|backfill --from ID [--to ID] [--max N] [--notify]]"
}

struct CheckServices {
    mastodon: mastodon::MastodonClient,
    llm: llm::LlmClient,
    slack: Option<slack::SlackNotifier>,
    /// Present for every run. Dry runs still read campaign context through it; `persist` is what
    /// decides whether anything is written back.
    store: StateStore,
    note_writer: Option<postgres::ModerationNoteWriter>,
    threshold: f64,
    persist: bool,
    retry_pending: bool,
}

#[derive(Debug)]
enum AccountCheckOutcome {
    Existing,
    System,
    NotSpam,
    Spam { notified: bool },
    Undetermined,
}

struct CheckedAccount {
    outcome: AccountCheckOutcome,
    status: JobStatus,
    verdict: Option<llm::SpamVerdict>,
    campaign: CampaignContext,
}

impl CheckedAccount {
    /// Whether moderators were notified. Read back off the outcome rather than carried alongside
    /// it, so the two cannot disagree about what happened.
    fn notified(&self) -> bool {
        matches!(self.outcome, AccountCheckOutcome::Spam { notified: true })
    }
}

#[derive(Default)]
struct ProcessSummary {
    last_contiguous_id: Option<String>,
    spam_detected: u32,
    spam_notified: u32,
    undetermined: u32,
    skipped_existing: u32,
    first_failure: Option<anyhow::Error>,
}

impl ProcessSummary {
    /// Keeps the failure that stopped the run, which is the one that explains it. Later failures
    /// are consequences of stopping, and the accounts behind them stay queued for retry regardless.
    fn record_failure(&mut self, error: anyhow::Error) {
        self.first_failure.get_or_insert(error);
    }

    /// Reports what the run did, then hands back the failure that stopped it, if any.
    ///
    /// The counts are logged before the error is returned rather than after a successful finish, so
    /// a run that stopped part-way still says how far it got: how many accounts were already
    /// notified is what tells an operator whether `retry-failed` has anything left to do.
    fn finish(self, dry_run: bool) -> Result<()> {
        info!(
            spam_detected = self.spam_detected,
            spam_notified = self.spam_notified,
            undetermined = self.undetermined,
            skipped_existing = self.skipped_existing,
            dry_run,
            failed = self.first_failure.is_some(),
            "check finished"
        );
        match self.first_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

async fn check(dry_run: bool) -> Result<()> {
    let config = config::Config::from_env(!dry_run)?;
    info!(
        dry_run,
        threshold = config.detection.spam_confidence_threshold,
        max_accounts = config.max_accounts_per_run,
        concurrency = config.check_concurrency,
        "configuration loaded"
    );

    let store = StateStore::new(&config.redis_url).await?;
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

    let services = build_services(&config, store.clone(), !dry_run).await?;
    let accounts = services
        .mastodon
        .fetch_remote_accounts(cursor.as_deref(), None, config.max_accounts_per_run)
        .await?;
    if accounts.is_empty() {
        info!("no new remote accounts");
        return Ok(());
    }

    let summary = process_accounts(accounts, services, config.check_concurrency).await;
    if dry_run {
        info!("dry-run: cursor and account jobs not updated");
    } else if let Some(id) = &summary.last_contiguous_id {
        store
            .set_cursor(id)
            .await
            .context("failed to save cursor")?;
        info!(cursor = %id, "cursor saved");
    }

    summary.finish(dry_run)
}

async fn build_services(
    config: &config::Config,
    store: StateStore,
    notify: bool,
) -> Result<CheckServices> {
    let detection = &config.detection;
    let (mastodon, llm) = detection_clients(detection)?;
    let slack = if notify {
        Some(slack::SlackNotifier::new(
            config
                .slack_webhook_url
                .as_deref()
                .context("SLACK_WEBHOOK_URL is required when notifications are enabled")?,
            config.slack_channel.clone(),
            &detection.mastodon_base_url,
        )?)
    } else {
        None
    };
    let note_writer = postgres::writer_for(config.postgres.as_ref().filter(|_| notify)).await?;
    Ok(CheckServices {
        mastodon,
        llm,
        slack,
        store,
        note_writer,
        threshold: detection.spam_confidence_threshold,
        persist: notify,
        retry_pending: false,
    })
}

/// The two clients a spam check always needs, built from one detection config.
///
/// `check-account` builds them without the rest of [`CheckServices`], so the construction lives
/// here rather than inline in [`build_services`].
fn detection_clients(
    detection: &config::DetectionConfig,
) -> Result<(mastodon::MastodonClient, llm::LlmClient)> {
    let mastodon = mastodon::MastodonClient::new(
        &detection.mastodon_base_url,
        &detection.mastodon_access_token,
    )?;
    let llm = llm::LlmClient::new(
        &detection.openai_api_base,
        &detection.openai_api_key,
        &detection.openai_model,
        detection.openai_json_mode,
        http::RetryConfig::default(),
    )?;
    Ok((mastodon, llm))
}

async fn process_accounts(
    accounts: Vec<mastodon::AdminAccount>,
    services: CheckServices,
    concurrency: usize,
) -> ProcessSummary {
    // One shared handle rather than a per-account copy: cloning the struct duplicated every
    // client's URLs, tokens, and model name for each of potentially thousands of accounts.
    let services = Arc::new(services);
    let mut summary = ProcessSummary::default();

    for chunk in accounts.chunks(concurrency) {
        let mut tasks = tokio::task::JoinSet::new();
        for account in chunk.iter().cloned() {
            let services = Arc::clone(&services);
            tasks.spawn(async move {
                let id = account.id.clone();
                (id, check_one(account, services).await)
            });
        }

        let mut results = HashMap::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((id, result)) => {
                    results.insert(id, result);
                }
                Err(error) => summary.record_failure(anyhow::Error::new(error)),
            }
        }

        // Walked in the original order, not the order the tasks finished in: the cursor may only
        // advance across accounts whose predecessors all succeeded.
        for account in chunk {
            let result = results
                .remove(&account.id)
                .unwrap_or_else(|| Err(anyhow::anyhow!("account check task produced no result")));
            match result {
                Ok(AccountCheckOutcome::Spam { notified }) => {
                    summary.spam_detected += 1;
                    summary.spam_notified += u32::from(notified);
                }
                Ok(AccountCheckOutcome::Undetermined) => summary.undetermined += 1,
                Ok(AccountCheckOutcome::Existing) => summary.skipped_existing += 1,
                Ok(AccountCheckOutcome::System | AccountCheckOutcome::NotSpam) => {}
                Err(error) => {
                    summary.record_failure(error.context(format!(
                        "check failed for {} (account {}); retry with retry-failed",
                        account.acct(),
                        account.id
                    )));
                    break;
                }
            }
            summary.last_contiguous_id = Some(account.id.clone());
        }
        if summary.first_failure.is_some() {
            break;
        }
    }

    summary
}

async fn check_one(
    account: mastodon::AdminAccount,
    services: Arc<CheckServices>,
) -> Result<AccountCheckOutcome> {
    let domain = account.domain.as_deref().unwrap_or("?");
    if is_system_account(&account.username, domain) {
        info!(username = %account.username, %domain, "system account, skipping");
        return Ok(AccountCheckOutcome::System);
    }

    if services.persist {
        let store = &services.store;
        if store.has_terminal_feedback(&account.id).await? {
            info!(account_id = %account.id, "account has terminal moderator feedback");
            return Ok(AccountCheckOutcome::Existing);
        }
        if let Some(job) = store.get_job(&account.id).await? {
            if job.status == JobStatus::NotificationPending {
                if services.retry_pending {
                    return retry_pending_notification(account, &services, job).await;
                }
                warn!(account_id = %account.id, "notification delivery is uncertain; use retry-failed to retry explicitly");
                return Ok(AccountCheckOutcome::Existing);
            }
            if job.status.is_completed() {
                info!(account_id = %account.id, status = ?job.status, "account already processed");
                return Ok(AccountCheckOutcome::Existing);
            }
        }
    }

    info!(username = %account.username, %domain, id = %account.id, "checking");
    let job = if services.persist {
        Some(
            services
                .store
                .begin_job(
                    &account.id,
                    &account.acct(),
                    services.llm.model(),
                    llm::PROMPT_VERSION,
                )
                .await?,
        )
    } else {
        None
    };

    match check_one_inner(&account, &services).await {
        Ok(checked) => {
            if let Some(job) = job {
                services
                    .store
                    .complete_job(
                        job,
                        checked.status,
                        checked.verdict.as_ref().map(Into::into),
                        checked.notified(),
                        &checked.campaign,
                    )
                    .await?;
            }
            // After the job is completed, never before: see `add_spam_note`.
            if checked.notified()
                && let Some(verdict) = &checked.verdict
            {
                add_spam_note(&services, &account.id, verdict).await;
            }
            Ok(checked.outcome)
        }
        Err(error) => {
            if let Some(job) = job
                && let Err(store_error) = services.store.fail_job(job, &error).await
            {
                error!(error = %chain(&store_error), "failed to persist account failure");
            }
            Err(error)
        }
    }
}

async fn check_one_inner(
    account: &mastodon::AdminAccount,
    services: &CheckServices,
) -> Result<CheckedAccount> {
    let statuses = services
        .mastodon
        .fetch_statuses(&account.id)
        .await
        .context("failed to fetch statuses")?;
    let signals = signals::analyze(account, &statuses);
    let campaign = services
        .store
        .campaign_context(
            &account.id,
            signals.bio_fingerprint.as_deref(),
            &signals.link_domains,
            services.persist,
        )
        .await?;

    let verdict = match services
        .llm
        .check_spam(account, &statuses, &signals, &campaign)
        .await
    {
        Ok(verdict) => verdict,
        Err(error) if llm::is_unparseable_verdict(&error) => {
            warn!(
                account_id = %account.id,
                error = %chain(&error),
                "no usable LLM verdict, storing as undetermined"
            );
            return Ok(CheckedAccount {
                outcome: AccountCheckOutcome::Undetermined,
                status: JobStatus::Undetermined,
                verdict: None,
                campaign,
            });
        }
        Err(error) => return Err(error).context("LLM check failed"),
    };

    // Neither of the two outcomes below owes anything to Slack, so nothing has to be written
    // ahead of time: the caller completes the job with this verdict as the next step.
    let domain = account.domain.as_deref().unwrap_or("?");
    if !verdict.spam {
        info!(username = %account.username, %domain, "not spam");
        return Ok(CheckedAccount {
            outcome: AccountCheckOutcome::NotSpam,
            status: JobStatus::NotSpam,
            verdict: Some(verdict),
            campaign,
        });
    }

    if verdict.confidence < services.threshold {
        info!(
            username = %account.username,
            %domain,
            confidence = verdict.confidence,
            threshold = services.threshold,
            reason = %verdict.reason,
            "spam detected below notification threshold"
        );
        return Ok(CheckedAccount {
            outcome: AccountCheckOutcome::Spam { notified: false },
            status: JobStatus::Spam,
            verdict: Some(verdict),
            campaign,
        });
    }

    warn!(
        username = %account.username,
        %domain,
        confidence = verdict.confidence,
        reason = %verdict.reason,
        campaign_matches = campaign.match_count(),
        "spam detected"
    );
    report_spam(account, services, verdict, campaign).await
}

/// Notifies moderators about a spam verdict that cleared the threshold, and records it.
///
/// The classification is written as pending before the notification goes out, so a crash
/// mid-delivery leaves the account in the retry queue rather than looking finished. With no Slack
/// configured nothing is owed, and the caller's `complete_job` records the verdict on its own.
async fn report_spam(
    account: &mastodon::AdminAccount,
    services: &CheckServices,
    verdict: llm::SpamVerdict,
    campaign: CampaignContext,
) -> Result<CheckedAccount> {
    if services.slack.is_some() {
        services
            .store
            .record_classification(
                &account.id,
                JobStatus::NotificationPending,
                (&verdict).into(),
                &campaign,
            )
            .await?;
    }

    let notified = notify_with_claim(services, account, &verdict).await?;
    if !notified {
        info!(account_id = %account.id, "notification disabled");
    }

    Ok(CheckedAccount {
        outcome: AccountCheckOutcome::Spam { notified },
        status: JobStatus::Spam,
        verdict: Some(verdict),
        campaign,
    })
}

async fn retry_pending_notification(
    account: mastodon::AdminAccount,
    services: &CheckServices,
    job: JobRecord,
) -> Result<AccountCheckOutcome> {
    let verdict: llm::SpamVerdict = job
        .verdict
        .clone()
        .context("pending notification has no stored verdict")?
        .into();
    let campaign = CampaignContext {
        matching_accounts: job.campaign_accounts.clone(),
    };
    match notify_with_claim(services, &account, &verdict).await {
        Ok(notified) => {
            services
                .store
                .complete_job(
                    job,
                    JobStatus::Spam,
                    Some((&verdict).into()),
                    notified,
                    &campaign,
                )
                .await?;
            if notified {
                add_spam_note(services, &account.id, &verdict).await;
            }
            Ok(AccountCheckOutcome::Spam { notified })
        }
        Err(error) => {
            if let Err(store_error) = services.store.fail_job(job, &error).await {
                error!(error = %chain(&store_error), "failed to persist notification retry failure");
            }
            Err(error)
        }
    }
}

async fn notify_with_claim(
    services: &CheckServices,
    account: &mastodon::AdminAccount,
    verdict: &llm::SpamVerdict,
) -> Result<bool> {
    let Some(slack) = &services.slack else {
        return Ok(false);
    };
    let store = &services.store;
    let Some(token) = store.claim_notification(&account.id).await? else {
        if store.has_terminal_feedback(&account.id).await? {
            info!(account_id = %account.id, "notification suppressed by moderator feedback");
            return Ok(false);
        }
        bail!(
            "notification delivery is already claimed for account {}",
            account.id
        );
    };
    let result = slack
        .notify_spam(account, verdict)
        .await
        .context("failed to send Slack notification");
    if let Err(error) = store.release_notification_claim(&account.id, &token).await {
        error!(account_id = %account.id, error = %chain(&error), "failed to release notification claim");
    }
    result.map(|()| true)
}

/// Records a delivered spam verdict as a Mastodon moderation note, when one is configured.
///
/// Called only after the job has been completed: the notification this documents is already out,
/// and a database timeout or process exit must not leave it pending for retry. For the same reason
/// a failure here is logged rather than raised — a missing note must not undo a delivered
/// notification.
async fn add_spam_note(services: &CheckServices, account_id: &str, verdict: &llm::SpamVerdict) {
    let Some(writer) = &services.note_writer else {
        return;
    };
    let note = t!(
        "note_spam",
        confidence = format!("{:.0}", verdict.confidence * 100.0),
        reason = &verdict.reason,
    );
    if let Err(error) = writer.add_note(account_id, &note).await {
        error!(account_id = %account_id, error = %chain(&error), "failed to add moderation note");
    }
}

async fn check_account_command(args: &[String]) -> Result<()> {
    let [account_id] = args else {
        bail!("usage: mastodon-spam-checker check-account <ID>");
    };
    validate_account_id(account_id)?;
    let (mastodon, llm) = detection_clients(&config::DetectionConfig::from_env()?)?;
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
    let store = StateStore::new(&config::redis_url_env()?).await?;
    println!(
        "{}",
        store.get_cursor().await?.as_deref().unwrap_or("(none)")
    );
    Ok(())
}

async fn retry_failed_command(args: &[String]) -> Result<()> {
    let max = parse_optional_max(args, 100)?;
    let config = config::Config::from_env(true)?;
    let store = StateStore::new(&config.redis_url).await?;
    let ids = store.failed_ids(max.saturating_mul(10)).await?;
    if ids.is_empty() {
        info!("retry queue is empty");
        return Ok(());
    }
    let mut services = build_services(&config, store.clone(), true).await?;
    services.retry_pending = true;
    let mut accounts = Vec::with_capacity(max.min(ids.len()));
    let mut unavailable = 0usize;
    let mut fetch_failures = 0usize;
    for id in ids {
        match services.mastodon.fetch_admin_account_optional(&id).await {
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
    process_accounts(accounts, services, config.check_concurrency)
        .await
        .finish(false)
}

async fn backfill_command(args: &[String]) -> Result<()> {
    let options = BackfillOptions::parse(args)?;
    let config = config::Config::from_env(options.notify)?;
    let store = StateStore::new(&config.redis_url).await?;
    let mut services = build_services(&config, store, options.notify).await?;
    // Backfills persist results even when notifications are intentionally disabled.
    services.persist = true;
    let accounts = services
        .mastodon
        .fetch_remote_accounts(Some(&options.from), options.to.as_deref(), options.max)
        .await?;
    process_accounts(accounts, services, config.check_concurrency)
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
        // Each flag takes its value in the same arm that matched it, so there is no second match on
        // an already-decided flag and no arm that the first match has to promise cannot be reached.
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
        assert!(t!("btn_suspend").contains("Suspend"));
        rust_i18n::set_locale("ja");
        assert!(t!("btn_suspend").contains("停止"));
    }

    #[test]
    fn system_accounts_are_detected() {
        assert!(is_system_account("mastodon.internal", "example.com"));
        assert!(is_system_account("internal.fetch", "example.com"));
        assert!(is_system_account("system.actor", "example.com"));
        assert!(is_system_account("example.com", "example.com"));
        assert!(!is_system_account("alice", "example.com"));
    }

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
}
