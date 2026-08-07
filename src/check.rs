//! The spam-check pipeline, shared by the periodic run, `retry-failed`, and `backfill`.
//!
//! One account goes through [`check_one`]: statuses are fetched, campaign signals looked up, a
//! verdict asked for, moderators notified, and the outcome recorded. [`process_accounts`] runs that
//! over a list of accounts and reports how far it got.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rust_i18n::t;
use tracing::{error, info, warn};

use crate::chain;
use crate::config::{Config, DetectionConfig};
use crate::http;
use crate::llm::{self, LlmClient, SpamVerdict};
use crate::mastodon::{AdminAccount, MastodonClient};
use crate::postgres::{self, ModerationNoteWriter};
use crate::redis::{CampaignContext, JobRecord, JobStatus, StateStore};
use crate::signals;
use crate::slack::SlackNotifier;

/// What a run may do beyond classifying the accounts it was given.
///
/// The three entry points differ only here: a dry run neither writes nor notifies, a backfill
/// writes but notifies only when asked, and `retry-failed` additionally re-sends deliveries the
/// periodic checker deliberately leaves alone.
#[derive(Clone, Copy)]
pub struct ServiceOptions {
    /// Send Slack notifications, and write the moderation notes that document them.
    pub notify: bool,
    /// Write job records, campaign index entries, and the retry queue.
    pub persist: bool,
    /// Re-send a notification whose delivery was left uncertain, rather than skipping the account.
    pub retry_pending: bool,
}

pub struct CheckServices {
    mastodon: MastodonClient,
    llm: LlmClient,
    slack: Option<SlackNotifier>,
    /// Present for every run. Dry runs still read campaign context through it; `persist` is what
    /// decides whether anything is written back.
    store: StateStore,
    note_writer: Option<ModerationNoteWriter>,
    threshold: f64,
    persist: bool,
    retry_pending: bool,
}

impl CheckServices {
    pub async fn build(
        config: &Config,
        store: StateStore,
        options: ServiceOptions,
    ) -> Result<Self> {
        let detection = &config.detection;
        let (mastodon, llm) = detection_clients(detection)?;
        let slack = if options.notify {
            Some(SlackNotifier::new(
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
        let note_writer =
            postgres::writer_for(config.postgres.as_ref().filter(|_| options.notify)).await?;
        Ok(Self {
            mastodon,
            llm,
            slack,
            store,
            note_writer,
            threshold: detection.spam_confidence_threshold,
            persist: options.persist,
            retry_pending: options.retry_pending,
        })
    }

    /// The Mastodon client, for the callers that select the accounts to check before handing them
    /// to [`process_accounts`].
    pub fn mastodon(&self) -> &MastodonClient {
        &self.mastodon
    }
}

/// The two clients a spam check always needs, built from one detection config.
///
/// `check-account` builds them without the rest of [`CheckServices`], so the construction lives
/// here rather than inline in [`CheckServices::build`].
pub fn detection_clients(detection: &DetectionConfig) -> Result<(MastodonClient, LlmClient)> {
    let mastodon = MastodonClient::new(
        &detection.mastodon_base_url,
        &detection.mastodon_access_token,
    )?;
    let llm = LlmClient::new(
        &detection.openai_api_base,
        &detection.openai_api_key,
        &detection.openai_model,
        detection.openai_json_mode,
        http::RetryConfig::default(),
    )?;
    Ok((mastodon, llm))
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
    verdict: Option<SpamVerdict>,
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
pub struct ProcessSummary {
    last_contiguous_id: Option<String>,
    spam_detected: u32,
    spam_notified: u32,
    undetermined: u32,
    skipped_existing: u32,
    first_failure: Option<anyhow::Error>,
}

impl ProcessSummary {
    /// The newest account every earlier account was also finished for, or `None` when the very
    /// first one failed. Saving anything past a failure would skip the account that failed.
    pub fn last_contiguous_id(&self) -> Option<&str> {
        self.last_contiguous_id.as_deref()
    }

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
    pub fn finish(self, dry_run: bool) -> Result<()> {
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

pub async fn process_accounts(
    accounts: Vec<AdminAccount>,
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
    account: AdminAccount,
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
    account: &AdminAccount,
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
    account: &AdminAccount,
    services: &CheckServices,
    verdict: SpamVerdict,
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
    account: AdminAccount,
    services: &CheckServices,
    job: JobRecord,
) -> Result<AccountCheckOutcome> {
    let verdict: SpamVerdict = job
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
    account: &AdminAccount,
    verdict: &SpamVerdict,
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
async fn add_spam_note(services: &CheckServices, account_id: &str, verdict: &SpamVerdict) {
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
        assert!(is_system_account("example.com", "example.com"));
        assert!(!is_system_account("alice", "example.com"));
    }

    #[test]
    fn the_failure_that_stopped_a_run_is_the_one_reported() {
        // Later failures are consequences of stopping, so the first one has to survive them.
        let mut summary = ProcessSummary::default();
        summary.record_failure(anyhow::anyhow!("first"));
        summary.record_failure(anyhow::anyhow!("second"));

        let error = summary.finish(false).unwrap_err();
        assert_eq!(error.to_string(), "first");
    }
}
