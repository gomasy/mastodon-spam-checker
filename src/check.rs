//! The spam-check pipeline, shared by the periodic run, `retry-failed`, and `backfill`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rust_i18n::t;
use tracing::{error, info, warn};

use crate::activitypub::RemoteFetcher;
use crate::auto_moderation::{self, AutoModerationConfig, AutoModerationOutcome};
use crate::chain;
use crate::config::{Config, DetectionConfig};
use crate::http;
use crate::llm::{self, LlmClient, SpamVerdict};
use crate::mastodon::{AdminAccount, MastodonClient, Status};
use crate::postgres::{self, ModerationNoteWriter};
use crate::redis::{
    CampaignContext, CheckSignals, JobRecord, JobStatus, KnownSpamContext, StateStore,
};
use crate::signals;
use crate::slack::SlackNotifier;

#[derive(Clone, Copy)]
pub struct ServiceOptions {
    /// Send Slack notifications and moderation notes.
    pub notify: bool,
    /// Write job records, campaign index entries, and the retry queue.
    pub persist: bool,
    /// Re-send notifications whose delivery was left uncertain.
    pub retry_pending: bool,
}

pub struct CheckServices {
    posts: PostSource,
    llm: LlmClient,
    slack: Option<SlackNotifier>,
    /// Read even in dry runs; written only with `persist`.
    store: StateStore,
    note_writer: Option<ModerationNoteWriter>,
    auto_moderation: Option<AutoModerationConfig>,
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
        let (posts, llm) = detection_clients(detection).await?;
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
            posts,
            llm,
            slack,
            store,
            note_writer,
            auto_moderation: config.auto_moderation.clone(),
            persist: options.persist,
            retry_pending: options.retry_pending,
        })
    }

    /// Only runs that persist and notify may act, so nothing is suspended unseen.
    fn auto_moderates(&self) -> bool {
        self.persist && self.slack.is_some()
    }

    pub fn mastodon(&self) -> &MastodonClient {
        &self.posts.mastodon
    }
}

pub async fn detection_clients(detection: &DetectionConfig) -> Result<(PostSource, LlmClient)> {
    let mastodon = MastodonClient::new(
        &detection.mastodon_base_url,
        &detection.mastodon_access_token,
    )?;
    let remote = RemoteFetcher::from_config(detection.remote_fetch.as_ref(), &mastodon).await?;
    let llm = LlmClient::new(detection, http::RetryConfig::default())?;
    Ok((PostSource { mastodon, remote }, llm))
}

/// An account's recent posts: this instance's copy, or the account's own outbox when that is empty.
pub struct PostSource {
    pub mastodon: MastodonClient,
    remote: Option<RemoteFetcher>,
}

impl PostSource {
    /// A failed remote fetch is logged and yields no posts, as if remote fetching were off.
    pub async fn fetch(&self, account: &AdminAccount) -> Result<Vec<Status>> {
        let statuses = self.mastodon.fetch_statuses(&account.id).await?;
        let Some(remote) = self.remote.as_ref().filter(|_| {
            statuses.is_empty() && account.account.statuses_count > 0 && account.domain.is_some()
        }) else {
            return Ok(statuses);
        };
        let Some(uri) = account.account.uri.as_deref().filter(|uri| !uri.is_empty()) else {
            warn!(account_id = %account.id, "account has no actor URI, skipping remote fetch");
            return Ok(statuses);
        };
        match remote.fetch_statuses(uri).await {
            Ok(statuses) => {
                info!(account_id = %account.id, count = statuses.len(), "fetched remote outbox");
                Ok(statuses)
            }
            Err(error) => {
                warn!(account_id = %account.id, error = %chain(&error), "remote outbox fetch failed");
                Ok(Vec::new())
            }
        }
    }
}

#[derive(Debug)]
enum AccountCheckOutcome {
    Existing,
    System,
    NotSpam(SpamVerdict),
    Spam {
        verdict: SpamVerdict,
        notified: bool,
        auto_moderated: bool,
    },
    Undetermined,
}

impl AccountCheckOutcome {
    fn verdict(&self) -> Option<&SpamVerdict> {
        match self {
            Self::NotSpam(verdict) | Self::Spam { verdict, .. } => Some(verdict),
            _ => None,
        }
    }

    fn notified(&self) -> bool {
        matches!(self, Self::Spam { notified: true, .. })
    }
}

struct CheckedAccount {
    outcome: AccountCheckOutcome,
    status: JobStatus,
    campaign: CampaignContext,
    signals: CheckSignals,
}

#[derive(Default)]
pub struct ProcessSummary {
    last_contiguous_id: Option<String>,
    spam_detected: u32,
    spam_notified: u32,
    auto_moderated: u32,
    undetermined: u32,
    skipped_existing: u32,
    first_failure: Option<anyhow::Error>,
}

impl ProcessSummary {
    /// The newest account with no failure at or before it; the cursor may advance this far.
    pub fn last_contiguous_id(&self) -> Option<&str> {
        self.last_contiguous_id.as_deref()
    }

    fn record_failure(&mut self, error: anyhow::Error) {
        self.first_failure.get_or_insert(error);
    }

    /// Logs the counts, even on failure, then returns the failure that stopped the run.
    pub fn finish(self, dry_run: bool) -> Result<()> {
        info!(
            spam_detected = self.spam_detected,
            spam_notified = self.spam_notified,
            auto_moderated = self.auto_moderated,
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

        // In input order, so the cursor never passes a failed account.
        for account in chunk {
            let result = results
                .remove(&account.id)
                .unwrap_or_else(|| Err(anyhow::anyhow!("account check task produced no result")));
            match result {
                Ok(AccountCheckOutcome::Spam {
                    notified,
                    auto_moderated,
                    ..
                }) => {
                    summary.spam_detected += 1;
                    summary.spam_notified += u32::from(notified);
                    summary.auto_moderated += u32::from(auto_moderated);
                }
                Ok(AccountCheckOutcome::Undetermined) => summary.undetermined += 1,
                Ok(AccountCheckOutcome::Existing) => summary.skipped_existing += 1,
                Ok(AccountCheckOutcome::System | AccountCheckOutcome::NotSpam(_)) => {}
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
            // An auto-moderated account whose notification failed must be re-notified, not
            // re-judged.
            let auto_moderated_failure = job.status == JobStatus::Failed
                && job.verdict.is_some()
                && store.auto_moderation(&account.id).await?.is_some();
            if job.status == JobStatus::NotificationPending || auto_moderated_failure {
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
                    &services.llm.model_label(),
                    llm::PROMPT_VERSION,
                )
                .await?,
        )
    } else {
        None
    };

    match check_one_inner(&account, &services).await {
        Ok(checked) => {
            if let Some(mut job) = job {
                job.signals = Some(checked.signals);
                services
                    .store
                    .complete_job(
                        job,
                        checked.status,
                        checked.outcome.verdict().map(Into::into),
                        checked.outcome.notified(),
                        &checked.campaign,
                    )
                    .await?;
            }
            if let AccountCheckOutcome::Spam {
                verdict,
                notified: true,
                ..
            } = &checked.outcome
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
        .posts
        .fetch(account)
        .await
        .context("failed to fetch statuses")?;
    let signals = signals::analyze(account, &statuses);
    let stored = CheckSignals {
        instance: account.domain.clone(),
        bio_fingerprint: signals.bio_fingerprint.clone(),
        link_domains: signals.link_domains.clone(),
    };
    let (campaign, known) = tokio::try_join!(
        services.store.campaign_context(
            &account.id,
            signals.bio_fingerprint.as_deref(),
            &signals.link_domains,
            services.persist,
        ),
        services
            .store
            .known_spam_context(&account.id, &stored, services.persist),
    )?;

    let verdict = match services
        .llm
        .check_spam(account, &statuses, &signals, &campaign, &known)
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
                campaign,
                signals: stored,
            });
        }
        Err(error) => return Err(error).context("LLM check failed"),
    };

    let domain = account.domain.as_deref().unwrap_or("?");
    let spam_probability = verdict.spam_probability();
    if !verdict.spam {
        info!(username = %account.username, %domain, spam_probability, "not spam");
        return Ok(CheckedAccount {
            outcome: AccountCheckOutcome::NotSpam(verdict),
            status: JobStatus::NotSpam,
            campaign,
            signals: stored,
        });
    }

    warn!(
        username = %account.username,
        %domain,
        spam_probability,
        reason = %verdict.reason,
        campaign_matches = campaign.match_count(),
        "spam detected"
    );
    report_spam(account, services, verdict, campaign, stored, &known).await
}

/// Records the verdict as notification-pending, auto-moderates, then notifies, so an interruption
/// leaves the account queued for `retry-failed`.
async fn report_spam(
    account: &AdminAccount,
    services: &CheckServices,
    verdict: SpamVerdict,
    campaign: CampaignContext,
    signals: CheckSignals,
    known: &KnownSpamContext,
) -> Result<CheckedAccount> {
    if services.slack.is_some() {
        services
            .store
            .record_classification(
                &account.id,
                JobStatus::NotificationPending,
                (&verdict).into(),
                &campaign,
                &signals,
            )
            .await?;
    }

    let auto = auto_moderate(account, services, &verdict, known).await?;
    let notified = notify_with_claim(services, account, &verdict, auto.as_ref()).await?;
    if !notified {
        info!(account_id = %account.id, "notification disabled");
    }

    Ok(CheckedAccount {
        outcome: AccountCheckOutcome::Spam {
            verdict,
            notified,
            auto_moderated: auto.as_ref().is_some_and(AutoModerationOutcome::acted),
        },
        status: JobStatus::Spam,
        campaign,
        signals,
    })
}

async fn auto_moderate(
    account: &AdminAccount,
    services: &CheckServices,
    verdict: &SpamVerdict,
    known: &KnownSpamContext,
) -> Result<Option<AutoModerationOutcome>> {
    let Some(config) = &services.auto_moderation else {
        return Ok(None);
    };
    let Some(matched) = config.qualifying_match(verdict.spam_probability(), known) else {
        return Ok(None);
    };
    if !services.auto_moderates() {
        info!(account_id = %account.id, ?matched, "matches known spam; auto-moderation skipped in a run without notifications");
        return Ok(None);
    }
    auto_moderation::apply(
        config.mode,
        services.mastodon(),
        &services.store,
        services.note_writer.as_ref(),
        account,
        matched,
    )
    .await
    .map(Some)
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
    let auto = services
        .store
        .auto_moderation(&account.id)
        .await?
        .map(|record| record.outcome());
    let auto_moderated = auto.as_ref().is_some_and(AutoModerationOutcome::acted);
    match notify_with_claim(services, &account, &verdict, auto.as_ref()).await {
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
            Ok(AccountCheckOutcome::Spam {
                verdict,
                notified,
                auto_moderated,
            })
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
    auto: Option<&AutoModerationOutcome>,
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
        .notify_spam(account, verdict, auto)
        .await
        .context("failed to send Slack notification");
    if let Err(error) = store.release_notification_claim(&account.id, &token).await {
        error!(account_id = %account.id, error = %chain(&error), "failed to release notification claim");
    }
    result.map(|()| true)
}

/// Notes a delivered spam verdict in Mastodon. Called only after the job is completed.
async fn add_spam_note(services: &CheckServices, account_id: &str, verdict: &SpamVerdict) {
    let note = t!(
        "note_spam",
        confidence = format!("{:.0}", verdict.confidence * 100.0),
        reason = &verdict.reason,
    );
    postgres::add_note_logged(services.note_writer.as_ref(), account_id, &note).await;
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
        let mut summary = ProcessSummary::default();
        summary.record_failure(anyhow::anyhow!("first"));
        summary.record_failure(anyhow::anyhow!("second"));

        let error = summary.finish(false).unwrap_err();
        assert_eq!(error.to_string(), "first");
    }
}
