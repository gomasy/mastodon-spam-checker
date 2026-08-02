use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};

use crate::ids::numeric_id_cmp;
use crate::signals::digest;

const KEY_PREFIX: &str = "mastodon_spam_checker";
const CURSOR_KEY: &str = "mastodon_spam_checker:last_account_id";
const FAILED_KEY: &str = "mastodon_spam_checker:failed_accounts";
const PENDING_NOTIFICATION_KEY: &str = "mastodon_spam_checker:pending_notifications";
// Slack uses a 30-second request timeout and at most three Retry-After delays capped at 30 seconds,
// so ten minutes safely covers the complete delivery attempt.
const NOTIFICATION_CLAIM_SECS: u64 = 10 * 60;
const RUN_LEASE_KEY: &str = "mastodon_spam_checker:run_lease";
const RUN_LEASE_SECS: u64 = 180;
const CAMPAIGN_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;
const CAMPAIGN_MEMBERS_PER_SIGNAL: i64 = 1_000;
/// How many matching accounts a campaign lookup keeps, per signal and in total.
const CAMPAIGN_MATCHES_REPORTED: usize = 20;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Processing,
    NotificationPending,
    NotSpam,
    Spam,
    Undetermined,
    Failed,
    ConfirmedSpam,
    FalsePositive,
    Suspended,
    Deleted,
    Unavailable,
}

impl JobStatus {
    pub fn is_completed(self) -> bool {
        matches!(
            self,
            Self::NotSpam
                | Self::Spam
                | Self::Undetermined
                | Self::ConfirmedSpam
                | Self::FalsePositive
                | Self::Suspended
                | Self::Deleted
                | Self::Unavailable
        )
    }

    /// The stored spelling, matching how `serde` renames the variants for [`JobRecord`].
    ///
    /// Statuses are written both inside JSON job records and as the bare value of the moderation
    /// action key; sharing one spelling keeps the two greppable as the same thing.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::NotificationPending => "notification_pending",
            Self::NotSpam => "not_spam",
            Self::Spam => "spam",
            Self::Undetermined => "undetermined",
            Self::Failed => "failed",
            Self::ConfirmedSpam => "confirmed_spam",
            Self::FalsePositive => "false_positive",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredVerdict {
    pub spam: bool,
    pub reason: String,
    pub confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobRecord {
    pub account_id: String,
    pub acct: String,
    pub status: JobStatus,
    pub attempts: u32,
    pub updated_at: u64,
    pub model: String,
    pub prompt_version: String,
    pub verdict: Option<StoredVerdict>,
    pub notified: bool,
    pub error: Option<String>,
    pub campaign_match_count: u64,
    pub campaign_accounts: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CampaignContext {
    pub matching_accounts: Vec<String>,
}

impl CampaignContext {
    pub fn match_count(&self) -> usize {
        self.matching_accounts.len()
    }
}

#[derive(Clone)]
pub struct StateStore {
    conn: ConnectionManager,
}

impl StateStore {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url).context("failed to create Redis client")?;
        let conn = client
            .get_connection_manager()
            .await
            .context("failed to connect to Redis")?;
        Ok(Self { conn })
    }

    pub async fn get_cursor(&self) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        conn.get(CURSOR_KEY)
            .await
            .context("failed to read cursor from Redis")
    }

    pub async fn set_cursor(&self, account_id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        redis::Script::new(
            "local current = redis.call('GET', KEYS[1])\n\
             if not current or string.len(ARGV[1]) > string.len(current) or \
                (string.len(ARGV[1]) == string.len(current) and ARGV[1] > current) then\n\
               redis.call('SET', KEYS[1], ARGV[1])\n\
               return 1\n\
             end\n\
             return 0",
        )
        .key(CURSOR_KEY)
        .arg(account_id)
        .invoke_async::<i32>(&mut conn)
        .await
        .context("failed to save cursor to Redis")?;
        Ok(())
    }

    pub async fn acquire_run_lease(&self) -> Result<String> {
        let token = format!(
            "{}:{}:{}",
            std::process::id(),
            now_timestamp(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        );
        let mut conn = self.conn.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(RUN_LEASE_KEY)
            .arg(&token)
            .arg("NX")
            .arg("EX")
            .arg(RUN_LEASE_SECS)
            .query_async(&mut conn)
            .await
            .context("failed to acquire run lease")?;
        if result.is_none() {
            bail!("another checker, retry, or backfill run is already active");
        }
        Ok(token)
    }

    pub async fn release_run_lease(&self, token: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let released = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then \
               return redis.call('DEL', KEYS[1]) \
             end \
             return 0",
        )
        .key(RUN_LEASE_KEY)
        .arg(token)
        .invoke_async::<i32>(&mut conn)
        .await
        .context("failed to release run lease")?;
        if released == 0 {
            bail!("run lease ownership was lost before release");
        }
        Ok(())
    }

    pub async fn renew_run_lease(&self, token: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let renewed = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then \
               return redis.call('EXPIRE', KEYS[1], ARGV[2]) \
             end \
             return 0",
        )
        .key(RUN_LEASE_KEY)
        .arg(token)
        .arg(RUN_LEASE_SECS)
        .invoke_async::<i32>(&mut conn)
        .await
        .context("failed to renew run lease")?;
        if renewed == 0 {
            bail!("run lease ownership was lost");
        }
        Ok(())
    }

    pub async fn get_job(&self, account_id: &str) -> Result<Option<JobRecord>> {
        let mut conn = self.conn.clone();
        let value: Option<String> = conn
            .get(job_key(account_id))
            .await
            .context("failed to read account job from Redis")?;
        parse_job(value.as_deref())
    }

    pub async fn begin_job(
        &self,
        account_id: &str,
        acct: &str,
        model: &str,
        prompt_version: &str,
    ) -> Result<JobRecord> {
        let attempts = self
            .get_job(account_id)
            .await?
            .map_or(1, |job| job.attempts.saturating_add(1));
        let job = JobRecord {
            account_id: account_id.to_string(),
            acct: acct.to_string(),
            status: JobStatus::Processing,
            attempts,
            updated_at: now_timestamp(),
            model: model.to_string(),
            prompt_version: prompt_version.to_string(),
            verdict: None,
            notified: false,
            error: None,
            campaign_match_count: 0,
            campaign_accounts: Vec::new(),
        };
        self.save_job(&job).await?;
        Ok(job)
    }

    pub async fn complete_job(
        &self,
        mut job: JobRecord,
        status: JobStatus,
        verdict: Option<StoredVerdict>,
        notified: bool,
        campaign: &CampaignContext,
    ) -> Result<()> {
        job.status = status;
        job.updated_at = now_timestamp();
        job.verdict = verdict;
        job.notified = notified;
        job.error = None;
        job.campaign_match_count = campaign.match_count() as u64;
        job.campaign_accounts = campaign.matching_accounts.clone();
        let value = serde_json::to_string(&job).context("failed to serialize account job")?;
        let mut conn = self.conn.clone();
        redis::pipe()
            .atomic()
            .set(job_key(&job.account_id), value)
            .ignore()
            .srem(FAILED_KEY, &job.account_id)
            .ignore()
            .srem(PENDING_NOTIFICATION_KEY, &job.account_id)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
            .context("failed to complete account job")
    }

    pub async fn record_classification(
        &self,
        account_id: &str,
        status: JobStatus,
        verdict: StoredVerdict,
        campaign: &CampaignContext,
    ) -> Result<()> {
        let mut job = self
            .get_job(account_id)
            .await?
            .with_context(|| format!("no processing job for account {account_id}"))?;
        job.status = status;
        job.updated_at = now_timestamp();
        job.verdict = Some(verdict);
        job.error = None;
        job.campaign_match_count = campaign.match_count() as u64;
        job.campaign_accounts = campaign.matching_accounts.clone();
        let value = serde_json::to_string(&job).context("failed to serialize account job")?;
        let mut pipeline = redis::pipe();
        pipeline.atomic().set(job_key(account_id), value).ignore();
        if job.status == JobStatus::NotificationPending {
            pipeline.sadd(PENDING_NOTIFICATION_KEY, account_id).ignore();
        }
        let mut conn = self.conn.clone();
        pipeline
            .query_async::<()>(&mut conn)
            .await
            .context("failed to persist account classification")
    }

    pub async fn fail_job(&self, mut job: JobRecord, error: &anyhow::Error) -> Result<()> {
        if let Some(current) = self.get_job(&job.account_id).await? {
            job.verdict = current.verdict;
            job.campaign_match_count = current.campaign_match_count;
            job.campaign_accounts = current.campaign_accounts;
        }
        job.status = JobStatus::Failed;
        job.updated_at = now_timestamp();
        job.error = Some(format!("{error:#}"));
        let value = serde_json::to_string(&job).context("failed to serialize account job")?;
        let mut conn = self.conn.clone();
        redis::pipe()
            .atomic()
            .set(job_key(&job.account_id), value)
            .ignore()
            .sadd(FAILED_KEY, &job.account_id)
            .ignore()
            .srem(PENDING_NOTIFICATION_KEY, &job.account_id)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
            .context("failed to persist account failure")
    }

    pub async fn record_feedback(
        &self,
        account_id: &str,
        status: JobStatus,
        user_id: &str,
    ) -> Result<()> {
        if self.get_job(account_id).await?.is_none() {
            bail!("no stored job for account {account_id}");
        }
        let value = serde_json::to_string(&FeedbackRecord {
            status,
            user_id: user_id.to_string(),
            updated_at: now_timestamp(),
        })
        .context("failed to serialize moderator feedback")?;
        let mut conn = self.conn.clone();
        let saved = redis::Script::new(
            "if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end \
             redis.call('SET', KEYS[1], ARGV[1]) \
             redis.call('SREM', KEYS[3], ARGV[2]) \
             redis.call('SREM', KEYS[4], ARGV[2]) \
             return 1",
        )
        .key(feedback_key(account_id))
        .key(notification_claim_key(account_id))
        .key(FAILED_KEY)
        .key(PENDING_NOTIFICATION_KEY)
        .arg(value)
        .arg(account_id)
        .invoke_async::<i32>(&mut conn)
        .await
        .context("failed to save moderator feedback")?;
        if saved == 0 {
            bail!("notification delivery is in progress; retry feedback shortly");
        }
        Ok(())
    }

    pub async fn claim_notification(&self, account_id: &str) -> Result<Option<String>> {
        let token = format!("{}:{}", std::process::id(), now_timestamp());
        let mut conn = self.conn.clone();
        redis::Script::new(
            "if redis.call('EXISTS', KEYS[1]) == 1 then return nil end \
             return redis.call('SET', KEYS[2], ARGV[1], 'NX', 'EX', ARGV[2])",
        )
        .key(feedback_key(account_id))
        .key(notification_claim_key(account_id))
        .arg(&token)
        .arg(NOTIFICATION_CLAIM_SECS)
        .invoke_async::<Option<String>>(&mut conn)
        .await
        .context("failed to claim notification delivery")
        .map(|result| result.map(|_| token))
    }

    pub async fn release_notification_claim(&self, account_id: &str, token: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then \
               return redis.call('DEL', KEYS[1]) \
             end \
             return 0",
        )
        .key(notification_claim_key(account_id))
        .arg(token)
        .invoke_async::<i32>(&mut conn)
        .await
        .context("failed to release notification claim")?;
        Ok(())
    }

    pub async fn record_action(&self, account_id: &str, status: JobStatus) -> Result<()> {
        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(action_key(account_id), status.as_str())
            .await
            .context("failed to save moderation action")
    }

    pub async fn is_false_positive(&self, account_id: &str) -> Result<bool> {
        Ok(matches!(
            self.feedback_status(account_id).await?,
            Some(JobStatus::FalsePositive)
        ))
    }

    pub async fn has_terminal_feedback(&self, account_id: &str) -> Result<bool> {
        Ok(matches!(
            self.feedback_status(account_id).await?,
            Some(JobStatus::FalsePositive | JobStatus::ConfirmedSpam)
        ))
    }

    async fn feedback_status(&self, account_id: &str) -> Result<Option<JobStatus>> {
        let mut conn = self.conn.clone();
        let value: Option<String> = conn
            .get(feedback_key(account_id))
            .await
            .context("failed to read moderator feedback")?;
        Ok(parse_feedback(value.as_deref())?.map(|feedback| feedback.status))
    }

    pub async fn failed_ids(&self, limit: usize) -> Result<Vec<String>> {
        let mut conn = self.conn.clone();
        let (mut ids, pending): (Vec<String>, Vec<String>) = redis::pipe()
            .smembers(FAILED_KEY)
            .smembers(PENDING_NOTIFICATION_KEY)
            .query_async(&mut conn)
            .await
            .context("failed to read retry queue")?;
        ids.extend(pending);
        ids.sort_by(|a, b| numeric_id_cmp(a, b));
        ids.dedup();

        let mut failed = Vec::new();
        for id in ids {
            // Both keys in one round trip: the queue can hold thousands of IDs, and this walks it
            // until `limit` live ones are found.
            let (feedback, job): (Option<String>, Option<String>) = redis::pipe()
                .get(feedback_key(&id))
                .get(job_key(&id))
                .query_async(&mut conn)
                .await
                .context("failed to read queued account state")?;
            if is_terminal_feedback(feedback.as_deref())? || is_completed_job(job.as_deref())? {
                self.remove_failed(&id).await?;
                continue;
            }
            failed.push(id);
            if failed.len() == limit {
                break;
            }
        }
        Ok(failed)
    }

    pub async fn mark_unavailable(&self, account_id: &str) -> Result<()> {
        let Some(mut job) = self.get_job(account_id).await? else {
            return self.remove_failed(account_id).await;
        };
        job.status = JobStatus::Unavailable;
        job.updated_at = now_timestamp();
        job.error = Some("account no longer exists in Mastodon".to_string());
        let value = serde_json::to_string(&job).context("failed to serialize account job")?;
        let mut conn = self.conn.clone();
        redis::pipe()
            .atomic()
            .set(job_key(account_id), value)
            .ignore()
            .srem(FAILED_KEY, account_id)
            .ignore()
            .srem(PENDING_NOTIFICATION_KEY, account_id)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
            .context("failed to mark unavailable account")
    }

    async fn remove_failed(&self, account_id: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        redis::pipe()
            .atomic()
            .srem(FAILED_KEY, account_id)
            .ignore()
            .srem(PENDING_NOTIFICATION_KEY, account_id)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
            .context("failed to remove account from retry queue")
    }

    /// Records this account against its campaign signals and reports which other recently seen
    /// accounts share one.
    ///
    /// An account can carry a bio fingerprint plus a domain per extracted link, so this runs over
    /// tens of keys. Every command for every key goes out in one pipeline: issued serially they
    /// cost four to five round trips per key, which dominated the time spent checking an account.
    /// The pipeline is deliberately not `atomic()` — these are independent per-key housekeeping
    /// commands, and wrapping them in MULTI/EXEC would only add contention.
    pub async fn campaign_context(
        &self,
        account_id: &str,
        bio_fingerprint: Option<&str>,
        link_domains: &[String],
        record: bool,
    ) -> Result<CampaignContext> {
        let mut keys =
            Vec::with_capacity(usize::from(bio_fingerprint.is_some()) + link_domains.len());
        if let Some(fingerprint) = bio_fingerprint {
            keys.push(format!("{KEY_PREFIX}:campaign:bio:{fingerprint}"));
        }
        keys.extend(
            link_domains
                .iter()
                .map(|domain| format!("{KEY_PREFIX}:campaign:domain:{}", digest(domain))),
        );
        if keys.is_empty() {
            return Ok(CampaignContext::default());
        }

        let now = now_timestamp();
        let cutoff = now.saturating_sub(CAMPAIGN_WINDOW_SECS);
        let mut pipeline = redis::pipe();
        for key in &keys {
            // Drop entries that fell out of the window before anything reads or caps the key.
            pipeline
                .cmd("ZREMRANGEBYSCORE")
                .arg(key)
                .arg("-inf")
                .arg(cutoff)
                .ignore();
            if record {
                pipeline
                    .zadd(key, account_id, now)
                    .ignore()
                    .expire(key, CAMPAIGN_WINDOW_SECS as i64)
                    .ignore()
                    // Keep only the newest members, so one busy domain cannot grow without bound.
                    .cmd("ZREMRANGEBYRANK")
                    .arg(key)
                    .arg(0)
                    .arg(-(CAMPAIGN_MEMBERS_PER_SIGNAL + 1))
                    .ignore();
            }
            // The only kept reply per key: newest members first.
            pipeline.zrevrange(key, 0, CAMPAIGN_MATCHES_REPORTED as isize - 1);
        }

        let mut conn = self.conn.clone();
        let per_key: Vec<Vec<String>> = pipeline
            .query_async(&mut conn)
            .await
            .context("failed to update and read campaign index")?;

        let matches: BTreeSet<String> = per_key
            .into_iter()
            .flatten()
            .filter(|id| id != account_id)
            .collect();

        Ok(CampaignContext {
            matching_accounts: most_recent_matches(matches),
        })
    }

    async fn save_job(&self, job: &JobRecord) -> Result<()> {
        let value = serde_json::to_string(job).context("failed to serialize account job")?;
        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(job_key(&job.account_id), value)
            .await
            .context("failed to save account job to Redis")
    }
}

fn parse_feedback(value: Option<&str>) -> Result<Option<FeedbackRecord>> {
    value
        .map(|value| serde_json::from_str(value).context("invalid moderator feedback in Redis"))
        .transpose()
}

fn parse_job(value: Option<&str>) -> Result<Option<JobRecord>> {
    value
        .map(|value| serde_json::from_str(value).context("invalid account job in Redis"))
        .transpose()
}

/// Whether a raw feedback value marks the account as decided by a moderator.
fn is_terminal_feedback(value: Option<&str>) -> Result<bool> {
    Ok(matches!(
        parse_feedback(value)?.map(|feedback| feedback.status),
        Some(JobStatus::FalsePositive | JobStatus::ConfirmedSpam)
    ))
}

/// Whether a raw job value shows the account has already reached a terminal status.
fn is_completed_job(value: Option<&str>) -> Result<bool> {
    Ok(parse_job(value)?.is_some_and(|job| job.status.is_completed()))
}

/// Caps the merged per-signal matches at the newest [`CAMPAIGN_MATCHES_REPORTED`] accounts.
///
/// Each signal is read newest-first, but merging them for de-duplication loses that order, and
/// taking the set's own order would keep whichever IDs sort first as text — `"1000"` ahead of
/// `"999"`. Re-sorting numerically, descending, keeps the accounts the campaign report is about.
fn most_recent_matches(matches: BTreeSet<String>) -> Vec<String> {
    let mut matches: Vec<String> = matches.into_iter().collect();
    matches.sort_by(|a, b| numeric_id_cmp(b, a));
    matches.truncate(CAMPAIGN_MATCHES_REPORTED);
    matches
}

fn job_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:job:{account_id}")
}

fn feedback_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:feedback:{account_id}")
}

fn action_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:moderation:{account_id}")
}

fn notification_claim_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:notification_claim:{account_id}")
}

#[derive(Serialize, Deserialize)]
struct FeedbackRecord {
    status: JobStatus,
    user_id: String,
    updated_at: u64,
}

fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_statuses_are_classified() {
        assert!(JobStatus::Spam.is_completed());
        assert!(JobStatus::FalsePositive.is_completed());
        assert!(!JobStatus::Failed.is_completed());
        assert!(!JobStatus::Processing.is_completed());
        assert!(!JobStatus::NotificationPending.is_completed());
    }

    #[test]
    fn campaign_matches_keep_the_most_recent_accounts() {
        // IDs increase over time, so "most recent" is the numerically largest, and the cap must
        // not fall back on lexicographic order (which would keep "1000" over "999").
        let ids = (1..=CAMPAIGN_MATCHES_REPORTED as u64 + 5)
            .map(|id| (id * 100).to_string())
            .collect::<BTreeSet<_>>();
        let kept = most_recent_matches(ids);

        assert_eq!(kept.len(), CAMPAIGN_MATCHES_REPORTED);
        assert_eq!(kept[0], "2500");
        assert_eq!(kept[kept.len() - 1], "600");
    }

    #[test]
    fn job_status_round_trips_through_its_stored_form() {
        // record_action and the JobRecord both persist this; one snake_case spelling for both.
        assert_eq!(JobStatus::ConfirmedSpam.as_str(), "confirmed_spam");
        assert_eq!(JobStatus::NotSpam.as_str(), "not_spam");
        assert_eq!(
            serde_json::to_string(&JobStatus::ConfirmedSpam).unwrap(),
            "\"confirmed_spam\""
        );
    }
}
