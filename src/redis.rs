use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, FromRedisValue, Pipeline, RedisError, RedisResult};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::ids::numeric_id_cmp;
use crate::signals::digest;

const KEY_PREFIX: &str = "mastodon_spam_checker";
const CURSOR_KEY: &str = "mastodon_spam_checker:last_account_id";
const FAILED_KEY: &str = "mastodon_spam_checker:failed_accounts";
const PENDING_NOTIFICATION_KEY: &str = "mastodon_spam_checker:pending_notifications";
const RETENTION_MIGRATION_KEY: &str = "mastodon_spam_checker:migration:account_state_retention_v2";
/// Covers a complete Slack delivery attempt: a 30-second request timeout plus at most three
/// Retry-After delays, each capped at 30 seconds.
const NOTIFICATION_CLAIM_SECS: u64 = 10 * 60;
const RUN_LEASE_KEY: &str = "mastodon_spam_checker:run_lease";
const RUN_LEASE_SECS: u64 = 180;
const CAMPAIGN_WINDOW_SECS: u64 = 30 * 24 * 60 * 60;
const CAMPAIGN_MEMBERS_PER_SIGNAL: i64 = 1_000;
/// How many matching accounts a campaign lookup keeps, per signal and in total.
const CAMPAIGN_MATCHES_REPORTED: usize = 20;
/// Keeps completed account history available for recent Slack actions without accumulating
/// forever. Unresolved retries and moderator feedback are deliberately exempt.
const ACCOUNT_STATE_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;

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

    /// The stored spelling, matching how `serde` renames the variants for [`JobRecord`]. Statuses
    /// are written both inside job records and as the bare moderation action value; one spelling
    /// keeps the two greppable as the same thing.
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

    /// Runs a read, reissuing it once if the connection had gone away underneath it.
    ///
    /// [`ConnectionManager`] replaces a dropped connection in the background but still fails the
    /// command that discovered the dead socket — so an idle `serve` process fails the first
    /// moderator click after the socket goes, with nothing the moderator can act on. By the time
    /// the error surfaces the replacement is in place, and the reissue runs against it.
    ///
    /// Reads only: a failed write may still have reached Redis, and nothing in the error says
    /// whether it did, so re-sending one could apply it twice.
    async fn read<T: FromRedisValue>(
        &self,
        query: &impl RedisRead,
        what: &'static str,
    ) -> Result<T> {
        let mut conn = self.conn.clone();
        match query.run(&mut conn).await {
            Err(e) if e.is_unrecoverable_error() => {
                note_reconnect(&e, what);
                query.run(&mut conn).await.context(what)
            }
            result => result.context(what),
        }
    }

    /// [`Self::read`] for the single-key GET most callers want.
    async fn read_key<T: FromRedisValue>(
        &self,
        key: impl redis::ToRedisArgs,
        what: &'static str,
    ) -> Result<T> {
        self.read(redis::cmd("GET").arg(key), what).await
    }

    pub async fn get_cursor(&self) -> Result<Option<String>> {
        self.read_key(CURSOR_KEY, "failed to read cursor from Redis")
            .await
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
        let value: Option<String> = self
            .read_key(job_key(account_id), "failed to read account job from Redis")
            .await?;
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
        self.write_job(&job, Retry::Clear, "failed to complete account job")
            .await
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
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        set_job(&mut pipeline, &job, serialize_job(&job)?);
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
        self.write_job(&job, Retry::Queue, "failed to persist account failure")
            .await
    }

    /// Records a moderator's verdict on an account, returning the verdict it replaced, if any.
    ///
    /// A later verdict overwrites an earlier one — correcting a mis-click is what these buttons are
    /// for, and either order is reachable, since an older notification for the same account still
    /// carries the buttons the newer one hid. The replaced verdict is handed back so the caller can
    /// log the reversal. The one refusal is a notification still being delivered, which would race
    /// the claim.
    pub async fn record_feedback(
        &self,
        account_id: &str,
        status: JobStatus,
        user_id: &str,
    ) -> Result<Option<JobStatus>> {
        let value = serde_json::to_string(&FeedbackRecord {
            status,
            user_id: user_id.to_string(),
            updated_at: now_timestamp(),
        })
        .context("failed to serialize moderator feedback")?;
        let mut conn = self.conn.clone();
        // The status code distinguishes a missing job and an in-flight notification without
        // racing a separate job read against the completed job's expiry.
        let (outcome, previous): (i32, String) = redis::Script::new(
            "if redis.call('EXISTS', KEYS[2]) == 0 and redis.call('EXISTS', KEYS[1]) == 0 then return {0, ''} end \
             if redis.call('EXISTS', KEYS[3]) == 1 then return {1, ''} end \
             local existing = redis.call('GET', KEYS[1]) \
             redis.call('SET', KEYS[1], ARGV[1]) \
             redis.call('SREM', KEYS[4], ARGV[2]) \
             redis.call('SREM', KEYS[5], ARGV[2]) \
             return {2, existing or ''}",
        )
        .key(feedback_key(account_id))
        .key(job_key(account_id))
        .key(notification_claim_key(account_id))
        .key(FAILED_KEY)
        .key(PENDING_NOTIFICATION_KEY)
        .arg(value)
        .arg(account_id)
        .invoke_async(&mut conn)
        .await
        .context("failed to save moderator feedback")?;
        match outcome {
            0 => bail!("no stored job for account {account_id}"),
            1 => bail!("notification delivery is in progress; retry feedback shortly"),
            2 => {}
            _ => bail!("unexpected moderator feedback result from Redis"),
        }
        // Empty means nothing to replace; an unparseable value reads the same way rather than
        // failing, since the new verdict is already written and this only feeds a log line.
        Ok(parse_feedback(Some(previous.as_str()))
            .ok()
            .flatten()
            .map(|feedback| feedback.status))
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
        conn.set_ex::<_, _, ()>(
            action_key(account_id),
            status.as_str(),
            ACCOUNT_STATE_RETENTION_SECS,
        )
        .await
        .context("failed to save moderation action")
    }

    /// Adds the current retention policy to records created before TTLs were introduced.
    ///
    /// The marker keeps later runs from scanning every account key, and is written only after both
    /// scans complete, so an interrupted migration is safely retried.
    pub async fn cleanup_expired_records(&self) -> Result<usize> {
        let migrated: bool = self
            .read(
                redis::cmd("EXISTS").arg(RETENTION_MIGRATION_KEY),
                "failed to read Redis retention migration state",
            )
            .await?;
        if migrated {
            return Ok(0);
        }

        let applied = self.apply_job_retention().await? + self.expire_legacy_actions().await?;

        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(RETENTION_MIGRATION_KEY, "complete")
            .await
            .context("failed to save Redis retention migration state")?;
        Ok(applied)
    }

    /// Expires completed and abandoned processing jobs according to their stored update time.
    /// Failed and notification-pending jobs remain durable until an operator resolves them.
    async fn apply_job_retention(&self) -> Result<usize> {
        let now = now_timestamp();
        let mut cursor = 0u64;
        let mut applied = 0usize;
        loop {
            let mut scan = redis::cmd("SCAN");
            scan.arg(cursor)
                .arg("MATCH")
                .arg(format!("{KEY_PREFIX}:job:*"))
                .arg("COUNT")
                .arg(500);
            let (next_cursor, keys): (u64, Vec<String>) =
                self.read(&scan, "failed to scan legacy Redis jobs").await?;

            if !keys.is_empty() {
                let mut reads = redis::pipe();
                for key in &keys {
                    reads.get(key);
                }
                let values: Vec<Option<String>> = self
                    .read(&reads, "failed to read legacy Redis jobs")
                    .await?;
                let mut updates = redis::pipe();
                for (key, value) in keys.iter().zip(values) {
                    let Some(job) = parse_job(value.as_deref())? else {
                        continue;
                    };
                    match remaining_job_ttl(&job, now) {
                        Some(0) => {
                            updates.del(key).ignore();
                            applied += 1;
                        }
                        Some(ttl) => {
                            updates.expire(key, ttl as i64).ignore();
                            applied += 1;
                        }
                        None => {}
                    }
                }
                if !updates.is_empty() {
                    let mut conn = self.conn.clone();
                    updates
                        .query_async::<()>(&mut conn)
                        .await
                        .context("failed to apply legacy Redis job retention")?;
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                return Ok(applied);
            }
        }
    }

    /// Moderation action values predate timestamps, so give legacy keys one full retention window.
    async fn expire_legacy_actions(&self) -> Result<usize> {
        let mut cursor = 0u64;
        let mut applied = 0usize;
        loop {
            let mut scan = redis::cmd("SCAN");
            scan.arg(cursor)
                .arg("MATCH")
                .arg(format!("{KEY_PREFIX}:moderation:*"))
                .arg("COUNT")
                .arg(500);
            let (next_cursor, keys): (u64, Vec<String>) = self
                .read(&scan, "failed to scan legacy Redis records")
                .await?;
            if !keys.is_empty() {
                let mut expiration = redis::pipe();
                for key in &keys {
                    expiration
                        .expire(key, ACCOUNT_STATE_RETENTION_SECS as i64)
                        .ignore();
                }
                let mut conn = self.conn.clone();
                expiration
                    .query_async::<()>(&mut conn)
                    .await
                    .context("failed to apply legacy Redis record retention")?;
                applied += keys.len();
            }
            cursor = next_cursor;
            if cursor == 0 {
                return Ok(applied);
            }
        }
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
        let value: Option<String> = self
            .read_key(
                feedback_key(account_id),
                "failed to read moderator feedback",
            )
            .await?;
        Ok(parse_feedback(value.as_deref())?.map(|feedback| feedback.status))
    }

    pub async fn failed_ids(&self, limit: usize) -> Result<Vec<String>> {
        let mut queue = redis::pipe();
        queue
            .smembers(FAILED_KEY)
            .smembers(PENDING_NOTIFICATION_KEY);
        let (mut ids, pending): (Vec<String>, Vec<String>) =
            self.read(&queue, "failed to read retry queue").await?;
        ids.extend(pending);
        ids.sort_by(|a, b| numeric_id_cmp(a, b));
        ids.dedup();

        let mut failed = Vec::new();
        for id in ids {
            // Both keys in one round trip: the queue can hold thousands of IDs, and this walks it
            // until `limit` live ones are found.
            let mut state = redis::pipe();
            state.get(feedback_key(&id)).get(job_key(&id));
            let (feedback, job): (Option<String>, Option<String>) = self
                .read(&state, "failed to read queued account state")
                .await?;
            // A missing job stays retryable: an interrupted retry can leave its ID queued after the
            // temporary Processing record expires, and begin_job reconstructs it.
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
        self.write_job(&job, Retry::Clear, "failed to mark unavailable account")
            .await
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
    /// accounts share one. With `record` unset nothing is written, so a dry run reports the same
    /// matches without leaving a trace.
    ///
    /// An account can carry a bio fingerprint plus a domain per extracted link, so this runs over
    /// tens of keys, all in one pipeline: issued serially they cost four to five round trips per
    /// key, which dominated the time spent checking an account. Not `atomic()` — these are
    /// independent per-key housekeeping commands, and MULTI/EXEC would only add contention.
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
        let mut conn = self.conn.clone();
        let per_key: Vec<Vec<String>> = campaign_pipeline(&keys, account_id, now, record)
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
        let mut pipeline = redis::pipe();
        set_job(&mut pipeline, job, serialize_job(job)?);
        let mut conn = self.conn.clone();
        pipeline
            .query_async::<()>(&mut conn)
            .await
            .context("failed to save account job to Redis")
    }

    /// Persists a job that reached an outcome and moves the account in or out of the retry queue to
    /// match, in one transaction: split, a crash in between would leave a completed account queued
    /// for retry, or a failed one with nothing to pick it up.
    ///
    /// The pending-notification set is cleared either way — once the job says what happened, the
    /// delivery it tracked is no longer in doubt.
    async fn write_job(&self, job: &JobRecord, retry: Retry, what: &'static str) -> Result<()> {
        let value = serialize_job(job)?;
        let account_id = &job.account_id;
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        set_job(&mut pipeline, job, value);
        match retry {
            Retry::Queue => pipeline.sadd(FAILED_KEY, account_id).ignore(),
            Retry::Clear => pipeline.srem(FAILED_KEY, account_id).ignore(),
        };
        pipeline.srem(PENDING_NOTIFICATION_KEY, account_id).ignore();
        let mut conn = self.conn.clone();
        pipeline.query_async::<()>(&mut conn).await.context(what)
    }
}

/// What [`StateStore::write_job`] does with the account's place in the retry queue.
#[derive(Clone, Copy)]
enum Retry {
    /// The check failed; `retry-failed` should pick the account up again.
    Queue,
    /// The account reached a terminal status and has nothing left to retry.
    Clear,
}

fn serialize_job(job: &JobRecord) -> Result<String> {
    serde_json::to_string(job).context("failed to serialize account job")
}

/// Writes account jobs with retention only when no retry or notification obligation remains.
fn set_job(pipeline: &mut Pipeline, job: &JobRecord, value: String) {
    if job.status.is_completed() || job.status == JobStatus::Processing {
        pipeline
            .set_ex(
                job_key(&job.account_id),
                value,
                ACCOUNT_STATE_RETENTION_SECS,
            )
            .ignore();
    } else {
        pipeline.set(job_key(&job.account_id), value).ignore();
    }
}

/// Remaining retention for a legacy job, or `None` when it still requires operator action.
fn remaining_job_ttl(job: &JobRecord, now: u64) -> Option<u64> {
    (job.status.is_completed() || job.status == JobStatus::Processing)
        .then(|| ACCOUNT_STATE_RETENTION_SECS.saturating_sub(now.saturating_sub(job.updated_at)))
}

/// Builds the per-key campaign commands for [`StateStore::campaign_context`]. Exactly one reply is
/// kept per key — the newest members still inside the window — so the caller reads back the same
/// shape regardless of `record`.
fn campaign_pipeline(keys: &[String], account_id: &str, now: u64, record: bool) -> redis::Pipeline {
    let cutoff = now.saturating_sub(CAMPAIGN_WINDOW_SECS);
    let mut pipeline = redis::pipe();
    for key in keys {
        if record {
            pipeline
                // Drop entries that fell out of the window before adding to or capping the key.
                .cmd("ZREMRANGEBYSCORE")
                .arg(key)
                .arg("-inf")
                .arg(cutoff)
                .ignore()
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
        // By score rather than by rank, so a dry run can skip the trim above and stay read-only
        // without reporting accounts that have since aged out. The bound is exclusive, matching
        // what the trim removes.
        pipeline
            .cmd("ZREVRANGEBYSCORE")
            .arg(key)
            .arg("+inf")
            .arg(format!("({cutoff}"))
            .arg("LIMIT")
            .arg(0)
            .arg(CAMPAIGN_MATCHES_REPORTED);
    }
    pipeline
}

/// A read [`StateStore::read`] can reissue against a replacement connection. `Cmd` and `Pipeline`
/// carry the same `query_async` but share no trait that names it, so without this the one retry
/// would be written out once per shape of read.
trait RedisRead {
    async fn run<T: FromRedisValue>(&self, conn: &mut ConnectionManager) -> RedisResult<T>;
}

impl RedisRead for redis::Cmd {
    async fn run<T: FromRedisValue>(&self, conn: &mut ConnectionManager) -> RedisResult<T> {
        self.query_async(conn).await
    }
}

impl RedisRead for Pipeline {
    async fn run<T: FromRedisValue>(&self, conn: &mut ConnectionManager) -> RedisResult<T> {
        self.query_async(conn).await
    }
}

/// Reports the connection loss [`StateStore::read`] is about to retry through. Its
/// `is_unrecoverable_error` guard is the same condition [`ConnectionManager`] uses to replace the
/// connection, so it is exactly the set of failures a second attempt reaches a live socket for.
fn note_reconnect(error: &RedisError, what: &'static str) {
    warn!(error = %error, read = what, "Redis connection was replaced, retrying the read once");
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
/// Each signal is read newest-first, but merging them for de-duplication loses that order, and the
/// set's own order is textual — `"1000"` ahead of `"999"`. Re-sorting numerically, descending,
/// keeps the accounts the campaign report is about.
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

    fn stored_job(status: JobStatus, updated_at: u64) -> JobRecord {
        JobRecord {
            account_id: "42".to_string(),
            acct: "alice@example.com".to_string(),
            status,
            attempts: 1,
            updated_at,
            model: "model".to_string(),
            prompt_version: "prompt".to_string(),
            verdict: None,
            notified: false,
            error: None,
            campaign_match_count: 0,
            campaign_accounts: Vec::new(),
        }
    }

    #[test]
    fn completed_statuses_are_classified() {
        assert!(JobStatus::Spam.is_completed());
        assert!(JobStatus::FalsePositive.is_completed());
        assert!(!JobStatus::Failed.is_completed());
        assert!(!JobStatus::Processing.is_completed());
        assert!(!JobStatus::NotificationPending.is_completed());
        assert!(!is_completed_job(None).unwrap());
    }

    #[test]
    fn campaign_matches_keep_the_most_recent_accounts() {
        // IDs increase over time, so "most recent" is the numerically largest.
        let ids = (1..=CAMPAIGN_MATCHES_REPORTED as u64 + 5)
            .map(|id| (id * 100).to_string())
            .collect::<BTreeSet<_>>();
        let kept = most_recent_matches(ids);

        assert_eq!(kept.len(), CAMPAIGN_MATCHES_REPORTED);
        assert_eq!(kept[0], "2500");
        assert_eq!(kept[kept.len() - 1], "600");
    }

    /// A timestamp far enough past the epoch that the campaign window does not clamp to zero.
    const CAMPAIGN_NOW: u64 = 1_800_000_000;

    /// The arguments a pipeline would send, one entry per RESP token.
    fn pipeline_tokens(pipeline: redis::Pipeline) -> Vec<String> {
        String::from_utf8_lossy(&pipeline.get_packed_pipeline())
            .split("\r\n")
            // Drop the array and bulk-string length prefixes, keeping the payload tokens.
            .filter(|part| !part.is_empty() && !part.starts_with('*') && !part.starts_with('$'))
            .map(str::to_string)
            .collect()
    }

    fn campaign_tokens(record: bool) -> Vec<String> {
        pipeline_tokens(campaign_pipeline(
            &["k".to_string()],
            "42",
            CAMPAIGN_NOW,
            record,
        ))
    }

    #[test]
    fn only_jobs_without_outstanding_work_expire() {
        let has_expiration = |status| {
            let job = stored_job(status, CAMPAIGN_NOW);
            let mut pipeline = redis::pipe();
            set_job(&mut pipeline, &job, "value".to_string());
            pipeline_tokens(pipeline)
                .iter()
                .any(|token| token == "SETEX")
        };

        assert!(has_expiration(JobStatus::Processing));
        assert!(has_expiration(JobStatus::NotSpam));
        assert!(!has_expiration(JobStatus::Failed));
        assert!(!has_expiration(JobStatus::NotificationPending));
    }

    #[test]
    fn legacy_job_retention_uses_the_stored_update_time() {
        let recent = stored_job(JobStatus::Spam, CAMPAIGN_NOW - 60);
        assert_eq!(
            remaining_job_ttl(&recent, CAMPAIGN_NOW),
            Some(ACCOUNT_STATE_RETENTION_SECS - 60)
        );

        let old = stored_job(
            JobStatus::NotSpam,
            CAMPAIGN_NOW - ACCOUNT_STATE_RETENTION_SECS,
        );
        assert_eq!(remaining_job_ttl(&old, CAMPAIGN_NOW), Some(0));
        assert_eq!(
            remaining_job_ttl(&stored_job(JobStatus::Failed, CAMPAIGN_NOW), CAMPAIGN_NOW),
            None
        );
        assert_eq!(
            remaining_job_ttl(
                &stored_job(JobStatus::NotificationPending, CAMPAIGN_NOW),
                CAMPAIGN_NOW
            ),
            None
        );
    }

    #[test]
    fn a_dry_run_reads_the_campaign_index_without_writing_to_it() {
        // `dry-run` leaves no trace, so the read must not depend on trimming the key first.
        let commands = |record| {
            campaign_tokens(record)
                .into_iter()
                .filter(|token| token.chars().all(|ch| ch.is_ascii_uppercase()))
                .collect::<Vec<_>>()
        };
        assert_eq!(commands(false), ["ZREVRANGEBYSCORE", "LIMIT"]);
        assert_eq!(
            commands(true),
            [
                "ZREMRANGEBYSCORE",
                "ZADD",
                "EXPIRE",
                "ZREMRANGEBYRANK",
                "ZREVRANGEBYSCORE",
                "LIMIT",
            ]
        );
    }

    #[test]
    fn the_campaign_window_bound_excludes_what_the_trim_removes() {
        // ZREMRANGEBYSCORE's max is inclusive, so the read's min must be exclusive or a dry run
        // would report an account the recording path had already dropped.
        let cutoff = CAMPAIGN_NOW - CAMPAIGN_WINDOW_SECS;
        let tokens = campaign_tokens(true);
        assert!(tokens.contains(&cutoff.to_string()), "{tokens:?}");
        assert!(tokens.contains(&format!("({cutoff}")), "{tokens:?}");
        // The account is scored with the current time, so it lands inside its own window.
        assert!(tokens.contains(&CAMPAIGN_NOW.to_string()), "{tokens:?}");
    }

    #[test]
    fn the_verdict_a_moderator_replaced_is_reported_back() {
        // `record_feedback` maps the script's reply through this: an empty string means nothing was
        // replaced, and an unparseable one must not fail the verdict already written.
        let replaced = |raw: &str| {
            parse_feedback(Some(raw))
                .ok()
                .flatten()
                .map(|feedback| feedback.status)
        };
        let stored = serde_json::to_string(&FeedbackRecord {
            status: JobStatus::ConfirmedSpam,
            user_id: "U1".to_string(),
            updated_at: 1,
        })
        .unwrap();

        assert_eq!(replaced(&stored), Some(JobStatus::ConfirmedSpam));
        assert_eq!(replaced(""), None);
        assert_eq!(replaced("{corrupt"), None);
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
