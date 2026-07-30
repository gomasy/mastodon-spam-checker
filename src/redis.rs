use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn is_completed(&self) -> bool {
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
    conn: MultiplexedConnection,
}

impl StateStore {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url).context("failed to create Redis client")?;
        let conn = client
            .get_multiplexed_async_connection()
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
        value
            .map(|value| serde_json::from_str(&value).context("invalid account job in Redis"))
            .transpose()
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
        conn.set::<_, _, ()>(action_key(account_id), format!("{status:?}"))
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
        let feedback: Option<FeedbackRecord> = value
            .map(|value| {
                serde_json::from_str(&value).context("invalid moderator feedback in Redis")
            })
            .transpose()?;
        Ok(feedback.map(|feedback| feedback.status))
    }

    pub async fn failed_ids(&self, limit: usize) -> Result<Vec<String>> {
        let mut conn = self.conn.clone();
        let mut ids: Vec<String> = conn
            .smembers(FAILED_KEY)
            .await
            .context("failed to read retry queue")?;
        let pending: Vec<String> = conn
            .smembers(PENDING_NOTIFICATION_KEY)
            .await
            .context("failed to read pending notification queue")?;
        ids.extend(pending);
        ids.sort_by(|a, b| numeric_id_cmp(a, b));
        ids.dedup();
        let mut failed = Vec::new();
        for id in ids {
            if self.has_terminal_feedback(&id).await?
                || self
                    .get_job(&id)
                    .await?
                    .is_some_and(|job| job.status.is_completed())
            {
                self.remove_failed(&id).await?;
            } else {
                failed.push(id);
                if failed.len() == limit {
                    break;
                }
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

    pub async fn campaign_context(
        &self,
        account_id: &str,
        bio_fingerprint: Option<&str>,
        link_domains: &[String],
        record: bool,
    ) -> Result<CampaignContext> {
        let mut conn = self.conn.clone();
        let mut keys = Vec::new();
        if let Some(fingerprint) = bio_fingerprint {
            keys.push(format!("{KEY_PREFIX}:campaign:bio:{fingerprint}"));
        }
        keys.extend(
            link_domains
                .iter()
                .map(|domain| format!("{KEY_PREFIX}:campaign:domain:{}", digest(domain))),
        );

        let now = now_timestamp();
        let cutoff = now.saturating_sub(CAMPAIGN_WINDOW_SECS);
        let mut matches = BTreeSet::new();
        for key in keys {
            redis::cmd("ZREMRANGEBYSCORE")
                .arg(&key)
                .arg("-inf")
                .arg(cutoff)
                .query_async::<i64>(&mut conn)
                .await
                .context("failed to prune campaign index")?;
            if record {
                conn.zadd::<_, _, _, ()>(&key, account_id, now)
                    .await
                    .context("failed to update campaign index")?;
                conn.expire::<_, ()>(&key, CAMPAIGN_WINDOW_SECS as i64)
                    .await
                    .context("failed to expire campaign index")?;
                redis::cmd("ZREMRANGEBYRANK")
                    .arg(&key)
                    .arg(0)
                    .arg(-(CAMPAIGN_MEMBERS_PER_SIGNAL + 1))
                    .query_async::<i64>(&mut conn)
                    .await
                    .context("failed to cap campaign index")?;
            }
            let members: Vec<String> = conn
                .zrevrange(&key, 0, 19)
                .await
                .context("failed to read campaign index")?;
            matches.extend(members.into_iter().filter(|id| id != account_id));
        }

        Ok(CampaignContext {
            matching_accounts: matches.into_iter().take(20).collect(),
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

fn numeric_id_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn digest(value: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
    fn numeric_ids_are_ordered_without_integer_conversion() {
        let mut ids = vec!["20".to_string(), "3".to_string(), "100".to_string()];
        ids.sort_by(|a, b| numeric_id_cmp(a, b));
        assert_eq!(ids, ["3", "20", "100"]);
    }
}
