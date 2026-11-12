//! Signals of moderator-confirmed spam, matched against later checks.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use super::{
    ACCOUNT_STATE_RETENTION_SECS, JobStatus, KEY_PREFIX, StateStore, add_windowed, feedback_key,
    job_key, now_timestamp, parse_feedback, parse_job,
};
use crate::chain;
use crate::signals::digest;

/// How long a confirmed account counts toward bio and domain matches.
const KNOWN_SPAM_WINDOW_SECS: u64 = 365 * 24 * 60 * 60;
const MEMBERS_PER_SIGNAL: i64 = 1_000;
/// High enough that a large server's observed count is not understated.
const OBSERVED_PER_SERVER: i64 = 20_000;

/// The signals a check stores on the job, so the account can be learned after Mastodon blanks it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CheckSignals {
    pub instance: Option<String>,
    pub bio_fingerprint: Option<String>,
    pub link_domains: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LearnSource {
    ConfirmedSpam,
    SlackAction,
    MastodonSuspension,
}

#[derive(Serialize, Deserialize)]
struct KnownSpamRecord {
    source: LearnSource,
    /// The checker had not flagged it.
    missed: bool,
    /// The index sets it was added to, for [`StateStore::forget_spam`].
    keys: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LearnOutcome {
    Learned {
        missed: bool,
    },
    AlreadyKnown,
    /// No job with signals: never checked, or checked too long ago.
    NoSignals,
    ClearedByModerator,
}

#[derive(Clone, Debug, Default)]
pub struct KnownSpamContext {
    pub bio_matches: u64,
    /// Matching domains with their account counts, most matched first.
    pub domain_matches: Vec<(String, u64)>,
    pub server: Option<ServerSpam>,
}

/// Accounts from one server checked within the retention window.
#[derive(Clone, Debug)]
pub struct ServerSpam {
    pub domain: String,
    pub confirmed: u64,
    pub observed: u64,
}

impl ServerSpam {
    /// At least two confirmed, making up at least a quarter of those observed.
    pub fn is_spam_heavy(&self) -> bool {
        self.confirmed >= 2 && self.confirmed.saturating_mul(4) >= self.observed
    }
}

impl StateStore {
    /// Matches `signals` against confirmed spam, excluding `account_id` itself. With `record`, also
    /// counts the account as observed from its server.
    pub async fn known_spam_context(
        &self,
        account_id: &str,
        signals: &CheckSignals,
        record: bool,
    ) -> Result<KnownSpamContext> {
        let now = now_timestamp();
        let signal_cutoff = now.saturating_sub(KNOWN_SPAM_WINDOW_SECS);
        let server_cutoff = now.saturating_sub(ACCOUNT_STATE_RETENTION_SECS);

        let mut lookups: Vec<(String, u64)> = Vec::new();
        lookups.extend(
            signals
                .bio_fingerprint
                .as_deref()
                .map(|fp| (bio_key(fp), signal_cutoff)),
        );
        lookups.extend(
            signals
                .link_domains
                .iter()
                .map(|domain| (domain_key(domain), signal_cutoff)),
        );
        if let Some(instance) = &signals.instance {
            lookups.push((server_key(instance), server_cutoff));
            lookups.push((observed_server_key(instance), server_cutoff));
        }
        if lookups.is_empty() {
            return Ok(KnownSpamContext::default());
        }

        let mut pipeline = redis::pipe();
        if record && let Some(instance) = &signals.instance {
            add_windowed(
                &mut pipeline,
                &observed_server_key(instance),
                account_id,
                now,
                now,
                ACCOUNT_STATE_RETENTION_SECS,
                OBSERVED_PER_SERVER,
            );
        }
        for (key, cutoff) in &lookups {
            pipeline
                .zcount(key, format!("({cutoff}"), "+inf")
                .zscore(key, account_id);
        }
        let mut conn = self.conn.clone();
        // Read as floats: ZCOUNT's integer parses as one, and ZSCORE's score is one.
        let replies: Vec<Option<f64>> = pipeline
            .query_async(&mut conn)
            .await
            .context("failed to read known spam index")?;
        let mut counts = lookups
            .iter()
            .zip(replies.chunks(2))
            .map(|((_, cutoff), reply)| {
                let count = reply.first().copied().flatten().unwrap_or(0.0) as u64;
                let own = reply
                    .get(1)
                    .copied()
                    .flatten()
                    .is_some_and(|score| score > *cutoff as f64);
                count.saturating_sub(u64::from(own))
            });

        let bio_matches = signals
            .bio_fingerprint
            .as_ref()
            .map_or(0, |_| counts.next().unwrap_or(0));
        let mut domain_matches: Vec<(String, u64)> = signals
            .link_domains
            .iter()
            .filter_map(|domain| {
                let count = counts.next().unwrap_or(0);
                (count > 0).then(|| (domain.clone(), count))
            })
            .collect();
        domain_matches.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let server = signals.instance.as_ref().map(|domain| ServerSpam {
            domain: domain.clone(),
            confirmed: counts.next().unwrap_or(0),
            observed: counts.next().unwrap_or(0),
        });
        Ok(KnownSpamContext {
            bio_matches,
            domain_matches,
            server,
        })
    }

    /// Adds an account's stored signals to the known spam index.
    pub async fn learn_spam(&self, account_id: &str, source: LearnSource) -> Result<LearnOutcome> {
        let mut state = redis::pipe();
        state
            .get(feedback_key(account_id))
            .get(job_key(account_id))
            .exists(known_spam_record_key(account_id));
        let (feedback, job, known): (Option<String>, Option<String>, bool) =
            self.read(&state, "failed to read account state").await?;
        if is_false_positive(feedback.as_deref())? {
            return Ok(LearnOutcome::ClearedByModerator);
        }
        if known {
            return Ok(LearnOutcome::AlreadyKnown);
        }
        let Some((job, signals)) = parse_job(job.as_deref())?
            .and_then(|job| job.signals.clone().map(|signals| (job, signals)))
        else {
            return Ok(LearnOutcome::NoSignals);
        };

        let mut keys = Vec::new();
        keys.extend(signals.bio_fingerprint.as_deref().map(bio_key));
        keys.extend(signals.link_domains.iter().map(|domain| domain_key(domain)));
        keys.extend(signals.instance.as_deref().map(server_key));
        let missed = !matches!(job.verdict, Some(ref verdict) if verdict.spam);
        let record = KnownSpamRecord {
            source,
            missed,
            keys,
        };

        let now = now_timestamp();
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for key in &record.keys {
            // Scored by check time, so the server share compares like with like.
            add_windowed(
                &mut pipeline,
                key,
                account_id,
                job.updated_at,
                now,
                KNOWN_SPAM_WINDOW_SECS,
                MEMBERS_PER_SIGNAL,
            );
        }
        pipeline
            .set_ex(
                known_spam_record_key(account_id),
                serde_json::to_string(&record).context("failed to serialize known spam record")?,
                KNOWN_SPAM_WINDOW_SECS,
            )
            .ignore();
        self.write(&pipeline, "failed to save known spam").await?;

        // A false positive recorded since the read above found nothing to forget; undo it here.
        let feedback: Option<String> = self
            .read_key(
                feedback_key(account_id),
                "failed to read moderator feedback",
            )
            .await?;
        if is_false_positive(feedback.as_deref())? {
            self.forget_spam(account_id).await?;
            return Ok(LearnOutcome::ClearedByModerator);
        }
        Ok(LearnOutcome::Learned { missed })
    }

    /// [`Self::learn_spam`] for side effects of a moderator action: the outcome is logged, and a
    /// failure is too rather than failing the action.
    pub async fn learn_logged(
        &self,
        account_id: &str,
        source: LearnSource,
    ) -> Option<LearnOutcome> {
        match self.learn_spam(account_id, source).await {
            Ok(outcome) => {
                match outcome {
                    LearnOutcome::Learned { missed } => {
                        info!(account_id, ?source, missed, "learned confirmed spam");
                    }
                    LearnOutcome::NoSignals => {
                        info!(account_id, ?source, "no stored signals to learn from");
                    }
                    LearnOutcome::AlreadyKnown | LearnOutcome::ClearedByModerator => {}
                }
                Some(outcome)
            }
            Err(error) => {
                error!(account_id, error = %chain(&error), "failed to learn confirmed spam");
                None
            }
        }
    }

    /// Removes an account from the known spam index, returning whether it was there.
    pub async fn forget_spam(&self, account_id: &str) -> Result<bool> {
        let value: Option<String> = self
            .read_key(
                known_spam_record_key(account_id),
                "failed to read known spam record",
            )
            .await?;
        let Some(value) = value else {
            return Ok(false);
        };
        let record: KnownSpamRecord =
            serde_json::from_str(&value).context("invalid known spam record in Redis")?;
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for key in &record.keys {
            pipeline.zrem(key, account_id).ignore();
        }
        pipeline.del(known_spam_record_key(account_id)).ignore();
        self.write(&pipeline, "failed to forget known spam").await?;
        Ok(true)
    }
}

fn is_false_positive(feedback: Option<&str>) -> Result<bool> {
    Ok(matches!(
        parse_feedback(feedback)?.map(|feedback| feedback.status),
        Some(JobStatus::FalsePositive)
    ))
}

fn known_spam_record_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:known_spam:account:{account_id}")
}

fn bio_key(fingerprint: &str) -> String {
    format!("{KEY_PREFIX}:known_spam:bio:{fingerprint}")
}

fn domain_key(domain: &str) -> String {
    format!("{KEY_PREFIX}:known_spam:domain:{}", digest(domain))
}

fn server_key(instance: &str) -> String {
    format!(
        "{KEY_PREFIX}:known_spam:server:{}",
        digest(&instance.to_ascii_lowercase())
    )
}

fn observed_server_key(instance: &str) -> String {
    format!(
        "{KEY_PREFIX}:observed:server:{}",
        digest(&instance.to_ascii_lowercase())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(confirmed: u64, observed: u64) -> ServerSpam {
        ServerSpam {
            domain: "spam.example".to_string(),
            confirmed,
            observed,
        }
    }

    #[test]
    fn a_server_is_spam_heavy_by_count_and_share() {
        assert!(server(2, 2).is_spam_heavy());
        assert!(server(3, 12).is_spam_heavy());
        assert!(!server(1, 1).is_spam_heavy());
        assert!(!server(30, 1_000).is_spam_heavy());
    }
}
