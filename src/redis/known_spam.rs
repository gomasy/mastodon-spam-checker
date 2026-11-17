//! Signals of moderator-confirmed spam, matched against later checks.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use super::{
    ACCOUNT_STATE_RETENTION_SECS, JobStatus, KEY_PREFIX, StateStore, action_key, add_windowed,
    feedback_key, job_key, now_timestamp, parse_feedback, parse_job,
};
use crate::auto_moderation::{AutoModerationRecord, AutoModerationState};
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
    /// Suspended by auto-moderation, not by a moderator: learning it would let the checker confirm
    /// its own verdicts, spreading each match to every other signal on the account.
    AutoModerated,
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
            .exists(known_spam_record_key(account_id))
            .exists(auto_moderation_key(account_id));
        let (feedback, job, known, auto_moderated): (Option<String>, Option<String>, bool, bool) =
            self.read(&state, "failed to read account state").await?;
        if is_false_positive(feedback.as_deref())? {
            return Ok(LearnOutcome::ClearedByModerator);
        }
        if known {
            return Ok(LearnOutcome::AlreadyKnown);
        }
        // A moderator's own confirmation of an auto-moderated account is still learned.
        if auto_moderated && source == LearnSource::MastodonSuspension {
            return Ok(LearnOutcome::AutoModerated);
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
                    LearnOutcome::AlreadyKnown
                    | LearnOutcome::ClearedByModerator
                    | LearnOutcome::AutoModerated => {}
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

    /// The accounts among `ids`, suspended in Mastodon, that [`Self::learn_spam`] would learn from
    /// [`LearnSource::MastodonSuspension`], read in one round trip.
    pub async fn learnable(&self, ids: &[String]) -> Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut state = redis::pipe();
        for id in ids {
            state
                .get(feedback_key(id))
                .get(job_key(id))
                .exists(known_spam_record_key(id))
                .exists(auto_moderation_key(id));
        }
        let states: Vec<(Option<String>, Option<String>, bool, bool)> =
            self.read(&state, "failed to read account state").await?;
        Ok(ids
            .iter()
            .zip(states)
            .filter(|(_, (feedback, job, known, auto_moderated))| {
                // Unparseable state is left to learn_spam, which reports it.
                !known
                    && !auto_moderated
                    && !is_false_positive(feedback.as_deref()).unwrap_or(false)
                    && parse_job(job.as_deref())
                        .map_or(true, |job| job.is_some_and(|job| job.signals.is_some()))
            })
            .map(|(id, _)| id.clone())
            .collect())
    }
}

impl StateStore {
    /// Records how far auto-moderation got. `Pending` must be saved *before* Mastodon is asked to
    /// suspend: the marker is what keeps the suspension from being learned as a moderator's. A
    /// suspension or deletion is also recorded as the account's moderation action, without
    /// learning from it, unlike [`Self::record_action`].
    pub async fn save_auto_moderation(
        &self,
        account_id: &str,
        record: &AutoModerationRecord,
    ) -> Result<()> {
        let action = match record.state {
            AutoModerationState::Pending => None,
            AutoModerationState::Suspended => Some(JobStatus::Suspended),
            AutoModerationState::Deleted => Some(JobStatus::Deleted),
        };
        let value =
            serde_json::to_string(record).context("failed to serialize auto-moderation state")?;
        let mut pipeline = redis::pipe();
        pipeline.atomic();
        pipeline
            .set_ex(
                auto_moderation_key(account_id),
                value,
                ACCOUNT_STATE_RETENTION_SECS,
            )
            .ignore();
        if let Some(action) = action {
            pipeline
                .set_ex(
                    action_key(account_id),
                    action.as_str(),
                    ACCOUNT_STATE_RETENTION_SECS,
                )
                .ignore();
        }
        self.write(&pipeline, "failed to save auto-moderation state")
            .await
    }

    /// Removes the marker after a suspension that did not happen, so a moderator suspending the
    /// account by hand later is learned as usual.
    pub async fn abort_auto_moderation(&self, account_id: &str) -> Result<()> {
        let mut pipeline = redis::pipe();
        pipeline.del(auto_moderation_key(account_id)).ignore();
        self.write(&pipeline, "failed to clear auto-moderation state")
            .await
    }

    pub async fn auto_moderation(&self, account_id: &str) -> Result<Option<AutoModerationRecord>> {
        let value: Option<String> = self
            .read_key(
                auto_moderation_key(account_id),
                "failed to read auto-moderation state",
            )
            .await?;
        value
            .map(|value| {
                serde_json::from_str(&value).context("invalid auto-moderation state in Redis")
            })
            .transpose()
    }
}

fn auto_moderation_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:auto_moderation:{account_id}")
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
