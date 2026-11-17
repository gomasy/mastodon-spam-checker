//! Acting on known spam without waiting for a moderator.
//!
//! An account qualifies only when the LLM judges it spam with high confidence *and* it shares a
//! concrete signal — identical profile text, or a destination domain — with accounts a moderator
//! already confirmed as spam. A spam-heavy server alone never qualifies: it says where an account
//! is from, not that it is one of the accounts a moderator has seen.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use rust_i18n::t;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::chain;
use crate::mastodon::{AdminAccount, MastodonClient};
use crate::postgres::{self, ModerationNoteWriter};
use crate::redis::{KnownSpamContext, StateStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutoModerationMode {
    Suspend,
    /// Suspends, then permanently deletes the account's data.
    Delete,
}

#[derive(Clone)]
pub struct AutoModerationConfig {
    pub mode: AutoModerationMode,
    /// The spam probability a verdict must reach, on top of the known spam match.
    pub min_confidence: f64,
    /// Domains whose matches never qualify, on top of [`PLATFORM_DOMAINS`].
    pub ignored_domains: BTreeSet<String>,
}

impl AutoModerationConfig {
    /// `off` disables auto-moderation; `false` and `0` are accepted like booleans elsewhere.
    pub fn parse_mode(value: &str) -> Result<Option<AutoModerationMode>> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "0" => Ok(None),
            "suspend" => Ok(Some(AutoModerationMode::Suspend)),
            "delete" => Ok(Some(AutoModerationMode::Delete)),
            _ => bail!("AUTO_MODERATION must be off, suspend, or delete"),
        }
    }

    pub fn parse_domains(value: &str) -> BTreeSet<String> {
        value
            .split(',')
            .map(|domain| domain.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|domain| !domain.is_empty())
            .collect()
    }

    /// The known spam signal that lets `known` be acted on without a moderator, if any.
    pub fn qualifying_match(
        &self,
        spam_probability: f64,
        known: &KnownSpamContext,
    ) -> Option<KnownSpamMatch> {
        if spam_probability < self.min_confidence {
            return None;
        }
        if known.bio_matches > 0 {
            return Some(KnownSpamMatch::Bio {
                accounts: known.bio_matches,
            });
        }
        known
            .domain_matches
            .iter()
            .find(|(domain, count)| *count >= MIN_DOMAIN_MATCHES && !self.is_ignored_domain(domain))
            .map(|(domain, count)| KnownSpamMatch::Domain {
                domain: domain.clone(),
                accounts: *count,
            })
    }

    fn is_ignored_domain(&self, domain: &str) -> bool {
        // A fully qualified `youtube.com.` is still YouTube.
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        // The domain itself and each parent: `m.youtube.com` is YouTube too.
        std::iter::successors(Some(domain.as_str()), |d| {
            d.split_once('.').map(|(_, rest)| rest)
        })
        .any(|candidate| {
            PLATFORM_DOMAINS.contains(&candidate) || self.ignored_domains.contains(candidate)
        })
    }
}

/// A shared destination domain only counts once this many confirmed accounts link to it: one
/// confirmed account that happened to link somewhere common must not condemn everyone else who does.
const MIN_DOMAIN_MATCHES: u64 = 2;

/// General-purpose platforms whose domain says nothing about who links to them. The LLM is told to
/// ignore these in prose; auto-moderation needs the list spelled out, because it acts on the match
/// itself.
const PLATFORM_DOMAINS: &[&str] = &[
    // Social networks and messaging
    "x.com",
    "twitter.com",
    "t.co",
    "facebook.com",
    "fb.com",
    "instagram.com",
    "threads.net",
    "threads.com",
    "tiktok.com",
    "bsky.app",
    "reddit.com",
    "linkedin.com",
    "pinterest.com",
    "tumblr.com",
    "discord.gg",
    "discord.com",
    "t.me",
    "telegram.me",
    "line.me",
    "weibo.com",
    "vk.com",
    // Fediverse
    "mastodon.social",
    "mstdn.jp",
    "misskey.io",
    "pawoo.net",
    // Video, audio, and images
    "youtube.com",
    "youtu.be",
    "twitch.tv",
    "vimeo.com",
    "nicovideo.jp",
    "nico.ms",
    "spotify.com",
    "soundcloud.com",
    "bandcamp.com",
    "apple.com",
    "imgur.com",
    "flickr.com",
    "pixiv.net",
    // Link-in-bio and personal pages
    "linktr.ee",
    "lit.link",
    "linkin.bio",
    "carrd.co",
    "about.me",
    "bio.link",
    "beacons.ai",
    // Creator support and shops
    "patreon.com",
    "ko-fi.com",
    "buymeacoffee.com",
    "fanbox.cc",
    "booth.pm",
    "skeb.jp",
    "fantia.jp",
    "etsy.com",
    "amazon.com",
    "amazon.co.jp",
    "amzn.to",
    "amzn.asia",
    // Code hosting and publishing
    "github.com",
    "github.io",
    "gitlab.com",
    "codeberg.org",
    "medium.com",
    "substack.com",
    "note.com",
    "hatenablog.com",
    "wordpress.com",
    "blogspot.com",
    "wikipedia.org",
    "google.com",
    "goo.gl",
    // URL shorteners
    "bit.ly",
    "tinyurl.com",
    "ow.ly",
    "buff.ly",
    "is.gd",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownSpamMatch {
    Bio { accounts: u64 },
    Domain { domain: String, accounts: u64 },
}

impl KnownSpamMatch {
    /// Unsanitized: Slack callers must pass it through `sanitize_mrkdwn`.
    pub fn describe(&self) -> String {
        match self {
            Self::Bio { accounts } => t!("auto_match_bio", count = accounts).to_string(),
            Self::Domain { domain, accounts } => {
                t!("auto_match_domain", domain = domain, count = accounts).to_string()
            }
        }
    }
}

/// What auto-moderation did, carried into the Slack notification.
#[derive(Clone, Debug)]
pub struct AutoModerationOutcome {
    pub matched: KnownSpamMatch,
    pub result: AutoModerationResult,
}

impl AutoModerationOutcome {
    /// Whether the account was at least suspended.
    pub fn acted(&self) -> bool {
        !matches!(self.result, AutoModerationResult::Failed(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutoModerationResult {
    Suspended,
    Deleted,
    /// Suspended, but deleting the data failed; the delete button stays for a moderator.
    DeleteFailed(String),
    /// Nothing was done; the notification keeps the manual suspend button.
    Failed(String),
}

/// How far auto-moderation got with an account, kept in Redis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoModerationRecord {
    pub state: AutoModerationState,
    pub matched: KnownSpamMatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoModerationState {
    /// About to suspend, or interrupted while doing so.
    Pending,
    Suspended,
    Deleted,
}

impl AutoModerationRecord {
    /// The outcome to report for a record found on a re-sent notification, where the error that
    /// left it unfinished is no longer known.
    pub fn outcome(&self) -> AutoModerationOutcome {
        let result = match self.state {
            AutoModerationState::Pending => {
                AutoModerationResult::Failed(t!("auto_interrupted").to_string())
            }
            AutoModerationState::Suspended => AutoModerationResult::Suspended,
            AutoModerationState::Deleted => AutoModerationResult::Deleted,
        };
        AutoModerationOutcome {
            matched: self.matched.clone(),
            result,
        }
    }
}

/// Suspends, and in delete mode deletes, an account that qualified. A Mastodon failure is reported
/// in the outcome rather than raised — a moderator can still act from the notification, so it must
/// not stop the run — while a Redis failure is raised like any other state failure.
///
/// Re-running for an account that already got this far picks up where it stopped.
pub async fn apply(
    mode: AutoModerationMode,
    mastodon: &MastodonClient,
    store: &StateStore,
    note_writer: Option<&ModerationNoteWriter>,
    account: &AdminAccount,
    matched: KnownSpamMatch,
) -> Result<AutoModerationOutcome> {
    let id = account.id.as_str();
    let previous = store.auto_moderation(id).await?.map(|record| record.state);
    let outcome = |result| AutoModerationOutcome {
        matched: matched.clone(),
        result,
    };
    let save = |state| {
        let record = AutoModerationRecord {
            state,
            matched: matched.clone(),
        };
        async move { store.save_auto_moderation(id, &record).await }
    };

    if previous == Some(AutoModerationState::Deleted) {
        return Ok(outcome(AutoModerationResult::Deleted));
    }
    if previous != Some(AutoModerationState::Suspended) {
        save(AutoModerationState::Pending).await?;
        if let Err(error) = mastodon.suspend_account(id).await {
            error!(account_id = id, error = %chain(&error), "auto-moderation failed to suspend account");
            store.abort_auto_moderation(id).await?;
            return Ok(outcome(AutoModerationResult::Failed(chain(&error))));
        }
        save(AutoModerationState::Suspended).await?;
        warn!(account_id = id, acct = %account.acct(), ?matched, "auto-moderation suspended account");
        let note = t!("note_auto_suspended", matched = matched.describe());
        postgres::add_note_logged(note_writer, id, &note).await;
    }

    if mode == AutoModerationMode::Suspend {
        return Ok(outcome(AutoModerationResult::Suspended));
    }
    if let Err(error) = mastodon.delete_account(id).await {
        error!(account_id = id, error = %chain(&error), "auto-moderation failed to delete account");
        return Ok(outcome(AutoModerationResult::DeleteFailed(chain(&error))));
    }
    save(AutoModerationState::Deleted).await?;
    info!(account_id = id, acct = %account.acct(), "auto-moderation deleted account data");
    Ok(outcome(AutoModerationResult::Deleted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> AutoModerationConfig {
        AutoModerationConfig {
            mode: AutoModerationMode::Suspend,
            min_confidence: 0.9,
            ignored_domains: AutoModerationConfig::parse_domains(extra),
        }
    }

    fn known(bio: u64, domains: &[(&str, u64)]) -> KnownSpamContext {
        KnownSpamContext {
            bio_matches: bio,
            domain_matches: domains.iter().map(|(d, c)| (d.to_string(), *c)).collect(),
            server: None,
        }
    }

    #[test]
    fn modes_are_parsed() {
        assert_eq!(AutoModerationConfig::parse_mode("off").unwrap(), None);
        assert_eq!(
            AutoModerationConfig::parse_mode(" Suspend ").unwrap(),
            Some(AutoModerationMode::Suspend)
        );
        assert_eq!(
            AutoModerationConfig::parse_mode("delete").unwrap(),
            Some(AutoModerationMode::Delete)
        );
        assert!(AutoModerationConfig::parse_mode("ban").is_err());
    }

    #[test]
    fn identical_profile_text_qualifies() {
        assert_eq!(
            config("").qualifying_match(0.95, &known(1, &[])),
            Some(KnownSpamMatch::Bio { accounts: 1 })
        );
    }

    #[test]
    fn low_confidence_never_qualifies() {
        assert_eq!(config("").qualifying_match(0.89, &known(5, &[])), None);
    }

    #[test]
    fn a_domain_needs_several_confirmed_accounts() {
        assert_eq!(
            config("").qualifying_match(0.95, &known(0, &[("shop.example", 1)])),
            None
        );
        assert_eq!(
            config("").qualifying_match(0.95, &known(0, &[("shop.example", 2)])),
            Some(KnownSpamMatch::Domain {
                domain: "shop.example".to_string(),
                accounts: 2
            })
        );
    }

    #[test]
    fn platform_domains_and_their_subdomains_never_qualify() {
        let config = config("Partner.Example, .cdn.example");
        for domain in [
            "youtube.com",
            "m.youtube.com",
            "partner.example",
            "a.cdn.example",
        ] {
            assert_eq!(
                config.qualifying_match(0.95, &known(0, &[(domain, 50)])),
                None,
                "{domain}"
            );
        }
        // A suffix that is not a parent domain is not covered.
        assert!(
            config
                .qualifying_match(0.95, &known(0, &[("notyoutube.com", 2)]))
                .is_some()
        );
    }

    #[test]
    fn a_later_domain_can_qualify_when_an_earlier_one_is_ignored() {
        assert_eq!(
            config("").qualifying_match(0.95, &known(0, &[("youtu.be", 9), ("shop.example", 2)])),
            Some(KnownSpamMatch::Domain {
                domain: "shop.example".to_string(),
                accounts: 2
            })
        );
    }

    #[test]
    fn a_spam_heavy_server_alone_never_qualifies() {
        let mut context = known(0, &[]);
        context.server = Some(crate::redis::ServerSpam {
            domain: "spam.example".to_string(),
            confirmed: 10,
            observed: 10,
        });
        assert_eq!(config("").qualifying_match(1.0, &context), None);
    }
}
