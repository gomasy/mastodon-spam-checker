use anyhow::{Context, Result, bail};

use crate::encryption;
use crate::llm::is_decision_model;

pub struct PostgresConfig {
    pub database_url: String,
    pub moderator_account_id: i64,
}

impl PostgresConfig {
    pub fn from_env() -> Result<Option<Self>> {
        match optional_env("DATABASE_URL")? {
            Some(url) => {
                let id: i64 = required_env("MODERATOR_ACCOUNT_ID")?
                    .parse()
                    .context("MODERATOR_ACCOUNT_ID is not a valid integer")?;
                Ok(Some(Self {
                    database_url: url,
                    moderator_account_id: id,
                }))
            }
            None => Ok(None),
        }
    }
}

/// Reading posts from a remote account's own outbox when this instance holds none of them.
pub struct RemoteFetchConfig {
    /// Mastodon's database, for the instance actor's private key.
    pub database_url: String,
    /// The `keyId` remote servers resolve to verify signatures.
    pub key_id: reqwest::Url,
    /// Replaces the User-Agent otherwise built to match Mastodon's own.
    pub user_agent: Option<String>,
    /// Decrypts the key on Mastodon 4.7+.
    pub encryption: Option<encryption::Secrets>,
}

impl RemoteFetchConfig {
    fn from_env(mastodon_base_url: &str) -> Result<Option<Self>> {
        if !bool_env("REMOTE_FETCH", false)? {
            return Ok(None);
        }
        let database_url = optional_env("DATABASE_URL")?
            .context("REMOTE_FETCH requires DATABASE_URL to read the instance actor's key")?;
        let key_id = optional_env("INSTANCE_ACTOR_KEY_ID")?
            .unwrap_or_else(|| default_key_id(mastodon_base_url));
        let key_id =
            reqwest::Url::parse(&key_id).context("INSTANCE_ACTOR_KEY_ID is not a valid URL")?;
        if key_id.fragment().is_none_or(str::is_empty) {
            bail!("INSTANCE_ACTOR_KEY_ID must name a key with a fragment, e.g. #main-key");
        }
        if key_id.scheme() != "https" {
            bail!(
                "INSTANCE_ACTOR_KEY_ID must be an https URL; set it explicitly when \
                 MASTODON_BASE_URL is not the instance's public https URL"
            );
        }
        Ok(Some(Self {
            database_url,
            key_id,
            user_agent: optional_env("REMOTE_FETCH_USER_AGENT")?,
            encryption: encryption_secrets_from_env()?,
        }))
    }
}

fn encryption_secrets_from_env() -> Result<Option<encryption::Secrets>> {
    match (
        optional_env("ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY")?,
        optional_env("ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT")?,
    ) {
        (Some(primary_key), Some(key_derivation_salt)) => Ok(Some(encryption::Secrets {
            primary_key,
            key_derivation_salt,
        })),
        (None, None) => Ok(None),
        _ => bail!(
            "ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY and \
             ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT must be set together"
        ),
    }
}

/// Where Mastodon publishes the instance actor's key: `/actor#main-key` on the web domain.
fn default_key_id(mastodon_base_url: &str) -> String {
    format!("{}/actor#main-key", mastodon_base_url.trim_end_matches('/'))
}

pub struct DetectionConfig {
    pub mastodon_base_url: String,
    pub mastodon_access_token: String,
    pub openai_api_base: String,
    pub openai_api_key: String,
    pub openai_model: String,
    pub openai_json_mode: bool,
    /// Decision models: a not-spam verdict below this confidence (0.0–1.0) counts as spam.
    pub spam_confidence_threshold: f64,
    /// Decision models: a chat model that re-checks spam verdicts.
    pub openai_review_model: Option<String>,
    pub remote_fetch: Option<RemoteFetchConfig>,
}

impl DetectionConfig {
    pub fn from_env() -> Result<Self> {
        let (mastodon_base_url, mastodon_access_token) = mastodon_env()?;
        let openai_model = env_or("OPENAI_MODEL", "gpt-4o")?;
        let openai_review_model = optional_env("OPENAI_REVIEW_MODEL")?;
        validate_review_model(&openai_model, openai_review_model.as_deref())?;
        let remote_fetch = RemoteFetchConfig::from_env(&mastodon_base_url)?;
        Ok(Self {
            mastodon_base_url,
            mastodon_access_token,
            openai_api_base: required_env("OPENAI_API_BASE")?,
            openai_api_key: required_env("OPENAI_API_KEY")?,
            openai_model,
            openai_json_mode: bool_env("OPENAI_JSON_MODE", true)?,
            spam_confidence_threshold: match optional_env("SPAM_CONFIDENCE_THRESHOLD")? {
                Some(value) => parse_confidence_threshold(&value)?,
                None => 0.7,
            },
            openai_review_model,
            remote_fetch,
        })
    }
}

/// Everything a checking run needs beyond its Redis connection, which each entry point opens for
/// itself through [`redis_url_env`] before the run starts.
pub struct Config {
    pub detection: DetectionConfig,
    pub max_accounts_per_run: usize,
    pub check_concurrency: usize,
    pub slack_webhook_url: Option<String>,
    pub slack_channel: Option<String>,
    pub postgres: Option<PostgresConfig>,
}

impl Config {
    pub fn from_env(require_slack: bool) -> Result<Self> {
        Ok(Self {
            detection: DetectionConfig::from_env()?,
            max_accounts_per_run: positive_usize_env("MAX_ACCOUNTS_PER_RUN", 1_000)?,
            check_concurrency: positive_usize_env("CHECK_CONCURRENCY", 4)?,
            slack_webhook_url: if require_slack {
                Some(required_env("SLACK_WEBHOOK_URL")?)
            } else {
                optional_env("SLACK_WEBHOOK_URL")?
            },
            slack_channel: optional_env("SLACK_CHANNEL")?,
            postgres: PostgresConfig::from_env()?,
        })
    }
}

pub struct ServeConfig {
    pub mastodon_base_url: String,
    pub mastodon_access_token: String,
    pub slack_signing_secret: String,
    pub listen_addr: String,
    pub redis_url: String,
    pub postgres: Option<PostgresConfig>,
}

impl ServeConfig {
    pub fn from_env() -> Result<Self> {
        let (mastodon_base_url, mastodon_access_token) = mastodon_env()?;
        Ok(Self {
            mastodon_base_url,
            mastodon_access_token,
            slack_signing_secret: required_env("SLACK_SIGNING_SECRET")?,
            listen_addr: env_or("LISTEN_ADDR", "127.0.0.1:8990")?,
            redis_url: redis_url_env()?,
            postgres: PostgresConfig::from_env()?,
        })
    }
}

const DEFAULT_REDIS_URL: &str = "redis://localhost:6379";

/// `REDIS_URL`, or the local default. Every entry point reaches Redis, including subcommands that
/// build no full [`Config`], so the default lives here rather than at each call site.
pub fn redis_url_env() -> Result<String> {
    env_or("REDIS_URL", DEFAULT_REDIS_URL)
}

fn mastodon_env() -> Result<(String, String)> {
    Ok((
        required_env("MASTODON_BASE_URL")?,
        required_env("MASTODON_ACCESS_TOKEN")?,
    ))
}

/// Reads an environment variable, treating a blank value as unset: `KEY=` in a .env file is the
/// usual way to disable a setting, so it falls back to the default instead of failing to parse.
fn optional_env(key: &str) -> Result<Option<String>> {
    match std::env::var(key) {
        Ok(value) => Ok(Some(value).filter(|v| !v.trim().is_empty())),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read environment variable {key}"))
        }
    }
}

fn required_env(key: &str) -> Result<String> {
    match optional_env(key)? {
        Some(value) => Ok(value),
        None => bail!("environment variable {key} is not set"),
    }
}

fn env_or(key: &str, default: &str) -> Result<String> {
    Ok(optional_env(key)?.unwrap_or_else(|| default.to_string()))
}

fn bool_env(key: &str, default: bool) -> Result<bool> {
    match optional_env(key)? {
        Some(value) => parse_bool(key, &value),
        None => Ok(default),
    }
}

fn positive_usize_env(key: &str, default: usize) -> Result<usize> {
    match optional_env(key)? {
        Some(value) => parse_positive_usize(&value, key),
        None => Ok(default),
    }
}

/// Parses a count that must be at least one, naming `source` — an environment variable or a CLI
/// flag — in the error.
pub fn parse_positive_usize(value: &str, source: &str) -> Result<usize> {
    let parsed = value
        .trim()
        .parse::<usize>()
        .with_context(|| format!("{source} is not a valid positive integer"))?;
    if parsed == 0 {
        bail!("{source} must be greater than zero");
    }
    Ok(parsed)
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => bail!("environment variable {key} must be true, false, 1, or 0"),
    }
}

/// A review model must be a chat model behind a decision model.
fn validate_review_model(model: &str, review_model: Option<&str>) -> Result<()> {
    let Some(review_model) = review_model else {
        return Ok(());
    };
    if !is_decision_model(model) {
        bail!("OPENAI_REVIEW_MODEL requires OPENAI_MODEL to be a decision model");
    }
    if is_decision_model(review_model) {
        bail!("OPENAI_REVIEW_MODEL must be a chat model, not a decision model");
    }
    Ok(())
}

fn parse_confidence_threshold(value: &str) -> Result<f64> {
    let threshold = value
        .trim()
        .parse::<f64>()
        .context("SPAM_CONFIDENCE_THRESHOLD is not a valid number")?;
    // Also rejects NaN and infinities: comparisons against them are always false.
    if !(0.0..=1.0).contains(&threshold) {
        bail!("SPAM_CONFIDENCE_THRESHOLD must be between 0.0 and 1.0");
    }
    Ok(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_values_are_parsed_strictly() {
        assert!(parse_bool("TEST", " TRUE ").unwrap());
        assert!(parse_bool("TEST", "1").unwrap());
        assert!(!parse_bool("TEST", "False").unwrap());
        assert!(!parse_bool("TEST", "0").unwrap());
        assert!(parse_bool("TEST", "yes").is_err());
        assert!(parse_bool("TEST", "").is_err());
    }

    #[test]
    fn confidence_threshold_is_validated() {
        assert_eq!(parse_confidence_threshold("0").unwrap(), 0.0);
        assert_eq!(parse_confidence_threshold(" 0.75 ").unwrap(), 0.75);
        assert_eq!(parse_confidence_threshold("1").unwrap(), 1.0);
        assert!(parse_confidence_threshold("-0.1").is_err());
        assert!(parse_confidence_threshold("1.1").is_err());
        assert!(parse_confidence_threshold("NaN").is_err());
        assert!(parse_confidence_threshold("invalid").is_err());
    }

    #[test]
    fn review_model_is_only_accepted_behind_a_decision_model() {
        assert!(validate_review_model("gpt-4o", None).is_ok());
        assert!(validate_review_model("typesafe/jev-1.13", Some("openai/gpt-4o")).is_ok());
        assert!(validate_review_model("openai/gpt-4o", Some("openai/gpt-4o-mini")).is_err());
        assert!(validate_review_model("typesafe/jev-1.13", Some("kev-latest")).is_err());
    }

    #[test]
    fn default_key_id_points_at_the_instance_actor() {
        assert_eq!(
            default_key_id("https://mastodon.example/"),
            "https://mastodon.example/actor#main-key"
        );
    }

    #[test]
    fn positive_sizes_are_validated() {
        assert_eq!(parse_positive_usize("4", "TEST").unwrap(), 4);
        assert_eq!(parse_positive_usize(" 4 ", "TEST").unwrap(), 4);
        assert!(parse_positive_usize("0", "TEST").is_err());
        assert!(parse_positive_usize("-1", "TEST").is_err());
        assert!(parse_positive_usize("", "TEST").is_err());
        assert!(parse_positive_usize("abc", "TEST").is_err());
        // The message names the setting to fix.
        let error = parse_positive_usize("0", "--max").unwrap_err().to_string();
        assert!(error.contains("--max"), "{error}");
    }
}
