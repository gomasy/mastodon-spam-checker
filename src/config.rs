use anyhow::{Context, Result, bail};

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

pub struct DetectionConfig {
    pub mastodon_base_url: String,
    pub mastodon_access_token: String,
    pub openai_api_base: String,
    pub openai_api_key: String,
    pub openai_model: String,
    pub openai_json_mode: bool,
    /// Skip Slack notifications if the spam confidence is below this threshold (0.0–1.0).
    pub spam_confidence_threshold: f64,
}

impl DetectionConfig {
    pub fn from_env() -> Result<Self> {
        let (mastodon_base_url, mastodon_access_token) = mastodon_env()?;
        Ok(Self {
            mastodon_base_url,
            mastodon_access_token,
            openai_api_base: required_env("OPENAI_API_BASE")?,
            openai_api_key: required_env("OPENAI_API_KEY")?,
            openai_model: env_or("OPENAI_MODEL", "gpt-4o")?,
            openai_json_mode: bool_env("OPENAI_JSON_MODE", true)?,
            spam_confidence_threshold: match optional_env("SPAM_CONFIDENCE_THRESHOLD")? {
                Some(value) => parse_confidence_threshold(&value)?,
                None => 0.0,
            },
        })
    }
}

pub struct Config {
    pub detection: DetectionConfig,
    pub redis_url: String,
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
            redis_url: redis_url_env()?,
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

/// `REDIS_URL`, or the local default. Every entry point reaches Redis, including the subcommands
/// that build no full [`Config`], so the default lives here rather than at each call site.
pub fn redis_url_env() -> Result<String> {
    env_or("REDIS_URL", DEFAULT_REDIS_URL)
}

fn mastodon_env() -> Result<(String, String)> {
    Ok((
        required_env("MASTODON_BASE_URL")?,
        required_env("MASTODON_ACCESS_TOKEN")?,
    ))
}

/// Reads an environment variable, treating a blank value as unset.
///
/// `KEY=` in a .env file is the usual way to disable a setting, so it falls back to the default
/// instead of failing to parse. Matches how SLACK_CHANNEL and DATABASE_URL are handled.
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

/// Parses a count that must be at least one, naming `source` (an environment variable or a CLI
/// flag) in the error. Shared with the command-line argument parsing in `main`.
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
    fn positive_sizes_are_validated() {
        assert_eq!(parse_positive_usize("4", "TEST").unwrap(), 4);
        assert_eq!(parse_positive_usize(" 4 ", "TEST").unwrap(), 4);
        assert!(parse_positive_usize("0", "TEST").is_err());
        assert!(parse_positive_usize("-1", "TEST").is_err());
        assert!(parse_positive_usize("", "TEST").is_err());
        assert!(parse_positive_usize("abc", "TEST").is_err());
        // The failing source is named, so the message points at the setting to fix.
        let error = parse_positive_usize("0", "--max").unwrap_err().to_string();
        assert!(error.contains("--max"), "{error}");
    }
}
