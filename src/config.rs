use anyhow::{Context, Result};

pub struct PostgresConfig {
    pub database_url: String,
    pub moderator_account_id: i64,
}

impl PostgresConfig {
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty()) {
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

pub struct Config {
    pub mastodon_base_url: String,
    pub mastodon_access_token: String,
    pub redis_url: String,
    pub openai_api_base: String,
    pub openai_api_key: String,
    pub openai_model: String,
    pub openai_json_mode: bool,
    /// スパム確信度がこの閾値(0.0-1.0)未満なら Slack 通知をスキップする
    pub spam_confidence_threshold: f64,
    pub slack_webhook_url: String,
    pub slack_channel: Option<String>,
    pub postgres: Option<PostgresConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let (mastodon_base_url, mastodon_access_token) = mastodon_env()?;
        Ok(Self {
            mastodon_base_url,
            mastodon_access_token,
            redis_url: env_or("REDIS_URL", "redis://localhost:6379"),
            openai_api_base: required_env("OPENAI_API_BASE")?,
            openai_api_key: required_env("OPENAI_API_KEY")?,
            openai_model: env_or("OPENAI_MODEL", "gpt-4o"),
            // response_format 非対応の OpenAI 互換 API では false にする
            openai_json_mode: std::env::var("OPENAI_JSON_MODE")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            // 未設定・パース失敗時は 0.0(すべて通知)で従来互換
            spam_confidence_threshold: std::env::var("SPAM_CONFIDENCE_THRESHOLD")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|v| (0.0..=1.0).contains(v))
                .unwrap_or(0.0),
            slack_webhook_url: required_env("SLACK_WEBHOOK_URL")?,
            slack_channel: std::env::var("SLACK_CHANNEL")
                .ok()
                .filter(|s| !s.is_empty()),
            postgres: PostgresConfig::from_env()?,
        })
    }
}

/// serve モード(Slack インタラクションサーバー)用の設定
pub struct ServeConfig {
    pub mastodon_base_url: String,
    pub mastodon_access_token: String,
    pub slack_signing_secret: String,
    pub listen_addr: String,
    pub postgres: Option<PostgresConfig>,
}

impl ServeConfig {
    pub fn from_env() -> Result<Self> {
        let (mastodon_base_url, mastodon_access_token) = mastodon_env()?;
        Ok(Self {
            mastodon_base_url,
            mastodon_access_token,
            slack_signing_secret: required_env("SLACK_SIGNING_SECRET")?,
            listen_addr: env_or("LISTEN_ADDR", "127.0.0.1:8990"),
            postgres: PostgresConfig::from_env()?,
        })
    }
}

fn mastodon_env() -> Result<(String, String)> {
    Ok((
        required_env("MASTODON_BASE_URL")?,
        required_env("MASTODON_ACCESS_TOKEN")?,
    ))
}

fn required_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("environment variable {key} is not set"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
