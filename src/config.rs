use anyhow::{Context, Result};

pub struct Config {
    pub mastodon_base_url: String,
    pub mastodon_access_token: String,
    pub redis_url: String,
    pub openai_api_base: String,
    pub openai_api_key: String,
    pub openai_model: String,
    pub openai_json_mode: bool,
    pub slack_webhook_url: String,
    pub slack_channel: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            mastodon_base_url: required_env("MASTODON_BASE_URL")?,
            mastodon_access_token: required_env("MASTODON_ACCESS_TOKEN")?,
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            openai_api_base: required_env("OPENAI_API_BASE")?,
            openai_api_key: required_env("OPENAI_API_KEY")?,
            openai_model: std::env::var("OPENAI_MODEL")
                .unwrap_or_else(|_| "gpt-4o".to_string()),
            // response_format 非対応の OpenAI 互換 API では false にする
            openai_json_mode: std::env::var("OPENAI_JSON_MODE")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            slack_webhook_url: required_env("SLACK_WEBHOOK_URL")?,
            slack_channel: std::env::var("SLACK_CHANNEL")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

fn required_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("環境変数 {key} が設定されていません"))
}
