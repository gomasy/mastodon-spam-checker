mod activitypub;
mod auto_moderation;
mod check;
mod cli;
mod config;
mod encryption;
mod http;
mod ids;
mod learn;
mod llm;
mod mastodon;
mod postgres;
mod redis;
mod server;
mod signals;
mod slack;
mod sql;
mod text;

use anyhow::{Result, bail};
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

rust_i18n::i18n!("locales", fallback = "en");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        bail!("failed to install rustls crypto provider");
    }

    dotenvy::dotenv().ok();
    let locale = std::env::var("APP_LANG").unwrap_or_else(|_| "en".to_string());
    rust_i18n::set_locale(&locale);
    init_logging();

    let args: Vec<String> = std::env::args().skip(1).collect();
    cli::dispatch(&args).await
}

fn init_logging() {
    let filter: Targets = std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| {
            Targets::new().with_target("mastodon_spam_checker", tracing::Level::INFO)
        });
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();
}

/// Formats an error with its full cause chain; plain `Display` shows only the outermost context.
pub fn chain(error: &anyhow::Error) -> String {
    format!("{error:#}")
}

#[cfg(test)]
mod tests {
    use rust_i18n::t;

    #[test]
    fn i18n_keys_resolve() {
        rust_i18n::set_locale("en");
        assert!(t!("btn_suspend").contains("Suspend"));
        rust_i18n::set_locale("ja");
        assert!(t!("btn_suspend").contains("停止"));
    }
}
