//! Learning spam from accounts suspended in Mastodon, which includes the checker's misses.

use anyhow::Result;
use tracing::info;

use crate::mastodon::MastodonClient;
use crate::redis::{LearnOutcome, LearnSource, StateStore};

/// Looks through the newest `max` suspended remote accounts. A failure on one account is logged and
/// the rest continue.
pub async fn learn_suspended(
    store: &StateStore,
    mastodon: &MastodonClient,
    max: usize,
) -> Result<()> {
    let suspended = mastodon.fetch_suspended_remote_account_ids(max).await?;
    let (mut learned, mut missed) = (0u32, 0u32);
    for id in store.learnable(&suspended).await? {
        if let Some(LearnOutcome::Learned { missed: was_missed }) = store
            .learn_logged(&id, LearnSource::MastodonSuspension)
            .await
        {
            learned += 1;
            missed += u32::from(was_missed);
        }
    }
    info!(
        scanned = suspended.len(),
        learned, missed, "learned from suspended accounts"
    );
    Ok(())
}
