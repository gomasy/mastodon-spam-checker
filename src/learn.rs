use anyhow::Result;
use tracing::info;

use crate::mastodon::MastodonClient;
use crate::redis::{LearnOutcome, LearnSource, StateStore};

/// Learns spam from the newest `max` suspended remote accounts, including the checker's misses.
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
