use anyhow::{Context, Result};
use tokio_postgres::{Client, NoTls};
use tracing::{error, info};

pub struct ModerationNoteWriter {
    client: Client,
    moderator_account_id: i64,
}

impl ModerationNoteWriter {
    pub async fn connect(database_url: &str, moderator_account_id: i64) -> Result<Self> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .context("failed to connect to PostgreSQL")?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!(error = %e, "PostgreSQL connection error");
            }
        });

        info!("connected to PostgreSQL for moderation notes");
        Ok(Self {
            client,
            moderator_account_id,
        })
    }

    pub async fn add_note(&self, target_account_id: &str, content: &str) -> Result<()> {
        let target_id: i64 = target_account_id
            .parse()
            .context("target account ID is not a valid integer")?;

        self.client
            .execute(
                "INSERT INTO account_moderation_notes (content, account_id, target_account_id, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())",
                &[&content, &self.moderator_account_id, &target_id],
            )
            .await
            .context("failed to insert moderation note")?;

        info!(target_account_id = %target_account_id, "moderation note added");
        Ok(())
    }
}
