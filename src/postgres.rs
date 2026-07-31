use std::time::SystemTime;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use tracing::{error, info, warn};

/// `created_at`/`updated_at` are bound as parameters rather than written with `NOW()`: Mastodon's
/// columns are `timestamp without time zone` holding UTC, and Postgres would convert `now()` into
/// the session time zone, dating every note by the database server's local wall clock. A
/// `SystemTime` is encoded as UTC for both `timestamp` and `timestamptz`, so it is correct either
/// way.
const INSERT_NOTE: &str = "INSERT INTO account_moderation_notes \
     (content, account_id, target_account_id, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $4)";

/// Writes rows into Mastodon's `account_moderation_notes` table.
///
/// The connection is treated as disposable. `serve` mode holds a writer for the lifetime of the
/// process, and a `tokio_postgres::Client` whose connection has ended fails every later request, so
/// a database restart, idle timeout, or brief network loss would otherwise silence moderation notes
/// permanently. Each write checks the connection first and redials when it has gone.
///
/// [`crate::redis::StateStore`] deliberately has no equivalent: its multiplexed connection
/// reconnects on its own, so nothing here has to redial it.
pub struct ModerationNoteWriter {
    database_url: String,
    moderator_account_id: i64,
    client: Mutex<Option<Client>>,
}

impl ModerationNoteWriter {
    pub async fn connect(database_url: &str, moderator_account_id: i64) -> Result<Self> {
        // Connect eagerly so a bad DATABASE_URL is reported at startup, not on the first detection.
        let client = Self::open(database_url).await?;
        info!("connected to PostgreSQL for moderation notes");
        Ok(Self {
            database_url: database_url.to_string(),
            moderator_account_id,
            client: Mutex::new(Some(client)),
        })
    }

    async fn open(database_url: &str) -> Result<Client> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .context("failed to connect to PostgreSQL")?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!(error = %e, "PostgreSQL connection error");
            }
        });

        Ok(client)
    }

    pub async fn add_note(&self, target_account_id: &str, content: &str) -> Result<()> {
        let target_id: i64 = target_account_id
            .parse()
            .context("target account ID is not a valid integer")?;
        let now = SystemTime::now();

        let mut guard = self.client.lock().await;
        let client = match guard.take() {
            Some(client) if !client.is_closed() => client,
            previous => {
                if previous.is_some() {
                    warn!("PostgreSQL connection was lost, reconnecting");
                }
                Self::open(&self.database_url).await?
            }
        };

        let result = client
            .execute(
                INSERT_NOTE,
                &[&content, &self.moderator_account_id, &target_id, &now],
            )
            .await;
        // Keep the connection for the next note unless the query itself killed it. A connection that
        // dies mid-query costs this one note; the next call reconnects.
        if !client.is_closed() {
            *guard = Some(client);
        }
        result.context("failed to insert moderation note")?;

        info!(target_account_id = %target_account_id, "moderation note added");
        Ok(())
    }
}
