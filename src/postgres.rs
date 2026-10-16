use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use tokio::sync::Mutex;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls};
use tracing::{error, info, warn};

use crate::config::PostgresConfig;
use crate::encryption;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Connects a note writer when moderation notes are configured, and nothing otherwise. The checker
/// and `serve` mode decide the same way, so the `Option` is unwrapped here rather than at both.
pub async fn writer_for(config: Option<&PostgresConfig>) -> Result<Option<ModerationNoteWriter>> {
    match config {
        Some(pg) => ModerationNoteWriter::connect(&pg.database_url, pg.moderator_account_id)
            .await
            .map(Some),
        None => Ok(None),
    }
}

/// Opens a connection to Mastodon's database, driving it on a background task until the client is
/// dropped.
pub async fn connect(database_url: &str) -> Result<Client> {
    let (client, connection) = tokio::time::timeout(
        DATABASE_TIMEOUT,
        tokio_postgres::connect(database_url, NoTls),
    )
    .await
    .context("timed out connecting to PostgreSQL")?
    .context("failed to connect to PostgreSQL")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!(error = %e, "PostgreSQL connection error");
        }
    });

    Ok(client)
}

/// Mastodon 4.7+ keeps keys, encrypted, in `keypairs`; `type = 0` is RSA.
const SELECT_KEYPAIR: &str = "SELECT private_key FROM keypairs \
     WHERE account_id = -99 AND type = 0 AND local_fragment = $1 AND NOT revoked \
     AND (expires_at IS NULL OR expires_at > now()) \
     ORDER BY id DESC LIMIT 1";

/// The instance actor's private key (PEM) for `key_id`. `-99` is Mastodon's
/// `Account::INSTANCE_ACTOR_ID`; before 4.7 its key is plain text in `accounts`.
pub async fn read_instance_actor_key(
    database_url: &str,
    key_id: &reqwest::Url,
    secrets: Option<&encryption::Secrets>,
) -> Result<String> {
    let client = connect(database_url).await?;
    let fragment = format!("#{}", key_id.fragment().unwrap_or_default());
    let read = async {
        match client.query_opt(SELECT_KEYPAIR, &[&fragment]).await {
            Ok(row) => {
                if let Some(key) = row.and_then(|row| non_empty_key(row.get(0))) {
                    return Ok(Some((key, true)));
                }
            }
            Err(e) if e.code() == Some(&SqlState::UNDEFINED_TABLE) => {}
            Err(e) => return Err(e),
        }
        let row = client
            .query_opt("SELECT private_key FROM accounts WHERE id = -99", &[])
            .await?;
        Ok(row
            .and_then(|row| non_empty_key(row.get(0)))
            .map(|key| (key, false)))
    };
    let (key, encrypted) = tokio::time::timeout(DATABASE_TIMEOUT, read)
        .await
        .context("timed out reading the instance actor's key")?
        .context("failed to read the instance actor's key")?
        .with_context(|| format!("the instance actor has no private key for {fragment}"))?;
    if !encrypted {
        return Ok(key);
    }
    let secrets = secrets.context(
        "the instance actor's key is encrypted; set the ACTIVE_RECORD_ENCRYPTION_* variables",
    )?;
    encryption::decrypt(&key, secrets).context("failed to decrypt the instance actor's key")
}

fn non_empty_key(key: Option<String>) -> Option<String> {
    key.filter(|key| !key.trim().is_empty())
}

/// `created_at`/`updated_at` are bound as parameters rather than written with `NOW()`: Mastodon's
/// columns are `timestamp without time zone` holding UTC, and Postgres would convert `now()` into
/// the session time zone, dating every note by the server's local wall clock. A `SystemTime` is
/// encoded as UTC for both `timestamp` and `timestamptz`, so it is correct either way.
const INSERT_NOTE: &str = "INSERT INTO account_moderation_notes \
     (content, account_id, target_account_id, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $4)";

/// Writes rows into Mastodon's `account_moderation_notes` table.
///
/// The connection is disposable: each write checks it first and redials when it has gone. `serve`
/// mode holds a writer for the life of the process, and a `tokio_postgres::Client` whose connection
/// ended fails every later request, so a database restart or idle timeout would otherwise silence
/// moderation notes permanently. [`crate::redis::StateStore`] gets the equivalent from Redis'
/// connection manager.
pub struct ModerationNoteWriter {
    database_url: String,
    moderator_account_id: i64,
    client: Mutex<Option<Client>>,
}

impl ModerationNoteWriter {
    pub async fn connect(database_url: &str, moderator_account_id: i64) -> Result<Self> {
        // Connect eagerly so a bad DATABASE_URL is reported at startup, not on the first detection.
        let client = connect(database_url).await?;
        info!("connected to PostgreSQL for moderation notes");
        Ok(Self {
            database_url: database_url.to_string(),
            moderator_account_id,
            client: Mutex::new(Some(client)),
        })
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
                connect(&self.database_url).await?
            }
        };

        let Ok(result) = tokio::time::timeout(
            DATABASE_TIMEOUT,
            client.execute(
                INSERT_NOTE,
                &[&content, &self.moderator_account_id, &target_id, &now],
            ),
        )
        .await
        else {
            // Dropping the query future does not stop PostgreSQL from executing it, so it is
            // cancelled explicitly before this client is discarded, or lock waits leak sessions.
            match tokio::time::timeout(DATABASE_TIMEOUT, client.cancel_token().cancel_query(NoTls))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "failed to cancel timed-out moderation note"),
                Err(_) => warn!("timed out cancelling moderation note"),
            }
            bail!("timed out inserting moderation note");
        };
        // Kept for the next note unless the query itself killed it, in which case this one note is
        // lost and the next call reconnects.
        if !client.is_closed() {
            *guard = Some(client);
        }
        result.context("failed to insert moderation note")?;

        info!(target_account_id = %target_account_id, "moderation note added");
        Ok(())
    }
}
