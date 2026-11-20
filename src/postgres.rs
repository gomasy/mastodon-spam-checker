use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use tokio::sync::Mutex;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::Type;
use tokio_postgres::{Client, NoTls};
use tracing::{error, info, warn};

use crate::chain;
use crate::config::PostgresConfig;
use crate::encryption;

const DATABASE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn writer_for(config: Option<&PostgresConfig>) -> Result<Option<ModerationNoteWriter>> {
    match config {
        Some(pg) => ModerationNoteWriter::connect(pg).await.map(Some),
        None => Ok(None),
    }
}

/// Connects, driving the connection on a background task until the client is dropped.
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

/// Timestamps are bound rather than `now()`: the columns are `timestamp without time zone` in UTC,
/// and `now()` would be converted to the session time zone.
const INSERT_NOTE: &str = "INSERT INTO account_moderation_notes \
     (content, account_id, target_account_id, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $4)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModerationAction {
    Suspend,
    Delete,
}

impl ModerationAction {
    pub const ALL: [Self; 2] = [Self::Suspend, Self::Delete];

    pub fn env_key(self) -> &'static str {
        match self {
            Self::Suspend => "SUSPEND_SQL",
            Self::Delete => "DELETE_SQL",
        }
    }
}

/// Adds a note when configured; a failure is logged, never raised.
pub async fn add_note_logged(writer: Option<&ModerationNoteWriter>, account_id: &str, note: &str) {
    if let Some(writer) = writer
        && let Err(error) = writer.add_note(account_id, note).await
    {
        error!(account_id, error = %chain(&error), "failed to add moderation note");
    }
}

/// Runs the SQL configured for `action`, if any; a failure is logged, never raised.
async fn run_action_sql_logged(
    writer: Option<&ModerationNoteWriter>,
    action: ModerationAction,
    account_id: &str,
) {
    if let Some(writer) = writer
        && let Err(error) = writer.run_action_sql(action, account_id).await
    {
        error!(account_id, ?action, error = %chain(&error), "failed to run action SQL");
    }
}

/// The database side of a moderation action: an optional note, then the action's SQL.
pub async fn after_action(
    writer: Option<&ModerationNoteWriter>,
    action: ModerationAction,
    account_id: &str,
    note: Option<&str>,
) {
    if let Some(note) = note {
        add_note_logged(writer, account_id, note).await;
    }
    run_action_sql_logged(writer, action, account_id).await;
}

/// Writes moderation notes and runs action SQL, redialling when the connection has gone.
pub struct ModerationNoteWriter {
    config: PostgresConfig,
    client: Mutex<Option<Client>>,
}

impl ModerationNoteWriter {
    /// Connects and validates the action SQL, so bad settings fail at startup.
    pub async fn connect(config: &PostgresConfig) -> Result<Self> {
        let client = connect(&config.database_url).await?;
        for action in ModerationAction::ALL {
            if let Some(sql) = config.action_sql(action) {
                let key = action.env_key();
                tokio::time::timeout(DATABASE_TIMEOUT, client.prepare_typed(sql, &[Type::INT8]))
                    .await
                    .with_context(|| format!("timed out validating {key}"))?
                    .with_context(|| format!("{key} is invalid"))?;
            }
        }
        info!("connected to PostgreSQL for moderation notes");
        Ok(Self {
            config: config.clone(),
            client: Mutex::new(Some(client)),
        })
    }

    pub async fn add_note(&self, target_account_id: &str, content: &str) -> Result<()> {
        let target_id = parse_account_id(target_account_id)?;
        let now = SystemTime::now();
        self.with_client("moderation note insert", async |client: &Client| {
            client
                .execute(
                    INSERT_NOTE,
                    &[
                        &content,
                        &self.config.moderator_account_id,
                        &target_id,
                        &now,
                    ],
                )
                .await
        })
        .await?;
        info!(target_account_id, "moderation note added");
        Ok(())
    }

    pub async fn run_action_sql(&self, action: ModerationAction, account_id: &str) -> Result<()> {
        let Some(sql) = self.config.action_sql(action) else {
            return Ok(());
        };
        let account_id = parse_account_id(account_id)?;
        // Typed so `$1` binds even when the SQL never references it.
        let rows = self
            .with_client(action.env_key(), async |client: &Client| {
                client
                    .execute_typed(sql, &[(&account_id, Type::INT8)])
                    .await
            })
            .await?;
        info!(account_id, ?action, rows, "action SQL executed");
        Ok(())
    }

    /// Runs `query` within [`DATABASE_TIMEOUT`], redialling first if the connection has gone.
    async fn with_client<T>(
        &self,
        what: &str,
        query: impl AsyncFnOnce(&Client) -> Result<T, tokio_postgres::Error>,
    ) -> Result<T> {
        let mut guard = self.client.lock().await;
        let client = match guard.take() {
            Some(client) if !client.is_closed() => client,
            previous => {
                if previous.is_some() {
                    warn!("PostgreSQL connection was lost, reconnecting");
                }
                connect(&self.config.database_url).await?
            }
        };

        let Ok(result) = tokio::time::timeout(DATABASE_TIMEOUT, query(&client)).await else {
            // Dropping the future does not stop the server-side query, so cancel it explicitly.
            match tokio::time::timeout(DATABASE_TIMEOUT, client.cancel_token().cancel_query(NoTls))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "failed to cancel timed-out {what}"),
                Err(_) => warn!("timed out cancelling {what}"),
            }
            bail!("{what} timed out");
        };
        if !client.is_closed() {
            *guard = Some(client);
        }
        result.with_context(|| format!("{what} failed"))
    }
}

fn parse_account_id(account_id: &str) -> Result<i64> {
    account_id
        .parse()
        .context("account ID is not a valid integer")
}
