use anyhow::{Context, Result};
use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;

const CURSOR_KEY: &str = "mastodon_spam_checker:last_account_id";

pub struct CursorStore {
    conn: MultiplexedConnection,
}

impl CursorStore {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url).context("failed to create Redis client")?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .context("failed to connect to Redis")?;
        Ok(Self { conn })
    }

    pub async fn get_cursor(&mut self) -> Result<Option<String>> {
        let value: Option<String> = self
            .conn
            .get(CURSOR_KEY)
            .await
            .context("failed to read cursor from Redis")?;

        Ok(value)
    }

    pub async fn set_cursor(&mut self, account_id: &str) -> Result<()> {
        self.conn
            .set::<_, _, ()>(CURSOR_KEY, account_id)
            .await
            .context("failed to save cursor to Redis")?;

        Ok(())
    }
}
