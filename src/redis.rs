use anyhow::{Context, Result};
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;

const CURSOR_KEY: &str = "mastodon_spam_checker:last_account_id";

pub struct CursorStore {
    conn: MultiplexedConnection,
}

impl CursorStore {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client =
            redis::Client::open(redis_url).context("Redis クライアントの作成に失敗")?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .context("Redis 接続失敗")?;
        Ok(Self { conn })
    }

    pub async fn get_cursor(&mut self) -> Result<Option<String>> {
        let value: Option<String> = self
            .conn
            .get(CURSOR_KEY)
            .await
            .context("Redis カーソル読み込み失敗")?;

        Ok(value)
    }

    pub async fn set_cursor(&mut self, account_id: &str) -> Result<()> {
        self.conn
            .set::<_, _, ()>(CURSOR_KEY, account_id)
            .await
            .context("Redis カーソル保存失敗")?;

        Ok(())
    }
}
