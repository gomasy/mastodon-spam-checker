use std::time::Duration;

use anyhow::{Result, bail};
use reqwest::{Client, Response};

/// 共通設定(User-Agent、タイムアウト)の HTTP クライアントを生成する
pub fn client(timeout: Duration) -> Client {
    Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .timeout(timeout)
        .build()
        .expect("failed to build HTTP client")
}

/// 成功ステータスでなければ、レスポンスボディを含むエラーにする
pub async fn ensure_success(resp: Response, what: &str) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    bail!("{what} error (HTTP {status}): {body}")
}
