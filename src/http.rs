use std::time::Duration;

use reqwest::Client;

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
