use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::mastodon::{AdminAccount, Status};

#[derive(Debug, Deserialize)]
pub struct SpamVerdict {
    pub spam: bool,
    pub reason: String,
    pub confidence: f64,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f64,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

const SYSTEM_PROMPT: &str = r#"You are a spam detection system for a Mastodon instance. Analyze the given account profile and recent posts to determine if the account is spam.

Notes:
- These are remote (federated) accounts. Even if the post count is above zero, it is normal for no posts to be retrievable. Do not treat this as suspicious.
- Accounts using languages that are uncommon among the server's user base should be treated with higher suspicion, especially when combined with other spam indicators.

Evaluation criteria:
- Excessive posting of suspicious URLs or link shorteners
- Cryptocurrency, gambling, or adult content spam patterns
- Spammy links or promotional content in the profile bio
- Unnaturally generated or incoherent text
- Profile that mimics legitimate accounts but with subtle differences
- If no avatar is set (i.e. the account uses the default avatar), examine the account with extra care
- If the username looks like a machine-generated, meaningless sequence of letters, treat the account with heightened suspicion

Respond ONLY with a JSON object in this exact format (no markdown, no extra text):
{"spam": true/false, "reason": "Brief explanation in Japanese", "confidence": 0.0-1.0}
"#;

pub struct LlmClient {
    client: Client,
    api_base: String,
    api_key: String,
    model: String,
}

impl LlmClient {
    pub fn new(api_base: &str, api_key: &str, model: &str) -> Self {
        let client = Client::builder()
            .user_agent(concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            api_base: api_base.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            model: model.to_string(),
        }
    }

    pub async fn check_spam(
        &self,
        account: &AdminAccount,
        statuses: &[Status],
    ) -> Result<SpamVerdict> {
        let user_prompt = build_user_prompt(account, statuses);

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: SYSTEM_PROMPT.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            temperature: 0.1,
        };

        let url = format!("{}/chat/completions", self.api_base);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&request)
            .send()
            .await
            .context("LLM API リクエスト失敗")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("LLM API エラー (HTTP {status}): {body}");
        }

        let resp: ChatResponse = resp
            .json()
            .await
            .context("LLM レスポンスのパース失敗")?;

        let content = &resp
            .choices
            .first()
            .context("LLM レスポンスに choices がありません")?
            .message
            .content;

        let content = content
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        let verdict: SpamVerdict =
            serde_json::from_str(content).context("LLM 判定結果の JSON パース失敗")?;

        Ok(verdict)
    }
}

fn build_user_prompt(account: &AdminAccount, statuses: &[Status]) -> String {
    let domain = account.domain.as_deref().unwrap_or("(local)");
    let note_plain = html_to_plain(&account.account.note);
    // Mastodon serves /avatars/original/missing.png when no avatar is set
    let avatar_state = if account.account.avatar.is_empty()
        || account.account.avatar.contains("missing.png")
    {
        "not set (default avatar)"
    } else {
        "set"
    };

    let mut prompt = format!(
        "## Account Profile\n\
         - Username: {}@{}\n\
         - Display Name: {}\n\
         - Bio: {}\n\
         - URL: {}\n\
         - Avatar: {}\n\
         - Followers: {} / Following: {} / Posts: {}\n",
        account.username,
        domain,
        account.account.display_name,
        note_plain,
        account.account.url,
        avatar_state,
        account.account.followers_count,
        account.account.following_count,
        account.account.statuses_count,
    );

    if statuses.is_empty() {
        prompt.push_str("\n## Recent Posts\n(No posts found)\n");
    } else {
        prompt.push_str("\n## Recent Posts\n");
        for status in statuses {
            let content_plain = html_to_plain(&status.content);
            prompt.push_str(&format!("- {}\n", content_plain));
        }
    }

    prompt
}

fn html_to_plain(html: &str) -> String {
    let mut result = html.to_string();
    result = result.replace("<br>", "\n").replace("<br/>", "\n").replace("<br />", "\n");
    result = result.replace("</p><p>", "\n\n");

    let mut plain = String::with_capacity(result.len());
    let mut in_tag = false;
    for ch in result.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => plain.push(ch),
            _ => {}
        }
    }

    plain
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
        .trim()
        .to_string()
}
