use std::collections::BTreeSet;

use crate::mastodon::{AdminAccount, Status};

#[derive(Debug, Default)]
pub struct AccountSignals {
    pub bio_fingerprint: Option<String>,
    pub link_domains: Vec<String>,
    pub links: Vec<String>,
}

pub fn analyze(account: &AdminAccount, statuses: &[Status]) -> AccountSignals {
    let bio = html_to_plain(&account.account.note);
    let normalized_bio = bio
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    // Short generic bios create noisy campaign matches (for example, "hello" or "artist").
    let bio_fingerprint = (normalized_bio.chars().count() >= 40).then(|| digest(&normalized_bio));

    let mut links = BTreeSet::new();
    collect_links(&account.account.note, &mut links);
    for field in &account.account.fields {
        collect_links(&field.value, &mut links);
    }
    for status in statuses {
        collect_links(&status.content, &mut links);
    }

    let links: Vec<String> = links.into_iter().take(30).collect();
    let link_domains = links
        .iter()
        .filter_map(|link| reqwest::Url::parse(link).ok())
        .filter_map(|url| url.host_str().map(str::to_ascii_lowercase))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    AccountSignals {
        bio_fingerprint,
        link_domains,
        links,
    }
}

pub fn html_to_plain(html: &str) -> String {
    let result = html
        .replace("<br>", "\n")
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        .replace("</p><p>", "\n\n");

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

fn collect_links(html: &str, links: &mut BTreeSet<String>) {
    let mut rest = html;
    while let Some(pos) = rest.find("href=") {
        rest = &rest[pos + 5..];
        let Some(quote) = rest.chars().next().filter(|ch| matches!(ch, '\'' | '"')) else {
            continue;
        };
        rest = &rest[quote.len_utf8()..];
        let Some(end) = rest.find(quote) else {
            break;
        };
        collect_url(&rest[..end], links);
        rest = &rest[end + quote.len_utf8()..];
    }

    for token in html.split_whitespace() {
        let candidate = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '<' | '>' | '(' | ')' | '[' | ']' | '"' | '\'' | ',' | ';'
            )
        });
        if candidate.starts_with("https://") || candidate.starts_with("http://") {
            collect_url(candidate, links);
        }
    }
}

fn collect_url(candidate: &str, links: &mut BTreeSet<String>) {
    let decoded = candidate.replace("&amp;", "&");
    if let Ok(mut url) = reqwest::Url::parse(&decoded)
        && matches!(url.scheme(), "http" | "https")
    {
        let path = url.path();
        // Mastodon renders mentions and hashtags as links. They describe federation navigation,
        // not a promotional destination shared by a spam campaign.
        if path.starts_with("/@") || path.starts_with("/users/") || path.starts_with("/tags/") {
            return;
        }
        url.set_fragment(None);
        links.insert(url.to_string());
    }
}

fn digest(value: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hidden_link_destinations() {
        let mut links = BTreeSet::new();
        collect_links(
            r#"<p>click <a href="https://Spam.Example/path?a=1&amp;b=2">here</a></p>"#,
            &mut links,
        );
        assert_eq!(
            links.into_iter().next().as_deref(),
            Some("https://spam.example/path?a=1&b=2")
        );
    }

    #[test]
    fn html_to_plain_strips_tags_and_decodes_entities() {
        assert_eq!(html_to_plain("<p>A &amp; B<br>next</p>"), "A & B\nnext");
    }
}
