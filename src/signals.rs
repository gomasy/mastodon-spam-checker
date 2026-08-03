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

/// Hex SHA-256 of `value`, used to key campaign signals by content without storing the content.
pub fn digest(value: &str) -> String {
    use std::fmt::Write;

    ring::digest::digest(&ring::digest::SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links_in(html: &str) -> Vec<String> {
        let mut links = BTreeSet::new();
        collect_links(html, &mut links);
        links.into_iter().collect()
    }

    #[test]
    fn extracts_hidden_link_destinations() {
        assert_eq!(
            links_in(r#"<p>click <a href="https://Spam.Example/path?a=1&amp;b=2">here</a></p>"#),
            ["https://spam.example/path?a=1&b=2"]
        );
    }

    #[test]
    fn federation_links_are_not_campaign_destinations() {
        // Mastodon renders every mention and hashtag as a link. Counting them would make each
        // instance a shared "destination domain" and match unrelated accounts as one campaign.
        assert_eq!(
            links_in(
                r#"<a href="https://mstdn.example/@bob">@bob</a>
                   <a href="https://mstdn.example/users/bob">bob</a>
                   <a href="https://mstdn.example/tags/art">#art</a>
                   <a href="https://shop.example/deal">deal</a>"#
            ),
            ["https://shop.example/deal"]
        );
    }

    #[test]
    fn a_fragment_does_not_split_one_destination_into_many() {
        // Same page, different anchors: kept apart these would dilute a campaign's match count.
        assert_eq!(
            links_in(
                r#"<a href="https://spam.example/x#a">1</a><a href="https://spam.example/x#b">2</a>"#
            ),
            ["https://spam.example/x"]
        );
    }

    #[test]
    fn bare_and_non_http_urls_are_handled() {
        // Plain-text URLs are picked up with their surrounding punctuation trimmed, while schemes
        // that cannot be a campaign destination are left out.
        assert_eq!(
            links_in("see (https://plain.example/a), javascript:alert(1) mailto:x@example.com"),
            ["https://plain.example/a"]
        );
    }

    #[test]
    fn html_to_plain_strips_tags_and_decodes_entities() {
        assert_eq!(html_to_plain("<p>A &amp; B<br>next</p>"), "A & B\nnext");
    }
}
