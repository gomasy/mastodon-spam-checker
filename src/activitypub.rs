//! Reads a remote account's recent posts straight from its ActivityPub outbox, signing requests
//! with the instance actor's key so authorized-fetch servers answer too.
//!
//! The URLs are remote-chosen, so only public https on the actor's origin is fetched, without
//! redirects, and resolved addresses are checked too.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{ACCEPT, CONTENT_TYPE, DATE, HOST};
use reqwest::{Client, Response, Url, redirect};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::Value;
use tracing::info;

use crate::config::RemoteFetchConfig;
use crate::http;
use crate::mastodon::{MastodonClient, MediaAttachment, STATUSES_LIMIT, Status};
use crate::postgres;

const ACTIVITY_JSON: &str = "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";
/// The headers [`signing_string`] covers, in order.
const SIGNED_HEADERS: &str = "(request-target) host date accept";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub struct RemoteFetcher {
    client: Client,
    key: RsaKeyPair,
    key_id: Url,
    rng: SystemRandom,
    retry: http::RetryConfig,
}

impl RemoteFetcher {
    /// Builds a fetcher when remote fetching is configured, and nothing otherwise.
    pub async fn from_config(
        config: Option<&RemoteFetchConfig>,
        mastodon: &MastodonClient,
    ) -> Result<Option<Self>> {
        match config {
            Some(config) => Self::load(config, mastodon).await.map(Some),
            None => Ok(None),
        }
    }

    async fn load(config: &RemoteFetchConfig, mastodon: &MastodonClient) -> Result<Self> {
        let user_agent = async {
            match &config.user_agent {
                Some(user_agent) => Ok(user_agent.clone()),
                None => mastodon
                    .fetch_version()
                    .await
                    .map(|version| mastodon_user_agent(&version, &config.key_id))
                    .context("failed to read the Mastodon version for the User-Agent"),
            }
        };
        let (pem, user_agent) = tokio::try_join!(
            postgres::read_instance_actor_key(&config.database_url),
            user_agent
        )?;
        let key = parse_private_key(&pem).context("failed to load the instance actor's key")?;
        info!(key_id = %config.key_id, %user_agent, "remote outbox fetching enabled");
        Ok(Self {
            client: http::client_builder(REQUEST_TIMEOUT)
                .user_agent(user_agent)
                .redirect(redirect::Policy::none())
                .no_proxy()
                .dns_resolver(PublicOnlyResolver)
                .build()
                .context("failed to build remote HTTP client")?,
            key,
            key_id: config.key_id.clone(),
            rng: SystemRandom::new(),
            // A server that is down should not stall the run.
            retry: http::RetryConfig {
                max_retries: 1,
                ..http::RetryConfig::default()
            },
        })
    }

    /// The newest posts in the outbox of the actor at `actor_uri`, reblogs excluded.
    pub async fn fetch_statuses(&self, actor_uri: &str) -> Result<Vec<Status>> {
        let actor_url = remote_url(actor_uri)?;
        let actor = self
            .get_json(&actor_url)
            .await
            .context("failed to fetch actor")?;
        let outbox_url = str_field(&actor, "outbox").context("actor has no outbox")?;
        let outbox_url = same_origin_url(outbox_url, &actor_url)?;
        let mut outbox = self
            .get_json(&outbox_url)
            .await
            .context("failed to fetch outbox")?;
        if !collection_items(&outbox).is_empty() {
            return Ok(statuses_from_page(&outbox));
        }

        // `first` is a page, or a link to one by URL or by `id`.
        let Some(first) = outbox.get_mut("first").map(Value::take) else {
            return Ok(Vec::new());
        };
        if !collection_items(&first).is_empty() {
            return Ok(statuses_from_page(&first));
        }
        let Some(page_url) = first.as_str().or_else(|| str_field(&first, "id")) else {
            return Ok(Vec::new());
        };
        let page_url = same_origin_url(page_url, &actor_url)?;
        let page = self
            .get_json(&page_url)
            .await
            .context("failed to fetch outbox page")?;
        Ok(statuses_from_page(&page))
    }

    async fn get_json(&self, url: &Url) -> Result<Value> {
        let host = host_header(url)?;
        let date = httpdate::fmt_http_date(SystemTime::now());
        let signature =
            self.signature_header(&signing_string(&request_target(url), &host, &date))?;

        let resp = http::send_with_retry_raw(
            || {
                self.client
                    .get(url.clone())
                    .header(HOST, &host)
                    .header(DATE, &date)
                    .header(ACCEPT, ACTIVITY_JSON)
                    .header("Signature", &signature)
            },
            "Remote ActivityPub request",
            self.retry,
        )
        .await?;

        let status = resp.status();
        if !status.is_success() {
            // The remote-controlled body is not quoted.
            bail!("{url} answered HTTP {status}");
        }
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type.contains("json") {
            bail!("{url} answered with {content_type:?} rather than ActivityPub JSON");
        }
        let body = read_limited(resp, MAX_BODY_BYTES).await?;
        serde_json::from_slice(&body).with_context(|| format!("{url} returned invalid JSON"))
    }

    fn signature_header(&self, signing_string: &str) -> Result<String> {
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_string.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow!("failed to sign request"))?;
        Ok(format!(
            "keyId=\"{}\",algorithm=\"rsa-sha256\",headers=\"{SIGNED_HEADERS}\",signature=\"{}\"",
            self.key_id,
            STANDARD.encode(signature)
        ))
    }
}

/// An RSA private key in PEM form: PKCS#1 (`RSA PRIVATE KEY`, what Mastodon stores) or PKCS#8.
fn parse_private_key(pem: &str) -> Result<RsaKeyPair> {
    let begin = pem.find("-----BEGIN ").context("no PEM header")?;
    let rest = &pem[begin + "-----BEGIN ".len()..];
    let label_end = rest.find("-----").context("malformed PEM header")?;
    let label = &rest[..label_end];
    let body = &rest[label_end + "-----".len()..];
    let footer = format!("-----END {label}-----");
    let body_end = body.find(&footer).context("no PEM footer")?;
    let base64: String = body[..body_end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let der = STANDARD.decode(base64).context("PEM body is not base64")?;
    match label {
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
        other => bail!("unsupported PEM type {other:?}"),
    }
    .map_err(|error| anyhow!("key rejected: {error}"))
}

/// `Mastodon/<version> (+https://<host>/)`.
fn mastodon_user_agent(mastodon_version: &str, key_id: &Url) -> String {
    let origin = key_id.origin().ascii_serialization();
    format!("Mastodon/{mastodon_version} (+{origin}/)")
}

/// The draft-cavage signing string for a GET over [`SIGNED_HEADERS`], as Mastodon signs.
fn signing_string(request_target: &str, host: &str, date: &str) -> String {
    format!(
        "(request-target): get {request_target}\nhost: {host}\ndate: {date}\naccept: {ACTIVITY_JSON}"
    )
}

fn request_target(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

/// Set explicitly so the header sent is byte-for-byte the one signed.
fn host_header(url: &Url) -> Result<String> {
    let host = url.host_str().context("URL has no host")?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// A remote-chosen URL, accepted only as https to a possibly public host.
fn remote_url(raw: &str) -> Result<Url> {
    let mut url = Url::parse(raw).with_context(|| format!("invalid URL {raw:?}"))?;
    if url.scheme() != "https" {
        bail!("refusing non-https URL {url}");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("refusing URL with credentials");
    }
    let host = url.host_str().context("URL has no host")?;
    // IP literals skip the resolver, so they are checked here instead.
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>()
        && !is_public_ip(ip)
    {
        bail!("refusing non-public address {ip}");
    }
    url.set_fragment(None);
    Ok(url)
}

/// [`remote_url`], additionally pinned to the actor's own origin.
fn same_origin_url(raw: &str, actor_url: &Url) -> Result<Url> {
    let url = remote_url(raw)?;
    if url.origin() != actor_url.origin() {
        bail!(
            "refusing {url}: not on the actor's origin {}",
            actor_url.origin().ascii_serialization()
        );
    }
    Ok(url)
}

async fn read_limited(mut resp: Response, limit: usize) -> Result<Vec<u8>> {
    if resp
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("response is larger than {limit} bytes");
    }
    let mut body = Vec::with_capacity(resp.content_length().map_or(0, |length| length as usize));
    while let Some(chunk) = resp.chunk().await.context("failed to read response")? {
        if body.len() + chunk.len() > limit {
            bail!("response is larger than {limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn collection_items(collection: &Value) -> &[Value] {
    collection
        .get("orderedItems")
        .or_else(|| collection.get("items"))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn statuses_from_page(page: &Value) -> Vec<Status> {
    collection_items(page)
        .iter()
        .filter_map(status_from_activity)
        .take(STATUSES_LIMIT)
        .collect()
}

/// A post from a `Create` with an embedded object. Reblogs and by-reference objects are skipped.
fn status_from_activity(activity: &Value) -> Option<Status> {
    if str_field(activity, "type") != Some("Create") {
        return None;
    }
    let object = activity.get("object").filter(|object| object.is_object())?;
    let content_map = object
        .get("contentMap")
        .and_then(Value::as_object)
        .and_then(|map| map.iter().next());
    let content = str_field(object, "content")
        .or_else(|| content_map.and_then(|(_, content)| content.as_str()))
        .unwrap_or_default();
    let attachments = match object.get("attachment") {
        Some(Value::Array(items)) => items.as_slice(),
        Some(item @ Value::Object(_)) => std::slice::from_ref(item),
        _ => &[],
    };
    let spoiler_text = str_field(object, "summary").unwrap_or_default();
    if content.is_empty() && spoiler_text.is_empty() && attachments.is_empty() {
        return None;
    }
    Some(Status {
        content: content.into(),
        spoiler_text: spoiler_text.into(),
        language: content_map.map(|(language, _)| language.clone()),
        created_at: str_field(object, "published").unwrap_or_default().into(),
        url: object_url(object),
        media_attachments: attachments
            .iter()
            .map(|item| MediaAttachment {
                description: str_field(item, "name").map(Into::into),
            })
            .collect(),
    })
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `url` may be a string, a `Link`, or a list of either; falls back to `id`.
fn object_url(object: &Value) -> Option<String> {
    fn link(value: &Value) -> Option<&str> {
        value.as_str().or_else(|| str_field(value, "href"))
    }
    match object.get("url") {
        Some(Value::Array(items)) => items.iter().find_map(link),
        Some(value) => link(value),
        None => None,
    }
    .or_else(|| str_field(object, "id"))
    .map(Into::into)
}

/// Drops resolved addresses outside the public internet, so DNS cannot point the fetcher inward.
struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public_ip(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} resolves to no public address").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        // Shared address space (carrier-grade NAT).
        || (a == 100 && (b & 0xc0) == 64)
        // Benchmarking.
        || (a == 198 && (b & 0xfe) == 18)
        // IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // Reserved.
        || a >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(v4);
    }
    let segments = ip.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    // NAT64 and 6to4 carry an IPv4 destination.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_ipv4(embedded(segments[6], segments[7]));
    }
    if segments[0] == 0x2002 {
        return is_public_ipv4(embedded(segments[1], segments[2]));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // IPv4-compatible (deprecated).
        || segments[..6] == [0; 6]
        // IPv4-translated (SIIT).
        || segments[..6] == [0, 0, 0, 0, 0xffff, 0]
        // Local-use NAT64.
        || segments[..3] == [0x64, 0xff9b, 1]
        // Unique local.
        || (segments[0] & 0xfe00) == 0xfc00
        // Link-local and (deprecated) site-local.
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        // Documentation.
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn non_public_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::1",
            "fec0::1",
            "::ffff:0:7f00:1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.215.14", "2606:4700::1111", "64:ff9b::808:808"] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn remote_urls_must_be_public_https() {
        assert!(remote_url("https://example.com/users/alice").is_ok());
        assert!(remote_url("http://example.com/users/alice").is_err());
        assert!(remote_url("https://127.0.0.1/users/alice").is_err());
        assert!(remote_url("https://[::1]/users/alice").is_err());
        assert!(remote_url("https://user:pass@example.com/").is_err());
        assert!(remote_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn followed_urls_stay_on_the_actors_origin() {
        let actor = remote_url("https://example.com/users/alice").unwrap();
        assert!(
            same_origin_url("https://example.com/users/alice/outbox?page=true", &actor).is_ok()
        );
        assert!(same_origin_url("https://evil.example/outbox", &actor).is_err());
        assert!(same_origin_url("https://example.com:8443/outbox", &actor).is_err());
    }

    #[test]
    fn signing_string_covers_target_host_date_and_accept() {
        let url = remote_url("https://example.com:8443/users/a/outbox?page=true#x").unwrap();
        assert_eq!(request_target(&url), "/users/a/outbox?page=true");
        assert_eq!(host_header(&url).unwrap(), "example.com:8443");
        assert_eq!(
            signing_string("/outbox", "example.com", "Thu, 01 Jan 2026 00:00:00 GMT"),
            format!(
                "(request-target): get /outbox\nhost: example.com\ndate: Thu, 01 Jan 2026 00:00:00 GMT\naccept: {ACTIVITY_JSON}"
            )
        );
    }

    #[test]
    fn user_agent_matches_mastodons() {
        assert_eq!(
            mastodon_user_agent(
                "4.4.0",
                &Url::parse("https://mastodon.example/actor#main-key").unwrap()
            ),
            "Mastodon/4.4.0 (+https://mastodon.example/)"
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        assert!(parse_private_key("").is_err());
        assert!(
            parse_private_key(
                "-----BEGIN RSA PRIVATE KEY-----\n!!!\n-----END RSA PRIVATE KEY-----"
            )
            .is_err()
        );
        assert!(
            parse_private_key(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
            )
            .is_err()
        );
        assert!(
            parse_private_key("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----")
                .is_err()
        );
    }

    #[test]
    fn outbox_page_yields_created_posts_only() {
        let page = json!({
            "type": "OrderedCollectionPage",
            "orderedItems": [
                {
                    "type": "Create",
                    "object": {
                        "id": "https://example.com/users/a/statuses/1",
                        "type": "Note",
                        "summary": "cw",
                        "content": "<p>buy now</p>",
                        "contentMap": { "ja": "<p>buy now</p>" },
                        "published": "2026-10-01T00:00:00Z",
                        "url": "https://example.com/@a/1",
                        "attachment": [{ "type": "Document", "name": "an image" }]
                    }
                },
                { "type": "Announce", "object": "https://other.example/notes/1" },
                { "type": "Create", "object": "https://example.com/notes/by-reference" },
                {
                    "type": "Create",
                    "object": {
                        "id": "https://example.com/notes/2",
                        "type": "Note",
                        "content": "second",
                        "url": [{ "type": "Link", "href": "https://example.com/notes/2.html" }]
                    }
                }
            ]
        });
        let statuses = statuses_from_page(&page);
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].content, "<p>buy now</p>");
        assert_eq!(statuses[0].spoiler_text, "cw");
        assert_eq!(statuses[0].language.as_deref(), Some("ja"));
        assert_eq!(statuses[0].created_at, "2026-10-01T00:00:00Z");
        assert_eq!(statuses[0].url.as_deref(), Some("https://example.com/@a/1"));
        assert_eq!(
            statuses[0].media_attachments[0].description.as_deref(),
            Some("an image")
        );
        assert_eq!(
            statuses[1].url.as_deref(),
            Some("https://example.com/notes/2.html")
        );
    }

    #[test]
    fn outbox_page_is_capped() {
        let items: Vec<Value> = (0..20)
            .map(|i| json!({ "type": "Create", "object": { "type": "Note", "content": i.to_string() } }))
            .collect();
        let statuses = statuses_from_page(&json!({ "orderedItems": items }));
        assert_eq!(statuses.len(), STATUSES_LIMIT);
        assert_eq!(statuses[0].content, "0");
    }
}
