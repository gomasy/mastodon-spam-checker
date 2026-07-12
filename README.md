# mastodon-spam-checker

An LLM-powered spam detector for Mastodon instances. It fetches newly
federated remote accounts through the Mastodon Admin API, asks an
OpenAI-compatible LLM whether each account looks like spam, and reports
detections to Slack. Each notification carries a **Suspend** button so a
moderator can suspend the account straight from Slack (with a confirmation
dialog) — handled by an optional companion server (`serve` mode).

Designed to run periodically (e.g. via cron or a systemd timer): each run
picks up where the previous one left off, using a cursor stored in Redis.

## How it works

1. Fetches remote accounts newer than the saved cursor via
   `GET /api/v2/admin/accounts` (up to 100 per run).
2. Skips system actors (instance actors, `mastodon.internal`, etc.).
3. Fetches each account's recent posts and builds a prompt from the
   profile and post contents (HTML is converted to plain text).
4. Asks the LLM for a verdict: `{"spam": bool, "reason": "...", "confidence": 0.0-1.0}`.
5. Sends a Slack notification (with a suspend button) for each account
   judged as spam.
6. Saves the last processed account ID to Redis as the cursor.

On retryable errors (fetch or LLM failures) the run stops without advancing
the cursor, so the next run resumes from the same account. Deleted accounts
(HTTP 404/410 on the statuses endpoint) are judged from their profile alone.

The prompt treats all account data as untrusted: instructions embedded in
profiles or posts are themselves considered a spam indicator.

## Requirements

- A Mastodon access token with the `admin:read:accounts` scope
  (plus `admin:write:accounts` if you use the suspend button)
- Redis (cursor storage)
- An OpenAI-compatible chat completions API
- A Slack incoming webhook (created from a Slack app if you use the
  suspend button — see below)

## Setup

```sh
cargo build --release
```

Configuration is read from environment variables (a `.env` file in the
working directory is also loaded):

```sh
cp .env.example .env
# edit .env
./target/release/mastodon-spam-checker
```

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MASTODON_BASE_URL` | ✅ | – | Base URL of your instance (e.g. `https://mastodon.example`) |
| `MASTODON_ACCESS_TOKEN` | ✅ | – | Access token with `admin:read:accounts` |
| `REDIS_URL` | | `redis://localhost:6379` | Redis connection URL |
| `OPENAI_API_BASE` | ✅ | – | OpenAI-compatible API base (e.g. `https://api.openai.com/v1`) |
| `OPENAI_API_KEY` | ✅ | – | API key |
| `OPENAI_MODEL` | | `gpt-4o` | Model name |
| `OPENAI_JSON_MODE` | | `true` | Set to `false` for APIs without `response_format` support |
| `SLACK_WEBHOOK_URL` | ✅ | – | Slack incoming webhook URL |
| `SLACK_CHANNEL` | | – | Override the webhook's default channel. Only honored by legacy custom-integration webhooks — Slack-app webhooks (required for the suspend button) ignore channel/username/icon overrides and always post to the channel chosen at install time. Quote the value (`"#spam-alerts"`) so `#` is not parsed as a comment |
| `SLACK_SIGNING_SECRET` | `serve` only | – | Signing secret of your Slack app (Basic Information page) |
| `LISTEN_ADDR` | | `127.0.0.1:8990` | Listen address for `serve` mode |

Logging verbosity can be adjusted with `RUST_LOG`
(e.g. `RUST_LOG=mastodon_spam_checker=debug`).

## Suspend button (`serve` mode)

Clicking a button in Slack sends an interaction payload to a public HTTPS
endpoint, so the suspend button needs a small always-on server in addition
to the periodic checker:

```sh
./target/release/mastodon-spam-checker serve
```

It listens on `LISTEN_ADDR` and handles `POST /slack/interactions`:
verifies the request signature with `SLACK_SIGNING_SECRET`, suspends the
account via `POST /api/v1/admin/accounts/:id/action`, and updates the
original Slack message with the result (on success the button is removed;
on failure it is kept so you can retry).

Setup:

1. Make sure your incoming webhook belongs to a Slack app
   (<https://api.slack.com/apps> — webhooks created via the legacy
   "Incoming WebHooks" custom integration cannot receive interactions).
2. Expose the server over HTTPS, e.g. behind a reverse proxy:
   `https://your-host.example/slack/interactions` → `127.0.0.1:8990`.
3. In the Slack app settings, enable **Interactivity & Shortcuts** and set
   the Request URL to that endpoint.
4. Copy the **Signing Secret** from Basic Information into
   `SLACK_SIGNING_SECRET`, and give the Mastodon token the
   `admin:write:accounts` scope.

The button always asks for confirmation before suspending. Requests with a
missing/invalid signature or a stale timestamp (>5 min, replay protection)
are rejected, duplicate clicks while a suspension is in flight are ignored,
and on SIGTERM the server finishes in-flight suspensions (up to 30 s)
before exiting.

Note: because app-owned webhooks ignore the `SLACK_CHANNEL` /
username / icon overrides, notifications will post to the channel chosen
when the webhook was installed.

Example systemd unit:

```ini
# /etc/systemd/system/mastodon-spam-checker-serve.service
[Unit]
Description=Slack interaction server for mastodon-spam-checker
Wants=network-online.target
After=network-online.target

[Service]
WorkingDirectory=/path/to/mastodon-spam-checker
ExecStart=/path/to/mastodon-spam-checker/target/release/mastodon-spam-checker serve
Restart=on-failure
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

### Running periodically

Example systemd units (every 10 minutes):

```ini
# /etc/systemd/system/mastodon-spam-checker.service
[Unit]
Description=LLM-powered spam detector for Mastodon
Wants=network-online.target
After=network-online.target redis.service

[Service]
Type=oneshot
# dotenvy loads .env from the working directory
WorkingDirectory=/path/to/mastodon-spam-checker
ExecStart=/path/to/mastodon-spam-checker/target/release/mastodon-spam-checker
# Runs as an ephemeral unprivileged user; the working directory and
# .env must be readable by it (or drop this and set User= instead)
DynamicUser=yes
```

```ini
# /etc/systemd/system/mastodon-spam-checker.timer
[Unit]
Description=Run mastodon-spam-checker every 10 minutes

[Timer]
OnCalendar=*:0/10
RandomizedDelaySec=30
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mastodon-spam-checker.timer
```

## Notes

- No account is suspended or silenced automatically. A suspension only
  happens when a moderator clicks the button in Slack and confirms the
  dialog; the checker itself only reports.
- The release profile is tuned for binary size (rustls with the pure-Rust
  `ring` backend, LTO, stripped symbols), producing a ~3 MB binary.

## License

[MIT](LICENSE)
