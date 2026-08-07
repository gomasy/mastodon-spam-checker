# mastodon-spam-checker

An LLM-powered spam detector for Mastodon instances. It fetches newly federated
remote accounts through the Mastodon Admin API, asks an OpenAI-compatible LLM
whether each account looks like spam, and reports detections to Slack. Each
notification carries a **Suspend** button so a moderator can act straight from
Slack; after suspension it becomes **Delete account**, which permanently deletes
the account's data after a second confirmation. Both are handled by an optional
companion server (`serve` mode).

Designed to run periodically (cron, systemd timer): each run picks up where the
previous one left off. Redis holds the cursor and a per-account record of
verdicts, attempts, campaign matches, moderator feedback, and failures. Completed
records and moderation action logs expire after 90 days — the first run after
upgrading applies the policy to pre-existing records — while unresolved retries,
moderator feedback, and the cursor stay durable.

## How it works

1. Fetches remote accounts newer than the saved cursor via
   `GET /api/v2/admin/accounts`, up to `MAX_ACCOUNTS_PER_RUN`.
2. Skips system actors (instance actors, `mastodon.internal`, etc.).
3. Fetches each account's recent posts and builds a bounded prompt from profile
   fields, extracted link destinations, account metadata, content warnings,
   language, timestamps, and media descriptions.
4. Correlates substantial bio fingerprints and linked domains with a capped
   sample of accounts observed in the last 30 days, exposing coordinated
   campaigns to the LLM without an unbounded Redis index.
5. Asks the LLM for a verdict:
   `{"spam": bool, "reason": "...", "confidence": 0.0-1.0}`.
6. Persists the verdict and sends a Slack notification for each account judged
   as spam, including the local moderation page, feedback actions, and a suspend
   button.
7. Saves the last contiguously processed account ID as the cursor.

The prompt treats all account data as untrusted: instructions embedded in
profiles or posts are themselves a spam indicator.

### Failures and retries

Transient failures against Mastodon, the LLM, and the Slack webhook — timeouts,
connection errors, 429, and 5xx — are retried with exponential backoff (base
500 ms, doubling, up to 3 retries). A `Retry-After` on a 429 is honored instead
of the computed backoff, capped at 30 seconds so leases and notification claims
cannot expire during an unbounded wait.

A failure that survives the retries, like a non-retryable one (4xx other than
429), stops the run: progress is saved through the preceding account, the failed
ID joins a durable retry queue, and the next run resumes from the same account.
Accounts later in the same concurrent batch that did complete are skipped from
their stored records. Deleted accounts (404/410 on the statuses endpoint) are
judged from their profile alone.

An LLM reply carrying no usable verdict is the one failure a later run cannot
recover from — the same reply would come back every time, parking the cursor
permanently — so the account is stored as `undetermined` and the run continues,
with the count reported at the end. A confidence outside 0.0–1.0 is normalized
for the same reason: values between 1 and 100 are read as a percentage, anything
else is clamped.

Normal checks, retries, and backfills share a renewable Redis lease, so
overlapping invocations fail instead of duplicating work. A Slack delivery
interrupted after it starts is stored as pending; the periodic checker leaves it
alone, and `retry-failed` re-sends it from the persisted verdict.

### Confidence threshold

`SPAM_CONFIDENCE_THRESHOLD` (0.0–1.0) suppresses noisy notifications: a spam
verdict is reported to Slack only when its `confidence` meets the threshold.
Detections below it are logged and otherwise ignored. The default `0.0` notifies
on every spam verdict.

### Dry-run mode

```sh
./target/release/mastodon-spam-checker dry-run
```

Runs the same fetch → LLM judgment pipeline but **does not** send Slack
notifications, require `SLACK_WEBHOOK_URL`, persist account jobs, or advance the
cursor — useful for tuning the prompt, model, or `SPAM_CONFIDENCE_THRESHOLD`.
Judgment results, including below-threshold detections, are still logged.

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
cp .env.example .env
# edit .env
./target/release/mastodon-spam-checker
```

Configuration is read from environment variables; a `.env` file in the working
directory is also loaded.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MASTODON_BASE_URL` | ✅ | – | Base URL of your instance (e.g. `https://mastodon.example`) |
| `MASTODON_ACCESS_TOKEN` | ✅ | – | Access token with `admin:read:accounts` |
| `REDIS_URL` | | `redis://localhost:6379` | Redis connection URL |
| `MAX_ACCOUNTS_PER_RUN` | | `1000` | Maximum accounts fetched across pagination in one run |
| `CHECK_CONCURRENCY` | | `4` | Maximum concurrent account checks |
| `OPENAI_API_BASE` | ✅ | – | OpenAI-compatible API base (e.g. `https://api.openai.com/v1`) |
| `OPENAI_API_KEY` | ✅ | – | API key |
| `OPENAI_MODEL` | | `gpt-4o` | Model name |
| `OPENAI_JSON_MODE` | | `true` | Set to `false` for APIs without `response_format` support. Accepts `true`, `false`, `1`, or `0` (case-insensitive) |
| `SPAM_CONFIDENCE_THRESHOLD` | | `0.0` | Skip Slack notifications for spam verdicts below this confidence (0.0–1.0) |
| `SLACK_WEBHOOK_URL` | normal check | – | Slack incoming webhook URL. Not required by `dry-run`, `check-account`, or backfill without `--notify` |
| `SLACK_CHANNEL` | | – | Override the webhook's default channel. Only honored by legacy custom-integration webhooks — Slack-app webhooks (required for the suspend button) always post to the channel chosen at install time. Quote the value (`"#spam-alerts"`) so `#` is not parsed as a comment |
| `SLACK_SIGNING_SECRET` | `serve` only | – | Signing secret of your Slack app (Basic Information page) |
| `LISTEN_ADDR` | | `127.0.0.1:8990` | Listen address for `serve` mode |
| `DATABASE_URL` | | – | Mastodon's PostgreSQL database. When set, moderation notes are written on spam detection and on suspension. Connects without TLS, so point it at a local socket or `localhost` |
| `MODERATOR_ACCOUNT_ID` | with `DATABASE_URL` | – | `account.id` shown as the note author in the Mastodon admin UI |

Values are validated at startup: malformed booleans, confidence thresholds, or
zero/invalid processing limits abort the run instead of being ignored. An empty
value (`KEY=`) counts as unset and falls back to the default, so a required
variable set to an empty string is reported as missing.

Logging verbosity is adjusted with `RUST_LOG`
(e.g. `RUST_LOG=mastodon_spam_checker=debug`).

### Moderation notes

With `DATABASE_URL` and `MODERATOR_ACCOUNT_ID` set, a row is inserted into
Mastodon's `account_moderation_notes` when an account is reported as spam and
when one is suspended from Slack, so the reasoning is visible in the admin UI. A
note that fails to write is logged and does not abort the action it accompanies.
Because `serve` mode is long-running, a connection lost to a database restart or
idle timeout is re-established on the next write.

## Operator commands

Classify one account without Redis, Slack, PostgreSQL, or cursor changes:

```sh
mastodon-spam-checker check-account 1234567890
```

Print the current Redis cursor:

```sh
mastodon-spam-checker cursor
```

Retry failed jobs and pending Slack deliveries. Successful retries leave the
queue; pending deliveries reuse the persisted verdict instead of calling the LLM
again:

```sh
mastodon-spam-checker retry-failed
mastodon-spam-checker retry-failed --max 25
```

Backfill an ID range. Both `--from` and the optional `--to` are exclusive
bounds. Results are persisted without changing the periodic cursor, and Slack
notifications are disabled unless `--notify` is supplied:

```sh
mastodon-spam-checker backfill --from 1000000000 --to 2000000000 --max 500
mastodon-spam-checker backfill --from 1000000000 --max 100 --notify
```

## Slack actions (`serve` mode)

Clicking a button in Slack sends an interaction payload to a public HTTPS
endpoint, so the suspend button needs a small always-on server alongside the
periodic checker:

```sh
./target/release/mastodon-spam-checker serve
```

It listens on `LISTEN_ADDR` and handles `POST /slack/interactions`: verifies the
request signature with `SLACK_SIGNING_SECRET`, records feedback in Redis,
suspends accounts via `POST /api/v1/admin/accounts/:id/action`, and updates the
original Slack message. A failed action keeps its button so it can be retried.

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

Both destructive actions ask for confirmation. Requests with a missing/invalid
signature or a stale timestamp (>5 min, replay protection) are rejected,
duplicate clicks while a suspension is in flight are ignored, and on SIGTERM the
server finishes in-flight suspensions (up to 30 s) before exiting.

**Confirm spam** stores a human-confirmed label and leaves suspension available.
**False positive** stores the correction and removes destructive actions from
that Slack message. Both records include the acting Slack user ID.

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

- No account is suspended or deleted automatically. These actions only happen
  when someone with access to the Slack notification clicks the corresponding
  button and confirms the dialog; the checker itself only reports. Restrict
  access to the notification channel to trusted moderators.
- The release profile is tuned for binary size (rustls with the pure-Rust
  `ring` backend, LTO, stripped symbols), producing a ~3 MB binary.

## License

[MIT](LICENSE)
