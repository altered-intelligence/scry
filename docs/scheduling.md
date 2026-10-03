# Scheduling — unattended collection + daily digest email

Scry's recurring work (feed ingestion every 30 min, OTX pulls, alert
evaluation, clustering, IOC decay, the weekly raw_html retention prune, and
the optional daily digest email) runs
in a single APScheduler process: `python -m scry.scheduler` (or
`scry scheduler run`). This page covers running it unattended and getting
the daily report delivered by email.

## 1. Daily digest email

The scheduler can generate the daily report (the same Markdown as
`scry report daily` / `/reports/daily`) and email it every morning at
**HH:12 local time** (default 07:12). It is **off by default**.

Setup:

1. Configure SMTP — either in the admin panel (Settings → SMTP) or via the
   `CTI_SMTP_*` env vars (see [configuration.md](./configuration.md)).
   Without SMTP the job logs `digest_skipped reason="smtp not configured"`
   and does nothing else.
2. Set the digest env vars and restart the scheduler:

   ```bash
   CTI_DIGEST_EMAIL_ENABLED=true
   CTI_DIGEST_EMAIL_TO=you@example.com
   CTI_DIGEST_EMAIL_HOUR=7        # local hour; always fires at :12
   ```

Subject line: `Scry daily digest — YYYY-MM-DD (N articles, M high-risk)`
(high-risk = observables seen in the last 24 h with risk ≥ 70). The body is
multipart: plain text plus a `text/markdown` part for clients that render it.

Dry-run the job without waiting for the morning:

```bash
CTI_DIGEST_EMAIL_ENABLED=true CTI_DIGEST_EMAIL_TO=you@example.com \
  .venv/bin/python -c "from scry.scheduler import _digest_job; _digest_job()"
```

## 2. macOS — run the scheduler with launchd

```bash
scry scheduler install        # writes ~/Library/LaunchAgents/com.scry.scheduler.plist
scry scheduler status         # installed? loaded? digest readiness?
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.scry.scheduler.plist
```

`install` is idempotent (re-run after upgrades; it reports
`installed` / `updated` / `unchanged`) and only writes the plist — loading
is your call, or pass `--load`:

```bash
scry scheduler install --load
```

The plist:

- runs the **current venv interpreter** (`sys.executable` at install time)
  with `-m scry.scheduler`, so reinstall after moving the project or
  recreating the venv;
- sets `WorkingDirectory` to the project root (so `.env` resolves) and an
  **absolute** `CTI_DATABASE_URL` (the default `./cti.sqlite` is anchored at
  the repo);
- `RunAtLoad` + `KeepAlive` — starts at login, restarts on crash;
- logs to `logs/scheduler.log` and `logs/scheduler.err.log` (gitignored).

Remove it:

```bash
launchctl bootout gui/$(id -u)/com.scry.scheduler   # if loaded
scry scheduler uninstall
```

Note: the web UI / API is a separate process (`scry serve` / uvicorn) — the
LaunchAgent covers only the background scheduler.

## 3. Linux — systemd user unit

`~/.config/systemd/user/scry-scheduler.service`:

```ini
[Unit]
Description=Scry CTI scheduler
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/path/to/cti-enrichment-agent
Environment=CTI_DATABASE_URL=sqlite+pysqlite:////path/to/cti-enrichment-agent/cti.sqlite
# Optional digest:
# Environment=CTI_DIGEST_EMAIL_ENABLED=true
# Environment=CTI_DIGEST_EMAIL_TO=you@example.com
ExecStart=/path/to/cti-enrichment-agent/.venv/bin/python -m scry.scheduler
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable --now scry-scheduler
loginctl enable-linger "$USER"     # keep it running after logout
journalctl --user -u scry-scheduler -f
```

## 4. Docker

The compose bundle already includes a `scheduler` service
(`python -m scry.scheduler`); set the digest env vars on that service to get
the email there.

## 4. raw_html retention (weekly prune)

Stored `raw_html` is the dominant share of database size and is only needed
to re-parse an article — every consumer (FTS, embeddings, extraction,
exports, UI) works off `extracted_text`. The scheduler prunes it for
articles older than `CTI_RAW_HTML_RETENTION_DAYS` (default 30; `0` = keep
forever) every **Sunday at 04:47 UTC**, logging `articles_pruned` and
`bytes_reclaimed`; the job skips cleanly when retention is 0 and never
raises. A pruned article that later needs its HTML is re-fetched from its
URL by `fetch_full_content`.

Manual runs (including a dry-run and file shrink via VACUUM):

```bash
scry prune-html --dry-run     # report counts + reclaimable bytes, no writes
scry prune-html               # prune at the configured horizon + VACUUM
scry prune-html --days 7      # custom horizon
```
