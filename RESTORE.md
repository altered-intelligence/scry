# How to restore from backup

Scry backup archive used with these instructions:
`scry-backup-2026-10-01.tar.gz.enc` (encrypted with the install's `.cti_secret` key — the key travels inside the archive, so no other secret is needed to decrypt it).

The archive contains: `cti.sqlite` (the full database), `.env`, `.cti_secret`, `config/*.yaml`, alembic files, and a `manifest.json` with version + table counts + sha256 checksums.

> **Golden rule: stop the scry server before backing up or restoring.** Restoring over a live SQLite database is the only way to hurt yourself with this process.

---

## Scenario A — Same machine (database corrupted, bad migration, bad config)

```bash
cd ~/Dropbox/Documents/projects/CTI/cti-enrichment-agent

# 1. Stop the server (Ctrl+C if it's running)

# 2. Move the broken DB aside instead of deleting it (no --force needed)
mv cti.sqlite cti.sqlite.broken

# 3. Restore — archive decrypts itself; target is the current directory
.venv/bin/scry restore ~/Documents/kimi/workspace/scry-backup-2026-10-01.tar.gz.enc

# 4. Check the printed summary, then verify counts look right
.venv/bin/scry stats

# 5. Start the server
.venv/bin/uvicorn scry.main:app --reload
```

If you skip step 2, restore **refuses** to overwrite the existing database — that's the guard doing its job. Either move the file aside first, or pass `--force` deliberately.

## Scenario B — Brand-new machine

```bash
# 1. Get the code
git clone https://github.com/altered-intelligence/scry.git
cd scry

# 2. Install (same as a fresh setup)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 3. Copy the backup archive onto this machine (USB, etc.), then restore
scry restore scry-backup-2026-10-01.tar.gz.enc

# 4. Boot — users, API keys, sources, and all intel data are back
uvicorn scry.main:app --reload
```

No `scry init-db` needed — the archive *is* your database. Your user accounts (including admins) come back with it, so log in normally; the first-run `/setup` page only appears when zero users exist.

---

## What restore does automatically

- Detects the `.enc` suffix and decrypts using the `.cti_secret` inside the archive
- Validates the manifest and every file's sha256 — a corrupted or tampered archive stops the restore before anything is touched
- Blocks archive entries that would escape the target directory (path-traversal guard)
- Refuses, without `--force`, an archive made by a **newer** scry version than the one installed
- Restores atomically (temp files, then swap) — you can't end up half-restored
- Prints a before/after table-count summary

## Troubleshooting

| Problem | Fix |
|---|---|
| "refuses to overwrite an existing database" | `mv cti.sqlite cti.sqlite.old` and re-run, or use `--force` |
| "archive was created by a newer scry" | Upgrade scry first (`git pull && pip install -e .`), or `--force` if you accept the risk |
| Checksum/manifest validation failed | The archive is corrupt or tampered — re-copy it from the source; don't force past this |
| Decryption fails | The archive needs the `.cti_secret` key that was on the machine that made it — it should be inside the archive; if you split them up, restore the key file first |

## Making a fresh backup

```bash
cd ~/Dropbox/Documents/projects/CTI/cti-enrichment-agent

# Server stopped, then:
.venv/bin/scry backup --encrypt -o ~/Documents/kimi/workspace/scry-backup-$(date +%F).tar.gz
```

- The archive **always contains secrets** (API keys, `.env`, `.cti_secret`) — store it somewhere you trust; never commit it to git
- `--full` additionally includes `data/` (raw HTML) and downloaded AI models (much larger)
- Add `--encrypt` unless you have another protection mechanism — it uses the install's existing Fernet key

*Written 2026-10-01 against scry v0.8.0. If the CLI changes, check `scry restore --help`.*
