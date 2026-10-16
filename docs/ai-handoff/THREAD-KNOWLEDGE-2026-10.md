# Scry: knowledge transfer from the October 2026 working thread

This is the portable memory of one long working thread (3 to 16 October 2026)
between the owner and an AI coding assistant. It records what was built,
why each decision was made, every problem hit along the way and how it was
diagnosed, and how to operate the project afterwards. It is written so a
different model, or a new session, can continue without re-discovering any
of it.

Read it together with [`HANDOFF.md`](../../HANDOFF.md) (architecture, golden
rules, master prompt) and [`CHANGELOG.md`](../../CHANGELOG.md) (per-release
detail). Machine-specific facts (paths, servers, backups) are deliberately
not in this public file; the owner keeps them in a private export.

---

## 1. Load order for a new model

1. `HANDOFF.md` section 8 (the master prompt) and section 7 (current state).
2. This file, sections 2 to 5.
3. `CHANGELOG.md` entries for 0.15.2 through 0.17.0.
4. `SCORING.md` (scoring model 0.2) and `SECURITY.md` (data flows, third-party terms).
5. `docs/usage-cli.md` for `scry reprocess`, `scry prune-evidence`, `scry ingest ransomware-feed`.

Then run the verification loop before changing anything:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check . && .venv/bin/black --check .
```

---

## 2. Owner preferences and working agreements

These were stated or confirmed by the owner during the thread. Treat them as rules.

- **Push and release only on request.** Commit locally freely; `git push`, tags and releases happen when the owner asks ("update GitHub", "tag vX and release it").
- **The master copy is this repository.** A separately deployed copy of Scry lives inside the owner's website project with its own copy-only patch (admin-only collection, 72-hour external enrichment limit, dark theme default). That copy is refreshed from this repo by re-copying the folder and re-applying its patch; do not assume changes here are live there.
- **The old hunt-workbook brand name must not appear anywhere** (data, docs, UI). Imported workbooks are branded "Atlas". The importer that created those rows is not in this repo; a re-import would reintroduce the old name.
- **Never handle credentials in chat.** When the owner pasted a GitHub token, the assistant refused to use it and moved the project to SSH deploy keys plus a tag-triggered release workflow. Tokens that appeared anywhere must be revoked by the owner.
- **Back up before any data change.** Every bulk data operation in this thread (rename, cleanup, backfill, imports, reprocess) was preceded by an SQLite `.backup` of the live database, kept outside the synced project folder.
- **Report honestly.** Say "verified" only after running something; list what was not verified (for example, mobile work was verified in browser emulation, not on physical phones).
- **Data stays local; code goes to GitHub.** Scraped or imported third-party data is never committed.

---

## 3. What was done, in order

| Date | Version | Work |
|---|---|---|
| 10-03 | (data) | Deep code review (efficiency, optimisation, security). Renamed the imported workbook brand to "Atlas" across titles, URLs (`local://atlas-*`), text, tags, mention evidence; FTS5 and embeddings refreshed. |
| 10-03 | 0.15.2 | Relationship evidence capped at 400 characters (`evidence_window`), `scry prune-evidence`, startup trim. Live DB 1.3 GB to 126 MB. |
| 10-03 | 0.16.0 | Single-URL ingest now parses pages; feeds sniffed by body; empty-article cleanup; scheduled full-page fetch for RSS stubs (`CTI_FULL_FETCH_*`) and a one-off backfill (+1,145 observables, +411 claims); bcrypt >72-byte password crash fixed; `Secure` cookies (`CTI_COOKIE_SECURE`); `/api/ai/provider` authenticated; `POST /sources` admin-only; tag-triggered release workflow. |
| 10-04 | 0.16.1 | Feedly removed entirely (settings, scripts, docs, redactor pattern); dashboard Quick links repointed to live views; ransomware feed file importer `scry ingest ransomware-feed`. |
| 10-04 | (data) | 226 ransomware leak-site posts (one 7-day window from a third-party tracker the owner subscribes to) captured and imported locally, tagged `source:<name>`; later copied into the deployed copy. |
| 10-06 | 0.17.0 | Product-review fixes: extraction precision, local-evidence attribution, scoring model 0.2 with stored explanations, `scry reprocess`, rewritten daily/weekly briefs, KEV `dateAdded`, 429 back-off, readable UI labels, admin-only key controls, data-flow documentation. Mobile support for phones/tablets/foldables, PWA icons, gzip. Embedded Orbistrace page. |
| 10-16 | (docs) | This knowledge transfer. |

---

## 4. Troubleshooting casebook

Each entry: symptom, root cause, fix, how it was verified, lesson.

### 4.1 Database grew to 1.3 GB
- **Symptom:** `cti.sqlite` 1.3 GB; slow backups and sync.
- **Root cause:** `relationships.evidence_text` held 1.16 GB. Punctuation-free imports (pasted IOC sheets) became one 250 KB "sentence", copied onto every relationship row from that sheet (9,385 rows, 73 distinct sentences).
- **Fix:** `evidence_window()` keeps the closest pair of endpoint mentions within 400 characters (two fragments when far apart); a sink guard in the pipeline; `truncate_relationship_evidence()` + `scry prune-evidence` + an idempotent startup trim.
- **Verified:** table 1,167 MB to 4.5 MB, file 126 MB after VACUUM.
- **Lesson:** measure per-table size (`dbstat`) before guessing; "sentence" splitting breaks on non-prose input.

### 4.2 Single-URL ingest stored empty articles
- **Root cause:** `ingest_url` persisted the fetch without parsing HTML, and the full-page pass only selected rows with no stored HTML, so these were never repaired. Some feeds also served XML with an HTML content type.
- **Fix:** `_persist_fetch` parses immediately; `looks_like_feed()` sniffs the body; cleanup re-parsed or removed the empty rows.

### 4.3 RSS stubs never got their full text
- **Fix:** `fetch_full_content(limit, max_age_hours, retry_after_hours)` wired into the scheduled ingest, bounded per run, with per-URL failure back-off recorded in `source_fetches`.

### 4.4 Passwords longer than 72 bytes crashed login
- **Root cause:** bcrypt 5 raises instead of truncating.
- **Fix:** passwords are SHA-256 pre-hashed (`bcrypt-sha256$` scheme), existing hashes still verify, input capped at 1,024 characters.

### 4.5 Security hardening items
- Cookies lacked `Secure` (now `auto` by default: set over HTTPS or trusted `X-Forwarded-Proto`; plain localhost still works in Safari).
- `GET /api/ai/provider` leaked configuration unauthenticated (now behind auth).
- `POST /sources` was not admin-gated (now admin-only).
- System enrichment key controls rendered for every user on the Alerts page (the API was already admin-only; the controls and their script now render for admins only).

### 4.6 Dashboard Quick links led to empty pages
- **Root cause:** three links filtered the Threat Feeds table, which nothing populates any more.
- **Fix:** repointed to live views; a test requires every Quick link to resolve with 200.

### 4.7 GitHub pushes from the assistant
- **Symptom:** the assistant cannot authenticate; the owner offered a classic token.
- **Decision:** tokens are never used from chat. An SSH deploy key was set up and `.github/workflows/release.yml` publishes a GitHub release when a `v*` tag is pushed (checks version agreement, runs lint and tests, extracts notes from the changelog).
- **Release recipe:** bump `pyproject.toml` and `scry/main.py`; rename the `[Unreleased]` changelog heading; add README "What's new"; update `HANDOFF.md` rows; run tests; commit; `git tag -a vX.Y.Z`; `git push origin main --follow-tags`; confirm the release via the public API.

### 4.8 Test failure after a toolchain change
- `test_install_writes_correct_plist` asserted the interpreter path ends with `python`; the venv now resolves to `python3.12`. The assertion accepts `python[\d.]*`.

### 4.9 Product review: ASP.NET became a risk-99 domain with Cl0p tags
An external product review found the analysis untrustworthy. Root causes, each fixed and pinned by `tests/test_accuracy_regressions.py`:

| Problem | Root cause | Fix |
|---|---|---|
| `asp.net` extracted as a domain | `.net` is a real TLD | product-name list (`ASP.NET`, `VB.NET`, `Microsoft.NET`, upper-case `.NET` suffix, `software_name_denylist` in policies.yaml); file-name-shaped hosts (`README.md`) flagged `possible-filename` |
| Every CVE in a roundup tagged Cl0p | the pipeline stamped every entity found anywhere in the article onto every indicator | actor/malware tags only when the indicator's own context (±160 chars) names the entity; none for victim domains |
| Actor "exploits" CVE links from roundups | same-sentence co-occurrence; roundups and lists are one huge "sentence" | endpoints within 120 characters, plus an exploitation verb for CVE links |
| "Play"/"Beacon" malware in 5,675 indicators | case-insensitive dictionary match on common English words | ambiguous names must be capitalised and near threat wording (`ambiguous_names` in aliases.yaml) |
| Risk 99 next to maliciousness 50 | article-wide topic bonuses (+20 ransomware, +25 exploited, +10 Microsoft) applied to every indicator | scoring model 0.2: full topic bonus only near the indicator (quarter otherwise); unverified network/file indicators capped at 69 (hunt, not block); citation links, victim domains, file names and clean vendor verdicts count as benign context |
| Scores unexplained; FP risk 0.0 looked like a measured zero | nothing stored the arithmetic | contributors stored in `enrichment.risk_breakdown`; observable page shows "How this score was built"; unevaluated FP risk reads "not assessed" |
| URL text vouched for itself | `/warlock-ransomware-exploit` in a URL matched topic and malicious cues | the indicator's own whitespace-delimited token is blanked before context checks |

**Results on the project database:** urgent/block indicators 1,033 to 38 (mostly KEV CVEs and malware hashes), Cl0p-tagged 69 to 2, Play-tagged 5,675 to 0, relationships 9,462 to 955 (the remaining ones name the malware on the same line as the indicator).

### 4.10 Reprocessing destroyed analyst work (found while building `scry reprocess`)
- **Symptom 1:** the first full reprocess "retracted" 7,792 indicators.
- **Root cause:** per-article cleanup deleted every observable mention, including 16,041 `manual_import` mentions written by the workbook importer (aliases, addresses, people). This also affected `scry extract` and the full-page refetch path.
- **Fix:** mentions with `extraction_method` in `PRESERVED_MENTION_METHODS` are never deleted. Rerun retracted exactly one false positive (`Microsoft.NET`).
- **Symptom 2:** the open review queue jumped from 143 to 368.
- **Root cause:** claims are recreated with new ids, so 225 already-closed reviews reopened.
- **Fix:** a closed review with the same article and evidence text carries its disposition to the new claim; the audit trail is repointed.
- **Symptom 3:** `too many SQL variables` on 37,000 ids. **Fix:** chunked `IN` queries (500).
- **Lesson:** run bulk rebuilds on a copy first and diff the counts that should not change (closed reviews, imported mentions).

### 4.11 "1,533 new KEV entries" in the daily report
- **Root cause:** `kev_added_at` was never stored; the report used the row's update time, which every KEV refresh touches.
- **Fix:** KEV ingestion stores CISA's `dateAdded`; briefs count by it.

### 4.12 Rate-limited feeds failed every cycle
- **Fix:** a feed answering 429/503 is paused 1 h, doubling per consecutive throttle up to 24 h (`throttled_until`); the full-page batch stops calling a host after it throttles. Briefs summarise problems per source with pause times instead of dumping raw errors.

### 4.13 Weak daily report
- Rewritten as "Scry Daily/Weekly Threat Brief": what changed, why it matters, recommended actions; KEV additions by date; ransomware posts; watchlist matches; block-level indicators with reasons; review queue with readable claim text. Stories de-duplicated (title normalisation plus cross-outlet title-overlap merge), ranked by decision relevance; feed index pages, sensor/pulse dumps and local imports excluded from "stories".

### 4.14 Phones zoomed every page out
- **Symptom:** on a 375 px iPhone, 13 of 18 pages laid out at 529 to 1,424 px, so the browser zoomed out to unreadable text; header 192 px tall.
- **Root causes and fixes:** tables widened the layout (now wrapped in `.table-scroll`, multi-column tables get a 640 px minimum and scroll in their box); inline `repeat(5|6,1fr)` grids (now `.grid.cols-5/6`, responsive); `code { word-break: break-all }` (now break only on overflow, short IDs `code.nb` never split); dropdowns opened on `:hover/:focus-within` only, and iOS Safari never focuses a tapped button (now click-toggled with `aria-expanded`, hover only under `@media (hover: hover)`); 13 px inputs triggered iOS focus-zoom (16 px on coarse pointers); header wrapped (collapsible menu up to 1,024 px, covering iPad and Galaxy Tab).
- **Also:** `format-detection` stops IPs/hashes becoming phone links; IOC search boxes disable autocapitalise/autocorrect; OTP and password-manager autocomplete hints; safe-area insets; manifest + Apple/Android icons (rendered with Pillow from the SVG logo); gzip (list pages ~60 KB to ~11 KB).
- **Verified:** browser emulation at 280 (folded Fold), 360 (Galaxy), 375 (iPhone), 844x390 (landscape), 820 (iPad), 1366 (desktop). Not yet checked on physical devices.

### 4.15 Embedded Orbistrace page is blank
- `/ui/orbistrace` frames the owner's Orbistrace site full-height under the Scry bar (sandboxed: clicks stay in the frame; deep links via `?path=`; `CTI_ORBISTRACE_URL`).
- **Root cause of blank page:** the Orbistrace server sends `X-Frame-Options: SAMEORIGIN` and `frame-ancestors 'self'`. The Orbistrace server must add the Scry origin to `frame-ancestors` and drop the `X-Frame-Options` header (see `docs/configuration.md`, "Embedding Orbistrace").

### 4.16 Assistant tooling lessons (useful for any agent on this machine)
- System `python3` and (until the Xcode licence was accepted) `git` were Xcode stubs; always use `.venv/bin/python`.
- `grep` is aliased to ugrep, which rejects some regexes on UTF-8; use `/usr/bin/grep`.
- zsh aborts a `&&` chain when a glob matches nothing (`rm -f x*`); BSD `sed -i` needs `''`.
- To render UI pages that require login against real data, copy the DB, delete users in the copy, and run with `CTI_OPEN_ACCESS=true`; never touch the live DB's accounts.
- Browser-automation output limits: keep JSON dumps under ~1,400 characters per call and read in chunks; synthetic scroll does not trigger lazy rendering.

---

## 5. Operating procedures

**Back up the live database**
```bash
sqlite3 cti.sqlite ".backup /path/outside/sync/cti-backup-$(date +%F).sqlite"
sqlite3 /path/outside/sync/cti-backup-*.sqlite "pragma integrity_check;"
```

**Rebuild after an extractor/scoring upgrade**
```bash
scry backup
scry reprocess --dry-run --all
scry reprocess --all        # keeps imported mentions and analyst decisions
```

**Import a ransomware tracker export (file import only, nothing fetched)**
```bash
scry ingest ransomware-feed export.json --source NAME --dry-run
scry ingest ransomware-feed export.json --source NAME
```

**Release:** see 4.7.

**Refresh the deployed copy:** re-copy this repository's folder into the website project, re-apply its copy-only patch, deploy code only, back up its DB, then run `scry reprocess --all` there if the scoring model changed.

---

## 6. Open items at hand-over (16 October 2026)

- Owner: delete the leftover Feedly bearer-token entries from the local Claude settings file and revoke that token; revoke any GitHub tokens created during the thread.
- Orbistrace server: allow the Scry origin in `frame-ancestors` (4.15).
- Check the mobile layout on a physical iPhone and Samsung phone.
- 64 legacy observables have no article mention, so `scry reprocess` does not rescore them (one link is still at block level).
- The Python venv interpreter is a symlink into a third-party app bundle; recreate the venv from a standalone Python if that app is removed.
- The live SQLite database sits in a cloud-synced folder; moving it outside sync avoids conflicted copies.
- Roadmap items in `HANDOFF.md` section 7 remain open (pgvector, rule generation, real connectors).
