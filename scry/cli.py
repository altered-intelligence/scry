"""scry CLI.

Commands:
  init-db                  Run migrations / create schema and load sources.yaml
  ingest-url <url>         Fetch + process a single article
  ingest-source <name>     Fetch + process a single configured source
  ingest-all               Fetch + process all enabled sources
  extract <article_id>     Re-run extraction on an existing article
  enrich <observable_id>   Re-run enrichment on an existing observable
  search <query>           Full-text search
  semantic-search <query>  Semantic search (articles)
  report daily             Print the daily report
  report weekly            Print the weekly report
  reporting brief          AI-synthesized executive briefing (--scope daily|weekly)
  sources list             List sources
  sources test             Run policy checks for each enabled source
  reviews list             List open analyst reviews
  alerts list              List recent alerts
  decay run                Apply IOC decay
  stats                    Show DB counts
  users create             Create a user account
  users list               List user accounts
  users promote|demote     Grant/revoke the admin role
  users reset-password     Reset a user's password (forces change + logout)
  users disable|enable     Disable/enable a user account
  users seed               Seed alakhani+admin (--yes; CTI_ADMIN_INITIAL_PASSWORD)
  feeds migrate-env-keys   Copy env VT/OTX keys into user profiles (--users a,b)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select

from scry.ai.errors import AskError
from scry.auth.passwords import hash_password
from scry.db import get_engine, session_scope
from scry.enrichment import EnrichmentEngine
from scry.ingestion import IngestionEngine
from scry.ingestion.source_registry import SourceRegistry
from scry.logging import configure_logging
from scry.models import (
    CVE,
    Alert,
    AnalystReview,
    Article,
    Base,
    Observable,
    Source,
    User,
)
from scry.pipeline import CTIPipeline
from scry.reporting import generate_brief, generate_daily_report, generate_weekly_report
from scry.scoring.lifecycle import LifecycleEngine
from scry.search import full_text_search, semantic_search

app = typer.Typer(no_args_is_help=True, add_completion=False, rich_markup_mode="markdown")
console = Console()


@app.command("init-db")
def init_db() -> None:
    """Create schema and load sources.yaml into the DB."""
    configure_logging()
    Base.metadata.create_all(bind=get_engine())
    from scry.migrations import run_migrations

    run_migrations()
    with session_scope() as session:
        SourceRegistry(session).sync_from_yaml()
    console.print("[green]DB initialized and sources synced[/green]")


@app.command("ingest-url")
def ingest_url(url: str, source_name: str | None = typer.Option(None, "--source")) -> None:
    """Fetch + process a single URL."""

    async def _run():
        with session_scope() as session:
            src = SourceRegistry(session).get(source_name) if source_name else None
            engine = IngestionEngine(session)
            article = await engine.ingest_url(url, source_id=src.id if src else None)
            if article is None:
                console.print("[yellow]Ingestion blocked by policy or duplicate URL[/yellow]")
                return
            CTIPipeline(session).process_article(article)
            console.print(f"[green]Ingested + processed article #{article.id}[/green]")

    asyncio.run(_run())


@app.command("ingest-source")
def ingest_source(name: str) -> None:
    """Fetch + process a single source by name."""

    async def _run():
        with session_scope() as session:
            src = SourceRegistry(session).get(name)
            if not src:
                console.print(f"[red]No source named {name!r}[/red]")
                raise typer.Exit(1)
            engine = IngestionEngine(session)
            res = await engine.ingest_source(src)
            pipeline = CTIPipeline(session)
            for art in session.scalars(
                select(Article).where(Article.source_id == src.id, Article.extractor_version == "0")
            ):
                pipeline.process_article(art)
            console.print_json(json.dumps(res))

    asyncio.run(_run())


@app.command("ingest-all")
def ingest_all() -> None:
    """Fetch + process every enabled source."""

    async def _run():
        with session_scope() as session:
            engine = IngestionEngine(session)
            res = await engine.ingest_all()
            pipeline = CTIPipeline(session)
            for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
                pipeline.process_article(art)
            console.print_json(json.dumps(res))

    asyncio.run(_run())


@app.command("extract")
def extract(article_id: int) -> None:
    """Re-run extraction on an article."""
    with session_scope() as session:
        art = session.get(Article, article_id)
        if not art:
            console.print(f"[red]No article {article_id}[/red]")
            raise typer.Exit(1)
        art.extractor_version = "0"
        CTIPipeline(session).process_article(art)
        console.print("[green]Done[/green]")


@app.command("enrich")
def enrich(observable_id: int) -> None:
    with session_scope() as session:
        ob = session.get(Observable, observable_id)
        if not ob:
            console.print("[red]Not found[/red]")
            raise typer.Exit(1)
        res = EnrichmentEngine(session).enrich_observable(ob)
        console.print_json(json.dumps(res.fields, default=str))


@app.command("search")
def cli_search(query: str, limit: int = 20) -> None:
    with session_scope() as session:
        hits = full_text_search(session, query, limit=limit)
        table = Table("type", "title", "snippet")
        for h in hits:
            table.add_row(h.object_type, str(h.title or ""), h.snippet[:100])
        console.print(table)


@app.command("semantic-search")
def cli_sem(query: str, limit: int = 20) -> None:
    with session_scope() as session:
        hits = semantic_search(session, query, target="articles", limit=limit)
        table = Table("score", "type", "title")
        for h in hits:
            table.add_row(f"{h.score:.3f}", h.object_type, str(h.title or ""))
        console.print(table)


# Default AI-Search model: Qwen2.5-1.5B-Instruct Q4_K_M (~1.0 GB, ~2 GB RAM at
# runtime — safe on 8 GB machines). Larger alternative: Llama-3.2-3B-Instruct
# Q4_K_M (~2 GB) — download its GGUF and point CTI_AI_SEARCH_MODEL_PATH at it.
AI_SETUP_MODEL_URL = (
    "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/" "qwen2.5-1.5b-instruct-q4_k_m.gguf"
)
AI_SETUP_MODEL_BYTES = 1_117_320_736  # expected size of the default GGUF


@app.command("ai-setup")
def ai_setup() -> None:
    """Download the local AI-Search model (GGUF, ~1 GB) with resume support."""
    from pathlib import Path

    import httpx
    from rich.progress import BarColumn, DownloadColumn, Progress, TransferSpeedColumn

    from scry.config import get_settings

    dest = Path(get_settings().ai_search_model_path).expanduser()
    if dest.is_file() and dest.stat().st_size == AI_SETUP_MODEL_BYTES:
        console.print(f"[green]Model already present at {dest} ({AI_SETUP_MODEL_BYTES:,} bytes)[/green]")
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    downloaded = dest.stat().st_size if dest.is_file() else 0
    headers = {"Range": f"bytes={downloaded}-"} if downloaded else {}
    if downloaded:
        console.print(f"[yellow]Resuming from {downloaded:,} bytes[/yellow]")

    console.print(f"Downloading {AI_SETUP_MODEL_URL}\n  → {dest}")
    try:
        with (
            httpx.stream(
                "GET",
                AI_SETUP_MODEL_URL,
                headers=headers,
                follow_redirects=True,
                timeout=httpx.Timeout(60.0, read=300.0),
            ) as r,
            Progress(
                "[progress.description]{task.description}",
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                console=console,
            ) as progress,
        ):
            r.raise_for_status()
            task = progress.add_task("model", total=None)
            mode = "ab" if downloaded else "wb"
            with dest.open(mode) as f:
                for chunk in r.iter_bytes(chunk_size=1024 * 1024):
                    f.write(chunk)
                    progress.advance(task, len(chunk))
    except httpx.HTTPError as e:
        console.print(f"[red]Download failed: {e}[/red]")
        raise typer.Exit(1) from None

    size = dest.stat().st_size
    if size != AI_SETUP_MODEL_BYTES:
        console.print(
            f"[yellow]Warning: size {size:,} ≠ expected {AI_SETUP_MODEL_BYTES:,} — "
            "re-run `scry ai-setup` to resume.[/yellow]"
        )
        raise typer.Exit(1)
    console.print(f"[green]Model ready at {dest} ({size:,} bytes)[/green]")
    console.print("Enable AI Search with [bold]CTI_ENABLE_AI_SEARCH=true[/bold] and restart Scry.")


report_app = typer.Typer(help="Reports")
app.add_typer(report_app, name="report")


@report_app.command("daily")
def report_daily(since_hours: int = 24) -> None:
    with session_scope() as session:
        sys.stdout.write(generate_daily_report(session, since_hours=since_hours))


@report_app.command("weekly")
def report_weekly() -> None:
    with session_scope() as session:
        sys.stdout.write(generate_weekly_report(session))


reporting_app = typer.Typer(help="AI-synthesized reporting")
app.add_typer(reporting_app, name="reporting")


@reporting_app.command("brief")
def reporting_brief(scope: str = typer.Option("daily", "--scope")) -> None:
    """Synthesize an executive briefing from the daily/weekly report via the active LLM."""

    if scope not in ("daily", "weekly"):
        console.print("[red]--scope must be 'daily' or 'weekly'[/red]")
        raise typer.Exit(2)

    async def _run():
        with session_scope() as session:
            return await generate_brief(session, scope)

    try:
        result = asyncio.run(_run())
    except AskError as exc:
        console.print(f"[red]{exc.detail}[/red]")
        raise typer.Exit(1) from None
    note = " · cached" if result["cached"] else ""
    console.print(f"[dim]{result['model']} · {result['elapsed_ms']} ms{note}[/dim]")
    sys.stdout.write(result["brief"] + "\n")


sources_app = typer.Typer(help="Source management")
app.add_typer(sources_app, name="sources")


@sources_app.command("list")
def sources_list() -> None:
    with session_scope() as session:
        table = Table("id", "name", "type", "enabled", "policy", "tags")
        for s in session.scalars(select(Source).order_by(Source.name)):
            table.add_row(
                str(s.id), s.name, s.type, str(s.enabled), s.collection_policy, ",".join(s.tags or [])
            )
        console.print(table)


@sources_app.command("test")
def sources_test() -> None:
    """Run policy + SSRF check for each enabled source. No fetching."""
    from scry.ingestion import CollectionPolicyEngine
    from scry.ingestion.ssrf import evaluate_url

    engine = CollectionPolicyEngine()
    with session_scope() as session:
        table = Table("source", "policy", "allowed", "ssrf", "reason")
        for s in session.scalars(select(Source).where(Source.enabled.is_(True))):
            dec = engine.evaluate(
                policy_name=s.collection_policy, source_enabled=s.enabled, source_safety_mode=s.safety_mode
            )
            url = s.feed or s.url or ""
            ssrf = evaluate_url(url) if url else None
            table.add_row(
                s.name, s.collection_policy, str(dec.allowed), str(ssrf.allowed if ssrf else "-"), dec.reason
            )
        console.print(table)


reviews_app = typer.Typer(help="Analyst review queue")
app.add_typer(reviews_app, name="reviews")


@reviews_app.command("list")
def reviews_list() -> None:
    with session_scope() as session:
        table = Table("id", "item", "reason", "confidence", "action")
        for r in session.scalars(select(AnalystReview).where(AnalystReview.status == "open").limit(100)):
            table.add_row(
                str(r.id), f"{r.item_type}#{r.item_id}", r.reason, str(r.confidence), r.recommended_action
            )
        console.print(table)


alerts_app = typer.Typer(help="Alerts")
app.add_typer(alerts_app, name="alerts")


@alerts_app.command("list")
def alerts_list() -> None:
    with session_scope() as session:
        table = Table("id", "trigger", "severity", "title")
        for a in session.scalars(select(Alert).order_by(Alert.id.desc()).limit(100)):
            table.add_row(str(a.id), a.trigger, a.severity, a.title[:120])
        console.print(table)


decay_app = typer.Typer(help="IOC decay")
app.add_typer(decay_app, name="decay")


@decay_app.command("run")
def decay_run() -> None:
    with session_scope() as session:
        res = LifecycleEngine(session).apply_decay()
        console.print({"expired": res.expired, "refreshed": res.refreshed})


@app.command("stats")
def stats() -> None:
    with session_scope() as session:
        out = {
            "sources": session.scalar(select(func.count(Source.id))),
            "articles": session.scalar(select(func.count(Article.id))),
            "observables": session.scalar(select(func.count(Observable.id))),
            "cves": session.scalar(select(func.count(CVE.id))),
            "alerts": session.scalar(select(func.count(Alert.id))),
            "open_reviews": session.scalar(
                select(func.count(AnalystReview.id)).where(AnalystReview.status == "open")
            ),
        }
        console.print_json(json.dumps(out))


@app.command("mcp")
def mcp_command() -> None:
    """Run the MCP server (stdio) for AI clients like Claude Desktop / Cursor.

    Requires the `mcp` extra: pip install scry[mcp]
    """
    try:
        from scry.mcp_server import main as mcp_main
    except ImportError as exc:  # pragma: no cover
        console.print("[red]The 'mcp' package is not installed. Run: pip install scry[mcp][/red]")
        raise typer.Exit(1) from exc
    mcp_main()


# ------------------------- users (v0.5.0 step 1) -------------------------

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SEED_INITIAL_PASSWORD_ENV = "CTI_ADMIN_INITIAL_PASSWORD"
SEED_INITIAL_PASSWORD_DEFAULT = "Batman911!#"


def _audit_user(session, action: str, user: User, detail: dict | None = None) -> None:
    from scry.audit import record

    record(
        session,
        action=action,
        actor="cli",
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, **(detail or {})},
    )


def _find_user(session, username: str) -> User | None:
    return session.scalar(select(User).where(func.lower(User.username) == username.lower()))


def _require_user(session, username: str) -> User:
    user = _find_user(session, username)
    if user is None:
        console.print(f"[red]No user named {username!r}[/red]")
        raise typer.Exit(1)
    return user


def _validate_email(email: str) -> str:
    email = email.strip()
    if not _EMAIL_RE.match(email):
        console.print(f"[red]Invalid email address: {email!r}[/red]")
        raise typer.Exit(2)
    return email


def _prompt_password() -> str:
    return typer.prompt("Password", hide_input=True, confirmation_prompt=True)


users_app = typer.Typer(help="User account management (v0.5.0)")
app.add_typer(users_app, name="users")


@users_app.command("create")
def users_create(
    username: str,
    email: str = typer.Option(..., "--email", "-e", help="Required — email is mandatory for all users"),
    password: str | None = typer.Option(None, "--password", "-p", help="Prompted when omitted"),
    role: str = typer.Option("user", "--role", help="user | admin"),
    admin: bool = typer.Option(False, "--admin", help="Shortcut for --role admin"),
) -> None:
    """Create a user account."""
    if admin:
        role = "admin"
    if role not in ("user", "admin"):
        console.print("[red]--role must be 'user' or 'admin'[/red]")
        raise typer.Exit(2)
    email = _validate_email(email)
    if password is None:
        password = _prompt_password()
    with session_scope() as session:
        if _find_user(session, username) is not None:
            console.print(f"[red]Username {username!r} already exists[/red]")
            raise typer.Exit(1)
        user = User(username=username, email=email, role=role, password_hash=hash_password(password))
        # Same rule as the /admin create form (v0.5.0 step 3): no mailer →
        # email trusted outright; SMTP up → unverified until the PIN is used.
        from scry import mail as _mail
        from scry.auth import verification as _verification

        user.email_verified = not _mail.smtp_configured(session)
        session.add(user)
        session.flush()
        _audit_user(session, "user.create", user, {"role": role})
        if _mail.smtp_configured(session):
            if _verification.issue_pin(session, user):
                console.print(f"[green]Verification code sent to {email}[/green]")
            else:
                console.print("[yellow]Could not send the verification email[/yellow]")
        else:
            console.print("[dim]SMTP not configured — email marked verified[/dim]")
    console.print(f"[green]Created user {username!r} ({role})[/green]")


@users_app.command("list")
def users_list() -> None:
    """List user accounts."""
    with session_scope() as session:
        table = Table("id", "username", "email", "role", "status", "last_login")
        for u in session.scalars(select(User).order_by(User.id)):
            last = u.last_login_at.strftime("%Y-%m-%d %H:%M") if u.last_login_at else "—"
            table.add_row(str(u.id), u.username, u.email, u.role, u.status, last)
        console.print(table)


def _set_role(username: str, role: str) -> None:
    with session_scope() as session:
        user = _require_user(session, username)
        user.role = role
        session.flush()
        _audit_user(session, f"user.{role}", user)
    console.print(f"[green]{username!r} is now {role}[/green]")


@users_app.command("promote")
def users_promote(username: str) -> None:
    """Grant the admin role."""
    _set_role(username, "admin")


@users_app.command("demote")
def users_demote(username: str) -> None:
    """Revoke the admin role (back to user)."""
    _set_role(username, "user")


@users_app.command("reset-password")
def users_reset_password(
    username: str,
    password: str | None = typer.Option(None, "--password", "-p", help="Prompted when omitted"),
) -> None:
    """Reset a user's password; forces a change at next login and logs them out."""
    if password is None:
        password = _prompt_password()
    from scry.auth.sessions import revoke_all_sessions

    with session_scope() as session:
        user = _require_user(session, username)
        user.password_hash = hash_password(password)
        user.must_change_password = True
        user.failed_login_count = 0
        user.locked_until = None
        revoked = revoke_all_sessions(session, user.id)
        session.flush()
        _audit_user(session, "user.reset_password", user, {"revoked_sessions": revoked})
    console.print(f"[green]Password reset for {username!r} ({revoked} session(s) revoked)[/green]")


@users_app.command("disable")
def users_disable(username: str) -> None:
    """Disable a user account (blocks login and invalidates sessions)."""
    from scry.auth.sessions import revoke_all_sessions

    with session_scope() as session:
        user = _require_user(session, username)
        user.status = "disabled"
        revoked = revoke_all_sessions(session, user.id)
        session.flush()
        _audit_user(session, "user.disable", user, {"revoked_sessions": revoked})
    console.print(f"[green]Disabled {username!r}[/green]")


@users_app.command("enable")
def users_enable(username: str) -> None:
    """Re-enable a disabled user account."""
    with session_scope() as session:
        user = _require_user(session, username)
        user.status = "active"
        session.flush()
        _audit_user(session, "user.enable", user)
    console.print(f"[green]Enabled {username!r}[/green]")


@users_app.command("seed")
def users_seed(
    yes: bool = typer.Option(False, "--yes", help="Confirm creation of the seeded admin accounts"),
) -> None:
    """Seed the standard admin accounts (alakhani + admin).

    Reads the initial password from $CTI_ADMIN_INITIAL_PASSWORD
    (default "Batman911!#"); both accounts are created with
    must_change_password=true. Existing usernames are skipped.
    """
    if not yes:
        console.print("[yellow]This creates admin accounts. Re-run with --yes to confirm.[/yellow]")
        raise typer.Exit(2)
    password = os.environ.get(SEED_INITIAL_PASSWORD_ENV, SEED_INITIAL_PASSWORD_DEFAULT)
    seeded: list[str] = []
    with session_scope() as session:
        from scry import mail as _mail

        for username, email in (("alakhani", "alakhani@example.com"), ("admin", "admin@example.com")):
            if _find_user(session, username) is not None:
                continue
            user = User(
                username=username,
                email=email,
                role="admin",
                password_hash=hash_password(password),
                must_change_password=True,
                # No mailer → nothing can verify the address; trust it (locked
                # bypass). With SMTP up the admin verifies via PIN later.
                email_verified=not _mail.smtp_configured(session),
            )
            session.add(user)
            session.flush()
            _audit_user(session, "user.seed", user)
            seeded.append(username)
    if seeded:
        source = f"${SEED_INITIAL_PASSWORD_ENV}" if SEED_INITIAL_PASSWORD_ENV in os.environ else "default"
        console.print(f"[green]Seeded admin accounts: {', '.join(seeded)}[/green]")
        console.print(f"[dim]Initial password from {source}; must be changed at first login.[/dim]")
    else:
        console.print("[yellow]Seed usernames already exist — nothing to do.[/yellow]")


# ------------------------- feeds (v0.5.0 step 6) -------------------------


feeds_app = typer.Typer(help="Per-user threat-feed API keys")
app.add_typer(feeds_app, name="feeds")


@feeds_app.command("migrate-env-keys")
def feeds_migrate_env_keys(
    users: str = typer.Option(..., "--users", help="Comma-separated usernames to receive the keys"),
) -> None:
    """Store CTI_VIRUSTOTAL_API_KEY / CTI_OTX_API_KEY as personal feed keys.

    Deployment-time helper: copies the env/.env system keys into the named
    users' profiles (encrypted, one row per user+provider). Skips users that
    already have a personal key for a provider, unknown usernames, and
    providers with an empty env key. Never prints key material.
    """
    from scry.config import get_settings
    from scry.enrichment.user_keys import get_key, set_key

    env_keys = {
        "virustotal": get_settings().virustotal_api_key,
        "otx": get_settings().otx_api_key,
    }
    usernames = [u.strip() for u in users.split(",") if u.strip()]
    migrated: list[str] = []
    skipped_existing: list[str] = []
    skipped_no_env: list[str] = []
    unknown_users: list[str] = []
    with session_scope() as session:
        for username in usernames:
            user = session.scalar(select(User).where(func.lower(User.username) == username.lower()))
            if user is None:
                unknown_users.append(username)
                continue
            for provider, env_key in env_keys.items():
                label = f"{username}:{provider}"
                if not env_key:
                    skipped_no_env.append(label)
                    continue
                if get_key(session, user.id, provider) is not None:
                    skipped_existing.append(label)
                    continue
                set_key(session, user.id, provider, env_key)
                migrated.append(label)

    table = Table("user:provider", "action")
    for label in migrated:
        table.add_row(label, "[green]migrated[/green]")
    for label in skipped_existing:
        table.add_row(label, "[yellow]skipped — personal key already set[/yellow]")
    for label in skipped_no_env:
        table.add_row(label, "[yellow]skipped — env key empty[/yellow]")
    for label in unknown_users:
        table.add_row(label, "[red]skipped — no such user[/red]")
    console.print(table)
    console.print(
        f"[dim]Summary: {len(migrated)} migrated, {len(skipped_existing)} already had keys, "
        f"{len(skipped_no_env)} no env key, {len(unknown_users)} unknown users.[/dim]"
    )


def main() -> None:  # entry point
    app()


if __name__ == "__main__":
    main()