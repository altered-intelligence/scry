"""FastAPI application entrypoint."""

from __future__ import annotations

import contextlib
import hmac
import json
import re
import secrets
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from scry.api import api_router
from scry.api.ai import ai_router
from scry.api.auth import require_api_key
from scry.api.chat import chat_router
from scry.api.deps import get_session
from scry.api.router import compute_stats
from scry.api.taxii import taxii_router
from scry.auth.dependencies import current_user, path_requires_ui_auth
from scry.auth.passwords import hash_password, verify_password
from scry.auth.sessions import (
    SESSION_COOKIE,
    SESSION_TTL,
    create_session,
    hash_token,
    lockout_remaining,
    record_login_failure,
    record_login_success,
    revoke_all_sessions,
    revoke_session,
    users_exist,
)
from scry.config import get_settings
from scry.crypto import decrypt, encrypt, mask
from scry.db import get_engine, session_scope, tag_filter
from scry.enrichment.engine import (
    _EXTERNAL_PROVIDERS,
    EnrichmentEngine,
    _is_stale,
    _is_valid_for_external,
    _marker_age_seconds,
    _provider_refresh_ttls,
)
from scry.enrichment.otx import OTXEnricher
from scry.enrichment.user_keys import (
    delete_key,
    get_decrypted_key,
    get_key,
    keys_for_user,
    record_test_result,
    set_key,
    test_key,
)
from scry.enrichment.virustotal import VirusTotalEnricher
from scry.ingestion.otx_pulses import last_run_stats, load_subscriptions, pull_all, resolve_key
from scry.logging import configure_logging, get_logger
from scry.models import (
    CVE,
    Alert,
    AnalystReview,
    ApiKey,
    Article,
    AuditLog,
    Base,
    Claim,
    EmailVerification,
    Entity,
    EntityMention,
    Observable,
    ObservableMention,
    PasskeyCredential,
    RansomwareFeedItem,
    RecoveryCode,
    Relationship,
    SessionToken,
    Source,
    SourceFetch,
    SystemSetting,
    ThreatFeedItem,
    User,
)

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "ui" / "templates"
STATIC_DIR = _HERE / "ui" / "static"

configure_logging()
_log = get_logger("startup")


def _ensure_db_ready() -> None:
    Base.metadata.create_all(bind=get_engine())
    # Column additions to EXISTING tables (create_all can't do those).
    from scry.migrations import run_migrations

    run_migrations()
    try:
        from scry.ingestion.source_registry import SourceRegistry

        with session_scope() as session:
            res = SourceRegistry(session).sync_from_yaml()
        _log.info("startup_sources_synced", **res)
    except Exception as exc:
        _log.warning("startup_source_sync_failed", exc=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    _ensure_db_ready()
    yield


app = FastAPI(
    title="Scry",
    version="0.8.0",
    description="Defensive CTI collection, extraction, enrichment, correlation, search, and reporting.",
    lifespan=lifespan,
)

app.include_router(api_router, dependencies=[Depends(require_api_key)])
app.include_router(ai_router, dependencies=[Depends(require_api_key)])
app.include_router(chat_router, dependencies=[Depends(require_api_key)])
# Read-only TAXII 2.1 server — authenticated like the rest of the API when a
# key is configured (no discovery exemption).
app.include_router(taxii_router, dependencies=[Depends(require_api_key)])

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["format_number"] = lambda v: f"{int(v):,}" if v is not None else "0"


def _timeago(value) -> Markup | str:
    """Render a datetime as a relative-time <time> element ("3h ago").

    Timezone-naive datetimes are assumed UTC. The absolute time is available
    on hover via the title attribute. None renders as an em dash.
    """
    if value is None:
        return Markup('<time class="muted">—</time>')
    if not isinstance(value, datetime):
        return escape(str(value))
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    secs = max(0, int((datetime.now(UTC) - value).total_seconds()))
    if secs < 60:
        label = "just now"
    elif secs < 3600:
        label = f"{secs // 60}m ago"
    elif secs < 86400:
        label = f"{secs // 3600}h ago"
    else:
        label = f"{secs // 86400}d ago"
    iso = value.isoformat()
    absolute = value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return Markup(f'<time datetime="{iso}" title="{absolute}">{label}</time>')


templates.env.filters["timeago"] = _timeago


def _redirect_flash(url: str, message: str, kind: str = "success") -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(
        url=f"{url}{sep}{urlencode({'flash': message, 'flash_kind': kind})}", status_code=303
    )


# ------------------------- auth (v0.5.0 step 1) -------------------------


@app.middleware("http")
async def ui_auth_middleware(request: Request, call_next):
    """Gate browser UI behind a session once any user account exists.

    Legacy behavior is preserved exactly: zero users → everything stays open
    (the MCP server and local automations depend on this). Gated paths: the
    dashboard (``/``), ``/ui/*``, and the future ``/admin`` prefix. ``/login``
    and ``/static`` are not under these prefixes, so they stay reachable.
    """
    if not path_requires_ui_auth(request.url.path):
        return await call_next(request)

    from scry.db import session_scope

    with session_scope() as session:
        has_users = users_exist(session)
    request.state.auth_required = has_users
    user = current_user(request) if has_users else None
    request.state.user = user
    if has_users and user is None:
        return RedirectResponse(url="/login", status_code=303)
    if user is not None and user.must_change_password and not _password_change_exempt(request.url.path):
        # Forced password change (first login / admin reset): everything
        # except the profile routes themselves, login/logout, and static
        # assets redirects back to /profile with the banner.
        return _redirect_flash("/profile", "You must change your password before continuing.", "error")
    return await call_next(request)


def _password_change_exempt(path: str) -> bool:
    return path.startswith(("/profile", "/login", "/logout", "/static"))


def _safe_next(next_url: str | None) -> str:
    """Only allow same-site relative redirects after login."""
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


def _login_redirect(message: str, next_url: str | None = None) -> RedirectResponse:
    params = {"error": message}
    if next_url:
        params["next"] = next_url
    return RedirectResponse(url=f"/login?{urlencode(params)}", status_code=303)


def _audit_login(session: Session, username: str, success: bool, detail: dict | None = None) -> None:
    from scry.audit import record

    record(
        session,
        action="login.success" if success else "login.failure",
        actor=username,
        target_type="user",
        detail=detail or {},
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    with session_scope() as session:
        has_users = users_exist(session)
    if has_users and current_user(request) is not None:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "has_users": has_users,
            "error": request.query_params.get("error"),
            "next": request.query_params.get("next"),
        },
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str | None = Form(None),
):
    with session_scope() as session:
        if not users_exist(session):
            return RedirectResponse(url="/login", status_code=303)

        user = session.scalar(select(User).where(func.lower(User.username) == username.lower()))
        generic_error = "Invalid username or password."
        if user is None:
            _audit_login(session, username, success=False)
            return _login_redirect(generic_error, next)

        remaining = lockout_remaining(user)
        if remaining is not None:
            minutes = max(1, int(remaining.total_seconds() // 60) + (1 if remaining.seconds % 60 else 0))
            _audit_login(session, username, success=False, detail={"reason": "locked"})
            return _login_redirect(f"Account locked. Try again in {minutes} minutes.", next)

        if user.status != "active":
            _audit_login(session, username, success=False, detail={"reason": "disabled"})
            return _login_redirect("This account is disabled.", next)

        if not verify_password(password, user.password_hash):
            record_login_failure(session, user)
            session.flush()
            remaining = lockout_remaining(user)
            _audit_login(session, username, success=False)
            if remaining is not None:
                return _login_redirect(
                    f"Too many failed attempts. Account locked for {int(remaining.total_seconds() // 60)} minutes.",
                    next,
                )
            return _login_redirect(generic_error, next)

        record_login_success(session, user)
        from scry.auth import totp as _totp

        if user.totp_enabled:
            # MFA required: do NOT create a session yet. Hand the browser a
            # short-lived signed pending marker (Fernet-encrypted {uid, exp}
            # cookie, no DB table); the challenge at /login/mfa completes the
            # login with a TOTP or recovery code.
            pending = _totp.issue_pending_marker(user.id)
            _audit_login(session, username, success=True, detail={"mfa": "pending"})
            session.commit()
            params = f"?{urlencode({'next': next})}" if next else ""
            response = RedirectResponse(url=f"/login/mfa{params}", status_code=303)
            response.set_cookie(
                _totp.MFA_PENDING_COOKIE,
                pending,
                max_age=int(_totp.MFA_PENDING_TTL.total_seconds()),
                httponly=True,
                samesite="lax",
                path="/",
            )
            return response

        raw_token = create_session(
            session,
            user,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        _audit_login(session, username, success=True)
        session.commit()

    response = RedirectResponse(url=_safe_next(next), status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/logout")
def logout(request: Request):
    with session_scope() as session:
        revoke_session(session, request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ------------------------- first-run setup (v0.7.1) -------------------------

# CSRF for the setup form: there is no session cookie yet, so the
# admin-form CSRF scheme (derived from the session cookie) cannot apply.
# Instead GET /setup issues a random token — its sha256 goes into a
# short-lived HttpOnly cookie, the raw token into a hidden form field —
# and POST /setup requires both to match (double-submit pattern).
SETUP_CSRF_COOKIE = "scry_setup_csrf"


def _setup_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _check_setup_csrf(request: Request, form_token: str | None) -> bool:
    raw = request.cookies.get(SETUP_CSRF_COOKIE)
    if not raw or not form_token:
        return False
    return hmac.compare_digest(hash_token(form_token), hash_token(raw))


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    """First-run admin creation — only while the users table is empty."""
    with session_scope() as session:
        has_users = users_exist(session)
    if has_users:
        raise HTTPException(404)
    token = _setup_csrf_token()
    response = templates.TemplateResponse(
        request,
        "setup.html",
        {
            "has_users": False,
            "error": request.query_params.get("error"),
            "csrf": token,
        },
    )
    response.set_cookie(
        SETUP_CSRF_COOKIE,
        token,
        max_age=600,
        httponly=True,
        samesite="lax",
        path="/setup",
    )
    return response


@app.post("/setup")
def setup_submit(
    request: Request,
    csrf: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    confirm_password: str = Form(""),
    email: str = Form(""),
):
    with session_scope() as session:
        if users_exist(session):
            # Defense in depth: the page is gone once any account exists.
            # Runs before field validation so a live instance always 404s.
            raise HTTPException(404)
        if not _check_setup_csrf(request, csrf):
            raise HTTPException(403)
        username = username.strip()
        if not username:
            return _setup_redirect("Username is required.")
        if len(password) < 8:
            return _setup_redirect("Password must be at least 8 characters.")
        if password != confirm_password:
            return _setup_redirect("Passwords do not match.")
        from scry import mail as _mail

        user = User(
            username=username,
            email=_validate_email_or_default(email, username),
            role="admin",
            password_hash=hash_password(password),
            must_change_password=False,  # installer just chose this password
            email_verified=not _mail.smtp_configured(session),
        )
        session.add(user)
        session.flush()
        from scry.audit import record

        record(
            session,
            action="user.setup",
            actor=username,
            target_type="user",
            target_id=user.id,
            detail={"role": "admin"},
        )
        # Log the installer straight in.
        raw_token = create_session(
            session,
            user,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        session.commit()

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(SETUP_CSRF_COOKIE, path="/setup")
    return response


def _validate_email_or_default(email: str, username: str) -> str:
    email = (email or "").strip()
    if not email:
        return f"{username}@example.com"
    if not _EMAIL_RE.match(email):
        raise HTTPException(422, "Invalid email address.")
    return email


def _setup_redirect(message: str) -> RedirectResponse:
    return RedirectResponse(url=f"/setup?{urlencode({'error': message})}", status_code=303)


# ------------------------- MFA login challenge (v0.5.0 step 4) -------------------------


def _mfa_redirect(message: str, next_url: str | None = None) -> RedirectResponse:
    params = {"error": message}
    if next_url:
        params["next"] = next_url
    return RedirectResponse(url=f"/login/mfa?{urlencode(params)}", status_code=303)


@app.get("/login/mfa", response_class=HTMLResponse)
def mfa_challenge_page(request: Request):
    from scry.auth import totp as _totp

    if current_user(request) is not None:
        return RedirectResponse(url="/", status_code=303)
    if _totp.read_pending_marker(request.cookies.get(_totp.MFA_PENDING_COOKIE)) is None:
        return _login_redirect("Your sign-in has expired — please log in again.")
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "has_users": True,
            "mfa_pending": True,
            "error": request.query_params.get("error"),
            "next": request.query_params.get("next"),
        },
    )


@app.post("/login/mfa")
def mfa_challenge_submit(
    request: Request,
    code: str = Form(...),
    next: str | None = Form(None),
):
    from scry.auth import totp as _totp

    uid = _totp.read_pending_marker(request.cookies.get(_totp.MFA_PENDING_COOKIE))
    if uid is None:
        return _login_redirect("Your sign-in has expired — please log in again.")

    with session_scope() as session:
        user = session.get(User, uid)
        if user is None or user.status != "active" or not user.totp_enabled:
            return _login_redirect("Please log in again.")

        submitted = (code or "").strip()
        via = None
        secret = decrypt(user.totp_secret_encrypted)
        if secret and _totp.verify_totp(secret, submitted):
            via = "totp"
        elif _totp.use_recovery_code(session, user, submitted):
            via = "recovery"

        if via is None:
            count = _totp.record_mfa_failure(user.id)
            if count >= _totp.MAX_MFA_ATTEMPTS:
                # Too many wrong codes: invalidate the pending marker — the
                # user must log in again from the password step.
                _audit_login(session, user.username, success=False, detail={"reason": "mfa_exhausted"})
                session.commit()
                response = _login_redirect("Too many failed codes — please sign in again.", next)
                response.delete_cookie(_totp.MFA_PENDING_COOKIE, path="/")
                return response
            _audit_login(session, user.username, success=False, detail={"reason": "mfa"})
            session.commit()
            return _mfa_redirect("Invalid authentication code.", next)

        _totp.clear_mfa_failures(user.id)
        raw_token = create_session(
            session,
            user,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        detail = {"via": via}
        if via == "recovery":
            from scry.audit import record

            remaining = session.scalar(
                select(func.count(RecoveryCode.id)).where(
                    RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
                )
            )
            record(
                session,
                action="mfa.recovery_code_use",
                actor=user.username,
                target_type="user",
                target_id=user.id,
                detail={"remaining": remaining},
            )
            detail["remaining_recovery_codes"] = remaining
        _audit_login(session, user.username, success=True, detail=detail)
        session.commit()

    response = RedirectResponse(url=_safe_next(next), status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(_totp.MFA_PENDING_COOKIE, path="/")
    return response


# ------------------------- admin (v0.5.0 step 2) -------------------------

# The app otherwise uses plain POST forms without CSRF tokens (same-site
# "lax" cookies already block cross-site posts). Admin actions additionally
# carry a session-scoped CSRF token: the Fernet-encrypted sha256 of the
# session cookie. It is derived from the HttpOnly cookie server-side, so an
# attacker page cannot read or forge it, and it rotates with the session.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SMTP_KEY_PREFIX = "smtp."


def _admin_csrf_token(raw_session: str) -> str:
    return encrypt(hash_token(raw_session))


def _check_admin_csrf(request: Request, form_token: str | None) -> bool:
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw or not form_token:
        return False
    return hmac.compare_digest(decrypt(form_token), hash_token(raw))


def _admin_or_none(request: Request) -> User | None:
    """The acting admin (middleware already resolved request.state.user)."""
    user = getattr(request.state, "user", None)
    if user is None or user.role != "admin":
        return None
    return user


def _audit_admin(
    session: Session, actor: User, action: str, target: User | None = None, detail: dict | None = None
) -> None:
    from scry.audit import record

    record(
        session,
        action=action,
        actor=actor.username,
        target_type="user" if target is not None else None,
        target_id=target.id if target is not None else None,
        detail={"target": target.username, **(detail or {})} if target is not None else (detail or {}),
    )


def _humanize_checked_age(enrichment: dict, provider: str, now: datetime) -> str:
    """Human-readable age of the ``{provider}_checked_at`` marker (v0.6.0 step 3)."""
    age = _marker_age_seconds(enrichment, provider, now)
    if age is None:
        return "never"
    if age < 90:
        return "just now"
    if age < 3600:
        return f"{int(age // 60)}m ago"
    if age < 86400:
        return f"{int(age // 3600)}h ago"
    return f"{int(age // 86400)}d ago"


def _enrichment_coverage(session: Session) -> dict:
    """Per-provider enrichment coverage + VT daily-quota snapshot (v0.5.0 step 6).

    Counts observables carrying each provider's ``*_checked_at`` marker in the
    shared enrichment JSON, with malicious/benign verdict tallies where
    derivable. The VT daily quota reads the date-stamped snapshot the
    enrichment batch records after every run (in-memory counters reset on
    restart, so a missing/stale snapshot just shows a fresh day).
    """
    providers = ("virustotal", "otx", "abuseipdb", "greynoise")
    coverage = {p: {"checked": 0, "stale": 0, "malicious": 0, "benign": 0} for p in providers}
    # v0.6.0 step 3 — stale = marker missing or older than the provider's
    # refresh TTL, among observables valid for that provider's external check.
    now = datetime.now(UTC)
    ttls = _provider_refresh_ttls()
    for ob in session.scalars(select(Observable)).all():
        enrichment = ob.enrichment or {}
        for name in providers:
            if f"{name}_checked_at" in enrichment:
                coverage[name]["checked"] += 1
            if (
                ob.type in _EXTERNAL_PROVIDERS[name]["types"]
                and _is_valid_for_external(ob.type, ob.normalized_value)
                and _is_stale(enrichment, name, ttls[name], now)
            ):
                coverage[name]["stale"] += 1
        vt = enrichment.get("virustotal") or {}
        if vt and not vt.get("not_found"):
            if (vt.get("malicious") or 0) > 0:
                coverage["virustotal"]["malicious"] += 1
            elif (vt.get("suspicious") or 0) == 0:
                coverage["virustotal"]["benign"] += 1
        otx = enrichment.get("otx") or {}
        if otx and not otx.get("not_found"):
            if (otx.get("pulse_count") or 0) >= 3:
                coverage["otx"]["malicious"] += 1
            else:
                coverage["otx"]["benign"] += 1

    quota_limit = get_settings().vt_daily_quota
    used = 0
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == "enrichment.vt_daily_quota"))
    if row and row.value:
        try:
            snap = json.loads(row.value)
            if snap.get("date") == datetime.now(UTC).date().isoformat():
                used = int(snap.get("used") or 0)
        except (TypeError, ValueError):
            pass
    vt_quota = {"limit": quota_limit, "used": used, "remaining": max(0, quota_limit - used)}
    return {"providers": coverage, "vt_quota": vt_quota}


def _admin_user_counts(session: Session) -> dict[str, int]:
    now = datetime.now(UTC)
    return {
        "users": session.scalar(select(func.count(User.id))) or 0,
        "admins": session.scalar(select(func.count(User.id)).where(User.role == "admin")) or 0,
        "active_sessions": session.scalar(
            select(func.count(SessionToken.id)).where(SessionToken.expires_at > now)
        )
        or 0,
        "active_last_7d": session.scalar(
            select(func.count(User.id)).where(User.last_login_at >= now - timedelta(days=7))
        )
        or 0,
    }


def _last_admin(session: Session, user: User) -> bool:
    """True when ``user`` is the only admin account (protects against lockout)."""
    if user.role != "admin":
        return False
    admins = session.scalar(select(func.count(User.id)).where(User.role == "admin")) or 0
    return admins <= 1


def _smtp_overview(session: Session) -> dict:
    """Effective SMTP config + which fields come from the DB vs the env fallback."""
    from scry.mail import SMTP_KEYS, get_smtp_config

    db_keys = {
        row.key.removeprefix(_SMTP_KEY_PREFIX): row.value
        for row in session.scalars(select(SystemSetting).where(SystemSetting.key.like("smtp.%")))
    }
    config = get_smtp_config(session)
    return {
        "config": config,
        "configured": config is not None,
        "db_fields": {k for k in SMTP_KEYS if db_keys.get(k)},
        "db_password_set": bool(db_keys.get("password")),
    }


def _collection_window_days(session: Session) -> int:
    from scry.ingestion.collection_window import get_window_days

    return get_window_days(session)


def _admin_context(request: Request, session: Session, admin: User) -> dict:
    """Template context shared by GET /admin and the admin POST handlers that
    render the page directly (one-time secrets must NOT ride redirect query
    strings — they would land in access logs and browser history)."""
    users = list(session.scalars(select(User).order_by(User.id)))
    passkey_counts = {
        uid: count
        for uid, count in session.execute(
            select(PasskeyCredential.user_id, func.count(PasskeyCredential.id)).group_by(
                PasskeyCredential.user_id
            )
        )
    }
    now = datetime.now(UTC)
    sessions_rows = list(
        session.execute(
            select(SessionToken, User)
            .join(User, User.id == SessionToken.user_id)
            .where(SessionToken.expires_at > now)
            .order_by(SessionToken.last_seen_at.desc().nullslast(), SessionToken.id.desc())
            .limit(100)
        )
    )
    failed_logins = list(
        session.scalars(
            select(AuditLog).where(AuditLog.action == "login.failure").order_by(AuditLog.id.desc()).limit(50)
        )
    )
    audit_entries = list(session.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(100)))
    return {
        "admin": admin,
        "csrf": _admin_csrf_token(request.cookies[SESSION_COOKIE]),
        "users": users,
        "passkey_counts": passkey_counts,
        "user_counts": _admin_user_counts(session),
        "stats": compute_stats(session),
        "failed_logins": failed_logins,
        "locked_users": [u for u in users if lockout_remaining(u) is not None],
        "sessions": sessions_rows,
        "audit_entries": audit_entries,
        "smtp": _smtp_overview(session),
        "enrichment_coverage": _enrichment_coverage(session),
        "collection_window_days": _collection_window_days(session),
    }


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, session: Session = Depends(get_session)):
    admin = _admin_or_none(request)
    if request.state.user is None:
        # Zero users → /login links to the /setup page; otherwise middleware
        # already redirected anonymous users here.
        return RedirectResponse(url="/login", status_code=303)
    if admin is None:
        return templates.TemplateResponse(request, "403.html", {}, status_code=403)

    return templates.TemplateResponse(request, "admin.html", _admin_context(request, session, admin))


@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    username: str = Form(...),
    email: str = Form(...),
    display_name: str = Form(""),
    role: str = Form("user"),
    password: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    if role not in ("user", "admin"):
        return _redirect_flash("/admin", "Role must be 'user' or 'admin'.", "error")
    email = email.strip()
    if not _EMAIL_RE.match(email):
        return _redirect_flash("/admin", f"Invalid email address: {email!r}", "error")
    username = username.strip()
    if not username:
        return _redirect_flash("/admin", "Username is required.", "error")
    if session.scalar(select(User).where(func.lower(User.username) == username.lower())):
        return _redirect_flash("/admin", f"Username {username!r} already exists.", "error")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(9)
    from scry import mail as _mail
    from scry.auth import verification as _verification

    user = User(
        username=username,
        email=email,
        display_name=display_name.strip() or None,
        role=role,
        password_hash=hash_password(password),
        must_change_password=generated,
        # No mailer → nothing can verify the address; per the locked bypass
        # the email is trusted outright. With SMTP up, a PIN is emailed.
        email_verified=not _mail.smtp_configured(session),
    )
    session.add(user)
    session.flush()
    pin_note = ""
    if _mail.smtp_configured(session):
        pin_note = (
            " Verification code sent to their email."
            if _verification.issue_pin(session, user)
            else " Verification email could not be sent."
        )
    _audit_admin(session, admin, "user.create", user, {"role": role, "email_verified": user.email_verified})
    if generated:
        # The temporary password is shown exactly once, on a rendered page —
        # never in a redirect query string (access logs / browser history).
        context = _admin_context(request, session, admin)
        context["one_time_secret"] = {
            "kind": "temporary password",
            "subject": f"new user {username!r}",
            "value": password,
            "note": f"Created user {username!r} ({role}).{pin_note} They must change it at first login.",
        }
        return templates.TemplateResponse(request, "admin.html", context)
    return _redirect_flash("/admin", f"Created user {username!r} ({role}).{pin_note}")


def _get_target(session: Session, user_id: int) -> User | None:
    return session.get(User, user_id)


@app.post("/admin/users/{user_id}/edit")
def admin_edit_user(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    email: str = Form(...),
    display_name: str = Form(""),
    role: str = Form("user"),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    user = _get_target(session, user_id)
    if user is None:
        return _redirect_flash("/admin", "User not found.", "error")
    if role not in ("user", "admin"):
        return _redirect_flash("/admin", "Role must be 'user' or 'admin'.", "error")
    if role != user.role and _last_admin(session, user):
        return _redirect_flash("/admin", f"{user.username} is the last admin — role change blocked.", "error")
    if user.id == admin.id and role != admin.role:
        return _redirect_flash("/admin", "You cannot change your own role.", "error")
    email = email.strip()
    if not _EMAIL_RE.match(email):
        return _redirect_flash("/admin", f"Invalid email address: {email!r}", "error")
    user.email = email
    user.display_name = display_name.strip() or None
    user.role = role
    session.flush()
    _audit_admin(session, admin, "user.update", user, {"role": role})
    return _redirect_flash("/admin", f"Updated {user.username!r}.")


@app.post("/admin/users/{user_id}/toggle")
def admin_toggle_user(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    user = _get_target(session, user_id)
    if user is None:
        return _redirect_flash("/admin", "User not found.", "error")
    if user.id == admin.id:
        return _redirect_flash("/admin", "You cannot disable your own account.", "error")
    if user.status == "active":
        user.status = "disabled"
        revoked = revoke_all_sessions(session, user.id)
        session.flush()
        _audit_admin(session, admin, "user.disable", user, {"revoked_sessions": revoked})
        return _redirect_flash("/admin", f"Disabled {user.username!r} ({revoked} session(s) revoked).")
    user.status = "active"
    session.flush()
    _audit_admin(session, admin, "user.enable", user)
    return _redirect_flash("/admin", f"Enabled {user.username!r}.")


@app.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    user = _get_target(session, user_id)
    if user is None:
        return _redirect_flash("/admin", "User not found.", "error")
    temp = secrets.token_urlsafe(9)
    user.password_hash = hash_password(temp)
    user.must_change_password = True
    user.failed_login_count = 0
    user.locked_until = None
    revoked = revoke_all_sessions(session, user.id)
    session.flush()
    _audit_admin(session, admin, "user.reset_password", user, {"revoked_sessions": revoked})
    # The temporary password is shown exactly once, on a rendered page —
    # never in a redirect query string (access logs / browser history).
    context = _admin_context(request, session, admin)
    context["one_time_secret"] = {
        "kind": "temporary password",
        "subject": f"user {user.username!r}",
        "value": temp,
        "note": (
            f"Password reset for {user.username!r} ({revoked} session(s) revoked). "
            "They must change it at first login."
        ),
    }
    return templates.TemplateResponse(request, "admin.html", context)


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    confirm: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    user = _get_target(session, user_id)
    if user is None:
        return _redirect_flash("/admin", "User not found.", "error")
    if _last_admin(session, user):
        return _redirect_flash("/admin", f"{user.username} is the last admin — deletion blocked.", "error")
    if user.id == admin.id:
        return _redirect_flash("/admin", "You cannot delete your own account.", "error")
    if confirm != user.username:
        return _redirect_flash(
            "/admin", f"Deletion not confirmed — type the username ({user.username}) to confirm.", "error"
        )
    username = user.username
    session.delete(user)  # session tokens cascade
    _audit_admin(session, admin, "user.delete", detail={"username": username})
    return _redirect_flash("/admin", f"Deleted user {username!r}.")


@app.post("/admin/users/{user_id}/revoke-sessions")
def admin_revoke_user_sessions(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    user = _get_target(session, user_id)
    if user is None:
        return _redirect_flash("/admin", "User not found.", "error")
    revoked = revoke_all_sessions(session, user.id)
    _audit_admin(session, admin, "session.revoke_all", user, {"revoked": revoked})
    return _redirect_flash("/admin", f"Revoked {revoked} session(s) for {user.username!r}.")


@app.post("/admin/users/{user_id}/reset-mfa")
def admin_reset_mfa(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    confirm: str = Form(""),
):
    """Force-disable MFA for a user (locked decision: admin can force-disable).
    Clears the enabled flag + secret + recovery codes and revokes sessions."""
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    user = _get_target(session, user_id)
    if user is None:
        return _redirect_flash("/admin", "User not found.", "error")
    if not user.totp_enabled and not user.totp_pending:
        return _redirect_flash("/admin", f"{user.username} does not have MFA enabled.")
    if confirm != user.username:
        return _redirect_flash(
            "/admin",
            f"Reset not confirmed — type the username ({user.username}) to confirm.",
            "error",
        )
    from scry.auth import totp as _totp

    user.totp_enabled = False
    user.totp_pending = False
    user.totp_secret_encrypted = None
    deleted = _totp.delete_recovery_codes(session, user.id)
    revoked = revoke_all_sessions(session, user.id)
    session.flush()
    _audit_admin(
        session,
        admin,
        "mfa.admin_reset",
        user,
        {"recovery_codes_deleted": deleted, "revoked_sessions": revoked},
    )
    return _redirect_flash("/admin", f"Reset MFA for {user.username!r} ({revoked} session(s) revoked).")


@app.post("/admin/sessions/{token_id}/revoke")
def admin_revoke_session(
    token_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    token = session.get(SessionToken, token_id)
    if token is None:
        return _redirect_flash("/admin", "Session not found.", "error")
    owner = session.get(User, token.user_id)
    username = owner.username if owner is not None else "?"
    session.delete(token)
    _audit_admin(session, admin, "session.revoke", detail={"username": username})
    return _redirect_flash("/admin", f"Revoked session #{token_id} ({username}).")


@app.post("/admin/smtp/save")
def admin_smtp_save(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    host: str = Form(""),
    port: str = Form("465"),
    user: str = Form(""),
    password: str = Form(""),
    starttls: str | None = Form(None),
    from_address: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    from scry.mail import save_smtp_config

    host = host.strip()
    if not host:
        # Blank host clears the DB overrides — the env config becomes effective again.
        session.execute(delete(SystemSetting).where(SystemSetting.key.like("smtp.%")))
        _audit_admin(session, admin, "smtp.clear")
        return _redirect_flash("/admin", "SMTP config cleared — env values (if any) apply.")
    try:
        port_num = int(port)
    except ValueError:
        return _redirect_flash("/admin", f"Invalid port: {port!r}", "error")
    if not 1 <= port_num <= 65535:
        return _redirect_flash("/admin", f"Invalid port: {port_num}", "error")
    if not from_address.strip() or not _EMAIL_RE.match(from_address.strip()):
        return _redirect_flash("/admin", "A valid from address is required.", "error")
    existing = session.scalar(select(SystemSetting).where(SystemSetting.key == "smtp.password"))
    if not password and existing is not None and existing.value:
        password_encrypted = existing.value  # keep the stored secret when left blank
        save_smtp_config(
            session,
            host=host,
            port=port_num,
            user=user,
            password="",
            starttls=starttls == "on",
            from_address=from_address,
        )
        session.flush()
        existing.value = password_encrypted
    else:
        save_smtp_config(
            session,
            host=host,
            port=port_num,
            user=user,
            password=password,
            starttls=starttls == "on",
            from_address=from_address,
        )
    session.flush()
    _audit_admin(session, admin, "smtp.update", detail={"host": host, "port": port_num})
    return _redirect_flash("/admin", f"SMTP config saved for {host}:{port_num}.")


@app.post("/admin/smtp/test")
def admin_smtp_test(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    test_to: str = Form(""),
):
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    from scry.mail import test_smtp

    to = test_to.strip() or None
    if to and not _EMAIL_RE.match(to):
        return _redirect_flash("/admin", f"Invalid test address: {to!r}", "error")
    ok, error = test_smtp(session, to=to)
    _audit_admin(session, admin, "smtp.test", detail={"ok": ok, "to": to})
    if ok:
        target = f" to {to}" if to else ""
        return _redirect_flash("/admin", f"SMTP test OK{target}.")
    return _redirect_flash("/admin", f"SMTP test failed: {error}", "error")


@app.post("/admin/collection-window/save")
def admin_collection_window_save(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    days: str = Form(""),
):
    """Set the global collection window — admin-only (v0.7.0 step 2).

    Collection is global: the window applies to every source for every
    user. Applies to new collection only; existing articles are untouched.
    """
    admin = _admin_or_none(request)
    if admin is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/admin", "Bad CSRF token — action rejected.", "error")
    from scry.ingestion.collection_window import set_window_days

    try:
        requested = int(days)
    except ValueError:
        return _redirect_flash("/admin", f"Invalid collection window: {days!r}", "error")
    saved = set_window_days(session, requested)
    _audit_admin(session, admin, "collection_window.set", detail={"days": saved, "requested": requested})
    return _redirect_flash("/admin", f"Collection window set to last {saved} day(s).")


# ------------------------- profile (v0.5.0 step 3) -------------------------

# CSRF on profile POST forms: same scheme as the admin panel — the
# Fernet-encrypted sha256 of the session cookie (see _admin_csrf_token).
_MIN_PASSWORD_LEN = 10
_API_KEY_PREFIX_LEN = 8  # "sk-" + 5 chars, e.g. "sk-x7Kq2…"
_MAX_KEY_EXPIRY_DAYS = 3650


def _profile_or_redirect(request: Request, session: Session) -> User | None:
    """Fresh ORM row for the signed-in user (middleware-set state is detached)."""
    state_user = getattr(request.state, "user", None)
    if state_user is None:
        return None
    return session.get(User, state_user.id)


def _audit_profile(session: Session, actor: User, action: str, detail: dict | None = None) -> None:
    from scry.audit import record

    record(
        session,
        action=action,
        actor=actor.username,
        target_type="user",
        target_id=actor.id,
        detail=detail or {},
    )


def _profile_context(request: Request, session: Session, user: User) -> dict:
    """Template context shared by GET /profile and the MFA enable step (which
    renders the recovery codes once)."""
    from scry import mail as _mail
    from scry.auth import totp as _totp

    api_keys = list(
        session.scalars(select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.id.desc()))
    )
    now = datetime.now(UTC)
    for key in api_keys:
        if key.revoked_at is not None:
            key.display_status = "revoked"
        elif key.expires_at is not None:
            exp = key.expires_at if key.expires_at.tzinfo else key.expires_at.replace(tzinfo=UTC)
            key.display_status = "expired" if exp <= now else "active"
        else:
            key.display_status = "active"
    pending_verification = session.scalar(
        select(EmailVerification)
        .where(
            EmailVerification.user_id == user.id,
            EmailVerification.consumed_at.is_(None),
        )
        .order_by(EmailVerification.id.desc())
    )
    # A pending (not yet confirmed) setup shows the QR + manual code inline.
    mfa_setup = None
    if user.totp_pending and not user.totp_enabled:
        secret = decrypt(user.totp_secret_encrypted)
        if secret:
            uri = _totp.provisioning_uri(secret, user.username)
            mfa_setup = {"secret": secret, "uri": uri, "qr": _totp.qr_data_uri(uri)}
    unused_recovery_codes = session.scalar(
        select(func.count(RecoveryCode.id)).where(
            RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
        )
    )
    return {
        "user": user,
        "csrf": _admin_csrf_token(request.cookies[SESSION_COOKIE]),
        "api_keys": api_keys,
        "passkeys": list(
            session.scalars(
                select(PasskeyCredential)
                .where(PasskeyCredential.user_id == user.id)
                .order_by(PasskeyCredential.id)
            )
        ),
        "smtp_configured": _mail.smtp_configured(session),
        "pending_verification": pending_verification,
        "mfa_setup": mfa_setup,
        "mfa_unused_recovery_codes": unused_recovery_codes or 0,
    }


@app.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, session: Session = Depends(get_session)):
    user = _profile_or_redirect(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "profile.html", _profile_context(request, session, user))


@app.post("/profile/display-name")
def profile_display_name(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    display_name: str = Form(""),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    user.display_name = display_name.strip() or None
    session.flush()
    _audit_profile(session, user, "user.update", {"field": "display_name"})
    return _redirect_flash("/profile", "Display name updated.")


@app.post("/profile/password")
def profile_change_password(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if not verify_password(current_password, user.password_hash):
        return _redirect_flash("/profile", "Current password is incorrect.", "error")
    if new_password != confirm_password:
        return _redirect_flash("/profile", "New passwords do not match.", "error")
    if len(new_password) < _MIN_PASSWORD_LEN:
        return _redirect_flash(
            "/profile", f"New password must be at least {_MIN_PASSWORD_LEN} characters.", "error"
        )
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.failed_login_count = 0
    user.locked_until = None
    # Sign out every other session; keep the one driving this request.
    keep = hash_token(request.cookies.get(SESSION_COOKIE) or "")
    revoked = session.execute(
        delete(SessionToken).where(SessionToken.user_id == user.id, SessionToken.token_hash != keep)
    ).rowcount
    session.flush()
    _audit_profile(session, user, "user.change_password", {"revoked_sessions": int(revoked or 0)})
    return _redirect_flash(
        "/profile",
        f"Password changed. {int(revoked or 0)} other session(s) were signed out.",
    )


@app.post("/profile/verify-email")
def profile_verify_email(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if user.email_verified:
        return _redirect_flash("/profile", "Your email is already verified.")
    from scry import mail as _mail
    from scry.auth import verification as _verification

    if not _mail.smtp_configured(session):
        # Locked decision: no mailer → verification auto-bypassed.
        user.email_verified = True
        session.flush()
        _audit_profile(session, user, "email.verify.bypass")
        return _redirect_flash("/profile", "SMTP not configured — email auto-verified.", "error")
    if _verification.issue_pin(session, user) is None:
        _audit_profile(session, user, "email.verify.send_failed")
        return _redirect_flash(
            "/profile",
            "Could not send the verification email — check the SMTP settings.",
            "error",
        )
    _audit_profile(session, user, "email.verify.send")
    return _redirect_flash("/profile", f"Verification code sent to {user.email}.")


@app.post("/profile/verify-email/confirm")
def profile_verify_email_confirm(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    code: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    from scry.auth import verification as _verification

    result = _verification.confirm_pin(session, user, code)
    if result == "ok":
        _audit_profile(session, user, "email.verify.confirm")
        return _redirect_flash("/profile", "Email verified.")
    if result == "expired":
        return _redirect_flash("/profile", "That code has expired — request a new one.", "error")
    if result == "invalidated":
        return _redirect_flash(
            "/profile",
            "Too many wrong attempts — the code was invalidated. Request a new one.",
            "error",
        )
    if result == "mismatch":
        return _redirect_flash("/profile", "Incorrect code — try again.", "error")
    return _redirect_flash("/profile", "No pending verification code — request one first.", "error")


@app.post("/profile/api-keys")
def profile_create_api_key(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    name: str = Form(...),
    expiry_days: str = Form(""),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    name = name.strip()
    if not name:
        return _redirect_flash("/profile", "A name/label is required for the API key.", "error")
    expires_at = None
    if expiry_days.strip():
        try:
            days = int(expiry_days)
        except ValueError:
            return _redirect_flash("/profile", f"Invalid expiry: {expiry_days!r}", "error")
        if not 1 <= days <= _MAX_KEY_EXPIRY_DAYS:
            return _redirect_flash("/profile", f"Expiry must be 1-{_MAX_KEY_EXPIRY_DAYS} days.", "error")
        expires_at = datetime.now(UTC) + timedelta(days=days)
    raw_key = "sk-" + secrets.token_urlsafe(32)
    session.add(
        ApiKey(
            user_id=user.id,
            name=name[:128],
            key_hash=hash_token(raw_key),
            prefix=raw_key[:_API_KEY_PREFIX_LEN],
            expires_at=expires_at,
        )
    )
    session.flush()
    _audit_profile(session, user, "api_key.create", {"name": name[:128], "expires_days": expiry_days or None})
    # The full key is shown exactly once, on a rendered page — never in a
    # redirect query string (access logs / browser history). Afterwards only
    # the prefix survives.
    context = _profile_context(request, session, user)
    context["new_api_key"] = {"name": name[:128], "value": raw_key}
    return templates.TemplateResponse(request, "profile.html", context)


@app.post("/profile/api-keys/{key_id}/revoke")
def profile_revoke_api_key(
    key_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    api_key = session.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id))
    if api_key is None:
        return _redirect_flash("/profile", "API key not found.", "error")
    if api_key.revoked_at is not None:
        return _redirect_flash("/profile", "That API key is already revoked.")
    api_key.revoked_at = datetime.now(UTC)
    session.flush()
    _audit_profile(session, user, "api_key.revoke", {"name": api_key.name, "prefix": api_key.prefix})
    return _redirect_flash("/profile", f"Revoked API key '{api_key.name}'.")


# ------------------------- TOTP MFA (v0.5.0 step 4) -------------------------

# Setup is verify-before-enable: POST /profile/mfa/setup (password confirm)
# generates + encrypts a secret and marks it pending; GET /profile then shows
# the QR code (inline data URI — no standalone QR endpoint exists) until the
# user confirms a valid code via POST /profile/mfa/verify, which enables MFA
# and shows the 10 one-time recovery codes exactly once.


@app.post("/profile/mfa/setup")
def profile_mfa_setup(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    password: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if user.totp_enabled:
        return _redirect_flash("/profile", "MFA is already enabled.")
    if not verify_password(password, user.password_hash):
        return _redirect_flash("/profile", "Password is incorrect.", "error")
    from scry.auth import totp as _totp

    # Restarting setup while pending regenerates the secret — the old QR
    # simply stops working.
    user.totp_secret_encrypted = encrypt(_totp.generate_secret())
    user.totp_pending = True
    session.flush()
    _audit_profile(session, user, "mfa.setup")
    return _redirect_flash(
        "/profile",
        "Scan the QR code with your authenticator app, then enter the 6-digit code to finish.",
    )


@app.post("/profile/mfa/verify")
def profile_mfa_verify(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    code: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if user.totp_enabled:
        return _redirect_flash("/profile", "MFA is already enabled.")
    if not user.totp_pending or not user.totp_secret_encrypted:
        return _redirect_flash("/profile", "Set up MFA first.", "error")
    from scry.auth import totp as _totp

    secret = decrypt(user.totp_secret_encrypted)
    if not secret or not _totp.verify_totp(secret, code):
        # Stay in pending state so the user can retry with the same QR.
        return _redirect_flash("/profile", "Incorrect code — try again.", "error")
    user.totp_enabled = True
    user.totp_pending = False
    codes = _totp.generate_recovery_codes()
    _totp.store_recovery_codes(session, user.id, codes)
    session.flush()
    _audit_profile(session, user, "mfa.enable")
    context = _profile_context(request, session, user)
    context["mfa_recovery_codes"] = codes
    return templates.TemplateResponse(request, "profile.html", context)


@app.post("/profile/mfa/cancel")
def profile_mfa_cancel(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if user.totp_pending:
        user.totp_secret_encrypted = None
        user.totp_pending = False
        session.flush()
        _audit_profile(session, user, "mfa.setup_cancel")
    return _redirect_flash("/profile", "MFA setup cancelled.")


@app.post("/profile/mfa/disable")
def profile_mfa_disable(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    password: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if not user.totp_enabled:
        return _redirect_flash("/profile", "MFA is not enabled.")
    if not verify_password(password, user.password_hash):
        return _redirect_flash("/profile", "Password is incorrect.", "error")
    from scry.auth import totp as _totp

    user.totp_enabled = False
    user.totp_pending = False
    user.totp_secret_encrypted = None
    deleted = _totp.delete_recovery_codes(session, user.id)
    # Sign out every OTHER session; keep the one driving this request.
    keep = hash_token(request.cookies.get(SESSION_COOKIE) or "")
    revoked = session.execute(
        delete(SessionToken).where(SessionToken.user_id == user.id, SessionToken.token_hash != keep)
    ).rowcount
    session.flush()
    _audit_profile(
        session,
        user,
        "mfa.disable",
        {"recovery_codes_deleted": deleted, "revoked_sessions": int(revoked or 0)},
    )
    return _redirect_flash(
        "/profile",
        f"MFA disabled. {int(revoked or 0)} other session(s) were signed out.",
    )


# ------------------------- passkeys / WebAuthn (v0.5.0 step 5) -------------------------

# Registration ceremony (session required, CSRF-gated, password-confirmed):
#   POST /profile/passkeys/register-begin    → WebAuthn creation options JSON;
#     the challenge rides in a short-lived Fernet pending cookie.
#   POST /profile/passkeys/register-complete → verifies the attestation and
#     stores the credential under the user-supplied name.
# Username-first login ceremony (no session): the user enters their username,
# we scope the assertion options to that user's credentials, and a successful
# assertion creates a session directly. A passkey IS the second factor: a
# successful passkey sign-in satisfies MFA (a user with totp_enabled skips the
# /login/mfa challenge — documented on the login page).
# rp_id/origin are derived per request from the Host header (scry/auth/webauthn.py).


@app.post("/profile/passkeys/register-begin")
def profile_passkey_register_begin(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    password: str = Form(...),
):
    from scry.auth import webauthn as _webauthn

    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return JSONResponse({"error": "Bad CSRF token — action rejected."}, status_code=403)
    if not verify_password(password, user.password_hash):
        return JSONResponse({"error": "Password is incorrect."}, status_code=403)
    rp_id, _origin = _webauthn.rp_context(request)
    credentials = list(session.scalars(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id)))
    options_json, challenge = _webauthn.registration_options_json(user, credentials, rp_id)
    marker = _webauthn.issue_passkey_marker(user.id, challenge)
    response = JSONResponse({"options": json.loads(options_json)})
    response.set_cookie(
        _webauthn.PASSKEY_PENDING_COOKIE,
        marker,
        max_age=int(_webauthn.PASSKEY_PENDING_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/profile/passkeys/register-complete")
def profile_passkey_register_complete(
    request: Request,
    session: Session = Depends(get_session),
    payload: dict = Body(default={}),
):
    from scry.auth import webauthn as _webauthn

    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, payload.get("csrf")):
        return JSONResponse({"error": "Bad CSRF token — action rejected."}, status_code=403)
    marker = _webauthn.read_passkey_marker(request.cookies.get(_webauthn.PASSKEY_PENDING_COOKIE))
    if marker is None or marker["uid"] != user.id:
        return JSONResponse({"error": "The passkey setup has expired — please try again."}, status_code=400)
    rp_id, origin = _webauthn.rp_context(request)
    credential = payload.get("credential") or {}
    try:
        verification = _webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=_webauthn.challenge_bytes(marker["challenge"]),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception:  # InvalidRegistrationResponse and friends — back to start.
        response = JSONResponse({"error": "Passkey verification failed — please try again."}, status_code=400)
        response.delete_cookie(_webauthn.PASSKEY_PENDING_COOKIE, path="/")
        return response
    name = ((payload.get("name") or "").strip() or "Passkey")[:128]
    transports = credential.get("transports")
    session.add(
        PasskeyCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=verification.aaguid or None,
            transports=",".join(transports) if isinstance(transports, list) else None,
            name=name,
        )
    )
    session.flush()
    _audit_profile(session, user, "passkey.register", {"name": name, "aaguid": verification.aaguid or None})
    response = JSONResponse({"ok": True, "name": name})
    response.delete_cookie(_webauthn.PASSKEY_PENDING_COOKIE, path="/")
    return response


@app.post("/profile/passkeys/{passkey_id}/rename")
def profile_passkey_rename(
    passkey_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    name: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    credential = session.scalar(
        select(PasskeyCredential).where(
            PasskeyCredential.id == passkey_id, PasskeyCredential.user_id == user.id
        )
    )
    if credential is None:
        return _redirect_flash("/profile", "Passkey not found.", "error")
    old_name = credential.name
    credential.name = name.strip()[:128] or "Passkey"
    session.flush()
    _audit_profile(session, user, "passkey.rename", {"from": old_name, "to": credential.name})
    return _redirect_flash("/profile", f"Passkey renamed to '{credential.name}'.")


@app.post("/profile/passkeys/{passkey_id}/delete")
def profile_passkey_delete(
    passkey_id: int,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    password: str = Form(...),
):
    user = _profile_or_redirect(request, session)
    if user is None:
        raise HTTPException(403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/profile", "Bad CSRF token — action rejected.", "error")
    if not verify_password(password, user.password_hash):
        return _redirect_flash("/profile", "Password is incorrect.", "error")
    credential = session.scalar(
        select(PasskeyCredential).where(
            PasskeyCredential.id == passkey_id, PasskeyCredential.user_id == user.id
        )
    )
    if credential is None:
        return _redirect_flash("/profile", "Passkey not found.", "error")
    name = credential.name
    session.delete(credential)
    session.flush()
    _audit_profile(session, user, "passkey.delete", {"name": name})
    return _redirect_flash("/profile", f"Deleted passkey '{name}'.")


@app.post("/login/passkey/begin")
def login_passkey_begin(request: Request, username: str = Form(...)):
    """Username-first passkey sign-in: scope the assertion to the user's
    credentials and hand the challenge to the browser via a pending cookie."""
    from scry.auth import webauthn as _webauthn

    rp_id, _origin = _webauthn.rp_context(request)
    generic_error = JSONResponse({"error": "No passkeys are registered for that username."}, status_code=400)
    with session_scope() as session:
        if not users_exist(session):
            return JSONResponse({"error": "No user accounts exist yet."}, status_code=400)
        user = session.scalar(select(User).where(func.lower(User.username) == username.lower()))
        if user is None or user.status != "active":
            return generic_error
        credentials = list(
            session.scalars(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id))
        )
        if not credentials:
            return generic_error
        options_json, challenge = _webauthn.authentication_options_json(credentials, rp_id)
        marker = _webauthn.issue_passkey_marker(user.id, challenge)
    response = JSONResponse({"options": json.loads(options_json)})
    response.set_cookie(
        _webauthn.PASSKEY_PENDING_COOKIE,
        marker,
        max_age=int(_webauthn.PASSKEY_PENDING_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/login/passkey/complete")
def login_passkey_complete(request: Request, payload: dict = Body(default={})):
    from scry.auth import webauthn as _webauthn

    marker = _webauthn.read_passkey_marker(request.cookies.get(_webauthn.PASSKEY_PENDING_COOKIE))
    if marker is None:
        return JSONResponse({"error": "The passkey sign-in has expired — please try again."}, status_code=400)
    rp_id, origin = _webauthn.rp_context(request)
    credential = payload.get("credential") or {}
    next_url = _safe_next(payload.get("next"))
    with session_scope() as session:
        user = session.get(User, marker["uid"])
        cred_id = _webauthn.credential_id_bytes(credential)
        credential_row = (
            session.scalar(
                select(PasskeyCredential).where(
                    PasskeyCredential.user_id == marker["uid"],
                    PasskeyCredential.credential_id == cred_id,
                )
            )
            if cred_id is not None
            else None
        )
        if user is None or user.status != "active" or credential_row is None:
            response = JSONResponse({"error": "Unknown passkey."}, status_code=400)
            response.delete_cookie(_webauthn.PASSKEY_PENDING_COOKIE, path="/")
            return response
        try:
            verification = _webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=_webauthn.challenge_bytes(marker["challenge"]),
                expected_rp_id=rp_id,
                expected_origin=origin,
                credential_public_key=credential_row.public_key,
                credential_current_sign_count=credential_row.sign_count,
            )
        except Exception:  # InvalidAuthenticationResponse et al — fail closed.
            _audit_login(session, user.username, success=False, detail={"reason": "passkey"})
            session.commit()
            response = JSONResponse({"error": "Passkey verification failed."}, status_code=400)
            response.delete_cookie(_webauthn.PASSKEY_PENDING_COOKIE, path="/")
            return response
        # Verified: advance the sign counter (clone detection), touch last used.
        credential_row.sign_count = verification.new_sign_count
        credential_row.last_used_at = datetime.now(UTC)
        record_login_success(session, user)
        raw_token = create_session(
            session,
            user,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        # A passkey assertion IS the second factor: when TOTP MFA is enabled it
        # is satisfied by the passkey sign-in (no /login/mfa challenge).
        _audit_login(
            session,
            user.username,
            success=True,
            detail={"via": "passkey", "mfa": "satisfied" if user.totp_enabled else "not_required"},
        )
        session.commit()
    response = JSONResponse({"ok": True, "redirect": next_url})
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(_webauthn.PASSKEY_PENDING_COOKIE, path="/")
    return response


# ------------------------- helpers -------------------------


def _tag_filter(column, tag: str):
    """SQLite-safe filter: match a quoted tag inside a JSON array column.

    Shared implementation (with LIKE-metacharacter escaping) lives in
    ``scry.db.tag_filter`` so the API router and alert engine use it too.
    """
    return tag_filter(column, tag)


def _qs_extra(**kwargs) -> str:
    pairs = [(k, v) for k, v in kwargs.items() if v not in (None, "", False)]
    return ("&" + urlencode(pairs)) if pairs else ""


def _resolve_rel_target(session: Session, kind: str, oid: int) -> dict | None:
    """Best-effort resolution of a Relationship endpoint to an Entity or Observable."""
    if kind in {"threat_actor", "malware_family", "organization", "person", "location", "campaign", "tool"}:
        e = session.get(Entity, oid)
        if e:
            return {"kind": "entity", "id": e.id, "type": e.type, "label": e.canonical_name}
    o = session.get(Observable, oid)
    if o and o.type == kind:
        return {"kind": "observable", "id": o.id, "type": o.type, "label": o.normalized_value}
    return None


# ------------------------- dashboard -------------------------


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)):
    settings = get_settings()
    counts = {
        "articles": session.scalar(select(func.count(Article.id))) or 0,
        "observables": session.scalar(select(func.count(Observable.id))) or 0,
        "cves": session.scalar(select(func.count(CVE.id))) or 0,
        "threat_feed_items": session.scalar(select(func.count(ThreatFeedItem.id))) or 0,
        "ransomware_feed_items": session.scalar(select(func.count(RansomwareFeedItem.id))) or 0,
        "open_reviews": session.scalar(
            select(func.count(AnalystReview.id)).where(AnalystReview.status == "open")
        )
        or 0,
    }
    high_risk = list(
        session.scalars(
            select(Observable)
            .where(Observable.risk_score >= 70)
            .order_by(Observable.risk_score.desc())
            .limit(15)
        )
    )
    recent_articles = list(session.scalars(select(Article).order_by(Article.id.desc()).limit(20)))
    # Recent high-risk threat feed items
    recent_threats = list(
        session.scalars(
            select(ThreatFeedItem)
            .where(ThreatFeedItem.risk_score >= 75)
            .order_by(ThreatFeedItem.date.desc())
            .limit(8)
        )
    )
    # Feed freshness: most recent fetch or article ingestion, whichever is newer.
    last_collected = max(
        (
            ts
            for ts in (
                session.scalar(select(func.max(SourceFetch.fetched_at))),
                session.scalar(select(func.max(Article.ingested_at))),
            )
            if ts is not None
        ),
        default=None,
    )
    # CSRF token for the Collect-now POST (empty in zero-user legacy mode —
    # the POST then rejects, same as the other UI mutations).
    raw_cookie = request.cookies.get(SESSION_COOKIE)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "counts": counts,
            "high_risk": high_risk,
            "articles": recent_articles,
            "recent_threats": recent_threats,
            "settings": settings,
            "last_collected": last_collected,
            "csrf": _admin_csrf_token(raw_cookie) if raw_cookie else "",
        },
    )


@app.post("/ui/ingest/run")
async def ui_ingest_run(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    """UI counterpart of POST /ingest/run — same services, browser-friendly redirect."""
    from scry.ingestion.ingest_engine import IngestionEngine
    from scry.pipeline import CTIPipeline

    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/", "Bad CSRF token — action rejected.", "error")
    try:
        engine = IngestionEngine(session)
        res = await engine.ingest_all()
        pipeline = CTIPipeline(session)
        for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
            pipeline.process_article(art)
        msg = (
            f"Collection complete: {res.get('articles', 0)} articles, "
            f"{res.get('cves', 0)} CVEs, {res.get('errors', 0)} errors, "
            f"{res.get('blocked', 0)} blocked"
        )
        return _redirect_flash("/", msg, "success" if not res.get("errors") else "error")
    except Exception as exc:
        _log.warning("ui_ingest_run_failed", exc=str(exc))
        return _redirect_flash("/", f"Collection failed: {exc}", "error")


# ------------------------- articles -------------------------


@app.get("/ui/articles", response_class=HTMLResponse)
def ui_articles(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    tag: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Article).order_by(Article.id.desc())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(Article.title.ilike(like), Article.extracted_text.ilike(like), Article.summary.ilike(like))
        )
    if tag:
        stmt = stmt.where(_tag_filter(Article.tags, tag))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    articles = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {"q": q, "tag": tag, "limit": limit, "offset": offset, "qs": _qs_extra(q=q, tag=tag)}
    return templates.TemplateResponse(
        request, "articles.html", {"articles": articles, "total": total, "filters": filters}
    )


@app.get("/ui/articles/{article_id}", response_class=HTMLResponse)
def ui_article_detail(article_id: int, request: Request, session: Session = Depends(get_session)):
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(404)
    source = session.get(Source, article.source_id) if article.source_id else None

    rows = session.execute(
        select(Observable, ObservableMention)
        .join(ObservableMention, ObservableMention.observable_id == Observable.id)
        .where(ObservableMention.article_id == article_id)
        .order_by(Observable.risk_score.desc())
    ).all()
    observable_mentions = [(ob, mention) for ob, mention in rows]

    rows = session.execute(
        select(Entity, EntityMention)
        .join(EntityMention, EntityMention.entity_id == Entity.id)
        .where(EntityMention.article_id == article_id)
    ).all()
    entity_mentions = [(e, mention) for e, mention in rows]

    claims = list(session.scalars(select(Claim).where(Claim.article_id == article_id)))

    return templates.TemplateResponse(
        request,
        "article_detail.html",
        {
            "article": article,
            "source": source,
            "observable_mentions": observable_mentions,
            "entity_mentions": entity_mentions,
            "claims": claims,
        },
    )


# ------------------------- observables -------------------------


@app.get("/ui/observables", response_class=HTMLResponse)
def ui_observables(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    type: str | None = None,
    tag: str | None = None,
    min_risk: float | None = None,
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Observable).order_by(Observable.risk_score.desc(), Observable.id.desc())
    if q:
        stmt = stmt.where(Observable.normalized_value.ilike(f"%{q.lower()}%"))
    if type:
        stmt = stmt.where(Observable.type == type)
    if tag:
        stmt = stmt.where(_tag_filter(Observable.tags, tag))
    if min_risk is not None:
        stmt = stmt.where(Observable.risk_score >= min_risk)
    if status:
        stmt = stmt.where(Observable.status == status)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    obs = list(session.scalars(stmt.offset(offset).limit(limit)))

    available_types = [
        t
        for (t,) in session.execute(
            select(Observable.type).group_by(Observable.type).order_by(Observable.type)
        ).all()
    ]
    filters = {
        "q": q,
        "type": type,
        "tag": tag,
        "min_risk": min_risk,
        "status": status,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(q=q, type=type, tag=tag, min_risk=min_risk, status=status),
    }
    user = _signed_in_user(request, session)
    personal_keys = keys_for_user(session, user.id) if user else {}
    raw_cookie = request.cookies.get(SESSION_COOKIE)
    return templates.TemplateResponse(
        request,
        "observables.html",
        {
            "observables": obs,
            "total": total,
            "filters": filters,
            "available_types": available_types,
            "personal_key_providers": sorted(personal_keys),
            "enrich_csrf": _admin_csrf_token(raw_cookie) if raw_cookie else "",
        },
    )


@app.post("/ui/observables/enrich-unenriched")
def ui_enrich_unenriched(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    mode: str = Form("unenriched"),
):
    """Bulk-enrich observables with the ACTING USER's personal VT/OTX keys
    (capped per run; VT daily-quota guard applies).

    v0.6.0 step 3 — `mode` picks the staleness behaviour:
    ``unenriched`` = only never-checked records; ``stale`` = staleness path
    (missing OR older than the provider refresh TTL); ``force`` = ignore
    markers entirely and re-enrich everything (burns quota).
    """
    user = _signed_in_user(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    back = "/ui/observables"
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(back, "Bad CSRF token — action rejected.", "error")
    if mode not in ("unenriched", "stale", "force"):
        return _redirect_flash(back, f"Unknown enrichment mode {mode!r}.", "error")
    keys = keys_for_user(session, user.id)
    if not keys:
        return _redirect_flash(
            back,
            "No personal VT/OTX keys — save one on the Threat Feeds page first "
            "(background jobs use the system keys).",
            "error",
        )
    engine = EnrichmentEngine(session, user_api_keys=keys)
    result = engine.run_external_enrichment_batch(
        limit=_ENRICH_UNENRICHED_CAP,
        force=mode == "force",
        include_stale=mode in ("stale", "force"),
    )

    mode_labels = {
        "unenriched": "Enrich unenriched (my keys)",
        "stale": "Re-enrich stale (my keys)",
        "force": "Force re-enrich all (my keys)",
    }
    parts = [f"checked {result['total_candidates']}"]
    for provider in _PERSONAL_KEY_PROVIDERS:
        if provider in result["providers"]:
            count_key = _PROVIDER_COUNT_KEYS[provider]
            parts.append(f"{provider} enriched {result.get(count_key, 0)}")
            refreshed = result.get("refreshed", {}).get(provider)
            if refreshed:
                parts.append(f"{provider} re-enriched stale {refreshed}")
    if result.get("fresh_skipped"):
        parts.append(
            "fresh (skipped): " + ", ".join(f"{k} {v}" for k, v in sorted(result["fresh_skipped"].items()))
        )
    if result.get("quota_skipped"):
        parts.append(
            "skipped per quota: " + ", ".join(f"{k} {v}" for k, v in sorted(result["quota_skipped"].items()))
        )
    if result["skipped"]:
        parts.append("skipped: " + ", ".join(f"{k} ({v})" for k, v in sorted(result["skipped"].items())))
    if result.get("errors"):
        parts.append(f"errors {result['errors']}")
    _feed_key_audit(session, user, f"observables.enrich_unenriched.{mode}", "+".join(sorted(keys)))
    return _redirect_flash(back, f"{mode_labels[mode]} — " + "; ".join(parts) + ".")


@app.get("/ui/observables/{ob_id}", response_class=HTMLResponse)
def ui_observable_detail(ob_id: int, request: Request, session: Session = Depends(get_session)):
    ob = session.get(Observable, ob_id)
    if not ob:
        raise HTTPException(404)

    rows = session.execute(
        select(Article, ObservableMention)
        .join(ObservableMention, ObservableMention.article_id == Article.id)
        .where(ObservableMention.observable_id == ob_id)
        .order_by(Article.id.desc())
        .limit(50)
    ).all()
    mentions = [(art, mention) for art, mention in rows]

    rels: list[tuple[str, Relationship, dict | None]] = []
    out_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.source_type == ob.type, Relationship.source_id == ob.id)
            .limit(100)
        )
    )
    in_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.target_type == ob.type, Relationship.target_id == ob.id)
            .limit(100)
        )
    )
    for r in out_rels:
        rels.append(("out", r, _resolve_rel_target(session, r.target_type, r.target_id)))
    for r in in_rels:
        rels.append(("in", r, _resolve_rel_target(session, r.source_type, r.source_id)))

    enrichment_json = json.dumps(ob.enrichment or {}, indent=2, default=str)

    # v0.6.0 step 3 — per-provider last-enriched age for the sidebar.
    now = datetime.now(UTC)
    enrichment_now = ob.enrichment or {}
    provider_ages = {
        name: _humanize_checked_age(enrichment_now, name, now)
        for name in ("virustotal", "otx", "abuseipdb", "greynoise")
    }

    # v0.8.0 step 3 — age of the certificate-transparency (passive DNS) data
    # for the CT block; None until the domain has been enriched by crt.sh.
    passive_dns_age = (
        _humanize_checked_age(enrichment_now, "passive_dns", now)
        if enrichment_now.get("passive_dns_enriched_at")
        else None
    )

    # v0.5.0 step 6 — live lookup is only offered for providers the acting
    # user has a personal key for (user-triggered actions use personal keys).
    user = _signed_in_user(request, session)
    personal_keys = keys_for_user(session, user.id) if user else {}
    raw_cookie = request.cookies.get(SESSION_COOKIE)

    vt_data = (ob.enrichment or {}).get("virustotal") or {}
    vt_verdict = None
    if vt_data and not vt_data.get("not_found"):
        ts = vt_data.get("last_analysis_date")
        vt_verdict = {
            "malicious": vt_data.get("malicious") or 0,
            "suspicious": vt_data.get("suspicious") or 0,
            "undetected": vt_data.get("undetected") or 0,
            "tags": vt_data.get("tags") or [],
            "last_analysis": (
                datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")
                if isinstance(ts, (int, float))
                else None
            ),
        }
    otx_data = (ob.enrichment or {}).get("otx") or {}
    otx_verdict = None
    if otx_data and not otx_data.get("not_found"):
        otx_verdict = {
            "pulse_count": otx_data.get("pulse_count"),
            "reputation": otx_data.get("reputation"),
        }

    return templates.TemplateResponse(
        request,
        "observable_detail.html",
        {
            "observable": ob,
            "mentions": mentions,
            "relationships": rels,
            "enrichment_json": enrichment_json,
            "provider_ages": provider_ages,
            "passive_dns_age": passive_dns_age,
            "can_lookup_vt": "virustotal" in personal_keys,
            "can_lookup_otx": "otx" in personal_keys,
            "lookup_csrf": _admin_csrf_token(raw_cookie) if raw_cookie else "",
            "vt_verdict": vt_verdict,
            "otx_verdict": otx_verdict,
        },
    )


@app.post("/ui/observables/{ob_id}/lookup/{provider}")
def ui_observable_lookup(
    ob_id: int,
    provider: str,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    """Single live enrichment with the ACTING USER's personal key.

    v0.6.0 step 3 — this is the per-record FORCE path: it always bypasses the
    disk cache AND the staleness check, so the verdict reflects the provider
    right now — at the cost of one real API call against the user's quota.
    """
    user = _signed_in_user(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    ob = session.get(Observable, ob_id)
    if not ob:
        raise HTTPException(404)
    back = f"/ui/observables/{ob_id}"
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(back, "Bad CSRF token — action rejected.", "error")
    if provider not in _PERSONAL_KEY_PROVIDERS:
        return _redirect_flash(back, f"Unknown provider {provider!r}.", "error")
    key = get_decrypted_key(session, user.id, provider)
    if not key:
        return _redirect_flash(
            back,
            f"No personal {_FEED_DISPLAY_NAMES[provider]} key — save one on the "
            "Threat Feeds page to run live lookups.",
            "error",
        )
    if provider == "virustotal":
        enricher: VirusTotalEnricher | OTXEnricher = VirusTotalEnricher(api_key=key)
    else:
        enricher = OTXEnricher(api_key=key)
    try:
        result = enricher.lookup(ob.normalized_value, ob.type, bypass_cache=True)
    finally:
        enricher.close()

    if result.ok:
        merged = dict(ob.enrichment or {})
        merged[provider] = result.fields
        merged[f"_{'vt' if provider == 'virustotal' else 'otx'}_status"] = "ok"
        merged[f"{provider}_checked_at"] = datetime.now(UTC).isoformat()
        ob.enrichment = merged
        session.commit()
        _feed_key_audit(session, user, f"observable.lookup.{provider}", provider)
        return _redirect_flash(back, f"{_FEED_DISPLAY_NAMES[provider]} live lookup complete.")
    error = result.error or "unknown error"
    quota_kind = "quota/rate limit" if (result.http_status == 429 or "quota" in error.lower()) else "error"
    return _redirect_flash(
        back, f"{_FEED_DISPLAY_NAMES[provider]} live lookup failed ({quota_kind}): {error}", "error"
    )


# ------------------------- CVEs -------------------------


@app.get("/ui/cves", response_class=HTMLResponse)
def ui_cves(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    vendor: str | None = None,
    severity: str | None = None,
    only_kev: bool = False,
    only_microsoft: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(CVE).order_by(CVE.kev.desc(), CVE.updated_at.desc())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                CVE.cve_id.ilike(like.upper()),
                CVE.vendor.ilike(like),
                CVE.product.ilike(like),
                CVE.description.ilike(like),
            )
        )
    if vendor:
        stmt = stmt.where(CVE.vendor.ilike(f"%{vendor}%"))
    if severity:
        stmt = stmt.where(CVE.severity == severity)
    if only_kev:
        stmt = stmt.where(CVE.kev.is_(True))
    if only_microsoft:
        stmt = stmt.where(CVE.is_microsoft.is_(True))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    cves = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {
        "q": q,
        "vendor": vendor,
        "severity": severity,
        "only_kev": only_kev,
        "only_microsoft": only_microsoft,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(
            q=q,
            vendor=vendor,
            severity=severity,
            only_kev="true" if only_kev else None,
            only_microsoft="true" if only_microsoft else None,
        ),
    }
    return templates.TemplateResponse(
        request, "cves.html", {"cves": cves, "total": total, "filters": filters}
    )


@app.get("/ui/cves/{cve_id}", response_class=HTMLResponse)
def ui_cve_detail(cve_id: str, request: Request, session: Session = Depends(get_session)):
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id.upper()))
    if not cve:
        raise HTTPException(404)
    needle = f"%{cve.cve_id}%"
    articles = list(
        session.scalars(
            select(Article)
            .where(or_(Article.title.ilike(needle), Article.extracted_text.ilike(needle)))
            .limit(50)
        )
    )
    return templates.TemplateResponse(request, "cve_detail.html", {"cve": cve, "articles": articles})


# ------------------------- entities -------------------------


@app.get("/ui/entities", response_class=HTMLResponse)
def ui_entities(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    type: str | None = None,
    tag: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Entity).order_by(Entity.type, Entity.canonical_name)
    if q:
        stmt = stmt.where(Entity.canonical_name.ilike(f"%{q}%"))
    if type:
        stmt = stmt.where(Entity.type == type)
    if tag:
        stmt = stmt.where(_tag_filter(Entity.tags, tag))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    entities = list(session.scalars(stmt.offset(offset).limit(limit)))
    available_types = [
        t for (t,) in session.execute(select(Entity.type).group_by(Entity.type).order_by(Entity.type)).all()
    ]
    filters = {
        "q": q,
        "type": type,
        "tag": tag,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(q=q, type=type, tag=tag),
    }
    return templates.TemplateResponse(
        request,
        "entities.html",
        {"entities": entities, "total": total, "filters": filters, "available_types": available_types},
    )


@app.get("/ui/entities/{entity_id}", response_class=HTMLResponse)
def ui_entity_detail(entity_id: int, request: Request, session: Session = Depends(get_session)):
    ent = session.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404)
    out_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.source_type == ent.type, Relationship.source_id == ent.id)
            .limit(2000)
        )
    )
    in_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.target_type == ent.type, Relationship.target_id == ent.id)
            .limit(2000)
        )
    )

    related_observables: list[tuple[Observable, str]] = []
    related_entities: list[tuple[Entity, str, str]] = []
    for r in out_rels:
        target = _resolve_rel_target(session, r.target_type, r.target_id)
        if target is None:
            continue
        if target["kind"] == "observable":
            o = session.get(Observable, target["id"])
            if o is not None:
                related_observables.append((o, r.relationship_type))
        else:
            e2 = session.get(Entity, target["id"])
            if e2 is not None and e2.id != ent.id:
                related_entities.append((e2, r.relationship_type, "out"))
    for r in in_rels:
        src = _resolve_rel_target(session, r.source_type, r.source_id)
        if src is None or src["kind"] != "entity":
            continue
        e2 = session.get(Entity, src["id"])
        if e2 is not None and e2.id != ent.id:
            related_entities.append((e2, r.relationship_type, "in"))

    related_observables.sort(key=lambda t: t[0].risk_score, reverse=True)
    related_observables = related_observables[:500]
    related_entities = related_entities[:200]

    rows = session.execute(
        select(Article)
        .join(EntityMention, EntityMention.article_id == Article.id)
        .where(EntityMention.entity_id == ent.id)
        .order_by(Article.id.desc())
        .limit(50)
    ).all()
    articles = [a for (a,) in rows]
    return templates.TemplateResponse(
        request,
        "entity_detail.html",
        {
            "entity": ent,
            "related_observables": related_observables,
            "related_entities": related_entities,
            "articles": articles,
        },
    )


# ------------------------- reviews -------------------------

_BULK_ACTIONS = {"approve": "true_positive", "reject": "false_positive"}


@app.post("/ui/reviews/bulk")
def ui_reviews_bulk(
    request: Request,
    session: Session = Depends(get_session),
    review_ids: list[int] = Form(default=[]),
    action: str = Form(default=""),
    csrf: str = Form(""),
):
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/ui/reviews", "Bad CSRF token — action rejected.", "error")
    disposition = _BULK_ACTIONS.get(action)
    if disposition is None:
        return _redirect_flash("/ui/reviews", f"Unknown bulk action: {action or '(none)'}", "error")
    rows = list(
        session.scalars(
            select(AnalystReview).where(
                AnalystReview.id.in_(review_ids or []), AnalystReview.status == "open"
            )
        )
    )
    now = datetime.now(UTC)
    # Attribute the dispositions to the acting user (column already exists).
    actor = _acting_username(request)
    for row in rows:
        row.status = "closed"
        row.disposition = disposition
        row.reviewed_at = now
        if not row.analyst:
            row.analyst = actor
    session.commit()
    from scry.audit import record

    record(
        session,
        action="review.bulk",
        actor=actor,
        target_type="analyst_review",
        detail={"action": action, "count": len(rows)},
    )
    verb = "approved" if action == "approve" else "rejected"
    return _redirect_flash("/ui/reviews", f"{len(rows)} reviews {verb}")


def _acting_username(request: Request) -> str:
    """The signed-in user behind a /ui/* POST ('system' in legacy open mode)."""
    user = getattr(request.state, "user", None)
    return user.username if user is not None else "system"


@app.get("/ui/reviews", response_class=HTMLResponse)
def ui_reviews(
    request: Request,
    session: Session = Depends(get_session),
    status: str = "open",
    item_type: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(AnalystReview).order_by(AnalystReview.id.desc())
    if status and status != "any":
        stmt = stmt.where(AnalystReview.status == status)
    if item_type:
        stmt = stmt.where(AnalystReview.item_type == item_type)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {
        "status": status,
        "item_type": item_type,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(status=status, item_type=item_type),
    }
    raw_cookie = request.cookies.get(SESSION_COOKIE)
    return templates.TemplateResponse(
        request,
        "reviews.html",
        {
            "rows": rows,
            "total": total,
            "filters": filters,
            "csrf": _admin_csrf_token(raw_cookie) if raw_cookie else "",
        },
    )


@app.get("/ui/reviews/{review_id}", response_class=HTMLResponse)
def ui_review_detail(review_id: int, request: Request, session: Session = Depends(get_session)):
    r = session.get(AnalystReview, review_id)
    if not r:
        raise HTTPException(404)
    linked_url = None
    if r.item_type == "observable":
        linked_url = f"/ui/observables/{r.item_id}"
    elif r.item_type == "claim":
        c = session.get(Claim, r.item_id)
        if c is not None:
            linked_url = f"/ui/articles/{c.article_id}"
    elif r.item_type == "entity":
        linked_url = f"/ui/entities/{r.item_id}"
    correction_json = json.dumps(r.correction or {}, indent=2, default=str) if r.correction else ""
    raw_cookie = request.cookies.get(SESSION_COOKIE)
    return templates.TemplateResponse(
        request,
        "review_detail.html",
        {
            "review": r,
            "linked_url": linked_url,
            "correction_json": correction_json,
            "csrf": _admin_csrf_token(raw_cookie) if raw_cookie else "",
        },
    )


@app.post("/ui/reviews/{review_id}", response_class=HTMLResponse)
def ui_review_patch(
    review_id: int,
    request: Request,
    session: Session = Depends(get_session),
    status: str | None = Form(None),
    disposition: str | None = Form(None),
    analyst: str | None = Form(None),
    comments: str | None = Form(None),
    csrf: str = Form(""),
):
    from scry.review import ReviewQueue

    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(f"/ui/reviews/{review_id}", "Bad CSRF token — action rejected.", "error")
    actor = _acting_username(request)
    queue = ReviewQueue(session)
    queue.update(
        review_id,
        status=status or None,
        disposition=disposition or None,
        # Attribute to the acting user unless the form names an analyst.
        analyst=analyst or actor,
        comments=comments or None,
        correction=None,
    )
    from scry.audit import record

    record(
        session,
        action="review.update",
        actor=actor,
        target_type="analyst_review",
        target_id=review_id,
        detail={"status": status, "disposition": disposition},
    )
    return _redirect_flash(f"/ui/reviews/{review_id}", f"Review #{review_id} updated")


# ------------------------- alerts -------------------------


@app.get("/ui/alerts", response_class=HTMLResponse)
def ui_alerts(
    request: Request,
    session: Session = Depends(get_session),
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Alert).order_by(Alert.id.desc())
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    alerts = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {"limit": limit, "offset": offset, "qs": ""}
    from scry.alerting.channels import channel_status
    from scry.enrichment.provider_settings import PROVIDER_META, load_provider_states

    states = load_provider_states(session)
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "alerts": alerts,
            "total": total,
            "filters": filters,
            "channels": channel_status(),
            "outbound_enabled": get_settings().enable_outbound_alerts,
            "enrichment_providers": [states[name].as_dict() for name in PROVIDER_META],
        },
    )


# ------------------------- tags -------------------------

_TAG_BUCKET_BREAKS = (50, 200, 800)


@app.get("/ui/tags", response_class=HTMLResponse)
def ui_tags(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
):
    counter: Counter[str] = Counter()
    for (tags_json,) in session.execute(select(Observable.tags)):
        for t in tags_json or []:
            counter[t] += 1
    for (tags_json,) in session.execute(select(Article.tags)):
        for t in tags_json or []:
            counter[t] += 1
    for (tags_json,) in session.execute(select(Entity.tags)):
        for t in tags_json or []:
            counter[t] += 1

    if q:
        needle = q.lower()
        counter = Counter({t: n for t, n in counter.items() if needle in t.lower()})

    buckets: list[tuple[str, int, str]] = []
    for tag, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
        if count >= _TAG_BUCKET_BREAKS[2]:
            size = "xl"
        elif count >= _TAG_BUCKET_BREAKS[1]:
            size = "l"
        elif count >= _TAG_BUCKET_BREAKS[0]:
            size = "m"
        else:
            size = "s"
        buckets.append((tag, count, size))

    return templates.TemplateResponse(request, "tags.html", {"tag_buckets": buckets, "filters": {"q": q}})


@app.get("/ui/tags/{tag:path}", response_class=HTMLResponse)
def ui_tag_detail(tag: str, request: Request, session: Session = Depends(get_session)):
    decoded = re.sub(r"\+", " ", tag)
    observables = list(
        session.scalars(
            select(Observable)
            .where(_tag_filter(Observable.tags, decoded))
            .order_by(Observable.risk_score.desc())
            .limit(500)
        )
    )
    articles = list(
        session.scalars(
            select(Article).where(_tag_filter(Article.tags, decoded)).order_by(Article.id.desc()).limit(200)
        )
    )
    entities = list(
        session.scalars(
            select(Entity).where(_tag_filter(Entity.tags, decoded)).order_by(Entity.canonical_name).limit(200)
        )
    )
    return templates.TemplateResponse(
        request,
        "tag_detail.html",
        {"tag": decoded, "observables": observables, "articles": articles, "entities": entities},
    )


# ------------------------- sources -------------------------


@app.get("/ui/sources", response_class=HTMLResponse)
def ui_sources(request: Request, session: Session = Depends(get_session)):
    sources = list(
        session.scalars(select(Source).order_by(Source.enabled.desc(), Source.baseline_confidence.desc()))
    )
    enabled_count = sum(1 for s in sources if s.enabled)
    user = getattr(request.state, "user", None)
    raw_cookie = request.cookies.get(SESSION_COOKIE)
    return templates.TemplateResponse(
        request,
        "sources.html",
        {
            "sources": sources,
            "total": len(sources),
            "enabled_count": enabled_count,
            "is_admin": user is not None and user.role == "admin",
            "csrf": _admin_csrf_token(raw_cookie) if raw_cookie else "",
            "collection_window_days": _collection_window_days(session),
        },
    )


@app.post("/ui/sources/{source_id}/toggle")
def ui_source_toggle(
    request: Request,
    source_id: int,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    """Flip Source.enabled — admin-only (v0.7.0 step 1).

    Collection is global: the toggle changes what every user collects. The
    runtime value lives in the DB and survives restarts because
    SourceRegistry.sync_from_yaml only applies yaml ``enabled`` at creation.
    """
    user = getattr(request.state, "user", None)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    if user.role != "admin":
        return templates.TemplateResponse(request, "403.html", {}, status_code=403)
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash("/ui/sources", "Bad CSRF token — action rejected.", "error")
    source = session.get(Source, source_id)
    if source is None:
        return _redirect_flash("/ui/sources", f"Unknown source #{source_id}.", "error")
    source.enabled = not source.enabled
    session.flush()
    from scry.audit import record

    record(
        session,
        action="source.toggle",
        actor=user.username,
        target_type="source",
        target_id=source.id,
        detail={"name": source.name, "enabled": source.enabled},
    )
    state = "enabled — it will be collected" if source.enabled else "disabled — collection skipped"
    return _redirect_flash("/ui/sources", f"{source.name} is now {state}.")


# ------------------------- search -------------------------


@app.get("/ui/search", response_class=HTMLResponse)
def ui_search(request: Request, q: str = "", session: Session = Depends(get_session)):
    from scry.search import full_text_search

    hits = full_text_search(session, q, limit=50) if q else []
    return templates.TemplateResponse(
        request,
        "search.html",
        {"q": q, "hits": hits, "enable_ai_search": get_settings().enable_ai_search},
    )


# ========================= Intel Feeds — Threat Feeds =========================

# ------------------------- per-user feed keys (v0.5.0 step 6) -------------------------

# Key-resolution rule (FEATURES.md): user-triggered enrichment uses the ACTING
# USER's personal VT/OTX keys; background/scheduled jobs keep the SYSTEM keys
# (env/DB chain, managed on the Alerts page). A user without a personal key
# cannot run that provider but sees all shared enriched data.

_PERSONAL_KEY_PROVIDERS = ("virustotal", "otx")
_FEED_DISPLAY_NAMES = {"virustotal": "VirusTotal", "otx": "AlienVault OTX"}
# Result-count keys used by EnrichmentEngine.run_external_enrichment_batch.
_PROVIDER_COUNT_KEYS = {"virustotal": "vt_enriched", "otx": "otx_enriched"}
_ENRICH_UNENRICHED_CAP = 50


def _feed_key_audit(session: Session, actor: User, action: str, provider: str) -> None:
    from scry.audit import record

    record(
        session,
        action=action,
        actor=actor.username,
        target_type="user",
        target_id=actor.id,
        detail={"provider": provider},
    )


def _my_keys_context(request: Request, session: Session) -> dict | None:
    """'My API keys' card data for the signed-in user; None when anonymous."""
    state_user = getattr(request.state, "user", None)
    if state_user is None:
        return None
    user = session.get(User, state_user.id)
    if user is None:
        return None
    raw = request.cookies.get(SESSION_COOKIE)
    cards = []
    for provider in _PERSONAL_KEY_PROVIDERS:
        row = get_key(session, user.id, provider)
        cards.append(
            {
                "provider": provider,
                "display_name": _FEED_DISPLAY_NAMES[provider],
                "has_key": row is not None,
                "masked": mask(get_decrypted_key(session, user.id, provider)) if row else "",
                "last_test_at": row.last_test_at if row else None,
                "last_test_ok": row.last_test_ok if row else None,
                "last_test_error": row.last_test_error if row else None,
            }
        )
    return {"cards": cards, "csrf": _admin_csrf_token(raw) if raw else ""}


def _signed_in_user(request: Request, session: Session) -> User | None:
    """The acting user for a UI POST, or None → caller redirects to /login."""
    state_user = getattr(request.state, "user", None)
    if state_user is None:
        return None
    return session.get(User, state_user.id)


# ------------------------- OTX pulse subscriptions (v0.6.0 step 1) -------------------------


def _otx_subs_context(request: Request, session: Session) -> dict | None:
    """'OTX pulse subscriptions' card data; None when anonymous."""
    state_user = getattr(request.state, "user", None)
    if state_user is None:
        return None
    raw = request.cookies.get(SESSION_COOKIE)
    subs = load_subscriptions()
    stats = last_run_stats(session, subs)
    for stat in stats.values():
        at = stat.get("at")
        if isinstance(at, str):
            with contextlib.suppress(ValueError):
                stat["at"] = datetime.fromisoformat(at)
    return {
        "csrf": _admin_csrf_token(raw) if raw else "",
        "subscriptions": [
            {
                "name": s.name,
                "query": s.query,
                "tags": s.tags,
                "max_pulse_age_days": s.max_pulse_age_days,
                "limit": s.limit,
                "last_run": stats.get(s.name) or {},
            }
            for s in subs
        ],
    }


def _summarize_otx_results(results: dict[str, dict[str, int]]) -> str:
    parts = []
    for name, counts in results.items():
        bits = []
        for key in ("added", "updated", "skipped", "filtered"):
            if counts.get(key):
                bits.append(f"{key} {counts[key]}")
        if counts.get("error"):
            bits.append("error")
        parts.append(f"{name}: {', '.join(bits) if bits else 'nothing new'}")
    return "; ".join(parts) if parts else "no subscriptions configured"


@app.post("/ui/intel-feeds/otx-pull")
def ui_otx_pull(
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    subscription: str = Form(""),
):
    """Pull OTX pulses for one subscription (or all) as the acting user.

    Uses the acting user's PERSONAL OTX key (locked v0.5 rule) — never the
    system key, never any key material in flashes or logs.
    """
    user = _signed_in_user(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    back = "/ui/intel-feeds/threat-feeds"
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(back, "Bad CSRF token — action rejected.", "error")

    api_key, _key_source = resolve_key(session, user)
    if not api_key:
        return _redirect_flash(
            back,
            "OTX pulse pull disabled: save a personal OTX key in 'My API keys' above first.",
            "error",
        )

    subs = load_subscriptions()
    name = subscription.strip()
    if name:
        subs = [s for s in subs if s.name == name]
        if not subs:
            return _redirect_flash(back, f"Unknown OTX pulse subscription {name!r}.", "error")

    results = pull_all(session, api_key=api_key, subscriptions=subs)
    _feed_key_audit(session, user, "otx_pulse.pull", name or "*")
    summary = _summarize_otx_results(results)
    return _redirect_flash(back, f"OTX pulse pull complete — {summary}.")


@app.post("/ui/intel-feeds/my-keys/{provider}/save")
def ui_my_key_save(
    provider: str,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
    api_key: str = Form(""),
):
    user = _signed_in_user(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    back = "/ui/intel-feeds/threat-feeds"
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(back, "Bad CSRF token — action rejected.", "error")
    if provider not in _PERSONAL_KEY_PROVIDERS:
        return _redirect_flash(back, f"Unknown provider {provider!r}.", "error")
    api_key = api_key.strip()
    if not api_key:
        return _redirect_flash(back, "API key must not be empty.", "error")
    set_key(session, user.id, provider, api_key)
    session.commit()
    _feed_key_audit(session, user, "feed_key.save", provider)
    return _redirect_flash(back, f"{_FEED_DISPLAY_NAMES[provider]} key saved ({mask(api_key)}).")


@app.post("/ui/intel-feeds/my-keys/{provider}/test")
def ui_my_key_test(
    provider: str,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    user = _signed_in_user(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    back = "/ui/intel-feeds/threat-feeds"
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(back, "Bad CSRF token — action rejected.", "error")
    if provider not in _PERSONAL_KEY_PROVIDERS:
        return _redirect_flash(back, f"Unknown provider {provider!r}.", "error")
    row = get_key(session, user.id, provider)
    if row is None:
        return _redirect_flash(back, f"No personal {_FEED_DISPLAY_NAMES[provider]} key saved yet.", "error")
    key = get_decrypted_key(session, user.id, provider)
    ok, error = test_key(provider, key)
    record_test_result(session, row, ok, error)
    session.commit()
    _feed_key_audit(session, user, "feed_key.test", provider)
    if ok:
        return _redirect_flash(back, f"{_FEED_DISPLAY_NAMES[provider]} key: Connected.")
    return _redirect_flash(
        back, f"{_FEED_DISPLAY_NAMES[provider]} key test failed ({error or 'unknown error'}).", "error"
    )


@app.post("/ui/intel-feeds/my-keys/{provider}/remove")
def ui_my_key_remove(
    provider: str,
    request: Request,
    session: Session = Depends(get_session),
    csrf: str = Form(""),
):
    user = _signed_in_user(request, session)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    back = "/ui/intel-feeds/threat-feeds"
    if not _check_admin_csrf(request, csrf):
        return _redirect_flash(back, "Bad CSRF token — action rejected.", "error")
    if provider not in _PERSONAL_KEY_PROVIDERS:
        return _redirect_flash(back, f"Unknown provider {provider!r}.", "error")
    removed = delete_key(session, user.id, provider)
    session.commit()
    if removed:
        _feed_key_audit(session, user, "feed_key.remove", provider)
        return _redirect_flash(back, f"{_FEED_DISPLAY_NAMES[provider]} key removed.")
    return _redirect_flash(back, f"No personal {_FEED_DISPLAY_NAMES[provider]} key to remove.", "error")


@app.get("/ui/intel-feeds/threat-feeds", response_class=HTMLResponse)
def ui_threat_feeds(
    request: Request,
    session: Session = Depends(get_session),
    q: str = "",
    category: str = "",
    network: str = "",
    country: str = "",
    sort: str = "date_desc",
    limit: int = Query(50, ge=1, le=200),
    offset: int = 0,
):
    from sqlalchemy import String as _String
    from sqlalchemy import cast as _cast

    stmt = select(ThreatFeedItem)

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                ThreatFeedItem.title.ilike(like),
                ThreatFeedItem.content.ilike(like),
                ThreatFeedItem.threat_actors.ilike(like),
                ThreatFeedItem.victim_site.ilike(like),
                ThreatFeedItem.victim_organization.ilike(like),
                _cast(ThreatFeedItem.tags, _String).ilike(like),
            )
        )
    if category:
        stmt = stmt.where(ThreatFeedItem.category == category)
    if network:
        stmt = stmt.where(ThreatFeedItem.network == network)
    if country:
        stmt = stmt.where(ThreatFeedItem.victim_country == country)

    # Sorting
    if sort == "risk_desc":
        stmt = stmt.order_by(ThreatFeedItem.risk_score.desc().nullslast(), ThreatFeedItem.date.desc())
    elif sort == "date_asc":
        stmt = stmt.order_by(ThreatFeedItem.date.asc())
    else:
        stmt = stmt.order_by(ThreatFeedItem.date.desc().nullslast())

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = list(session.scalars(stmt.limit(limit).offset(offset)).all())

    # Aggregates for filters (computed once across all records, not just filtered)
    all_cats = session.execute(
        select(ThreatFeedItem.category, func.count(ThreatFeedItem.id).label("c"))
        .group_by(ThreatFeedItem.category)
        .order_by(func.count(ThreatFeedItem.id).desc())
    ).all()
    cat_counts = [(row[0] or "Unknown", row[1]) for row in all_cats if row[0]]

    networks = [
        row[0]
        for row in session.execute(
            select(ThreatFeedItem.network).distinct().where(ThreatFeedItem.network.isnot(None))
        ).all()
    ]

    countries = [
        row[0]
        for row in session.execute(
            select(ThreatFeedItem.victim_country)
            .where(ThreatFeedItem.victim_country.isnot(None))
            .group_by(ThreatFeedItem.victim_country)
            .order_by(func.count(ThreatFeedItem.id).desc())
            .limit(40)
        ).all()
    ]

    qs = _qs_extra(q=q, category=category, network=network, country=country, sort=sort)
    filters = dict(
        q=q, category=category, network=network, country=country, sort=sort, offset=offset, limit=limit, qs=qs
    )

    return templates.TemplateResponse(
        request,
        "threat_feeds.html",
        {
            "items": items,
            "total": total,
            "cat_counts": cat_counts,
            "networks": sorted(networks),
            "countries": countries,
            "categories": [c for c, _ in cat_counts],
            "filters": filters,
            "my_keys": _my_keys_context(request, session),
            "otx_subs": _otx_subs_context(request, session),
        },
    )


@app.get("/ui/intel-feeds/threat-feeds/{item_id}", response_class=HTMLResponse)
def ui_threat_feed_detail(item_id: int, request: Request, session: Session = Depends(get_session)):
    item = session.get(ThreatFeedItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Threat feed item not found")

    # Related items from same actor
    related = []
    if item.threat_actors:
        related = list(
            session.scalars(
                select(ThreatFeedItem)
                .where(ThreatFeedItem.threat_actors == item.threat_actors)
                .where(ThreatFeedItem.id != item.id)
                .order_by(ThreatFeedItem.date.desc())
                .limit(10)
            ).all()
        )

    return templates.TemplateResponse(
        request,
        "threat_feed_detail.html",
        {
            "item": item,
            "related": related,
        },
    )


# ========================= Intel Feeds — Ransomware Feeds =========================


@app.get("/ui/intel-feeds/ransomware-feeds", response_class=HTMLResponse)
def ui_ransomware_feeds(
    request: Request,
    session: Session = Depends(get_session),
    q: str = "",
    group: str = "",
    country: str = "",
    industry: str = "",
    sort: str = "discovered_desc",
    limit: int = Query(50, ge=1, le=200),
    offset: int = 0,
):
    from sqlalchemy import String as _String
    from sqlalchemy import cast as _cast

    stmt = select(RansomwareFeedItem)

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                RansomwareFeedItem.post_title.ilike(like),
                RansomwareFeedItem.description.ilike(like),
                RansomwareFeedItem.victim_website.ilike(like),
                RansomwareFeedItem.group_name.ilike(like),
                _cast(RansomwareFeedItem.tags, _String).ilike(like),
            )
        )
    if group:
        stmt = stmt.where(RansomwareFeedItem.group_name == group)
    if country:
        stmt = stmt.where(RansomwareFeedItem.victim_country == country)
    if industry:
        stmt = stmt.where(RansomwareFeedItem.activity == industry)

    # Sorting
    if sort == "risk_desc":
        stmt = stmt.order_by(
            RansomwareFeedItem.risk_score.desc().nullslast(), RansomwareFeedItem.discovered.desc()
        )
    elif sort == "discovered_asc":
        stmt = stmt.order_by(RansomwareFeedItem.discovered.asc())
    elif sort == "published_desc":
        stmt = stmt.order_by(RansomwareFeedItem.published.desc().nullslast())
    else:
        stmt = stmt.order_by(RansomwareFeedItem.discovered.desc().nullslast())

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = list(session.scalars(stmt.limit(limit).offset(offset)).all())

    # Aggregates (global, not filtered)
    group_counts = [
        (row[0], row[1])
        for row in session.execute(
            select(RansomwareFeedItem.group_name, func.count(RansomwareFeedItem.id).label("c"))
            .where(RansomwareFeedItem.group_name.isnot(None))
            .group_by(RansomwareFeedItem.group_name)
            .order_by(func.count(RansomwareFeedItem.id).desc())
        ).all()
        if row[0]
    ]
    groups = [g for g, _ in group_counts]

    countries = [
        row[0]
        for row in session.execute(
            select(RansomwareFeedItem.victim_country)
            .where(RansomwareFeedItem.victim_country.isnot(None))
            .group_by(RansomwareFeedItem.victim_country)
            .order_by(func.count(RansomwareFeedItem.id).desc())
            .limit(60)
        ).all()
    ]

    industries = [
        row[0]
        for row in session.execute(
            select(RansomwareFeedItem.activity)
            .where(RansomwareFeedItem.activity.isnot(None))
            .group_by(RansomwareFeedItem.activity)
            .order_by(func.count(RansomwareFeedItem.id).desc())
        ).all()
    ]

    qs = _qs_extra(q=q, group=group, country=country, industry=industry, sort=sort)
    filters = dict(
        q=q, group=group, country=country, industry=industry, sort=sort, offset=offset, limit=limit, qs=qs
    )

    return templates.TemplateResponse(
        request,
        "ransomware_feeds.html",
        {
            "items": items,
            "total": total,
            "group_counts": group_counts,
            "groups": groups,
            "countries": countries,
            "industries": industries,
            "filters": filters,
        },
    )


@app.get("/ui/intel-feeds/ransomware-feeds/{item_id}", response_class=HTMLResponse)
def ui_ransomware_feed_detail(item_id: int, request: Request, session: Session = Depends(get_session)):
    item = session.get(RansomwareFeedItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Ransomware feed item not found")

    # Other victims from the same group (most recent 10)
    related = []
    if item.group_name:
        related = list(
            session.scalars(
                select(RansomwareFeedItem)
                .where(RansomwareFeedItem.group_name == item.group_name)
                .where(RansomwareFeedItem.id != item.id)
                .order_by(RansomwareFeedItem.discovered.desc())
                .limit(10)
            ).all()
        )

    # Other victims from same country (different group, most recent 8)
    country_peers = []
    if item.victim_country:
        country_peers = list(
            session.scalars(
                select(RansomwareFeedItem)
                .where(RansomwareFeedItem.victim_country == item.victim_country)
                .where(RansomwareFeedItem.id != item.id)
                .order_by(RansomwareFeedItem.discovered.desc())
                .limit(8)
            ).all()
        )

    return templates.TemplateResponse(
        request,
        "ransomware_feed_detail.html",
        {
            "item": item,
            "related": related,
            "country_peers": country_peers,
        },
    )
