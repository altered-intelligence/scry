"""MCP server — let AI clients query the local scry intel DB over stdio.

Start it with `scry mcp` or `python -m scry.mcp_server`, then point an MCP
client (Claude Desktop, Cursor, …) at that command. Requires the `mcp`
extra: `pip install scry[mcp]`.

Each tool opens its own DB session via `session_scope` against the same
SQLite file the web app uses. Access is process-local, so the optional HTTP
API key (CTI_API_KEY) does not apply here. stdout carries MCP JSON-RPC, so
nothing may print to it — all logging goes to stderr (see scry/logging.py).
"""

from __future__ import annotations

import logging
import sys
import time
from importlib import metadata as importlib_metadata
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scry.api.ai import _LINK_BY_TYPE, AskError, answer_question
from scry.api.router import compute_stats
from scry.db import session_scope
from scry.models import Alert, Observable
from scry.search import full_text_search

_START = time.monotonic()

__all__ = [
    "build_server",
    "main",
    "tool_scry_alerts",
    "tool_scry_ask",
    "tool_scry_health",
    "tool_scry_observables",
    "tool_scry_search",
    "tool_scry_stats",
]


def _version() -> str:
    try:
        return importlib_metadata.version("scry")
    except importlib_metadata.PackageNotFoundError:
        return "unknown"


# ---------------------------------------------------------------------------
# Tool bodies — plain functions taking an open Session so tests can call them
# directly with the conftest fixtures. The FastMCP wrappers below only add
# session management.
# ---------------------------------------------------------------------------


def tool_scry_health(session: Session) -> dict[str, Any]:
    """Health snapshot: status, app version, uptime, and DB connectivity."""
    try:
        session.scalar(select(func.count(Observable.id)))
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "version": _version(),
        "uptime_seconds": int(time.monotonic() - _START),
        "db_ok": db_ok,
    }


def tool_scry_stats(session: Session) -> dict[str, Any]:
    """Record counts for every collection type (same numbers as GET /stats)."""
    return compute_stats(session)


def tool_scry_search(session: Session, query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Full-text search across articles, observables, entities, and claims."""
    out: list[dict[str, Any]] = []
    for h in full_text_search(session, query, limit=limit):
        link_tpl = _LINK_BY_TYPE.get(h.object_type)
        out.append(
            {
                "object_type": h.object_type,
                "object_id": h.object_id,
                "title": h.title or "",
                "snippet": h.snippet,
                "score": h.score,
                "link": link_tpl.format(id=h.object_id) if link_tpl else "",
            }
        )
    return out


def tool_scry_observables(
    session: Session, query: str = "", type: str = "", limit: int = 25
) -> list[dict[str, Any]]:
    """List observables (IOCs), optionally filtered by value substring and/or exact type."""
    stmt = select(Observable).order_by(Observable.risk_score.desc(), Observable.id.desc())
    if query:
        stmt = stmt.where(Observable.normalized_value.ilike(f"%{query.lower()}%"))
    if type:
        stmt = stmt.where(Observable.type == type)
    rows = session.scalars(stmt.limit(limit)).all()
    return [
        {
            "id": o.id,
            "type": o.type,
            "value": o.value,
            "normalized_value": o.normalized_value,
            "risk_score": o.risk_score,
            "status": o.status,
            "tags": o.tags or [],
            "first_seen": o.first_seen.isoformat() if o.first_seen else None,
            "last_seen": o.last_seen.isoformat() if o.last_seen else None,
        }
        for o in rows
    ]


def tool_scry_alerts(
    session: Session, limit: int = 20, include_acknowledged: bool = False
) -> list[dict[str, Any]]:
    """Recent alerts, newest first; delivered (acknowledged) ones are excluded unless requested."""
    stmt = select(Alert).order_by(Alert.id.desc())
    if not include_acknowledged:
        stmt = stmt.where(Alert.delivered.is_(False))
    rows = session.scalars(stmt.limit(limit)).all()
    return [
        {
            "id": a.id,
            "trigger": a.trigger,
            "title": a.title,
            "severity": a.severity,
            "confidence": a.confidence,
            "delivered": a.delivered,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows
    ]


async def tool_scry_ask(session: Session, question: str) -> dict[str, Any]:
    """Ask a natural-language question; answers are grounded in the collected intel.

    Returns an error dict (never raises) when no LLM provider is available.
    """
    try:
        return await answer_question(session, question)
    except AskError as exc:
        return {"error": exc.detail, "error_status": exc.status_code, "sources": []}


# ---------------------------------------------------------------------------
# FastMCP wiring
# ---------------------------------------------------------------------------


def build_server():
    """Build the FastMCP server with all six scry tools registered."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("scry")

    @mcp.tool()
    def scry_health() -> dict:
        """Check scry health: app version, uptime, and DB connectivity."""
        try:
            with session_scope() as session:
                return tool_scry_health(session)
        except Exception as exc:  # DB down — report, don't crash the client
            return {"status": "degraded", "version": _version(), "db_ok": False, "error": str(exc)}

    @mcp.tool()
    def scry_stats() -> dict:
        """Record counts for every collection type (articles, observables, CVEs, alerts…)."""
        with session_scope() as session:
            return tool_scry_stats(session)

    @mcp.tool()
    def scry_search(query: str, limit: int = 10) -> list[dict]:
        """Search the intel database across articles, observables, entities, and claims."""
        with session_scope() as session:
            return tool_scry_search(session, query, limit=limit)

    @mcp.tool()
    def scry_observables(query: str = "", type: str = "", limit: int = 25) -> list[dict]:
        """List observables (IOCs), optionally filtered by value substring and/or exact type."""
        with session_scope() as session:
            return tool_scry_observables(session, query=query, type=type, limit=limit)

    @mcp.tool()
    def scry_alerts(limit: int = 20, include_acknowledged: bool = False) -> list[dict]:
        """Recent alerts, newest first; acknowledged (delivered) alerts excluded by default."""
        with session_scope() as session:
            return tool_scry_alerts(session, limit=limit, include_acknowledged=include_acknowledged)

    @mcp.tool()
    async def scry_ask(question: str) -> dict:
        """Ask a question in plain English and get a grounded answer with [n] source citations."""
        with session_scope() as session:
            return await tool_scry_ask(session, question)

    return mcp


def _force_stderr_logging() -> None:
    """stdio carries MCP JSON-RPC — root logging must never write to stdout."""
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "stream", None) is sys.stdout:
            root.removeHandler(h)
    if not any(getattr(h, "stream", None) is sys.stderr for h in root.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
    root.setLevel(logging.INFO)


def main() -> None:
    _force_stderr_logging()
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
