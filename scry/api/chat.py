"""AI Search conversation memory — ChatSession / ChatMessage endpoints.

A session groups ask exchanges so follow-up questions carry context: the ask
endpoint (scry/api/ai.py) loads the session, prepends recent turns to the
model context, and persists the exchange back onto the session. This module
holds the session CRUD routes plus the shared history/persistence helpers.

v0.5.0 step 3 (per-user chat privacy): sessions carry a nullable owner
(``ChatSession.user_id``). Requests with a resolved user (session cookie or
per-user API key, stashed on ``request.state.api_user`` by the API auth
dependency) only see and use their own sessions plus legacy owner-less ones;
master-key/legacy requests keep the shared view. The owner column may be
absent on databases that predate the migration — ``_owner_enabled`` detects
that and falls back to the legacy shared behavior.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from scry.api.deps import get_session
from scry.models import ChatMessage, ChatSession, User

chat_router = APIRouter(prefix="/api/ai", tags=["ai"])

# How many user/assistant turns are prepended as context on a follow-up ask.
HISTORY_TURNS = 8

DEFAULT_TITLE = "New conversation"
_TITLE_MAX = 80

# Cached per-engine answers to "does chat_sessions have the user_id column?"
# (existing DBs are migrated at startup; this is the belt-and-braces fallback).
_OWNER_ENABLED: dict[int, bool] = {}


def _owner_enabled(session: Session) -> bool:
    bind = session.get_bind()
    key = id(bind)
    if key not in _OWNER_ENABLED:
        cols = sa_inspect(bind).get_columns("chat_sessions")
        _OWNER_ENABLED[key] = any(c["name"] == "user_id" for c in cols)
    return _OWNER_ENABLED[key]


def _owned_filter(user: User):
    """Owner-scoped WHERE clause: own sessions + legacy owner-less ones."""
    return or_(ChatSession.user_id.is_(None), ChatSession.user_id == user.id)


def _check_owned(chat: ChatSession, user: User | None, session: Session) -> None:
    """404 (not 403) so a session's existence is never leaked across users."""
    if user is None or not _owner_enabled(session):
        return
    if chat.user_id not in (None, user.id):
        raise HTTPException(404, detail=f"Chat session {chat.id} not found")


def load_chat_session(session: Session, session_id: int, user: User | None = None) -> ChatSession:
    """Fetch a session for asking — 404 when missing/archived/not owned."""
    chat = session.get(ChatSession, session_id)
    if chat is None:
        raise HTTPException(404, detail=f"Chat session {session_id} not found")
    _check_owned(chat, user, session)
    if chat.archived:
        raise HTTPException(409, detail=f"Chat session {session_id} is archived")
    return chat


def recent_turns(session: Session, chat: ChatSession, turns: int = HISTORY_TURNS) -> list[dict[str, str]]:
    """Last N complete user/assistant pairs, oldest first, for model context."""
    rows = list(
        session.scalars(
            select(ChatMessage)
            .where(ChatMessage.session_id == chat.id, ChatMessage.role.in_(["user", "assistant"]))
            .order_by(ChatMessage.id.desc())
            .limit(turns * 2)
        )
    )
    rows.reverse()
    # Drop a dangling assistant reply with no preceding user message so the
    # list alternates user, assistant starting with the user.
    if rows and rows[0].role == "assistant":
        rows = rows[1:]
    # Keep only complete pairs (an unanswered user question carries no reply).
    if len(rows) % 2:
        rows = rows[:-1]
    return [{"role": m.role, "content": m.content} for m in rows]


def persist_exchange(
    session: Session,
    chat: ChatSession,
    question: str,
    result: dict[str, Any],
) -> None:
    """Save the user question + assistant answer onto a session."""
    session.add(ChatMessage(session_id=chat.id, role="user", content=question))
    provider_name, _, model_id = str(result.get("model") or "").partition("/")
    session.add(
        ChatMessage(
            session_id=chat.id,
            role="assistant",
            content=str(result.get("answer") or ""),
            model_provider=provider_name or None,
            model_id=model_id or None,
            sources=list(result.get("sources") or []),
            tokens_in=result.get("tokens_in"),
            tokens_out=result.get("tokens_out"),
            duration_ms=result.get("elapsed_ms"),
        )
    )
    chat.message_count += 2
    if chat.title == DEFAULT_TITLE:
        chat.title = question.strip()[:_TITLE_MAX]
    session.commit()


def _session_out(chat: ChatSession) -> dict[str, Any]:
    return {
        "id": chat.id,
        "title": chat.title,
        "message_count": chat.message_count,
        "updated_at": chat.updated_at.isoformat() if chat.updated_at else None,
        "archived": chat.archived,
    }


def _message_out(msg: ChatMessage) -> dict[str, Any]:
    return {
        "id": msg.id,
        "role": msg.role,
        "content": msg.content,
        "sources": msg.sources or [],
        "model_provider": msg.model_provider,
        "model_id": msg.model_id,
        "duration_ms": msg.duration_ms,
        "error": msg.error,
        "created_at": msg.created_at.isoformat() if msg.created_at else None,
    }


class SessionRename(BaseModel):
    id: int
    title: str = Field(min_length=1, max_length=512)


@chat_router.get("/sessions")
def list_sessions(
    request: Request,
    include_archived: bool = False,
    session: Session = Depends(get_session),
) -> dict[str, Any]:
    """Conversations visible to the caller, most recently updated first.

    With a resolved user (session cookie / per-user API key): own sessions
    plus legacy owner-less ones. Master-key / legacy requests keep the
    shared, unfiltered view.
    """
    user = getattr(request.state, "api_user", None)
    stmt = select(ChatSession).order_by(ChatSession.updated_at.desc())
    if not include_archived:
        stmt = stmt.where(ChatSession.archived.is_(False))
    if user is not None and _owner_enabled(session):
        stmt = stmt.where(_owned_filter(user))
    return {"sessions": [_session_out(c) for c in session.scalars(stmt).all()]}


@chat_router.post("/sessions")
def rename_session(
    request: Request, payload: SessionRename, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Rename a conversation."""
    chat = session.get(ChatSession, payload.id)
    if chat is None:
        raise HTTPException(404, detail=f"Chat session {payload.id} not found")
    _check_owned(chat, getattr(request.state, "api_user", None), session)
    chat.title = payload.title.strip()
    session.commit()
    return _session_out(chat)


@chat_router.delete("/sessions/{session_id}")
def delete_session(
    session_id: int, request: Request, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Hard delete a conversation (its messages cascade)."""
    chat = session.get(ChatSession, session_id)
    if chat is None:
        raise HTTPException(404, detail=f"Chat session {session_id} not found")
    _check_owned(chat, getattr(request.state, "api_user", None), session)
    session.delete(chat)
    session.commit()
    return {"deleted": session_id}


@chat_router.get("/sessions/{session_id}")
def get_session_detail(
    session_id: int, request: Request, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """One conversation with its full message history, oldest first."""
    chat = session.get(ChatSession, session_id)
    if chat is None:
        raise HTTPException(404, detail=f"Chat session {session_id} not found")
    _check_owned(chat, getattr(request.state, "api_user", None), session)
    return {**_session_out(chat), "messages": [_message_out(m) for m in chat.messages]}
