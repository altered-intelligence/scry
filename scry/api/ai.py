"""AI Search endpoints — grounded Q&A over the collected CTI data.

Answers come from a configurable LLM provider ("bring your own model"):
- local:  bundled GGUF via llama-cpp-python, embedded in the Scry process
          (no server, no cloud, no API keys) — the zero-config default
- ollama: local models served by an Ollama instance
- openai / anthropic / google / xai: frontier APIs (key stored encrypted)

Provider choice and credentials live in the llm_settings table and are
managed from the Search page. Retrieval (keyword search over collected
intel) is provider-independent.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scry.ai.errors import AskError
from scry.ai.prompts import AI_SEARCH_SYSTEM_PROMPT, build_ai_search_user_prompt
from scry.ai.providers.local import LocalLlamaProvider
from scry.ai.registry import PROVIDER_CLASSES, resolve_ai_provider
from scry.ai.registry import provider_model as _provider_model
from scry.api.chat import load_chat_session, persist_exchange, recent_turns
from scry.api.deps import get_session
from scry.audit import record
from scry.auth.dependencies import require_admin
from scry.config import get_settings
from scry.crypto import decrypt, encrypt, mask
from scry.logging import get_logger
from scry.models import LLMSetting
from scry.schemas.search import SearchHit
from scry.search import full_text_search

logger = get_logger("api.ai")

ai_router = APIRouter(prefix="/api/ai", tags=["ai"])

# UI link paths per hit type — must match how search.html builds links.
_LINK_BY_TYPE = {
    "article": "/ui/articles/{id}",
    "observable": "/ui/observables/{id}",
    "entity": "/ui/entities/{id}",
    "claim": "/ui/articles/{id}",
}

# Static metadata for the provider picker. Needs drive which config
# fields the UI shows; "auto" providers need no credentials at all.
_PROVIDER_META: dict[str, dict[str, Any]] = {
    "local": {"display_name": "Local GGUF (bundled)", "needs_api_key": False, "needs_base_url": False},
    "ollama": {"display_name": "Ollama (local server)", "needs_api_key": False, "needs_base_url": True},
    "openai": {"display_name": "OpenAI", "needs_api_key": True, "needs_base_url": True},
    "anthropic": {"display_name": "Anthropic", "needs_api_key": True, "needs_base_url": False},
    "google": {"display_name": "Google Gemini", "needs_api_key": True, "needs_base_url": False},
    "xai": {"display_name": "xAI (Grok)", "needs_api_key": True, "needs_base_url": False},
}


# Cheap English stopwords — keyword extraction for retrieval.
_STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "or",
    "of",
    "in",
    "on",
    "for",
    "to",
    "with",
    "what",
    "which",
    "who",
    "whom",
    "how",
    "when",
    "where",
    "why",
    "is",
    "are",
    "was",
    "were",
    "did",
    "does",
    "do",
    "any",
    "all",
    "this",
    "that",
    "these",
    "those",
    "there",
    "their",
    "they",
    "them",
    "have",
    "has",
    "had",
    "been",
    "being",
    "be",
    "by",
    "at",
    "as",
    "it",
    "its",
    "from",
    "about",
    "into",
    "over",
    "under",
    "than",
    "then",
    "so",
    "such",
    "can",
    "could",
    "should",
    "would",
    "will",
    "shall",
    "may",
    "might",
    "not",
    "no",
    "if",
    "me",
    "my",
    "we",
    "our",
    "you",
    "your",
    "i",
    "tell",
    "show",
    "list",
    "give",
    "summarize",
    "explain",
    "describe",
}


def _keywords(question: str) -> list[str]:
    """Significant tokens from a natural-language question (order-preserving)."""
    out: list[str] = []
    for tok in question.lower().split():
        tok = "".join(ch for ch in tok if ch.isalnum() or ch in "-_.:")
        if len(tok) >= 3 and tok not in _STOPWORDS and tok not in out:
            out.append(tok)
    return out


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    # Optional conversation memory: when set, prior turns become context and
    # the exchange is persisted onto the session (see scry/api/chat.py).
    session_id: int | None = None


class ProviderConfig(BaseModel):
    provider: str
    enabled: bool = True
    api_key: str | None = None  # None = keep existing; "" + clear_api_key clears
    clear_api_key: bool = False
    base_url: str | None = None
    default_model: str | None = None


def _provider() -> LocalLlamaProvider:
    return LocalLlamaProvider()


def _resolve_provider(session: Session):
    """Provider that will answer the next question (None if none usable)."""
    provider, _ = resolve_ai_provider(session)
    return provider


def _collect_sources(session: Session, question: str, limit: int) -> list[dict[str, Any]]:
    """Retrieve context for the question via full-text search.

    Natural-language questions don't substring-match stored text, so we run
    one search per significant keyword and merge hits, ranked by how many
    keywords matched (then first-seen order).
    """
    merged: dict[tuple[str, int], tuple[int, int, SearchHit]] = {}
    for kw_pos, kw in enumerate(_keywords(question)):
        for hit in full_text_search(session, kw, limit=limit):
            key = (hit.object_type, hit.object_id)
            if key in merged:
                count, pos, _ = merged[key]
                merged[key] = (count + 1, min(pos, kw_pos), hit)
            else:
                merged[key] = (1, kw_pos, hit)
    ranked = sorted(merged.values(), key=lambda t: (-t[0], t[1]))[:limit]

    sources: list[dict[str, Any]] = []
    for i, (_, _, h) in enumerate(ranked, start=1):
        link_tpl = _LINK_BY_TYPE.get(h.object_type)
        sources.append(
            {
                "n": i,
                "type": h.object_type,
                "title": h.title,
                "snippet": h.snippet,
                "link": link_tpl.format(id=h.object_id) if link_tpl else "",
            }
        )
    return sources


def _provider_entry(session: Session, provider_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    """One row of provider state for the UI picker."""
    row = session.query(LLMSetting).filter_by(provider=provider_id).one_or_none()
    cls = PROVIDER_CLASSES.get(provider_id)
    entry: dict[str, Any] = {
        "id": provider_id,
        "display_name": meta["display_name"],
        "needs_api_key": meta["needs_api_key"],
        "needs_base_url": meta["needs_base_url"],
        "configured": row is not None,
        "enabled": bool(row and row.enabled),
        "api_key_masked": mask(decrypt(row.api_key_encrypted)) if row else "—",
        "base_url": (row.base_url if row else "") or "",
        "default_model": (row.default_model if row else "") or "",
        "last_check_ok": (row.last_check_ok if row else None),
        "last_check_error": (row.last_check_error if row else None),
        "available": False,
        "models": [],
    }
    try:
        if cls is not None:
            if provider_id == "local":
                p = LocalLlamaProvider()
                entry["available"] = p.is_available()
                entry["models"] = (
                    [{"id": p.model_path.name, "label": f"Bundled: {p.model_path.name}"}]
                    if entry["available"]
                    else []
                )
            elif provider_id == "ollama":
                p = cls(base_url=(row.base_url if row else "") or "")
                entry["available"] = p.is_available()
                entry["models"] = [{"id": m.model_id, "label": m.label} for m in p.list_models()]
            else:
                entry["models"] = [{"id": m.model_id, "label": m.label} for m in cls().list_models()]
                entry["available"] = bool(row and row.api_key_encrypted)
    except Exception as exc:  # never let one provider break the whole list
        logger.warning("provider_entry_error", provider=provider_id, error=str(exc))
    return entry


@ai_router.get("/status")
def ai_status(session: Session = Depends(get_session)) -> dict[str, Any]:
    """Feature/model status — cheap checks only; never loads a model or pings a server."""
    settings = get_settings()
    provider = _provider()
    present = provider.is_available()
    size_mb = round(provider.model_path.stat().st_size / (1024 * 1024)) if present else None
    # Report the active provider without network probes: the DB-enabled row
    # wins; otherwise the bundled model if present; otherwise Ollama *may*
    # be there (the ask endpoint auto-detects it for real).
    row = session.query(LLMSetting).filter_by(enabled=True).first()
    if row:
        active_id = row.provider
        active_model = row.default_model or ""
    elif present:
        active_id = "local"
        active_model = provider.model_path.name
    else:
        active_id = "ollama"
        active_model = ""
    idle = getattr(provider, "idle_seconds", None)
    return {
        "enabled": settings.enable_ai_search,
        "model_path": settings.ai_search_model_path,
        "model_present": present,
        "model_loaded": provider.model_loaded,
        "model_size_mb": size_mb,
        "idle_seconds": round(idle, 1) if idle is not None else None,
        "idle_unload_s": settings.ai_idle_unload_s,
        # Provider-aware additions (status pill uses these when non-local):
        "active_provider": active_id,
        "active_display": _PROVIDER_META.get(active_id, {}).get("display_name", active_id),
        "active_model": active_model,
    }


@ai_router.get("/provider")
def ai_provider_list(session: Session = Depends(get_session)) -> dict[str, Any]:
    """All providers with their config state — powers the Search-page picker."""
    providers = [_provider_entry(session, pid, meta) for pid, meta in _PROVIDER_META.items()]
    active, active_src = resolve_ai_provider(session)
    return {
        "providers": providers,
        "active": active_src or (active.name if active else ""),
    }


@ai_router.put("/provider", dependencies=[Depends(require_admin)])
async def ai_provider_configure(
    payload: ProviderConfig, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Create/update one provider's settings (key encrypted at rest).

    Admin-only (``require_admin``): this endpoint stores LLM credentials and
    probes arbitrary base URLs with them.
    """
    meta = _PROVIDER_META.get(payload.provider)
    if meta is None:
        raise HTTPException(404, detail=f"Unknown provider '{payload.provider}'")

    row = session.query(LLMSetting).filter_by(provider=payload.provider).one_or_none()
    if row is None:
        row = LLMSetting(provider=payload.provider)
        session.add(row)

    # Stored-key exfiltration guard: the connection check below POSTs the
    # (decrypted) stored key to base_url. If the caller changes base_url
    # without re-entering the key, refuse — otherwise an attacker could point
    # the provider at their own server and harvest the stored key.
    base_url_changing = payload.base_url is not None and (payload.base_url or None) != (row.base_url or None)
    reusing_stored_key = not payload.api_key and not payload.clear_api_key and bool(row.api_key_encrypted)
    if meta["needs_api_key"] and base_url_changing and reusing_stored_key:
        raise HTTPException(
            400,
            detail=(
                "Re-enter the API key when changing the base URL — "
                "the stored key is never sent to a new endpoint."
            ),
        )

    if payload.clear_api_key:
        row.api_key_encrypted = None
    elif payload.api_key:
        row.api_key_encrypted = encrypt(payload.api_key)
    if payload.base_url is not None:
        row.base_url = payload.base_url or None
    if payload.default_model is not None:
        row.default_model = payload.default_model or None
    row.enabled = payload.enabled
    if payload.enabled:
        # One active provider at a time: enabling this row disables the rest.
        session.query(LLMSetting).filter(
            LLMSetting.provider != payload.provider, LLMSetting.enabled.is_(True)
        ).update({"enabled": False}, synchronize_session="fetch")

    # Connection check (auto-providers: file/server presence only).
    cls = PROVIDER_CLASSES[payload.provider]
    key = decrypt(row.api_key_encrypted) if row.api_key_encrypted else ""
    inst = cls(api_key=key, base_url=row.base_url or "", default_model=row.default_model or "")
    if payload.provider == "local":
        ok, err = inst.is_available(), (
            "model file missing — run: scry ai-setup" if not inst.is_available() else ""
        )
    elif payload.provider == "ollama":
        ok, err = inst.is_available(), ("" if inst.is_available() else "no Ollama server found")
    else:
        ok, err = await inst.test_connection()
    row.last_check_ok = ok
    row.last_check_error = err or None
    row.last_check_at = datetime.now(UTC)
    session.commit()

    record(
        session,
        action="ai.provider.configure",
        target_type="llm_setting",
        target_id=row.id,
        detail={"provider": payload.provider, "enabled": payload.enabled, "check_ok": ok},
    )

    entry = _provider_entry(session, payload.provider, meta)
    entry["check_ok"] = ok
    entry["check_error"] = err
    return entry


# AskError lives in scry.ai.errors (shared with reporting briefs); it is
# re-exported here via the import above so existing imports keep working.


# Appended to the system prompt when a session's prior turns are included.
_HISTORY_SYSTEM_SUFFIX = """

The analyst is continuing an ongoing conversation with you. The messages
before their new question are the conversation so far: recent prior turns,
oldest first. Use them to resolve follow-ups ("it", "that group", "which
CVEs did you mean") and to stay consistent with your earlier answers. The
grounding rules still apply: answer only from the numbered sources supplied
with the new question and cite them as [1], [2], …
"""


# ---- Prompt size budgeting ----
# The bundled local model runs a 4096-token context; an unbounded history or
# too many source snippets overflows it and the ask endpoint fails (permanent
# 502 on long chats). Budget in characters (~4 chars/token heuristic) and
# reserve room for the system prompt and the generated answer.
_PROMPT_TOKEN_BUDGET = 4096
_CHARS_PER_TOKEN = 4
_SNIPPET_CHAR_CAP = 600
_HISTORY_MSG_CHAR_CAP = 2000


def _prompt_char_budget(question: str, max_answer_tokens: int) -> int:
    """Characters available for sources + history in one ask request."""
    fixed = (
        len(AI_SEARCH_SYSTEM_PROMPT)
        + len(_HISTORY_SYSTEM_SUFFIX)
        + len(question)
        + max_answer_tokens * _CHARS_PER_TOKEN
    )
    return max(1000, _PROMPT_TOKEN_BUDGET * _CHARS_PER_TOKEN - fixed)


def _cap_sources(sources: list[dict[str, Any]], char_budget: int) -> list[dict[str, Any]]:
    """Keep as many top-ranked sources as fit the budget, snippets truncated.

    Sources are re-numbered afterwards so the [1], [2], … citations in the
    answer still line up with the list returned to the caller.
    """
    kept: list[dict[str, Any]] = []
    used = 0
    for s in sources:
        snippet = str(s.get("snippet") or "")
        if len(snippet) > _SNIPPET_CHAR_CAP:
            snippet = snippet[:_SNIPPET_CHAR_CAP] + "…"
        entry_chars = len(str(s.get("title") or "")) + len(snippet) + 32
        if kept and used + entry_chars > char_budget:
            break
        kept.append({**s, "snippet": snippet})
        used += entry_chars
    for i, s in enumerate(kept, start=1):
        s["n"] = i
    return kept


def _trim_history(history: list[dict[str, str]], char_budget: int) -> list[dict[str, str]]:
    """Keep the newest turns that fit the budget; drop the oldest pairs first.

    History alternates user/assistant, so whole pairs are trimmed from the
    front to preserve the alternation and the most recent exchange.
    """
    msgs: list[dict[str, str]] = []
    for m in history:
        content = str(m.get("content") or "")
        if len(content) > _HISTORY_MSG_CHAR_CAP:
            content = content[:_HISTORY_MSG_CHAR_CAP] + "…"
        msgs.append({"role": str(m.get("role") or "user"), "content": content})
    while len(msgs) > 2 and sum(len(m["content"]) for m in msgs) > char_budget:
        del msgs[:2]
    return msgs


async def answer_question(
    session: Session,
    question: str,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Answer a natural-language question from the collected intel (shared core).

    Powers both POST /api/ai/ask and the MCP `scry_ask` tool. Raises AskError
    on any failure: feature disabled, no usable provider, timeout, model error.

    When `history` is given (conversation memory), the prior turns are passed
    to the model as alternating user/assistant messages before the new user
    prompt, and the system prompt notes the continuing conversation.
    """
    settings = get_settings()
    if not settings.enable_ai_search:
        raise AskError(
            403,
            "AI Search is disabled. Set CTI_ENABLE_AI_SEARCH=true and restart to enable it.",
        )

    provider = _resolve_provider(session)
    if provider is None:
        raise AskError(
            503,
            (
                "No LLM provider available. Configure one on the Search page "
                "(OpenAI / Anthropic / Ollama…) or run: scry ai-setup for the bundled model."
            ),
        )
    if isinstance(provider, LocalLlamaProvider) and not provider.is_available():
        raise AskError(
            503,
            f"Model file not found at {settings.ai_search_model_path}. Download it with: scry ai-setup",
        )
    model = _provider_model(provider)
    if not model:
        raise AskError(
            400,
            f"No model configured for provider '{provider.name}' — set a default model on the Search page.",
        )

    question = question.strip()

    # Budget the prompt against a 4096-token context: cap source snippets,
    # then fit as much recent history as the remaining budget allows.
    budget = _prompt_char_budget(question, settings.ai_search_max_tokens)
    sources = _cap_sources(_collect_sources(session, question, settings.ai_search_max_sources), budget // 2)
    used_by_sources = sum(len(str(s.get("title") or "")) + len(str(s.get("snippet") or "")) for s in sources)
    history = _trim_history(history or [], max(0, budget - used_by_sources))
    user_prompt = build_ai_search_user_prompt(question, sources)

    # Conversation memory: prior turns precede the new user prompt as real
    # alternating messages (never concatenated into one prompt).
    messages: list[dict[str, str]] = list(history)
    system = AI_SEARCH_SYSTEM_PROMPT + (_HISTORY_SYSTEM_SUFFIX if history else "")
    messages.append({"role": "user", "content": user_prompt})

    tokens_in: int | None = None
    tokens_out: int | None = None

    async def _collect_answer() -> str:
        nonlocal tokens_in, tokens_out
        parts: list[str] = []
        async for chunk in provider.chat_stream(
            messages,
            model=model,
            system=system,
            max_tokens=settings.ai_search_max_tokens,
        ):
            if chunk.error:
                raise RuntimeError(chunk.error)
            if chunk.text:
                parts.append(chunk.text)
            if chunk.tokens_in is not None:
                tokens_in = chunk.tokens_in
            if chunk.tokens_out is not None:
                tokens_out = chunk.tokens_out
        return "".join(parts).strip()

    start = time.monotonic()
    try:
        answer = await asyncio.wait_for(_collect_answer(), timeout=settings.ai_search_timeout_s)
    except TimeoutError:
        raise AskError(
            504,
            (
                f"The model did not answer within {settings.ai_search_timeout_s}s. "
                "The first local question loads the model (~10s); try again."
            ),
        ) from None
    except RuntimeError as exc:
        logger.warning("ai_ask_provider_error", error=str(exc))
        raise AskError(502, f"Model error: {exc}") from None
    elapsed_ms = int((time.monotonic() - start) * 1000)

    return {
        "answer": answer or "(empty answer from model)",
        "sources": [
            {"n": s["n"], "type": s["type"], "title": s["title"], "link": s["link"]} for s in sources
        ],
        "model": f"{provider.name}/{model}",
        "elapsed_ms": elapsed_ms,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
    }


@ai_router.post("/ask")
async def ai_ask(
    request: Request, payload: AskRequest, session: Session = Depends(get_session)
) -> dict[str, Any]:
    chat = None
    history = None
    if payload.session_id is not None:
        # Per-user privacy (v0.5.0 step 3): a session_id owned by someone
        # else 404s, so neither history nor the exchange leaks across users.
        user = getattr(request.state, "api_user", None)
        chat = load_chat_session(session, payload.session_id, user=user)
        history = recent_turns(session, chat)
    try:
        result = await answer_question(session, payload.question, history=history)
    except AskError as exc:
        raise HTTPException(exc.status_code, detail=exc.detail) from None
    if chat is not None:
        persist_exchange(session, chat, payload.question.strip(), result)
        result["session_id"] = chat.id
    return result
