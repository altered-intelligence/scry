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

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scry.ai.prompts import AI_SEARCH_SYSTEM_PROMPT, build_ai_search_user_prompt
from scry.ai.providers.local import LocalLlamaProvider
from scry.ai.registry import PROVIDER_CLASSES, resolve_ai_provider
from scry.api.deps import get_session
from scry.audit import record
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


def _provider_model(provider) -> str:
    """Model identifier to pass to chat_stream for this provider."""
    if getattr(provider, "name", "") == "local" and hasattr(provider, "model_path"):
        return str(provider.model_path).split("/")[-1]
    if getattr(provider, "default_model", ""):
        return provider.default_model
    list_models = getattr(provider, "list_models", None)
    if callable(list_models):
        models = list_models()
        if models:
            return models[0].model_id
    return ""


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
    return {
        "enabled": settings.enable_ai_search,
        "model_path": settings.ai_search_model_path,
        "model_present": present,
        "model_loaded": provider.model_loaded,
        "model_size_mb": size_mb,
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


@ai_router.put("/provider")
async def ai_provider_configure(
    payload: ProviderConfig, session: Session = Depends(get_session)
) -> dict[str, Any]:
    """Create/update one provider's settings (key encrypted at rest)."""
    meta = _PROVIDER_META.get(payload.provider)
    if meta is None:
        raise HTTPException(404, detail=f"Unknown provider '{payload.provider}'")

    row = session.query(LLMSetting).filter_by(provider=payload.provider).one_or_none()
    if row is None:
        row = LLMSetting(provider=payload.provider)
        session.add(row)

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


class AskError(Exception):
    """A question could not be answered — carries an HTTP-style status + message.

    Raised by `answer_question` so the HTTP endpoint (maps it to
    HTTPException) and the MCP `scry_ask` tool (maps it to an error dict)
    share one implementation without web exceptions leaking into the MCP
    server.
    """

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


async def answer_question(session: Session, question: str) -> dict[str, Any]:
    """Answer a natural-language question from the collected intel (shared core).

    Powers both POST /api/ai/ask and the MCP `scry_ask` tool. Raises AskError
    on any failure: feature disabled, no usable provider, timeout, model error.
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
    sources = _collect_sources(session, question, settings.ai_search_max_sources)
    user_prompt = build_ai_search_user_prompt(question, sources)

    async def _collect_answer() -> str:
        parts: list[str] = []
        async for chunk in provider.chat_stream(
            [{"role": "user", "content": user_prompt}],
            model=model,
            system=AI_SEARCH_SYSTEM_PROMPT,
            max_tokens=settings.ai_search_max_tokens,
        ):
            if chunk.error:
                raise RuntimeError(chunk.error)
            if chunk.text:
                parts.append(chunk.text)
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
    }


@ai_router.post("/ask")
async def ai_ask(payload: AskRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    try:
        return await answer_question(session, payload.question)
    except AskError as exc:
        raise HTTPException(exc.status_code, detail=exc.detail) from None
