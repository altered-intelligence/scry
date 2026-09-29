"""AI Search endpoints — grounded Q&A over the collected CTI data.

Backed by a SELF-CONTAINED local LLM (GGUF via llama-cpp-python, embedded in
the Scry process). No server, no cloud calls, no API keys. Everything
degrades gracefully: when the feature flag is off or the model file is
missing, the endpoints return clear 4xx/5xx errors instead of hanging.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from scry.ai.prompts import AI_SEARCH_SYSTEM_PROMPT, build_ai_search_user_prompt
from scry.ai.providers.local import LocalLlamaProvider
from scry.api.deps import get_session
from scry.config import get_settings
from scry.logging import get_logger
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


def _provider() -> LocalLlamaProvider:
    return LocalLlamaProvider()


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


@ai_router.get("/status")
def ai_status() -> dict[str, Any]:
    """Feature/model status — pure filesystem checks, never loads the model."""
    settings = get_settings()
    provider = _provider()
    present = provider.is_available()
    size_mb = round(provider.model_path.stat().st_size / (1024 * 1024)) if present else None
    return {
        "enabled": settings.enable_ai_search,
        "model_path": settings.ai_search_model_path,
        "model_present": present,
        "model_loaded": provider.model_loaded,
        "model_size_mb": size_mb,
    }


@ai_router.post("/ask")
async def ai_ask(payload: AskRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    settings = get_settings()
    if not settings.enable_ai_search:
        raise HTTPException(
            403,
            detail="AI Search is disabled. Set CTI_ENABLE_AI_SEARCH=true and restart to enable it.",
        )

    provider = _provider()
    if not provider.is_available():
        raise HTTPException(
            503,
            detail=(
                f"Model file not found at {settings.ai_search_model_path}. " "Download it with: scry ai-setup"
            ),
        )

    question = payload.question.strip()
    sources = _collect_sources(session, question, settings.ai_search_max_sources)
    user_prompt = build_ai_search_user_prompt(question, sources)

    async def _collect_answer() -> str:
        parts: list[str] = []
        async for chunk in provider.chat_stream(
            [{"role": "user", "content": user_prompt}],
            model=provider.model_path.name,
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
        raise HTTPException(
            504,
            detail=(
                f"The model did not answer within {settings.ai_search_timeout_s}s. "
                "The first question loads the model (~10s); try again."
            ),
        ) from None
    except RuntimeError as exc:
        logger.warning("ai_ask_provider_error", error=str(exc))
        raise HTTPException(502, detail=f"Local model error: {exc}") from None
    elapsed_ms = int((time.monotonic() - start) * 1000)

    return {
        "answer": answer or "(empty answer from model)",
        "sources": [
            {"n": s["n"], "type": s["type"], "title": s["title"], "link": s["link"]} for s in sources
        ],
        "model": provider.model_path.name,
        "elapsed_ms": elapsed_ms,
    }
