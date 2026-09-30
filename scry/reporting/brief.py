"""AI-synthesized executive briefings from the daily/weekly reports.

Takes the plain-text report produced by the existing generators and pipes it
through the active LLM provider (same resolution logic as AI Search) into a
short executive briefing. Results are cached in memory per (scope, UTC day)
so repeated calls don't re-run the model.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from scry.ai.errors import AskError
from scry.ai.prompts import BRIEF_SYSTEM_PROMPT, build_brief_user_prompt
from scry.ai.providers.local import LocalLlamaProvider
from scry.ai.registry import provider_model, resolve_ai_provider
from scry.config import get_settings
from scry.logging import get_logger
from scry.reporting.daily import generate_daily_report
from scry.reporting.weekly import generate_weekly_report

logger = get_logger("reporting.brief")

SCOPES = ("daily", "weekly")

# (scope, UTC date) -> briefing result. In-memory only; resets on restart.
_brief_cache: dict[tuple[str, str], dict[str, Any]] = {}


def clear_brief_cache() -> None:
    """Drop all cached briefs (test helper / manual reset)."""
    _brief_cache.clear()


def _report_for_scope(session: Session, scope: str) -> str:
    if scope == "daily":
        return generate_daily_report(session)
    return generate_weekly_report(session)


async def generate_brief(session: Session, scope: str) -> dict[str, Any]:
    """Synthesize an executive briefing from the daily/weekly report.

    Raises AskError (status_code + detail) on any failure, mirroring
    answer_question so the HTTP endpoint and CLI share one implementation.
    """
    if scope not in SCOPES:
        raise AskError(422, f"scope must be one of {'|'.join(SCOPES)}")

    day = datetime.now(UTC).date().isoformat()
    key = (scope, day)
    cached = _brief_cache.get(key)
    if cached is not None:
        out = dict(cached)
        out["cached"] = True
        return out

    settings = get_settings()
    if not settings.enable_ai_search:
        raise AskError(
            403,
            "AI Search is disabled. Set CTI_ENABLE_AI_SEARCH=true and restart to enable it.",
        )

    provider, _ = resolve_ai_provider(session)
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
    model = provider_model(provider)
    if not model:
        raise AskError(
            400,
            f"No model configured for provider '{provider.name}' — set a default model on the Search page.",
        )

    report_text = _report_for_scope(session, scope)
    user_prompt = build_brief_user_prompt(scope, report_text)

    async def _collect_brief() -> str:
        parts: list[str] = []
        async for chunk in provider.chat_stream(
            [{"role": "user", "content": user_prompt}],
            model=model,
            system=BRIEF_SYSTEM_PROMPT,
            max_tokens=settings.ai_search_max_tokens,
        ):
            if chunk.error:
                raise RuntimeError(chunk.error)
            if chunk.text:
                parts.append(chunk.text)
        return "".join(parts).strip()

    start = time.monotonic()
    try:
        brief = await asyncio.wait_for(_collect_brief(), timeout=settings.ai_search_timeout_s)
    except TimeoutError:
        raise AskError(
            504,
            (
                f"The model did not answer within {settings.ai_search_timeout_s}s. "
                "The first local question loads the model (~10s); try again."
            ),
        ) from None
    except RuntimeError as exc:
        logger.warning("report_brief_provider_error", scope=scope, error=str(exc))
        raise AskError(502, f"Model error: {exc}") from None
    elapsed_ms = int((time.monotonic() - start) * 1000)

    result: dict[str, Any] = {
        "brief": brief or "(empty answer from model)",
        "model": f"{provider.name}/{model}",
        "elapsed_ms": elapsed_ms,
        "scope": scope,
        "generated_at": datetime.now(UTC).isoformat(),
        "cached": False,
    }
    _brief_cache[key] = result
    return result
