"""Provider registry — loads enabled providers from DB and exposes a unified API."""

from __future__ import annotations

from sqlalchemy.orm import Session

from scry.ai.providers.anthropic import AnthropicProvider
from scry.ai.providers.base import LLMProvider
from scry.ai.providers.google import GoogleProvider
from scry.ai.providers.local import LocalLlamaProvider
from scry.ai.providers.ollama import OllamaProvider
from scry.ai.providers.openai import OpenAIProvider
from scry.ai.providers.xai import XAIProvider
from scry.crypto import decrypt
from scry.models import LLMSetting

PROVIDER_CLASSES = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "xai": XAIProvider,
    "google": GoogleProvider,
    "ollama": OllamaProvider,
    "local": LocalLlamaProvider,
}


def _load_setting(session: Session, provider: str) -> LLMSetting | None:
    return session.query(LLMSetting).filter_by(provider=provider).one_or_none()


def get_provider(session: Session, provider: str) -> LLMProvider | None:
    """Instantiate one provider with credentials from the DB. None if not configured."""
    s = _load_setting(session, provider)
    if not s:
        # Embedded model auto-detect: no key needed, file must exist
        if provider == "local":
            p = LocalLlamaProvider()
            return p if p.is_available() else None
        # Ollama auto-detect: no key needed
        if provider == "ollama":
            p = OllamaProvider()
            return p if p.is_available() else None
        return None

    api_key = decrypt(s.api_key_encrypted) if s.api_key_encrypted else ""
    cls = PROVIDER_CLASSES.get(provider)
    if not cls:
        return None
    return cls(api_key=api_key, base_url=s.base_url or "", default_model=s.default_model or "")


def list_enabled_providers(session: Session) -> list[LLMProvider]:
    """Return every enabled+configured provider, plus auto-detected Ollama."""
    out: list[LLMProvider] = []
    rows = session.query(LLMSetting).filter_by(enabled=True).all()
    seen: set[str] = set()
    for row in rows:
        if row.provider == "ollama":
            p = OllamaProvider(base_url=row.base_url or "")
            if p.is_available():
                out.append(p)
                seen.add("ollama")
            continue
        key = decrypt(row.api_key_encrypted) if row.api_key_encrypted else ""
        if not key:
            continue
        cls = PROVIDER_CLASSES.get(row.provider)
        if not cls:
            continue
        out.append(cls(api_key=key, base_url=row.base_url or "", default_model=row.default_model or ""))
        seen.add(row.provider)

    # Always include Ollama if available locally (auto-detect)
    if "ollama" not in seen:
        ollama = OllamaProvider()
        if ollama.is_available():
            out.append(ollama)
    return out


def list_all_models(session: Session) -> list[dict]:
    """Aggregate models from enabled providers. Returns dicts grouped by provider."""
    out: list[dict] = []
    for p in list_enabled_providers(session):
        for m in p.list_models():
            out.append(
                {
                    "provider": p.name,
                    "provider_display": p.display_name,
                    "model_id": m.model_id,
                    "label": m.label,
                    "context_window": m.context_window,
                }
            )
    return out


def get_default_model(session: Session) -> tuple[str, str] | None:
    """Return (provider, model_id) for the first enabled provider's default. None if no providers."""
    rows = session.query(LLMSetting).filter_by(enabled=True).all()
    for row in rows:
        if row.default_model:
            return (row.provider, row.default_model)
    providers = list_enabled_providers(session)
    if providers and providers[0].list_models():
        m = providers[0].list_models()[0]
        return (providers[0].name, m.model_id)
    return None


def resolve_ai_provider(session: Session) -> tuple[LLMProvider | None, str]:
    """Pick the provider that answers AI Search questions.

    Priority: the DB-enabled provider row (bring-your-own-model), then the
    bundled local GGUF if its file exists, then an auto-detected Ollama.
    Returns (provider_or_none, provider_id).
    """
    row = session.query(LLMSetting).filter_by(enabled=True).first()
    if row:
        p = get_provider(session, row.provider)
        if p is not None:
            return p, row.provider
    local = LocalLlamaProvider()
    if local.is_available():
        return local, "local"
    ollama = OllamaProvider()
    if ollama.is_available():
        return ollama, "ollama"
    return None, ""
