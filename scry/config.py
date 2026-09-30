"""Configuration loader.

Centralized settings (env + YAML). The whole platform reads from here so
defaults stay safe-by-default and risky knobs are visible in one place.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"


class Settings(BaseSettings):
    # NOTE: the CTI_ env prefix is intentionally kept after the rebrand to
    # Scry — existing .env files (CTI_FEEDLY_API_TOKEN etc.) must keep working.
    model_config = SettingsConfigDict(env_prefix="CTI_", env_file=".env", extra="ignore")

    env: str = "local"
    log_level: str = "INFO"

    database_url: str = "sqlite+pysqlite:///./cti.sqlite"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # API auth: when set, all /api routes require this token (X-API-Key or
    # Authorization: Bearer). Empty (default) keeps every endpoint open.
    api_key: str = ""

    # Safety
    enable_dark_web: bool = False
    enable_js_rendering: bool = False
    enable_file_downloads: bool = False
    enable_exploit_repo_clone: bool = False
    enable_outbound_alerts: bool = False
    max_fetch_bytes: int = 5 * 1024 * 1024
    fetch_timeout_seconds: int = 20

    # LLM
    llm_provider: str = "stub"  # "stub" | "anthropic"

    # HTTP identity — some feeds (CISA, Microsoft) block bot-like User-Agents.
    default_user_agent: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    )

    # UI
    enable_ai_search: bool = (
        True  # show the AI assistant panel on /ui/search (set CTI_ENABLE_AI_SEARCH=false to hide)
    )

    # AI Search (self-contained local LLM via llama.cpp — no server, no cloud, no API keys)
    ai_search_model_path: str = (
        "data/models/qwen2.5-1.5b-instruct-q4_k_m.gguf"  # ~1.0 GB; `scry ai-setup` downloads it
    )
    ai_search_max_tokens: int = 512  # answer length cap (keeps latency sane on 8 GB machines)
    ai_search_max_sources: int = 8  # top search hits fed to the model as context
    ai_search_timeout_s: int = 120  # hard timebox for one answer (first answer includes ~12s model load)

    # Retention
    retention_raw_html_days: int = 14
    retention_article_text_days: int = 365

    # Alert channels (off until explicitly enabled)
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    webhook_url: str = ""  # generic JSON webhook
    alert_email_from: str = ""
    alert_email_to: str = ""
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = False
    notify_desktop: bool = False  # macOS desktop notifications via osascript

    # Optional integrations (legacy fields for backwards compatibility)
    misp_key: str = ""
    opencti_key: str = ""

    # Enrichment providers (off unless key is set)
    virustotal_api_key: str = ""
    otx_api_key: str = ""
    vt_rate_per_min: int = 4
    vt_daily_quota: int = 480
    otx_rate_per_sec: int = 8

    # IP/Domain enrichment
    greynoise_api_key: str = ""
    urlscan_api_key: str = ""
    abuseipdb_api_key: str = ""

    # Infrastructure discovery
    censys_api_id: str = ""
    censys_api_secret: str = ""
    shodan_api_key: str = ""

    # CVE enrichment
    nvd_api_key: str = ""  # Optional, increases rate limit
    github_token: str = ""  # For GitHub Advisories API

    # Threat intelligence platforms
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_ssl: bool = True
    opencti_url: str = ""
    opencti_api_key: str = ""
    opencti_verify_ssl: bool = True
    taxii_url: str = ""
    taxii_username: str = ""
    taxii_password: str = ""
    taxii_verify_ssl: bool = True

    # SIEM/SOAR integrations
    sentinel_workspace_id: str = ""
    sentinel_api_key: str = ""
    sentinel_subscription_id: str = ""
    sentinel_resource_group: str = ""
    splunk_url: str = ""
    splunk_token: str = ""
    splunk_verify_ssl: bool = True
    elastic_url: str = ""
    elastic_api_key: str = ""
    elastic_verify_ssl: bool = True

    # Case management
    thehive_url: str = ""
    thehive_api_key: str = ""
    thehive_verify_ssl: bool = True
    cortex_url: str = ""
    cortex_api_key: str = ""
    cortex_verify_ssl: bool = True

    # Social media collectors
    reddit_client_id: str = ""
    reddit_client_secret: str = ""
    twitter_bearer_token: str = ""
    bluesky_handle: str = ""
    bluesky_password: str = ""
    mastodon_instance: str = ""
    mastodon_token: str = ""

    # Feedly Threat Intelligence
    feedly_api_token: str = ""
    feedly_user_id: str = ""  # Optional: for personal streams

    config_dir: Path = Field(default=CONFIG_DIR)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def _read_yaml(name: str) -> dict[str, Any]:
    path = get_settings().config_dir / name
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML config {name} must be a mapping at top level")
    return data


def load_sources() -> list[dict[str, Any]]:
    return list(_read_yaml("sources.yaml").get("sources", []))


def load_watchlists() -> list[dict[str, Any]]:
    return list(_read_yaml("watchlists.yaml").get("watchlists", []))


def load_pirs() -> list[dict[str, Any]]:
    return list(_read_yaml("pirs.yaml").get("pirs", []))


def load_otx_pulse_subscriptions() -> list[dict[str, Any]]:
    return list(_read_yaml("otx_pulses.yaml").get("subscriptions", []))


def load_policies() -> dict[str, Any]:
    return _read_yaml("policies.yaml")


def load_aliases() -> dict[str, Any]:
    return _read_yaml("aliases.yaml")
