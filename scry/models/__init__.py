"""Model package — re-export everything so alembic can discover metadata."""

from __future__ import annotations

from scry.models.article import Article, ArticleEmbedding
from scry.models.base import Base
from scry.models.chat import ChatMessage, ChatSession
from scry.models.claim import Claim
from scry.models.connector_setting import ConnectorSetting
from scry.models.cti_objects import (
    AttackMapping,
    Campaign,
    Detection,
    MalwareFamily,
    ThreatActor,
)
from scry.models.cve import CVE
from scry.models.entity import Entity, EntityMention
from scry.models.llm_setting import LLMSetting
from scry.models.observable import Observable, ObservableMention
from scry.models.ransomware_feed import RansomwareFeedItem
from scry.models.relationship import Relationship
from scry.models.source import Source, SourceFetch, SourceReliabilityProfile
from scry.models.system import SystemSetting
from scry.models.telegram_channel import TelegramChannel
from scry.models.threat_feed import ThreatFeedItem
from scry.models.threat_intel_source import ThreatIntelSource
from scry.models.user import (
    ApiKey,
    EmailVerification,
    PasskeyCredential,
    RecoveryCode,
    SessionToken,
    User,
    UserFeedKey,
)
from scry.models.workflow import (
    Alert,
    AnalystReview,
    AuditLog,
    Cluster,
    Conflict,
    Job,
)

__all__ = [
    "CVE",
    "Alert",
    "AnalystReview",
    "ApiKey",
    "Article",
    "ArticleEmbedding",
    "AttackMapping",
    "AuditLog",
    "Base",
    "Campaign",
    "ChatMessage",
    "ChatSession",
    "Claim",
    "Cluster",
    "Conflict",
    "ConnectorSetting",
    "Detection",
    "EmailVerification",
    "Entity",
    "EntityMention",
    "Job",
    "LLMSetting",
    "MalwareFamily",
    "Observable",
    "ObservableMention",
    "PasskeyCredential",
    "RansomwareFeedItem",
    "RecoveryCode",
    "Relationship",
    "SessionToken",
    "Source",
    "SourceFetch",
    "SourceReliabilityProfile",
    "SystemSetting",
    "TelegramChannel",
    "ThreatActor",
    "ThreatFeedItem",
    "ThreatIntelSource",
    "User",
    "UserFeedKey",
]
