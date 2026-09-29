"""Alert engine.

Scans for trigger conditions and creates Alert rows. Delivery is only
attempted when CTI_ENABLE_OUTBOUND_ALERTS=true and a channel is configured.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.alerting.channels import deliver
from scry.config import get_settings
from scry.logging import get_logger
from scry.models import CVE, Alert, Article, Observable

logger = get_logger("alerting")


@dataclass
class AlertCandidate:
    trigger: str
    title: str
    summary: str
    severity: str
    related: dict
    why_it_matters: str
    recommended_action: str
    dedup_key: str
    needs_review: bool = False
    confidence: int = 70


class AlertEngine:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.settings = get_settings()

    def evaluate(self) -> list[Alert]:
        candidates = [
            *self._new_kev_alerts(),
            *self._microsoft_exploited_alerts(),
            *self._high_risk_observable_alerts(),
            *self._ransomware_topic_alerts(),
        ]
        created: list[Alert] = []
        for c in candidates:
            existing = self.session.scalar(select(Alert).where(Alert.dedup_key == c.dedup_key))
            if existing:
                continue
            alert = Alert(
                trigger=c.trigger,
                title=c.title,
                summary=c.summary,
                why_it_matters=c.why_it_matters,
                severity=c.severity,
                confidence=c.confidence,
                related=c.related,
                recommended_action=c.recommended_action,
                needs_review=c.needs_review,
                dedup_key=c.dedup_key,
            )
            self.session.add(alert)
            created.append(alert)
        self.session.commit()

        if self.settings.enable_outbound_alerts:
            for alert in created:
                try:
                    delivered = deliver(alert)
                    alert.delivered = delivered
                except Exception as exc:
                    logger.warning("alert_delivery_failed", id=alert.id, exc=str(exc))
            self.session.commit()
        return created

    # ---- generators ----

    def _new_kev_alerts(self) -> list[AlertCandidate]:
        out: list[AlertCandidate] = []
        for cve in self.session.scalars(select(CVE).where(CVE.kev.is_(True))):
            dk = _key("kev", cve.cve_id)
            out.append(
                AlertCandidate(
                    trigger="cisa_kev",
                    title=f"CISA KEV: {cve.cve_id} ({cve.vendor or '?'} {cve.product or '?'})",
                    summary=cve.description or "Added to the Known Exploited Vulnerabilities catalog.",
                    severity="high",
                    related={"cve_id": cve.cve_id, "vendor": cve.vendor, "product": cve.product},
                    why_it_matters="CISA KEV vulnerabilities are confirmed exploited in the wild.",
                    recommended_action="Confirm exposure, prioritize patching, hunt for exploitation indicators.",
                    dedup_key=dk,
                    confidence=95,
                )
            )
        return out

    def _microsoft_exploited_alerts(self) -> list[AlertCandidate]:
        out: list[AlertCandidate] = []
        rows = self.session.scalars(
            select(CVE).where(CVE.is_microsoft.is_(True), CVE.exploited_in_the_wild.is_(True))
        )
        for cve in rows:
            out.append(
                AlertCandidate(
                    trigger="microsoft_exploited",
                    title=f"Microsoft exploited: {cve.cve_id}",
                    summary=cve.description or f"Microsoft vulnerability {cve.cve_id} reported as exploited.",
                    severity="high",
                    related={"cve_id": cve.cve_id, "product": cve.product},
                    why_it_matters="Microsoft products are widely deployed; exploitation is high impact.",
                    recommended_action="Prioritize patching; deploy compensating controls; hunt for IOCs.",
                    dedup_key=_key("ms_itw", cve.cve_id),
                    confidence=90,
                )
            )
        return out

    def _high_risk_observable_alerts(self) -> list[AlertCandidate]:
        out: list[AlertCandidate] = []
        for ob in self.session.scalars(
            select(Observable).where(
                Observable.risk_score >= 80, Observable.actionability.in_(("urgent_review", "block_if_safe"))
            )
        ):
            out.append(
                AlertCandidate(
                    trigger="high_risk_observable",
                    title=f"High-risk {ob.type}: {ob.normalized_value}",
                    summary=f"Risk score {ob.risk_score:.0f}/100; actionability {ob.actionability}.",
                    severity="high" if ob.risk_score >= 90 else "medium",
                    related={
                        "observable_id": ob.id,
                        "type": ob.type,
                        "value": ob.normalized_value,
                        "tags": ob.tags,
                    },
                    why_it_matters="Recent, high-confidence observable on watchlist topics.",
                    recommended_action="Hunt across telemetry; consider block if safe.",
                    dedup_key=_key("hi_risk_ob", str(ob.id)),
                    confidence=ob.maliciousness_confidence,
                )
            )
        return out

    def _ransomware_topic_alerts(self) -> list[AlertCandidate]:
        out: list[AlertCandidate] = []
        rows = self.session.scalars(select(Article).where(Article.tags.contains(["ransomware"])))
        for art in rows:
            out.append(
                AlertCandidate(
                    trigger="ransomware_activity",
                    title=f"Ransomware reporting: {art.title[:140]}",
                    summary=(art.summary or art.extracted_text or "")[:300],
                    severity="medium",
                    related={"article_id": art.id, "url": art.url},
                    why_it_matters="Ransomware reporting may indicate active campaigns relevant to your sector.",
                    recommended_action="Triage IOCs and TTPs; review backup posture.",
                    dedup_key=_key("rw_article", art.url),
                    confidence=70,
                )
            )
        return out


def _key(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]
    return f"{parts[0]}:{h}"
