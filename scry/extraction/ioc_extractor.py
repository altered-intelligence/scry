"""IOC extractor.

Regex-first with structural validation. Produces IOCCandidate objects with
evidence text and context windows. Conservative on what it accepts: defang
forms are refanged before validation; common false positives (CDN hosts,
example.com, version strings) are filtered or tagged.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

import tldextract

from scry.config import load_policies
from scry.extraction.defang import looks_defanged, refang
from scry.schemas.extraction import IOCCandidate

_TLDX = tldextract.TLDExtract(suffix_list_urls=())  # offline


# --- Regex catalog ---------------------------------------------------------

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
IPV4_DEFANGED_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\[\.\]){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IPV6_RE = re.compile(r"(?<![A-Za-z0-9:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![A-Za-z0-9:])")

DOMAIN_BODY = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,}|[a-z]{2,24})"
DOMAIN_RE = re.compile(rf"\b{DOMAIN_BODY}\b", re.IGNORECASE)
DEFANGED_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9-]+\[?\.\]?)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,})\b", re.IGNORECASE
)

URL_RE = re.compile(r"\b(?:https?|hxxps?|h\[t\]tps?)\[?:\]?/{2}(?:[^\s<>\"'\)]+)", re.IGNORECASE)

EMAIL_RE = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.IGNORECASE)
EMAIL_DEFANGED_RE = re.compile(
    r"\b[a-z0-9._%+\-]+\s?(?:\[at\]|\(at\)|\[@\])\s?[a-z0-9.\-]+\s?(?:\[\.\]|\(\.\)|\[dot\])\s?[a-z]{2,}\b",
    re.IGNORECASE,
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Hashes — anchor on word boundaries to avoid catching long base64.
MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
SHA512_RE = re.compile(r"\b[a-f0-9]{128}\b", re.IGNORECASE)
SSDEEP_RE = re.compile(r"\b\d+:[A-Za-z0-9+/]{6,}:[A-Za-z0-9+/]{4,}\b")
TLSH_RE = re.compile(r"\bT[0-9A-F]{70}\b", re.IGNORECASE)

ASN_RE = re.compile(r"\bAS\d{1,7}\b")

ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)

# Wallets
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

# MITRE
ATTACK_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Registry, mutex, pipe
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)[\\/][^\s\"'<>]+",
    re.IGNORECASE,
)
NAMED_PIPE_RE = re.compile(r"\\\\\.\\pipe\\[A-Za-z0-9_\-]+", re.IGNORECASE)

# Package supply chain
NPM_RE = re.compile(r"\b@?[a-z0-9-]+/[a-z0-9._\-]{2,}\b")
PYPI_RE = re.compile(r"(?<=pip install )[a-zA-Z0-9_\-]{2,}")
DOCKER_IMAGE_RE = re.compile(r"\b(?:[a-z0-9.\-]+/)?[a-z0-9._\-]+:[a-zA-Z0-9._\-]+\b")

# JARM / JA3 / JA4
JARM_RE = re.compile(r"\b[0-9a-f]{62}\b", re.IGNORECASE)
JA3_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)  # same shape as md5, used together
JA4_RE = re.compile(r"\bja4=[a-z0-9_]+\b", re.IGNORECASE)

# Telegram / Discord references
TELEGRAM_RE = re.compile(r"\b(?:t\.me|telegram\.me)/[A-Za-z0-9_]+\b", re.IGNORECASE)
DISCORD_INVITE_RE = re.compile(r"\bdiscord(?:\.gg|\.com/invite)/[A-Za-z0-9]+\b", re.IGNORECASE)


# --- Validators ------------------------------------------------------------

_VERSION_LIKE_RE = re.compile(r"^\d+\.\d+(?:\.\d+){0,3}$")  # 1.2.3, 5.7.0.1
_ALPHA_TLDS = {"local", "internal", "lan", "home", "test", "example", "invalid"}


def _is_valid_domain(value: str) -> bool:
    if "." not in value:
        return False
    if _VERSION_LIKE_RE.match(value):
        return False
    parsed = _TLDX(value.lower())
    if not parsed.suffix:
        return False
    if parsed.suffix in _ALPHA_TLDS:
        return False
    return not any(seg == "" or len(seg) > 63 for seg in value.split("."))


_RFC1918_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]


def _is_public_ipv4(value: str) -> bool:
    """Allow documentation IPs (TEST-NET-*) since they appear in real CTI fixtures.

    We block only RFC 1918, loopback, link-local, multicast, unspecified, and
    broadcast. Documentation IPs (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) are treated as real for extraction purposes.
    """
    try:
        ip = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        return False
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        return False
    return not any(ip in net for net in _RFC1918_NETS)


# --- Extraction ------------------------------------------------------------


class IOCExtractor:
    """Stateless extractor."""

    EXTRACTOR_VERSION = "0.1"

    def __init__(self) -> None:
        self.policies = load_policies()
        self.benign_hosts = {h.lower() for h in self.policies.get("benign_infrastructure_hosts", []) or []}

    def extract(self, text: str) -> list[IOCCandidate]:
        if not text:
            return []
        out: list[IOCCandidate] = []
        out.extend(self._extract_simple("ipv4", IPV4_RE, text, _is_public_ipv4))
        out.extend(
            self._extract_simple(
                "ipv4", IPV4_DEFANGED_RE, text, _is_public_ipv4, transform=lambda s: s.replace("[.]", ".")
            )
        )
        out.extend(self._extract_simple("ipv6", IPV6_RE, text, self._valid_ipv6))
        out.extend(self._extract_url(text))
        out.extend(self._extract_domains(text))
        out.extend(self._extract_emails(text))
        out.extend(self._extract_hashes(text))
        out.extend(self._extract_simple("cve", CVE_RE, text, lambda v: True, normalize=str.upper))
        out.extend(self._extract_simple("asn", ASN_RE, text, lambda v: True, normalize=str.upper))
        out.extend(
            self._extract_simple(
                "onion", ONION_RE, text, lambda v: True, normalize=str.lower, tags=["darkweb"]
            )
        )
        out.extend(self._extract_simple("wallet_btc", BTC_RE, text, lambda v: True, tags=["wallet"]))
        out.extend(self._extract_simple("wallet_eth", ETH_RE, text, lambda v: True, tags=["wallet"]))
        out.extend(self._extract_simple("wallet_xmr", XMR_RE, text, lambda v: True, tags=["wallet"]))
        out.extend(
            self._extract_simple("attack_technique", ATTACK_TID_RE, text, lambda v: True, normalize=str.upper)
        )
        out.extend(self._extract_simple("registry_key", REGISTRY_RE, text, lambda v: True))
        out.extend(self._extract_simple("named_pipe", NAMED_PIPE_RE, text, lambda v: True))
        out.extend(
            self._extract_simple("telegram_handle", TELEGRAM_RE, text, lambda v: True, normalize=str.lower)
        )
        out.extend(
            self._extract_simple(
                "discord_invite", DISCORD_INVITE_RE, text, lambda v: True, normalize=str.lower
            )
        )
        out = self._dedupe_and_tag_fp(out)
        return out

    # ---- helpers ----

    def _valid_ipv6(self, value: str) -> bool:
        try:
            ip = ipaddress.IPv6Address(value)
        except (ipaddress.AddressValueError, ValueError):
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)

    def _extract_simple(
        self,
        ioc_type: str,
        pattern: re.Pattern[str],
        text: str,
        validator,
        *,
        normalize=None,
        transform=None,
        tags: list[str] | None = None,
    ) -> list[IOCCandidate]:
        out: list[IOCCandidate] = []
        for m in pattern.finditer(text):
            raw = m.group(0)
            value = transform(raw) if transform else raw
            normalized = normalize(value) if normalize else value
            if not validator(normalized):
                continue
            out.append(
                IOCCandidate(
                    type=ioc_type,
                    value=raw,
                    normalized_value=normalized,
                    defanged_value=raw if looks_defanged(raw) else None,
                    evidence_text=_window(text, m.start(), m.end(), pad=80),
                    context_window=_window(text, m.start(), m.end(), pad=160),
                    extraction_method="regex",
                    extraction_confidence=80,
                    tags=list(tags or []),
                )
            )
        return out

    def _extract_url(self, text: str) -> list[IOCCandidate]:
        out: list[IOCCandidate] = []
        for m in URL_RE.finditer(text):
            raw = m.group(0).rstrip(").,;:'\"")
            refanged = refang(raw)
            # Drop URLs whose host fails domain validation
            host = re.match(r"https?://([^/]+)", refanged, flags=re.IGNORECASE)
            if not host or not _is_valid_domain(host.group(1).split(":")[0]):
                continue
            out.append(
                IOCCandidate(
                    type="url",
                    value=raw,
                    normalized_value=refanged.lower(),
                    defanged_value=raw if looks_defanged(raw) else None,
                    evidence_text=_window(text, m.start(), m.end()),
                    context_window=_window(text, m.start(), m.end(), pad=160),
                    extraction_method="regex",
                    extraction_confidence=85,
                )
            )
        return out

    def _extract_domains(self, text: str) -> list[IOCCandidate]:
        out: list[IOCCandidate] = []
        seen: set[str] = set()
        for m in DOMAIN_RE.finditer(text):
            raw = m.group(0)
            normalized = raw.lower().rstrip(".")
            if not _is_valid_domain(normalized):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append(
                IOCCandidate(
                    type="domain",
                    value=raw,
                    normalized_value=normalized,
                    evidence_text=_window(text, m.start(), m.end()),
                    context_window=_window(text, m.start(), m.end(), pad=160),
                    extraction_method="regex",
                    extraction_confidence=75,
                )
            )
        for m in DEFANGED_DOMAIN_RE.finditer(text):
            raw = m.group(0)
            refanged = refang(raw).lower().rstrip(".")
            if not _is_valid_domain(refanged):
                continue
            if refanged in seen:
                continue
            seen.add(refanged)
            out.append(
                IOCCandidate(
                    type="domain",
                    value=raw,
                    normalized_value=refanged,
                    defanged_value=raw,
                    evidence_text=_window(text, m.start(), m.end()),
                    context_window=_window(text, m.start(), m.end(), pad=160),
                    extraction_method="regex",
                    extraction_confidence=80,
                )
            )
        return out

    def _extract_emails(self, text: str) -> list[IOCCandidate]:
        out: list[IOCCandidate] = []
        for m in EMAIL_RE.finditer(text):
            raw = m.group(0)
            normalized = raw.lower()
            domain = normalized.split("@", 1)[1] if "@" in normalized else ""
            if not _is_valid_domain(domain):
                continue
            out.append(
                IOCCandidate(
                    type="email",
                    value=raw,
                    normalized_value=normalized,
                    evidence_text=_window(text, m.start(), m.end()),
                    context_window=_window(text, m.start(), m.end(), pad=160),
                    extraction_method="regex",
                    extraction_confidence=85,
                )
            )
        for m in EMAIL_DEFANGED_RE.finditer(text):
            raw = m.group(0)
            refanged = refang(raw).lower().replace(" ", "")
            if "@" not in refanged:
                continue
            domain = refanged.split("@", 1)[1]
            if not _is_valid_domain(domain):
                continue
            out.append(
                IOCCandidate(
                    type="email",
                    value=raw,
                    normalized_value=refanged,
                    defanged_value=raw,
                    evidence_text=_window(text, m.start(), m.end()),
                    context_window=_window(text, m.start(), m.end(), pad=160),
                    extraction_method="regex",
                    extraction_confidence=85,
                )
            )
        return out

    def _extract_hashes(self, text: str) -> list[IOCCandidate]:
        out: list[IOCCandidate] = []
        # SHA512 first, then SHA256, then SHA1, then MD5 to avoid double-counting.
        for ioc_type, pat in (
            ("sha512", SHA512_RE),
            ("sha256", SHA256_RE),
            ("sha1", SHA1_RE),
            ("md5", MD5_RE),
        ):
            for m in pat.finditer(text):
                raw = m.group(0)
                normalized = raw.lower()
                out.append(
                    IOCCandidate(
                        type=ioc_type,
                        value=raw,
                        normalized_value=normalized,
                        evidence_text=_window(text, m.start(), m.end()),
                        context_window=_window(text, m.start(), m.end(), pad=160),
                        extraction_method="regex",
                        extraction_confidence=80,
                    )
                )
        for m in SSDEEP_RE.finditer(text):
            out.append(
                IOCCandidate(
                    type="ssdeep",
                    value=m.group(0),
                    normalized_value=m.group(0),
                    evidence_text=_window(text, m.start(), m.end()),
                    extraction_method="regex",
                    extraction_confidence=75,
                )
            )
        for m in TLSH_RE.finditer(text):
            out.append(
                IOCCandidate(
                    type="tlsh",
                    value=m.group(0),
                    normalized_value=m.group(0).upper(),
                    evidence_text=_window(text, m.start(), m.end()),
                    extraction_method="regex",
                    extraction_confidence=75,
                )
            )
        return out

    def _dedupe_and_tag_fp(self, items: Iterable[IOCCandidate]) -> list[IOCCandidate]:
        # Dedup on (type, normalized_value), prefer items with higher confidence.
        best: dict[tuple[str, str], IOCCandidate] = {}
        for it in items:
            key = (it.type, it.normalized_value)
            if key not in best or it.extraction_confidence > best[key].extraction_confidence:
                # Merge: keep the higher-confidence one but accumulate tags.
                if key in best:
                    it.tags = list({*it.tags, *best[key].tags})
                best[key] = it
        # Tag obvious benign infra
        for it in best.values():
            if it.type in {"domain", "url"}:
                host = it.normalized_value
                if it.type == "url":
                    h = re.match(r"https?://([^/]+)", host)
                    host = h.group(1).split(":")[0] if h else host
                root = ".".join(host.split(".")[-2:])
                if root in self.benign_hosts or any(host.endswith(b) for b in self.benign_hosts):
                    it.tags = list({*it.tags, "benign-shared-infrastructure"})
                    it.false_positive_risk = max(it.false_positive_risk, 0.7)
                    it.maliciousness_confidence = min(it.maliciousness_confidence, 30)
        return sorted(best.values(), key=lambda x: (x.type, x.normalized_value))


def _window(text: str, start: int, end: int, *, pad: int = 80) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].replace("\n", " ").strip()
