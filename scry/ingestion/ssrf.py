"""SSRF guard.

Blocks the most common SSRF foot-guns. Configurable via policies.yaml.
We resolve the hostname before fetching and refuse loopback / RFC1918 /
metadata service / link-local addresses by default. Onion is opt-in.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from scry.config import get_settings, load_policies

ALLOWED_SCHEMES = {"http", "https"}
ONION_SUFFIX = ".onion"


@dataclass
class SsrfDecision:
    allowed: bool
    reason: str = ""


def _ip_in_blocked_ranges(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, blocked_cidrs: list[str]
) -> bool:
    for cidr in blocked_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip in net:
            return True
    return False


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


def evaluate_url(url: str) -> SsrfDecision:
    settings = get_settings()
    policies = load_policies()
    blocked_cidrs = policies.get("benign_ip_ranges", []) or []
    deny_hosts = {h.lower() for h in policies.get("ssrf_denylist_hosts", []) or []}

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return SsrfDecision(False, f"scheme not allowed: {parsed.scheme}")
    if not parsed.hostname:
        return SsrfDecision(False, "no hostname")
    host = parsed.hostname.lower()
    if host in deny_hosts:
        return SsrfDecision(False, f"host on SSRF denylist: {host}")
    if host.endswith(ONION_SUFFIX):
        if not settings.enable_dark_web:
            return SsrfDecision(False, "onion address disallowed (dark web disabled)")
        return SsrfDecision(True, "onion allowed (explicitly enabled)")
    if host == "localhost":
        return SsrfDecision(False, "localhost disallowed")

    ips = _resolve(host)
    if not ips:
        # We don't trust unresolvable hosts but we do allow them through; the
        # transport layer will fail. This avoids accidentally blocking sites
        # in offline test environments.
        return SsrfDecision(True, "host resolution failed; transport will gate")

    for ip in ips:
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return SsrfDecision(False, f"address {ip} is special-use")
        if ip.is_private:
            return SsrfDecision(False, f"address {ip} is private")
        if _ip_in_blocked_ranges(ip, blocked_cidrs):
            return SsrfDecision(False, f"address {ip} in blocked range")
    return SsrfDecision(True, "ok")
