"""Ithil — "Moon-stone. Looks where no one should."

Dark-web / insider / covert-channel surface scanner.

This stone works without an API key using HIBP's free k-anonymity Pwned Passwords
endpoint for email *domain* exposure (via breaches.json public feed) and performs
these checks:

  - Target domain's presence in published breach list (HaveIBeenPwned public
    breaches.json — no key required, just a Cloudflare-backed public feed).
    Caveat: identifies breaches *of the domain* (e.g. "acme.com was breached"),
    not of specific email addresses — that needs the paid key.
  - Subdomain enumeration surface via crt.sh certificate transparency logs
    (public, no key, returns historical TLS certs issued for that domain).
  - Typosquat domain presence check for common variants.
  - Optional: per-email breach lookup IF HIBP_API_KEY is set (EmailAccount endpoint).

Everything here is lawful OSINT against public indexes. No Tor, no dark-market
scraping — those land in paid tier Phase 2 where we use a vetted TI feed.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
import urllib.error

from ..base import BaseAgent, Finding, Target
from .. import config

HIBP_PUBLIC_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_ACCOUNT = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
CRT_SH = "https://crt.sh/?q={q}&output=json"

TYPOSQUAT_TEMPLATES = [
    # Common homoglyph / deletion / swap patterns
    "{d}-secure.com", "{d}-login.com", "{d}-portal.com",
    "{d}.co", "{d}.net", "{d}s.com",
]

UA = {"User-Agent": config.USER_AGENT, "Accept": "application/json"}


def _get_json(url: str, headers: dict | None = None, timeout: int = 15):
    h = dict(UA)
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode(errors="replace")
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        # 404 = nothing found; 429 = rate limit; 5xx = upstream flakiness (crt.sh 502s a lot)
        if e.code in (404, 429) or 500 <= e.code < 600:
            return None
        return None
    except Exception:
        return None


class IthilAgent(BaseAgent):
    AGENT_KEY = "ithil"

    def scan_target(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        host = urllib.parse.urlparse(target["url"]).hostname or ""
        if not host:
            return findings

        # Strip to registrable-ish domain (naive; sufficient for demo)
        parts = host.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

        findings.extend(self._check_breaches_for_domain(root_domain))
        findings.extend(self._check_subdomain_surface(root_domain))
        findings.extend(self._check_typosquats(root_domain))

        # Per-email lookups only if we have the paid HIBP key AND the target
        # specifies emails to check (opt-in, avoids getting rate-limited)
        emails = target.get("emails") or []
        if emails and config.HIBP_API_KEY:
            for em in emails[:5]:
                findings.extend(self._check_email_breach(em))

        return findings

    def _check_breaches_for_domain(self, domain: str) -> list[Finding]:
        url = HIBP_PUBLIC_BREACHES + "?domain=" + urllib.parse.quote(domain)
        data = _get_json(url)
        if not data or not isinstance(data, list):
            return [Finding(
                severity="info", category="breach",
                title=f"No public breaches listed for {domain}",
                description="HaveIBeenPwned's public breach feed has no entry matching this domain. "
                            "This does NOT mean the domain is safe — only that no aggregated breach is indexed.",
                evidence={"domain": domain})]

        out = []
        for b in data[:5]:
            pwn = b.get("PwnCount", 0)
            title = b.get("Title", b.get("Name", "Unknown"))
            date = b.get("BreachDate", "")
            classes = b.get("DataClasses", [])
            out.append(Finding(
                severity="high" if pwn > 1_000_000 else "medium",
                category="breach",
                title=f"Domain {domain} appears in breach: {title}",
                description=f"{pwn:,} accounts exposed on {date}. Data classes: {', '.join(classes) or 'unknown'}.",
                evidence={"breach": b, "pwn_count": pwn},
                remediation="Force password resets for affected users. Rotate any shared secrets from the breach era. "
                            "Publish a security-incident advisory if users are likely impacted."))
        return out

    def _check_subdomain_surface(self, domain: str) -> list[Finding]:
        data = _get_json(CRT_SH.format(q=urllib.parse.quote("%." + domain)))
        if not data or not isinstance(data, list):
            return []
        names = set()
        for row in data:
            for n in (row.get("name_value") or "").splitlines():
                n = n.strip().lower()
                if n and "*" not in n and n.endswith(domain):
                    names.add(n)
        if not names:
            return []
        interesting = [n for n in names
                       if any(k in n for k in ("dev", "staging", "test", "admin",
                                               "internal", "beta", "qa", "uat",
                                               "vpn", "mail", "old", "legacy"))]
        out = []
        out.append(Finding(
            severity="info", category="surface",
            title=f"{len(names)} subdomains observed in certificate transparency logs",
            description="Public CT logs reveal every TLS certificate issued for your domain. "
                        "Each subdomain is potential attack surface.",
            evidence={"sample": sorted(list(names))[:20], "total": len(names)}))
        if interesting:
            out.append(Finding(
                severity="medium", category="surface",
                title=f"Staging/dev/admin-like subdomains publicly visible ({len(interesting)})",
                description="Subdomains with dev/staging/admin-style names are often less hardened than production "
                            "and become the softest path into the perimeter.",
                evidence={"subdomains": sorted(interesting)[:20]},
                remediation="Put non-prod subdomains behind SSO or VPN. If they must be public, bring security headers to parity with prod."))
        return out

    def _check_typosquats(self, domain: str) -> list[Finding]:
        base = domain.split(".")[0]
        hits = []
        for tmpl in TYPOSQUAT_TEMPLATES:
            cand = tmpl.format(d=base)
            if cand == domain:
                continue
            # Cheap "does it resolve" test
            try:
                import socket
                socket.gethostbyname(cand)
                hits.append(cand)
            except Exception:
                continue
        if hits:
            return [Finding(
                severity="medium", category="brand_risk",
                title=f"Possible typosquat domains resolve: {', '.join(hits[:5])}",
                description="Active domains with names similar to yours are common phishing setups.",
                evidence={"typosquats": hits},
                remediation="Register obvious look-alikes yourself, monitor with a DMARC/domain-intel tool, and request takedown if abuse confirmed.")]
        return []

    def _check_email_breach(self, email: str) -> list[Finding]:
        key = config.HIBP_API_KEY
        if not key:
            return []
        url = HIBP_ACCOUNT.format(email=urllib.parse.quote(email))
        data = _get_json(url, headers={"hibp-api-key": key, "user-agent": "PalantiriScanner"})
        if not data:
            return []
        if isinstance(data, list) and data:
            return [Finding(
                severity="high", category="breach",
                title=f"Email {email} appears in {len(data)} breaches",
                description="This email address was pwned in one or more published breaches.",
                evidence={"breaches": [b.get("Name") for b in data[:10]]},
                remediation="Force a password reset for this user. If this is a shared role inbox, rotate all tokens that inbox received.")]
        return []
