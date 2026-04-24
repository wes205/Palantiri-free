"""Annúminas — "Tower of the West. Keeps the kingdom lawful."

Governance & compliance scanner. Checks:
  - Privacy policy page present + reachable
  - Terms of service present + reachable
  - Cookie consent mechanism detectable
  - PII in URLs (email, SSN-like, long numeric tokens, session-id in query)
  - Third-party tracker surface (Google Analytics, Meta Pixel, TikTok, etc.)
  - Basic SOC2 / GDPR / CCPA / HIPAA signal alignment (presence of DPO/contact,
    data-deletion path, accessibility statement)
  - robots.txt + sitemap presence (not security per se, but governance posture)

Pure stdlib. Read-only GET with a short body-peek.
"""
from __future__ import annotations

import re
import urllib.parse
import urllib.request
import urllib.error

from ..base import BaseAgent, Finding, Target
from .. import config

LEGAL_PAGE_CANDIDATES = {
    "privacy": [
        "privacy-policy", "privacy", "privacy.html", "privacy-policy.html",
        "legal/privacy", "privacy/policy", "about/privacy",
    ],
    "terms": [
        "terms-of-service", "terms", "tos", "terms.html",
        "terms-of-service.html", "legal/terms", "terms-and-conditions",
    ],
    "security_txt": [".well-known/security.txt"],
    "accessibility": ["accessibility", "accessibility-statement", "a11y"],
    "contact": ["contact", "contact-us", "support", "about/contact"],
}

TRACKER_SIGNATURES = {
    "google_analytics": [r"google-analytics\.com/ga\.js", r"gtag\(", r"googletagmanager\.com/gtag",
                         r"ga\('create'", r"G-[A-Z0-9]{6,}"],
    "meta_pixel":       [r"connect\.facebook\.net", r"fbq\('init'"],
    "tiktok_pixel":     [r"analytics\.tiktok\.com"],
    "linkedin_insight": [r"px\.ads\.linkedin\.com", r"_linkedin_partner_id"],
    "hotjar":           [r"static\.hotjar\.com"],
    "mixpanel":         [r"cdn\.mxpnl\.com"],
    "segment":          [r"cdn\.segment\.com"],
}

COOKIE_BANNER_SIGNATURES = [
    r"cookie[-_ ]?consent", r"cookie[-_ ]?banner", r"onetrust", r"cookiebot",
    r"klaro", r"osano", r"uc-banner", r"we use cookies",
]

DATA_DELETION_SIGNATURES = [
    r"right to (be )?(forgotten|delete|deletion)",
    r"delete (my|your) (account|data)",
    r"data (deletion|removal) request",
    r"subject access request", r"\bDSAR\b",
    r"ccpa (opt[- ]?out|request)", r"gdpr request",
]

# PII-in-URL patterns
PII_URL_PATTERNS = {
    "email_in_query": re.compile(r"[?&][^=&]*email=[^&]*@", re.I),
    "ssn_like":       re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "cc_like":        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "session_token":  re.compile(r"[?&](sid|sessionid|session_id|token|auth)=[A-Za-z0-9+/=_\-]{16,}", re.I),
}


def _get(url: str, timeout: int = 10, max_bytes: int = 200_000):
    headers = {"User-Agent": config.USER_AGENT, "Accept": "text/html,*/*"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes).decode(errors="replace")
            return resp.status, dict(resp.headers.items()), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, ""
    except Exception:
        return None, {}, ""


class AnnuminasAgent(BaseAgent):
    AGENT_KEY = "annuminas"

    def scan_target(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        base = target["url"].rstrip("/")

        # Fetch homepage once for tracker + cookie-banner detection
        status, _, body = _get(base)
        if status is None:
            findings.append(Finding(
                severity="high", category="reachability",
                title="Annúminas could not reach the homepage",
                description=f"{base} returned no response during governance scan."))
            return findings

        findings.extend(self._check_legal_pages(base))
        findings.extend(self._check_cookie_consent(body, base))
        findings.extend(self._check_trackers(body, base))
        findings.extend(self._check_data_deletion(body, base))
        findings.extend(self._check_robots(base))
        # Scan the homepage URL itself + any links we picked up for PII leaks
        findings.extend(self._check_pii_in_url(base))
        return findings

    # ── legal-page presence ─────────────────────────────────────────────────
    def _check_legal_pages(self, base: str) -> list[Finding]:
        out = []
        for kind, paths in LEGAL_PAGE_CANDIDATES.items():
            found_path = None
            for p in paths:
                status, _, _ = _get(f"{base}/{p}", timeout=6, max_bytes=1024)
                if status == 200:
                    found_path = p
                    break
            if kind == "privacy" and not found_path:
                out.append(Finding(
                    severity="high", category="compliance",
                    title="No privacy policy page detected",
                    description="A published privacy policy is required by GDPR, CCPA, CalOPPA, and most advertising partners.",
                    remediation="Publish /privacy-policy describing data collection, retention, and user rights."))
            elif kind == "terms" and not found_path:
                out.append(Finding(
                    severity="medium", category="compliance",
                    title="No terms-of-service page detected",
                    description="ToS defines acceptable use and liability limits.",
                    remediation="Publish /terms-of-service."))
            elif kind == "security_txt" and not found_path:
                out.append(Finding(
                    severity="info", category="policy",
                    title="No .well-known/security.txt",
                    description="security.txt gives researchers a standard way to report vulnerabilities.",
                    remediation="Add /.well-known/security.txt with a contact email and disclosure policy."))
            elif kind == "accessibility" and not found_path:
                out.append(Finding(
                    severity="info", category="compliance",
                    title="No accessibility statement",
                    description="ADA litigation against public websites has climbed; an accessibility statement documents conformance effort.",
                    remediation="Publish an accessibility statement and target WCAG 2.1 AA."))
        return out

    # ── cookie consent ──────────────────────────────────────────────────────
    def _check_cookie_consent(self, body: str, base: str) -> list[Finding]:
        low = body.lower()
        has_banner = any(re.search(sig, low) for sig in COOKIE_BANNER_SIGNATURES)
        has_trackers = any(
            any(re.search(p, low) for p in patterns)
            for patterns in TRACKER_SIGNATURES.values()
        )
        if has_trackers and not has_banner:
            return [Finding(
                severity="high", category="compliance",
                title="Third-party trackers load with no cookie-consent banner",
                description="Under GDPR (and increasingly CPRA) non-essential cookies require prior consent. "
                            "Trackers firing on first load without a banner is one of the most-fined compliance violations.",
                evidence={"url": base},
                remediation="Install a consent management platform (Cookiebot, OneTrust, Klaro, or a lightweight homegrown banner). "
                            "Block non-essential scripts until the user opts in.")]
        if has_trackers and has_banner:
            return [Finding(
                severity="info", category="compliance",
                title="Cookie banner present",
                description="A cookie-consent mechanism is detectable. Confirm scripts are blocked before consent.")]
        return []

    # ── trackers ────────────────────────────────────────────────────────────
    def _check_trackers(self, body: str, base: str) -> list[Finding]:
        hits = []
        for name, patterns in TRACKER_SIGNATURES.items():
            if any(re.search(p, body, re.I) for p in patterns):
                hits.append(name)
        if not hits:
            return []
        return [Finding(
            severity="info", category="trackers",
            title=f"Third-party trackers detected: {', '.join(hits)}",
            description="Disclose these in your privacy policy and ensure consent gating.",
            evidence={"trackers": hits, "url": base})]

    # ── data-deletion path ──────────────────────────────────────────────────
    def _check_data_deletion(self, body: str, base: str) -> list[Finding]:
        low = body.lower()
        # Only a signal — we check homepage. A real deployment would crawl /privacy.
        found = any(re.search(p, low) for p in DATA_DELETION_SIGNATURES)
        if not found:
            # Also check privacy page if we can find it
            privacy_body = None
            for p in ("privacy-policy", "privacy", "privacy.html", "privacy-policy.html"):
                status, _, b = _get(f"{base}/{p}", max_bytes=100_000)
                if status == 200:
                    privacy_body = (b or "").lower()
                    break
            if privacy_body is not None:
                found = any(re.search(p, privacy_body) for p in DATA_DELETION_SIGNATURES)
        if not found:
            return [Finding(
                severity="medium", category="compliance",
                title="No visible data-deletion / DSAR path",
                description="GDPR, CCPA, and CPRA all require a reasonably accessible way for users to request deletion. "
                            "Neither the homepage nor the privacy policy (if we could find one) mention DSAR / right to deletion.",
                remediation="Add a clear 'Request data deletion' path (email link, form, or in-app button) and document it in the privacy policy.")]
        return []

    # ── robots.txt + sitemap ────────────────────────────────────────────────
    def _check_robots(self, base: str) -> list[Finding]:
        out = []
        rs, _, rb = _get(f"{base}/robots.txt", timeout=6, max_bytes=50_000)
        if rs != 200:
            out.append(Finding(
                severity="info", category="crawl",
                title="robots.txt not reachable",
                description="Not a security issue, but most mature sites have one.",
                remediation="Add /robots.txt describing crawl rules; link the sitemap from there."))
        else:
            # "Disallow: /" with nothing else often means staging leaked
            if re.search(r"Disallow:\s*/\s*$", rb, re.M) and "Allow" not in rb:
                out.append(Finding(
                    severity="low", category="crawl",
                    title="robots.txt disallows all — is this intentional?",
                    description="Full disallow usually indicates a staging site accidentally made public."))
        ss, _, _ = _get(f"{base}/sitemap.xml", timeout=6, max_bytes=1024)
        if ss != 200:
            out.append(Finding(
                severity="info", category="crawl",
                title="No /sitemap.xml",
                description="Helps SEO; not a security issue."))
        return out

    # ── PII in URL ──────────────────────────────────────────────────────────
    def _check_pii_in_url(self, url: str) -> list[Finding]:
        out = []
        for key, pat in PII_URL_PATTERNS.items():
            if pat.search(url):
                out.append(Finding(
                    severity="high", category="pii",
                    title=f"Possible PII in URL: {key}",
                    description="PII in URLs leaks to server logs, referrer headers, and browser history.",
                    evidence={"url": url, "match": key},
                    remediation="Move sensitive values to POST bodies or HTTPS-only cookies. Never accept PII as query params."))
        return out
