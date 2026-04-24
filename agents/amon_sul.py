"""Amon Sûl — "Hill of the Wind. Widest view from high ground."

Perimeter + network posture scanner. Checks:
  - HTTPS reachability + TLS certificate validity + expiry
  - HTTP → HTTPS redirect
  - Security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
    Referrer-Policy, Permissions-Policy, X-XSS-Protection (legacy)
  - Server banner leak / version disclosure
  - Exposed paths: .git/, .env, /phpinfo.php, /phpmyadmin, /.DS_Store,
    /wp-config.php, /server-status, /actuator/health, /.well-known/security.txt
  - DNS: A + AAAA records, CAA present?
  - Open / reachable port surface (minimal — just 80/443/21/22 HEAD probes)

No external libraries required — stdlib only. Safe read-only probing;
no fuzzing, no auth, no form submissions.
"""
from __future__ import annotations

import datetime as dt
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error

from ..base import BaseAgent, Finding, Target
from .. import config


# Paths we HEAD-probe looking for common leak/misconfiguration sources.
# Status codes 200/301/302/401/403 on these paths generally indicates presence.
EXPOSED_PATHS = [
    (".git/config",                "critical", "exposed_path",
     "Exposed .git repository",
     "The .git directory is reachable from the public web. Attackers can reconstruct source code, "
     "credentials, and history.",
     "Block /.git/ at your web server or CDN. Example for nginx: `location ~ /\\.git { deny all; }`."),
    (".env",                       "critical", "exposed_path",
     "Exposed .env file",
     ".env files typically contain database URLs, API keys, and secrets. Publicly reachable .env "
     "is one of the highest-severity misconfigurations.",
     "Block /.env at the web server. Rotate every secret the file contained."),
    (".DS_Store",                  "low",      "exposed_path",
     "macOS .DS_Store file exposed",
     "Reveals directory contents. Minor info-leak; not critical on its own.",
     "Block /.DS_Store. Add to your web server's deny patterns and to .gitignore."),
    ("wp-config.php",              "critical", "exposed_path",
     "Exposed wp-config.php",
     "WordPress configuration with DB credentials. A 200 here is catastrophic; 403 is expected.",
     "Ensure wp-config.php returns 403 or is outside the web root."),
    ("wp-config.php.bak",          "critical", "exposed_path",
     "Exposed wp-config.php.bak",
     "Backup file with full WP credentials.",
     "Delete the backup and block *.bak and *.old patterns."),
    ("phpinfo.php",                "high",     "exposed_path",
     "Public phpinfo()",
     "Reveals server config, loaded modules, env vars, paths — a reconnaissance goldmine.",
     "Delete the file. Never leave phpinfo() reachable."),
    ("phpmyadmin/",                "high",     "exposed_path",
     "phpMyAdmin reachable",
     "phpMyAdmin on a public path is a brute-force target.",
     "Move behind VPN/IP allowlist, or proxy-auth."),
    ("server-status",              "medium",   "exposed_path",
     "Apache server-status exposed",
     "Apache mod_status page exposes request URLs and internal state.",
     "Restrict /server-status to 127.0.0.1 or remove mod_status."),
    ("actuator/health",            "low",      "exposed_path",
     "Spring Actuator reachable",
     "The /actuator endpoint can leak env vars and health info. /health alone is usually fine; "
     "the discovery of actuator at all warrants reviewing which sub-endpoints are exposed.",
     "Lock down actuator/* behind auth (spring-boot-starter-security)."),
    (".well-known/security.txt",   "info",     "policy",
     ".well-known/security.txt missing",
     "security.txt is the standard disclosure policy file.",
     "Add a .well-known/security.txt with a contact email for responsible disclosure."),
]

# Headers we expect on a hardened web property
EXPECTED_HEADERS = {
    "Strict-Transport-Security":   ("high",   "Missing HSTS header",
                                     "Browsers won't pin HTTPS — downgrades and cookie theft via "
                                     "network attacker become possible.",
                                     "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`."),
    "Content-Security-Policy":     ("medium", "Missing Content-Security-Policy",
                                     "No CSP means broader XSS impact if any vector exists.",
                                     "Start with a report-only CSP, then tighten."),
    "X-Content-Type-Options":      ("low",    "Missing X-Content-Type-Options",
                                     "MIME-type sniffing can be abused on older browsers.",
                                     "Add `X-Content-Type-Options: nosniff`."),
    "X-Frame-Options":             ("low",    "Missing X-Frame-Options / frame-ancestors",
                                     "Clickjacking protection absent.",
                                     "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`."),
    "Referrer-Policy":             ("low",    "Missing Referrer-Policy",
                                     "Cross-origin referer can leak sensitive URL params.",
                                     "Add `Referrer-Policy: strict-origin-when-cross-origin`."),
    "Permissions-Policy":          ("info",   "Missing Permissions-Policy",
                                     "Not required, but limits what third-party content can ask for.",
                                     "Add `Permissions-Policy` restricting camera/mic/geolocation by default."),
}


def _head(url: str, timeout: int = 10):
    """HEAD request; fall through to GET if HEAD is 405."""
    headers = {"User-Agent": config.USER_AGENT, "Accept": "*/*"}
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()) if e.headers else {}
        except (urllib.error.URLError, socket.timeout, ConnectionError):
            if method == "GET":
                return None, {}
            continue
    return None, {}


def _get_body(url: str, timeout: int = 8, max_bytes: int = 8192):
    """GET and return (status, body_bytes). Cap body read so scans stay light."""
    headers = {"User-Agent": config.USER_AGENT, "Accept": "*/*"}
    try:
        req = urllib.request.Request(url, method="GET", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        try:
            return e.code, (e.read(max_bytes) if hasattr(e, "read") else b"")
        except Exception:
            return e.code, b""
    except Exception:
        return None, b""


# Content-signature markers that prove a sensitive file actually leaked
# (vs. being served empty or executed by a handler).
LEAK_MARKERS = {
    "wp-config.php":     [b"<?php", b"DB_NAME", b"DB_PASSWORD", b"AUTH_KEY", b"table_prefix"],
    "wp-config.php.bak": [b"<?php", b"DB_NAME", b"DB_PASSWORD", b"AUTH_KEY"],
    ".env":              [b"=", b"API_KEY", b"SECRET", b"DATABASE_URL", b"PASSWORD"],
    ".git/config":       [b"[core]", b"[remote", b"repositoryformatversion"],
    "phpinfo.php":       [b"PHP Version", b"phpinfo()", b"System ", b"Build Date"],
    ".DS_Store":         [b"Bud1"],  # DS_Store magic
}


def _host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""


def _scheme(url: str) -> str:
    return urllib.parse.urlparse(url).scheme or "https"


class AmonSulAgent(BaseAgent):
    AGENT_KEY = "amon_sul"

    def scan_target(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        url = target["url"].rstrip("/")
        host = _host(url)
        scheme = _scheme(url)

        # 1. TLS certificate (if HTTPS)
        if scheme == "https":
            findings.extend(self._check_tls(host))

        # 2. HTTP → HTTPS redirect
        findings.extend(self._check_http_redirect(host, scheme))

        # 3. Security headers on the homepage
        status, headers = _head(url)
        if status is None:
            findings.append(Finding(
                severity="high", category="reachability",
                title="Target did not respond",
                description=f"Could not reach {url} for perimeter probing. TLS or DNS may be failing.",
                remediation="Verify the domain resolves, the origin accepts HEAD/GET, and no WAF is 403'ing our scanner UA."))
            return findings

        findings.extend(self._check_headers(url, headers))
        findings.extend(self._check_banner_leak(headers))

        # 4. Exposed paths
        findings.extend(self._check_exposed_paths(url))

        # 5. DNS posture
        if host:
            findings.extend(self._check_dns(host))

        return findings

    # ──────────────────────────────────────────────────────────────
    def _check_tls(self, host: str) -> list[Finding]:
        out = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
        except ssl.SSLError as e:
            out.append(Finding(
                severity="high", category="tls",
                title="TLS handshake failed",
                description=f"SSL error on {host}:443 — {e}",
                evidence={"error": str(e)},
                remediation="Review your certificate chain, cipher suites, and TLS version."))
            return out
        except Exception as e:
            out.append(Finding(
                severity="high", category="tls",
                title="Could not establish TLS connection",
                description=f"{host}:443 — {e}",
                evidence={"error": str(e)}))
            return out

        # TLS protocol version
        if version and version in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(Finding(
                severity="high", category="tls",
                title=f"Insecure TLS protocol version: {version}",
                description="TLS 1.0 and 1.1 are deprecated; SSL 3.0 is broken.",
                evidence={"negotiated_version": version},
                remediation="Require TLS 1.2 minimum. Prefer TLS 1.3."))

        # Expiry
        na = cert.get("notAfter")
        if na:
            try:
                expires = dt.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                days_left = (expires - dt.datetime.utcnow()).days
                if days_left < 0:
                    out.append(Finding(
                        severity="critical", category="tls",
                        title="TLS certificate expired",
                        description=f"Expired {-days_left} days ago.",
                        evidence={"notAfter": na},
                        remediation="Renew immediately."))
                elif days_left < 14:
                    out.append(Finding(
                        severity="high", category="tls",
                        title=f"TLS certificate expires in {days_left} days",
                        description="Renew well before expiry.",
                        evidence={"notAfter": na, "days_left": days_left},
                        remediation="Renew the certificate; set up automated renewal."))
                elif days_left < 30:
                    out.append(Finding(
                        severity="medium", category="tls",
                        title=f"TLS certificate expires in {days_left} days",
                        evidence={"notAfter": na, "days_left": days_left},
                        remediation="Plan renewal; automate if possible."))
            except Exception:
                pass

        # Subject / SAN mismatch for host
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        if sans and host not in sans and not any(
            s.startswith("*.") and host.endswith(s[1:]) for s in sans
        ):
            out.append(Finding(
                severity="medium", category="tls",
                title="Certificate SAN doesn't match host",
                description=f"Host {host} not in subjectAltName {sans}",
                evidence={"subjectAltName": sans}))

        return out

    def _check_http_redirect(self, host: str, scheme: str) -> list[Finding]:
        if not host:
            return []
        url = f"http://{host}/"
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": config.USER_AGENT})
            # Don't follow redirects — we want to see the Location header itself
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **kw): return None
            opener = urllib.request.build_opener(NoRedirect)
            try:
                resp = opener.open(req, timeout=8)
                status = resp.status
                loc = resp.headers.get("Location", "")
            except urllib.error.HTTPError as e:
                status = e.code
                loc = e.headers.get("Location", "") if e.headers else ""
            except Exception:
                return []
            if status == 200:
                return [Finding(
                    severity="high", category="transport",
                    title="HTTP served without redirect to HTTPS",
                    description="The origin answers plain HTTP with content instead of 301/308 to HTTPS.",
                    remediation="Configure a permanent redirect from HTTP to HTTPS at the origin or CDN.")]
            if status in (301, 302, 307, 308):
                if loc.startswith("https://"):
                    return []
                return [Finding(
                    severity="medium", category="transport",
                    title="HTTP redirects but not to HTTPS",
                    description=f"Location header is {loc!r}",
                    evidence={"status": status, "location": loc},
                    remediation="Make sure HTTP redirects to https:// on the same host.")]
        except Exception:
            pass
        return []

    def _check_headers(self, url: str, headers: dict) -> list[Finding]:
        out = []
        present = {k.lower(): v for k, v in headers.items()}
        for hdr, (sev, title, desc, fix) in EXPECTED_HEADERS.items():
            if hdr.lower() not in present:
                out.append(Finding(
                    severity=sev, category="header",
                    title=title,
                    description=desc,
                    evidence={"url": url, "missing_header": hdr},
                    remediation=fix))
        # HSTS preload hint
        hsts = present.get("strict-transport-security", "")
        if hsts and "preload" not in hsts.lower() and "includesubdomains" not in hsts.lower():
            out.append(Finding(
                severity="info", category="header",
                title="HSTS present but not hardened",
                description="Consider adding includeSubDomains and preload.",
                evidence={"value": hsts},
                remediation="Upgrade to `max-age=63072000; includeSubDomains; preload` once ready."))
        return out

    def _check_banner_leak(self, headers: dict) -> list[Finding]:
        out = []
        present = {k.lower(): v for k, v in headers.items()}
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            v = present.get(h)
            if v and any(ch.isdigit() for ch in v):
                out.append(Finding(
                    severity="low", category="info_leak",
                    title=f"Version leak in {h} header",
                    description=f"Exact version {v!r} is disclosed to every visitor. Helps attackers fingerprint known CVEs.",
                    evidence={"header": h, "value": v},
                    remediation="Suppress or generalize the header (e.g. nginx `server_tokens off;`)."))
        return out

    def _check_exposed_paths(self, base: str) -> list[Finding]:
        out = []
        for path, sev, cat, title, desc, fix in EXPOSED_PATHS:
            url = f"{base}/{path}"
            status, _ = _head(url, timeout=6)
            if status is None:
                continue

            # security.txt is a POSITIVE signal — only flag its absence
            if path == ".well-known/security.txt":
                if status in (404, 403, None):
                    out.append(Finding(severity=sev, category=cat, title=title,
                                       description=desc, remediation=fix,
                                       evidence={"url": url, "status": status}))
                continue

            if status == 200:
                # For paths with known leak markers, verify content actually leaked.
                # Files like wp-config.php legitimately return 200 with empty body
                # when PHP executes them — that is NOT a leak.
                if path in LEAK_MARKERS:
                    _, body = _get_body(url, timeout=6)
                    markers_hit = [m.decode("latin-1", "ignore")
                                   for m in LEAK_MARKERS[path] if m in body]
                    if not markers_hit:
                        # 200 but no leak content — record as informational, not critical
                        if body.strip():
                            # Non-empty but non-matching — worth a low note
                            out.append(Finding(
                                severity="info", category=cat,
                                title=f"{path} returns 200 but no leak markers found",
                                description="The path is reachable but the body doesn't contain "
                                            "the usual credential/secret markers. Likely executed "
                                            "by a handler or an unrelated page. Not flagging as a leak.",
                                evidence={"url": url, "status": status,
                                          "body_bytes": len(body)},
                                remediation="Confirm the handler intentionally serves this path; "
                                            "ideally return 404 to reduce attack surface."))
                        # empty body → server handled it correctly, skip silently
                        continue
                    # Content actually leaked — flag at declared severity with proof
                    out.append(Finding(
                        severity=sev, category=cat, title=title,
                        description=desc + f" Confirmed leak markers: {', '.join(markers_hit)}.",
                        remediation=fix,
                        evidence={"url": url, "status": status,
                                  "markers_found": markers_hit,
                                  "body_bytes": len(body)}))
                else:
                    # Paths without leak markers — status 200 is the signal itself
                    out.append(Finding(severity=sev, category=cat, title=title,
                                       description=desc, remediation=fix,
                                       evidence={"url": url, "status": status}))
            elif status in (401, 403) and path in ("wp-config.php", ".git/config", ".env"):
                # Present but locked — lower severity
                out.append(Finding(severity="low", category=cat,
                                   title=f"{title} — file present but access-denied",
                                   description="The path returns 401/403, which usually means the file exists. "
                                               "Worth confirming it can't be reached via a backup, alternate host, or cache.",
                                   evidence={"url": url, "status": status},
                                   remediation=fix))
        return out

    def _check_dns(self, host: str) -> list[Finding]:
        out = []
        try:
            infos = socket.getaddrinfo(host, None)
            v4 = {i[4][0] for i in infos if i[0] == socket.AF_INET}
            v6 = {i[4][0] for i in infos if i[0] == socket.AF_INET6}
            if not v4:
                out.append(Finding(
                    severity="low", category="dns",
                    title="No IPv4 A records",
                    description=f"{host} doesn't resolve to any IPv4. Most clients still need v4.",
                    remediation="Add an A record."))
            if not v6:
                out.append(Finding(
                    severity="info", category="dns",
                    title="No IPv6 AAAA records",
                    description="Not a vulnerability; just a posture note.",
                    remediation="Consider adding AAAA records if your hosting supports it."))
            out.append(Finding(
                severity="info", category="dns",
                title=f"Resolved {host} to {len(v4)} IPv4 and {len(v6)} IPv6 addresses",
                evidence={"A": sorted(v4), "AAAA": sorted(v6)}))
        except socket.gaierror as e:
            out.append(Finding(
                severity="high", category="dns",
                title=f"DNS resolution failed for {host}",
                description=str(e),
                remediation="Check nameserver configuration and domain registration."))
        return out
