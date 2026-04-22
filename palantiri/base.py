"""Base Agent class — all Seven Stones inherit from this.

Lifecycle:
    agent = SomeAgent()
    scan = agent.start_scan(target)            # opens palantiri_scans row
    try:
        findings = agent.scan_target(target)   # subclass implements
        agent.persist_findings(scan, findings) # writes palantiri_findings
        agent.finish_scan(scan, findings)
    except Exception as e:
        agent.fail_scan(scan, str(e))
        raise

The base class handles Supabase persistence, local JSONL backup, stable
fingerprinting for dedup, and the Elostirion audit trail.
"""
from __future__ import annotations

import abc
import datetime as dt
import hashlib
import json
import logging
import time
import uuid
from collections import Counter
from typing import Any

from . import config, supa

log = logging.getLogger("palantiri.agent")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def fingerprint(target_id: str, agent: str, category: str, title: str) -> str:
    """Stable hash so repeated scans don't duplicate the same finding."""
    h = hashlib.sha256()
    h.update(f"{target_id}|{agent}|{category}|{title}".encode())
    return h.hexdigest()[:32]


class Finding(dict):
    """A single discovered issue. Subclasses return a list of these from scan_target()."""

    def __init__(self, *, severity: str, category: str, title: str,
                 description: str = "", evidence: dict | None = None,
                 remediation: str = ""):
        assert severity in SEV_ORDER, f"bad severity: {severity}"
        super().__init__(
            severity=severity,
            category=category,
            title=title[:200],
            description=description,
            evidence=evidence or {},
            remediation=remediation,
        )


class Target(dict):
    """A scan target. Either an in-memory ad-hoc dict or a row from palantiri_targets."""
    @classmethod
    def adhoc(cls, url: str, name: str | None = None) -> "Target":
        return cls(
            id=str(uuid.uuid5(uuid.NAMESPACE_URL, url)),
            name=name or url,
            url=url,
            domains=[],
            emails=[],
            tags=["adhoc"],
            _adhoc=True,
        )


class BaseAgent(abc.ABC):
    """Subclass and set AGENT_KEY + implement scan_target()."""

    AGENT_KEY: str = ""                       # e.g. "amon_sul"
    DEFAULT_SEVERITY: str = "info"

    def __init__(self, *, local_only: bool = False):
        """local_only=True skips Supabase writes (useful for dev + demos)."""
        assert self.AGENT_KEY, f"{type(self).__name__} must set AGENT_KEY"
        self.local_only = local_only or not supa.have_write_key()
        if self.local_only:
            log.info(f"[{self.AGENT_KEY}] local_only mode (no Supabase writes)")

    # ── required subclass entrypoint ────────────────────────────────────────
    @abc.abstractmethod
    def scan_target(self, target: Target) -> list[Finding]:
        ...

    # ── lifecycle ───────────────────────────────────────────────────────────
    def run(self, target: Target) -> dict:
        """Full lifecycle: open scan → scan → persist → close."""
        t0 = time.time()
        scan = self.start_scan(target)
        try:
            findings = self.scan_target(target)
            self.persist_findings(scan, target, findings)
            self.finish_scan(scan, findings, duration_ms=int((time.time()-t0)*1000))
            return {"scan": scan, "findings": findings, "ok": True}
        except Exception as exc:
            log.exception(f"[{self.AGENT_KEY}] scan failed for {target.get('url')}")
            self.fail_scan(scan, str(exc))
            return {"scan": scan, "findings": [], "ok": False, "error": str(exc)}

    # ── Supabase write helpers ──────────────────────────────────────────────
    def start_scan(self, target: Target) -> dict:
        row = {
            "id": str(uuid.uuid4()),
            "target_id": target["id"] if not target.get("_adhoc") else None,
            "agent": self.AGENT_KEY,
            "status": "running",
            "started_at": dt.datetime.utcnow().isoformat() + "Z",
        }
        if self.local_only:
            self._jsonl("scans", row)
            return row
        try:
            return supa.insert("palantiri_scans", row) or row
        except Exception:
            log.warning(f"[{self.AGENT_KEY}] could not open scan row — falling back to local")
            self._jsonl("scans", row)
            return row

    def finish_scan(self, scan: dict, findings: list[Finding], duration_ms: int):
        sev_counts = Counter(f["severity"] for f in findings)
        summary = {
            "findings": len(findings),
            **{sev: sev_counts.get(sev, 0) for sev in SEV_ORDER},
        }
        patch = {
            "status": "completed",
            "finished_at": dt.datetime.utcnow().isoformat() + "Z",
            "duration_ms": duration_ms,
            "summary": summary,
        }
        self._patch_scan(scan["id"], patch)
        self._audit("scan_completed", scan_id=scan["id"],
                    target_id=scan.get("target_id"), payload=summary)

    def fail_scan(self, scan: dict, err: str):
        patch = {
            "status": "failed",
            "finished_at": dt.datetime.utcnow().isoformat() + "Z",
            "error": err[:500],
        }
        self._patch_scan(scan["id"], patch)
        self._audit("scan_failed", scan_id=scan["id"],
                    target_id=scan.get("target_id"), payload={"error": err[:500]})

    def persist_findings(self, scan: dict, target: Target, findings: list[Finding]):
        if not findings:
            return
        for f in findings:
            row = {
                "id": str(uuid.uuid4()),
                "scan_id": scan["id"],
                "target_id": scan.get("target_id"),
                "agent": self.AGENT_KEY,
                "severity": f["severity"],
                "category": f["category"],
                "title": f["title"],
                "description": f.get("description", ""),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", ""),
                "status": "open",
                "fingerprint": fingerprint(str(scan.get("target_id") or target["id"]),
                                           self.AGENT_KEY, f["category"], f["title"]),
            }
            if self.local_only:
                self._jsonl("findings", row)
            else:
                try:
                    supa.insert("palantiri_findings", row, returning=False)
                except Exception:
                    log.warning(f"[{self.AGENT_KEY}] finding insert failed — falling back to local")
                    self._jsonl("findings", row)
            self._audit("finding_created", scan_id=scan["id"],
                        target_id=scan.get("target_id"), finding_id=row["id"],
                        payload={"severity": row["severity"],
                                 "category": row["category"],
                                 "title": row["title"]})

    # ── private ─────────────────────────────────────────────────────────────
    def _patch_scan(self, scan_id: str, patch: dict):
        if self.local_only:
            self._jsonl("scans_update", {"id": scan_id, **patch})
            return
        try:
            supa.update("palantiri_scans", {"id": scan_id}, patch)
        except Exception:
            log.warning(f"[{self.AGENT_KEY}] scan patch failed — falling back to local")
            self._jsonl("scans_update", {"id": scan_id, **patch})

    def _audit(self, event_type: str, *, scan_id: str | None = None,
               target_id: str | None = None, finding_id: str | None = None,
               payload: dict | None = None):
        row = {
            "ts": dt.datetime.utcnow().isoformat() + "Z",
            "actor": f"{self.AGENT_KEY}_agent",
            "event_type": event_type,
            "target_id": target_id,
            "scan_id": scan_id,
            "finding_id": finding_id,
            "payload": payload or {},
        }
        if self.local_only:
            self._jsonl("audit", row)
            return
        try:
            supa.insert("palantiri_audit", row, returning=False)
        except Exception:
            self._jsonl("audit", row)

    def _jsonl(self, bucket: str, row: dict):
        path = config.LOCAL_FINDINGS_DIR / f"{bucket}.jsonl"
        with path.open("a") as f:
            f.write(json.dumps(row, default=str) + "\n")
