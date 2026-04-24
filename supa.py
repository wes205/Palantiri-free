"""Tiny Supabase REST client — just what the agents need.

No Python dependency on supabase-py to keep this lightweight. We only need:
  - insert into palantiri_scans / palantiri_findings / palantiri_audit
  - update palantiri_scans (finish)
  - select palantiri_targets / palantiri_findings

Uses the service-role key when present (needed to bypass RLS for agent writes).
Falls back to anon key for read-only ops, which is fine for dashboards but will
NOT let agents insert findings — set SUPABASE_SERVICE_ROLE_KEY before running.
"""
from __future__ import annotations
import json
import logging
import urllib.request
import urllib.error
from typing import Any

from . import config

log = logging.getLogger("palantiri.supa")


def _key() -> str:
    return config.SUPABASE_SERVICE_ROLE_KEY or config.SUPABASE_ANON_KEY


def _req(method: str, path: str, body: Any | None = None, prefer: str | None = None) -> Any:
    url = f"{config.SUPABASE_URL}/rest/v1{path}"
    headers = {
        "apikey": _key(),
        "Authorization": f"Bearer {_key()}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode()
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode(errors="replace")
        log.warning("supabase %s %s → HTTP %s: %s", method, path, e.code, body_txt[:300])
        raise
    except urllib.error.URLError as e:
        log.warning("supabase %s %s → network error: %s", method, path, e)
        raise


def insert(table: str, row: dict, returning: bool = True) -> dict | None:
    prefer = "return=representation" if returning else "return=minimal"
    out = _req("POST", f"/{table}", body=row, prefer=prefer)
    if isinstance(out, list) and out:
        return out[0]
    return None


def update(table: str, match: dict, patch: dict) -> dict | None:
    q = "&".join(f"{k}=eq.{urllib.request.quote(str(v))}" for k, v in match.items())
    out = _req("PATCH", f"/{table}?{q}", body=patch, prefer="return=representation")
    if isinstance(out, list) and out:
        return out[0]
    return None


def select(table: str, *, filters: dict | None = None, order: str | None = None,
           limit: int | None = None) -> list[dict]:
    parts = []
    if filters:
        for k, v in filters.items():
            if isinstance(v, tuple):
                # (op, value) form, e.g. ("gte", "2026-01-01")
                op, val = v
                parts.append(f"{k}={op}.{urllib.request.quote(str(val))}")
            else:
                parts.append(f"{k}=eq.{urllib.request.quote(str(v))}")
    if order:
        parts.append(f"order={order}")
    if limit:
        parts.append(f"limit={limit}")
    qs = ("?" + "&".join(parts)) if parts else ""
    out = _req("GET", f"/{table}{qs}")
    return out if isinstance(out, list) else []


def have_write_key() -> bool:
    return bool(config.SUPABASE_SERVICE_ROLE_KEY)
