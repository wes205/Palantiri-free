"""Runtime configuration for the Palantiri agent framework."""
from __future__ import annotations
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"

# Lightweight dotenv loader (avoid python-dotenv dependency)
if ENV_FILE.exists():
    for raw in ENV_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)

SUPABASE_URL       = os.getenv("SUPABASE_URL", "https://zpsdffdluphqnwnmoshn.supabase.co")
SUPABASE_ANON_KEY  = os.getenv("SUPABASE_ANON_KEY", "sb_publishable_qfr2XG5tdfNje2CfBjVANg_a9yccq68")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")  # required for agent writes
ANTHROPIC_API_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
HIBP_API_KEY       = os.getenv("HIBP_API_KEY", "")  # optional; Ithil uses free k-anonymity endpoint if absent

SCAN_TIMEOUT_SEC   = int(os.getenv("PALANTIRI_SCAN_TIMEOUT_SEC", "20"))
USER_AGENT         = os.getenv("PALANTIRI_USER_AGENT",
                               "PalantiriScanner/0.1 (+https://palantirisecurity.ai)")

# Agents may also write to a local JSONL dump as a second-hand backup
LOCAL_FINDINGS_DIR = ROOT / "palantiri" / "data"
LOCAL_FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
