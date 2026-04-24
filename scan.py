#!/usr/bin/env python3
"""Palantiri scan CLI.

Usage:
    # Free tier (no account, writes to palantiri/data/*.jsonl):
    python3 scan.py <url>                        # Quick + Advanced scan
    python3 scan.py <url> --tier free

    # Paid tiers (require SUPABASE_SERVICE_ROLE_KEY + ANTHROPIC_API_KEY in env):
    python3 scan.py <url> --tier watch
    python3 scan.py <url> --tier high_seat

    # Single stone:
    python3 scan.py <url> --agent amon_sul

    # Ecosystem preset:
    python3 scan.py ecosystem
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from palantiri.base import Target, SEV_ORDER
from palantiri.agents import ALL_AGENTS
from palantiri.tiers import TIERS, agents_for, FREE_AGENTS

log = logging.getLogger("palantiri.scan")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")


ECOSYSTEM = [
    ("JobZone (production)",     "https://jobzoneonline.com"),
    ("JobZone (Hostinger clone)", "https://palevioletred-elephant-981524.hostingersite.com"),
    ("Crucible Markets",         "https://crucible-markets-tmp.vercel.app"),
    ("Studio Labs",              "https://studio-labs-blond.vercel.app"),
    ("UNIFEED",                  "https://web-livid-six-43.vercel.app"),
    ("Palantiri (self)",         "https://palantirisecurity.com"),
]


def run_tier(url: str, name: str, tier: str):
    """Run every agent in the requested tier, in suite dependency order."""
    target = Target.adhoc(url, name=name)
    agent_keys = agents_for(tier)

    print(f"\n{'=' * 78}")
    print(f"PALANTIRI — tier: {tier}  ({TIERS[tier]['desc']})")
    print(f"TARGET: {name} — {url}")
    print(f"Running: {', '.join(agent_keys)}")
    print("=" * 78)

    totals = {sev: 0 for sev in SEV_ORDER}
    total_findings = 0

    for key in agent_keys:
        cls = ALL_AGENTS.get(key)
        if not cls:
            log.error("unknown agent: %s", key)
            continue
        agent = cls()
        res = agent.run(target)
        findings = res.get("findings", [])
        ok = res.get("ok", False)
        status = "OK" if ok else "FAIL"

        counts = {sev: 0 for sev in SEV_ORDER}
        for f in findings:
            counts[f["severity"]] += 1
            totals[f["severity"]] += 1
        total_findings += len(findings)

        sev_line = " ".join(f"{counts[s]}{s[0]}" for s in SEV_ORDER if counts[s])
        oss_tag = "[OSS]" if key in FREE_AGENTS else "[paid]"
        print(f"  {oss_tag} {key:<12} {status:<4} {len(findings):>3} findings  {sev_line}")

        for f in findings:
            sev = f["severity"]
            # Only print critical+high+medium in summary — rest in JSONL
            if sev in ("critical", "high", "medium"):
                print(f"      [{sev:>8}] {key}/{f['category']:<15} {f['title']}")

    print("-" * 78)
    tot_line = "  ".join(f"{totals[s]} {s}" for s in SEV_ORDER if totals[s])
    print(f"TOTAL: {total_findings} findings   {tot_line}")
    print("=" * 78)
    print("Local JSONL written to palantiri/data/")
    if tier == "free":
        print("Upgrade to 'watch' for correlation + LLM reasoning + SOC rollup.")
    print()


def run_single(url: str, name: str, agent_key: str):
    target = Target.adhoc(url, name=name)
    cls = ALL_AGENTS.get(agent_key)
    if not cls:
        log.error("unknown agent: %s  (known: %s)", agent_key, list(ALL_AGENTS))
        return
    agent = cls()
    res = agent.run(target)
    print(json.dumps({"target": name, "agent": agent_key,
                      "ok": res["ok"], "findings": len(res["findings"])},
                     indent=2, default=str))
    for f in res["findings"]:
        print(f"  [{f['severity']:>8}] {agent_key}/{f['category']:<15} {f['title']}")


def main():
    ap = argparse.ArgumentParser(
        description="Palantiri Seven Stones scanner — free tier runs account-less.")
    ap.add_argument("target", help="URL or 'ecosystem' to run the preset")
    ap.add_argument("--name", default=None, help="human label (default: url)")
    ap.add_argument("--tier", default="free", choices=list(TIERS),
                    help="tier to run (default: free — OSS, no account)")
    ap.add_argument("--agent", default=None,
                    help=f"run a single agent (overrides --tier). One of: {list(ALL_AGENTS)}")
    args = ap.parse_args()

    if args.target == "ecosystem":
        for name, url in ECOSYSTEM:
            if args.agent:
                run_single(url, name, args.agent)
            else:
                run_tier(url, name, args.tier)
        return

    name = args.name or args.target
    if args.agent:
        run_single(args.target, name, args.agent)
    else:
        run_tier(args.target, name, args.tier)


if __name__ == "__main__":
    main()
