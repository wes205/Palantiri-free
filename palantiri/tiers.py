"""Palantiri tier definitions — OSS Free Edition.

Free tier is the only tier shipped in this repo. Paid tiers (Watch / Guard /
High Seat) require the private paid fork at palantirisecurity.ai.
"""
from __future__ import annotations

FREE_AGENTS = ["amon_sul", "annuminas", "ithil"]

TIERS = {
    "free": {"agents": FREE_AGENTS, "guard": [],
             "desc": "Quick + Advanced external scan. No account required. MIT licensed."},
}


def agents_for(tier: str) -> list[str]:
    if tier != "free":
        raise ValueError(
            f"Tier {tier!r} is a paid tier. The OSS Free Edition only supports "
            f"--tier free. See https://palantirisecurity.ai/#pricing for paid tiers."
        )
    return FREE_AGENTS


def is_oss(agent_key: str) -> bool:
    return agent_key in FREE_AGENTS
