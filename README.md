# Palantiri Security — Free Edition

**Three open-source "stones" that scan any website for security, compliance, and exposure issues. No account. No rate limits. MIT licensed.**

> Palantiri Security is an IT-security SaaS built by CRUCiBLE CAPiTAL SYSTEMS LLC. The **Free Edition** in this repository is the open-source core we give away. Paid tiers (Watch / Guard / High Seat) add continuous monitoring, LLM-driven correlation, endpoint protection, and enterprise compliance evidence on top of this foundation.
>
> This project is **not affiliated with Palantir Technologies Inc.** "Palantíri" is a Tolkien reference — the seeing-stones.

---

## What's in the box

Three scanning "stones," each skilled in one domain:

| Stone | Role | What it actually checks |
|-------|------|-------------------------|
| **Amon Sûl**  | Perimeter posture | TLS cert + expiry, HTTP→HTTPS redirect, security headers (HSTS/CSP/X-CTO/X-FO/Referrer-Policy/Permissions-Policy), server banner version leaks, exposed-path fingerprinting with body-content leak verification (`.git/config`, `.env`, `wp-config.php`, `phpinfo.php`, `phpmyadmin`, `server-status`, etc.), DNS A/AAAA resolution, `.well-known/security.txt` policy check |
| **Annúminas** | Governance & compliance | Legal-page presence (Privacy, Terms, Accessibility, Contact, security.txt), cookie-consent banner detection, third-party tracker signatures (GA, Meta Pixel, TikTok, LinkedIn Insight, Hotjar, Mixpanel, Segment), PII-in-URL patterns (emails, SSN-like, CC-like, session tokens in query strings), GDPR-style "tracker without consent banner" detection |
| **Ithil**     | Dark web & insider threat | HIBP public breaches lookup (no key required), CT-log subdomain enumeration via crt.sh, public-facing staging/dev/admin/API/backup subdomain exposure, typosquat domain pattern generator, optional per-email breach lookup if you supply a HIBP key |

All three run **entirely from Python stdlib**. No `pip install` pain, no dependencies to audit.

---

## Quick start

```bash
git clone https://github.com/CRUCiBLE-CAPiTAL-SYSTEMS/palantiri-free
cd palantiri-free

# Quick + Advanced scan of any site:
python3 scan.py https://example.com

# Just one stone:
python3 scan.py https://example.com --agent amon_sul
python3 scan.py https://example.com --agent annuminas
python3 scan.py https://example.com --agent ithil
```

Findings are written to `palantiri/data/findings.jsonl` in append-only JSON Lines. No account, no network calls to us, no telemetry.

---

## Example output

```
==============================================================================
PALANTIRI — tier: free  (Quick + Advanced external scan. No account.)
TARGET: example.com — https://example.com
Running: amon_sul, annuminas, ithil
==============================================================================
  [OSS] amon_sul     OK   8 findings  1h 3l 2i
      [    high] amon_sul/header          Missing HSTS header
  [OSS] annuminas    OK   4 findings  1m 2l 1i
      [  medium] annuminas/compliance     Trackers fire without visible cookie banner
  [OSS] ithil        OK   3 findings  1m 2i
      [  medium] ithil/dark_web           Domain appears in 4 public breach datasets
------------------------------------------------------------------------------
TOTAL: 15 findings   1 high  2 medium  5 low  7 info
==============================================================================
```

---

## What this edition does NOT do

We are honest about scope. The Free Edition is a **scanner**. It does not:

- Remove threats from endpoints (that's the Guard tier — paid)
- Correlate findings across multiple targets with LLM reasoning (Watch tier)
- Run continuously or send alerts (Watch tier)
- Provide a hosted dashboard (hosted at palantirisecurity.ai — paid)
- Maintain a tamper-evident audit log with hash-chain sealing (High Seat tier)
- Drive SOAR playbooks against CrowdSec / firewalls (High Seat tier)

For those, see the [paid tiers](https://palantirisecurity.ai/#pricing).

---

## Paid tier ladder (for context)

| Tier      | Adds on top of free                                                                                 |
|-----------|------------------------------------------------------------------------------------------------------|
| **Watch**      | Orthanc (LLM correlation via Claude), Anor (SOC rollup), Supabase persistence, continuous sweeps |
| **Guard**      | Everything in Watch, plus endpoint stack orchestrating ClamAV, YARA, osquery, Suricata, CrowdSec |
| **High Seat**  | Everything in Guard, plus Elostirion (hash-chained forensic audit) and Osgiliath (SOAR + remediation planner) |

---

## Contributing

We accept contributions that make the three OSS stones sharper:

- **New exposed-path patterns** — file a PR to `palantiri/agents/amon_sul.py::EXPOSED_PATHS` with a brief evidence note.
- **New tracker signatures** — add to `palantiri/agents/annuminas.py::TRACKER_SIGNATURES`.
- **New typosquat patterns, new breach-feed integrations** — Ithil welcomes them.
- **False-positive reports** — open an issue with URL + current output + what the real answer should be.

Out of scope for this repo: anything that requires an API key you don't control, anything in `palantiri/agents/` beyond the three OSS stones (those live in the private paid fork), anything that depends on paid SaaS.

See `CONTRIBUTING.md` for details.

---

## Trademark & legal

- **Palantiri**™ and the Seven Stones branding are trademarks of CRUCiBLE CAPiTAL SYSTEMS LLC.
- This repository is licensed under MIT. Forks and derivatives are welcome; please rename commercial derivatives to avoid consumer confusion with our paid product.
- This software is provided as-is, without warranty. **Only scan systems you own or have explicit permission to scan.** Scanning third parties without authorization may violate computer-abuse laws in your jurisdiction.
- Not affiliated with Palantir Technologies Inc.

---

## Why open-source the scanning core?

Two reasons:

1. **Scanners are commodity.** Nobody should pay for `curl + a header check`. We want Palantiri to be the name people trust for that baseline, for free. Our revenue comes from the hard part — correlation, endpoint response, compliance evidence, and running it 24/7 so you don't have to.
2. **OSS is the honest way to say "here's exactly what we do."** If you don't trust a scanner's claims, read the code.

If the Free Edition gives you value, consider trying a paid tier when you're ready for continuous monitoring or endpoint protection. Either way — thanks for using Palantiri.
