# Contributing to Palantiri Free Edition

Thanks for considering a contribution. Palantiri Free is intentionally small — three scanning stones, Python stdlib only, no external dependencies. That scope makes contributions easier to review and easier to trust.

## What we accept

- **New exposed-path patterns** for Amon Sûl. Include a brief "seen in the wild" note and, if relevant, what a false-positive would look like so we can gate against it.
- **New tracker / cookie-banner / PII-pattern signatures** for Annúminas.
- **New typosquat patterns, new public breach-feed integrations** for Ithil.
- **False-positive reports.** Include the URL (if public), the current output, and what the correct answer should be.
- **Correctness fixes.** If our logic is wrong, PRs welcome.
- **Tests.** We under-test. Any test contribution is appreciated.

## What's out of scope for this repo

- New *agents* beyond the three OSS stones. Orthanc, Anor, Elostirion, Osgiliath, and the Guard endpoint stack live in the paid fork. If you want those capabilities, see the paid tiers at [palantirisecurity.com](https://palantirisecurity.com).
- Anything requiring an API key or paid service that not every user will have.
- Anything that adds a non-stdlib dependency. We'll consider one ONLY if it's cryptographic or parser-related and the stdlib alternative is genuinely bad.

## Process

1. Open an issue first for anything non-trivial. A five-minute discussion saves an hour of rework.
2. Fork, branch, PR. Small PRs are easier to review.
3. Run `python3 scan.py https://example.com` and paste the before/after output in the PR description.
4. By submitting a PR you agree to license your contribution under the project MIT license.

## Security issues

If you think you've found a security issue in Palantiri itself (not in something Palantiri scanned), email **security@palantirisecurity.com** instead of opening a public issue. We try to respond within 72 hours. See `.well-known/security.txt`.

## Code style

- Stdlib only. No `pip install` to run the free tier.
- Type hints on public functions.
- Log with `logging`, not `print`, except in the CLI itself.
- Findings use the `Finding` class in `palantiri/base.py` — never return raw dicts.
- Severity levels: `critical` / `high` / `medium` / `low` / `info`. Err toward low.

## Not affiliated with Palantir Technologies Inc.

Please don't use "Palantir" in your fork's name. Use "Palantiri," the plural (which is the actual Tolkien word for multiple seeing-stones), or rename your fork entirely.
