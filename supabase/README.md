# Palantiri — scan-lite Edge Function

`functions/scan-lite/index.ts` is the Deno Edge Function that powers the
live scanner demo on [palantirisecurity.com](https://palantirisecurity.com).

It accepts a POST request with `{ "url": "https://example.com" }` and runs
a compressed Amon Sûl + Annúminas + Ithil scan server-side, returning
structured findings with severity, evidence, and remediation text.

## Deploy to your own Supabase project

```bash
# Install Supabase CLI
brew install supabase/tap/supabase

# Link to your project
supabase login
supabase link --project-ref YOUR_PROJECT_REF

# Deploy
supabase functions deploy scan-lite --no-verify-jwt
```

## Environment variables required

| Variable | Notes |
|---|---|
| `SUPABASE_URL` | Auto-provided by Supabase runtime |
| `SUPABASE_SERVICE_ROLE_KEY` | Auto-provided by Supabase runtime |

No other secrets are required for the free scan. The function stores
anonymous scan history (domain hash only — no PII) in a `scan_results`
table so it can return score deltas on repeat scans. The table schema is:

```sql
create table if not exists scan_results (
  id          uuid primary key default gen_random_uuid(),
  domain_hash text not null,
  score       int  not null,
  grade       text not null,
  findings    jsonb,
  scanned_at  timestamptz default now()
);
create index on scan_results (domain_hash, scanned_at desc);
```

## Usage (curl)

```bash
curl -X POST https://YOUR_PROJECT_REF.supabase.co/functions/v1/scan-lite \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```
