// Palantiri scan-lite — free-tier live scan endpoint.
//
// Runs a compressed Amon Sûl + Annúminas + Ithil scan and returns structured
// findings with severity, evidence snippets, and remediation guidance.
//
// Response shape:
//   {
//     host, grade, score,
//     groups: [{ category, title, severity, findings: [...] }],
//     history: { previous_scan_at, score_delta, new_findings, resolved_findings } | null,
//     scope_limits: [...],
//     compliance_disclaimer: "...",
//     duration_ms, upgrade_hint
//   }
//
// History is anonymous: we hash the domain (not the IP) and look up the
// most recent scan-lite record for that hash. No account required.
//
// Required env (Supabase auto-provides):
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

import { serve } from "https://deno.land/std@0.177.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const supa = createClient(SUPABASE_URL, SERVICE_ROLE);

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey",
};

type Severity = "critical" | "high" | "medium" | "low" | "info" | "pass";
type Stone = "amon_sul" | "annuminas" | "ithil" | "anor";
type FixTier = "free" | "watch" | "guard" | "fortress";

type Finding = {
  stone: Stone;
  category: string;      // "header" | "transport" | "compliance" | "exposure" | ...
  name: string;
  severity: Severity;
  pass: boolean;
  detail: string;
  evidence: Record<string, unknown>;
  remediation: string;   // copy-pasteable guidance. Empty string if pass.
  weight: number;
  auto_fix_tier?: FixTier;  // which paid tier auto-remediates this finding
};

type Group = {
  category: string;      // human-readable group heading
  stone: Stone;
  summary: string;       // one-line takeaway
  severity: Severity;    // worst severity in this group
  findings: Finding[];
};

const SCOPE_LIMITS = [
  "Palantiri Free scans what is visible from the public internet only.",
  "It does NOT: test login/authenticated pages, analyze source code or dependencies, check cloud provider config (AWS/GCP/Azure), monitor runtime for malware, or prove legal compliance.",
  "A passing score means your external posture looks clean — it does not mean your systems are secure end-to-end.",
  "Compliance findings are risk signals, NOT legal evidence. Consult counsel for actual GDPR/CCPA/HIPAA compliance determinations.",
];

const COMPLIANCE_DISCLAIMER =
  "Annúminas checks for the PRESENCE of privacy/terms pages and cookie banners. Presence does not prove compliance, and absence does not prove a violation. These are risk indicators for your legal team to review.";

const RESERVED_HOSTS = [
  /^localhost$/i, /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^0\.0\.0\.0$/, /^::1$/, /^169\.254\./,
];

function isPrivate(host: string): boolean {
  return RESERVED_HOSTS.some((r) => r.test(host));
}

async function fetchWithTimeout(url: string, opts: RequestInit = {}, ms = 10000): Promise<Response | null> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: controller.signal, redirect: "manual" });
  } catch (_e) {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function sha256(s: string): Promise<string> {
  const b = new TextEncoder().encode(s);
  const h = await crypto.subtle.digest("SHA-256", b);
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function sevRank(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1, pass: 0 }[s];
}

function worstSeverity(findings: Finding[]): Severity {
  let worst: Severity = "pass";
  for (const f of findings) {
    if (f.pass) continue;
    if (sevRank(f.severity) > sevRank(worst)) worst = f.severity;
  }
  return worst;
}

// ── Scan ───────────────────────────────────────────────────────────────
async function scan(rawUrl: string): Promise<{ findings: Finding[]; host: string }> {
  let url = rawUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  const u = new URL(url);
  const host = u.hostname;
  const findings: Finding[] = [];

  // 1. HTTPS in use?
  const isHttps = u.protocol === "https:";
  findings.push({
    stone: "amon_sul", category: "transport",
    name: "HTTPS / TLS in use",
    severity: isHttps ? "pass" : "high",
    pass: isHttps,
    detail: isHttps ? "Connected over HTTPS." : "Connected over plain HTTP — traffic unencrypted.",
    evidence: { protocol: u.protocol },
    remediation: isHttps ? "" :
      "Install a TLS certificate (Let's Encrypt is free and automated via Caddy, Certbot, or Cloudflare). " +
      "Then force-redirect HTTP to HTTPS at the origin or CDN.",
    weight: 20,
  });

  // 2. Homepage request
  const t0 = Date.now();
  const homepage = await fetchWithTimeout(url);
  if (!homepage) {
    findings.push({
      stone: "amon_sul", category: "reachability",
      name: "Site reachable",
      severity: "medium", pass: false,
      detail: "Could not reach the site within 10 seconds. Timeout or DNS failure.",
      evidence: { url, timeout_ms: 10000, elapsed_ms: Date.now() - t0 },
      remediation: "Check DNS resolution (`dig <host>`) and that your origin accepts HTTPS GET. " +
                   "WAF 403s on unknown user-agents are another common cause.",
      weight: 5,
    });
    return { findings, host };
  }
  const headers = new Headers(homepage.headers);

  // 3. Security headers (each one is its own finding with its own evidence + fix)
  const hdrChecks: Array<{
    key: string; name: string; severity: Severity; weight: number;
    detail_present: (v: string) => string; detail_missing: string;
    remediation: string;
  }> = [
    {
      key: "strict-transport-security",
      name: "HSTS (Strict-Transport-Security)",
      severity: "high", weight: 10,
      detail_present: (v) => `Header present: ${v}`,
      detail_missing: "Browsers will not pin HTTPS — one downgrade attempt can serve plain HTTP.",
      remediation: "Add to your response headers:\n  Strict-Transport-Security: max-age=31536000; includeSubDomains\n" +
        "Once stable, upgrade to `max-age=63072000; includeSubDomains; preload` and submit at hstspreload.org.",
    },
    {
      key: "content-security-policy",
      name: "Content Security Policy",
      severity: "medium", weight: 15,
      detail_present: (v) => `Policy set (${v.length} chars).`,
      detail_missing: "No CSP — any XSS vector has full scripting capability.",
      remediation: "Start in report-only mode to avoid breakage:\n  Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data: https:; script-src 'self'; report-uri /csp-report\n" +
        "Once reports are clean for a week, flip to enforcement.",
    },
    {
      key: "x-content-type-options",
      name: "X-Content-Type-Options",
      severity: "low", weight: 5,
      detail_present: (v) => `Set: ${v}`,
      detail_missing: "MIME-sniffing on user-uploaded content can be abused in older browsers.",
      remediation: "Add to response headers:\n  X-Content-Type-Options: nosniff",
    },
    {
      key: "x-frame-options",
      name: "X-Frame-Options / frame-ancestors",
      severity: "low", weight: 10,
      detail_present: (v) => `Set: ${v}`,
      detail_missing: "Clickjacking is possible via iframe embedding.",
      remediation: "Either header-based (`X-Frame-Options: DENY`) OR CSP (`frame-ancestors 'none'`). " +
        "CSP is preferred for new deployments.",
    },
    {
      key: "referrer-policy",
      name: "Referrer-Policy",
      severity: "low", weight: 5,
      detail_present: (v) => `Set: ${v}`,
      detail_missing: "Cross-origin Referer can leak query-string secrets to third-party sites.",
      remediation: "Add:\n  Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
      key: "permissions-policy",
      name: "Permissions-Policy",
      severity: "info", weight: 3,
      detail_present: (v) => `Set: ${v.slice(0, 100)}`,
      detail_missing: "Browsers will grant camera/mic/geolocation prompts freely to any embedded content.",
      remediation: "Add a baseline deny:\n  Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()",
    },
  ];

  for (const c of hdrChecks) {
    const v = headers.get(c.key);
    const pass = !!v && v.length > 0;
    findings.push({
      stone: "amon_sul", category: "header",
      name: c.name,
      severity: pass ? "pass" : c.severity,
      pass,
      detail: pass ? c.detail_present(v!) : `Missing. ${c.detail_missing}`,
      evidence: pass ? { header: c.key, value: v } : { header: c.key, value: null },
      remediation: pass ? "" : c.remediation,
      weight: c.weight,
    });
  }

  // 4. Banner / version leak
  for (const h of ["server", "x-powered-by", "x-aspnet-version"]) {
    const v = headers.get(h);
    if (v && /\d/.test(v)) {
      findings.push({
        stone: "amon_sul", category: "info_leak",
        name: `Version disclosure in ${h}`,
        severity: "low", pass: false,
        detail: `Exact version leaked to every visitor.`,
        evidence: { header: h, value: v },
        remediation: h === "server"
          ? "In nginx: `server_tokens off;` (http {} block). In Apache: `ServerTokens Prod` + `ServerSignature Off`."
          : `Remove or generalize the ${h} header at your origin.`,
        weight: 5,
      });
    }
  }

  // 5. HTTP → HTTPS redirect
  if (isHttps) {
    const httpUrl = `http://${host}/`;
    const httpResp = await fetchWithTimeout(httpUrl);
    const loc = httpResp?.headers.get("location") || "";
    const status = httpResp?.status;
    const redirected = httpResp && [301, 302, 307, 308].includes(httpResp.status) && loc.startsWith("https://");
    findings.push({
      stone: "amon_sul", category: "transport",
      name: "HTTP redirects to HTTPS",
      severity: redirected ? "pass" : (httpResp ? "medium" : "info"),
      pass: !!redirected,
      detail: redirected
        ? `HTTP returns ${status} → ${loc}.`
        : httpResp
          ? `HTTP returned ${status} with no HTTPS redirect.`
          : "HTTP endpoint unreachable (may be intentional).",
      evidence: { http_status: status, location: loc || null },
      remediation: redirected ? "" :
        "Configure a 301 permanent redirect from http:// to https:// at the origin or CDN. " +
        "In nginx: `return 301 https://$host$request_uri;`. At Cloudflare: Rules → Redirect Rules.",
      weight: 10,
    });
  }

  // 6a. Baseline probe — figure out how the host responds to a known-bogus
  // path. Static hosts like Vercel return 403 for *every* unknown .php (or
  // blanket deny extensions). Without this we'd flag "wp-config.php
  // present but access-denied" on sites that have never heard of PHP.
  const bogusProbe = await fetchWithTimeout(
    `${u.protocol}//${host}/__palantiri_canary_${Math.random().toString(36).slice(2, 10)}.php`,
    {},
    5000,
  );
  const blanketBlocks403 = bogusProbe && [401, 403].includes(bogusProbe.status);

  // 6. Exposed paths (real GETs, check body for leak markers)
  const EXPOSED = [
    { path: ".git/config", name: "Exposed .git repository",
      severity: "critical" as Severity, weight: 20,
      markers: ["[core]", "[remote", "repositoryformatversion"],
      remediation: "Block `/.git/` at the web server.\n  nginx: `location ~ /\\.git { deny all; return 404; }`\n  Apache: add to .htaccess: `RedirectMatch 404 /\\.git`" },
    { path: ".env", name: "Exposed .env file",
      severity: "critical" as Severity, weight: 20,
      markers: ["API_KEY", "SECRET", "DATABASE_URL", "PASSWORD"],
      remediation: "Block `/.env`. ROTATE every credential the file contained — assume they're compromised." },
    { path: "wp-config.php", name: "Exposed wp-config.php",
      severity: "critical" as Severity, weight: 20,
      markers: ["DB_NAME", "DB_PASSWORD", "AUTH_KEY"],
      remediation: "Move wp-config.php above the web root, OR deny direct access in .htaccess:\n  <Files wp-config.php>\n    Require all denied\n  </Files>" },
    { path: "phpinfo.php", name: "Public phpinfo()",
      severity: "high" as Severity, weight: 10,
      markers: ["PHP Version", "phpinfo()"],
      remediation: "Delete the file. It exposes loaded modules, env vars, and paths — fingerprinting gold." },
  ];

  for (const item of EXPOSED) {
    const eurl = `${u.protocol}//${host}/${item.path}`;
    const r = await fetchWithTimeout(eurl, {}, 6000);
    if (!r) continue;
    if (r.status === 200) {
      let body = "";
      try { body = (await r.text()).slice(0, 8192); } catch { /* noop */ }
      const hit = item.markers.filter((m) => body.includes(m));
      if (hit.length) {
        findings.push({
          stone: "amon_sul", category: "exposure",
          name: item.name,
          severity: item.severity, pass: false,
          detail: `Confirmed leak. Markers found in body: ${hit.join(", ")}.`,
          evidence: { url: eurl, status: 200, markers_found: hit, body_bytes: body.length },
          remediation: item.remediation,
          weight: item.weight,
        });
      }
      // 200 with empty body = handler ate it, don't flag
    } else if ([401, 403].includes(r.status) && !blanketBlocks403) {
      // Only flag a 403 if the host does NOT return 403 for arbitrary
      // nonsense paths. Vercel / Cloudflare Pages / many static hosts
      // return 403 blanket-style for unknown .php, producing noise.
      findings.push({
        stone: "amon_sul", category: "exposure",
        name: `${item.name} — present but access-denied`,
        severity: "low", pass: false,
        detail: `Returns ${r.status}. File likely exists but is blocked. Worth confirming it can't be reached via a backup copy or alternate host.`,
        evidence: { url: eurl, status: r.status },
        remediation: item.remediation,
        weight: 3,
      });
    }
  }

  // 7. security.txt (Annúminas)
  const secResp = await fetchWithTimeout(`${u.protocol}//${host}/.well-known/security.txt`);
  const secPresent = !!(secResp && secResp.status === 200);
  findings.push({
    stone: "annuminas", category: "policy",
    name: ".well-known/security.txt disclosure policy",
    severity: secPresent ? "pass" : "info",
    pass: secPresent,
    detail: secPresent
      ? "Responsible-disclosure contact published."
      : "No security.txt — researchers have no documented path to report vulnerabilities.",
    evidence: { url: `${u.protocol}//${host}/.well-known/security.txt`, status: secResp?.status ?? null },
    remediation: secPresent ? "" :
      "Create /.well-known/security.txt with:\n  Contact: mailto:security@yourdomain.com\n  Policy: https://yourdomain.com/security-policy\n  Preferred-Languages: en",
    weight: 3,
  });

  // 8. Privacy + Terms pages (Annúminas)
  const LEGAL = [
    { path: "/privacy", name: "Privacy Policy page",
      remediation: "Publish a privacy policy covering what data you collect, why, who you share it with, retention, user rights (access/delete/portability), and contact. Templates: termly.io, iubenda.com — but have counsel review." },
    { path: "/terms", name: "Terms of Service page",
      remediation: "Publish ToS covering acceptable use, user obligations, IP rights, limitation of liability, governing law, and termination. A lawyer's review here is cheaper than a dispute later." },
  ];
  for (const l of LEGAL) {
    const r = await fetchWithTimeout(`${u.protocol}//${host}${l.path}`);
    let found = !!(r && r.status === 200);
    let finalUrl: string | null = null;
    // Honor ONE redirect level — 301/302/307/308 to a live /privacy-policy
    // or /terms-of-service page is a valid way to serve these pages.
    if (!found && r && [301, 302, 307, 308].includes(r.status)) {
      const loc = r.headers.get("location");
      if (loc) {
        // Resolve relative location
        let target: string;
        try {
          target = new URL(loc, `${u.protocol}//${host}${l.path}`).toString();
        } catch { target = loc.startsWith("http") ? loc : `${u.protocol}//${host}${loc.startsWith("/") ? loc : "/" + loc}`; }
        const r2 = await fetchWithTimeout(target, {}, 6000);
        if (r2 && r2.status === 200) {
          found = true;
          finalUrl = target;
        }
      }
    }
    findings.push({
      stone: "annuminas", category: "compliance",
      name: l.name,
      severity: found ? "pass" : "medium",
      pass: found,
      detail: found
        ? (finalUrl
            ? `Reachable at ${l.path} (redirects to ${finalUrl}).`
            : `Reachable at ${l.path}.`)
        : `Not found at ${l.path}. This is a risk indicator, not proof of a violation.`,
      evidence: { url: `${u.protocol}//${host}${l.path}`, status: r?.status ?? null, resolved_url: finalUrl },
      remediation: found ? "" : l.remediation,
      weight: 5,
    });
  }

  // 9. Trackers without consent banner (Annúminas) — naive homepage scan
  try {
    const body = (await (await fetchWithTimeout(url))?.text() ?? "").slice(0, 250_000).toLowerCase();
    const trackers: Array<[string, string]> = [
      ["google-analytics", "Google Analytics"],
      ["googletagmanager", "Google Tag Manager"],
      ["facebook.com/tr", "Meta Pixel"],
      ["fbevents.js", "Meta Pixel"],
      ["hotjar", "Hotjar"],
      ["mixpanel", "Mixpanel"],
      ["segment.io", "Segment"],
      ["linkedin.com/insight", "LinkedIn Insight"],
      ["tiktok pixel", "TikTok Pixel"],
      ["analytics.tiktok", "TikTok Analytics"],
    ];
    const found = trackers.filter(([needle]) => body.includes(needle));
    const bannerish = /cookie|consent|gdpr|ccpa/.test(body) && /(accept|agree|allow|dismiss)/.test(body);
    if (found.length && !bannerish) {
      findings.push({
        stone: "annuminas", category: "compliance",
        name: "Third-party trackers loaded with no visible consent banner",
        severity: "medium", pass: false,
        detail: `Detected: ${found.map((f) => f[1]).join(", ")}. This is a GDPR/CCPA risk signal — not a legal finding.`,
        evidence: { trackers: found.map((f) => f[1]) },
        remediation: "Either (a) add a cookie consent banner that blocks non-essential trackers until the user opts in " +
          "(OneTrust, Cookiebot, iubenda, or the open-source Klaro), OR (b) drop the trackers entirely and use server-side analytics (Plausible, Fathom).",
        weight: 10,
      });
    } else {
      findings.push({
        stone: "annuminas", category: "compliance",
        name: "Trackers + consent check",
        severity: "pass", pass: true,
        detail: found.length
          ? `Trackers detected (${found.map((f) => f[1]).join(", ")}) and a consent-banner-like pattern is present.`
          : "No obvious third-party trackers detected on the homepage.",
        evidence: { trackers: found.map((f) => f[1]), banner_pattern_found: bannerish },
        remediation: "",
        weight: 5,
      });
    }
  } catch { /* body fetch may fail on SSR; skip */ }

  // 10. Ithil — crt.sh subdomain surface
  try {
    const parts = host.split(".");
    const root = parts.slice(-2).join(".");
    const ct = await fetchWithTimeout(
      `https://crt.sh/?q=${encodeURIComponent("%." + root)}&output=json`,
      {}, 8000);
    if (ct && ct.status === 200) {
      const data = await ct.json() as Array<{ name_value?: string }>;
      const names = new Set<string>();
      for (const row of data.slice(0, 400)) {
        for (const n of (row.name_value || "").split("\n")) {
          const clean = n.trim().toLowerCase();
          if (clean && !clean.includes("*") && clean.endsWith(root)) names.add(clean);
        }
      }
      const risky = [...names].filter((n) =>
        /(^|\.)(dev|staging|test|admin|internal|beta|qa|uat|vpn|mail|old|legacy)(\.|-)/.test(n)
      );
      findings.push({
        stone: "ithil", category: "exposure",
        name: "Risky subdomains in public CT logs",
        severity: risky.length === 0 ? "pass" : "medium",
        pass: risky.length === 0,
        detail: risky.length === 0
          ? `${names.size} subdomains observed in certificate transparency; none match dev/staging/admin patterns.`
          : `Dev/staging/admin-like subdomains are publicly visible: ${risky.slice(0, 5).join(", ")}${risky.length > 5 ? ", …" : ""}`,
        evidence: { total_subdomains: names.size, risky: risky.slice(0, 20) },
        remediation: risky.length === 0 ? "" :
          "Put non-prod subdomains behind SSO, VPN, or IP-allowlists. If they must be public, bring their security headers and auth posture to parity with prod — attackers pivot through the weakest one.",
        weight: 10,
      });
    }
  } catch { /* crt.sh 5xx is common; skip */ }

  // 11. Email authentication DNS — SPF (Anor: DNS/live-posture)
  try {
    const root = host.split(".").slice(-2).join(".");
    const txtRecords = await Deno.resolveDns(root, "TXT").catch(() => [] as string[][]);
    const flatTxt = txtRecords.map((r) => r.join("")).filter(Boolean);
    const spf = flatTxt.find((r) => /^v=spf1\b/i.test(r));
    if (spf) {
      const allMode = /[\-\+\?\~]all\b/i.exec(spf);
      const hard = allMode && allMode[0].startsWith("-");
      findings.push({
        stone: "anor", category: "email_auth",
        name: "SPF record published",
        severity: hard ? "pass" : (allMode ? "low" : "medium"),
        pass: !!hard,
        detail: hard
          ? `SPF published with hard-fail: ${spf.slice(0, 120)}`
          : allMode
            ? `SPF published but uses ${allMode[0]} (softer than -all). Spoofed mail may still deliver.`
            : `SPF published but missing an 'all' directive — policy is ambiguous.`,
        evidence: { record: spf },
        remediation: hard ? "" :
          "Update your TXT record to end with `-all` once you're confident every legitimate sender is listed. Example: `v=spf1 include:_spf.google.com -all`",
        weight: 10,
        auto_fix_tier: "watch",
      });
    } else {
      findings.push({
        stone: "anor", category: "email_auth",
        name: "SPF record published",
        severity: "medium", pass: false,
        detail: "No SPF record found. Anyone can send email claiming to be from your domain.",
        evidence: { host: root, records_checked: flatTxt.length },
        remediation:
          "Publish a TXT record at your apex domain:\n" +
          "  v=spf1 include:_spf.google.com include:amazonses.com -all\n" +
          "(Include directives for every service that sends mail on your behalf, then close with -all.)",
        weight: 10,
        auto_fix_tier: "watch",
      });
    }
  } catch { /* DNS resolution blocked by sandbox in some cases */ }

  // 12. DMARC policy (Anor)
  try {
    const root = host.split(".").slice(-2).join(".");
    const dmarcTxt = await Deno.resolveDns(`_dmarc.${root}`, "TXT").catch(() => [] as string[][]);
    const dmarcRec = dmarcTxt.map((r) => r.join("")).find((r) => /^v=DMARC1\b/i.test(r));
    if (dmarcRec) {
      const policy = /\bp=(\w+)/i.exec(dmarcRec)?.[1]?.toLowerCase() || "";
      const strong = policy === "reject" || policy === "quarantine";
      findings.push({
        stone: "anor", category: "email_auth",
        name: "DMARC policy published",
        severity: strong ? "pass" : "medium",
        pass: strong,
        detail: strong
          ? `DMARC p=${policy} — real enforcement.`
          : `DMARC exists but p=${policy || "none"} — observations only, no enforcement.`,
        evidence: { record: dmarcRec },
        remediation: strong ? "" :
          "Upgrade the policy once your reports are clean: first p=none (monitor), then p=quarantine (soft-fail to spam), then p=reject (drop entirely). Include rua= for aggregate reports (DMARC Analyzer, Postmark, and Dmarcian all have free tiers).",
        weight: 10,
        auto_fix_tier: "watch",
      });
    } else {
      findings.push({
        stone: "anor", category: "email_auth",
        name: "DMARC policy published",
        severity: "medium", pass: false,
        detail: "No DMARC record at _dmarc subdomain. Phishing campaigns spoofing your brand won't be reported or blocked.",
        evidence: { host: `_dmarc.${root}` },
        remediation:
          "Start in monitor mode (safe, no delivery impact):\n" +
          "  _dmarc.yourdomain.com  TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1\"\n" +
          "After 2 weeks of clean reports, upgrade to p=quarantine, then p=reject.",
        weight: 10,
        auto_fix_tier: "watch",
      });
    }
  } catch { /* noop */ }

  // 13. CAA record — pins which CAs may issue certs for this domain (Anor)
  try {
    const root = host.split(".").slice(-2).join(".");
    const caaRecs = await Deno.resolveDns(root, "CAA").catch(() => [] as Array<{ flags: number; tag: string; value: string }>);
    if (caaRecs && caaRecs.length) {
      findings.push({
        stone: "anor", category: "email_auth",
        name: "CAA record pins cert authorities",
        severity: "pass", pass: true,
        detail: `${caaRecs.length} CAA record(s) published.`,
        evidence: { records: caaRecs.map((r) => `${r.tag} "${r.value}"`) },
        remediation: "",
        weight: 5,
      });
    } else {
      findings.push({
        stone: "anor", category: "email_auth",
        name: "CAA record pins cert authorities",
        severity: "low", pass: false,
        detail: "No CAA record — any certificate authority on earth can issue a TLS cert for your domain. A compromised CA could MITM your users.",
        evidence: { host: root },
        remediation:
          "Publish CAA records naming only the CAs you actually use:\n" +
          "  yourdomain.com  CAA  0 issue \"letsencrypt.org\"\n" +
          "  yourdomain.com  CAA  0 issuewild \"letsencrypt.org\"\n" +
          "  yourdomain.com  CAA  0 iodef \"mailto:security@yourdomain.com\"",
        weight: 5,
        auto_fix_tier: "watch",
      });
    }
  } catch { /* noop */ }

  // 14. CSP quality analysis (Amon Sûl) — existing check only validates presence
  const cspValue = headers.get("content-security-policy") || "";
  if (cspValue) {
    const issues: string[] = [];
    // Check unsafe-inline only in script-src — style-src unsafe-inline is low-risk (CSS can't execute JS)
    const scriptSrcMatch = /script-src\s+([^;]+)/i.exec(cspValue);
    const scriptSrcValue = scriptSrcMatch ? scriptSrcMatch[1] : "";
    if (/'unsafe-inline'/i.test(scriptSrcValue)) issues.push("allows 'unsafe-inline' in script-src (XSS via inline injection is executable)");
    if (/'unsafe-eval'/i.test(scriptSrcValue || cspValue)) issues.push("allows 'unsafe-eval' (eval(), new Function(), setTimeout(string) all run)");
    if (/\bscript-src[^;]*\*(\s|;|$)/i.test(cspValue)) issues.push("wildcard in script-src (any origin can load scripts)");
    if (!/\bframe-ancestors\b/i.test(cspValue)) issues.push("missing frame-ancestors directive (clickjacking via iframes)");
    if (!/\bbase-uri\b/i.test(cspValue)) issues.push("missing base-uri directive (base-tag hijacking is possible)");
    if (!/\bobject-src\b/i.test(cspValue)) issues.push("missing object-src 'none' (plugin-based XSS still possible)");
    findings.push({
      stone: "amon_sul", category: "header",
      name: "CSP quality (beyond presence)",
      severity: issues.length === 0 ? "pass" : issues.length >= 3 ? "medium" : "low",
      pass: issues.length === 0,
      detail: issues.length === 0
        ? "CSP uses nonce/hash-based script allowlisting with no unsafe directives."
        : `CSP has ${issues.length} weakness${issues.length === 1 ? "" : "es"}: ${issues.join("; ")}.`,
      evidence: { csp_length: cspValue.length, issues },
      remediation: issues.length === 0 ? "" :
        "Tighten your CSP in report-only mode first so you can see what breaks:\n" +
        "  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; report-uri /csp-report\n" +
        "Generate a fresh per-request nonce server-side and inject it into your <script> tags. When reports are clean for a week, flip to enforcement mode.",
      weight: 10,
      auto_fix_tier: "guard",
    });
  }

  // 15. Cookie security flags on any Set-Cookie headers (Amon Sûl)
  const cookieHeaders: string[] = [];
  // Headers API: for multi-value Set-Cookie, Deno exposes them via getSetCookie()
  const getSC = (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSC === "function") {
    for (const c of getSC.call(headers)) cookieHeaders.push(c);
  } else {
    const single = headers.get("set-cookie");
    if (single) cookieHeaders.push(single);
  }
  if (cookieHeaders.length) {
    const insecure: Array<{ name: string; missing: string[] }> = [];
    for (const c of cookieHeaders) {
      const name = (c.split("=")[0] || "").trim();
      const missing: string[] = [];
      if (!/;\s*HttpOnly\b/i.test(c)) missing.push("HttpOnly");
      if (!/;\s*Secure\b/i.test(c)) missing.push("Secure");
      if (!/;\s*SameSite=/i.test(c)) missing.push("SameSite");
      if (missing.length) insecure.push({ name, missing });
    }
    findings.push({
      stone: "amon_sul", category: "header",
      name: "Cookie security flags",
      severity: insecure.length === 0 ? "pass" : "medium",
      pass: insecure.length === 0,
      detail: insecure.length === 0
        ? `${cookieHeaders.length} cookie(s) all carry HttpOnly + Secure + SameSite.`
        : `${insecure.length} cookie(s) missing flags: ${insecure.map((c) => `${c.name} (${c.missing.join("+")})`).join(", ")}`,
      evidence: { total_cookies: cookieHeaders.length, insecure: insecure.slice(0, 10) },
      remediation: insecure.length === 0 ? "" :
        "Every cookie that carries auth state should be set with all three flags:\n" +
        "  Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax; Path=/\n" +
        "HttpOnly blocks document.cookie access (stops XSS from stealing sessions). Secure forces TLS. SameSite=Lax blocks cross-site CSRF on state-changing requests.",
      weight: 10,
      auto_fix_tier: "watch",
    });
  }

  // 16. Mixed content — http:// asset references in an HTTPS page (Amon Sûl)
  if (isHttps) {
    try {
      const hBody = (await (await fetchWithTimeout(url))?.text() ?? "").slice(0, 300_000);
      // Match src=, href=, action= pointing to explicit http://
      const mixed = hBody.match(/(?:src|href|action)\s*=\s*["']http:\/\/[^"']+["']/gi) || [];
      const filtered = mixed.filter((m) => !/http:\/\/(www\.)?(w3\.org|schema\.org|purl\.org|xmlns\.com)/i.test(m));
      findings.push({
        stone: "amon_sul", category: "header",
        name: "Mixed content (HTTP assets on HTTPS page)",
        severity: filtered.length === 0 ? "pass" : "medium",
        pass: filtered.length === 0,
        detail: filtered.length === 0
          ? "No http:// asset references detected in homepage source."
          : `${filtered.length} http:// reference(s) on an HTTPS page — modern browsers block these and log a mixed-content warning.`,
        evidence: { samples: filtered.slice(0, 5) },
        remediation: filtered.length === 0 ? "" :
          "Replace every `http://` asset URL with `https://` (or protocol-relative `//`). Modern sites serve every third-party library over HTTPS; if a vendor doesn't, host it yourself.",
        weight: 5,
        auto_fix_tier: "watch",
      });
    } catch { /* noop */ }
  }

  // 17. Subresource Integrity on external scripts (Amon Sûl)
  if (isHttps) {
    try {
      const hBody = (await (await fetchWithTimeout(url))?.text() ?? "").slice(0, 300_000);
      // Find <script src="https://..."> tags on other origins
      const tags = hBody.match(/<script\b[^>]*\bsrc\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi) || [];
      const external = tags.filter((t) => {
        const m = /src\s*=\s*["'](https?:\/\/[^"']+)/i.exec(t);
        if (!m) return false;
        try { return new URL(m[1]).host !== host; } catch { return false; }
      });
      const noIntegrity = external.filter((t) => !/\bintegrity\s*=/i.test(t));
      if (external.length) {
        findings.push({
          stone: "amon_sul", category: "header",
          name: "Subresource Integrity on external scripts",
          severity: noIntegrity.length === 0 ? "pass" : "low",
          pass: noIntegrity.length === 0,
          detail: noIntegrity.length === 0
            ? `All ${external.length} external script(s) use integrity hashes.`
            : `${noIntegrity.length} of ${external.length} external script(s) have no integrity hash — a compromise of those CDNs would execute arbitrary code on your site.`,
          evidence: { external_total: external.length, missing_integrity: noIntegrity.length, samples: noIntegrity.slice(0, 3).map((t) => (/src\s*=\s*["']([^"']+)/i.exec(t) || [])[1]) },
          remediation: noIntegrity.length === 0 ? "" :
            "Compute and add integrity hashes. SRI generator: https://www.srihash.org — produces a one-line attribute to paste:\n" +
            "  <script src=\"https://cdn.example/lib.js\" integrity=\"sha384-…\" crossorigin=\"anonymous\"></script>\n" +
            "The browser refuses to execute a file that doesn't match the hash.",
          weight: 5,
          auto_fix_tier: "guard",
        });
      }
    } catch { /* noop */ }
  }

  // 18. www vs apex consistency — scan both, flag if posture diverges (Amon Sûl)
  if (isHttps && !/^www\./i.test(host)) {
    try {
      const wwwResp = await fetchWithTimeout(`https://www.${host}/`, {}, 6000);
      if (wwwResp) {
        const wwwHeaders = new Headers(wwwResp.headers);
        const diverged = [
          ["strict-transport-security", "HSTS"],
          ["content-security-policy", "CSP"],
          ["x-frame-options", "X-Frame-Options"],
        ].filter(([k]) => !!headers.get(k) !== !!wwwHeaders.get(k));
        if (diverged.length) {
          findings.push({
            stone: "amon_sul", category: "transport",
            name: "www vs apex have different security posture",
            severity: "low", pass: false,
            detail: `Your apex and www subdomain serve different headers. Attackers pivot through the weaker one: ${diverged.map((d) => d[1]).join(", ")}.`,
            evidence: { apex_host: host, www_host: `www.${host}`, diverged: diverged.map((d) => d[1]) },
            remediation: "Add a 301 redirect from one to the other at the edge, so both hostnames go through the same origin. In Vercel: add both domains, set one as redirect target. In nginx: single server block with server_name apex + www, redirect one.",
            weight: 5,
            auto_fix_tier: "watch",
          });
        }
      }
    } catch { /* noop */ }
  }

  return { findings, host };
}

// ── Grouping ───────────────────────────────────────────────────────────
function groupFindings(findings: Finding[]): Group[] {
  const groups: Record<string, { stone: Stone; findings: Finding[] }> = {};
  const categoryTitles: Record<string, string> = {
    transport:    "Transport security (HTTPS/TLS)",
    header:       "Security headers",
    info_leak:    "Version / fingerprint leaks",
    exposure:     "Exposed paths & files",
    reachability: "Site reachability",
    policy:       "Disclosure policy",
    compliance:   "Governance & compliance (Annúminas)",
    email_auth:   "Email authentication & DNS (Anor)",
  };

  for (const f of findings) {
    const g = groups[f.category] ||= { stone: f.stone, findings: [] };
    g.findings.push(f);
  }

  return Object.entries(groups).map(([cat, g]) => {
    const worst = worstSeverity(g.findings);
    const failures = g.findings.filter((x) => !x.pass).length;
    return {
      category: categoryTitles[cat] || cat,
      stone: g.stone,
      severity: worst,
      summary: failures === 0
        ? `${g.findings.length}/${g.findings.length} checks passed.`
        : `${failures} of ${g.findings.length} checks failed (worst: ${worst}).`,
      findings: g.findings.sort((a, b) => sevRank(b.severity) - sevRank(a.severity)),
    };
  }).sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

// ── History (anonymous, by domain hash) ────────────────────────────────
async function lookupHistory(host: string, currentFingerprints: string[], currentScore: number): Promise<{
  previous_scan_at: string | null;
  previous_score: number | null;
  score_delta: number | null;
  new_findings: number;
  resolved_findings: number;
} | null> {
  const hash = await sha256("palantiri:host:" + host.toLowerCase());
  try {
    const { data } = await supa
      .from("palantiri_scans")
      .select("started_at, summary")
      .eq("agent", "scan_lite_edge")
      .filter("summary->>host_hash", "eq", hash)
      .order("started_at", { ascending: false })
      .limit(1);
    if (!data?.length) return null;
    const prev = data[0];
    const prevScore = (prev.summary as any)?.score_pct ?? null;
    const prevFps: string[] = (prev.summary as any)?.failure_fingerprints ?? [];
    const nowSet = new Set(currentFingerprints);
    const prevSet = new Set(prevFps);
    return {
      previous_scan_at: prev.started_at,
      previous_score: prevScore,
      score_delta: prevScore != null ? currentScore - prevScore : null,
      new_findings: [...nowSet].filter((x) => !prevSet.has(x)).length,
      resolved_findings: [...prevSet].filter((x) => !nowSet.has(x)).length,
    };
  } catch {
    return null;
  }
}

// ── HTTP handler ───────────────────────────────────────────────────────
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "POST only" }), { status: 405, headers: CORS });
  }

  let body: { url?: string };
  try { body = await req.json(); } catch { body = {}; }
  const rawUrl = (body.url || "").trim();
  if (!rawUrl) return new Response(JSON.stringify({ error: "url required" }), { status: 400, headers: CORS });

  let u: URL;
  try { u = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : "https://" + rawUrl); }
  catch { return new Response(JSON.stringify({ error: "invalid url" }), { status: 400, headers: CORS }); }

  if (isPrivate(u.hostname)) {
    return new Response(JSON.stringify({ error: "refusing to scan private/loopback address" }),
      { status: 400, headers: CORS });
  }

  const t0 = Date.now();
  const { findings, host } = await scan(u.toString());
  const durationMs = Date.now() - t0;

  // Score: higher weights count more; a critical failure pulls the score down harder
  const totalWeight = findings.reduce((s, f) => s + f.weight, 0) || 1;
  const scored = findings.reduce((s, f) => s + (f.pass ? f.weight : 0), 0);
  const pct = Math.round((scored / totalWeight) * 100);
  const grade = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 55 ? "C" : pct >= 35 ? "D" : "F";

  const groups = groupFindings(findings);
  const failureFps = findings
    .filter((f) => !f.pass)
    .map((f) => `${f.stone}|${f.category}|${f.name}`);

  // History lookup (anonymous)
  const history = await lookupHistory(host, failureFps, pct);

  // Log this scan (non-blocking)
  try {
    const hostHash = await sha256("palantiri:host:" + host.toLowerCase());
    await supa.from("palantiri_scans").insert({
      target_id: null,
      agent: "scan_lite_edge",
      status: "completed",
      started_at: new Date(t0).toISOString(),
      finished_at: new Date().toISOString(),
      duration_ms: durationMs,
      summary: {
        host_hash: hostHash,
        findings: findings.length,
        failures: failureFps.length,
        score_pct: pct,
        grade,
        failure_fingerprints: failureFps,
      },
    });
  } catch { /* non-fatal */ }

  const hasCompliance = findings.some((f) => f.stone === "annuminas");
  return new Response(JSON.stringify({
    host, grade, score: pct,
    groups,
    findings,              // flat list, for backwards-compat
    history,
    scope_limits: SCOPE_LIMITS,
    compliance_disclaimer: hasCompliance ? COMPLIANCE_DISCLAIMER : null,
    duration_ms: durationMs,
    upgrade_hint: pct < 75
      ? "Your score is below a B. The paid Watch tier runs this scan continuously, correlates findings across time, and alerts you to new issues via Slack/email."
      : "Consider the paid Watch tier for continuous monitoring and change diffing.",
  }), { status: 200, headers: { ...CORS, "content-type": "application/json" } });
});
