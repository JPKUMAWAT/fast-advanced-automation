# Bug Hunting Guide — Step by Step

This file walks through every phase of `recon.sh`, in order: which tool runs, what the output looks like, and exactly what to look for to find a real bug. Use it alongside a run's output folder.

> Every hit in this guide is a **lead**, not a confirmed bug. Always manually reproduce before reporting — automated tools (especially nuclei and CORS scanners) produce false positives.

---

## Step 1 — Subdomain enumeration
**Tools:** `subfinder`, `assetfinder`, `findomain`, `sublist3r`, `subdominator`
**Output:** `raw/*.txt` → merged into `final/all_subs.txt`

**What it does:** finds every subdomain of the target that's publicly known (certificate transparency logs, passive DNS, search engines).

**What to look for:**
- Unusual or forgotten-looking names: `old-`, `staging-`, `dev-`, `test-`, `internal-`, `uat-`, `backup-`, `vpn-`, `legacy-`. These are far more likely to be unpatched or misconfigured than the main production site.
- Subdomains that don't match the company's normal naming — can indicate a forgotten acquisition or shadow IT asset.

**No bug here yet** — this step just builds your target list for every step after it.

---

## Step 2 — Scope filtering
**Tool:** `grep -f` against your scope file
**Output:** `final/in_scope.txt`

**What to look for:** nothing — this is a safety step. Double-check the result actually matches what the program's policy page says is in scope before continuing. When in doubt, re-read the program's scope page manually; don't trust the filter blindly.

---

## Step 3 — Wildcard DNS check
**Tool:** `dnsx` (random-subdomain probe)
**Output:** `final/wildcard_ips.txt` (only created if wildcard found)

**What it means if found:** the domain resolves *any* random subdomain to the same IP(s). Every later "subdomain is live" result could be a false positive from the wildcard catching it, not a real host.

**What to do:** if `wildcard_ips.txt` has entries, treat `final/resolved.txt` with suspicion — manually spot-check a few resolved hosts to confirm they're real, not wildcard noise.

---

## Step 4 — DNS resolution
**Tool:** `dnsx`
**Output:** `final/resolved.txt`

**What it does:** confirms which subdomains actually resolve to an IP (i.e. are "alive" in DNS, even if nothing is listening on a web port).

**What to look for:**
- A resolved subdomain with **no live HTTP(S) service** in step 6 but DNS still resolves → check Step 9 (takeover). A dangling DNS record pointing at a deprovisioned cloud resource is the classic takeover setup.

---

## Step 5 — Port scanning *(optional, `--portscan`)*
**Tool:** `naabu`
**Output:** `ports/open_ports.txt`

**What to look for:**
- Ports besides 80/443: 8080, 8443, 3000, 5000, 9200 (Elasticsearch), 27017 (MongoDB), 6379 (Redis), 3306 (MySQL), 5432 (Postgres), 22 (SSH on an unexpected host).
- A database or admin port open to the internet with no auth is a critical, easy-to-report finding — but only if the program's scope allows this kind of testing. Never attempt to log in or extract data; reporting "port X is open with banner Y" is usually enough.

---

## Step 6 — HTTP(S) probing
**Tool:** `httpx` / `httpx-toolkit`
**Output:** `http/live_hosts.txt` (status code, title, tech stack), `http/live_urls.txt`

**What to look for:**
- `[401]` / `[403]` status on something that sounds internal (`admin.`, `internal.`, `staging.`) — worth checking if the auth can be bypassed.
- Page titles containing "login", "dashboard", "Jenkins", "Grafana", "Kibana", "phpMyAdmin" — default or exposed admin panels.
- `-tech-detect` output showing an old framework/CMS version — cross-reference with known CVEs for that version in Step 11.
- A `[200]` on a host you didn't expect to be public (e.g. something that should be internal-only).

---

## Step 7 — Subdomain takeover check *(optional, `--takeover`)*
**Tools:** `subzy`, `nuclei -tags takeover`
**Output:** `vulns/takeover_subzy.txt`, `vulns/takeover_nuclei.txt`

**What it means:** a subdomain's CNAME points to a cloud service (Heroku, AWS S3, GitHub Pages, Shopify, Azure, Fastly, etc.) that is no longer provisioned — meaning *anyone* can claim that service name and serve content from the victim's subdomain.

**How to verify before reporting:**
1. Confirm the CNAME with `dig CNAME <subdomain>`.
2. Visit the subdomain — look for the service's signature "not found / not configured" error page (e.g. `NoSuchBucket` for S3, `There isn't a GitHub Pages site here` for GitHub Pages).
3. Only register/claim the resource if the program's rules explicitly allow it — many programs want you to report without claiming.

**Why it matters:** high severity, easy to prove, commonly pays well — a top category for beginners.

---

## Step 8 — WAF/CDN detection *(optional, `--wafcheck`)*
**Tool:** `wafw00f`
**Output:** `waf/waf_results.txt`

**What to look for:** not a bug by itself — use it to decide scanning intensity. If a WAF is detected, slow down (`-r` / `-rl` flags) to avoid tripping rate limits or getting the testing IP blocked.

---

## Step 9 — Favicon fingerprinting *(optional, `--favicon`)*
**Tool:** `favfreak`
**Output:** `favicon/`

**What to look for:** a favicon hash matching a known default (Jenkins, GitLab, Grafana, Zabbix, etc.) tells you what software is running **without even loading the page** — useful for quickly triaging hundreds of hosts for a specific known-vulnerable product.

---

## Step 10 — Crawling + historical URLs *(optional, `--crawl`)*
**Tools:** `katana` (live crawl), `gau`, `waybackurls` (historical/archived URLs)
**Output:** `urls/all_urls.txt`

**What to look for:**
- URL parameters that look like file paths, IDs, or redirects: `?file=`, `?redirect=`, `?url=`, `?id=`, `?path=`, `?next=` — candidates for LFI, open redirect, or IDOR.
- `.git/`, `.env`, `.bak`, `.sql`, `.zip`, `config.json`, `swagger.json`, `/api/v1/`, `/debug/`, `/.well-known/` — exposed config or debug endpoints.
- Old API versions (`/api/v1/` when the current is `/api/v3/`) — older versions often lack newer security fixes.
- Endpoints that only appear in historical data (gau/waybackurls) but not in the live crawl — these are "forgotten" and worth checking if they still respond.

---

## Step 11 — Directory brute-forcing *(optional, `--ffuf <wordlist>`)*
**Tool:** `ffuf`
**Output:** `urls/ffuf/*.json`

**What to look for:**
- `200`/`204` on paths not linked anywhere on the site — hidden functionality.
- `301`/`302` redirects to internal-looking hosts.
- `401`/`403` on `/admin`, `/api/internal`, `/backup` — confirms something exists even if you can't access it yet (useful alongside other findings).

---

## Step 12 — JS collection + secrets scan *(optional, `--jsscan`)*
**Tools:** `subjs` (collect JS files), `trufflehog` / `gitleaks` (scan for secrets)
**Output:** `js/js_files.txt`, `js/secrets_trufflehog.json` or `js/secrets_gitleaks.json`

**What to look for:**
- API keys (AWS `AKIA...`, Google `AIza...`, Stripe `sk_live_...`, Slack `xox...`), JWT tokens, internal hostnames, hardcoded passwords, database connection strings.
- Even without a scanner hit, manually grep JS files for `apiKey`, `secret`, `token`, `password`, `Authorization`, internal domain names (`*.internal.`, `*.corp.`).
- **Verify before reporting**: check whether the key is actually live/valid (does it authenticate?) and what it grants access to — an expired or already-rotated key is a much lower-severity finding.

---

## Step 13 — Cloud storage enumeration *(optional, `--cloudscan`)*
**Tools:** `S3Scanner` or `cloud_enum`
**Output:** `cloud/*.txt`

**What to look for:**
- A bucket named after the company/product that returns a directory listing (public read) or accepts uploads (public write).
- Sensitive files inside: backups, customer data exports, internal documents, source code.
- **Only list/view what's needed to confirm exposure** — don't exfiltrate large amounts of data; screenshot the listing as your PoC.

---

## Step 14 — GitHub leak scanning *(optional, `--githubscan`)*
**Tools:** `github-subdomains`, `trufflehog github`
**Output:** `github/github_secrets.json`, extra subdomains in `raw/github_subs.txt`

**What to look for:**
- Secrets committed to public repos belonging to the company or its employees — API keys, `.env` files, internal config, infrastructure-as-code with embedded credentials.
- Old commits that deleted a secret but left it in git history (tools like trufflehog scan full history, not just the latest commit).

---

## Step 15 — CORS misconfiguration *(optional, `--corsscan`)*
**Tool:** `Corsy`
**Output:** `cors/cors_results.json`

**What to look for:**
- Response header `Access-Control-Allow-Origin` reflecting an arbitrary attacker-supplied origin **combined with** `Access-Control-Allow-Credentials: true`. This combination lets an attacker's page read authenticated API responses on behalf of a logged-in victim.
- Null-origin acceptance (`Access-Control-Allow-Origin: null`) on an authenticated endpoint.

**How to verify:** send a request with `Origin: https://evil-attacker.com` and check if it's reflected back with credentials allowed — build a minimal PoC HTML page that fetches a sensitive endpoint cross-origin and shows you can read the response.

---

## Step 16 — New-subdomain diff
**Tool:** built into `recon.sh` (`comm` against the previous run)
**Output:** `final/new_subs.txt`

**What to look for:** anything that's brand new since your last scan deserves a fresh pass through Steps 6–15 — newly stood-up infrastructure often ships before hardening (WAF rules, auth, rate limiting) is fully in place.

---

## Step 17 — Screenshots *(optional, `--screenshots`)*
**Tool:** `gowitness`
**Output:** `http/screenshots/`

**What to look for:** this step doesn't find bugs directly — it's a fast visual triage. Scroll through screenshots looking for: login pages, error pages revealing stack traces or framework names, "under construction" pages (often less hardened), and anything that looks like an internal tool exposed externally.

---

## Step 18 — Nuclei vulnerability scan
**Tool:** `nuclei`
**Output:** `vulns/nuclei_results.txt` / `.json`

**What to look for:**
- `[critical]` and `[high]` severity tags first.
- Template IDs mentioning `exposure`, `takeover`, `default-login`, `cve-`, `misconfig` are usually the most actionable.
- **Always manually reproduce** the exact request nuclei made (the JSON output includes the matched request/response) before reporting — nuclei templates can false-positive on pages that merely *look* vulnerable.

---

## Final step — Prioritize and report

For every candidate from Steps 7–18, before writing a report ask:

1. **Can I prove it?** Do you have a concrete request/response, screenshot, or working PoC?
2. **What's the real impact?** "I found an exposed `.git` folder" is weaker than "I found an exposed `.git` folder containing the production database password, which I verified grants read access to the following tables (redacted)."
3. **Is it in scope?** Re-check the program's current scope page — not just your scope file — right before submitting.
4. **Is it a duplicate?** Search the program's public disclosed reports (if available) for the same issue.
5. **Write the report with:** a clear title, steps to reproduce, impact statement, and a minimal PoC. Redact any real user data.

Good luck — and always test responsibly, inside scope, and within the program's rules of engagement.
