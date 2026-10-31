# recon.sh — Full-Spectrum Bug Bounty Recon Pipeline

A single Bash pipeline that chains 35+ open-source recon and vulnerability-scanning
tools into one run: subdomain enumeration → DNS resolution → HTTP probing → crawling →
JS/secret scanning → vulnerability scanning → correlation → a queryable SQLite database
and a Markdown summary report.

> ⚠️ **For authorized security testing only.** Only run this against targets you own,
> or where you have explicit written permission (e.g. an in-scope bug bounty program).
> Running active scans, bruteforce, fuzzing, XSS/SQLi probing, or OOB probing against a
> target without authorization is illegal in most jurisdictions.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
  - [On Kali Linux](#on-kali-linux)
  - [On Ubuntu / Debian](#on-ubuntu--debian)
  - [Manual / other distros](#manual--other-distros)
- [Quick start](#quick-start)
- [Full tool list](#full-tool-list)
- [All command-line options](#all-command-line-options)
- [Usage examples](#usage-examples)
- [Output structure](#output-structure)
- [Advanced usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Requirements

| Requirement | Why |
|---|---|
| Linux (Kali, Ubuntu, Debian, Parrot, WSL2) | Bash + Linux tool ecosystem |
| Go ≥ 1.21 | Most tools install via `go install` |
| Python 3 + pip3 | Python-based tools (sublist3r, dnsgen, arjun, etc.) |
| Git | Cloning tools with no package/binary release |
| ~2 GB free disk | Go toolchain + binaries + nuclei templates |
| `sqlite3` (optional) | Powers `final/recon.db` |
| `dig` (optional) | Needed for `--shodan` |

Core tools (**required** — the script checks for these and warns if missing, but still
runs in a degraded mode):

```
subfinder, assetfinder, findomain, sublist3r, subdominator, dnsx, httpx (or httpx-toolkit), nuclei
```

Every other tool is **optional** — any step whose tool isn't installed is skipped with a
warning, so the pipeline never hard-fails because one tool is missing.

---

## Installation

### On Kali Linux

Kali ships Go, Python 3, pip3, and git by default, but some are outdated or missing
pieces (`pipx`, `$GOPATH/bin` not on `$PATH`). Do this once:

```bash
# 1. Update Kali and make sure the base toolchain is present
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y golang-go python3 python3-pip python3-venv git curl unzip sqlite3 dnsutils build-essential

# 2. Confirm Go version (need 1.21+; Kali's repo version can lag)
go version
# If it's older than 1.21, install a current Go manually:
#   wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
#   sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
#   echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc   # Kali's default shell is zsh

# 3. Make sure Go's bin dir and pip's user bin dir are on PATH (Kali uses zsh by default)
echo 'export GOPATH=$HOME/go' >> ~/.zshrc
echo 'export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin' >> ~/.zshrc
source ~/.zshrc

# 4. pip on Kali/Debian is "externally managed" — always use --break-system-packages
#    (install.sh already does this for you automatically)

# 5. Clone the repo and run the installer
git clone https://github.com/<you>/recon-toolkit.git
cd recon-toolkit
chmod +x install.sh recon.sh
./install.sh --full        # installs every tool, core + optional
```

Kali-specific notes:

- Kali's default shell is **zsh**, not bash — `source ~/.zshrc`, not `~/.bashrc`, after
  editing your PATH. The scripts themselves are `#!/usr/bin/env bash` and run fine under
  zsh as a login shell, this only affects where you add `PATH` exports.
- `naabu`'s raw-socket SYN scan needs root. On Kali you're often already root (classic
  Kali default) or using `sudo` — `recon.sh` detects this automatically and falls back
  to `-scan-type connect` when not root, so it works either way, just slightly slower.
- `amass`, `nuclei -update-templates`, and `go install` all make outbound network calls.
  If you're on a VPN/VM with restrictive egress, whitelist `github.com`, `objects.githubusercontent.com`,
  `proxy.golang.org`, and `pypi.org`.
- Kali's built-in `sqlmap` and the one `install.sh` sets up are both fine — if you
  already have `sqlmap` on `$PATH` from Kali's own repo, `install.sh` detects it and
  skips reinstalling.

### On Ubuntu / Debian

Same steps as Kali above, minus the Kali-specific notes — just use `~/.bashrc` instead
of `~/.zshrc` if you're on bash (Ubuntu/Debian default):

```bash
sudo apt update && sudo apt install -y golang-go python3 python3-pip git curl unzip sqlite3 dnsutils build-essential
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc
git clone https://github.com/<you>/recon-toolkit.git
cd recon-toolkit
chmod +x install.sh recon.sh
./install.sh --full
```

### Manual / other distros

Install Go, Python 3 + pip3, and git through your distro's package manager, make sure
`$GOPATH/bin` and `~/.local/bin` are on `$PATH`, then run `./install.sh --full`.
Everything else (tool-by-tool install logic, fallbacks for tools with no `go install`
path) is handled by the script.

**Verify the install:**

```bash
which subfinder dnsx httpx nuclei naabu katana gau ffuf subjs trufflehog gowitness amass dalfox arjun
which interactsh-client sqlite3
```

Any tool not found here either failed to install (check the colored output from
`install.sh` for a `[-]` warning) or needs a manual step — see
[Troubleshooting](#troubleshooting).

---

## Quick start

```bash
# Core-only recon (no flags = passive subdomain enum + resolve + HTTP probe + nuclei)
./recon.sh -d example.com

# Everything safe, in one go (excludes --sqli, which is opt-in only)
./recon.sh -d example.com --full --notify

# Batch mode: one root domain per line in a file
./recon.sh -dL targets.txt --full
```

Results land in `./<domain>_<timestamp>/`, and a human-readable `final/SUMMARY.md` is
printed at the end of every run.

---

## Full tool list

### Core (required)

| Tool | Role |
|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Passive subdomain/asset enumeration |
| [findomain](https://github.com/findomain/findomain) | Fast passive subdomain enumeration |
| [sublist3r](https://github.com/aboul3la/Sublist3r) | Search-engine-based subdomain enumeration |
| [subdominator](https://pypi.org/project/subdominator/) | Passive subdomain enumeration |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution, wildcard detection |
| [httpx](https://github.com/projectdiscovery/httpx) / httpx-toolkit | HTTP(S) probing, tech-detect, status codes, titles |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |

### Optional — Asset discovery

| Tool | Flag | Role |
|---|---|---|
| [amass](https://github.com/owasp-amass/amass) | `--amass` | Deep passive/active asset discovery |
| [chaos-client](https://github.com/projectdiscovery/chaos-client) | `--chaos` | ProjectDiscovery Chaos dataset (needs `CHAOS_API_KEY`) |
| [github-subdomains](https://github.com/gwen001/github-subdomains) | `--githubscan` | Subdomain/secret discovery via GitHub code search |
| [asnmap](https://github.com/projectdiscovery/asnmap) | `--asn` | ASN / IP range discovery |

### Optional — Active DNS bruteforce

| Tool | Flag | Role |
|---|---|---|
| [puredns](https://github.com/d3mondev/puredns) | `--bruteforce <wordlist>` | Fast, accurate DNS bruteforce resolution |
| [massdns](https://github.com/blechschmidt/massdns) | `--bruteforce <wordlist>` | Fallback resolver if puredns is absent |
| [dnsgen](https://github.com/ProjectAnte/dnsgen) | `--bruteforce <wordlist>` | Subdomain permutation wordlist generation |
| altdns | `--bruteforce <wordlist>` | Alternate permutation generator (fallback) |

### Optional — Ports & live hosts

| Tool | Flag | Role |
|---|---|---|
| [naabu](https://github.com/projectdiscovery/naabu) | `--portscan` | Port scanning |

### Optional — Crawling & historical URLs

| Tool | Flag | Role |
|---|---|---|
| [katana](https://github.com/projectdiscovery/katana) | `--crawl` | Active, JS-aware crawling |
| [gospider](https://github.com/jaeles-project/gospider) | `--crawl` | Alternate crawler |
| [hakrawler](https://github.com/hakluke/hakrawler) | `--crawl` | Lightweight crawler |
| [gau](https://github.com/lc/gau) | `--crawl` | Historical URLs (Wayback/CommonCrawl/OTX/URLScan) |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | `--crawl` | Historical URLs via Wayback Machine |

### Optional — Fuzzing & API discovery

| Tool | Flag | Role |
|---|---|---|
| [ffuf](https://github.com/ffuf/ffuf) | `--ffuf <wordlist>` | Directory/file brute-forcing |
| [kiterunner](https://github.com/assetnote/kiterunner) (`kr`) | `--api` / `--api-wordlist` | API route/endpoint bruteforce |
| [arjun](https://github.com/s0md3v/Arjun) | `--params` | Hidden HTTP parameter discovery |
| [paramspider](https://github.com/devanshbatham/ParamSpider) | `--params` | Hidden parameter discovery from archived URLs |

### Optional — JavaScript & secrets

| Tool | Flag | Role |
|---|---|---|
| [subjs](https://github.com/lc/subjs) | `--jsscan` | Collect JS files from live hosts |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | `--jsscan` | Extract endpoints hidden inside JS |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | `--jsscan` | Extract secrets/API keys hidden inside JS |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | `--jsscan`, `--githubscan` | Secret scanning (filesystem + GitHub) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | `--jsscan` (fallback) | Secret scanning, alternate engine |

### Optional — Vulnerability & misconfig scanning

| Tool | Flag | Role |
|---|---|---|
| [subzy](https://github.com/PentestPad/subzy) | `--takeover` | Subdomain takeover detection |
| [dalfox](https://github.com/hahwul/dalfox) | `--xss` | Reflected/DOM XSS scanning |
| [sqlmap](https://sqlmap.org/) | `--sqli` (opt-in) | SQL injection detection scan |
| [interactsh-client](https://github.com/projectdiscovery/interactsh) | `--interactsh` | Out-of-band blind vuln probing (SSRF/XXE/SSTI) |
| [Corsy](https://github.com/s0md3v/Corsy) | `--corsscan` | CORS misconfiguration scanning |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | `--wafcheck` | WAF/CDN fingerprinting |
| [S3Scanner](https://github.com/sa7mon/S3Scanner) | `--cloudscan` | S3 bucket enumeration |
| cloud_enum | `--cloudscan` | AWS/GCP/Azure storage enumeration (preferred if present) |
| [favfreak](https://github.com/devanshbatham/FavFreak) | `--favicon` | Favicon-hash tech fingerprinting |

### Optional — Custom modules (built into recon.sh itself, no extra tool)

| Module | Flag | Role |
|---|---|---|
| IDOR / access-control scanner | `--idor`, `--idor-session-a`, `--idor-session-b` | Finds numeric/UUID IDs, mutates them, and (with two session header files) diffs responses between two accounts |
| JWT analysis | `--jwt` | Finds JWTs in responses/JS, decodes headers, flags `alg:none` and weak-signing indicators |
| GraphQL discovery | `--graphql` | Probes common GraphQL paths, attempts introspection, dumps leaked schemas |
| Correlation layer | on by default, `--no-correlate` to skip | Cross-references JS secrets against API routes, maps detected tech+version to a CVE-check shortlist |
| SQLite backend | on by default, `--no-db` to skip | Builds `final/recon.db` — subdomains, live hosts, nuclei findings, JWTs, GraphQL endpoints, IDOR candidates |

### Optional — Reporting

| Tool | Flag | Role |
|---|---|---|
| [gowitness](https://github.com/sensepost/gowitness) | `--screenshots` | Screenshots of live hosts |
| [notify](https://github.com/projectdiscovery/notify) | `--notify` | Slack/Discord/Telegram summary notification |
| `curl` (built-in) | `--shodan` | Free Shodan InternetDB enrichment, no API key needed |

**35+ tools total**, each wired into its own pipeline phase with graceful skip-if-missing
behavior — no single missing tool breaks the run.

---

## All command-line options

```
Usage: ./recon.sh -d <domain> [options]
       ./recon.sh -dL <domains_file> [options]     (batch mode, one domain per line)

Required (one of):
  -d,  --domain <domain>       Target root domain
  -dL, --domain-list <file>    File of multiple root domains

Core options:
  -s,  --scope <file>          In-scope patterns file (filters results)
  -o,  --outdir <dir>          Output directory (default: ./<domain>_<timestamp>)
  -t,  --threads <n>           Thread count (default: 100)
  -r,  --rate-limit <n>        Nuclei rate limit, req/sec (default: 150)
  --sev <list>                 Nuclei severities (default: critical,high,medium,low)

Module toggles:
  --full                       Enable ALL safe modules (excludes --sqli — opt-in only)
  --amass                      Deep passive asset discovery
  --chaos                      ProjectDiscovery Chaos dataset (needs CHAOS_API_KEY)
  --bruteforce <wordlist>      Active DNS bruteforce + permutation
  --shodan                     Shodan InternetDB enrichment (free, no key needed)
  --takeover                   Subdomain takeover check
  --portscan                   Port scanning (naabu)
  --crawl                      Active crawling + historical URLs
  --ffuf <wordlist>            Directory/file brute-force
  --params                     Hidden parameter discovery
  --api                        API route bruteforce (hosted Assetnote wordlist)
  --api-wordlist <file.kite>   API route bruteforce with your own compiled wordlist
  --jsscan                     JS collection + endpoint/secret extraction
  --xss                        Reflected/DOM XSS scan
  --sqli                       SQLi DETECTION scan (opt-in only — see warning below)
  --interactsh                 Out-of-band blind vuln probing
  --idor                       IDOR candidate scanning (static heuristic)
  --idor-session-a <file>      Session A headers (enables session-diff IDOR mode)
  --idor-session-b <file>      Session B headers
  --jwt                        JWT discovery + weak-signing check
  --graphql                    GraphQL endpoint discovery + introspection
  --no-correlate               Skip the cross-module correlation pass
  --no-db                      Skip building final/recon.db
  --cloudscan                  Cloud storage bucket enumeration
  --githubscan                 GitHub-based subdomain/secret leak discovery
  --corsscan                   CORS misconfiguration scan
  --wafcheck                   WAF/CDN fingerprinting
  --asn                        ASN / IP range discovery
  --favicon                    Favicon-hash fingerprinting
  --screenshots                Screenshot live hosts

Notifications:
  --notify                     Send summary via the 'notify' tool
  --webhook <url>               POST summary JSON to a custom webhook URL

  -h,  --help                  Show help
```

> ⚠️ `--sqli` sends extra probing requests to every parameterized URL found (even at
> `--level=1 --risk=1`, detection-only, no `--dump`). Only use it where your target's
> program explicitly allows automated SQLi testing.

---

## Usage examples

```bash
# Everything safe + Slack/Discord notification at the end
./recon.sh -d example.com -s scope.txt --full --notify

# Takeover hunting + JS secrets + full crawl
./recon.sh -dL targets.txt --takeover --jsscan --crawl

# Crawl, find hidden params, then XSS-test them
./recon.sh -d example.com --crawl --params --xss

# Active DNS bruteforce with a custom wordlist + Shodan enrichment
./recon.sh -d example.com --bruteforce wordlists/subs.txt --shodan

# Real broken-access-control testing with two logged-in sessions
./recon.sh -d example.com --crawl --idor \
  --idor-session-a cookies_user_a.txt \
  --idor-session-b cookies_user_b.txt

# GraphQL + JWT + blind OOB vulns in one pass
./recon.sh -d example.com --crawl --graphql --jwt --interactsh

# Opt-in SQLi detection pass (only once your program explicitly allows it)
./recon.sh -d example.com --crawl --sqli

# Narrow, fast, CI-friendly run: core recon + nuclei only, low rate limit
./recon.sh -d example.com -t 50 -r 50 --sev critical,high
```

`cookies_user_a.txt` / `cookies_user_b.txt` are plain `curl -H`-format header files, one
header per line, e.g.:

```
Cookie: session=abc123...
Authorization: Bearer eyJ...
```

---

## Output structure

```
<domain>_<timestamp>/
├── raw/          per-tool subdomain enum output (incl. amass, chaos)
├── final/        merged, scoped, resolved subdomains + diff + wildcard info + recon.db
├── interactsh/   out-of-band blind vulnerability probing results
├── idor/         IDOR / broken access control candidates
├── jwt/          JWT tokens found + weak-signing analysis
├── graphql/      GraphQL endpoints with open introspection + leaked schemas
├── intel/        CORRELATION.md — cross-module findings + tech-to-CVE shortlist
├── bruteforce/   active DNS bruteforce + permutation results
├── shodan/       Shodan InternetDB enrichment
├── ports/        naabu port scan results
├── http/         live hosts, tech stack, screenshots
├── urls/         crawled + historical URLs, ffuf results
├── params/       hidden parameter discovery (arjun, paramspider)
├── api/          kiterunner API route bruteforce results
├── js/           collected JS files, endpoints (linkfinder), secrets (secretfinder/trufflehog)
├── xss/          dalfox XSS scan results
├── sqli/         sqlmap detection-scan results (only if --sqli used)
├── cloud/        cloud bucket enumeration
├── github/       GitHub leak scan
├── cors/         CORS misconfig results
├── waf/          WAF/CDN fingerprinting
├── asn/          ASN / IP ranges
├── favicon/      favicon hash fingerprinting
├── vulns/        nuclei + takeover results
└── logs/         full run log
```

Empty folders (modules you didn't enable) are automatically removed at the end of the run.

`final/SUMMARY.md` is regenerated every run with a count table across every stage, plus
this same folder-structure reference.

---

## Advanced usage

### Querying the SQLite backend

```bash
sqlite3 final/recon.db "SELECT * FROM nuclei_findings;"
sqlite3 final/recon.db "SELECT COUNT(*) FROM subdomains;"
sqlite3 final/recon.db "SELECT * FROM idor_candidates;"
```

Tables: `subdomains`, `live_hosts`, `nuclei_findings`, `jwt_tokens`,
`graphql_endpoints`, `idor_candidates`.

### Continuous monitoring

Run the same target daily/weekly via cron — `final/new_subs.txt` and the
`.recon_history/` folder automatically diff each run against the last one, so you only
need to look at what's *new*:

```bash
# crontab -e
0 6 * * * cd /path/to/recon-toolkit && ./recon.sh -d example.com --full --notify >> cron.log 2>&1
```

### One-time setup for tools that need auth

- **Chaos** (`--chaos`): `export CHAOS_API_KEY=your_key` (free at chaos.projectdiscovery.io)
- **asnmap** (`--asn`): run `asnmap -auth` once, follow the printed URL + login code
- **GitHub scanning** (`--githubscan`, `trufflehog github`): `export GITHUB_TOKEN=your_token`
- **Shodan InternetDB** (`--shodan`): no key needed, it's the free InternetDB endpoint

### Compiling a custom kiterunner wordlist

```bash
kr kb compile routes.json routes.kite
./recon.sh -d example.com --api-wordlist routes.kite
```

### Tuning for large scopes

```bash
# Lower thread count + rate limit for a strict/rate-limiting target
./recon.sh -d example.com --full -t 30 -r 50

# Scope file to keep results tight on a big org
./recon.sh -d example.com --full -s scope.txt
```

`scope.txt` is a plain grep pattern file, one pattern per line, e.g.:

```
\.example\.com$
\.example-staging\.net$
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found` after `install.sh` | Run `source ~/.bashrc` (or `~/.zshrc` on Kali) — PATH wasn't picked up in the current shell |
| `naabu` finds 0 ports | You're not root — recon.sh already falls back to `-scan-type connect` automatically, just slower |
| `asnmap` hangs / asks for an API key | Run `asnmap -auth` once outside the script (one-time login) |
| `go install` fails with "must not contain directives" | Some tools (trufflehog, kiterunner) don't support `go install` — `install.sh` already uses their official install script / `git clone + make build` instead |
| pip install fails with "externally-managed-environment" | `install.sh` already passes `--break-system-packages` — if installing manually, add that flag yourself |
| nuclei scan looks stuck | It is NOT silent-forever — `-stats -stats-interval 20` prints progress every 20s, and the whole phase has a 15-minute hard ceiling |
| A phase looks hung for 30+ seconds | Long-running phases (crawl, params, XSS) print a heartbeat log line every 30s — this is expected on a thorough scan |

---

## Disclaimer

This toolkit automates **reconnaissance and detection-level scanning**. It does not
exploit, dump data, or cause damage by default — `--sqli` remains detection-only
(`--level=1 --risk=1`, no `--dump`) even when explicitly enabled. That said:

- Only run this against infrastructure you own or are explicitly authorized to test.
- Read the bug bounty program's scope and rules before enabling `--sqli`, `--bruteforce`,
  `--portscan`, `--ffuf`, `--interactsh`, or `--idor` — these are active/intrusive modules.
- The authors are not responsible for misuse of this tool.
