#!/usr/bin/env bash
#
# recon.sh — Full-Spectrum Bug Bounty Recon Pipeline
#
# Usage:
#   ./recon.sh -d example.com [-s scope.txt] [options]
#   ./recon.sh -dL domains.txt [options]            (batch mode)
#
# Core requirements:
#   subfinder, assetfinder, findomain, sublist3r, subdominator,
#   dnsx, httpx-toolkit (or httpx), nuclei
#
# Optional (each step auto-skips if the tool isn't installed):
#   amass             - deep passive/active asset discovery (alt to subfinder)
#   chaos-client       - ProjectDiscovery Chaos DNS dataset (needs CHAOS_API_KEY)
#   naabu             - port scanning
#   katana            - active crawling / endpoint discovery
#   gospider, hakrawler - alternate crawlers
#   gau, waybackurls   - historical URL discovery
#   ffuf              - directory/file brute-forcing
#   puredns, massdns   - active DNS bruteforce resolution
#   dnsgen, altdns     - subdomain permutation wordlist generation
#   subjs             - collect JS files from live hosts
#   linkfinder         - endpoints hidden inside JS files
#   secretfinder       - secrets hidden inside JS files
#   trufflehog         - secrets scanning (local files + GitHub)
#   gitleaks           - secrets scanning (alt)
#   S3Scanner, cloud_enum - cloud storage bucket enumeration
#   github-subdomains  - GitHub-based subdomain/leak discovery
#   Corsy              - CORS misconfiguration scanning
#   wafw00f            - WAF/CDN fingerprinting
#   asnmap             - ASN / IP range discovery
#   favfreak           - favicon-hash tech fingerprinting
#   arjun, paramspider  - hidden parameter discovery
#   kiterunner          - API route/endpoint bruteforce
#   dalfox              - XSS scanning
#   sqlmap              - SQLi detection (opt-in only, detection-level by default)
#   gowitness           - screenshots
#   notify              - Slack/Discord/Telegram alerts
#   curl                - used for the free Shodan InternetDB lookup (no API key needed)
#
# Manual/GUI tools (Burp Suite, Caido, OWASP ZAP) are NOT part of this script —
# they're interactive interception proxies, not CLI recon tools. Use them by
# hand on the interesting hosts/endpoints this script surfaces. See README.md.
#
# For authorized security testing / bug bounty use only.
# -----------------------------------------------------------------------

set -uo pipefail

# ---------- Cleanup on exit/interrupt ----------
# Some tools we background with '&' (notably sublist3r, which forks its own
# Python multiprocessing worker per search engine) spawn grandchild processes
# that are NOT automatically killed when this script exits or is Ctrl-C'd.
# Left running, they can bleed stray output, crashes, or even "[sudo] password
# for kali:" prompts into a completely unrelated LATER terminal session. Track
# every backgrounded PID and make sure the whole subtree is killed on exit.
BG_PIDS=()
# Recursively kill a process and everything it spawned (children, grandchildren,
# ...) — needed because e.g. sublist3r forks its own Python multiprocessing
# worker PER SEARCH ENGINE, which is a grandchild of the PID we captured, not
# a direct child, so a single-level kill would miss it.
killtree() {
  local pid="$1" child
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    killtree "$child"
  done
  kill -TERM "$pid" 2>/dev/null
}
cleanup_background_jobs() {
  local pid
  for pid in "${BG_PIDS[@]:-}"; do
    [ -z "$pid" ] && continue
    killtree "$pid"
  done
}
trap cleanup_background_jobs EXIT INT TERM

# ---------- Defaults ----------
THREADS=100
OUTDIR=""
SCOPE_FILE=""
DOMAIN_LIST=""
NOTIFY=false
WEBHOOK_URL=""
NUCLEI_RATE_LIMIT=150
SEVERITIES="critical,high,medium,low"
SCREENSHOTS=false
PORTSCAN=false
CRAWL=false
JS_SCAN=false
CLOUD_SCAN=false
GITHUB_SCAN=false
CORS_SCAN=false
WAF_CHECK=false
ASN_SCAN=false
FAVICON_SCAN=false
FFUF_WORDLIST=""
TAKEOVER=false
FULL=false
HISTORY_DIR=".recon_history"
AMASS_SCAN=false
CHAOS_SCAN=false
BRUTE_WORDLIST=""
SHODAN_LOOKUP=false
PARAM_DISCOVERY=false
API_SCAN=false
API_WORDLIST=""
XSS_SCAN=false
SQLI_SCAN=false
SQLI_RISK=1
SQLI_LEVEL=1
INTERACTSH_SCAN=false
IDOR_SCAN=false
IDOR_SESSION_A=""
IDOR_SESSION_B=""
JWT_SCAN=false
GRAPHQL_SCAN=false
CORRELATE=true
DB_BACKEND=true

# ---------- Colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()   { echo -e "${BLUE}[*]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
ok()    { echo -e "${GREEN}[+]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
warn()  { echo -e "${YELLOW}[!]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
err()   { echo -e "${RED}[-]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE" >&2; }
have()  { command -v "$1" >/dev/null 2>&1; }
countf() { [ -f "$1" ] && wc -l < "$1" || echo 0; }
# Caps a host/URL list to $2 lines before a slow per-item loop, warning once if
# it had to trim — the same fix that made Phase 7 (Shodan) fast on large scopes,
# applied anywhere else a new module loops over live_urls.txt/resolved hosts.
cap_list() {
  local file="$1" cap="$2" label="$3" total
  total=$(countf "$file")
  if [ "$total" -gt "$cap" ]; then
    warn "$label: $total hosts is a lot — capping to the first $cap to keep this phase fast."
    head -n "$cap" "$file"
  else
    cat "$file" 2>/dev/null
  fi
}

usage() {
  cat <<EOF
Usage: $0 -d <domain> [options]
       $0 -dL <domains_file> [options]     (batch mode, one domain per line)

Required (one of):
  -d,  --domain <domain>     Target root domain
  -dL, --domain-list <file>  File of multiple root domains

Core options:
  -s,  --scope <file>        In-scope patterns file (filters results)
  -o,  --outdir <dir>        Output directory (default: ./<domain>_<timestamp>)
  -t,  --threads <n>         Thread count (default: 100)
  -r,  --rate-limit <n>      Nuclei rate limit, req/sec (default: 150)
  --sev <list>                Nuclei severities (default: critical,high,medium,low)

Module toggles (each skips gracefully if its tool isn't installed):
  --full                      Enable ALL safe modules below (excludes --sqli — opt-in only)
  --amass                     Deep passive asset discovery with amass (extra subdomain source)
  --chaos                     Pull subdomains from ProjectDiscovery Chaos (needs CHAOS_API_KEY)
  --bruteforce <wordlist>     Active DNS bruteforce + permutation (puredns/massdns, dnsgen/altdns)
  --shodan                    Enrich resolved IPs via Shodan InternetDB (free, no key needed)
  --takeover                  Subdomain takeover check (nuclei takeover templates + subzy)
  --portscan                  Port scanning with naabu
  --crawl                     Active crawling + historical URLs (katana, gospider, hakrawler, gau, waybackurls)
  --ffuf <wordlist>           Directory/file brute-force with ffuf
  --params                    Hidden parameter discovery (arjun, paramspider)
  --api                        API route/endpoint bruteforce with kiterunner (uses its
                               hosted Assetnote wordlist — no local file needed)
  --api-wordlist <file.kite>   Same as --api but with your own compiled .kite wordlist
                               (build one with: kr kb compile routes.json routes.kite)
  --jsscan                    Collect JS + find endpoints/secrets (subjs, linkfinder, secretfinder, trufflehog/gitleaks)
  --xss                       Reflected/DOM XSS scan on parameterized URLs (dalfox)
  --sqli                      SQLi DETECTION scan on parameterized URLs (sqlmap, opt-in only — see warning below)
  --interactsh                Out-of-band (OOB) probing for BLIND vulns: SSRF, XXE, SSTI,
                               blind command injection (interactsh-client). Catches bugs
                               that give no visible response — a major gap in pure HTTP scanning.
  --idor                      IDOR candidates: finds numeric/UUID IDs in discovered URLs,
                               mutates them, and flags endpoints worth testing by hand.
  --idor-session-a <file>     Header file (curl -H format, one per line) for account A.
  --idor-session-b <file>     Header file for account B. With both A and B given, every
                               discovered URL is fetched as BOTH accounts and the responses
                               are diffed — the real way to catch broken access control.
  --jwt                       Find JWTs in responses/JS, decode them, flag alg:none and
                               other weak-signing indicators (detection only, no forging).
  --graphql                   Probe common GraphQL paths and attempt introspection — a full
                               leaked schema is a common, high-value, under-tested finding.
  --no-correlate               Skip the correlation pass (on by default): cross-references
                               JS secrets against discovered API routes and maps detected
                               tech + versions to known CVEs, instead of leaving you to
                               manually connect findings across a dozen output folders.
  --no-db                      Skip building final/recon.db (on by default): a SQLite
                               database of every finding, for historical tracking, querying,
                               and feeding into your own reporting/dashboard tooling.
  --cloudscan                 Cloud storage bucket enumeration (S3Scanner, cloud_enum)
  --githubscan                GitHub-based subdomain/secret leak discovery
  --corsscan                  CORS misconfiguration scan (Corsy)
  --wafcheck                  WAF/CDN fingerprinting (wafw00f)
  --asn                       ASN / IP range discovery (asnmap)
  --favicon                   Favicon-hash fingerprinting (favfreak)
  --screenshots               Screenshot live hosts (gowitness)

Notifications:
  --notify                    Send summary via 'notify' tool (if installed)
  --webhook <url>              Also POST summary JSON to a custom webhook URL

  -h,  --help                 Show this help

⚠️  --sqli runs sqlmap against every parameterized URL found. Even at the
    default detection-only settings (--level=1 --risk=1, no --dump, no
    destructive flags) this sends extra probing requests. Only use it on
    targets whose program explicitly allows automated SQLi testing — many
    don't. When unsure, leave it off and test suspected parameters by hand.

Examples:
  $0 -d example.com -s scope.txt --full --notify
  $0 -dL targets.txt --takeover --jsscan --crawl
  $0 -d example.com --crawl --params --xss
  $0 -d example.com --bruteforce wordlists/subs.txt --shodan
EOF
  exit 1
}

# ---------- Arg parsing ----------
DOMAIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -dL|--domain-list) DOMAIN_LIST="$2"; shift 2 ;;
    -s|--scope) SCOPE_FILE="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    -t|--threads) THREADS="$2"; shift 2 ;;
    -r|--rate-limit) NUCLEI_RATE_LIMIT="$2"; shift 2 ;;
    --sev) SEVERITIES="$2"; shift 2 ;;
    --full) FULL=true; shift ;;
    --amass) AMASS_SCAN=true; shift ;;
    --chaos) CHAOS_SCAN=true; shift ;;
    --bruteforce) BRUTE_WORDLIST="$2"; shift 2 ;;
    --shodan) SHODAN_LOOKUP=true; shift ;;
    --takeover) TAKEOVER=true; shift ;;
    --portscan) PORTSCAN=true; shift ;;
    --crawl) CRAWL=true; shift ;;
    --ffuf) FFUF_WORDLIST="$2"; shift 2 ;;
    --params) PARAM_DISCOVERY=true; shift ;;
    --api) API_SCAN=true; shift ;;
    --api-wordlist) API_SCAN=true; API_WORDLIST="$2"; shift 2 ;;
    --jsscan) JS_SCAN=true; shift ;;
    --xss) XSS_SCAN=true; shift ;;
    --sqli) SQLI_SCAN=true; shift ;;
    --interactsh) INTERACTSH_SCAN=true; shift ;;
    --idor) IDOR_SCAN=true; shift ;;
    --idor-session-a) IDOR_SCAN=true; IDOR_SESSION_A="$2"; shift 2 ;;
    --idor-session-b) IDOR_SCAN=true; IDOR_SESSION_B="$2"; shift 2 ;;
    --jwt) JWT_SCAN=true; shift ;;
    --graphql) GRAPHQL_SCAN=true; shift ;;
    --no-correlate) CORRELATE=false; shift ;;
    --no-db) DB_BACKEND=false; shift ;;
    --cloudscan) CLOUD_SCAN=true; shift ;;
    --githubscan) GITHUB_SCAN=true; shift ;;
    --corsscan) CORS_SCAN=true; shift ;;
    --wafcheck) WAF_CHECK=true; shift ;;
    --asn) ASN_SCAN=true; shift ;;
    --favicon) FAVICON_SCAN=true; shift ;;
    --screenshots) SCREENSHOTS=true; shift ;;
    --notify) NOTIFY=true; shift ;;
    --webhook) WEBHOOK_URL="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [ "$FULL" = true ]; then
  AMASS_SCAN=true; CHAOS_SCAN=true; SHODAN_LOOKUP=true
  TAKEOVER=true; PORTSCAN=true; CRAWL=true; JS_SCAN=true; CLOUD_SCAN=true
  GITHUB_SCAN=true; CORS_SCAN=true; WAF_CHECK=true; ASN_SCAN=true
  FAVICON_SCAN=true; SCREENSHOTS=true; PARAM_DISCOVERY=true; XSS_SCAN=true; API_SCAN=true
  INTERACTSH_SCAN=true; IDOR_SCAN=true; JWT_SCAN=true; GRAPHQL_SCAN=true
  # Note: --sqli and --bruteforce (needs a wordlist) are NEVER auto-enabled by --full.
  # Session-diff IDOR (--idor-session-a/-b) also needs explicit credentials, so --full
  # only gets the static-heuristic IDOR pass. All of these are opt-in only.
fi

if [ -z "$DOMAIN" ] && [ -z "$DOMAIN_LIST" ]; then
  echo "Error: provide -d <domain> or -dL <domains_file>"
  usage
fi

# ---------- Sanitize domain input ----------
# Accepts a full URL by mistake (https://www.example.com/path) and reduces it
# to a bare domain (www.example.com), so downstream tools and folder names don't break.
sanitize_domain() {
  local d="$1"
  d="${d#http://}"; d="${d#https://}"   # strip scheme
  d="${d%%/*}"                           # strip any path
  d="${d%%:*}"                           # strip any port
  d="${d%.}"                             # strip trailing dot
  echo "$d"
}

if [ -n "$DOMAIN" ]; then
  CLEAN_DOMAIN="$(sanitize_domain "$DOMAIN")"
  if [ "$CLEAN_DOMAIN" != "$DOMAIN" ]; then
    echo "Note: interpreting '$DOMAIN' as domain '$CLEAN_DOMAIN' (stripped scheme/path/port)"
  fi
  DOMAIN="$CLEAN_DOMAIN"
  if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'; then
    echo "Error: '$DOMAIN' doesn't look like a valid bare domain (e.g. example.com)"
    exit 1
  fi
fi

# ---------- Batch mode dispatcher ----------
if [ -n "$DOMAIN_LIST" ]; then
  if [ ! -f "$DOMAIN_LIST" ]; then
    echo "Domain list file not found: $DOMAIN_LIST"
    exit 1
  fi
  SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  ARGS=("$@")
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "=== Starting recon for: $line ==="
    bash "$SELF" -d "$line" "${ARGS[@]}"
  done < "$DOMAIN_LIST"
  exit 0
fi

# ---------- Setup ----------
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTDIR="${OUTDIR:-${DOMAIN}_${TIMESTAMP}}"
mkdir -p "$OUTDIR"/{raw,final,http,vulns,ports,urls,js,cloud,github,cors,waf,asn,favicon,logs,bruteforce,shodan,params,api,xss,sqli,interactsh,idor,jwt,graphql,intel}
cd "$OUTDIR" || { echo "Cannot cd into $OUTDIR"; exit 1; }
LOGFILE="logs/recon.log"
touch "$LOGFILE"

log "Starting recon against: $DOMAIN"
log "Output directory: $(pwd)"
log "Threads: $THREADS | Nuclei rate-limit: $NUCLEI_RATE_LIMIT"
[ "$FULL" = true ] && log "Mode: FULL (all modules enabled)"

HTTPX_BIN=""
if have httpx-toolkit; then HTTPX_BIN="httpx-toolkit"
elif have httpx; then HTTPX_BIN="httpx"
else err "Neither httpx-toolkit nor httpx found. Install one."; exit 1
fi

# ---------- Core dependency check (informational — tools still skip gracefully) ----------
CORE_TOOLS=(subfinder assetfinder findomain sublist3r subdominator dnsx nuclei)
MISSING_CORE=()
for t in "${CORE_TOOLS[@]}"; do have "$t" || MISSING_CORE+=("$t"); done
if [ "${#MISSING_CORE[@]}" -gt 0 ]; then
  warn "Missing core tools (steps using them will be skipped/degraded): ${MISSING_CORE[*]}"
  warn "Run scripts/install.sh to install everything in one go"
fi

run_if_available() {
  local tool="$1"; shift
  # Redirect stdin from /dev/null: if this tool (or a library it depends on,
  # e.g. a package quietly running `sudo something` on first use) ever tries
  # to prompt interactively, it fails fast instead of silently hanging the
  # whole script — this bit us once with asnmap and could happen with any tool.
  if have "$tool"; then "$@" < /dev/null; else warn "Skipping $tool (not installed)"; fi
}

# ========================================================================
# PHASE 1: Subdomain Enumeration (passive, parallel)
# ========================================================================
log "Phase 1: Subdomain enumeration"
run_if_available subfinder subfinder -d "$DOMAIN" -all -recursive -t "$THREADS" -silent -o raw/subfinder.txt & BG_PIDS+=("$!")
run_if_available assetfinder bash -c "assetfinder -subs-only '$DOMAIN' > raw/assetfinder.txt" & BG_PIDS+=("$!")
run_if_available findomain findomain -t "$DOMAIN" -u raw/findomain.txt & BG_PIDS+=("$!")
run_if_available sublist3r sublist3r -d "$DOMAIN" -t 50 -o raw/sublist3r.txt & BG_PIDS+=("$!")
run_if_available subdominator bash -c "subdominator -d '$DOMAIN' > raw/subdominator.txt" & BG_PIDS+=("$!")
if [ "$AMASS_SCAN" = true ]; then
  run_if_available amass bash -c "amass enum -passive -d '$DOMAIN' -o raw/amass.txt" & BG_PIDS+=("$!")
fi
if [ "$CHAOS_SCAN" = true ]; then
  if [ -z "${CHAOS_API_KEY:-}" ]; then
    warn "Skipping chaos (CHAOS_API_KEY env var not set — get one free at chaos.projectdiscovery.io)"
  else
    run_if_available chaos bash -c "chaos -d '$DOMAIN' -key '$CHAOS_API_KEY' -silent -o raw/chaos.txt" & BG_PIDS+=("$!")
  fi
fi
if [ "$GITHUB_SCAN" = true ]; then
  run_if_available github-subdomains bash -c "github-subdomains -d '$DOMAIN' -raw > raw/github_subs.txt" & BG_PIDS+=("$!")
fi
wait
BG_PIDS=()   # all finished cleanly — nothing left for the exit trap to chase
ok "Subdomain enumeration complete"

# ========================================================================
# PHASE 2: Merge, Dedup, Clean
# ========================================================================
log "Phase 2: Merging and deduplicating"
# The pattern matches the bare target domain ITSELF as well as any subdomain of it.
# Without the "(label.)?" prefix being optional, a target that is already a
# subdomain (e.g. press.priceline.com) with no further sub-subdomains discovered
# would get filtered down to zero results and the whole run would exit early.
cat raw/*.txt 2>/dev/null \
  | grep -E "^([a-zA-Z0-9._-]+\.)?${DOMAIN//./\\.}$" \
  | tr '[:upper:]' '[:lower:]' \
  | sort -u > final/all_subs.txt
TOTAL_RAW=$(cat raw/*.txt 2>/dev/null | wc -l)
TOTAL_UNIQUE=$(wc -l < final/all_subs.txt)
ok "Raw hits: $TOTAL_RAW -> Unique: $TOTAL_UNIQUE"

# ========================================================================
# PHASE 3: Scope Filtering
# ========================================================================
if [ -n "$SCOPE_FILE" ] && [ -f "$SCOPE_FILE" ]; then
  log "Phase 3: Applying scope filter from $SCOPE_FILE"
  grep -f "$SCOPE_FILE" final/all_subs.txt > final/in_scope.txt || touch final/in_scope.txt
  ok "In-scope subdomains: $(wc -l < final/in_scope.txt)"
  SUBS_FILE="final/in_scope.txt"
else
  warn "No scope file provided — using ALL discovered subdomains. Verify program scope before active scanning."
  SUBS_FILE="final/all_subs.txt"
fi
[ -s "$SUBS_FILE" ] || { err "No subdomains to process. Exiting."; exit 1; }

# ========================================================================
# PHASE 4: Wildcard DNS Detection
# ========================================================================
log "Phase 4: Wildcard DNS check"
if have dnsx; then
  WILDCARD_IPS=""
  for i in 1 2 3; do
    RAND_SUB="nonexistent-$(date +%s)-$RANDOM-$i.$DOMAIN"
    IP=$(dnsx -silent <<< "$RAND_SUB" 2>/dev/null | head -n1)
    [ -n "$IP" ] && WILDCARD_IPS="$WILDCARD_IPS $IP"
  done
  if [ -n "$(echo "$WILDCARD_IPS" | tr -d '[:space:]')" ]; then
    warn "Wildcard DNS detected — results may contain false positives"
    echo "$WILDCARD_IPS" | tr ' ' '\n' | sort -u > final/wildcard_ips.txt
  else
    ok "No wildcard DNS detected"
  fi
else
  warn "dnsx not installed — cannot check for wildcard DNS, results unverified"
fi

# ========================================================================
# PHASE 5: DNS Resolution
# ========================================================================
log "Phase 5: DNS resolution"
if have dnsx; then
  dnsx -l "$SUBS_FILE" -silent -o final/resolved.txt
  ok "Resolved: $(countf final/resolved.txt)"
else
  warn "dnsx not installed — skipping resolution, falling back to unresolved subdomain list"
  touch final/resolved.txt
fi
RESOLVED_FILE="final/resolved.txt"
[ -s "$RESOLVED_FILE" ] || RESOLVED_FILE="$SUBS_FILE"

# ========================================================================
# PHASE 6: Active DNS Bruteforce + Permutation (optional, --bruteforce)
# ========================================================================
if [ -n "$BRUTE_WORDLIST" ]; then
  log "Phase 6: Active DNS bruteforce + permutation"
  if [ ! -f "$BRUTE_WORDLIST" ]; then
    warn "Bruteforce wordlist not found: $BRUTE_WORDLIST — skipping"
  else
    # Permutation: expand known subdomains into likely variants (dev-api, api-dev, etc.)
    if have dnsgen; then
      dnsgen final/all_subs.txt 2>>"$LOGFILE" > bruteforce/permutations.txt || true
    elif have altdns; then
      altdns -i final/all_subs.txt -o bruteforce/permutations.txt -w "$BRUTE_WORDLIST" 2>>"$LOGFILE" || true
    else
      warn "Neither dnsgen nor altdns installed, skipping permutation step"
      touch bruteforce/permutations.txt
    fi
    cat "$BRUTE_WORDLIST" bruteforce/permutations.txt 2>/dev/null \
      | sed "s/\$/.${DOMAIN}/" | sort -u > bruteforce/brute_candidates.txt 2>/dev/null || true

    # puredns and massdns both need a plain list of resolver IPs (one per line),
    # NOT /etc/resolv.conf's "nameserver X.X.X.X" format. Write a small public
    # resolver list ourselves so this works out of the box with no setup.
    cat > bruteforce/resolvers.txt <<'RESOLVERS'
1.1.1.1
8.8.8.8
8.8.4.4
9.9.9.9
1.0.0.1
RESOLVERS

    # Resolution: resolve all candidates at once, fast
    if have puredns; then
      puredns resolve bruteforce/brute_candidates.txt -r bruteforce/resolvers.txt \
        --write bruteforce/brute_resolved.txt 2>>"$LOGFILE" || true
    elif have massdns; then
      massdns -r bruteforce/resolvers.txt -t A -o S -w bruteforce/brute_resolved.txt bruteforce/brute_candidates.txt 2>>"$LOGFILE" || true
    else
      warn "Neither puredns nor massdns installed, skipping active bruteforce resolution"
      touch bruteforce/brute_resolved.txt
    fi
    BRUTE_COUNT=$(countf bruteforce/brute_resolved.txt)
    ok "Bruteforce found: $BRUTE_COUNT resolved candidate(s)"
    if [ "$BRUTE_COUNT" -gt 0 ]; then
      # puredns --write gives clean hostnames already. massdns -o S gives
      # "hostname. A 1.2.3.4" lines — normalize both to bare hostnames before merging.
      awk '{gsub(/\.$/, "", $1); print $1}' bruteforce/brute_resolved.txt \
        | grep -E "^([a-zA-Z0-9._-]+\.)?${DOMAIN//./\\.}$" >> final/all_subs.txt
      sort -u -o final/all_subs.txt final/all_subs.txt
    fi
  fi
fi

# ========================================================================
# PHASE 7: Shodan InternetDB Enrichment (optional, --shodan)
# ========================================================================
if [ "$SHODAN_LOOKUP" = true ]; then
  log "Phase 7: Enriching resolved IPs via Shodan InternetDB"
  if have curl && have dig; then
    HOST_TOTAL=$(countf "$RESOLVED_FILE")
    SHODAN_CAP=300
    if [ "$HOST_TOTAL" -gt "$SHODAN_CAP" ]; then
      warn "$HOST_TOTAL hosts to check — that's a lot, likely because dnsx wasn't available to"
      warn "filter down to resolved hosts first (see Phase 5). Capping this lookup to the first"
      warn "$SHODAN_CAP to avoid a multi-hour run; install dnsx for a properly filtered, faster pass."
      head -n "$SHODAN_CAP" "$RESOLVED_FILE" > shodan/.capped_hosts.txt
      SHODAN_INPUT="shodan/.capped_hosts.txt"
    else
      SHODAN_INPUT="$RESOLVED_FILE"
    fi
    : > shodan/internetdb_results.json
    SHODAN_DONE=0
    while read -r host; do
      ip=$(dig +short "$host" 2>/dev/null | head -n1)
      SHODAN_DONE=$((SHODAN_DONE + 1))
      [ -z "$ip" ] && continue
      curl -s --max-time 5 "https://internetdb.shodan.io/$ip" >> shodan/internetdb_results.json 2>>"$LOGFILE" || true
      echo "" >> shodan/internetdb_results.json
      # Progress every 25 hosts so a large run doesn't look stuck with no output.
      if [ $((SHODAN_DONE % 25)) -eq 0 ]; then
        log "Phase 7: $SHODAN_DONE host(s) checked so far..."
      fi
    done < "$SHODAN_INPUT"
    rm -f shodan/.capped_hosts.txt
    ok "Shodan InternetDB lookups saved to shodan/internetdb_results.json (free tier, no key needed)"
  else
    warn "curl or dig not available, skipping Shodan InternetDB lookup"
  fi
fi

# ========================================================================
# PHASE 8: ASN / IP Range Discovery (optional)
# ========================================================================
if [ "$ASN_SCAN" = true ]; then
  log "Phase 8: ASN / IP range discovery"
  if have asnmap; then
    # asnmap needs a one-time ProjectDiscovery Cloud auth (run `asnmap -auth` once
    # and log in). Without it, asnmap prompts interactively for an API key and
    # will hang the whole script waiting on stdin — redirect stdin from
    # /dev/null so it fails fast instead of blocking.
    asnmap -d "$DOMAIN" -silent -o asn/ranges.txt < /dev/null 2>>"$LOGFILE" || true
    ASN_COUNT=$(countf asn/ranges.txt)
    if [ "$ASN_COUNT" -eq 0 ]; then
      warn "ASN lookup returned nothing — run 'asnmap -auth' once to log in to ProjectDiscovery Cloud, then retry"
    else
      ok "ASN ranges: $ASN_COUNT (review before scanning — often broader than bounty scope)"
    fi
  else
    warn "asnmap not installed, skipping ASN discovery"
  fi
fi

# ========================================================================
# PHASE 9: HTTP Probing
# ========================================================================
# Runs BEFORE port scanning on purpose: naabu's active port scan can trip a
# target's WAF/rate-limiter, which can then cause the very next phase's
# requests to fail — we saw this exact pattern (port scan -> 0 live hosts
# right after, on a host confirmed live moments earlier). Capturing live
# hosts first means that data survives even if the port scan upsets the WAF.
log "Phase 9: HTTP(S) probing with $HTTPX_BIN"
"$HTTPX_BIN" -l "$RESOLVED_FILE" -silent -status-code -title -tech-detect -follow-redirects \
  -threads "$THREADS" -o http/live_hosts.txt
LIVE_COUNT=$(countf http/live_hosts.txt)
ok "Live HTTP(S) hosts: $LIVE_COUNT"
awk '{print $1}' http/live_hosts.txt > http/live_urls.txt
if [ ! -s http/live_urls.txt ]; then
  warn "No live HTTP(S) hosts found. This can be a transient network/WAF issue rather"
  warn "than a real result — all subdomain/DNS work so far is still saved. Host-dependent"
  warn "modules below will have nothing to scan and will show 0, but the run continues"
  warn "so you get a summary instead of losing everything. Consider re-running if this"
  warn "looks wrong (check logs/recon.log for connectivity errors from this run)."
fi

# ========================================================================
# PHASE 10: Port Scanning (optional)
# ========================================================================
if [ "$PORTSCAN" = true ]; then
  log "Phase 10: Port scanning with naabu"
  if have naabu; then
    # naabu's default SYN scan needs raw-socket access (root). Running
    # unprivileged silently returns 0 results with no error — use CONNECT
    # scan instead, which works fine without root (slightly slower, but reliable).
    if [ "$(id -u)" -eq 0 ]; then
      naabu -l "$RESOLVED_FILE" -silent -rate "$NUCLEI_RATE_LIMIT" -o ports/open_ports.txt 2>>"$LOGFILE" || true
    else
      warn "Not running as root — naabu would silently find 0 ports with its default SYN scan. Using -scan-type connect instead."
      naabu -l "$RESOLVED_FILE" -scan-type connect -silent -rate "$NUCLEI_RATE_LIMIT" -o ports/open_ports.txt 2>>"$LOGFILE" || true
    fi
    ok "Open ports found: $(countf ports/open_ports.txt)"
  else
    warn "naabu not installed, skipping port scan"
  fi
fi

# ========================================================================
# PHASE 11: Subdomain Takeover Check (optional)
# ========================================================================
if [ "$TAKEOVER" = true ]; then
  log "Phase 11: Subdomain takeover check"
  if have subzy; then
    subzy run --targets final/resolved.txt --output vulns/takeover_subzy.txt 2>>"$LOGFILE" || true
  else
    warn "subzy not installed, skipping subzy pass"
  fi
  if have nuclei; then
    nuclei -l http/live_urls.txt -tags takeover -silent -o vulns/takeover_nuclei.txt 2>>"$LOGFILE" || true
    TAKEOVER_COUNT=$(countf vulns/takeover_nuclei.txt)
    [ "$TAKEOVER_COUNT" -gt 0 ] && warn "POSSIBLE TAKEOVER(S): $TAKEOVER_COUNT — see vulns/takeover_nuclei.txt" || ok "No takeover indicators found"
  fi
fi

# ========================================================================
# PHASE 12: WAF/CDN Detection (optional)
# ========================================================================
if [ "$WAF_CHECK" = true ]; then
  log "Phase 12: WAF/CDN fingerprinting"
  if have wafw00f; then
    while read -r url; do
      wafw00f "$url" >> waf/waf_results.txt 2>>"$LOGFILE"
    done < <(cap_list http/live_urls.txt 200 "Phase WAF check")
    ok "WAF detection results saved to waf/waf_results.txt"
  else
    warn "wafw00f not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 13: Favicon Fingerprinting (optional)
# ========================================================================
if [ "$FAVICON_SCAN" = true ]; then
  log "Phase 13: Favicon-hash fingerprinting"
  if have favfreak; then
    # favfreak takes URLs on stdin, not a -f flag, and -o is an output *prefix*
    # (it writes <prefix>_<hash>.txt files), not a directory.
    cat http/live_urls.txt | favfreak -o favicon/results 2>>"$LOGFILE" || true
    ok "Favicon fingerprints saved to favicon/"
  else
    warn "favfreak not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 14: Crawling + Historical URL Discovery (optional)
# ========================================================================
if [ "$CRAWL" = true ]; then
  log "Phase 14: Crawling + historical URL discovery"
  if have katana; then
    katana -list http/live_urls.txt -silent -jc -o urls/katana.txt 2>>"$LOGFILE" || true
  else
    warn "katana not installed, skipping active crawl"
  fi
  if have gospider; then
    gospider -S http/live_urls.txt -o urls/gospider_raw -q 2>>"$LOGFILE" || true
    cat urls/gospider_raw/*.txt 2>/dev/null | grep -oE 'https?://[^ ]+' | sort -u > urls/gospider.txt || true
  else
    warn "gospider not installed, skipping"
  fi
  if have hakrawler; then
    cat http/live_urls.txt | hakrawler -d 2 2>>"$LOGFILE" > urls/hakrawler.txt || true
  else
    warn "hakrawler not installed, skipping"
  fi
  if have gau; then
    # One gau process per subdomain, sequential — on a target with thousands
    # of subdomains (we've seen 3000+ on a real run) this is the same class
    # of multi-hour slowdown fixed elsewhere in this phase for other tools.
    while read -r d; do gau --subs "$d" 2>>"$LOGFILE"; done < <(cap_list final/all_subs.txt 300 "Phase gau historical URLs") > urls/gau.txt
  else
    warn "gau not installed, skipping"
  fi
  if have waybackurls; then
    # waybackurls queries the Wayback Machine per-subdomain internally even
    # though it takes the whole list on stdin in one process — same cap
    # applied for the same reason as gau above.
    cap_list final/all_subs.txt 300 "Phase waybackurls" | waybackurls > urls/wayback.txt 2>>"$LOGFILE" || true
  else
    warn "waybackurls not installed, skipping"
  fi
  cat urls/*.txt 2>/dev/null | sort -u > urls/all_urls.txt
  ok "Total discovered URLs: $(countf urls/all_urls.txt)"
fi

# ========================================================================
# PHASE 15: Hidden Parameter Discovery (optional, --params)
# ========================================================================
if [ "$PARAM_DISCOVERY" = true ]; then
  log "Phase 15: Hidden parameter discovery"
  if have arjun; then
    while read -r url; do
      name=$(echo "$url" | sed 's#[^a-zA-Z0-9]#_#g')
      arjun -u "$url" -oT "params/arjun_${name}.txt" -q 2>>"$LOGFILE" || true
    done < <(cap_list http/live_urls.txt 150 "Phase Arjun parameter discovery")
    ok "Arjun parameter discovery complete, see params/"
  else
    warn "arjun not installed, skipping"
  fi
  if have paramspider; then
    # paramspider has no -o flag — it writes to its own ./results/<domain>.txt by default.
    # Run it, then move whatever it produced into our own output folder.
    while read -r d; do
      ( cd params && paramspider -d "$d" >> "../logs/recon.log" 2>&1 ) || true
    done < <(cap_list final/all_subs.txt 200 "Phase ParamSpider")
    [ -d params/results ] && mv params/results/* params/ 2>/dev/null && rmdir params/results 2>/dev/null
    ok "ParamSpider discovery complete, see params/"
  else
    warn "paramspider not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 16: API Route/Endpoint Bruteforce (optional, --api)
# ========================================================================
if [ "$API_SCAN" = true ]; then
  log "Phase 16: API route bruteforce"
  # kiterunner's real binary is 'kr', not 'kiterunner'. It needs a compiled
  # .kite wordlist (not plain text) — if the user passed one via --api <file>,
  # use it with -w; otherwise fall back to kiterunner's own hosted Assetnote
  # wordlist (-A), which needs no local file at all.
  if have kr; then
    # Each call tests up to 20,000 routes against ONE host — by far the
    # heaviest per-host tool in the pipeline, so it gets the tightest cap.
    while read -r url; do
      name=$(echo "$url" | sed 's#[^a-zA-Z0-9]#_#g')
      if [ -n "$API_WORDLIST" ] && [ -f "$API_WORDLIST" ]; then
        kr scan "$url" -w "$API_WORDLIST" --output json 2>>"$LOGFILE" > "api/kiterunner_${name}.json" || true
      else
        kr scan "$url" -A=apiroutes-210228:20000 --output json 2>>"$LOGFILE" > "api/kiterunner_${name}.json" || true
      fi
    done < <(cap_list http/live_urls.txt 40 "Phase kiterunner (up to 20k routes PER host)")
    ok "kiterunner API route scan complete, see api/"
  else
    warn "kr (kiterunner) not installed, skipping API bruteforce"
  fi
fi

# ========================================================================
# PHASE 17: Directory/File Brute-forcing (optional)
# ========================================================================
if [ -n "$FFUF_WORDLIST" ]; then
  log "Phase 17: Directory brute-forcing with ffuf"
  if have ffuf && [ -f "$FFUF_WORDLIST" ]; then
    mkdir -p urls/ffuf
    while read -r url; do
      name=$(echo "$url" | sed 's#[^a-zA-Z0-9]#_#g')
      ffuf -u "${url}/FUZZ" -w "$FFUF_WORDLIST" -mc 200,204,301,302,307,401,403 \
        -silent -o "urls/ffuf/${name}.json" -of json 2>>"$LOGFILE" || true
    done < <(cap_list http/live_urls.txt 100 "Phase ffuf directory brute-force")
    ok "ffuf results saved to urls/ffuf/"
  else
    warn "ffuf not installed or wordlist missing, skipping brute-force"
  fi
fi

# ========================================================================
# PHASE 18: JS Collection + Secrets Scanning (optional)
# ========================================================================
if [ "$JS_SCAN" = true ]; then
  log "Phase 18: JS file collection + secrets scanning"
  if have subjs; then
    cat http/live_urls.txt | subjs > js/js_files.txt 2>>"$LOGFILE" || true
    ok "JS files collected: $(countf js/js_files.txt)"
  else
    warn "subjs not installed, skipping JS collection"
  fi
  if [ -s js/js_files.txt ]; then
    if have trufflehog; then
      trufflehog filesystem --directory=js/ --json > js/secrets_trufflehog.json 2>>"$LOGFILE" || true
    elif have gitleaks; then
      gitleaks detect --no-git --source=js/ --report-path=js/secrets_gitleaks.json 2>>"$LOGFILE" || true
    else
      warn "Neither trufflehog nor gitleaks installed, skipping JS secrets scan"
    fi
    if have linkfinder; then
      while read -r jsurl; do
        name=$(echo "$jsurl" | sed 's#[^a-zA-Z0-9]#_#g')
        linkfinder -i "$jsurl" -o cli 2>>"$LOGFILE" >> "js/linkfinder_${name}.txt" || true
      done < <(cap_list js/js_files.txt 300 "Phase LinkFinder")
      ok "LinkFinder endpoint extraction complete, see js/linkfinder_*.txt"
    else
      warn "linkfinder not installed, skipping JS endpoint extraction"
    fi
    if have secretfinder; then
      while read -r jsurl; do
        name=$(echo "$jsurl" | sed 's#[^a-zA-Z0-9]#_#g')
        secretfinder -i "$jsurl" -o cli 2>>"$LOGFILE" >> "js/secretfinder_${name}.txt" || true
      done < <(cap_list js/js_files.txt 300 "Phase SecretFinder")
      ok "SecretFinder scan complete, see js/secretfinder_*.txt"
    else
      warn "secretfinder not installed, skipping"
    fi
  fi
fi

# ========================================================================
# PHASE 19: Reflected/DOM XSS Scan (optional, --xss)
# ========================================================================
if [ "$XSS_SCAN" = true ]; then
  log "Phase 19: XSS scan on parameterized URLs"
  if have dalfox; then
    PARAM_URLS="xss/param_urls.txt"
    grep -E '\?.+=' urls/all_urls.txt 2>/dev/null | sort -u > "$PARAM_URLS" || touch "$PARAM_URLS"
    if [ -s "$PARAM_URLS" ]; then
      # A large crawl can turn up hundreds of parameterized URLs, and dalfox
      # tries multiple payloads per URL — uncapped, this can run for many
      # minutes with no progress output (we saw 11+ min on a real target).
      cap_list "$PARAM_URLS" 150 "Phase XSS" > xss/.capped_param_urls.txt
      dalfox file xss/.capped_param_urls.txt --silence --timeout 8 -o xss/dalfox_results.txt 2>>"$LOGFILE" || true
      rm -f xss/.capped_param_urls.txt
      XSS_COUNT=$(countf xss/dalfox_results.txt)
      [ "$XSS_COUNT" -gt 0 ] && warn "Possible XSS finding(s): $XSS_COUNT — see xss/dalfox_results.txt" || ok "No XSS indicators found"
    else
      warn "No parameterized URLs found (run --crawl first) — skipping XSS scan"
    fi
  else
    warn "dalfox not installed, skipping XSS scan"
  fi
fi

# ========================================================================
# PHASE 20: SQLi Detection Scan (opt-in only, --sqli)
# ========================================================================
if [ "$SQLI_SCAN" = true ]; then
  log "Phase 20: SQLi detection scan (level=$SQLI_LEVEL, risk=$SQLI_RISK — detection only)"
  warn "sqlmap sends extra probing requests to every parameterized URL. Make sure your program explicitly allows automated SQLi testing before this runs."
  if have sqlmap; then
    PARAM_URLS_SQLI="sqli/param_urls.txt"
    grep -E '\?.+=' urls/all_urls.txt 2>/dev/null | sort -u > "$PARAM_URLS_SQLI" || touch "$PARAM_URLS_SQLI"
    if [ -s "$PARAM_URLS_SQLI" ]; then
      # sqlmap tests several injection techniques per parameter and does NOT
      # parallelize a -m targets file itself — uncapped, this is easily the
      # slowest phase in the whole pipeline on a real crawl (same class of
      # issue fixed for XSS/dalfox above, but sqlmap has no per-run timeout
      # flag as reliable as dalfox's, so capping the input is the real fix).
      cap_list "$PARAM_URLS_SQLI" 50 "Phase SQLi (sqlmap tests multiple techniques per URL)" > sqli/.capped_param_urls.txt
      sqlmap -m sqli/.capped_param_urls.txt --batch --level="$SQLI_LEVEL" --risk="$SQLI_RISK" \
        --random-agent --output-dir=sqli/ 2>>"$LOGFILE" || true
      rm -f sqli/.capped_param_urls.txt
      ok "sqlmap detection pass complete, see sqli/ for any findings"
    else
      warn "No parameterized URLs found (run --crawl first) — skipping SQLi scan"
    fi
  else
    warn "sqlmap not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 21: Out-of-Band Blind Vulnerability Probing (optional, --interactsh)
# ========================================================================
# Catches bugs that never show up in an HTTP response: blind SSRF, blind XXE,
# blind SSTI, blind command/code injection. Nuclei and dalfox only catch
# vulnerabilities that reflect something back — this is the gap they leave.
if [ "$INTERACTSH_SCAN" = true ]; then
  log "Phase 21: Out-of-band blind vulnerability probing (interactsh)"
  if have interactsh-client; then
    interactsh-client -json -o interactsh/interactions.json > interactsh/client.log 2>>"$LOGFILE" &
    INTERACTSH_PID=$!
    BG_PIDS+=("$INTERACTSH_PID")
    sleep 5
    # interactsh-client prints its generated interaction domain in its startup
    # banner (e.g. "https://abcd1234.oast.fun") — pull it from the log.
    OAST_URL=$(grep -oE 'https?://[a-z0-9]+\.oast\.[a-z]+' interactsh/client.log 2>/dev/null | head -n1)
    OAST_DOMAIN="${OAST_URL#http://}"; OAST_DOMAIN="${OAST_DOMAIN#https://}"
    if [ -z "$OAST_DOMAIN" ]; then
      warn "Could not get an interactsh domain (check interactsh/client.log) — skipping probes"
      kill -TERM "$INTERACTSH_PID" 2>/dev/null
    else
      ok "Interactsh domain: $OAST_DOMAIN — sending probes"
      # Common SSRF/XXE/SSTI-prone parameter names, probed with the OOB domain
      # as the value. A later interaction logged against this domain means the
      # target's backend reached out to us — strong, hard-to-miss-with-noise
      # evidence of a blind vulnerability, even with zero visible response.
      PARAM_URLS_OOB="interactsh/param_urls.txt"
      grep -E '\?.+=' urls/all_urls.txt 2>/dev/null | sort -u > "$PARAM_URLS_OOB" || touch "$PARAM_URLS_OOB"
      if [ -s "$PARAM_URLS_OOB" ]; then
        while read -r url; do
          base="${url%%\?*}"; qs="${url#*\?}"
          newqs=$(echo "$qs" | sed -E "s/(url|uri|redirect|callback|feed|src|dest|continue|next|path|file|image|avatar|webhook)=[^&]*/\1=http:\/\/${OAST_DOMAIN}/gi")
          curl -s -o /dev/null --max-time 5 "${base}?${newqs}" 2>>"$LOGFILE" &
        done < <(cap_list "$PARAM_URLS_OOB" 300 "Phase OOB param probing")
        wait
      fi
      # Header-based blind SSRF is just as common (X-Forwarded-For / X-Forwarded-Host
      # / Referer are frequently trusted and fetched server-side for logging,
      # previews, or internal routing).
      while read -r url; do
        curl -s -o /dev/null --max-time 5 \
          -H "X-Forwarded-For: ${OAST_DOMAIN}" \
          -H "X-Forwarded-Host: ${OAST_DOMAIN}" \
          -H "Referer: http://${OAST_DOMAIN}/" \
          "$url" 2>>"$LOGFILE" &
      done < <(cap_list http/live_urls.txt 300 "Phase OOB header probing")
      wait
      log "Probes sent, waiting 20s for any out-of-band interactions..."
      sleep 20
      kill -TERM "$INTERACTSH_PID" 2>/dev/null
      sleep 1
      OOB_HITS=$(countf interactsh/interactions.json)
      if [ "$OOB_HITS" -gt 0 ]; then
        warn "POSSIBLE BLIND VULN: $OOB_HITS out-of-band interaction(s) received — see interactsh/interactions.json"
        warn "Match the interaction timestamp against the probes above to find which URL/header triggered it."
      else
        ok "No out-of-band interactions received"
      fi
    fi
  else
    warn "interactsh-client not installed, skipping OOB probing"
  fi
fi

# ========================================================================
# PHASE 22: Broken Access Control / IDOR Candidates (optional, --idor)
# ========================================================================
if [ "$IDOR_SCAN" = true ]; then
  log "Phase 22: IDOR and access-control candidate scanning"
  # Pull every URL containing a numeric ID or a UUID — the classic IDOR shape:
  # path-based (/api/users/482), query-param-based (?user_id=482, &id=1001 —
  # the single most common IDOR pattern, easy to miss with a path-only regex),
  # or a UUID (/invoices/9f1b...-uuid).
  grep -E '/[0-9]{2,}([/?]|$)|[?&][A-Za-z_]+=[0-9]{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    urls/all_urls.txt 2>/dev/null | sort -u > idor/id_candidates.txt || touch idor/id_candidates.txt

  if [ -n "$IDOR_SESSION_A" ] && [ -n "$IDOR_SESSION_B" ] && [ -f "$IDOR_SESSION_A" ] && [ -f "$IDOR_SESSION_B" ]; then
    # Session-diff mode: the real test for broken access control. Fetch every
    # candidate URL as BOTH accounts and flag where responses look the same
    # (same status + similar length) — that's account A seeing account B's
    # (or an arbitrary ID's) data.
    ok "Session-diff mode: comparing account A vs account B on each candidate URL"
    HDRS_A=(); while read -r h; do HDRS_A+=(-H "$h"); done < "$IDOR_SESSION_A"
    HDRS_B=(); while read -r h; do HDRS_B+=(-H "$h"); done < "$IDOR_SESSION_B"
    : > idor/session_diff_results.txt
    while read -r url; do
      (
        resp_a=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 5 "${HDRS_A[@]}" "$url" 2>/dev/null)
        resp_b=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 5 "${HDRS_B[@]}" "$url" 2>/dev/null)
        echo "$url | A: $resp_a | B: $resp_b" >> idor/session_diff_results.txt
        if [ "$resp_a" = "$resp_b" ] && [ -n "$resp_a" ]; then
          echo "$url | IDENTICAL response for both accounts (A: $resp_a, B: $resp_b)" >> idor/flagged_identical.txt
        fi
      ) &
    done < <(cap_list idor/id_candidates.txt 200 "Phase IDOR session-diff (2 requests per URL)")
    wait
    FLAGGED=$(countf idor/flagged_identical.txt)
    [ "$FLAGGED" -gt 0 ] && warn "$FLAGGED URL(s) gave identical responses to both accounts — see idor/flagged_identical.txt" \
      || ok "No identical-response candidates found"
  else
    # Static heuristic mode (no credentials supplied): mutate each numeric ID
    # up/down by 1 and diff the response against the original — not proof of
    # IDOR by itself (no auth context), but narrows thousands of URLs down to
    # a short, concrete list worth testing by hand with a second account.
    ok "Static heuristic mode (no --idor-session-a/-b given): mutating IDs and diffing responses"
    : > idor/mutation_results.txt
    # Each URL's check runs in the background (like the OOB probing phase) —
    # sequential 2-requests-per-URL with an 8s timeout each was the slowest
    # part of a real run (100 candidates could take 25+ minutes). Backgrounded,
    # the whole capped batch finishes in roughly one request's time instead.
    while read -r url; do
      (
        # UUIDs can't be sensibly "incremented" — flag them directly for manual
        # testing instead of trying (and failing) to do arithmetic on a digit
        # run embedded inside one.
        if echo "$url" | grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
          echo "$url | UUID-based ID — can't auto-mutate, test manually with a second account" >> idor/flagged_candidates.txt
          exit 0
        fi
        id=$(echo "$url" | grep -oE '[0-9]{2,}' | tail -n1)
        [ -z "$id" ] && exit 0
        # 10#$id forces base-10 parsing — without it, an ID with a leading zero
        # (e.g. 042) is misread as octal by bash arithmetic and can crash on
        # digits like 8/9 that aren't valid octal ("value too great for base").
        mutated=$((10#$id + 1))
        murl="${url/$id/$mutated}"
        orig=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 5 "$url" 2>/dev/null)
        mut=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 5 "$murl" 2>/dev/null)
        echo "$url | orig: $orig | +1: $mut ($murl)" >> idor/mutation_results.txt
        if [ "$orig" = "$mut" ] && [ -n "$orig" ] && [[ "$orig" == 200* ]]; then
          echo "$url -> $murl | both return $orig — worth testing by hand" >> idor/flagged_candidates.txt
        fi
      ) &
    done < <(cap_list idor/id_candidates.txt 100 "Phase IDOR static heuristic (2 requests per URL)")
    wait
    FLAGGED=$(countf idor/flagged_candidates.txt)
    [ "$FLAGGED" -gt 0 ] && warn "$FLAGGED candidate(s) flagged — see idor/flagged_candidates.txt (manual verification required)" \
      || ok "No obvious candidates found in the static heuristic pass"
  fi
fi

# ========================================================================
# PHASE 23: JWT Detection + Weak Signing Check (optional, --jwt)
# ========================================================================
if [ "$JWT_SCAN" = true ]; then
  log "Phase 23: JWT detection and weak-signing check"
  if have python3; then
    : > jwt/found_tokens.txt
    # Pull candidate response bodies: live host responses + any downloaded JS.
    while read -r url; do
      curl -s --max-time 8 "$url" 2>>"$LOGFILE"
    done < <(cap_list http/live_urls.txt 300 "Phase JWT body fetch") > jwt/.bodies.tmp 2>/dev/null || true
    cat js/js_files.txt 2>/dev/null | while read -r jsurl; do curl -s --max-time 8 "$jsurl" 2>>"$LOGFILE"; done >> jwt/.bodies.tmp 2>/dev/null || true
    # Signature segment uses '*' not '+': alg:none tokens (the highest-value
    # case here) often have an EMPTY signature — a '+' would miss exactly them.
    grep -oE 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' jwt/.bodies.tmp 2>/dev/null | sort -u > jwt/found_tokens.txt || true
    rm -f jwt/.bodies.tmp
    TOKEN_COUNT=$(countf jwt/found_tokens.txt)
    if [ "$TOKEN_COUNT" -gt 0 ]; then
      ok "$TOKEN_COUNT JWT(s) found — decoding headers for weak-signing indicators"
      python3 - jwt/found_tokens.txt jwt/decoded_report.txt <<'PYEOF'
import sys, base64, json
inp, outp = sys.argv[1], sys.argv[2]
def b64(s):
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return None
with open(inp) as f, open(outp, "w") as out:
    for line in f:
        tok = line.strip()
        if not tok:
            continue
        parts = tok.split(".")
        if len(parts) < 2:
            continue
        hdr = b64(parts[0])
        if hdr is None:
            continue
        alg = str(hdr.get("alg", "")).lower()
        flag = ""
        if alg == "none":
            flag = "  <-- CRITICAL: alg=none, signature not verified if the server accepts this"
        elif alg.startswith("hs"):
            flag = "  <-- symmetric alg (HS*): check for algorithm-confusion if an RS*/ES* public key is discoverable"
        out.write(f"{tok[:40]}... | alg={hdr.get('alg')} | {json.dumps(hdr)}{flag}\n")
PYEOF
      NONE_ALG=$(grep -c "alg=none" jwt/decoded_report.txt 2>/dev/null || echo 0)
      [ "$NONE_ALG" -gt 0 ] && warn "CRITICAL: $NONE_ALG token(s) with alg=none — see jwt/decoded_report.txt" \
        || ok "No alg=none tokens found — see jwt/decoded_report.txt for full breakdown"
    else
      ok "No JWTs found in sampled responses/JS"
    fi
  else
    warn "python3 not available, skipping JWT decode"
  fi
fi

# ========================================================================
# PHASE 24: GraphQL Endpoint Discovery + Introspection (optional, --graphql)
# ========================================================================
if [ "$GRAPHQL_SCAN" = true ]; then
  log "Phase 24: endpoint discovery and introspection check"
  INTROSPECTION_QUERY='{"query":"{__schema{queryType{name}}}"}'
  : > graphql/endpoints_found.txt
  while read -r url; do
    for path in /graphql /api/graphql /v1/graphql /graphql/v1 /query /api/query; do
      resp=$(curl -s --max-time 6 -X POST -H "Content-Type: application/json" -d "$INTROSPECTION_QUERY" "${url}${path}" 2>>"$LOGFILE")
      if echo "$resp" | grep -q "queryType"; then
        echo "${url}${path}" >> graphql/endpoints_found.txt
        name=$(echo "${url}${path}" | sed 's#[^a-zA-Z0-9]#_#g')
        curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
          -d '{"query":"query IntrospectionQuery { __schema { types { name fields { name } } } } "}' \
          "${url}${path}" > "graphql/schema_${name}.json" 2>>"$LOGFILE" || true
      fi
    done
  done < <(cap_list http/live_urls.txt 150 "Phase GraphQL (6 paths tried per host)")
  GQL_COUNT=$(countf graphql/endpoints_found.txt)
  if [ "$GQL_COUNT" -gt 0 ]; then
    warn "$GQL_COUNT GraphQL endpoint(s) with introspection ENABLED — full schema may be leaked, see graphql/"
  else
    ok "No GraphQL endpoints with open introspection found"
  fi
fi

# ========================================================================
# PHASE 25: Cloud Storage Enumeration (optional)
# ========================================================================
if [ "$CLOUD_SCAN" = true ]; then
  log "Phase 25: Cloud storage bucket enumeration"
  if have cloud_enum; then
    cloud_enum -k "$DOMAIN" --disable-azure --disable-gcp -l cloud/cloud_enum.txt 2>>"$LOGFILE" || true
  elif have s3scanner; then
    # Real binary is lowercase 's3scanner', no 'scan' subcommand, and the flag
    # is single-dash '-bucket-file' (Go-style flags), not '--bucket-file'.
    # Capped for the same reason as gau/waybackurls above — this tries every
    # line as a bucket name candidate against AWS, which is slow and risks
    # rate-limiting with thousands of candidates.
    cap_list final/all_subs.txt 500 "Phase s3scanner" > cloud/.capped_bucket_names.txt
    s3scanner -bucket-file cloud/.capped_bucket_names.txt -json > cloud/s3_results.json 2>>"$LOGFILE" || true
    rm -f cloud/.capped_bucket_names.txt
  else
    warn "No cloud enumeration tool installed (cloud_enum / s3scanner), skipping"
  fi
  ok "Cloud enumeration pass complete (review cloud/ for results)"
fi

# ========================================================================
# PHASE 26: GitHub Leak Scanning (optional)
# ========================================================================
if [ "$GITHUB_SCAN" = true ]; then
  log "Phase 26: GitHub leak scanning"
  if have trufflehog; then
    trufflehog github --org="$DOMAIN" --json > github/github_secrets.json 2>>"$LOGFILE" || \
      warn "trufflehog GitHub scan needs GITHUB_TOKEN env var and an org/user match — check manually"
  else
    warn "trufflehog not installed, skipping GitHub secrets scan"
  fi
  ok "GitHub scan pass complete (review github/ for results)"
fi

# ========================================================================
# PHASE 27: CORS Misconfiguration Scan (optional)
# ========================================================================
if [ "$CORS_SCAN" = true ]; then
  log "Phase 27: CORS misconfiguration scan"
  if have corsy || have Corsy; then
    CORSY_BIN=$(have corsy && echo corsy || echo Corsy)
    "$CORSY_BIN" -i http/live_urls.txt -o cors/cors_results.json 2>>"$LOGFILE" || true
    ok "CORS scan complete, see cors/cors_results.json"
  else
    warn "Corsy not installed, skipping CORS scan"
  fi
fi

# ========================================================================
# PHASE 28: Diff Against Previous Run (new subdomain monitoring)
# ========================================================================
log "Phase 28: Diff against previous run"
mkdir -p "../$HISTORY_DIR"
PREV_FILE="../$HISTORY_DIR/${DOMAIN}_last_subs.txt"
if [ -f "$PREV_FILE" ]; then
  comm -13 <(sort "$PREV_FILE") <(sort final/all_subs.txt) > final/new_subs.txt
  NEW_COUNT=$(wc -l < final/new_subs.txt)
  [ "$NEW_COUNT" -gt 0 ] && warn "$NEW_COUNT NEW subdomain(s) since last run — final/new_subs.txt" || ok "No new subdomains since last run"
else
  log "No previous run found — this becomes the baseline"
  cp final/all_subs.txt final/new_subs.txt
fi
cp final/all_subs.txt "$PREV_FILE"

# ========================================================================
# PHASE 29: Screenshots (optional)
# ========================================================================
if [ "$SCREENSHOTS" = true ]; then
  log "Phase 29: Screenshots with gowitness"
  if have gowitness; then
    gowitness file -f http/live_urls.txt -P http/screenshots/ --no-http 2>>"$LOGFILE" || \
      gowitness scan file -f http/live_urls.txt -P http/screenshots/ 2>>"$LOGFILE" || true
    ok "Screenshots saved to http/screenshots/"
  else
    warn "gowitness not installed, skipping screenshots"
  fi
fi

# ========================================================================
# PHASE 30: Vulnerability Scanning (nuclei)
# ========================================================================
log "Phase 30: Nuclei scan (severity: $SEVERITIES, rate-limit: $NUCLEI_RATE_LIMIT req/s)"
nuclei -l http/live_urls.txt -s "$SEVERITIES" -rl "$NUCLEI_RATE_LIMIT" -c 25 -silent \
  -o vulns/nuclei_results.txt -je vulns/nuclei_results.json
FINDINGS=$(countf vulns/nuclei_results.txt)
ok "Nuclei findings: $FINDINGS"

# ========================================================================
# PHASE 31: Correlation Layer (on by default, --no-correlate to skip)
# ========================================================================
# This is where recon stops being "wide" and starts being "smart": instead of
# leaving you to manually cross-reference a dozen output folders, connect
# findings that are related by host/subdomain, and turn detected tech +
# versions into an actionable CVE shortlist rather than raw banner strings.
if [ "$CORRELATE" = true ]; then
  log "Phase 31: Correlating findings across modules"
  if have python3; then
    CORR_COUNT=$(python3 - <<'PYEOF'
import re, json, glob, os

report = []

# --- 1. JS secrets <-> API routes, correlated by host ---
def host_of(url):
    m = re.search(r'https?://([^/]+)', url)
    return m.group(1) if m else url

secret_files = glob.glob("js/secretfinder_*.txt") + glob.glob("js/secrets_*.json")
api_routes = []
for f in glob.glob("api/kiterunner_*.json") + ["urls/all_urls.txt"]:
    if os.path.exists(f):
        with open(f, errors="ignore") as fh:
            api_routes += [l.strip() for l in fh if "/api/" in l or "/v1/" in l or "/v2/" in l]

if secret_files and api_routes:
    api_hosts = {}
    for r in api_routes:
        h = host_of(r)
        api_hosts.setdefault(h, []).append(r)
    for sf in secret_files:
        # the mock/real filenames encode the source host, e.g. secretfinder_https___sub_example_com.txt
        base = os.path.basename(sf)
        for h, routes in api_hosts.items():
            h_safe = re.sub(r'[^a-zA-Z0-9]', '_', h)
            if h_safe and h_safe in base:
                report.append(f"## Possible secret <-> API correlation\n- Secret file: {sf}\n- API routes on the SAME host ({h}), worth checking if the secret grants access:\n"
                               + "\n".join(f"  - {r}" for r in routes[:10]) + "\n"
                               + "- NOTE: this only flags proximity (same host). It does NOT test the secret against "
                                 "these routes automatically — verify manually and only within your program's rules.\n")

# --- 2. Tech stack -> CVE shortlist candidates ---
tech_versions = []
if os.path.exists("http/live_hosts.txt"):
    with open("http/live_hosts.txt", errors="ignore") as f:
        for line in f:
            m = re.search(r'\[([^\]]*:[^\]]*)\]', line)
            if m:
                for item in m.group(1).split(","):
                    if ":" in item:
                        tech_versions.append(item.strip())

if tech_versions:
    report.append("## Detected tech with version numbers — check each against a CVE database\n"
                   + "(WPScan, NVD, or `cvemap -product <name> -version <version>` if installed)\n"
                   + "\n".join(f"- {t}" for t in sorted(set(tech_versions))) + "\n")

with open("intel/CORRELATION.md", "w") as f:
    f.write("# Correlation Report\n\n")
    if report:
        f.write("\n".join(report))
    else:
        f.write("No cross-module correlations found with the data available from this run.\n"
                "This improves with --jsscan, --api/--crawl, and --tech-detect (always on) enabled together.\n")
print(len(report))
PYEOF
)
    ok "Correlation report written to intel/CORRELATION.md (${CORR_COUNT:-0} item(s) found)"
  else
    warn "python3 not available, skipping correlation layer"
  fi
fi

# ========================================================================
# PHASE 32: SQLite Backend (on by default, --no-db to skip)
# ========================================================================
# A queryable, structured record of the run instead of 20 scattered text
# files — the foundation for historical tracking ("show me every new finding
# since last month") and for feeding your own dashboard/reporting tooling.
if [ "$DB_BACKEND" = true ]; then
  log "Phase 32: Building final/recon.db"
  if have sqlite3; then
    sqlite3 final/recon.db <<'SQLEOF'
CREATE TABLE IF NOT EXISTS subdomains (domain TEXT PRIMARY KEY, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS live_hosts (url TEXT PRIMARY KEY, raw_line TEXT, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS nuclei_findings (finding TEXT, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS jwt_tokens (token_prefix TEXT, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS graphql_endpoints (url TEXT PRIMARY KEY, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS idor_candidates (url TEXT, scanned_at TEXT DEFAULT CURRENT_TIMESTAMP);
SQLEOF
    # Batch every table's inserts into ONE sqlite3 invocation per table (wrapped
    # in a transaction), instead of spawning a new sqlite3 process per row —
    # with thousands of subdomains that per-row approach would take many
    # minutes and look exactly like the Phase 7 slowdown we fixed earlier.
    sql_escape() { printf '%s' "$1" | sed "s/'/''/g"; }
    run_batch() {
      # Reads SQL statements from stdin, wraps them in one transaction, and
      # runs the whole batch as a SINGLE sqlite3 invocation — not one process
      # per row, which would be minutes-slow on a few thousand subdomains.
      { echo "BEGIN TRANSACTION;"; cat; echo "COMMIT;"; } | sqlite3 final/recon.db 2>>"$LOGFILE" || true
    }

    if [ -s final/all_subs.txt ]; then
      while read -r d; do echo "INSERT OR IGNORE INTO subdomains (domain) VALUES ('$(sql_escape "$d")');"; done < final/all_subs.txt | run_batch
    fi
    if [ -s http/live_hosts.txt ]; then
      while IFS= read -r l; do u=$(echo "$l" | awk '{print $1}'); echo "INSERT OR IGNORE INTO live_hosts (url, raw_line) VALUES ('$(sql_escape "$u")', '$(sql_escape "$l")');"; done < http/live_hosts.txt | run_batch
    fi
    if [ -s vulns/nuclei_results.txt ]; then
      while IFS= read -r l; do echo "INSERT INTO nuclei_findings (finding) VALUES ('$(sql_escape "$l")');"; done < vulns/nuclei_results.txt | run_batch
    fi
    if [ -s jwt/found_tokens.txt ]; then
      while IFS= read -r t; do echo "INSERT INTO jwt_tokens (token_prefix) VALUES ('$(sql_escape "${t:0:40}")');"; done < jwt/found_tokens.txt | run_batch
    fi
    if [ -s graphql/endpoints_found.txt ]; then
      while IFS= read -r g; do echo "INSERT OR IGNORE INTO graphql_endpoints (url) VALUES ('$(sql_escape "$g")');"; done < graphql/endpoints_found.txt | run_batch
    fi
    if [ -s idor/flagged_candidates.txt ]; then
      while IFS= read -r i; do echo "INSERT INTO idor_candidates (url) VALUES ('$(sql_escape "$i")');"; done < idor/flagged_candidates.txt | run_batch
    fi
    ok "final/recon.db built — query it with: sqlite3 final/recon.db 'SELECT * FROM nuclei_findings;'"
  else
    warn "sqlite3 not installed, skipping DB backend (install: sudo apt install sqlite3)"
  fi
fi

# ========================================================================
# CLEANUP: Remove empty output folders
# ========================================================================
# mkdir -p creates every module's folder upfront regardless of which modules
# actually ran, so unused ones (e.g. sqli/ when --sqli was never passed) are
# left behind empty. Clean those up now that every phase has finished writing.
log "Cleaning up empty output folders"
EMPTIED=0
for i in 1 2; do
  while IFS= read -r d; do
    rmdir "$d" 2>/dev/null && EMPTIED=$((EMPTIED + 1))
  done < <(find . -mindepth 1 -type d -empty 2>/dev/null)
done
[ "$EMPTIED" -gt 0 ] && ok "Removed $EMPTIED empty folder(s)" || ok "No empty folders to remove"

# ========================================================================
# PHASE 33: Summary Report
# ========================================================================
log "Phase 33: Generating summary report"
SUMMARY="final/SUMMARY.md"
cat > "$SUMMARY" <<EOF
# Recon Summary — $DOMAIN
Generated: $(date '+%Y-%m-%d %H:%M:%S')

| Stage                          | Count |
|---------------------------------|-------|
| Raw enum hits                    | $TOTAL_RAW |
| Unique subdomains                 | $TOTAL_UNIQUE |
| In-scope subdomains               | $(wc -l < "$SUBS_FILE") |
| Resolved (live DNS)               | $(countf "$RESOLVED_FILE") |
| Live HTTP(S) hosts                | $LIVE_COUNT |
| New subdomains (vs last run)      | $(countf final/new_subs.txt) |
| Wildcard DNS detected             | $([ -s final/wildcard_ips.txt ] 2>/dev/null && echo "YES" || echo "No") |
| Bruteforce-found subdomains       | $(countf bruteforce/brute_resolved.txt) |
| Open ports found                  | $(countf ports/open_ports.txt) |
| Discovered URLs (crawl/history)   | $(countf urls/all_urls.txt) |
| Parameterized URLs (XSS/SQLi input)| $(countf xss/param_urls.txt) |
| JS files collected                | $(countf js/js_files.txt) |
| Takeover indicators               | $(countf vulns/takeover_nuclei.txt) |
| XSS indicators (dalfox)           | $(countf xss/dalfox_results.txt) |
| Out-of-band interactions (blind vulns) | $(countf interactsh/interactions.json) |
| IDOR candidates flagged           | $(countf idor/flagged_candidates.txt) |
| JWTs found                        | $(countf jwt/found_tokens.txt) |
| GraphQL endpoints (introspection open) | $(countf graphql/endpoints_found.txt) |
| Nuclei findings                   | $FINDINGS |

## Output structure
- raw/        — per-tool subdomain enum output (incl. amass, chaos)
- final/      — merged, scoped, resolved subdomains + diff + wildcard info + recon.db (SQLite)
- interactsh/ — out-of-band blind vulnerability probing results
- idor/       — IDOR / broken access control candidates
- jwt/        — JWT tokens found + weak-signing analysis
- graphql/    — GraphQL endpoints with open introspection + leaked schemas
- intel/      — CORRELATION.md: cross-module findings + tech-to-CVE shortlist
- bruteforce/ — active DNS bruteforce + permutation results
- shodan/     — Shodan InternetDB enrichment
- ports/      — naabu port scan results
- http/       — live hosts, tech stack, screenshots
- urls/       — crawled + historical URLs, ffuf results
- params/     — hidden parameter discovery (arjun, paramspider)
- api/        — kiterunner API route bruteforce results
- js/         — collected JS files, endpoints (linkfinder), secrets (secretfinder/trufflehog)
- xss/        — dalfox XSS scan results
- sqli/       — sqlmap detection-scan results (only if --sqli used)
- cloud/      — cloud bucket enumeration
- github/     — GitHub leak scan
- cors/       — CORS misconfig results
- waf/        — WAF/CDN fingerprinting
- asn/        — ASN / IP ranges
- favicon/    — favicon hash fingerprinting
- vulns/      — nuclei + takeover results
- logs/       — full run log
EOF
ok "Summary written to $SUMMARY"
cat "$SUMMARY"

# ---------- Notifications ----------
if [ "$NOTIFY" = true ]; then
  if have notify; then
    echo "Recon done: $DOMAIN — $FINDINGS nuclei findings, $LIVE_COUNT live hosts, $(countf final/new_subs.txt) new subs." | notify -silent
    ok "Notification sent via notify"
  else
    warn "notify tool not found, skipping"
  fi
fi

if [ -n "$WEBHOOK_URL" ]; then
  if have curl; then
    curl -s -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" \
      -d "{\"domain\":\"$DOMAIN\",\"live_hosts\":$LIVE_COUNT,\"findings\":$FINDINGS}" >/dev/null 2>>"$LOGFILE" || \
      warn "Webhook POST failed, check logs"
    ok "Webhook notified"
  fi
fi

ok "Recon complete. Results in: $(pwd)"
