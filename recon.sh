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
#   favfreak            - favicon-hash tech fingerprinting
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
BG_PIDS=()
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
# Concurrency for this script's OWN per-host while-loops (Shodan, wafw00f,
# arjun, linkfinder, secretfinder). Deliberately separate from THREADS, which
# is passed to tools that already manage their own internal concurrency —
# running those loops at THREADS=100 in parallel against one target's hosts
# is what causes rate-limit bans / API blocks, so this defaults much lower.
LOOP_CONCURRENCY=10
# How long any single Phase 1 enumeration tool (subfinder, sublist3r, etc.) is
# allowed to run before being killed. Phase 1 backgrounds several tools and
# then does a plain `wait` for all of them — with no timeout, one engine
# stuck on a slow/unreachable host (common on restricted networks, VPNs, or
# when an upstream API like crt.sh/DNSdumpster is down) blocks that `wait`
# indefinitely and the whole script looks frozen, even though every other
# tool already finished.
ENUM_TIMEOUT=240

# ---------- Colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()   { echo -e "${BLUE}[*]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
ok()    { echo -e "${GREEN}[+]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
warn()  { echo -e "${YELLOW}[!]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
err()   { echo -e "${RED}[-]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE" >&2; }
have()  { command -v "$1" >/dev/null 2>&1; }
countf() { [ -f "$1" ] && wc -l < "$1" || echo 0; }

# run_parallel <input_file> <label>
# Reads stdin from input_file and feeds each line into `xargs -P
# $LOOP_CONCURRENCY -I{}`, running the rest of the arguments as the command
# template (use {} where the line should be substituted). Logs start/end
# with item counts so long batches never look frozen. This replaces the old
# pattern — a bare `while read` loop, one item at a time, often with a fixed
# `sleep`, no timeout — which is what made Phase 7 look hung against 3000+
# hosts: serial + sleep 0.3s/host + no per-host timeout on dig/curl.
# run_parallel <input_file> <label> <bash_command_string using $1 for the item>
# $1 is the current line, so the string must use $1 (not {}); wrapping in
# bash -c means things like redirection (>>) and pipes inside the command
# string work correctly, unlike a bare `xargs -I{} cmd {}` which cannot
# redirect — xargs would otherwise pass '>>' as a literal argument to cmd.
run_parallel() {
  local input_file="$1" label="$2" cmd="$3"
  local total
  total=$(countf "$input_file")
  if [ "$total" -eq 0 ]; then
    warn "$label: no input items, skipping"
    return 0
  fi
  log "$label: processing $total item(s) at concurrency $LOOP_CONCURRENCY"
  xargs -a "$input_file" -P "$LOOP_CONCURRENCY" -I{} bash -c "$cmd" _ {} 2>>"$LOGFILE"
  ok "$label: done"
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
  -c,  --concurrency <n>     Parallel jobs for per-host loops: Shodan, wafw00f,
                              arjun, linkfinder, secretfinder (default: 10)
  --enum-timeout <seconds>   Max time per Phase 1 enum tool before it's killed
                              (default: 240) — stops one stuck engine (e.g. a
                              sublist3r search provider hanging on a slow/
                              unreachable host) from freezing the whole run
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
    -c|--concurrency) LOOP_CONCURRENCY="$2"; shift 2 ;;
    --enum-timeout) ENUM_TIMEOUT="$2"; shift 2 ;;
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
  # Note: --sqli and --bruteforce (needs a wordlist) are NEVER auto-enabled by --full.
  # Both are opt-in only — pass them explicitly if you want them.
fi

if [ -z "$DOMAIN" ] && [ -z "$DOMAIN_LIST" ]; then
  echo "Error: provide -d <domain> or -dL <domains_file>"
  usage
fi

# ---------- Sanitize domain input ----------
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
SCRIPT_START_EPOCH=$(date +%s)
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTDIR="${OUTDIR:-${DOMAIN}_${TIMESTAMP}}"
mkdir -p "$OUTDIR"/{raw,final,http,vulns,ports,urls,js,cloud,github,cors,waf,asn,favicon,logs,bruteforce,shodan,params,api,xss,sqli}
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
  if ! have "$tool"; then
    warn "Skipping $tool (not installed)"
    return 0
  fi
  # `timeout` kills the whole command (and whatever it execs into) after
  # $ENUM_TIMEOUT seconds. Without this, a single hung engine inside e.g.
  # sublist3r (which has no global timeout of its own) blocks Phase 1's
  # `wait` forever — every other tool can finish in seconds and the script
  # still looks "stuck" because it's waiting on that one PID. Exit code 124
  # is `timeout`'s specific signal for "I killed it", so we only warn in
  # that case rather than on every normal non-zero exit.
  timeout "$ENUM_TIMEOUT" "$@" < /dev/null
  local rc=$?
  if [ "$rc" -eq 124 ]; then
    warn "$tool timed out after ${ENUM_TIMEOUT}s — killed, continuing with results from other tools (raise with --enum-timeout if this target is just slow)"
  fi
  return 0
}

# ========================================================================
# PHASE 1: Subdomain Enumeration (passive, parallel)
# ========================================================================
log "Phase 1: Subdomain enumeration"
run_if_available subfinder subfinder -d "$DOMAIN" -all -recursive -t "$THREADS" -silent -o raw/subfinder.txt & BG_PIDS+=("$!")
run_if_available assetfinder bash -c "assetfinder -subs-only '$DOMAIN' > raw/assetfinder.txt" & BG_PIDS+=("$!")
run_if_available findomain findomain -t "$DOMAIN" -u raw/findomain.txt & BG_PIDS+=("$!")
# -e excludes dnsdumpster: its CSRF-token regex no longer matches DNSdumpster's
# current page, so that one engine always crashes with an IndexError (worker
# dies, prints a traceback) while contributing nothing. Everything else still runs.
run_if_available sublist3r sublist3r -d "$DOMAIN" -t 50 \
  -e "baidu,yahoo,google,bing,ask,netcraft,virustotal,threatcrowd,ssl,passivedns" \
  -o raw/sublist3r.txt & BG_PIDS+=("$!")
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

    cat > bruteforce/resolvers.txt <<'RESOLVERS'
1.1.1.1
8.8.8.8
8.8.4.4
9.9.9.9
1.0.0.1
RESOLVERS

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
      awk '{gsub(/\.$/, "", $1); print $1}' bruteforce/brute_resolved.txt \
        | grep -E "\.${DOMAIN//./\\.}$" >> final/all_subs.txt
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
    HOST_COUNT=$(countf "$RESOLVED_FILE")
    log "Resolving $HOST_COUNT host(s) to IPs first (this used to be the step that looked stuck)"
    : > shodan/resolved_ips.txt
    i=0
    while read -r host; do
      i=$((i + 1))
      [ $((i % 100)) -eq 0 ] && log "  DNS lookup progress: $i / $HOST_COUNT"
      dig +short +time=2 +tries=1 "$host" 2>/dev/null | head -n1
    done < "$RESOLVED_FILE" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > shodan/resolved_ips.txt
    IP_COUNT=$(countf shodan/resolved_ips.txt)
    ok "Deduplicated to $IP_COUNT unique IP(s) — querying Shodan InternetDB in parallel"
    : > shodan/internetdb_results.json
    run_parallel shodan/resolved_ips.txt "Shodan InternetDB lookup" \
      'curl -s -m 5 "https://internetdb.shodan.io/$1" >> shodan/internetdb_results.json; echo >> shodan/internetdb_results.json'
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
# PHASE 9: Port Scanning (optional)
# ========================================================================
if [ "$PORTSCAN" = true ]; then
  log "Phase 9: Port scanning with naabu"
  if have naabu; then
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
# PHASE 10: HTTP Probing
# ========================================================================
log "Phase 10: HTTP(S) probing with $HTTPX_BIN"
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
    : > waf/waf_results.txt
    run_parallel http/live_urls.txt "WAF/CDN fingerprinting" \
      'wafw00f "$1" >> waf/waf_results.txt 2>>'"$LOGFILE"
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
    while read -r d; do gau --subs "$d" 2>>"$LOGFILE"; done < final/all_subs.txt > urls/gau.txt
  else
    warn "gau not installed, skipping"
  fi
  if have waybackurls; then
    cat final/all_subs.txt | waybackurls > urls/wayback.txt 2>>"$LOGFILE" || true
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
    run_parallel http/live_urls.txt "Arjun parameter discovery" \
      'name=$(echo "$1" | sed "s#[^a-zA-Z0-9]#_#g"); arjun -u "$1" -oT "params/arjun_${name}.txt" -q >>'"$LOGFILE"' 2>&1'
    ok "Arjun parameter discovery complete, see params/"
  else
    warn "arjun not installed, skipping"
  fi
  if have paramspider; then
    while read -r d; do
      ( cd params && paramspider -d "$d" >> "../logs/recon.log" 2>&1 ) || true
    done < final/all_subs.txt
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
  if have kr; then
    while read -r url; do
      name=$(echo "$url" | sed 's#[^a-zA-Z0-9]#_#g')
      if [ -n "$API_WORDLIST" ] && [ -f "$API_WORDLIST" ]; then
        kr scan "$url" -w "$API_WORDLIST" --output json 2>>"$LOGFILE" > "api/kiterunner_${name}.json" || true
      else
        kr scan "$url" -A=apiroutes-210228:20000 --output json 2>>"$LOGFILE" > "api/kiterunner_${name}.json" || true
      fi
    done < http/live_urls.txt
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
    done < http/live_urls.txt
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
      run_parallel js/js_files.txt "LinkFinder endpoint extraction" \
        'name=$(echo "$1" | sed "s#[^a-zA-Z0-9]#_#g"); linkfinder -i "$1" -o cli >> "js/linkfinder_${name}.txt" 2>>'"$LOGFILE"
      ok "LinkFinder endpoint extraction complete, see js/linkfinder_*.txt"
    else
      warn "linkfinder not installed, skipping JS endpoint extraction"
    fi
    if have secretfinder; then
      run_parallel js/js_files.txt "SecretFinder scan" \
        'name=$(echo "$1" | sed "s#[^a-zA-Z0-9]#_#g"); secretfinder -i "$1" -o cli >> "js/secretfinder_${name}.txt" 2>>'"$LOGFILE"
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
      dalfox file "$PARAM_URLS" --silence -o xss/dalfox_results.txt 2>>"$LOGFILE" || true
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
      sqlmap -m "$PARAM_URLS_SQLI" --batch --level="$SQLI_LEVEL" --risk="$SQLI_RISK" \
        --random-agent --output-dir=sqli/ 2>>"$LOGFILE" || true
      ok "sqlmap detection pass complete, see sqli/ for any findings"
    else
      warn "No parameterized URLs found (run --crawl first) — skipping SQLi scan"
    fi
  else
    warn "sqlmap not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 21: Cloud Storage Enumeration (optional)
# ========================================================================
if [ "$CLOUD_SCAN" = true ]; then
  log "Phase 21: Cloud storage bucket enumeration"
  if have cloud_enum; then
    cloud_enum -k "$DOMAIN" --disable-azure --disable-gcp -l cloud/cloud_enum.txt 2>>"$LOGFILE" || true
  elif have s3scanner; then
    s3scanner -bucket-file final/all_subs.txt -json > cloud/s3_results.json 2>>"$LOGFILE" || true
  else
    warn "No cloud enumeration tool installed (cloud_enum / s3scanner), skipping"
  fi
  ok "Cloud enumeration pass complete (review cloud/ for results)"
fi

# ========================================================================
# PHASE 22: GitHub Leak Scanning (optional)
# ========================================================================
if [ "$GITHUB_SCAN" = true ]; then
  log "Phase 22: GitHub leak scanning"
  if have trufflehog; then
    trufflehog github --org="$DOMAIN" --json > github/github_secrets.json 2>>"$LOGFILE" || \
      warn "trufflehog GitHub scan needs GITHUB_TOKEN env var and an org/user match — check manually"
  else
    warn "trufflehog not installed, skipping GitHub secrets scan"
  fi
  ok "GitHub scan pass complete (review github/ for results)"
fi

# ========================================================================
# PHASE 23: CORS Misconfiguration Scan (optional)
# ========================================================================
if [ "$CORS_SCAN" = true ]; then
  log "Phase 23: CORS misconfiguration scan"
  if have corsy || have Corsy; then
    CORSY_BIN=$(have corsy && echo corsy || echo Corsy)
    "$CORSY_BIN" -i http/live_urls.txt -o cors/cors_results.json 2>>"$LOGFILE" || true
    ok "CORS scan complete, see cors/cors_results.json"
  else
    warn "Corsy not installed, skipping CORS scan"
  fi
fi

# ========================================================================
# PHASE 24: Diff Against Previous Run (new subdomain monitoring)
# ========================================================================
log "Phase 24: Diff against previous run"
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
# PHASE 25: Screenshots (optional)
# ========================================================================
if [ "$SCREENSHOTS" = true ]; then
  log "Phase 25: Screenshots with gowitness"
  if have gowitness; then
    gowitness file -f http/live_urls.txt -P http/screenshots/ --no-http 2>>"$LOGFILE" || \
      gowitness scan file -f http/live_urls.txt -P http/screenshots/ 2>>"$LOGFILE" || true
    ok "Screenshots saved to http/screenshots/"
  else
    warn "gowitness not installed, skipping screenshots"
  fi
fi

# ========================================================================
# PHASE 26: Vulnerability Scanning (nuclei)
# ========================================================================
log "Phase 26: Nuclei scan (severity: $SEVERITIES, rate-limit: $NUCLEI_RATE_LIMIT req/s)"
nuclei -l http/live_urls.txt -s "$SEVERITIES" -rl "$NUCLEI_RATE_LIMIT" -c 25 -silent \
  -o vulns/nuclei_results.txt -je vulns/nuclei_results.json
FINDINGS=$(countf vulns/nuclei_results.txt)
ok "Nuclei findings: $FINDINGS"

SCRIPT_END_EPOCH=$(date +%s)
ELAPSED=$((SCRIPT_END_EPOCH - SCRIPT_START_EPOCH))
ELAPSED_FMT=$(printf '%dh %dm %ds' $((ELAPSED/3600)) $((ELAPSED%3600/60)) $((ELAPSED%60)))

# ========================================================================
# CLEANUP: Remove empty output folders
# ========================================================================
log "Cleaning up empty output folders"
EMPTIED=0
for i in 1 2; do
  while IFS= read -r d; do
    rmdir "$d" 2>/dev/null && EMPTIED=$((EMPTIED + 1))
  done < <(find . -mindepth 1 -type d -empty 2>/dev/null)
done
[ "$EMPTIED" -gt 0 ] && ok "Removed $EMPTIED empty folder(s)" || ok "No empty folders to remove"

# ========================================================================
# PHASE 27: Summary Report
# ========================================================================
SUMMARY="final/SUMMARY.md"
cat > "$SUMMARY" <<EOF
# Recon Summary — $DOMAIN
Generated: $(date '+%Y-%m-%d %H:%M:%S')
Total run time: $ELAPSED_FMT

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
| Nuclei findings                   | $FINDINGS |

## Output structure
- raw/        — per-tool subdomain enum output (incl. amass, chaos)
- final/      — merged, scoped, resolved subdomains + diff + wildcard info
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
