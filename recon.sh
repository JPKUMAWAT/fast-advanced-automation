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
#   naabu            - port scanning
#   katana           - active crawling / endpoint discovery
#   gau, waybackurls  - historical URL discovery
#   ffuf             - directory/file brute-forcing
#   subjs            - collect JS files from live hosts
#   trufflehog        - secrets scanning (local files + GitHub)
#   gitleaks          - secrets scanning (alt)
#   S3Scanner, cloud_enum - cloud storage bucket enumeration
#   github-subdomains - GitHub-based subdomain/leak discovery
#   Corsy             - CORS misconfiguration scanning
#   wafw00f           - WAF/CDN fingerprinting
#   asnmap            - ASN / IP range discovery
#   favfreak          - favicon-hash tech fingerprinting
#   gowitness         - screenshots
#   notify            - Slack/Discord/Telegram alerts
#
# For authorized security testing / bug bounty use only.
# -----------------------------------------------------------------------

set -uo pipefail

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

# ---------- Colors ----------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()   { echo -e "${BLUE}[*]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
ok()    { echo -e "${GREEN}[+]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
warn()  { echo -e "${YELLOW}[!]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE"; }
err()   { echo -e "${RED}[-]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*" | tee -a "$LOGFILE" >&2; }
have()  { command -v "$1" >/dev/null 2>&1; }

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
  --full                      Enable ALL modules below
  --takeover                  Subdomain takeover check (nuclei takeover templates + subzy)
  --portscan                  Port scanning with naabu
  --crawl                     Active crawling + historical URLs (katana, gau, waybackurls)
  --ffuf <wordlist>           Directory/file brute-force with ffuf
  --jsscan                    Collect JS files + scan for secrets (subjs, trufflehog/gitleaks)
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

Examples:
  $0 -d example.com -s scope.txt --full --notify
  $0 -dL targets.txt --takeover --jsscan --crawl
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
    --takeover) TAKEOVER=true; shift ;;
    --portscan) PORTSCAN=true; shift ;;
    --crawl) CRAWL=true; shift ;;
    --ffuf) FFUF_WORDLIST="$2"; shift 2 ;;
    --jsscan) JS_SCAN=true; shift ;;
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
  TAKEOVER=true; PORTSCAN=true; CRAWL=true; JS_SCAN=true; CLOUD_SCAN=true
  GITHUB_SCAN=true; CORS_SCAN=true; WAF_CHECK=true; ASN_SCAN=true
  FAVICON_SCAN=true; SCREENSHOTS=true
fi

if [ -z "$DOMAIN" ] && [ -z "$DOMAIN_LIST" ]; then
  echo "Error: provide -d <domain> or -dL <domains_file>"
  usage
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
mkdir -p "$OUTDIR"/{raw,final,http,vulns,ports,urls,js,cloud,github,cors,waf,asn,favicon,logs}
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

run_if_available() {
  local tool="$1"; shift
  if have "$tool"; then "$@"; else warn "Skipping $tool (not installed)"; fi
}

# ========================================================================
# PHASE 1: Subdomain Enumeration (passive, parallel)
# ========================================================================
log "Phase 1: Subdomain enumeration"
run_if_available subfinder subfinder -d "$DOMAIN" -all -recursive -t "$THREADS" -silent -o raw/subfinder.txt &
run_if_available assetfinder bash -c "assetfinder -subs-only '$DOMAIN' > raw/assetfinder.txt" &
run_if_available findomain findomain -t "$DOMAIN" -u raw/findomain.txt &
run_if_available sublist3r sublist3r -d "$DOMAIN" -t 50 -o raw/sublist3r.txt &
run_if_available subdominator bash -c "subdominator -d '$DOMAIN' > raw/subdominator.txt" &
if [ "$GITHUB_SCAN" = true ]; then
  run_if_available github-subdomains bash -c "github-subdomains -d '$DOMAIN' -raw > raw/github_subs.txt" &
fi
wait
ok "Subdomain enumeration complete"

# ========================================================================
# PHASE 2: Merge, Dedup, Clean
# ========================================================================
log "Phase 2: Merging and deduplicating"
cat raw/*.txt 2>/dev/null \
  | grep -E "^[a-zA-Z0-9._-]+\.${DOMAIN//./\\.}$" \
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

# ========================================================================
# PHASE 5: DNS Resolution
# ========================================================================
log "Phase 5: DNS resolution"
dnsx -l "$SUBS_FILE" -silent -o final/resolved.txt
ok "Resolved: $(wc -l < final/resolved.txt 2>/dev/null || echo 0)"
RESOLVED_FILE="final/resolved.txt"
[ -s "$RESOLVED_FILE" ] || RESOLVED_FILE="$SUBS_FILE"

# ========================================================================
# PHASE 6: ASN / IP Range Discovery (optional)
# ========================================================================
if [ "$ASN_SCAN" = true ]; then
  log "Phase 6: ASN / IP range discovery"
  if have asnmap; then
    asnmap -d "$DOMAIN" -silent -o asn/ranges.txt 2>>"$LOGFILE"
    ok "ASN ranges: $(wc -l < asn/ranges.txt 2>/dev/null || echo 0) (review before scanning — often broader than bounty scope)"
  else
    warn "asnmap not installed, skipping ASN discovery"
  fi
fi

# ========================================================================
# PHASE 7: Port Scanning (optional)
# ========================================================================
if [ "$PORTSCAN" = true ]; then
  log "Phase 7: Port scanning with naabu"
  if have naabu; then
    naabu -l "$RESOLVED_FILE" -silent -rate "$NUCLEI_RATE_LIMIT" -o ports/open_ports.txt 2>>"$LOGFILE"
    ok "Open ports found: $(wc -l < ports/open_ports.txt 2>/dev/null || echo 0)"
  else
    warn "naabu not installed, skipping port scan"
  fi
fi

# ========================================================================
# PHASE 8: HTTP Probing
# ========================================================================
log "Phase 8: HTTP(S) probing with $HTTPX_BIN"
"$HTTPX_BIN" -l "$RESOLVED_FILE" -silent -status-code -title -tech-detect -follow-redirects \
  -threads "$THREADS" -o http/live_hosts.txt
LIVE_COUNT=$(wc -l < http/live_hosts.txt 2>/dev/null || echo 0)
ok "Live HTTP(S) hosts: $LIVE_COUNT"
awk '{print $1}' http/live_hosts.txt > http/live_urls.txt
[ -s http/live_urls.txt ] || { err "No live hosts found. Stopping."; exit 1; }

# ========================================================================
# PHASE 9: Subdomain Takeover Check (optional)
# ========================================================================
if [ "$TAKEOVER" = true ]; then
  log "Phase 9: Subdomain takeover check"
  if have subzy; then
    subzy run --targets final/resolved.txt --output vulns/takeover_subzy.txt 2>>"$LOGFILE" || true
  else
    warn "subzy not installed, skipping subzy pass"
  fi
  if have nuclei; then
    nuclei -l http/live_urls.txt -tags takeover -silent -o vulns/takeover_nuclei.txt 2>>"$LOGFILE" || true
    TAKEOVER_COUNT=$(wc -l < vulns/takeover_nuclei.txt 2>/dev/null || echo 0)
    [ "$TAKEOVER_COUNT" -gt 0 ] && warn "POSSIBLE TAKEOVER(S): $TAKEOVER_COUNT — see vulns/takeover_nuclei.txt" || ok "No takeover indicators found"
  fi
fi

# ========================================================================
# PHASE 10: WAF/CDN Detection (optional)
# ========================================================================
if [ "$WAF_CHECK" = true ]; then
  log "Phase 10: WAF/CDN fingerprinting"
  if have wafw00f; then
    while read -r url; do
      wafw00f "$url" >> waf/waf_results.txt 2>>"$LOGFILE"
    done < http/live_urls.txt
    ok "WAF detection results saved to waf/waf_results.txt"
  else
    warn "wafw00f not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 11: Favicon Fingerprinting (optional)
# ========================================================================
if [ "$FAVICON_SCAN" = true ]; then
  log "Phase 11: Favicon-hash fingerprinting"
  if have favfreak; then
    favfreak -f http/live_urls.txt -o favicon/ 2>>"$LOGFILE" || true
    ok "Favicon fingerprints saved to favicon/"
  else
    warn "favfreak not installed, skipping"
  fi
fi

# ========================================================================
# PHASE 12: Crawling + Historical URL Discovery (optional)
# ========================================================================
if [ "$CRAWL" = true ]; then
  log "Phase 12: Crawling + historical URL discovery"
  if have katana; then
    katana -list http/live_urls.txt -silent -jc -o urls/katana.txt 2>>"$LOGFILE" || true
  else
    warn "katana not installed, skipping active crawl"
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
  ok "Total discovered URLs: $(wc -l < urls/all_urls.txt 2>/dev/null || echo 0)"
fi

# ========================================================================
# PHASE 13: Directory/File Brute-forcing (optional)
# ========================================================================
if [ -n "$FFUF_WORDLIST" ]; then
  log "Phase 13: Directory brute-forcing with ffuf"
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
# PHASE 14: JS Collection + Secrets Scanning (optional)
# ========================================================================
if [ "$JS_SCAN" = true ]; then
  log "Phase 14: JS file collection + secrets scanning"
  if have subjs; then
    cat http/live_urls.txt | subjs > js/js_files.txt 2>>"$LOGFILE" || true
    ok "JS files collected: $(wc -l < js/js_files.txt 2>/dev/null || echo 0)"
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
  fi
fi

# ========================================================================
# PHASE 15: Cloud Storage Enumeration (optional)
# ========================================================================
if [ "$CLOUD_SCAN" = true ]; then
  log "Phase 15: Cloud storage bucket enumeration"
  if have cloud_enum; then
    cloud_enum -k "$DOMAIN" --disable-azure --disable-gcp -l cloud/cloud_enum.txt 2>>"$LOGFILE" || true
  elif have S3Scanner; then
    S3Scanner scan --bucket-file final/all_subs.txt > cloud/s3_results.txt 2>>"$LOGFILE" || true
  else
    warn "No cloud enumeration tool installed (cloud_enum / S3Scanner), skipping"
  fi
  ok "Cloud enumeration pass complete (review cloud/ for results)"
fi

# ========================================================================
# PHASE 16: GitHub Leak Scanning (optional)
# ========================================================================
if [ "$GITHUB_SCAN" = true ]; then
  log "Phase 16: GitHub leak scanning"
  if have trufflehog; then
    trufflehog github --org="$DOMAIN" --json > github/github_secrets.json 2>>"$LOGFILE" || \
      warn "trufflehog GitHub scan needs GITHUB_TOKEN env var and an org/user match — check manually"
  else
    warn "trufflehog not installed, skipping GitHub secrets scan"
  fi
  ok "GitHub scan pass complete (review github/ for results)"
fi

# ========================================================================
# PHASE 17: CORS Misconfiguration Scan (optional)
# ========================================================================
if [ "$CORS_SCAN" = true ]; then
  log "Phase 17: CORS misconfiguration scan"
  if have corsy || have Corsy; then
    CORSY_BIN=$(have corsy && echo corsy || echo Corsy)
    "$CORSY_BIN" -i http/live_urls.txt -o cors/cors_results.json 2>>"$LOGFILE" || true
    ok "CORS scan complete, see cors/cors_results.json"
  else
    warn "Corsy not installed, skipping CORS scan"
  fi
fi

# ========================================================================
# PHASE 18: Diff Against Previous Run (new subdomain monitoring)
# ========================================================================
log "Phase 18: Diff against previous run"
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
# PHASE 19: Screenshots (optional)
# ========================================================================
if [ "$SCREENSHOTS" = true ]; then
  log "Phase 19: Screenshots with gowitness"
  if have gowitness; then
    gowitness file -f http/live_urls.txt -P http/screenshots/ --no-http 2>>"$LOGFILE" || \
      gowitness scan file -f http/live_urls.txt -P http/screenshots/ 2>>"$LOGFILE" || true
    ok "Screenshots saved to http/screenshots/"
  else
    warn "gowitness not installed, skipping screenshots"
  fi
fi

# ========================================================================
# PHASE 20: Vulnerability Scanning (nuclei)
# ========================================================================
log "Phase 20: Nuclei scan (severity: $SEVERITIES, rate-limit: $NUCLEI_RATE_LIMIT req/s)"
nuclei -l http/live_urls.txt -s "$SEVERITIES" -rl "$NUCLEI_RATE_LIMIT" -c 25 -silent \
  -o vulns/nuclei_results.txt -je vulns/nuclei_results.json
FINDINGS=$(wc -l < vulns/nuclei_results.txt 2>/dev/null || echo 0)
ok "Nuclei findings: $FINDINGS"

# ========================================================================
# PHASE 21: Summary Report
# ========================================================================
countf() { [ -f "$1" ] && wc -l < "$1" || echo "n/a"; }

SUMMARY="final/SUMMARY.md"
cat > "$SUMMARY" <<EOF
# Recon Summary — $DOMAIN
Generated: $(date '+%Y-%m-%d %H:%M:%S')

| Stage                          | Count |
|---------------------------------|-------|
| Raw enum hits                    | $TOTAL_RAW |
| Unique subdomains                 | $TOTAL_UNIQUE |
| In-scope subdomains               | $(wc -l < "$SUBS_FILE") |
| Resolved (live DNS)               | $(wc -l < "$RESOLVED_FILE" 2>/dev/null || echo 0) |
| Live HTTP(S) hosts                | $LIVE_COUNT |
| New subdomains (vs last run)      | $(wc -l < final/new_subs.txt 2>/dev/null || echo 0) |
| Wildcard DNS detected             | $([ -s final/wildcard_ips.txt ] 2>/dev/null && echo "YES" || echo "No") |
| Open ports found                  | $(countf ports/open_ports.txt) |
| Discovered URLs (crawl/history)   | $(countf urls/all_urls.txt) |
| JS files collected                | $(countf js/js_files.txt) |
| Takeover indicators               | $(countf vulns/takeover_nuclei.txt) |
| Nuclei findings                   | $FINDINGS |

## Output structure
- raw/        — per-tool subdomain enum output
- final/      — merged, scoped, resolved subdomains + diff + wildcard info
- ports/      — naabu port scan results
- http/       — live hosts, tech stack, screenshots
- urls/       — crawled + historical URLs, ffuf results
- js/         — collected JS files + secrets scan
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
    echo "Recon done: $DOMAIN — $FINDINGS nuclei findings, $LIVE_COUNT live hosts, $(wc -l < final/new_subs.txt 2>/dev/null || echo 0) new subs." | notify -silent
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
