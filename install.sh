#!/usr/bin/env bash
#
# install.sh — One-shot installer for every tool recon.sh can use.
#
# Usage:
#   ./install.sh            Install core (required) tools only
#   ./install.sh --full      Install core + all optional module tools
#
# Installs Go-based tools via `go install`, Python tools via `pip3`,
# and a couple of tools that ship only as prebuilt binaries/releases.
# Safe to re-run — each step skips if the tool is already on $PATH.
# -----------------------------------------------------------------------

set -uo pipefail

FULL=false
[ "${1:-}" = "--full" ] && FULL=true

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
log()  { echo -e "${BLUE}[*]${NC} $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

GOBIN_DIR="${GOBIN:-$(go env GOPATH 2>/dev/null)/bin}"
[ -z "$GOBIN_DIR" ] && GOBIN_DIR="$HOME/go/bin"

# ---------- Pre-flight checks ----------
log "Checking prerequisites..."
MISSING_PREREQ=()
have go     || MISSING_PREREQ+=("go (https://go.dev/doc/install)")
have python3 || MISSING_PREREQ+=("python3")
have pip3   || MISSING_PREREQ+=("pip3")
have git    || MISSING_PREREQ+=("git")

if [ "${#MISSING_PREREQ[@]}" -gt 0 ]; then
  err "Missing prerequisites, install these first:"
  for p in "${MISSING_PREREQ[@]}"; do echo "    - $p"; done
  exit 1
fi
ok "Prerequisites OK (go, python3, pip3, git found)"
log "Go tools will install to: $GOBIN_DIR  (make sure this is in your \$PATH)"

go_install() {
  local name="$1" pkg="$2"
  if have "$name"; then
    ok "$name already installed, skipping"
  else
    log "Installing $name..."
    if go install -v "$pkg@latest" 2>&1 | tail -5; then
      ok "$name installed"
    else
      warn "$name failed to install, check the log above"
    fi
  fi
}

pip_install() {
  local name="$1" pkg="$2"
  if have "$name"; then
    ok "$name already installed, skipping"
  else
    log "Installing $name via pip..."
    pip3 install --user --break-system-packages "$pkg" >/dev/null 2>&1 \
      || pip3 install --user "$pkg" >/dev/null 2>&1
    have "$name" && ok "$name installed" || warn "$name install may need manual PATH setup"
  fi
}

# =========================================================================
# CORE (required by recon.sh)
# =========================================================================
log "=== Installing core tools ==="
go_install subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder
go_install assetfinder  github.com/tomnomnom/assetfinder
go_install dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx
go_install httpx        github.com/projectdiscovery/httpx/cmd/httpx
go_install nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei

# findomain ships as a prebuilt binary release, not go-installable
if have findomain; then
  ok "findomain already installed, skipping"
else
  log "Installing findomain (prebuilt binary)..."
  curl -sL https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip \
    && unzip -o -q /tmp/findomain.zip -d /tmp \
    && chmod +x /tmp/findomain \
    && sudo mv /tmp/findomain /usr/local/bin/findomain 2>/dev/null \
    || mv /tmp/findomain "$HOME/.local/bin/findomain" 2>/dev/null
  have findomain && ok "findomain installed" || warn "findomain install failed — install manually from https://github.com/findomain/findomain/releases"
fi

# sublist3r — python tool, no pip package, clone + run as module
if have sublist3r; then
  ok "sublist3r already installed, skipping"
else
  log "Installing sublist3r (git clone)..."
  git clone -q https://github.com/aboul3la/Sublist3r.git "$HOME/.tools/Sublist3r" 2>/dev/null
  pip3 install --user --break-system-packages -r "$HOME/.tools/Sublist3r/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/.tools/Sublist3r/sublist3r.py "$@"\n' "$HOME" > "$HOME/.local/bin/sublist3r" 2>/dev/null
  chmod +x "$HOME/.local/bin/sublist3r" 2>/dev/null
  ok "sublist3r installed (wrapper in ~/.local/bin)"
fi

# subdominator — pip-installable
pip_install subdominator subdominator

ok "Core install pass complete"

if [ "$FULL" = false ]; then
  echo ""
  log "Core tools done. Run with --full to also install optional module tools:"
  echo "    ./install.sh --full"
  exit 0
fi

# =========================================================================
# OPTIONAL (per module in recon.sh --full)
# =========================================================================
log "=== Installing optional module tools ==="

go_install naabu            github.com/projectdiscovery/naabu/v2/cmd/naabu
go_install katana           github.com/projectdiscovery/katana/cmd/katana
go_install gau              github.com/lc/gau/v2/cmd/gau
go_install waybackurls      github.com/tomnomnom/waybackurls
go_install ffuf             github.com/ffuf/ffuf/v2
go_install subjs            github.com/lc/subjs
if have trufflehog; then
  ok "trufflehog already installed, skipping"
else
  # trufflehog's own go.mod uses replace directives, so `go install` always
  # fails with "must not contain directives..." — their official installer
  # script is the only reliable method.
  log "Installing trufflehog (official install script)..."
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b "$HOME/.local/bin" >/dev/null 2>&1
  have trufflehog && ok "trufflehog installed" || warn "trufflehog install failed — see https://github.com/trufflesecurity/trufflehog#floppy_disk-installation"
fi
# Real module path is zricethezav/gitleaks, NOT gitleaks/gitleaks — the import
# path github.com/gitleaks/gitleaks/v8 does not exist.
go_install gitleaks         github.com/zricethezav/gitleaks/v8
go_install github-subdomains github.com/gwen001/github-subdomains
go_install asnmap           github.com/projectdiscovery/asnmap/cmd/asnmap
go_install subzy            github.com/PentestPad/subzy
go_install gowitness        github.com/sensepost/gowitness
go_install notify           github.com/projectdiscovery/notify/cmd/notify

# Extra asset-discovery sources
go_install amass            github.com/owasp-amass/amass/v4/cmd/amass
go_install chaos            github.com/projectdiscovery/chaos-client/cmd/chaos

# Active DNS bruteforce + permutation
go_install puredns          github.com/d3mondev/puredns/v2
# dnsgen is a Python tool, not a Go module — `go install` can never work for it.
pip_install dnsgen dnsgen
if have massdns; then
  ok "massdns already installed, skipping"
else
  log "Installing massdns (build from source)..."
  git clone -q https://github.com/blechschmidt/massdns.git "$HOME/.tools/massdns" 2>/dev/null
  (cd "$HOME/.tools/massdns" && make >/dev/null 2>&1 && cp bin/massdns "$HOME/.local/bin/massdns" 2>/dev/null)
  have massdns && ok "massdns installed" || warn "massdns build failed — build manually from https://github.com/blechschmidt/massdns"
fi

# Alternate crawlers
go_install gospider         github.com/jaeles-project/gospider
go_install hakrawler        github.com/hakluke/hakrawler

# Hidden parameter discovery + API route bruteforce
pip_install arjun arjun
if have paramspider; then
  ok "paramspider already installed, skipping"
else
  log "Installing paramspider (git clone)..."
  git clone -q https://github.com/devanshbatham/ParamSpider.git "$HOME/.tools/ParamSpider" 2>/dev/null
  pip3 install --user --break-system-packages -e "$HOME/.tools/ParamSpider" >/dev/null 2>&1
  ok "paramspider installed"
fi
# kiterunner has no working `go install` path (its module doesn't expose a
# cmd/kr package) — the officially supported method is clone + make build.
if have kr; then
  ok "kr (kiterunner) already installed, skipping"
else
  log "Installing kr / kiterunner (git clone + make build)..."
  git clone -q --depth 1 https://github.com/assetnote/kiterunner.git "$HOME/.tools/kiterunner" 2>/dev/null
  ( cd "$HOME/.tools/kiterunner" && make build >/dev/null 2>&1 && cp dist/kr "$HOME/.local/bin/kr" 2>/dev/null )
  have kr && ok "kr (kiterunner) installed" || warn "kr build failed — download a prebuilt binary instead from https://github.com/assetnote/kiterunner/releases"
fi

# JS endpoint/secret extraction
pip_install linkfinder   linkfinder || true
if [ ! -d "$HOME/.tools/LinkFinder" ]; then
  log "Installing LinkFinder (git clone)..."
  git clone -q https://github.com/GerbenJavado/LinkFinder.git "$HOME/.tools/LinkFinder" 2>/dev/null
  pip3 install --user --break-system-packages -r "$HOME/.tools/LinkFinder/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/.tools/LinkFinder/linkfinder.py "$@"\n' "$HOME" > "$HOME/.local/bin/linkfinder" 2>/dev/null
  chmod +x "$HOME/.local/bin/linkfinder" 2>/dev/null
  ok "LinkFinder installed (wrapper in ~/.local/bin)"
fi
if [ ! -d "$HOME/.tools/SecretFinder" ]; then
  log "Installing SecretFinder (git clone)..."
  git clone -q https://github.com/m4ll0k/SecretFinder.git "$HOME/.tools/SecretFinder" 2>/dev/null
  pip3 install --user --break-system-packages -r "$HOME/.tools/SecretFinder/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/.tools/SecretFinder/SecretFinder.py "$@"\n' "$HOME" > "$HOME/.local/bin/secretfinder" 2>/dev/null
  chmod +x "$HOME/.local/bin/secretfinder" 2>/dev/null
  ok "SecretFinder installed (wrapper in ~/.local/bin)"
fi

# XSS + SQLi (opt-in, detection-focused)
go_install dalfox github.com/hahwul/dalfox/v2
if have sqlmap; then
  ok "sqlmap already installed, skipping"
else
  log "Installing sqlmap (git clone)..."
  git clone -q --depth 1 https://github.com/sqlmapproject/sqlmap.git "$HOME/.tools/sqlmap" 2>/dev/null
  printf '#!/usr/bin/env bash\npython3 %s/.tools/sqlmap/sqlmap.py "$@"\n' "$HOME" > "$HOME/.local/bin/sqlmap" 2>/dev/null
  chmod +x "$HOME/.local/bin/sqlmap" 2>/dev/null
  ok "sqlmap installed (wrapper in ~/.local/bin) — use --sqli only with explicit program authorization"
fi

pip_install wafw00f wafw00f
pip_install cloud_enum cloudenum

# S3Scanner — go-installable; the actual binary name is lowercase 's3scanner'
go_install s3scanner github.com/sa7mon/s3scanner

# Corsy — git clone, python script
if have corsy || [ -d "$HOME/.tools/Corsy" ]; then
  ok "Corsy already installed, skipping"
else
  log "Installing Corsy (git clone)..."
  git clone -q https://github.com/s0md3v/Corsy.git "$HOME/.tools/Corsy" 2>/dev/null
  pip3 install --user --break-system-packages -r "$HOME/.tools/Corsy/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/.tools/Corsy/corsy.py "$@"\n' "$HOME" > "$HOME/.local/bin/corsy" 2>/dev/null
  chmod +x "$HOME/.local/bin/corsy" 2>/dev/null
  ok "Corsy installed (wrapper in ~/.local/bin)"
fi

# favfreak — git clone, python script
if have favfreak || [ -d "$HOME/.tools/FavFreak" ]; then
  ok "favfreak already installed, skipping"
else
  log "Installing favfreak (git clone)..."
  git clone -q https://github.com/devanshbatham/FavFreak.git "$HOME/.tools/FavFreak" 2>/dev/null
  pip3 install --user --break-system-packages mmh3 requests >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/.tools/FavFreak/favfreak.py "$@"\n' "$HOME" > "$HOME/.local/bin/favfreak" 2>/dev/null
  chmod +x "$HOME/.local/bin/favfreak" 2>/dev/null
  ok "favfreak installed (wrapper in ~/.local/bin)"
fi

# nuclei templates (needed for -tags takeover etc.)
if have nuclei; then
  log "Updating nuclei templates..."
  nuclei -update-templates -silent >/dev/null 2>&1 && ok "nuclei templates updated"
fi

# System packages used by a couple of optional modules (curl is almost always
# present; dig comes from dnsutils/bind-utils and isn't always installed by default)
if ! have dig; then
  warn "dig not found (needed for --shodan). Install it with:"
  echo "    sudo apt install dnsutils      # Debian/Ubuntu/Kali"
  echo "    sudo yum install bind-utils    # RHEL/CentOS"
fi

echo ""
ok "Full install pass complete."
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: tools were installed to $GOBIN_DIR and ~/.local/bin,${NC}"
echo -e "${YELLOW}   but your CURRENT shell doesn't know about that yet.${NC}"
echo -e "${YELLOW}   Running recon.sh right now will still show tools as 'not installed'.${NC}"
echo ""
log "Run this in your current shell before using recon.sh:"
echo "    export PATH=\"\$PATH:$GOBIN_DIR:\$HOME/.local/bin\""
echo ""
log "To make it permanent, add that line to ~/.bashrc or ~/.zshrc, then either"
log "run 'source ~/.bashrc' or open a new terminal."
echo ""
log "Verify everything is reachable with:"
echo "    which subfinder dnsx httpx nuclei naabu katana gau ffuf subjs trufflehog gowitness amass dalfox arjun"
echo ""
log "Not installed by this script — manual interception/testing tools:"
echo "    Burp Suite:  https://portswigger.net/burp"
echo "    Caido:       https://caido.io"
echo "    OWASP ZAP:   https://www.zaproxy.org"
echo "    These are interactive proxies, not CLI recon tools — use them by hand"
echo "    on the interesting hosts/endpoints recon.sh surfaces."
