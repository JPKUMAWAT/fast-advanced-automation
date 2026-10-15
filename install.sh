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
go_install trufflehog       github.com/trufflesecurity/trufflehog/v3
go_install gitleaks         github.com/gitleaks/gitleaks/v8
go_install github-subdomains github.com/gwen001/github-subdomains
go_install asnmap           github.com/projectdiscovery/asnmap/cmd/asnmap
go_install subzy            github.com/PentestPad/subzy
go_install gowitness        github.com/sensepost/gowitness
go_install notify           github.com/projectdiscovery/notify/cmd/notify

pip_install wafw00f wafw00f
pip_install cloud_enum cloudenum

# S3Scanner — go-installable alternative
go_install S3Scanner github.com/sa7mon/s3scanner

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

echo ""
ok "Full install pass complete."
echo ""
log "Make sure these are in your \$PATH:"
echo "    export PATH=\"\$PATH:$GOBIN_DIR:\$HOME/.local/bin\""
echo ""
log "Add the line above to your ~/.bashrc or ~/.zshrc, then run:"
echo "    source ~/.bashrc"
echo ""
log "Verify everything is reachable with:"
echo "    which subfinder dnsx httpx nuclei naabu katana gau ffuf subjs trufflehog gowitness"
