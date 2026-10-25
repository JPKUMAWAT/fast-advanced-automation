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
LOCAL_BIN="$HOME/.local/bin"
TOOLS_DIR="$HOME/.tools"

# ---------- FIX #1 + #2: create dirs and export PATH BEFORE anything installs ----------
# Without this, every wrapper script written to ~/.local/bin below is invisible
# to `have()` checks later in THIS SAME run (a freshly installed tool would be
# reported as "not installed" by the very next step that depends on it), and
# redirects into ~/.local/bin silently fail if the directory doesn't exist yet.
mkdir -p "$LOCAL_BIN" "$TOOLS_DIR" "$GOBIN_DIR"
export PATH="$PATH:$GOBIN_DIR:$LOCAL_BIN"

# ---------- Track failures for the end-of-run summary ----------
INSTALLED=()
FAILED=()

# ---------- Pre-flight checks ----------
log "Checking prerequisites..."
MISSING_PREREQ=()
have go     || MISSING_PREREQ+=("go (https://go.dev/doc/install)")
have python3 || MISSING_PREREQ+=("python3")
have pip3   || MISSING_PREREQ+=("pip3")
have git    || MISSING_PREREQ+=("git")
have unzip  || MISSING_PREREQ+=("unzip (needed for findomain's release .zip)")

if [ "${#MISSING_PREREQ[@]}" -gt 0 ]; then
  err "Missing prerequisites, install these first:"
  for p in "${MISSING_PREREQ[@]}"; do echo "    - $p"; done
  exit 1
fi
ok "Prerequisites OK (go, python3, pip3, git, unzip found)"
log "Go tools install to: $GOBIN_DIR | wrapper/script tools install to: $LOCAL_BIN"
log "Both are now on PATH for the rest of this run."

go_install() {
  local name="$1" pkg="$2"
  if have "$name"; then
    ok "$name already installed, skipping"
    INSTALLED+=("$name")
  else
    log "Installing $name..."
    if go install -v "$pkg@latest" 2>&1 | tail -5; then
      hash -r   # refresh bash's command lookup cache for this session
      if have "$name"; then
        ok "$name installed"
        INSTALLED+=("$name")
      else
        warn "$name: go install reported success but binary not found on PATH (check GOBIN_DIR name vs expected binary name)"
        FAILED+=("$name")
      fi
    else
      warn "$name failed to install, check the log above"
      FAILED+=("$name")
    fi
  fi
}

pip_install() {
  local name="$1" pkg="$2"
  if have "$name"; then
    ok "$name already installed, skipping"
    INSTALLED+=("$name")
  else
    log "Installing $name via pip..."
    pip3 install --user --break-system-packages "$pkg" >/dev/null 2>&1 \
      || pip3 install --user "$pkg" >/dev/null 2>&1
    hash -r
    if have "$name"; then
      ok "$name installed"
      INSTALLED+=("$name")
    else
      warn "$name install may need manual PATH setup"
      FAILED+=("$name")
    fi
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
  INSTALLED+=("findomain")
else
  log "Installing findomain (prebuilt binary)..."
  if curl -sL https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip \
      && unzip -o -q /tmp/findomain.zip -d /tmp \
      && chmod +x /tmp/findomain; then
    # FIX #3: install straight to ~/.local/bin (already ours to write, already
    # on PATH). Only try sudo as a non-interactive, non-blocking fallback —
    # `sudo -n` fails immediately instead of hanging on a password prompt.
    if mv /tmp/findomain "$LOCAL_BIN/findomain" 2>/dev/null; then
      :
    elif sudo -n mv /tmp/findomain /usr/local/bin/findomain 2>/dev/null; then
      :
    else
      warn "Could not place findomain binary (no write access to $LOCAL_BIN and no passwordless sudo)"
    fi
  fi
  hash -r
  if have findomain; then ok "findomain installed"; INSTALLED+=("findomain")
  else warn "findomain install failed — install manually from https://github.com/findomain/findomain/releases"; FAILED+=("findomain"); fi
fi

# sublist3r — python tool, no pip package, clone + run as module
if have sublist3r; then
  ok "sublist3r already installed, skipping"
  INSTALLED+=("sublist3r")
else
  log "Installing sublist3r (git clone)..."
  git clone -q https://github.com/aboul3la/Sublist3r.git "$TOOLS_DIR/Sublist3r" 2>/dev/null
  pip3 install --user --break-system-packages -r "$TOOLS_DIR/Sublist3r/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/Sublist3r/sublist3r.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/sublist3r"
  chmod +x "$LOCAL_BIN/sublist3r"
  hash -r
  if have sublist3r; then ok "sublist3r installed (wrapper in $LOCAL_BIN)"; INSTALLED+=("sublist3r")
  else warn "sublist3r wrapper not found on PATH"; FAILED+=("sublist3r"); fi
fi

# subdominator — pip-installable
pip_install subdominator subdominator

ok "Core install pass complete"

if [ "$FULL" = false ]; then
  echo ""
  log "Core tools done. Run with --full to also install optional module tools:"
  echo "    ./install.sh --full"
fi

# =========================================================================
# OPTIONAL (per module in recon.sh --full)
# =========================================================================
if [ "$FULL" = true ]; then
log "=== Installing optional module tools ==="

go_install naabu            github.com/projectdiscovery/naabu/v2/cmd/naabu
go_install katana           github.com/projectdiscovery/katana/cmd/katana
go_install gau              github.com/lc/gau/v2/cmd/gau
go_install waybackurls      github.com/tomnomnom/waybackurls
go_install ffuf             github.com/ffuf/ffuf/v2
go_install subjs            github.com/lc/subjs
if have trufflehog; then
  ok "trufflehog already installed, skipping"; INSTALLED+=("trufflehog")
else
  # trufflehog's own go.mod uses replace directives, so `go install` always
  # fails with "must not contain directives..." — their official installer
  # script is the only reliable method.
  log "Installing trufflehog (official install script)..."
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b "$LOCAL_BIN" >/dev/null 2>&1
  hash -r
  if have trufflehog; then ok "trufflehog installed"; INSTALLED+=("trufflehog")
  else warn "trufflehog install failed — see https://github.com/trufflesecurity/trufflehog#floppy_disk-installation"; FAILED+=("trufflehog"); fi
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
  ok "massdns already installed, skipping"; INSTALLED+=("massdns")
else
  log "Installing massdns (build from source)..."
  git clone -q https://github.com/blechschmidt/massdns.git "$TOOLS_DIR/massdns" 2>/dev/null
  (cd "$TOOLS_DIR/massdns" && make >/dev/null 2>&1 && cp bin/massdns "$LOCAL_BIN/massdns" 2>/dev/null)
  hash -r
  if have massdns; then ok "massdns installed"; INSTALLED+=("massdns")
  else warn "massdns build failed — build manually from https://github.com/blechschmidt/massdns"; FAILED+=("massdns"); fi
fi

# Alternate crawlers
go_install gospider         github.com/jaeles-project/gospider
go_install hakrawler        github.com/hakluke/hakrawler

# Hidden parameter discovery + API route bruteforce
pip_install arjun arjun
if have paramspider; then
  ok "paramspider already installed, skipping"; INSTALLED+=("paramspider")
else
  log "Installing paramspider (git clone)..."
  git clone -q https://github.com/devanshbatham/ParamSpider.git "$TOOLS_DIR/ParamSpider" 2>/dev/null
  pip3 install --user --break-system-packages -e "$TOOLS_DIR/ParamSpider" >/dev/null 2>&1
  hash -r
  if have paramspider; then ok "paramspider installed"; INSTALLED+=("paramspider")
  else warn "paramspider install may need manual PATH setup"; FAILED+=("paramspider"); fi
fi
# kiterunner has no working `go install` path (its module doesn't expose a
# cmd/kr package) — the officially supported method is clone + make build.
if have kr; then
  ok "kr (kiterunner) already installed, skipping"; INSTALLED+=("kr")
else
  log "Installing kr / kiterunner (git clone + make build)..."
  git clone -q --depth 1 https://github.com/assetnote/kiterunner.git "$TOOLS_DIR/kiterunner" 2>/dev/null
  ( cd "$TOOLS_DIR/kiterunner" && make build >/dev/null 2>&1 && cp dist/kr "$LOCAL_BIN/kr" 2>/dev/null )
  hash -r
  if have kr; then ok "kr (kiterunner) installed"; INSTALLED+=("kr")
  else warn "kr build failed — download a prebuilt binary instead from https://github.com/assetnote/kiterunner/releases"; FAILED+=("kr"); fi
fi

# JS endpoint/secret extraction
# FIX #4: no PyPI package named "linkfinder" exists — the git-clone wrapper
# below is the only real install path, so the bogus pip_install call that
# used to precede it (which always failed and printed a confusing warning)
# has been removed.
if [ ! -d "$TOOLS_DIR/LinkFinder" ]; then
  log "Installing LinkFinder (git clone)..."
  git clone -q https://github.com/GerbenJavado/LinkFinder.git "$TOOLS_DIR/LinkFinder" 2>/dev/null
  pip3 install --user --break-system-packages -r "$TOOLS_DIR/LinkFinder/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/LinkFinder/linkfinder.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/linkfinder"
  chmod +x "$LOCAL_BIN/linkfinder"
  hash -r
  if have linkfinder; then ok "LinkFinder installed (wrapper in $LOCAL_BIN)"; INSTALLED+=("linkfinder")
  else warn "LinkFinder wrapper not found on PATH"; FAILED+=("linkfinder"); fi
else
  ok "LinkFinder already installed, skipping"; INSTALLED+=("linkfinder")
fi
if [ ! -d "$TOOLS_DIR/SecretFinder" ]; then
  log "Installing SecretFinder (git clone)..."
  git clone -q https://github.com/m4ll0k/SecretFinder.git "$TOOLS_DIR/SecretFinder" 2>/dev/null
  pip3 install --user --break-system-packages -r "$TOOLS_DIR/SecretFinder/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/SecretFinder/SecretFinder.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/secretfinder"
  chmod +x "$LOCAL_BIN/secretfinder"
  hash -r
  if have secretfinder; then ok "SecretFinder installed (wrapper in $LOCAL_BIN)"; INSTALLED+=("secretfinder")
  else warn "SecretFinder wrapper not found on PATH"; FAILED+=("secretfinder"); fi
else
  ok "SecretFinder already installed, skipping"; INSTALLED+=("secretfinder")
fi

# XSS + SQLi (opt-in, detection-focused)
go_install dalfox github.com/hahwul/dalfox/v2
if have sqlmap; then
  ok "sqlmap already installed, skipping"; INSTALLED+=("sqlmap")
else
  log "Installing sqlmap (git clone)..."
  git clone -q --depth 1 https://github.com/sqlmapproject/sqlmap.git "$TOOLS_DIR/sqlmap" 2>/dev/null
  printf '#!/usr/bin/env bash\npython3 %s/sqlmap/sqlmap.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/sqlmap"
  chmod +x "$LOCAL_BIN/sqlmap"
  hash -r
  if have sqlmap; then ok "sqlmap installed (wrapper in $LOCAL_BIN) — use --sqli only with explicit program authorization"; INSTALLED+=("sqlmap")
  else warn "sqlmap wrapper not found on PATH"; FAILED+=("sqlmap"); fi
fi

pip_install wafw00f wafw00f

# FIX #4 (cont'd): "cloudenum" is not a reliable/real PyPI package for this
# tool — install the same way as the other git-only tools above instead.
if have cloud_enum; then
  ok "cloud_enum already installed, skipping"; INSTALLED+=("cloud_enum")
else
  log "Installing cloud_enum (git clone)..."
  git clone -q https://github.com/initstring/cloud_enum.git "$TOOLS_DIR/cloud_enum" 2>/dev/null
  pip3 install --user --break-system-packages -r "$TOOLS_DIR/cloud_enum/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/cloud_enum/cloud_enum.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/cloud_enum"
  chmod +x "$LOCAL_BIN/cloud_enum"
  hash -r
  if have cloud_enum; then ok "cloud_enum installed (wrapper in $LOCAL_BIN)"; INSTALLED+=("cloud_enum")
  else warn "cloud_enum wrapper not found on PATH"; FAILED+=("cloud_enum"); fi
fi

# FIX #5: the real repo/binary is "S3Scanner" (capital S, capital S) — `go
# install` names the binary after the import path verbatim, so a plain
# go_install here produces a binary your script can never find under the
# lowercase name it checks for. Install it, then add a lowercase symlink so
# recon.sh's `have s3scanner` check actually works.
if have s3scanner; then
  ok "s3scanner already installed, skipping"; INSTALLED+=("s3scanner")
else
  log "Installing s3scanner (as S3Scanner)..."
  if go install -v github.com/sa7mon/S3Scanner@latest 2>&1 | tail -5; then
    hash -r
    if have S3Scanner; then
      ln -sf "$(command -v S3Scanner)" "$LOCAL_BIN/s3scanner"
      hash -r
    fi
  fi
  if have s3scanner; then ok "s3scanner installed (symlinked to S3Scanner)"; INSTALLED+=("s3scanner")
  else warn "s3scanner failed to install"; FAILED+=("s3scanner"); fi
fi

# Corsy — git clone, python script
if have corsy; then
  ok "Corsy already installed, skipping"; INSTALLED+=("corsy")
else
  log "Installing Corsy (git clone)..."
  git clone -q https://github.com/s0md3v/Corsy.git "$TOOLS_DIR/Corsy" 2>/dev/null
  pip3 install --user --break-system-packages -r "$TOOLS_DIR/Corsy/requirements.txt" >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/Corsy/corsy.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/corsy"
  chmod +x "$LOCAL_BIN/corsy"
  hash -r
  if have corsy; then ok "Corsy installed (wrapper in $LOCAL_BIN)"; INSTALLED+=("corsy")
  else warn "Corsy wrapper not found on PATH"; FAILED+=("corsy"); fi
fi

# favfreak — git clone, python script
if have favfreak; then
  ok "favfreak already installed, skipping"; INSTALLED+=("favfreak")
else
  log "Installing favfreak (git clone)..."
  git clone -q https://github.com/devanshbatham/FavFreak.git "$TOOLS_DIR/FavFreak" 2>/dev/null
  pip3 install --user --break-system-packages mmh3 requests >/dev/null 2>&1
  printf '#!/usr/bin/env bash\npython3 %s/FavFreak/favfreak.py "$@"\n' "$TOOLS_DIR" > "$LOCAL_BIN/favfreak"
  chmod +x "$LOCAL_BIN/favfreak"
  hash -r
  if have favfreak; then ok "favfreak installed (wrapper in $LOCAL_BIN)"; INSTALLED+=("favfreak")
  else warn "favfreak wrapper not found on PATH"; FAILED+=("favfreak"); fi
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
  FAILED+=("dig")
fi

fi # end FULL block

# =========================================================================
# FIX #6: end-of-run summary — one glanceable table instead of scrollback
# =========================================================================
echo ""
log "=== Install summary ==="
ok "Installed/available (${#INSTALLED[@]}): ${INSTALLED[*]:-none}"
if [ "${#FAILED[@]}" -gt 0 ]; then
  err "Failed/missing (${#FAILED[@]}): ${FAILED[*]}"
else
  ok "Nothing failed."
fi
echo ""

# =========================================================================
# FIX #7: persist PATH automatically instead of only printing instructions.
# This is exactly the gap that caused "install.sh says 40/40 installed" in
# one terminal run, immediately followed by "recon.sh says subfinder/
# assetfinder/dnsx not installed" in a separate `bash recon.sh ...` run —
# a child process's `export PATH=...` dies with it; it was never visible to
# any other terminal or script invocation in the first place.
# -------------------------------------------------------------------------
RC_FILE="$HOME/.bashrc"
case "${SHELL:-}" in *zsh*) RC_FILE="$HOME/.zshrc" ;; esac
PATH_LINE="export PATH=\"\$PATH:$GOBIN_DIR:$LOCAL_BIN\""
if [ -f "$RC_FILE" ] && grep -qF "$PATH_LINE" "$RC_FILE" 2>/dev/null; then
  ok "$RC_FILE already has the PATH export — nothing to do."
else
  { echo ""; echo "# Added by recon toolkit install.sh"; echo "$PATH_LINE"; } >> "$RC_FILE"
  ok "Added PATH export to $RC_FILE permanently."
  warn "Still run 'source $RC_FILE' (or open a new terminal) before using recon.sh —"
  warn "a shell that's ALREADY open, like this one, won't pick up an rc-file change on its own."
fi

if [ "$FULL" = false ]; then
  exit 0
fi

echo ""
ok "Full install pass complete."
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
