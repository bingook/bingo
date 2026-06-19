#!/usr/bin/env bash
# ================================================================
#  Bingo Installer — macOS / Linux
#  One-liner: curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
# ================================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
cat << 'BANNER'

  ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗ 
  ██╔══██╗██║████╗  ██║██╔════╝ ██╔═══██╗
  ██████╔╝██║██╔██╗ ██║██║  ███╗██║   ██║
  ██╔══██╗██║██║╚██╗██║██║   ██║██║   ██║
  ██████╔╝██║██║ ╚████║╚██████╔╝╚██████╔╝
  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝

BANNER
}

step() { echo -e "${GREEN}▸${RESET} ${BOLD}$*${RESET}"; }
ok()   { echo -e "${GREEN}  ✔  $*${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠  $*${RESET}"; }
err()  { echo -e "${RED}  ✖  $*${RESET}"; exit 1; }
info() { echo -e "${DIM}  $*${RESET}"; }

detect_os() {
    OS="unknown"
    case "$(uname -s)" in
        Darwin) OS="macos" ;;
        Linux)  OS="linux" ;;
        *)      OS="other" ;;
    esac
    info "OS: $OS ($(uname -m))"
}

check_python() {
    step "Checking Python 3.10+"
    PY=""
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null)
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "${major:-0}" -ge 3 ] && [ "${minor:-0}" -ge 10 ]; then
                PY="$cmd"
                ok "Python $ver ($cmd)"
                break
            fi
        fi
    done

    if [ -z "$PY" ]; then
        warn "Python 3.10+ not found. Install it first:"
        if [ "$OS" = "macos" ]; then
            info "  brew install python@3.12"
        else
            info "  sudo apt install python3.12   # Debian/Ubuntu"
            info "  sudo dnf install python3.12   # Fedora"
        fi
        err "Please install Python 3.10+ and run this script again"
    fi
}

check_pip() {
    step "Checking pip"
    if ! "$PY" -m pip --version &>/dev/null; then
        warn "pip not found — trying ensurepip"
        "$PY" -m ensurepip --upgrade 2>/dev/null || err "Failed to install pip"
    fi
    ok "pip $(${PY} -m pip --version | awk '{print $2}')"
}

install_deps() {
    step "Installing dependencies..."
    "$PY" -m pip install --quiet --upgrade \
        rich prompt_toolkit httpx pydantic \
        requests urllib3 beautifulsoup4 lxml \
        chardet charset-normalizer fake-useragent \
        python-dotenv PyJWT cryptography dnspython \
        colorama tldextract html5lib cssselect \
        aiohttp certifi hatchling
    ok "Dependencies installed"
}

install_bingo() {
    step "Installing Bingo"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo ".")"

    if [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
        "$PY" -m pip install --quiet -e "$SCRIPT_DIR"
    else
        "$PY" -m pip install --quiet bingo-ai
    fi
    ok "Bingo installed"
}

setup_path() {
    step "Setting up PATH"
    SCRIPTS=$("$PY" -c "import sysconfig; print(sysconfig.get_path('scripts'))")

    if echo "$PATH" | grep -q "$SCRIPTS"; then
        ok "PATH already set ($SCRIPTS)"
        return
    fi

    SHELL_RC=""
    SHELL_NAME="$(basename "${SHELL:-bash}")"
    case "$SHELL_NAME" in
        zsh)  SHELL_RC="$HOME/.zshrc" ;;
        bash) SHELL_RC="${BASH_PROFILE:-$HOME/.bashrc}" ;;
        fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
        *)    SHELL_RC="$HOME/.profile" ;;
    esac

    EXPORT_LINE="export PATH=\"\$PATH:$SCRIPTS\""
    if [ "$SHELL_NAME" = "fish" ]; then
        EXPORT_LINE="set -gx PATH \$PATH $SCRIPTS"
    fi

    if [ -f "$SHELL_RC" ] && grep -q "$SCRIPTS" "$SHELL_RC" 2>/dev/null; then
        ok "Already registered in $SHELL_RC"
    else
        echo "" >> "$SHELL_RC"
        echo "# Bingo AI Terminal" >> "$SHELL_RC"
        echo "$EXPORT_LINE" >> "$SHELL_RC"
        warn "PATH added to $SHELL_RC"
        info "Open a new terminal or run: source $SHELL_RC"
    fi

    export PATH="$PATH:$SCRIPTS"
}

verify() {
    step "Verifying installation"
    if command -v bingo &>/dev/null; then
        VER=$(bingo --version 2>/dev/null || echo "?")
        ok "bingo $VER → $(command -v bingo)"
    else
        warn "'bingo' command not found"
        info "Open a new terminal and try again"
        info "Or run directly: $SCRIPTS/bingo"
    fi
}

clear
echo -e "${GREEN}$(banner)${RESET}"
echo -e "${CYAN}  macOS / Linux Installer${RESET}"
echo ""

detect_os
check_python
check_pip
install_deps
install_bingo
setup_path
verify

# ── EXE Phase 0 deps — Playwright 스타일 자동 설치 ──────────────
echo ""
echo -e "${CYAN}  ══════════════════════════════════════${RESET}"
echo -e "${CYAN}  EXE Phase 0 — Windows PE Analysis Libs${RESET}"
echo -e "${DIM}  pefile · lief · yara-python · ssdeep · requests${RESET}"
echo -e "${DIM}  Used for static analysis of EXE/DLL/SYS files${RESET}"
echo -e "${CYAN}  ══════════════════════════════════════${RESET}"
echo ""

# Playwright 스타일: 이미 설치된 항목은 표시, 없는 것만 설치
_exe_deps=("pefile:pefile:required" "lief:lief:optional" "yara-python:yara:optional" "ssdeep:ssdeep:optional" "requests:requests:optional")

_all_ok=true
for _entry in "${_exe_deps[@]}"; do
    _pip="${_entry%%:*}"
    _rest="${_entry#*:}"
    _mod="${_rest%%:*}"
    _tag="${_rest#*:}"

    if "$PY" -c "import ${_mod}" &>/dev/null 2>&1; then
        ok "already installed  ${_pip}"
    else
        _all_ok=false
        echo -e "${YELLOW}  📦  will install   ${_pip}  ${DIM}(${_tag})${RESET}"
    fi
done

echo ""

if ! $_all_ok; then
    step "Installing EXE Phase 0 dependencies"
    for _entry in "${_exe_deps[@]}"; do
        _pip="${_entry%%:*}"
        _rest="${_entry#*:}"
        _mod="${_rest%%:*}"
        _tag="${_rest#*:}"

        if "$PY" -c "import ${_mod}" &>/dev/null 2>&1; then
            continue   # already installed
        fi

        printf "    ${YELLOW}📦  Installing${RESET}  %-20s" "${_pip} ..."
        if "$PY" -m pip install --quiet "${_pip}" 2>/dev/null; then
            echo -e "\r    ${GREEN}✅  Installed  ${RESET}  ${_pip}              "
        else
            if [ "${_tag}" = "required" ]; then
                echo -e "\r    ${RED}❌  Failed (required)${RESET}  ${_pip}"
            else
                echo -e "\r    ${YELLOW}⚠   Failed (optional)${RESET}  ${_pip} — skipping"
            fi
        fi
    done
    echo ""
fi

# 최종 상태 표시
echo -e "${DIM}  EXE Phase 0 status:${RESET}"
for _entry in "${_exe_deps[@]}"; do
    _pip="${_entry%%:*}"
    _rest="${_entry#*:}"
    _mod="${_rest%%:*}"
    _tag="${_rest#*:}"
    if "$PY" -c "import ${_mod}" &>/dev/null 2>&1; then
        echo -e "    ${GREEN}✅${RESET}  ${_pip}"
    else
        if [ "${_tag}" = "required" ]; then
            echo -e "    ${RED}❌${RESET}  ${_pip}  ${DIM}← pip install ${_pip}${RESET}"
        else
            echo -e "    ${YELLOW}⚠ ${RESET}  ${_pip}  ${DIM}(optional)${RESET}"
        fi
    fi
done

# ── Playwright 선택 설치 ─────────────────────────────────────────
echo ""
echo -e "${CYAN}  ══════════════════════════════════════${RESET}"
echo -e "${CYAN}  Optional: Playwright (JS rendering)${RESET}"
echo -e "${DIM}  Enables recon on JavaScript-heavy / SPA sites${RESET}"
echo -e "${DIM}  Requires ~150MB Chromium download${RESET}"
echo -e "${CYAN}  ══════════════════════════════════════${RESET}"
echo ""
# 이미 설치 여부 확인
_pw_installed=false
if python3 -c "import playwright" &>/dev/null 2>&1; then
    _pw_installed=true
fi

if $_pw_installed; then
    ok "Playwright already installed — skipping"
else
    read -r -p "  Install Playwright? [y/N] " _pw_answer </dev/tty || _pw_answer=""
    if [[ "${_pw_answer,,}" == "y" ]]; then
        step "Installing Playwright"
        if python3 -m pip install playwright -q; then
            ok "playwright package installed"
        else
            warn "playwright pip install failed"
        fi
        if python3 -m playwright install chromium; then
            ok "Chromium browser installed"
        else
            warn "chromium install failed"
        fi
    else
        info "Skipped. Bingo will auto-install Playwright when needed."
        info "Or install manually: pip install playwright && playwright install chromium"
    fi
fi

echo ""
echo -e "${GREEN}  ══════════════════════════════════════${RESET}"
echo -e "${GREEN}  Installation complete!${RESET}"
echo ""
echo -e "${BOLD}${GREEN}    bingo${RESET}"
echo ""
echo -e "${DIM}  Run 'bingo' to get started${RESET}"
echo -e "${GREEN}  ══════════════════════════════════════${RESET}"
echo ""
