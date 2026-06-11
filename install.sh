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
    step "Installing dependencies (rich · prompt_toolkit · httpx · pydantic)"
    "$PY" -m pip install --quiet --upgrade rich prompt_toolkit httpx pydantic hatchling
    ok "Dependencies installed"
}

pip_install() {
    # pip / pip3 / python -m pip 순서로 시도
    local pkg="$1"
    if "$PY" -m pip install --quiet "$pkg" 2>/dev/null; then
        return 0
    fi
    warn "pip install failed for $pkg — using vendor fallback"
    return 1
}

install_security_tools() {
    step "Installing security tools (sqlmap · wafw00f)"
    # sqlmap
    if ! command -v sqlmap &>/dev/null; then
        pip_install sqlmap && ok "sqlmap installed" || ok "sqlmap — using vendor fallback"
    else
        ok "sqlmap already installed ($(sqlmap --version 2>/dev/null | head -1))"
    fi
    # wafw00f
    if ! command -v wafw00f &>/dev/null; then
        pip_install wafw00f && ok "wafw00f installed" || ok "wafw00f — using vendor fallback"
    else
        ok "wafw00f already installed"
    fi
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
install_security_tools
setup_path
verify

echo ""
echo -e "${GREEN}  ══════════════════════════════════════${RESET}"
echo -e "${GREEN}  Installation complete!${RESET}"
echo ""
echo -e "${BOLD}${GREEN}    bingo${RESET}"
echo ""
echo -e "${DIM}  Run 'bingo' to get started${RESET}"
echo -e "${GREEN}  ══════════════════════════════════════${RESET}"
echo ""
