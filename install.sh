#!/usr/bin/env bash
# ================================================================
#  Bingo Installer — macOS / Linux
#  원클릭: curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
# ================================================================
set -euo pipefail

# ── 색상 ──────────────────────────────────────────────────────────
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

# ── OS 감지 ───────────────────────────────────────────────────────
detect_os() {
    OS="unknown"
    case "$(uname -s)" in
        Darwin) OS="macos" ;;
        Linux)  OS="linux" ;;
        *)      OS="other" ;;
    esac
    info "OS: $OS ($(uname -m))"
}

# ── Python 확인 ───────────────────────────────────────────────────
check_python() {
    step "Python 3.10+ 확인"
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
        warn "Python 3.10+ 를 찾을 수 없습니다. 설치 안내:"
        if [ "$OS" = "macos" ]; then
            info "  brew install python@3.12"
        else
            info "  sudo apt install python3.12   # Debian/Ubuntu"
            info "  sudo dnf install python3.12   # Fedora"
        fi
        err "Python 3.10+ 설치 후 다시 실행하세요"
    fi
}

# ── pip 가용성 확인 ───────────────────────────────────────────────
check_pip() {
    step "pip 확인"
    if ! "$PY" -m pip --version &>/dev/null; then
        warn "pip 없음 — ensurepip으로 설치 시도"
        "$PY" -m ensurepip --upgrade 2>/dev/null || err "pip 설치 실패"
    fi
    ok "pip $(${PY} -m pip --version | awk '{print $2}')"
}

# ── 의존성 설치 ───────────────────────────────────────────────────
install_deps() {
    step "의존성 설치 (rich · prompt_toolkit · httpx · pydantic)"
    "$PY" -m pip install --quiet --upgrade rich prompt_toolkit httpx pydantic hatchling
    ok "의존성 완료"
}

# ── bingo 설치 ───────────────────────────────────────────────────
install_bingo() {
    step "Bingo 설치"
    # curl로 실행한 경우와 git clone 후 실행한 경우 모두 처리
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo ".")"

    if [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
        # git clone된 경우: editable 설치
        "$PY" -m pip install --quiet -e "$SCRIPT_DIR"
    else
        # curl pipe 경우: PyPI에서 설치
        "$PY" -m pip install --quiet bingo-ai
    fi
    ok "설치 완료"
}

# ── PATH 자동 등록 ────────────────────────────────────────────────
setup_path() {
    step "PATH 설정"
    SCRIPTS=$("$PY" -c "import sysconfig; print(sysconfig.get_path('scripts'))")

    if echo "$PATH" | grep -q "$SCRIPTS"; then
        ok "PATH 이미 설정됨 ($SCRIPTS)"
        return
    fi

    # 셸별 rc 파일 감지
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
        ok "이미 $SHELL_RC 에 등록됨"
    else
        echo "" >> "$SHELL_RC"
        echo "# Bingo AI Terminal" >> "$SHELL_RC"
        echo "$EXPORT_LINE" >> "$SHELL_RC"
        warn "PATH를 $SHELL_RC 에 추가했습니다"
        info "새 터미널을 열거나: source $SHELL_RC"
    fi

    # 현재 세션에도 적용
    export PATH="$PATH:$SCRIPTS"
}

# ── 설치 확인 ─────────────────────────────────────────────────────
verify() {
    step "설치 확인"
    if command -v bingo &>/dev/null; then
        VER=$(bingo --version 2>/dev/null || echo "?")
        ok "bingo $VER → $(command -v bingo)"
    else
        warn "'bingo' 명령어를 찾을 수 없습니다"
        info "새 터미널을 열고 다시 시도하세요"
        info "또는: $SCRIPTS/bingo"
    fi
}

# ── 메인 ─────────────────────────────────────────────────────────
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

echo ""
echo -e "${GREEN}  ══════════════════════════════════════${RESET}"
echo -e "${GREEN}  설치 완료!${RESET}"
echo ""
echo -e "${BOLD}${GREEN}    bingo${RESET}"
echo ""
echo -e "${DIM}  첫 실행 시 언어와 AI 모델을 설정합니다${RESET}"
echo -e "${GREEN}  ══════════════════════════════════════${RESET}"
echo ""
