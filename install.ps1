# ================================================================
#  Bingo Installer for Windows (PowerShell)
#  Usage: iwr -useb https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
# ================================================================
$ErrorActionPreference = "Stop"

$GREEN  = "`e[32m"
$CYAN   = "`e[36m"
$YELLOW = "`e[33m"
$RED    = "`e[31m"
$DIM    = "`e[2m"
$BOLD   = "`e[1m"
$RESET  = "`e[0m"

function Write-Banner {
    Write-Host ""
    Write-Host "$GREEN  ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗  $RESET"
    Write-Host "$GREEN  ██╔══██╗██║████╗  ██║██╔════╝ ██╔═══██╗ $RESET"
    Write-Host "$GREEN  ██████╔╝██║██╔██╗ ██║██║  ███╗██║   ██║ $RESET"
    Write-Host "$GREEN  ██╔══██╗██║██║╚██╗██║██║   ██║██║   ██║ $RESET"
    Write-Host "$GREEN  ██████╔╝██║██║ ╚████║╚██████╔╝╚██████╔╝ $RESET"
    Write-Host "$GREEN  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝  $RESET"
    Write-Host "$CYAN  AI Terminal  ·  v0.1.0  ·  Multi-Model $RESET"
    Write-Host ""
}

function Write-Step  { param($msg) Write-Host "$GREEN▸$RESET $BOLD$msg$RESET" }
function Write-Ok    { param($msg) Write-Host "$GREEN  ✔  $msg$RESET" }
function Write-Warn  { param($msg) Write-Host "$YELLOW  ⚠  $msg$RESET" }
function Write-Err   { param($msg) Write-Host "$RED  ✖  $msg$RESET"; exit 1 }
function Write-Info  { param($msg) Write-Host "$DIM  $msg$RESET" }

# ── Python 확인 ───────────────────────────────────────────────────
function Check-Python {
    Write-Step "Python 3.10+ 확인"
    try {
        $ver = python --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
                Write-Err "Python 3.10 이상 필요 (현재 $ver)"
            }
            Write-Ok "$ver"
        } else {
            Write-Err "Python 버전을 확인할 수 없습니다"
        }
    } catch {
        Write-Err "Python이 설치되어 있지 않습니다. https://python.org 에서 설치하세요."
    }
}

# ── pip 의존성 설치 ───────────────────────────────────────────────
function Install-Deps {
    Write-Step "의존성 설치 (rich, prompt_toolkit, httpx, pydantic)"
    pip install --quiet rich prompt_toolkit httpx pydantic hatchling
    if ($LASTEXITCODE -ne 0) { Write-Err "의존성 설치 실패" }
    Write-Ok "의존성 설치 완료"
}

# ── bingo 설치 ───────────────────────────────────────────────────
function Install-Bingo {
    Write-Step "Bingo 설치"
    $ScriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $ScriptDir) { $ScriptDir = Get-Location }
    pip install --quiet -e $ScriptDir
    if ($LASTEXITCODE -ne 0) { Write-Err "Bingo 설치 실패" }
    Write-Ok "bingo 명령어 등록 완료"
}

# ── PATH 확인 및 등록 ─────────────────────────────────────────────
function Check-Path {
    Write-Step "PATH 확인"
    $scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    if ($currentPath -notlike "*$scripts*") {
        Write-Warn "PATH에 $scripts 를 추가합니다"
        [Environment]::SetEnvironmentVariable(
            "PATH",
            "$currentPath;$scripts",
            "User"
        )
        $env:PATH += ";$scripts"
        Write-Ok "PATH 등록 완료 (새 터미널에서 적용됩니다)"
    } else {
        Write-Ok "PATH 이미 설정됨"
    }
}

# ── 메인 ─────────────────────────────────────────────────────────
Clear-Host
Write-Banner
Write-Host "$CYAN  Windows Installer$RESET`n"

Check-Python
Install-Deps
Install-Bingo
Check-Path

Write-Host ""
Write-Host "$GREEN  ══════════════════════════════════════$RESET"
Write-Host "$GREEN  설치 완료! 새 터미널에서 실행하세요:$RESET"
Write-Host ""
Write-Host "$BOLD$GREEN    bingo$RESET"
Write-Host ""
Write-Host "$GREEN  ══════════════════════════════════════$RESET"
Write-Host ""
