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
    Write-Host "$CYAN  AI Terminal  ·  v1.0.0  ·  Multi-Model $RESET"
    Write-Host ""
}

function Write-Step  { param($msg) Write-Host "$GREEN▸$RESET $BOLD$msg$RESET" }
function Write-Ok    { param($msg) Write-Host "$GREEN  ✔  $msg$RESET" }
function Write-Warn  { param($msg) Write-Host "$YELLOW  ⚠  $msg$RESET" }
function Write-Err   { param($msg) Write-Host "$RED  ✖  $msg$RESET"; exit 1 }
function Write-Info  { param($msg) Write-Host "$DIM  $msg$RESET" }

function Check-Python {
    Write-Step "Checking Python 3.10+"
    try {
        $ver = python --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
                Write-Err "Python 3.10+ required (found $ver)"
            }
            Write-Ok "$ver"
        } else {
            Write-Err "Could not detect Python version"
        }
    } catch {
        Write-Err "Python not found. Install it from https://python.org"
    }
}

function Get-PipCmd {
    # pip / pip3 / python -m pip 순서로 작동하는 명령 반환
    foreach ($cmd in @("pip", "pip3")) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) {
            return $cmd
        }
    }
    return $null  # python -m pip 폴백
}

function Invoke-Pip {
    param([string[]]$Args)
    $pip = Get-PipCmd
    if ($pip) {
        & $pip @Args
    } else {
        python -m pip @Args
    }
    return $LASTEXITCODE
}

function Install-Deps {
    Write-Step "Installing dependencies (rich, prompt_toolkit, httpx, pydantic)"
    Invoke-Pip @("install", "--quiet", "rich", "prompt_toolkit", "httpx", "pydantic", "hatchling")
    if ($LASTEXITCODE -ne 0) { Write-Err "Dependency installation failed" }
    Write-Ok "Dependencies installed"
}

function Install-Bingo {
    Write-Step "Installing Bingo"
    $ScriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $ScriptDir) { $ScriptDir = Get-Location }
    Invoke-Pip @("install", "--quiet", "-e", "$ScriptDir")
    if ($LASTEXITCODE -ne 0) { Write-Err "Bingo installation failed" }
    Write-Ok "Bingo installed successfully"
}


function Check-Path {
    Write-Step "Setting up PATH"
    $scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    if ($currentPath -notlike "*$scripts*") {
        Write-Warn "Adding $scripts to PATH"
        [Environment]::SetEnvironmentVariable(
            "PATH",
            "$currentPath;$scripts",
            "User"
        )
        $env:PATH += ";$scripts"
        Write-Ok "PATH updated (restart terminal to apply)"
    } else {
        Write-Ok "PATH already set"
    }
}

Clear-Host
Write-Banner
Write-Host "$CYAN  Windows Installer$RESET`n"

Check-Python
Install-Deps
Install-Bingo
Check-Path

Write-Host ""
Write-Host "$GREEN  ══════════════════════════════════════$RESET"
Write-Host "$GREEN  Installation complete!$RESET"
Write-Host ""
Write-Host "$BOLD$GREEN    bingo$RESET"
Write-Host ""
Write-Host "$DIM  Run 'bingo' to get started$RESET"
Write-Host "$GREEN  ══════════════════════════════════════$RESET"
Write-Host ""
