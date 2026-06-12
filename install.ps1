# ================================================================
#  Bingo Windows Installer
#  PowerShell 5.1+  (NOT CMD)
#
#  irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
# ================================================================

# pip stderr를 에러로 처리하지 않음
$ErrorActionPreference = "Continue"

function Step  { Write-Host "`n>> $args" -ForegroundColor Cyan }
function OK    { Write-Host "  [OK] $args" -ForegroundColor Green }
function Warn  { Write-Host "  [!!] $args" -ForegroundColor Yellow }
function Fail  { Write-Host "  [X]  $args" -ForegroundColor Red; Read-Host "Press Enter"; exit 1 }

Clear-Host
Write-Host ""
Write-Host "  BINGO - AI Pentest Agent" -ForegroundColor Green
Write-Host "  Windows Installer" -ForegroundColor Cyan
Write-Host ""

# ── 1. Python 확인 ────────────────────────────────────────────────
Step "Checking Python..."
$py = $null
foreach ($cmd in "python","python3","py") {
    try {
        $v = & $cmd --version 2>&1
        if ("$v" -match "Python 3\.(\d+)" -and [int]$Matches[1] -ge 10) {
            $py = $cmd; OK "$v  ($cmd)"; break
        }
    } catch {}
}
if (-not $py) { Fail "Python 3.10+ not found. Get it from https://python.org/downloads/" }

# ── 2. pip 확인 ───────────────────────────────────────────────────
Step "Checking pip..."
$pip = $null
foreach ($cmd in "pip","pip3") {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) { $pip = $cmd; break }
}
if (-not $pip) { $pip = "$py -m pip" }
OK "pip: $pip"

# ── 3. bingo 소스 다운로드 ────────────────────────────────────────
Step "Downloading bingo..."
$dest = "$env:USERPROFILE\bingo"

if (Test-Path "$dest\pyproject.toml") {
    OK "Already exists at $dest — skipping download"
} else {
    # git 시도
    $gitOk = $false
    if (Get-Command git -ErrorAction SilentlyContinue) {
        git clone --quiet https://github.com/bingook/bingo.git "$dest" 2>&1 | Out-Null
        $gitOk = (Test-Path "$dest\pyproject.toml")
    }

    # git 없거나 실패 → zip 다운로드
    if (-not $gitOk) {
        Warn "git not found, using zip download..."
        $zip = "$env:TEMP\bingo_install.zip"
        Invoke-WebRequest `
            "https://github.com/bingook/bingo/archive/refs/heads/main.zip" `
            -OutFile $zip -UseBasicParsing
        if (Test-Path "$env:USERPROFILE\bingo-main") {
            Remove-Item "$env:USERPROFILE\bingo-main" -Recurse -Force
        }
        Expand-Archive $zip "$env:USERPROFILE" -Force
        Rename-Item "$env:USERPROFILE\bingo-main" "$dest"
        Remove-Item $zip -Force
    }

    if (-not (Test-Path "$dest\pyproject.toml")) {
        Fail "Download failed. Try manually: git clone https://github.com/bingook/bingo.git"
    }
    OK "Downloaded to $dest"
}

# ── 4. 의존성 설치 ────────────────────────────────────────────────
Step "Installing dependencies..."
$deps = @("rich","prompt_toolkit","httpx","pydantic","openai","anthropic")
foreach ($d in $deps) {
    Write-Host "  Installing $d..." -NoNewline
    # cmd /c 로 실행 — PowerShell NativeCommandError 완전 우회
    cmd /c "`"$py`" -m pip install -q $d" 2>$null | Out-Null
    Write-Host " OK" -ForegroundColor Green
}

# ── 5. bingo 설치 ─────────────────────────────────────────────────
Step "Installing bingo..."
Set-Location $dest
cmd /c "`"$py`" -m pip install -q -e ." 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Warn "editable failed, trying regular install..."
    cmd /c "`"$py`" -m pip install -q ." 2>$null | Out-Null
}
OK "bingo installed"

# ── 6. PATH 등록 ──────────────────────────────────────────────────
Step "Configuring PATH..."
try {
    $scripts = cmd /c "`"$py`" -c `"import sysconfig; print(sysconfig.get_path('scripts'))`"" 2>$null
    $up = [Environment]::GetEnvironmentVariable("PATH","User")
    if ($up -notlike "*$scripts*") {
        [Environment]::SetEnvironmentVariable("PATH","$up;$scripts","User")
        $env:PATH += ";$scripts"
        OK "Added to PATH: $scripts"
    } else { OK "PATH already set" }
} catch { Warn "PATH config failed — run: python -m bingo" }

# ── 완료 ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ===========================================" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run:  bingo" -ForegroundColor Cyan
Write-Host "  Or:   python -m bingo" -ForegroundColor Cyan
Write-Host ""
Write-Host "  (If 'bingo' not found, restart PowerShell)" -ForegroundColor Yellow
Write-Host "  ===========================================" -ForegroundColor Green
Write-Host ""
