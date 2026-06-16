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

# ── 4+5. Python으로 직접 설치 (PowerShell pip 오류 완전 우회) ─────
Step "Installing bingo and dependencies..."

# Python 스크립트로 pip 실행 — NativeCommandError 발생 안 함
$installPy = @"
import subprocess, sys, os

deps = ['rich', 'prompt_toolkit', 'httpx', 'pydantic', 'openai', 'anthropic']
dest = r'$dest'

for d in deps:
    print(f'  {d}...', end='', flush=True)
    r = subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '-q', d],
        capture_output=True, text=True
    )
    print(' OK' if r.returncode == 0 else ' (warn)')

print('  bingo...', end='', flush=True)
r = subprocess.run(
    [sys.executable, '-m', 'pip', 'install', '-q', '-e', dest],
    capture_output=True, text=True
)
if r.returncode != 0:
    r = subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '-q', dest],
        capture_output=True, text=True
    )
print(' OK' if r.returncode == 0 else ' (warn)')
"@

# 임시 파일로 저장 후 실행
$tmpPy = "$env:TEMP\bingo_install_deps.py"
$installPy | Out-File -FilePath $tmpPy -Encoding UTF8
& $py $tmpPy
Remove-Item $tmpPy -Force -ErrorAction SilentlyContinue
OK "Installation complete"

# ── 6. PATH 등록 ──────────────────────────────────────────────────
Step "Configuring PATH..."
try {
    $scripts = (& $py -c "import sysconfig; print(sysconfig.get_path('scripts'))") | Out-String
    $scripts = $scripts.Trim()
    $up = [Environment]::GetEnvironmentVariable("PATH","User")
    if ($up -notlike "*$scripts*") {
        [Environment]::SetEnvironmentVariable("PATH","$up;$scripts","User")
        $env:PATH += ";$scripts"
        OK "Added to PATH: $scripts"
    } else { OK "PATH already set" }
} catch { Warn "PATH config failed — run: python -m bingo" }

# ── EXE Phase 0 deps — Playwright 스타일 자동 설치 ───────────────
Write-Host ""
Write-Host "  ===========================================" -ForegroundColor Cyan
Write-Host "  EXE Phase 0 — Windows PE Analysis Libs" -ForegroundColor Cyan
Write-Host "  pefile · lief · yara-python · ssdeep · requests" -ForegroundColor DarkGray
Write-Host "  Used for static analysis of EXE/DLL/SYS files" -ForegroundColor DarkGray
Write-Host "  ===========================================" -ForegroundColor Cyan
Write-Host ""

$exePy = @"
import subprocess, sys, importlib

# (pip_name, import_name, required)
EXE_DEPS = [
    ("pefile",      "pefile",   True),
    ("lief",        "lief",     False),
    ("yara-python", "yara",     False),
    ("ssdeep",      "ssdeep",   False),
    ("requests",    "requests", False),
]

needs_install = []
for pip_name, imp, req in EXE_DEPS:
    try:
        importlib.import_module(imp)
        print(f'    OK  already installed  {pip_name}')
    except ImportError:
        tag = '(required)' if req else '(optional)'
        print(f'    --  will install       {pip_name}  {tag}')
        needs_install.append((pip_name, imp, req))

if not needs_install:
    print()
    print('    All EXE Phase 0 dependencies already installed!')
    sys.exit(0)

print()
for pip_name, imp, req in needs_install:
    print(f'    >> Installing {pip_name} ...', end='', flush=True)
    r = subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '-q', pip_name],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        print(f'\r    OK  Installed   {pip_name}              ')
    else:
        if req:
            print(f'\r    X   Failed (required): {pip_name}')
        else:
            print(f'\r    !   Failed (optional): {pip_name} -- skipping')

print()
print('  EXE Phase 0 status:')
for pip_name, imp, req in EXE_DEPS:
    try:
        importlib.import_module(imp)
        print(f'    [OK] {pip_name}')
    except ImportError:
        tag = 'MISSING (required)' if req else 'not installed (optional)'
        print(f'    [--] {pip_name}  <- {tag}')
"@

$tmpExePy = "$env:TEMP\bingo_exe_deps.py"
$exePy | Out-File -FilePath $tmpExePy -Encoding UTF8
& $py $tmpExePy
Remove-Item $tmpExePy -Force -ErrorAction SilentlyContinue
OK "EXE Phase 0 dependency check complete"

# ── Playwright 선택 설치 ──────────────────────────────────────────
Write-Host ""
Write-Host "  ===========================================" -ForegroundColor Cyan
Write-Host "  Optional: Playwright (JS rendering recon)" -ForegroundColor Cyan
Write-Host "  Enables recon on JavaScript-heavy / SPA sites" -ForegroundColor DarkGray
Write-Host "  Requires ~150MB Chromium download" -ForegroundColor DarkGray
Write-Host "  ===========================================" -ForegroundColor Cyan
Write-Host ""
$pwAnswer = Read-Host "  Install Playwright? [y/N]"
if ($pwAnswer -match '^[yY]') {
    Step "Installing Playwright..."
    $pwPy = @"
import subprocess, sys
print('  Installing playwright package...')
r1 = subprocess.run([sys.executable, '-m', 'pip', 'install', 'playwright', '-q'],
    capture_output=True, text=True)
print('  OK' if r1.returncode == 0 else f'  pip warn: {r1.stderr[:100]}')

print('  Downloading Chromium (~150MB)...')
r2 = subprocess.run([sys.executable, '-m', 'playwright', 'install', 'chromium'],
    capture_output=True, text=True)
print('  Chromium OK' if r2.returncode == 0 else f'  chromium warn: {r2.stderr[:100]}')
"@
    $tmpPw = "$env:TEMP\bingo_playwright.py"
    $pwPy | Out-File -FilePath $tmpPw -Encoding UTF8
    & $py $tmpPw
    Remove-Item $tmpPw -Force -ErrorAction SilentlyContinue
    OK "Playwright installed"
} else {
    Write-Host "  Skipped. Bingo will auto-install when needed." -ForegroundColor DarkGray
    Write-Host "  Manual: pip install playwright && playwright install chromium" -ForegroundColor DarkGray
}

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
