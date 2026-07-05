"""
Tool Registry — 설치된 외부 도구를 자동 감지하고 경로를 반환
우선순위:
  1. vendor/ 폴더 내장 버전 (sqlmap, wafw00f)
  2. ~/.bingo/tools/ (Go 바이너리 자동 다운로드 위치)
  3. 시스템 PATH에 설치된 버전
  4. 없으면 설치 힌트 표시
"""
from __future__ import annotations
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# bingo 패키지 루트 기준 vendor 폴더
_VENDOR_DIR = Path(__file__).parent.parent.parent / "vendor"
_SQLMAP_PY  = _VENDOR_DIR / "sqlmap" / "sqlmap.py"
_WAFW00F_PY = _VENDOR_DIR / "wafw00f" / "wafw00f" / "main.py"

# 자동 다운로드된 Go 바이너리 위치
_BINGO_TOOLS_DIR = Path.home() / ".bingo" / "tools"


def _find_binary(name: str) -> str | None:
    """~/.bingo/tools/ → 시스템 PATH 순서로 바이너리 탐색"""
    local = _BINGO_TOOLS_DIR / name
    if local.exists():
        return str(local)
    # Windows
    local_exe = _BINGO_TOOLS_DIR / f"{name}.exe"
    if local_exe.exists():
        return str(local_exe)
    return shutil.which(name)


def _try_python_module(module: str) -> bool:
    """python3 -m <module> --version 이 성공하는지 확인"""
    try:
        r = subprocess.run(
            [sys.executable, "-m", module, "--version"],
            capture_output=True, timeout=8,
        )
        return r.returncode == 0
    except Exception:
        return False


def get_sqlmap_cmd() -> list[str]:
    """sqlmap 실행 명령 자동 탐색 — 모든 설치 방식 지원.

    탐색 순서:
      1. vendor/sqlmap/sqlmap.py  (bingo 내장)
      2. shutil.which("sqlmap")   (PATH: pip install sqlmap / brew / apt → console_scripts)
      3. ~/.local/bin/sqlmap      (pip install --user on Linux)
      4. python3 -m sqlmap        (pip install sqlmap → 모듈만 설치된 경우)
      5. 알려진 경로의 sqlmap.py  (git clone 위치들)
         - /usr/share/sqlmap/sqlmap.py          (Kali: apt install sqlmap)
         - /usr/local/share/sqlmap/sqlmap.py
         - /opt/sqlmap/sqlmap.py
         - ~/sqlmap/sqlmap.py
         - ~/tools/sqlmap/sqlmap.py
         - ~/.local/share/sqlmap/sqlmap.py
         - /opt/homebrew/opt/sqlmap/libexec/sqlmap.py  (macOS Homebrew)
    """
    # 1. vendor 내장 (bingo 패키지 동봉 버전)
    if _SQLMAP_PY.exists():
        return [sys.executable, str(_SQLMAP_PY)]

    # 2. 시스템 PATH — pip/brew/apt 가 생성하는 console_scripts
    path = shutil.which("sqlmap")
    if path:
        return [path]

    # 3. pip install --user on Linux → ~/.local/bin/sqlmap
    local_bin = Path.home() / ".local" / "bin" / "sqlmap"
    if local_bin.exists():
        return [str(local_bin)]

    # 4. python3 -m sqlmap (패키지만 설치, 스크립트 미생성)
    if _try_python_module("sqlmap"):
        return [sys.executable, "-m", "sqlmap"]

    # 5. 알려진 경로의 sqlmap.py
    _known: list[Path] = [
        Path("/usr/share/sqlmap/sqlmap.py"),           # Kali Linux apt
        Path("/usr/local/share/sqlmap/sqlmap.py"),
        Path("/opt/sqlmap/sqlmap.py"),
        Path.home() / "sqlmap" / "sqlmap.py",          # git clone ~/sqlmap
        Path.home() / "tools" / "sqlmap" / "sqlmap.py",
        Path.home() / ".local" / "share" / "sqlmap" / "sqlmap.py",
        Path("/opt/homebrew/opt/sqlmap/libexec/sqlmap.py"),  # macOS Homebrew
        Path("/opt/homebrew/share/sqlmap/sqlmap.py"),
        Path.home() / "Desktop" / "sqlmap" / "sqlmap.py",
        Path.home() / "Downloads" / "sqlmap" / "sqlmap.py",
    ]
    for p in _known:
        if p.exists():
            return [sys.executable, str(p)]

    return []  # 미설치 → 빈 리스트


def get_wafw00f_cmd() -> list[str]:
    """wafw00f 실행 명령 자동 탐색.

    탐색 순서:
      1. vendor/wafw00f/wafw00f/main.py  (bingo 내장)
      2. shutil.which("wafw00f")
      3. ~/.local/bin/wafw00f
      4. python3 -m wafw00f
    """
    if _WAFW00F_PY.exists():
        return [sys.executable, str(_WAFW00F_PY)]
    path = shutil.which("wafw00f")
    if path:
        return [path]
    local_bin = Path.home() / ".local" / "bin" / "wafw00f"
    if local_bin.exists():
        return [str(local_bin)]
    if _try_python_module("wafw00f"):
        return [sys.executable, "-m", "wafw00f"]
    return []


def get_tool_cmd(name: str) -> list[str]:
    """범용 도구 명령 탐색 — sqlmap/wafw00f 외 나머지 도구들.

    탐색 순서:
      1. shutil.which(name)          → 시스템 PATH
      2. ~/.bingo/tools/<name>       → bingo 자동 다운로드 위치
      3. ~/.local/bin/<name>         → pip install --user / manual
      4. /usr/local/bin/<name>
      5. /opt/homebrew/bin/<name>    → macOS Homebrew
      6. ~/go/bin/<name>             → go install ...
      7. ~/tools/<name>              → 수동 설치 ~/tools
    """
    # 1. 시스템 PATH (가장 일반적)
    p = shutil.which(name)
    if p:
        return [p]

    _candidates: list[Path] = [
        _BINGO_TOOLS_DIR / name,
        _BINGO_TOOLS_DIR / f"{name}.exe",          # Windows
        Path.home() / ".local" / "bin" / name,
        Path("/usr/local/bin") / name,
        Path("/opt/homebrew/bin") / name,           # macOS Homebrew
        Path.home() / "go" / "bin" / name,          # go install
        Path.home() / "tools" / name,
        Path.home() / ".cargo" / "bin" / name,      # Rust cargo install
        Path("/usr/bin") / name,
    ]
    for candidate in _candidates:
        if candidate.exists():
            return [str(candidate)]
    return []


@dataclass
class ToolInfo:
    name: str
    path: str | None
    version: str
    available: bool
    install_hint: str


# ── 지원하는 외부 도구 목록 ──────────────────────────────────────
_TOOLS: dict[str, dict] = {
    # 정찰
    "nmap": {
        "hint": "brew install nmap  /  apt install nmap  /  choco install nmap",
        "version_flag": "--version",
    },
    "subfinder": {
        "hint": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "version_flag": "-version",
    },
    "amass": {
        "hint": "go install github.com/owasp-amass/amass/v4/...@master",
        "version_flag": "version",
    },
    "whatweb": {
        "hint": "gem install whatweb  /  apt install whatweb",
        "version_flag": "--version",
    },
    "wafw00f": {
        "hint": "pip install wafw00f",
        "version_flag": "--version",
    },
    # 스캔
    "nuclei": {
        "hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "version_flag": "-version",
    },
    "httpx": {
        "hint": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "version_flag": "-version",
    },
    "nikto": {
        "hint": "apt install nikto  /  brew install nikto",
        "version_flag": "-Version",
    },
    # 익스플로잇
    "sqlmap": {
        "hint": "pip install sqlmap  /  apt install sqlmap",
        "version_flag": "--version",
    },
    "ffuf": {
        "hint": "go install github.com/ffuf/ffuf/v2@latest",
        "version_flag": "-V",
    },
    "gobuster": {
        "hint": "go install github.com/OJ/gobuster/v3@latest",
        "version_flag": "version",
    },
    # 기타
    "curl": {
        "hint": "기본 설치됨",
        "version_flag": "--version",
    },
    "python3": {
        "hint": "기본 설치됨",
        "version_flag": "--version",
    },
}


class ToolRegistry:
    _cache: dict[str, ToolInfo] = {}

    @classmethod
    def probe(cls, name: str) -> ToolInfo:
        if name in cls._cache:
            return cls._cache[name]

        info = _TOOLS.get(name, {"hint": "", "version_flag": "--version"})

        # 도구별 전용 탐색기 사용 (모든 설치 방식 커버)
        if name == "sqlmap":
            cmd = get_sqlmap_cmd()
        elif name == "wafw00f":
            cmd = get_wafw00f_cmd()
        else:
            cmd = get_tool_cmd(name)

        path = cmd[-1] if cmd else None
        version = ""

        if cmd:
            try:
                flag = info.get("version_flag", "--version")
                out = subprocess.run(
                    cmd + [flag],
                    capture_output=True, text=True, timeout=5
                )
                raw = (out.stdout or out.stderr or "").strip()
                version = raw.split("\n")[0][:60]
            except Exception:
                version = "installed"

        result = ToolInfo(
            name=name,
            path=path,
            version=version,
            available=bool(cmd),
            install_hint=info.get("hint", ""),
        )
        cls._cache[name] = result
        return result

    @classmethod
    def available(cls, name: str) -> bool:
        return cls.probe(name).available

    @classmethod
    def scan_all(cls) -> dict[str, ToolInfo]:
        return {name: cls.probe(name) for name in _TOOLS}

    @classmethod
    def available_tools(cls) -> list[str]:
        return [n for n in _TOOLS if cls.probe(n).available]

    @classmethod
    def missing_tools(cls) -> list[ToolInfo]:
        return [cls.probe(n) for n in _TOOLS if not cls.probe(n).available]
