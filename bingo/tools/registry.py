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


def get_sqlmap_cmd() -> list[str]:
    """sqlmap 실행 명령 반환 — vendor 내장 우선, 없으면 시스템 PATH"""
    if _SQLMAP_PY.exists():
        return [sys.executable, str(_SQLMAP_PY)]
    path = shutil.which("sqlmap")
    if path:
        return [path]
    return []


def get_wafw00f_cmd() -> list[str]:
    """wafw00f 실행 명령 반환 — vendor 내장 우선, 없으면 시스템 PATH"""
    if _WAFW00F_PY.exists():
        return [sys.executable, str(_WAFW00F_PY)]
    path = shutil.which("wafw00f")
    if path:
        return [path]
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

        # vendor 내장 버전 우선 확인
        vendor_cmd: list[str] = []
        if name == "sqlmap" and _SQLMAP_PY.exists():
            vendor_cmd = [sys.executable, str(_SQLMAP_PY)]
        elif name == "wafw00f" and _WAFW00F_PY.exists():
            vendor_cmd = [sys.executable, str(_WAFW00F_PY)]

        # ~/.bingo/tools/ → 시스템 PATH 순서
        path = str(vendor_cmd[1]) if vendor_cmd else _find_binary(name)
        version = ""

        cmd = vendor_cmd if vendor_cmd else ([path] if path else [])
        if cmd:
            try:
                flag = info.get("version_flag", "--version")
                out = subprocess.run(
                    cmd + [flag],
                    capture_output=True, text=True, timeout=5
                )
                raw = (out.stdout or out.stderr or "").strip()
                version = ("vendor " if vendor_cmd else "") + raw.split("\n")[0][:50]
            except Exception:
                version = "vendor (embedded)" if vendor_cmd else "unknown"

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
