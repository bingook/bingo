"""
Tool Registry — 설치된 외부 도구를 자동 감지하고 경로를 반환
외부 도구가 없어도 Python 내장 구현으로 fallback
"""
from __future__ import annotations
import shutil
import subprocess
import sys
from dataclasses import dataclass


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
        path = shutil.which(name)
        version = ""

        if path:
            try:
                flag = info.get("version_flag", "--version")
                out = subprocess.run(
                    [path, flag],
                    capture_output=True, text=True, timeout=5
                )
                raw = (out.stdout or out.stderr or "").strip()
                version = raw.split("\n")[0][:60]
            except Exception:
                version = "unknown"

        result = ToolInfo(
            name=name,
            path=path,
            version=version,
            available=path is not None,
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
