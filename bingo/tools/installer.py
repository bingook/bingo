"""
installer.py — 패키지 매니저로 도구 자동 설치
brew (macOS) / apt / yum (Linux) / choco (Windows)
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from typing import Callable


def _run(cmd: list[str], log: Callable[[str], None]) -> bool:
    log(f"  실행: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode == 0:
            return True
        log(f"  오류: {(proc.stderr or proc.stdout)[:200]}")
        return False
    except Exception as e:
        log(f"  실패: {e}")
        return False


def _os() -> str:
    s = platform.system().lower()
    return {"darwin": "macos", "linux": "linux", "windows": "windows"}.get(s, s)


def _pip_install(pkg: str, log: Callable[[str], None]) -> bool:
    return _run([sys.executable, "-m", "pip", "install", "--quiet", pkg], log)


def _brew_install(pkg: str, log: Callable[[str], None]) -> bool:
    if not shutil.which("brew"):
        log("  brew 없음")
        return False
    return _run(["brew", "install", "-q", pkg], log)


def _apt_install(pkg: str, log: Callable[[str], None]) -> bool:
    if not shutil.which("apt-get"):
        return False
    return _run(["sudo", "apt-get", "install", "-y", "-q", pkg], log)


def _yum_install(pkg: str, log: Callable[[str], None]) -> bool:
    mgr = shutil.which("dnf") or shutil.which("yum")
    if not mgr:
        return False
    return _run([mgr, "install", "-y", "-q", pkg], log)


# 도구별 설치 레시피
_RECIPES: dict[str, dict] = {
    "nmap": {
        "macos":   lambda log: _brew_install("nmap", log),
        "linux":   lambda log: _apt_install("nmap", log) or _yum_install("nmap", log),
        "windows": lambda log: log("  nmap: https://nmap.org/download.html 에서 설치") or False,
    },
    "nikto": {
        "macos":   lambda log: _brew_install("nikto", log),
        "linux":   lambda log: _apt_install("nikto", log) or _yum_install("nikto", log),
        "windows": lambda log: log("  nikto: Linux/macOS 전용") or False,
    },
    "whatweb": {
        "macos":   lambda log: _brew_install("whatweb", log),
        "linux":   lambda log: _apt_install("whatweb", log) or _yum_install("whatweb", log),
        "windows": lambda log: log("  whatweb: Linux/macOS 전용") or False,
    },
    "sqlmap": {
        "macos":   lambda log: _pip_install("sqlmap", log),
        "linux":   lambda log: _pip_install("sqlmap", log) or _apt_install("sqlmap", log),
        "windows": lambda log: _pip_install("sqlmap", log),
    },
    "wafw00f": {
        "macos":   lambda log: _pip_install("wafw00f", log),
        "linux":   lambda log: _pip_install("wafw00f", log),
        "windows": lambda log: _pip_install("wafw00f", log),
    },
}


def install_tool(name: str, log: Callable[[str], None] | None = None) -> bool:
    """
    도구를 자동 설치. 성공하면 True.
    Go 바이너리는 downloader.download_tool() 사용.
    """
    log = log or (lambda s: print(s))
    os_name = _os()
    recipe = _RECIPES.get(name, {})
    fn = recipe.get(os_name)

    if fn:
        log(f"  {name}: {os_name} 패키지 매니저로 설치 시도...")
        return fn(log)

    log(f"  {name}: 자동 설치 미지원 ({os_name})")
    return False
