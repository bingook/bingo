"""
downloader.py — Go 바이너리 자동 다운로드 (GitHub Releases)
Bingo local tools directory에 저장, 플랫폼/아키텍처 자동 감지
"""
from __future__ import annotations

import os
import platform
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

from ..core.local_state import tools_dir

TOOLS_DIR = tools_dir()

# Go 도구 GitHub Releases 정보
GO_TOOLS: dict[str, dict] = {
    "nuclei": {
        "repo": "projectdiscovery/nuclei",
        "asset_pattern": "nuclei_{version}_{os}_{arch}.zip",
        "binary": "nuclei",
    },
    "httpx": {
        "repo": "projectdiscovery/httpx",
        "asset_pattern": "httpx_{version}_{os}_{arch}.zip",
        "binary": "httpx",
    },
    "subfinder": {
        "repo": "projectdiscovery/subfinder",
        "asset_pattern": "subfinder_{version}_{os}_{arch}.zip",
        "binary": "subfinder",
    },
    "ffuf": {
        "repo": "ffuf/ffuf",
        "asset_pattern": "ffuf_{version}_{os}_{arch}.tar.gz",
        "binary": "ffuf",
    },
    "gobuster": {
        "repo": "OJ/gobuster",
        "asset_pattern": "gobuster_{os}_{arch}.tar.gz",
        "binary": "gobuster",
    },
    "amass": {
        "repo": "owasp-amass/amass",
        "asset_pattern": "amass_{os}_{arch}.zip",
        "binary": "amass",
    },
}


def _get_platform() -> tuple[str, str]:
    """(os_name, arch) — GitHub Releases 파일명 형식"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_name = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system, system)
    arch = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "i386": "386", "i686": "386",
    }.get(machine, machine)

    return os_name, arch


def _get_latest_version(repo: str) -> str | None:
    """GitHub API로 최신 릴리즈 버전 조회"""
    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "bingo-installer"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            import json
            data = json.loads(resp.read())
            tag = data.get("tag_name", "")
            return tag.lstrip("v")
    except Exception:
        return None


def _download_file(url: str, dest: Path, log: Callable[[str], None]) -> bool:
    """파일 다운로드 with 진행률"""
    try:
        log(f"  Downloading: {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "bingo-installer"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk = 8192
            with open(dest, "wb") as f:
                while True:
                    data = resp.read(chunk)
                    if not data:
                        break
                    f.write(data)
                    downloaded += len(data)
                    if total:
                        pct = downloaded * 100 // total
                        log(f"  {pct}%  ({downloaded // 1024}KB / {total // 1024}KB)")
        return True
    except Exception as e:
        log(f"  Download failed: {e}")
        return False


def _extract_binary(archive: Path, binary_name: str, dest_dir: Path, log: Callable[[str], None]) -> Path | None:
    """아카이브에서 바이너리 추출"""
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as zf:
                for name in zf.namelist():
                    base = Path(name).name
                    if base == binary_name or base == f"{binary_name}.exe":
                        out = dest_dir / base
                        out.write_bytes(zf.read(name))
                        out.chmod(out.stat().st_mode | stat.S_IEXEC)
                        log(f"  Extracted: {out}")
                        return out
        elif archive.name.endswith(".tar.gz"):
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    base = Path(member.name).name
                    if base == binary_name or base == f"{binary_name}.exe":
                        f = tf.extractfile(member)
                        if f:
                            out = dest_dir / base
                            out.write_bytes(f.read())
                            out.chmod(out.stat().st_mode | stat.S_IEXEC)
                            log(f"  Extracted: {out}")
                            return out
    except Exception as e:
        log(f"  Extraction failed: {e}")
    return None


def download_tool(
    name: str,
    log: Callable[[str], None] | None = None,
) -> Path | None:
    """
    Go 바이너리 자동 다운로드.
    성공 시 바이너리 경로 반환, 실패 시 None.
    """
    log = log or (lambda s: print(s))
    info = GO_TOOLS.get(name)
    if not info:
        log(f"  {name}: auto-download not supported")
        return None

    os_name, arch = _get_platform()
    log(f"  Platform: {os_name}/{arch}")

    binary = TOOLS_DIR / (info["binary"] + (".exe" if os_name == "windows" else ""))
    if binary.exists():
        log(f"  {name}: already installed ({binary})")
        return binary

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    log(f"  {name}: checking latest version...")
    version = _get_latest_version(info["repo"])
    if not version:
        log(f"  Version lookup failed")
        return None
    log(f"  Latest: v{version}")

    # 다운로드 URL 구성
    ext = ".zip" if os_name != "linux" or name not in ("ffuf", "gobuster") else ".tar.gz"
    # 도구별 URL 패턴
    repo = info["repo"]
    b_name = info["binary"]

    url_candidates = [
        f"https://github.com/{repo}/releases/download/v{version}/{b_name}_{version}_{os_name}_{arch}{ext}",
        f"https://github.com/{repo}/releases/download/v{version}/{b_name}_{version}_{os_name}_{arch}.tar.gz",
        f"https://github.com/{repo}/releases/download/v{version}/{b_name}_{os_name}_{arch}{ext}",
        f"https://github.com/{repo}/releases/download/v{version}/{b_name}_{os_name}_{arch}.zip",
    ]

    archive_path = TOOLS_DIR / f"{name}_download{ext}"
    success = False
    for url in url_candidates:
        if _download_file(url, archive_path, log):
            success = True
            break

    if not success:
        log(f"  {name}: download failed (all URLs tried)")
        return None

    result = _extract_binary(archive_path, b_name, TOOLS_DIR, log)
    try:
        archive_path.unlink()
    except Exception:
        pass

    if result:
        log(f"  {name}: installed → {result}")
    return result
