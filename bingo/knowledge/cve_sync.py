"""
bingo/knowledge/cve_sync.py — CVE / Exploit KB 추가 동기화 (선택적)
=====================================================================
⚠️  주의: 이 모듈은 GitHub에서 추가 데이터를 동기화하는 선택적 기능입니다.
         GitHub 레포가 삭제/비공개 전환되어도 bingo는 정상 동작합니다.
         내장 KB(bingo/knowledge/base/)가 항상 1순위로 로드됩니다.

trickest/cve    : CVE PoC 마크다운 (1999-현재)  — 추가 데이터
bikini/exploitarium : 0-day PoC + 취약점 연구    — 추가 데이터

동기화 결과는 ~/.bingo/knowledge/ 에 저장되며
KBLoader가 내장 base/ 다음 순서로 로드합니다.

사용:
    from bingo.knowledge.cve_sync import CVESyncer
    s = CVESyncer()
    s.sync()          # 전체 동기화 (최초 클론 또는 pull)
    s.sync_cve()      # trickest/cve 만
    s.sync_exploit()  # exploitarium 만
    s.status()        # 동기화 상태 dict 반환
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional


# ── 기본 경로 ────────────────────────────────────────────────────────
def _kb_root() -> Path:
    d = Path.home() / ".bingo" / "knowledge"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_dir() -> Path:
    d = Path.home() / ".bingo" / ".cve_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── CVE 분류 키워드 매핑 ──────────────────────────────────────────────
_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "RCE":     ["rce", "remote code", "command injection", "exec", "shell"],
    "SQLi":    ["sql", "sqli", "injection", "database", "mysql", "postgres"],
    "XSS":     ["xss", "cross-site scripting", "javascript injection"],
    "SSRF":    ["ssrf", "server-side request", "metadata"],
    "LFI":     ["lfi", "path traversal", "file inclusion", "directory traversal"],
    "Auth":    ["auth", "authentication", "bypass", "credential", "privilege"],
    "XXE":     ["xxe", "xml external", "entity"],
    "Upload":  ["upload", "file upload", "webshell", "shell upload"],
    "DoS":     ["dos", "denial", "crash", "overflow", "buffer"],
    "IDOR":    ["idor", "insecure direct", "object reference"],
    "Crypto":  ["crypto", "weak cipher", "tls", "ssl", "certificate"],
    "Other":   [],
}


def _classify_cve(text: str) -> str:
    """CVE 내용에서 카테고리 추론"""
    lower = text[:500].lower()
    for cat, keywords in _CATEGORY_KEYWORDS.items():
        if cat == "Other":
            continue
        if any(kw in lower for kw in keywords):
            return cat
    return "Other"


class CVESyncer:
    """
    trickest/cve + bikini/exploitarium 동기화 관리자.

    동기화 결과는 ~/.bingo/knowledge/CVE/ 와 ~/.bingo/knowledge/Exploitarium/ 에 저장.
    """

    TRICKEST_URL   = "https://github.com/trickest/cve.git"
    EXPLOITARIUM_URL = "https://github.com/bikini/exploitarium.git"

    # 최근 5년치만 sparse checkout (너무 많으면 오래 걸림)
    CVE_YEARS = ["2022", "2023", "2024", "2025", "2026"]

    def __init__(self, kb_root: Optional[str] = None) -> None:
        self._kb_root   = Path(kb_root) if kb_root else _kb_root()
        self._cache_dir = _cache_dir()
        self._cve_repo   = self._cache_dir / "trickest-cve"
        self._exploit_repo = self._cache_dir / "exploitarium"

    # ── 공통 유틸 ─────────────────────────────────────────────────────
    def _run(self, cmd: list[str], cwd: Optional[Path] = None) -> tuple[int, str]:
        try:
            r = subprocess.run(
                cmd, cwd=str(cwd) if cwd else None,
                capture_output=True, text=True, timeout=300,
            )
            return r.returncode, r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            return 1, "timeout"
        except Exception as e:
            return 1, str(e)

    def _git_available(self) -> bool:
        code, _ = self._run(["git", "--version"])
        return code == 0

    # ── trickest/cve 동기화 ──────────────────────────────────────────
    def sync_cve(self, progress_cb=None) -> dict:
        """trickest/cve 클론/업데이트 → ~/.bingo/knowledge/CVE/ 로 변환"""
        if not self._git_available():
            return {"ok": False, "error": "git not found"}

        # 클론 또는 pull
        if not self._cve_repo.exists():
            if progress_cb:
                progress_cb("trickest/cve clone 중... (최초 1회, 약 1-3분 소요)")
            self._cve_repo.mkdir(parents=True, exist_ok=True)
            code, out = self._run([
                "git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
                self.TRICKEST_URL, str(self._cve_repo),
            ])
            if code != 0:
                return {"ok": False, "error": f"clone failed: {out[:300]}"}
            # sparse checkout: 최근 연도만
            self._run(
                ["git", "sparse-checkout", "set"] + self.CVE_YEARS,
                cwd=self._cve_repo,
            )
        else:
            if progress_cb:
                progress_cb("trickest/cve pull 중...")
            self._run(["git", "pull", "--depth=1"], cwd=self._cve_repo)

        # KB 폴더로 변환
        dest_root = self._kb_root / "CVE"
        dest_root.mkdir(parents=True, exist_ok=True)

        count = 0
        cve_files = list(self._cve_repo.rglob("CVE-*.md"))
        if progress_cb:
            progress_cb(f"CVE 파일 {len(cve_files)}개 변환 중...")

        for md in cve_files:
            try:
                text = md.read_text(encoding="utf-8", errors="ignore").strip()
                if len(text) < 30:
                    continue
                cve_id = md.stem
                cat = _classify_cve(text)
                cat_dir = dest_root / cat
                cat_dir.mkdir(exist_ok=True)
                out_file = cat_dir / f"{cve_id}.md"
                out_file.write_text(text, encoding="utf-8")
                count += 1
            except Exception:
                pass

        return {"ok": True, "synced": count, "source": "trickest/cve"}

    # ── bikini/exploitarium 동기화 ───────────────────────────────────
    def sync_exploit(self, progress_cb=None) -> dict:
        """exploitarium 클론/업데이트 → ~/.bingo/knowledge/Exploitarium/ 로 변환"""
        if not self._git_available():
            return {"ok": False, "error": "git not found"}

        if not self._exploit_repo.exists():
            if progress_cb:
                progress_cb("exploitarium clone 중...")
            code, out = self._run([
                "git", "clone", "--depth=1",
                self.EXPLOITARIUM_URL, str(self._exploit_repo),
            ])
            if code != 0:
                return {"ok": False, "error": f"clone failed: {out[:300]}"}
        else:
            if progress_cb:
                progress_cb("exploitarium pull 중...")
            self._run(["git", "pull", "--depth=1"], cwd=self._exploit_repo)

        dest_root = self._kb_root / "Exploitarium"
        dest_root.mkdir(parents=True, exist_ok=True)

        count = 0
        code_exts = {".py", ".c", ".js", ".rs", ".sh", ".rb", ".go", ".php"}

        for poc_dir in sorted(self._exploit_repo.iterdir()):
            if not poc_dir.is_dir() or poc_dir.name.startswith("."):
                continue
            poc_name = poc_dir.name
            parts: list[str] = []

            # README.md
            readme = poc_dir / "README.md"
            if readme.exists():
                try:
                    content = readme.read_text(encoding="utf-8", errors="ignore").strip()
                    if content:
                        parts.append(content)
                except Exception:
                    pass

            # 코드 파일
            for code_file in sorted(poc_dir.iterdir()):
                if code_file.suffix in code_exts and code_file.is_file():
                    try:
                        code = code_file.read_text(encoding="utf-8", errors="ignore").strip()
                        if len(code) > 20:
                            ext = code_file.suffix.lstrip(".")
                            parts.append(f"```{ext}\n# {code_file.name}\n{code}\n```")
                    except Exception:
                        pass

            if not parts:
                continue

            full = "\n\n".join(parts)
            out_file = dest_root / f"{poc_name}.md"
            out_file.write_text(
                f"# {poc_name}\n\n{full[:8000]}",
                encoding="utf-8",
            )
            count += 1

        return {"ok": True, "synced": count, "source": "exploitarium"}

    # ── 전체 동기화 ──────────────────────────────────────────────────
    def sync(self, progress_cb=None) -> dict:
        """trickest/cve + exploitarium 동시 동기화"""
        r1 = self.sync_cve(progress_cb)
        r2 = self.sync_exploit(progress_cb)
        return {
            "cve": r1,
            "exploit": r2,
            "total": r1.get("synced", 0) + r2.get("synced", 0),
        }

    # ── 상태 조회 ────────────────────────────────────────────────────
    def status(self) -> dict:
        cve_dir    = self._kb_root / "CVE"
        exploit_dir = self._kb_root / "Exploitarium"

        cve_count     = len(list(cve_dir.rglob("*.md"))) if cve_dir.exists() else 0
        exploit_count = len(list(exploit_dir.glob("*.md"))) if exploit_dir.exists() else 0

        # 마지막 git commit 날짜
        def _last_commit(repo: Path) -> str:
            if not repo.exists():
                return "not synced"
            code, out = self._run(
                ["git", "log", "-1", "--format=%cd", "--date=short"], cwd=repo
            )
            return out.strip() or "unknown"

        return {
            "cve_docs":     cve_count,
            "exploit_docs": exploit_count,
            "cve_last":     _last_commit(self._cve_repo),
            "exploit_last": _last_commit(self._exploit_repo),
            "kb_root":      str(self._kb_root),
        }
