"""
bingo/knowledge/loader.py — 로컬 지식 베이스 로더

읽기 우선순위:
  1순위: bingo/knowledge/base/  (프로젝트 내장, git에 포함 — GitHub 없어도 항상 사용 가능)
  2순위: ~/.bingo/knowledge/    (사용자 추가 파일 + /cve sync 결과)

AI 대화 시 관련 KB 내용을 시스템 프롬프트에 동적 주입.
카테고리 = 폴더명 (예: SQLi, XSS, SSRF, LFI, Auth, JWT, CVE, WAF …)

v3.6.0: list_docs() / get() / reload() 추가, CVE ID 직접 검색 지원
         base/ 폴더를 1순위 소스로 변경 (GitHub 의존성 제거)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional


# ── 경로 설정 ────────────────────────────────────────────────────────
def _builtin_base() -> Path:
    """패키지 내장 knowledge/base/ 경로 (git에 포함)"""
    return Path(__file__).parent / "base"


def _user_kb_root() -> Path:
    """사용자 추가 KB 경로 ~/.bingo/knowledge/ (선택적, /cve sync 결과)"""
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
        # CVE-XXXX-XXXXX 직접 매칭
        if re.search(r"cve-\d{4}-\d+", q):
            cve_id = re.search(r"(cve-\d{4}-\d+)", q)
            if cve_id and cve_id.group(1) in self.path.stem.lower():
                return True
        kws = self.keywords()
        # (1) 키워드가 쿼리 문자열에 포함: 'xss' in 'xss payload'
        if any(kw in q for kw in kws):
            return True
        # (2) 쿼리 단어가 키워드에 부분 포함: 'sql' in 'sqli', 'inject' in 'injection'
        q_words = re.findall(r"\b[a-z0-9]{3,}\b", q)
        if any(qw in kw for kw in kws for qw in q_words):
            return True
        return False


class KBLoader:
    """
    지식 베이스 로더.

    읽기 순서:
      1. bingo/knowledge/base/   — 내장 보안 지식 (GitHub 불필요)
      2. ~/.bingo/knowledge/     — 사용자 파일 + /cve sync 결과

    사용법:
        kb = KBLoader()
        snippet = kb.inject_for("sql injection bypass")
    """

    def __init__(self, root: Optional[str] = None) -> None:
        # root 직접 지정 시 해당 경로만 사용 (테스트용)
        self._custom_root = Path(root) if root else None
        self._entries: List[KBEntry] = []
        self._loaded = False

    def _load_from_dir(self, base: Path) -> int:
        """디렉터리에서 md 파일 로드, 추가된 수 반환"""
        count = 0
        if not base.exists():
            return 0
        for md in base.rglob("*.md"):
            try:
                content = md.read_text(encoding="utf-8")
                category = md.parent.name
                title = md.stem.replace("-", " ").replace("_", " ")
                self._entries.append(KBEntry(category, title, content, md))
                count += 1
            except Exception:
                pass
        return count

    def load(self) -> int:
        self._entries = []

        if self._custom_root:
            # 테스트 모드: 지정 경로만
            n = self._load_from_dir(self._custom_root)
        else:
            # 1순위: 내장 base/ (항상 사용 가능)
            n = self._load_from_dir(_builtin_base())
            # 2순위: 사용자 KB (없어도 OK)
            n += self._load_from_dir(_user_kb_root())

        self._loaded = True
        return n

    def search(self, query: str, top_k: int = 5) -> List[dict]:
        """키워드로 KB 검색, /kb search 와 inject_for 모두 지원"""
        if not self._loaded:
            self.load()
        matched = [e for e in self._entries if e.matches(query)]
        results = []
        for e in matched[:top_k]:
            snippet = e.content[:200].replace("\n", " ").strip()
            results.append({
                "name":    f"{e.category}/{e.title}",
                "snippet": snippet,
                "entry":   e,
            })
        return results

    def count(self) -> int:
        if not self._loaded:
            self.load()
        return len(self._entries)

    # ── terminal.py /kb 명령어 전용 API ──────────────────────────────
    def list_docs(self) -> List[dict]:
        """/kb list 에서 사용. 각 문서의 name/size/summary 반환."""
        if not self._loaded:
            self.load()
        result = []
        for e in sorted(self._entries, key=lambda x: x.category + x.title):
            snippet = e.content[:120].replace("\n", " ").strip()
            result.append({
                "name":     f"{e.category}/{e.title}",
                "size":     len(e.content),
                "summary":  snippet,
                "category": e.category,
                "path":     str(e.path),
            })
        return result

    def get(self, name: str) -> Optional[str]:
        """/kb show <name> 용. 'Category/title' 또는 'title' 으로 조회."""
        if not self._loaded:
            self.load()
        name_lower = name.lower().replace("-", " ").replace("_", " ")
        for e in self._entries:
            full = f"{e.category}/{e.title}".lower()
            if name_lower in full or e.title.lower() == name_lower:
                return e.content
        return None

    def reload(self) -> int:
        """KB 디렉터리를 다시 스캔."""
        self._loaded = False
        return self.load()

    def inject_for(self, query: str, max_chars: int = 2000) -> str:
        """쿼리와 관련된 KB 내용을 AI 주입용 텍스트로 반환."""
        results = self.search(query)
        if not results:
            return ""
        parts = ["[KNOWLEDGE BASE]"]
        remaining = max_chars
        for r in results:
            e = r["entry"]
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
