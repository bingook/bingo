"""
secknowledge_loader.py — SecKnowledge Reference 파일 런타임 로더
bingo v2.2.6

WooYun 88,636 + 先知 L1-L4 + GAARM 150 + OWASP 기반의
Web+AI 보안 테스트 지식베이스를 런타임에 로드하여 AI에게 제공.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from functools import lru_cache

# ─────────────────────────────────────────────────────────────
# Reference 파일 경로 탐색
# ─────────────────────────────────────────────────────────────

_SEARCH_PATHS: list[Path] = [
    # macOS Cursor 스킬 경로
    Path.home() / ".cursor" / "skills" / "secknowledge" / "references",
    # 상대 경로 fallback (bingo 설치 경로 기준)
    Path(__file__).parent.parent.parent / ".cursor" / "skills" / "secknowledge" / "references",
]


def _find_references_dir() -> Path | None:
    for p in _SEARCH_PATHS:
        if p.exists() and p.is_dir():
            return p
    return None


REFERENCES_DIR: Path | None = _find_references_dir()


# ─────────────────────────────────────────────────────────────
# Reference 파일 매핑
# ─────────────────────────────────────────────────────────────

REFERENCE_FILES: dict[str, str] = {
    # Web 보안
    "sqli":            "web-sqli.md",
    "xss":             "web-xss.md",
    "rce":             "web-rce.md",
    "upload":          "web-upload.md",
    "ssrf":            "web-ssrf-misc.md",
    "logic-auth":      "web-logic-auth.md",
    "xxe":             "web-xxe.md",
    "deser":           "web-deser.md",
    "traversal":       "web-traversal.md",
    "leak":            "web-leak.md",
    "modern-proto":    "web-modern-protocols.md",
    "deployment":      "web-deployment-security.md",
    # AI/LLM 보안
    "prompt":          "ai-app-prompt.md",
    "mcp":             "ai-app-mcp.md",
    "agent-cot":       "ai-app-agent-cot.md",
    "jailbreak":       "ai-model-jailbreak.md",
    "hallucination":   "ai-model-hallucination.md",
    "content":         "ai-model-content.md",
    "extraction":      "ai-model-extraction.md",
    "misuse":          "ai-model-misuse.md",
    "ai-data-app":     "ai-data-app.md",
    "ai-identity":     "ai-identity-app.md",
    "ai-escape":       "ai-baseline-escape.md",
    "ai-frontier":     "ai-app-frontier.md",
    # 방법론
    "methodology":     "testing-methodology.md",
    "gaarm":           "gaarm-risk-matrix.md",
}


@lru_cache(maxsize=None)
def load_reference(key: str, max_chars: int = 8000) -> str:
    """
    key에 해당하는 reference 파일을 로드하여 문자열로 반환.
    REFERENCES_DIR 가 없으면 빈 문자열 반환.
    """
    if REFERENCES_DIR is None:
        return f"[UNABLE TO LOAD: secknowledge reference 디렉토리를 찾을 수 없습니다. "               f"~/.cursor/skills/secknowledge/references/ 경로를 확인하세요]"

    filename = REFERENCE_FILES.get(key)
    if not filename:
        return f"[UNABLE TO CITE: '{key}' 키가 REFERENCE_FILES에 없습니다]"

    path = REFERENCES_DIR / filename
    if not path.exists():
        return f"[UNABLE TO ASSESS: {filename} 파일이 존재하지 않습니다]"

    text = path.read_text(encoding="utf-8", errors="ignore")
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n\n... (이하 {len(text) - max_chars}자 생략. 전체 보기: load_reference('{key}', max_chars=999999))"
    return text


def load_section(key: str, section_pattern: str, max_chars: int = 3000) -> str:
    """
    reference 파일에서 특정 섹션(헤더 패턴)만 추출.
    예: load_section('sqli', '1.3 绕过', 2000)
    """
    full = load_reference(key, max_chars=999999)
    if full.startswith("[UNABLE"):
        return full

    lines = full.split("\n")
    result: list[str] = []
    capturing = False
    depth = 0

    header_re = re.compile(section_pattern, re.IGNORECASE)

    for line in lines:
        if header_re.search(line) and line.startswith("#"):
            capturing = True
            depth = line.count("#", 0, 10)
            result.append(line)
            continue
        if capturing:
            cur_depth = len(line) - len(line.lstrip("#")) if line.startswith("#") else 0
            if cur_depth > 0 and cur_depth <= depth and result:
                break
            result.append(line)

    text = "\n".join(result)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n... (섹션 생략)"
    return text or f"[섹션 '{section_pattern}'을 찾지 못했습니다]"


def list_available() -> list[str]:
    """사용 가능한 reference 키 목록"""
    if REFERENCES_DIR is None:
        return []
    return [k for k, f in REFERENCE_FILES.items()
            if (REFERENCES_DIR / f).exists()]


def is_available() -> bool:
    """secknowledge references 디렉토리가 있는지 확인"""
    return REFERENCES_DIR is not None


def references_status() -> str:
    """참조 파일 상태 요약"""
    if REFERENCES_DIR is None:
        return "❌ References 없음 — ~/.cursor/skills/secknowledge/references/ 가 필요합니다"
    avail = list_available()
    total = len(REFERENCE_FILES)
    return (
        f"✅ References: {len(avail)}/{total}개 사용 가능\n"
        f"   경로: {REFERENCES_DIR}\n"
        f"   사용 가능: {', '.join(avail)}"
    )
