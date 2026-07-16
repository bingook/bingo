"""
bingo/core/memory.py — autoDream 세션 간 메모리 시스템 (v6.2.151)

grok-build xai-grok-memory 아키텍처 Python 이식.

## 스토리지 레이아웃
  ~/.config/bingo/memory/
  ├── MEMORY.md                          # 글로벌 영구 지식
  └── {workspace_hash}/                  # blake3-like hash of cwd
      ├── MEMORY.md                      # 워크스페이스/타겟별 지식
      └── sessions/
          └── YYYY-MM-DD-{target}-{id8}.md

## 주요 기능
  1. save_session()        — 세션 종료 시 발견사항 자동 추출 → 세션 파일 저장
  2. query_memory()        — FTS 기반 기억 검색 (유사 타겟/취약점/계정 재활용)
  3. inject_context()      — 검색 결과를 AI 시스템 컨텍스트 문자열로 반환
  4. dream_consolidate()   — 여러 세션을 LLM이 통합 요약 → MEMORY.md 갱신
  5. auto_dream()          — 조건 충족 시 dream_consolidate 자동 실행

## 검색 알고리즘
  FTS 키워드 매칭 + 도메인/IP 직접 비교 + 시간 감쇠
  (grok-build MMR 다양성 재랭킹의 Python 단순화 버전)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

# ── 경로 상수 ─────────────────────────────────────────────────────────────────
_MEM_ROOT = Path.home() / ".config" / "bingo" / "memory"
_GLOBAL_MEMORY = _MEM_ROOT / "MEMORY.md"
_DB_PATH = _MEM_ROOT / "bingo_memory.db"

# autoDream 트리거 조건
_DREAM_MIN_SESSIONS = 3      # 최소 새 세션 수
_DREAM_MIN_HOURS = 12        # 마지막 통합 이후 최소 경과 시간

# 시간 감쇠 (세션 기억)
_DECAY_HALF_LIFE_DAYS = 30   # 30일 후 점수 0.5로 감쇠

# ── 데이터 클래스 ──────────────────────────────────────────────────────────────
@dataclass
class MemoryChunk:
    chunk_id: str
    source: str          # "global" | "workspace" | "session"
    path: str
    content: str
    score: float = 0.0
    created_at: int = field(default_factory=lambda: int(time.time()))


@dataclass
class SessionFindings:
    """세션에서 추출한 발견사항."""
    target: str
    session_id: str
    timestamp: str
    sqli_points: list[dict]   = field(default_factory=list)
    credentials: list[dict]   = field(default_factory=list)
    endpoints: list[str]      = field(default_factory=list)
    vulns: list[dict]         = field(default_factory=list)
    admin_panels: list[str]   = field(default_factory=list)
    hashes: list[str]         = field(default_factory=list)
    notes: list[str]          = field(default_factory=list)
    raw_summary: str          = ""


# ── 유틸 ──────────────────────────────────────────────────────────────────────
def _workspace_hash(cwd: Optional[str] = None) -> str:
    """현재 작업 디렉터리의 해시 (16자) → 워크스페이스 식별자."""
    cwd = cwd or os.getcwd()
    return hashlib.md5(cwd.encode()).hexdigest()[:16]


def _workspace_dir(cwd: Optional[str] = None) -> Path:
    return _MEM_ROOT / _workspace_hash(cwd)


def _sessions_dir(cwd: Optional[str] = None) -> Path:
    return _workspace_dir(cwd) / "sessions"


def _workspace_memory(cwd: Optional[str] = None) -> Path:
    return _workspace_dir(cwd) / "MEMORY.md"


def _apply_temporal_decay(score: float, created_at: int, source: str) -> float:
    """시간 감쇠 적용. global/workspace는 영구 보존."""
    if source in ("global", "workspace"):
        return score
    age_days = (time.time() - created_at) / 86400
    lam = 0.693147 / _DECAY_HALF_LIFE_DAYS  # ln(2) / half_life
    return score * (2.71828 ** (-lam * age_days))


# ── SQLite 인덱스 ─────────────────────────────────────────────────────────────
_db_lock = threading.Lock()


@contextmanager
def _get_db() -> Iterator[sqlite3.Connection]:
    _MEM_ROOT.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db() -> None:
    """SQLite FTS5 테이블 초기화."""
    with _get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS chunks (
                chunk_id   TEXT PRIMARY KEY,
                source     TEXT NOT NULL,
                path       TEXT NOT NULL,
                target     TEXT DEFAULT '',
                content    TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_used  INTEGER DEFAULT 0
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
                USING fts5(content, chunk_id UNINDEXED, tokenize='unicode61');
            CREATE TABLE IF NOT EXISTS dream_state (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
        """)


def _upsert_chunk(
    chunk_id: str,
    source: str,
    path: str,
    target: str,
    content: str,
    created_at: int,
) -> None:
    with _db_lock, _get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO chunks VALUES (?,?,?,?,?,?,?)",
            (chunk_id, source, path, target, content, created_at, 0),
        )
        conn.execute(
            "INSERT OR REPLACE INTO chunks_fts(content, chunk_id) VALUES (?,?)",
            (content, chunk_id),
        )


def _fts_search(query: str, limit: int = 10) -> list[dict]:
    """FTS5 BM25 키워드 검색."""
    if not query.strip():
        return []
    try:
        with _get_db() as conn:
            rows = conn.execute(
                """
                SELECT c.chunk_id, c.source, c.path, c.target, c.content, c.created_at,
                       bm25(chunks_fts) AS bm25_score
                FROM chunks_fts f
                JOIN chunks c ON c.chunk_id = f.chunk_id
                WHERE chunks_fts MATCH ?
                ORDER BY bm25_score
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.debug(f"[memory] FTS search error: {e}")
        return []


# ── 세션 파일 파싱 ────────────────────────────────────────────────────────────
def _extract_findings_from_text(text: str, target: str, session_id: str) -> SessionFindings:
    """세션 로그 / raw_results 텍스트에서 발견사항 자동 추출."""
    findings = SessionFindings(
        target=target,
        session_id=session_id,
        timestamp=datetime.now().isoformat(),
    )

    # 자격증명 추출 (admin/ID:PW 패턴)
    cred_pats = [
        r"(?:id|username|user|아이디)[=:\s]+([a-zA-Z0-9_@.\-]{3,40})\s*[\|/,]\s*(?:pw|password|pass|패스워드)[=:\s]+([^\s\n,\|]{3,60})",
        r"(?:아이디|계정)\s*:\s*([^\s\n,]{3,40})\s*[\|/,]\s*(?:비밀번호|패스워드)\s*:\s*([^\s\n,]{3,60})",
        r"admin[_\s]?(?:id|user|login)[=:\s]+([^\s\n,]{3,40})",
    ]
    for pat in cred_pats:
        for m in re.finditer(pat, text, re.IGNORECASE):
            entry = {"raw": m.group(0)[:120]}
            findings.credentials.append(entry)

    # MD5/bcrypt 해시 추출
    hash_pats = [
        r"\b[a-fA-F0-9]{32}\b",    # MD5
        r"\$2[ab]\$\d{2}\$[./A-Za-z0-9]{53}",  # bcrypt
        r"\b[a-fA-F0-9]{64}\b",    # SHA-256
    ]
    seen_hashes: set[str] = set()
    for pat in hash_pats:
        for m in re.finditer(pat, text):
            h = m.group(0)
            if h not in seen_hashes:
                seen_hashes.add(h)
                findings.hashes.append(h)

    # SQLi 포인트 추출
    sqli_pat = r"(https?://[^\s'\"]{10,})\s*(?:param(?:eter)?[=:\s]*([a-zA-Z_][a-zA-Z0-9_]{0,30}))?.*?(?:SQLI|SQL.INJECT|1=1|WAITFOR|TIME.*DELAY|시간.*지연)"
    for m in re.finditer(sqli_pat, text, re.IGNORECASE | re.DOTALL):
        findings.sqli_points.append({
            "url": m.group(1)[:200],
            "param": m.group(2) or "unknown",
        })

    # 관리자 페이지 URL 추출
    admin_pat = r"(https?://[^\s'\"]{10,}/(?:admin|manage|dashboard|login)[^\s'\"]{0,60})"
    for m in re.finditer(admin_pat, text, re.IGNORECASE):
        url = m.group(1)[:200]
        if url not in findings.admin_panels:
            findings.admin_panels.append(url)

    # 취약점 키워드
    vuln_keywords = [
        ("SQLi", r"(?:SQL.?inject|sqli\s*확인|sqli\s*confirmed)"),
        ("XSS", r"(?:cross.site|xss\s*확인|alert\(|xss\s*confirmed)"),
        ("RCE", r"(?:remote.code|rce\s*확인|command.inject)"),
        ("LFI", r"(?:local.file|lfi\s*확인|path.travers)"),
        ("SSRF", r"(?:ssrf\s*확인|server.side.request)"),
        ("IDOR", r"(?:idor\s*확인|insecure.direct)"),
    ]
    for vname, vpat in vuln_keywords:
        if re.search(vpat, text, re.IGNORECASE):
            findings.vulns.append({"type": vname, "target": target})

    # 요약 (앞 500자)
    findings.raw_summary = text[:500].strip()

    return findings


# ── 공개 API ──────────────────────────────────────────────────────────────────
def save_session(
    session_log_path: Optional[str | Path],
    target: str,
    agent_state: dict,
    raw_results_snippets: list[str],
    session_id: Optional[str] = None,
) -> Optional[Path]:
    """
    세션 종료 시 발견사항을 추출하여 메모리에 저장.

    Parameters
    ----------
    session_log_path : 세션 로그 파일 경로 (없으면 raw_results_snippets만 사용)
    target           : 타겟 URL/IP
    agent_state      : bingo agent_state dict
    raw_results_snippets : 실행 결과 텍스트 목록 (마지막 N개)
    session_id       : 고유 세션 ID (없으면 자동 생성)
    """
    try:
        _init_db()
        if not target:
            return None

        session_id = session_id or hashlib.md5(
            f"{target}{time.time()}".encode()
        ).hexdigest()[:8]

        # 타겟에서 도메인/IP 추출
        _tgt_clean = re.sub(r"https?://", "", target).split("/")[0].replace(":", "_")

        # 날짜 슬러그
        date_slug = datetime.now().strftime("%Y-%m-%d")
        fname = f"{date_slug}-{_tgt_clean[:30]}-{session_id}.md"

        # 세션 폴더 준비
        sdir = _sessions_dir()
        sdir.mkdir(parents=True, exist_ok=True)
        spath = sdir / fname

        # 텍스트 소스 합치기
        combined_text = ""
        if session_log_path:
            try:
                combined_text = Path(session_log_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        if raw_results_snippets:
            combined_text += "\n\n" + "\n---\n".join(raw_results_snippets[-5:])

        # 발견사항 추출
        findings = _extract_findings_from_text(combined_text, target, session_id)

        # agent_state에서 추가 정보 병합
        if agent_state:
            for cred in agent_state.get("credentials", []):
                if cred not in findings.credentials:
                    findings.credentials.append(cred)
            for tbl in agent_state.get("tables", []):
                findings.notes.append(f"table: {tbl}")
            if agent_state.get("db_name"):
                findings.notes.append(f"db: {agent_state['db_name']}")
            if agent_state.get("waf"):
                findings.notes.append(f"waf: {agent_state['waf']}")

        # 마크다운 형식으로 저장
        md_lines = [
            f"# Session: {target}",
            f"**Date**: {findings.timestamp}",
            f"**Session**: {session_id}",
            "",
        ]
        if findings.sqli_points:
            md_lines.append("## SQLi Points")
            for sp in findings.sqli_points:
                md_lines.append(f"- URL: {sp['url']} | param: {sp['param']}")
        if findings.credentials:
            md_lines.append("## Credentials")
            for c in findings.credentials[:10]:
                md_lines.append(f"- {c}")
        if findings.hashes:
            md_lines.append("## Hashes")
            for h in findings.hashes[:20]:
                md_lines.append(f"- {h}")
        if findings.admin_panels:
            md_lines.append("## Admin Panels")
            for ap in findings.admin_panels[:5]:
                md_lines.append(f"- {ap}")
        if findings.vulns:
            md_lines.append("## Vulnerabilities")
            for v in findings.vulns:
                md_lines.append(f"- [{v['type']}] {v['target']}")
        if findings.notes:
            md_lines.append("## Notes")
            for n in findings.notes:
                md_lines.append(f"- {n}")
        if findings.raw_summary:
            md_lines.append("## Summary (auto)")
            md_lines.append(f"```\n{findings.raw_summary[:400]}\n```")

        spath.write_text("\n".join(md_lines), encoding="utf-8")

        # FTS 인덱스에 추가
        chunk_id = f"session:{session_id}:{_tgt_clean}"
        _upsert_chunk(
            chunk_id=chunk_id,
            source="session",
            path=str(spath),
            target=target,
            content="\n".join(md_lines),
            created_at=int(time.time()),
        )

        logger.info(f"[memory] Session saved: {spath}")
        return spath

    except Exception as e:
        logger.warning(f"[memory] save_session error: {e}")
        return None


def query_memory(
    query: str,
    target: Optional[str] = None,
    limit: int = 5,
) -> list[MemoryChunk]:
    """
    FTS + 도메인 직접 매칭으로 관련 기억을 검색.

    Parameters
    ----------
    query  : 검색 쿼리 (타겟 URL, 취약점명, 계정 등)
    target : 타겟 URL/IP (있으면 도메인 직접 비교도 수행)
    limit  : 최대 반환 개수
    """
    try:
        _init_db()
        results: list[MemoryChunk] = []

        # 글로벌/워크스페이스 MEMORY.md 항상 포함
        for mem_path, source in [(_GLOBAL_MEMORY, "global"), (_workspace_memory(), "workspace")]:
            if mem_path.exists():
                content = mem_path.read_text(encoding="utf-8", errors="replace")
                if content.strip():
                    results.append(MemoryChunk(
                        chunk_id=f"{source}:memory.md",
                        source=source,
                        path=str(mem_path),
                        content=content[:2000],
                        score=1.0,
                    ))

        # FTS 검색
        _query_terms = query.replace("/", " ").replace(":", " ").replace(".", " ")
        if target:
            _tgt_clean = re.sub(r"https?://", "", target).split("/")[0]
            _query_terms += " " + _tgt_clean

        fts_rows = _fts_search(_query_terms, limit=limit * 2)
        seen_ids: set[str] = {r.chunk_id for r in results}

        for row in fts_rows:
            cid = row["chunk_id"]
            if cid in seen_ids:
                continue
            seen_ids.add(cid)

            # 음수 BM25 점수를 양수로 변환 (FTS5는 낮을수록 좋음)
            raw_score = abs(row.get("bm25_score", 0) or 0)
            base_score = min(1.0, raw_score / 10.0)
            score = _apply_temporal_decay(base_score, row["created_at"], row["source"])

            results.append(MemoryChunk(
                chunk_id=cid,
                source=row["source"],
                path=row["path"],
                content=row["content"][:1000],
                score=score,
                created_at=row["created_at"],
            ))

        # 점수 내림차순 정렬, limit 적용
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    except Exception as e:
        logger.warning(f"[memory] query_memory error: {e}")
        return []


def inject_context(
    target: str,
    lang: str = "en",
    limit: int = 4,
) -> str:
    """
    타겟 관련 기억을 AI 시스템 컨텍스트 주입용 문자열로 반환.

    세션 시작 시 이 문자열을 유저 메시지 앞에 주입하면
    bingo가 이전 세션 결과를 바탕으로 공격을 이어간다.
    """
    try:
        chunks = query_memory(query=target, target=target, limit=limit)
        if not chunks:
            return ""

        header = {
            "ko": "=== 🧠 이전 세션 기억 (autoDream) ===",
            "zh": "=== 🧠 历史会话记忆 (autoDream) ===",
            "en": "=== 🧠 Previous Session Memory (autoDream) ===",
        }.get(lang, "=== 🧠 Previous Session Memory ===")

        footer = {
            "ko": "=== 위 정보를 바탕으로 공격을 이어가세요 ===",
            "zh": "=== 请基于以上信息继续攻击 ===",
            "en": "=== Continue attack based on the above memory ===",
        }.get(lang, "=== Continue from memory above ===")

        parts = [header]
        for chunk in chunks:
            src_label = f"[{chunk.source}]" if chunk.source != "session" else f"[session:{chunk.path[-30:]}]"
            parts.append(f"\n{src_label} (relevance={chunk.score:.2f})\n{chunk.content[:600]}")
        parts.append(footer)

        return "\n".join(parts)

    except Exception as e:
        logger.warning(f"[memory] inject_context error: {e}")
        return ""


def auto_dream(
    model=None,
    build_messages_fn=None,
    lang: str = "en",
) -> bool:
    """
    autoDream: 조건 충족 시 세션 기록을 LLM으로 통합 요약 → MEMORY.md 갱신.

    Parameters
    ----------
    model            : BaseModel 인스턴스 (없으면 건너뜀)
    build_messages_fn: bingo의 _build_messages 함수
    lang             : 언어 코드

    Returns True if dream was executed.
    """
    try:
        _init_db()
        sdir = _sessions_dir()
        if not sdir.exists():
            return False

        # 조건 확인
        with _get_db() as conn:
            last_dream_str = conn.execute(
                "SELECT value FROM dream_state WHERE key='last_dream_at'"
            ).fetchone()

        last_dream_at = float((last_dream_str["value"] if last_dream_str else None) or 0)
        hours_since = (time.time() - last_dream_at) / 3600

        # 마지막 통합 이후 세션 수 카운트
        sessions_since_dream = []
        for sf in sorted(sdir.glob("*.md")):
            if sf.stat().st_mtime > last_dream_at:
                sessions_since_dream.append(sf)

        if hours_since < _DREAM_MIN_HOURS:
            logger.debug(f"[memory] Dream too soon: {hours_since:.1f}h < {_DREAM_MIN_HOURS}h")
            return False
        if len(sessions_since_dream) < _DREAM_MIN_SESSIONS:
            logger.debug(f"[memory] Too few sessions: {len(sessions_since_dream)} < {_DREAM_MIN_SESSIONS}")
            return False

        # 세션 내용 합치기
        combined = "\n\n---\n\n".join(
            sf.read_text(encoding="utf-8", errors="replace")[:800]
            for sf in sessions_since_dream[:8]  # 최대 8개
        )

        if model is None or build_messages_fn is None:
            # LLM 없이도 간단한 머지 수행
            _simple_dream_merge(sessions_since_dream, lang)
            _mark_dream_done()
            return True

        # LLM 통합 요약 프롬프트
        prompt_map = {
            "ko": (
                f"[autoDream 통합 요약]\n"
                f"다음은 bingo 침투테스트 세션 기록입니다.\n"
                f"중요 정보(취약점, 계정, SQL 인젝션 포인트, WAF 정보)를 추출해서\n"
                f"간결한 불릿 목록(마크다운)으로 요약하세요. 중복 제거.\n\n"
                f"---\n{combined[:3000]}\n---"
            ),
            "zh": (
                f"[autoDream 整合摘要]\n"
                f"以下是bingo渗透测试会话记录。\n"
                f"提取重要信息（漏洞、凭据、SQL注入点、WAF信息）\n"
                f"用简洁的Markdown项目符号列表汇总，去除重复。\n\n"
                f"---\n{combined[:3000]}\n---"
            ),
            "en": (
                f"[autoDream Consolidation]\n"
                f"Below are bingo pentest session logs.\n"
                f"Extract key findings (vulns, credentials, SQLi points, WAF info)\n"
                f"and summarize as a concise markdown bullet list. Remove duplicates.\n\n"
                f"---\n{combined[:3000]}\n---"
            ),
        }
        dream_prompt = prompt_map.get(lang, prompt_map["en"])

        from ..models.base import Message, StreamChunk
        msgs = build_messages_fn("")
        msgs_with_dream = list(msgs) + [Message(role="user", content=dream_prompt)]

        summary_parts = []
        try:
            for chunk in model.chat_stream(msgs_with_dream, _amp_skip=True):
                if chunk.text:
                    summary_parts.append(chunk.text)
                if chunk.done:
                    break
        except Exception as e:
            logger.warning(f"[memory] Dream LLM call failed: {e}")
            _simple_dream_merge(sessions_since_dream, lang)
            _mark_dream_done()
            return True

        summary = "".join(summary_parts).strip()
        if not summary:
            return False

        # MEMORY.md 갱신
        mem_path = _workspace_memory()
        mem_path.parent.mkdir(parents=True, exist_ok=True)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        header_map = {
            "ko": f"\n\n## 자동 통합 — {now_str} ({len(sessions_since_dream)}개 세션)\n",
            "zh": f"\n\n## 自动整合 — {now_str} ({len(sessions_since_dream)}个会话)\n",
            "en": f"\n\n## autoDream — {now_str} ({len(sessions_since_dream)} sessions)\n",
        }
        section_header = header_map.get(lang, header_map["en"])

        existing = mem_path.read_text(encoding="utf-8") if mem_path.exists() else ""
        mem_path.write_text(existing + section_header + summary, encoding="utf-8")

        # FTS 인덱스 갱신
        _upsert_chunk(
            chunk_id=f"workspace:memory.md",
            source="workspace",
            path=str(mem_path),
            target="",
            content=existing + section_header + summary,
            created_at=int(time.time()),
        )

        _mark_dream_done()
        logger.info(f"[memory] autoDream complete: {len(sessions_since_dream)} sessions consolidated")
        return True

    except Exception as e:
        logger.warning(f"[memory] auto_dream error: {e}")
        return False


def _simple_dream_merge(session_files: list[Path], lang: str) -> None:
    """LLM 없이 세션 기록을 단순 연결하여 MEMORY.md에 추가."""
    mem_path = _workspace_memory()
    mem_path.parent.mkdir(parents=True, exist_ok=True)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    header_map = {
        "ko": f"\n\n## 세션 기록 ({now_str})\n",
        "zh": f"\n\n## 会话记录 ({now_str})\n",
        "en": f"\n\n## Session Records ({now_str})\n",
    }
    existing = mem_path.read_text(encoding="utf-8") if mem_path.exists() else ""
    merged = "\n\n".join(sf.read_text(encoding="utf-8", errors="replace")[:400]
                         for sf in session_files[:5])
    mem_path.write_text(
        existing + header_map.get(lang, header_map["en"]) + merged,
        encoding="utf-8",
    )


def _mark_dream_done() -> None:
    with _db_lock, _get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO dream_state VALUES ('last_dream_at', ?)",
            (str(time.time()),),
        )


def clear_memory(target: Optional[str] = None) -> int:
    """타겟 메모리 삭제. target=None이면 모든 세션 메모리 삭제."""
    count = 0
    try:
        sdir = _sessions_dir()
        if sdir.exists():
            for sf in sdir.glob("*.md"):
                if target is None or target.replace("https://", "").split("/")[0] in sf.name:
                    sf.unlink()
                    count += 1
        # DB도 정리
        with _db_lock, _get_db() as conn:
            if target:
                _tgt_clean = target.replace("https://", "").split("/")[0]
                conn.execute("DELETE FROM chunks WHERE target LIKE ?", (f"%{_tgt_clean}%",))
            else:
                conn.execute("DELETE FROM chunks WHERE source='session'")
    except Exception as e:
        logger.warning(f"[memory] clear_memory error: {e}")
    return count


def memory_status(lang: str = "en") -> str:
    """메모리 상태 요약 문자열 반환."""
    try:
        _init_db()
        sdir = _sessions_dir()
        session_count = len(list(sdir.glob("*.md"))) if sdir.exists() else 0
        global_exists = _GLOBAL_MEMORY.exists()
        workspace_exists = _workspace_memory().exists()
        with _get_db() as conn:
            chunk_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        label = {
            "ko": f"🧠 autoDream 메모리: 세션 {session_count}개 | 인덱스 청크 {chunk_count}개 | 글로벌: {'✓' if global_exists else '✗'} | 워크스페이스: {'✓' if workspace_exists else '✗'}",
            "zh": f"🧠 autoDream内存: {session_count}个会话 | {chunk_count}个索引块 | 全局: {'✓' if global_exists else '✗'} | 工作区: {'✓' if workspace_exists else '✗'}",
            "en": f"🧠 autoDream: {session_count} sessions | {chunk_count} index chunks | global: {'✓' if global_exists else '✗'} | workspace: {'✓' if workspace_exists else '✗'}",
        }
        return label.get(lang, label["en"])
    except Exception:
        return "🧠 autoDream: unavailable"
