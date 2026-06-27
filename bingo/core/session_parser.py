"""
bingo v3.2.72 — Session Log Parser (세션 로그 자동 파싱 → target_memory 저장)

세션 종료 시 ~/.config/bingo/sessions/session_*.md 를 자동 파싱해
SQLi 포인트, 확인된 유저, 주요 엔드포인트를 target_memory에 저장.
다음 세션 시작 시 이 정보가 AI에게 자동 주입되어 재탐색 없이 바로 공략.

파싱 대상: bingo가 자동 저장하는 세션 로그 (사용자가 수동 생성한 파일 불필요)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

# ── 세션 로그 저장 위치 ───────────────────────────────────────────
_SESSIONS_DIR = Path.home() / ".config" / "bingo" / "sessions"

# ── 정규식 패턴 정의 ─────────────────────────────────────────────

# bingo 요약 텍스트 섹션 분리 (코드블록 제외)
_SECTION_RE = re.compile(
    r"### \*\*bingo\*\*[^\n]*\n(.*?)(?=### \*\*(?:bingo|YOU)\*\*|\Z)",
    re.DOTALL,
)
# 코드 블록 제거
_CODE_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)

# Target URL 추출
_TARGET_RE = re.compile(r"New target:\s*(https?://[^\s/]+(?:/[^\s]*)?)")

# ── SQLi 의심 패턴 (bingo 요약 텍스트 기준) ──────────────────────
# 파라미터명이 백틱이나 따옴표로 감싸진 형태 + 크기 변화/주입 키워드
_SQLI_KEYWORDS = re.compile(
    r"(?:"
    # Chinese
    r"响应大小有变化|大小.*?变化|可能存在SQL注入|SQL注入.*?可能|"
    r"时间盲注.*?确认|盲注.*?成功|错误注入.*?成功|注入.*?成功|"
    r"SQL注入.*?确认|SQLi.*?确认|"
    # Korean
    r"응답.*?크기.*?차이|SQLi.*?가능|SQL.*?인젝션.*?가능|"
    r"시간.*?지연.*?확인|SQLi.*?확인|블라인드.*?SQLi|"
    # English
    r"size.*?differ|possible.*?sql.*?inject|blind.*?sqli|"
    r"time.*?delay.*?confirm|sql.*?inject.*?confirm|"
    # v3.2.71 내부 마커
    r"\[SQLi크기변화감지\]|\[SQLi尺寸变化检测\]|\[SQLi Size Diff Detected\]"
    r")",
    re.I,
)
# 파라미터명 추출 (백틱/따옴표 감싸기)
_PARAM_BACKTICK_RE = re.compile(r"[`'\"](\w+)[`'\"]")
# URL 추출 (https://... or /path/to/endpoint)
_URL_FULL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
_PATH_RE = re.compile(r"(?<![\"'/])(/[a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\.]+)*\.(?:do|jsp|json|aspx|php|action|html))")

# ── 유저 확인 패턴 ────────────────────────────────────────────────
# checkId.do - userid=XXX code=0001 패턴
_USER_CODE0001_RE = re.compile(
    r"userid[=：\s:]+[`'\"]?(\w+)[`'\"]?[^)]{0,80}code[=：\s:][`'\"]?0001[`'\"]?",
    re.I | re.DOTALL,
)
# 발견/확인 표현 + 유저명 패턴
_USER_FOUND_RE = re.compile(
    r"(?:已存在|user.*?exist|존재.*?확인|사용자.*?존재)[^：:\n]{0,30}[：:\s]+[`'\"]?(\w+)[`'\"]?",
    re.I,
)
# "존재하는 사용자: admin, user1" 형태
_USER_LIST_RE = re.compile(
    r"(?:存在的用户|확인된.*?유저|existing.*?user)[：:\s]+([^\n]{2,80})",
    re.I,
)

# ── 엔드포인트 발견 패턴 ─────────────────────────────────────────
_EP_FOUND_RE = re.compile(
    r"(?:发现|找到|关键端点|discovered|found|발견|확인)[^：:\n]{0,20}[`'\"]?(/[a-zA-Z0-9_/\-\.]+\.(?:do|jsp|json|aspx|php|action))[`'\"]?",
    re.I,
)
_EP_LOGIN_RE = re.compile(
    r"(/(?:login|auth|member|join|admin)[a-zA-Z0-9_/\-\.]*\.(?:do|jsp|json|aspx|php|action))",
    re.I,
)


class ParseResult(NamedTuple):
    target: str | None
    sqli_points: list[dict]
    confirmed_users: list[str]
    endpoints: list[dict]
    notes: list[str]


def parse_session_log(log_path: Path) -> ParseResult:
    """세션 로그 파일 하나를 파싱해서 발견 정보를 반환."""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ParseResult(None, [], [], [], [])

    # 1. Target URL 추출
    target: str | None = None
    tm = _TARGET_RE.search(text)
    if tm:
        target = tm.group(1).rstrip("/.,")

    # 2. bingo 요약 섹션만 추출 (코드블록 제거)
    sections: list[str] = []
    for m in _SECTION_RE.finditer(text):
        raw = m.group(1)
        clean = _CODE_BLOCK_RE.sub(" ", raw).strip()
        if clean:
            sections.append(clean)

    sqli_points: list[dict] = []
    confirmed_users: list[str] = []
    endpoints: list[dict] = []
    notes: list[str] = []

    _seen_sqli: set[str] = set()
    _seen_users: set[str] = set()
    _seen_eps: set[str] = set()

    for section in sections:
        # ── SQLi 탐지 ─────────────────────────────────────────────
        if _SQLI_KEYWORDS.search(section):
            # 파라미터명 추출 (가장 가까운 백틱 감싸기)
            params = _PARAM_BACKTICK_RE.findall(section)
            # URL 추출
            full_urls = _URL_FULL_RE.findall(section)
            paths = _PATH_RE.findall(section)

            # 파라미터 중 SQL 관련 가능성 높은 것 (short words = param names)
            sqli_params = [p for p in params if 2 <= len(p) <= 30 and not p.startswith("http")]

            base_url = target or ""
            for url in (full_urls or [base_url]):
                url = url.rstrip(".,)")
                for param in (sqli_params or ["unknown"]):
                    key = f"{url}:{param}"
                    if key not in _seen_sqli:
                        _seen_sqli.add(key)
                        sqli_points.append({
                            "url": url,
                            "param": param,
                            "method": "GET",
                            "sqli_type": _guess_sqli_type(section),
                            "evidence": section[:300],
                        })

            # 경로만 있는 경우
            if not full_urls and paths:
                for path in paths[:3]:
                    url = (target or "") + path
                    for param in (sqli_params or ["unknown"]):
                        key = f"{url}:{param}"
                        if key not in _seen_sqli:
                            _seen_sqli.add(key)
                            sqli_points.append({
                                "url": url,
                                "param": param,
                                "method": "GET",
                                "sqli_type": _guess_sqli_type(section),
                                "evidence": section[:300],
                            })

        # ── 유저 탐지 ─────────────────────────────────────────────
        for um in _USER_CODE0001_RE.finditer(section):
            user = um.group(1).strip()
            if user and user not in _seen_users and len(user) <= 30:
                _seen_users.add(user)
                confirmed_users.append(user)

        for um in _USER_FOUND_RE.finditer(section):
            user = um.group(1).strip()
            if user and user not in _seen_users and len(user) <= 30:
                _seen_users.add(user)
                confirmed_users.append(user)

        for um in _USER_LIST_RE.finditer(section):
            raw_list = um.group(1)
            for tok in re.split(r"[,\s，、]+", raw_list):
                tok = tok.strip().strip("`'\"")
                if tok and tok not in _seen_users and 1 <= len(tok) <= 30:
                    _seen_users.add(tok)
                    confirmed_users.append(tok)

        # ── 엔드포인트 탐지 ──────────────────────────────────────
        for em in _EP_FOUND_RE.finditer(section):
            ep = em.group(1)
            if ep not in _seen_eps:
                _seen_eps.add(ep)
                endpoints.append({"url": ep, "status": 200, "note": "session log"})

        # login/admin 경로도 수집
        for em in _EP_LOGIN_RE.finditer(section):
            ep = em.group(1)
            if ep not in _seen_eps:
                _seen_eps.add(ep)
                endpoints.append({"url": ep, "status": 200, "note": "session log"})

        # ── 주요 노트 (MSSQL 확인, WAF 우회 성공 등) ────────────
        note = _extract_note(section)
        if note:
            notes.append(note)

    return ParseResult(
        target=target,
        sqli_points=sqli_points,
        confirmed_users=confirmed_users,
        endpoints=endpoints[:20],
        notes=notes[:5],
    )


def _guess_sqli_type(text: str) -> str:
    """SQLi 유형 추측."""
    t = text.lower()
    if any(k in t for k in ["time", "delay", "waitfor", "sleep", "시간", "时间"]):
        return "time-based"
    if any(k in t for k in ["error", "syntax", "错误", "에러", "오류"]):
        return "error-based"
    if any(k in t for k in ["boolean", "bool", "and 1=", "1=1", "true", "false", "布尔", "블리안"]):
        return "boolean-blind"
    if any(k in t for k in ["union", "联合", "유니온"]):
        return "union"
    if any(k in t for k in ["size", "大小", "크기", "변화", "变化", "differ"]):
        return "size-based"
    return "unknown"


def _extract_note(text: str) -> str | None:
    """중요 관찰 내용 추출."""
    notes_kw = [
        (r"MSSQL|SQL\s*Server", "DB: MSSQL"),
        (r"MySQL", "DB: MySQL"),
        (r"Oracle", "DB: Oracle"),
        (r"PostgreSQL", "DB: PostgreSQL"),
        (r"WAF.*?绕过|bypass.*?WAF|WAF.*?우회", "WAF bypass confirmed"),
        (r"Cloudflare|cloudflare", "Uses Cloudflare WAF"),
        (r"checkId.*?enumerate|枚举.*?用户", "User enumeration via checkId.do"),
    ]
    for pattern, label in notes_kw:
        if re.search(pattern, text, re.I):
            return label
    return None


def parse_all_sessions_for_target(target: str) -> ParseResult:
    """
    특정 타겟과 관련된 모든 세션 로그를 파싱해서 정보를 통합 반환.
    target: URL 문자열 (e.g. "https://www.kira.or.kr")
    """
    if not _SESSIONS_DIR.exists():
        return ParseResult(target, [], [], [], [])

    # 타겟 도메인 추출
    domain_m = re.search(r"https?://([^/]+)", target)
    domain = domain_m.group(1) if domain_m else target

    all_sqli: list[dict] = []
    all_users: list[str] = []
    all_eps: list[dict] = []
    all_notes: list[str] = []

    _seen_sqli: set[str] = set()
    _seen_users: set[str] = set()
    _seen_eps: set[str] = set()

    # 최신 순으로 정렬
    log_files = sorted(_SESSIONS_DIR.glob("session_*.md"), reverse=True)

    for log_file in log_files:
        # 파일이 이 타겟 관련인지 확인 (파일 내에 도메인 포함 여부)
        try:
            header = log_file.read_text(encoding="utf-8", errors="replace")[:2000]
        except Exception:
            continue
        if domain not in header:
            continue

        result = parse_session_log(log_file)

        for pt in result.sqli_points:
            key = f"{pt['url']}:{pt['param']}"
            if key not in _seen_sqli:
                _seen_sqli.add(key)
                all_sqli.append(pt)

        for u in result.confirmed_users:
            if u not in _seen_users:
                _seen_users.add(u)
                all_users.append(u)

        for ep in result.endpoints:
            if ep["url"] not in _seen_eps:
                _seen_eps.add(ep["url"])
                all_eps.append(ep)

        for n in result.notes:
            if n not in all_notes:
                all_notes.append(n)

    return ParseResult(
        target=target,
        sqli_points=all_sqli,
        confirmed_users=all_users,
        endpoints=all_eps[:20],
        notes=all_notes[:5],
    )


def parse_and_save_to_memory(log_path: Path, target: str) -> tuple[int, int, int]:
    """
    세션 로그를 파싱해 target_memory에 저장.
    terminal.py 세션 종료 시점에 호출.

    Returns: (sqli_count, user_count, ep_count)
    """
    try:
        from .target_memory import record_sqli_point, record_users, record_endpoint, save as tm_save
    except ImportError:
        return (0, 0, 0)

    result = parse_session_log(log_path)

    for pt in result.sqli_points:
        try:
            record_sqli_point(
                target,
                pt["url"],
                pt["param"],
                pt.get("method", "GET"),
                sqli_type=pt.get("sqli_type", "unknown"),
            )
        except Exception:
            pass

    if result.confirmed_users:
        try:
            record_users(target, result.confirmed_users)
        except Exception:
            pass

    for ep in result.endpoints:
        try:
            record_endpoint(target, ep["url"], ep.get("status", 200), ep.get("note", ""))
        except Exception:
            pass

    if result.notes:
        try:
            from .target_memory import load as tm_load
            mem = tm_load(target)
            existing = mem.get("notes", [])
            for n in result.notes:
                if n not in existing:
                    existing.append(n)
            tm_save(target, {"notes": existing})
        except Exception:
            pass

    return (
        len(result.sqli_points),
        len(result.confirmed_users),
        len(result.endpoints),
    )
