"""bingo/tools/findings_exporter.py — 실시간 취약점 발견 자동 저장 엔진

실제 침투 테스트 중 코드 실행 결과에서 유의미한 발견을 자동으로 감지하고
JSON 파일로 누적 저장. 세션 종료 후 바로 리포팅/후속 분석에 활용.

지원 패턴:
  - SQL 인젝션: DB명/테이블/컬럼/계정 추출 결과
  - XSS: payload 실행 확인 (alert, DOM mutation)
  - SSRF: 내부망 응답 / cloud metadata 획득
  - 파일 읽기 (LFI/RFI): /etc/passwd, config 등
  - 인증 우회: 관리자 패널 접근, 토큰 탈취
  - RCE: 명령 실행 결과
  - 자격 증명: 아이디/비밀번호 추출
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# ─── 발견 유형 ───────────────────────────────────────────────────────────────
FINDING_SQLI        = "sqli"
FINDING_XSS         = "xss"
FINDING_SSRF        = "ssrf"
FINDING_LFI         = "lfi"
FINDING_RCE         = "rce"
FINDING_AUTH_BYPASS = "auth_bypass"
FINDING_CREDENTIAL  = "credential"
FINDING_INFO_DISC   = "info_disclosure"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"


@dataclass
class Finding:
    id: str
    vuln_type: str
    severity: str
    target: str
    payload: str
    evidence: str           # 실제 응답/결과 (잘린 최대 2000자)
    timestamp: float = field(default_factory=time.time)
    confirmed: bool = False  # Playwright 등으로 2차 검증 완료 여부
    screenshot_path: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_str"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        return d


# ─── 패턴 탐지 규칙 ──────────────────────────────────────────────────────────

_SQLI_PATTERNS = [
    # DB명 / 테이블명 추출 결과
    # v6.2.39: 'public' 제거 — <!DOCTYPE HTML PUBLIC> 에서 오탐 발생. public 은 DB context 별도 패턴으로.
    re.compile(r'\b(master|tempdb|model|msdb|information_schema|mysql|postgres)\b', re.I),
    # v6.2.39: public은 PostgreSQL schema 패턴으로만 인식 (단독 public 금지 — DOCTYPE 오탐)
    re.compile(r'\bpublic\b.*?\b(?:schema|table|column|pg_tables|pg_class)\b', re.I),
    re.compile(r'\b(dbo|sysobjects|syscolumns|sys\.tables|sys\.columns)\b', re.I),
    # 자격 증명 추출
    re.compile(r'\b(admin|administrator|root|sa|dba|superuser)\b.*?(password|passwd|pwd|hash)', re.I),
    # 구체적 추출 패턴
    re.compile(r'(table_name|column_name|table_schema)\s*[=:]\s*[\'"]?\w', re.I),
    # v5.1.1 FIX: "extractvalue" 단어 단독 매칭 → bash echo 문("EXTRACTVALUE 458B")에서 오발.
    # 반드시 SQL 함수 호출 형태(괄호 포함)여야 실제 주입 시도로 인정.
    # 이전: re.compile(r'extractvalue|updatexml|group_concat.*from', re.I)  ← echo 오발
    re.compile(r'extractvalue\s*\(|updatexml\s*\(|group_concat\s*\([^)]*\)\s+from\s', re.I),
]

_XSS_PATTERNS = [
    # v5.1.1 FIX: <script src="x.js"></script> 는 정상 외부 스크립트 — XSS 아님.
    # src= 속성 없는 인라인 스크립트(내용 있음)만 매칭.
    # v6.2.39 FIX: location.replace/href/assign 만 있는 스크립트는 서버 리다이렉트 — XSS 아님.
    # 예: <script>location.replace('../../');</script> — WAF 리다이렉트 응답이므로 오탐.
    # 반드시 실제 공격용 JS (alert/eval/document/fetch 등) 포함 시에만 XSS 인정.
    re.compile(
        r'<script\b(?![^>]*\bsrc\s*=)[^>]*>'
        r'(?![^<]*\blocation\.(?:replace|href|assign|reload)\b[^<]*</script>)'
        r'[^<\s]',
        re.I
    ),
    # v6.2.145 FIX: alert() 단독 패턴 삭제 → _is_server_alert_response() 함수로 대체.
    # 기존 패턴이 서버 자체 생성 alert('등록된 하위 메뉴가 없습니다.') 등을 XSS로 오탐.
    # 실제 XSS alert는 _detect_vuln_type 에서 페이로드 반영 여부 확인 후 처리.
    # v5.1.1 FIX: onerror= 단독(이벤트 핸들러 속성 이름만)도 오발.
    # 실행 함수(alert/eval/document/fetch 등)가 포함된 경우만 매칭.
    re.compile(r'(?:onerror|onload|onfocus|onmouseover)\s*=\s*["\']?\s*(?:alert|eval|document\.|window\.|fetch\s*\(|location\.)', re.I),
    re.compile(r'\bXSS\b.*?(confirmed|실행|성공|detected)', re.I),
    re.compile(r'window\.__BINGO_XSS__\s*=\s*1', re.I),
]

# v6.2.145: 서버 자체 생성 alert() 오탐 방지
# 서버가 직접 출력하는 alert('에러메시지'); history.back() 패턴 — XSS 아님
_SERVER_ALERT_PATTERN = re.compile(
    r'<script[^>]*>\s*alert\s*\(\s*["\'][^"\']*["\'][^)]*\)\s*;?\s*'
    r'(?:history\.back|location\.|window\.location)',
    re.I | re.DOTALL,
)
# XSS 페이로드가 코드/URL에 포함됐는지 확인 (진짜 XSS 공격 시도)
_XSS_PAYLOAD_IN_CODE = re.compile(
    r'(?:<script|alert\s*\(|onerror\s*=|javascript:|<img[^>]+on\w+=|<svg[^>]+on\w+=|%3cscript|%3ealert)',
    re.I,
)

_XSS_URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>]+(?:%3C|<)(?:script|img|svg|body)[^\s"\'<>]*',
    re.I
)

_SSRF_PATTERNS = [
    re.compile(r'169\.254\.169\.254'),                           # AWS metadata
    re.compile(r'metadata\.google\.internal', re.I),
    re.compile(r'169\.254\.170\.2'),                             # ECS metadata
    re.compile(r'fd00:ec2::254'),                                # IPv6 metadata
    re.compile(r'(internal|intranet|localhost|127\.0\.0\.).*?(200 OK|\bOK\b)', re.I),
]

_LFI_PATTERNS = [
    re.compile(r'root:[^:]+:[^:]+:[^:]+:[^:]+:/\w'),           # /etc/passwd actual content
    re.compile(r'\[global\].*?\[database\]', re.I | re.DOTALL),
    # env file — key=value pair required (not just a mention)
    re.compile(r'(DB_HOST|DB_PASSWORD|DB_USER|SECRET_KEY|APP_KEY)\s*=\s*\S', re.I),
    # v4.9.4: PHP source code — require actual code token, not just <?php mention
    # <?php mention alone is too broad (matches PHP error pages, docs, source comments)
    re.compile(r'<\?php\s+(?:function|class|namespace|echo|require|include|\$[a-zA-Z_])', re.I),
    # mysql/apache config file — key=value required, not just "database ... password" text
    re.compile(r'(?:^|\n)\s*password\s*=\s*\S{3,}', re.I),
]

# v4.9.4: LFI 오탐 방지 패턴
# php://filter 요청이 홈페이지로 리다이렉트된 경우 구별
_LFI_REDIRECT_HTML = re.compile(
    r'<(?:html|head|meta|body|title|div|span|script)[^>]*>',
    re.I
)
_PHP_FILTER_IN_OUTPUT = re.compile(
    r'php://filter/(?:convert\.base64-encode|read=[^/\s]+)/resource=',
    re.I
)
# 실제 LFI 성공 시 나타나는 base64 인코딩 파일 내용 (100자 이상 연속 base64)
_BASE64_FILE_BLOCK = re.compile(
    r'(?:^|[\s\'"\n])([A-Za-z0-9+/]{100,}={0,2})(?:\s|\'|"|$)',
    re.M
)

_RCE_PATTERNS = [
    re.compile(r'\buid=\d+\([^)]+\)\s+gid=\d+', re.I),        # id 명령어
    re.compile(r'(Linux|Darwin|Windows)\s+\S+\s+\S+\s+\S+\s+(x86_64|arm)', re.I),  # uname
    re.compile(r'whoami.*:\s*\w+', re.I),
    re.compile(r'cat /etc/(passwd|shadow|hosts)', re.I),
    re.compile(r'web\.config|system\.ini|boot\.ini', re.I),
]

_CRED_PATTERNS = [
    # v6.2.83: (?<!\.) 추가 — JS 객체 속성 접근(e.password=Authorization+...) 오탐 방지
    # 이전: 단순 password= 매칭 → e.password=Authorization+(o.password||) 에서 오탐 발생
    # v6.2.66: JS 미니파이 오탐 방지 — 값에 JS 구문 문자({}()[]) 포함 시 매칭 제외, 최소 6자
    re.compile(r'(?<!\.)(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{6,})[\'"]', re.I),   # 따옴표 감싼 값
    re.compile(r'(?<!\.)(?:password|passwd|pwd)\s*=\s*([a-zA-Z0-9@._\-!$%^&*+]{6,})(?!\s*[+|&(;])', re.I),  # = 할당만 (JS 연산자 후속 제외)
    re.compile(r'(?:admin|root|sa)\s*[/|:]\s*([a-zA-Z0-9@._\-!$%^&*+]{6,})', re.I),
    re.compile(r'\$2[aby]\$\d+\$[./A-Za-z0-9]{53}'),          # bcrypt hash (very specific)
    # v6.2.10: MD5/SHA 해시 — 세션쿠키 오탐 억제를 위해 "password" 또는 "hash" 컨텍스트 필요
    re.compile(r'(?:hash|passwd|md5|sha1|sha256)\s*[:=]\s*([0-9a-f]{32,64})', re.I),
]

# v6.2.66: 미니파이 JS 출력 감지 — JS chunk 다운로드 출력에서 credential 오탐 방지
# v6.2.83: JS 코드 분석 결과 출력(다운로드 컨텍스트 없이도 JS 코드 내용 자체)도 감지
_MINIFIED_JS_CONTEXT = re.compile(
    r'(?:'
    r'下载:\s*\S+\.js\s*\('          # 중국어: "下载: xxx.js (xxxB)"
    r'|download(?:ing)?:\s*\S+\.js'  # 영어: "downloading: xxx.js"
    r'|\S+\.js\s*\(\d+B\)'           # "chunk.js (12345B)"
    r'|chunk大小:\s*\d+'             # chunk大小 (중국어)
    r'|chunk대small:\s*\d+'          # (혼용 방지용)
    r'|__next_f\.push'               # Next.js SSR flush
    r'|webpackChunk|webpackBootstrap'
    r'|_next/static/chunks/'
    r'|statics\.\w+\.com.*\.js'      # CDN에서 JS 다운로드
    # v6.2.83: JS 코드 자체에서 credential 오탐 방지
    r'|withXsrfToken|withCredentials'        # JS XHR 속성명 — 코드 내 JS 구조
    r'|\w\.\w{1,4}=\w{2,}\+\('              # e.b=Func+( 패턴 — JS 미니파이 연산
    r'|\|\|[a-zA-Z_$]\)|=[a-zA-Z_$]+\+\('  # ||t) 또는 =Auth+( — JS 논리연산자
    r')',
    re.I
)

# v4.8.0: SQLi 컨텍스트 키워드 — 코드에 이것이 있으면 credential보다 sqli 우선
_SQLI_CONTEXT_KEYWORDS = re.compile(
    r'extractvalue|updatexml|information_schema|group_concat|sleep\s*\('
    r'|waitfor\s+delay|union\s+select|blind\s+sqli|time.?based|boolean.?based'
    r'|time_based|sqli|sql.?inject',
    re.I
)

# v5.1.1: WAF 차단 응답 조기 종료 패턴
# 소형 응답(≤ 2KB) + 차단 메시지 → 취약점 없음, 모든 패턴 검사 건너뜀
# 방어 원리: WAF가 요청을 차단했다는 것은 페이로드가 서버에 도달 못했음 → 취약점 증명 불가
_WAF_BLOCK_KO = re.compile(
    r'(?:요청이\s*차단|차단\s*되었습니다|보안\s*정책\s*위반|접근.*차단|차단.*접근)',
    re.I,
)
_WAF_BLOCK_EN = re.compile(
    r'(?:request\s+(?:has\s+been\s+)?blocked|access\s+denied\s+by|blocked\s+by\s+(?:waf|security|policy))',
    re.I,
)

# v6.2.16: WAF 보안 도메인 302 리다이렉트 패턴 (페이로드 차단 = 취약점 없음)
# 예: Location: http://sh1.igear.co.kr/secure/index.html → WAF payload block, NOT sqli evidence
_WAF_SECURITY_REDIRECT = re.compile(
    r'location\s*:\s*https?://(?:'
    r'[a-z0-9.-]*igear\.co\.kr'      # igear WAF (Korea)
    r'|[a-z0-9.-]*securecp\.co\.kr'  # SecureCP WAF (Korea)
    r'|[a-z0-9.-]*cloudbric\.'       # Cloudbric WAF (Korea)
    r'|[a-z0-9.-]*sitelock\.'        # SiteLock WAF
    r'|[a-z0-9.-]*sucuri\.'          # Sucuri WAF
    r'|[a-z0-9.-]*incapsula\.'       # Imperva/Incapsula WAF
    r'|[a-z0-9.-]*akamai\.'          # Akamai WAF
    r'|[a-z0-9.-]*cloudflare\.com/cdn-cgi/error'  # Cloudflare block
    r')/(?:secure|block|blocked|deny|error|403)',
    re.I,
)

# v4.9.4: Oracle 실패 오탐 억제 패턴
# 추출된 값이 동일 문자의 반복이면 oracle이 실패한 것 (aaa..., bbb... 등)
_ORACLE_FAILURE_REPEATED = re.compile(
    r'[\'"]([a-zA-Z])\1{9,}[\'"]',   # 10개 이상 동일 문자: 'aaaaaaaaaa' 또는 'bbbbbbbbbb'
)
# oracle 무효 경고가 명시된 경우
_ORACLE_FAILURE_WARNING = re.compile(
    r'oracle\s*(?:可能)?(?:无效|invalid|unstable|不稳定|失效)'
    r'|⚠️\s*oracle'
    r'|oracle\s*might\s*be\s*invalid',
    re.I
)

_AUTH_BYPASS_PATTERNS = [
    re.compile(r'(관리자|admin)\s*(패널|panel|dashboard|로그인|login)\s*(성공|접근|완료|OK)', re.I),
    # v6.2.10: Set-Cookie 단독으론 auth_bypass 아님 — 제거 (세션쿠키 오탐 다수 발생)
    # re.compile(r'Set-Cookie:.*?(admin|session|auth|jwt)', re.I),  ← 삭제됨
    # HTTP 200 + admin — URL 경로가 실제로 admin이어야 함 (응답 헤더 텍스트 아님)
    re.compile(r'(Location|URL):\s*.*?/admin(?:/|$)', re.I),
    re.compile(r'(welcome|dashboard|admin)\s*-\s*(admin|root|manager)', re.I),
]


def _detect_vuln_type(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """출력 텍스트에서 취약점 유형과 심각도 탐지. 없으면 None.
    우선순위: RCE > LFI > AUTH_BYPASS > CREDENTIAL > SSRF > XSS > SQLi

    v4.8.0 수정: SQLi 컨텍스트(code_snippet에 EXTRACTVALUE/SLEEP 등) 포함 시
    CREDENTIAL보다 SQLi를 우선 분류 — 오분류 방지.

    v4.9.4 수정:
    - LFI 오탐 방지: php://filter 요청인데 HTML 응답(homepage redirect)이면 LFI 아님
    - Oracle 실패 억제: 추출값이 'aaa...' 반복 문자이면 credential/sqli 오탐 억제
    """
    # ── v6.2.168: 도구 자체 "NOT vulnerable" 판정 → 즉시 None ───────────────────
    # sqli_error / sqli_autoexploit 등이 명시적으로 취약하지 않다고 판단한 경우
    # 출력에 페이로드 텍스트(EXTRACTVALUE 등)가 포함돼 SQLI_PATTERNS에 오매칭되는 것 방지
    _NOT_VULN_RE = re.compile(
        r'NOT\s+vulnerable\s*[❌✗×⛔]'
        r'|→\s*NOT\s+vulnerable'
        r'|DB\s+errors\s+found:\s*None'
        r'|boolean\s+oracle.*?fail'
        r'|confirmed\s*[=:]\s*(?:false|0\b|False)',
        re.I
    )
    if _NOT_VULN_RE.search(output):
        return None

    # ── v5.1.1: WAF 차단 응답 조기 종료 ─────────────────────────────────────────
    # 소형 응답(≤ 2000B) + 한국어/영어 차단 메시지 → 취약점 감지 건너뜀.
    # WAF 차단 = 페이로드 미도달, 취약점 증명 불가. 오발 방지.
    if len(output) <= 2000 and (
        _WAF_BLOCK_KO.search(output) or _WAF_BLOCK_EN.search(output)
    ):
        return None

    # ── v6.2.168: Cloudflare 403/차단 응답 조기 종료 ─────────────────────────────
    # Cloudflare error page, Ray ID, CF challenge 등 → 페이로드 차단, 취약점 없음
    _CF_BLOCK_RE = re.compile(
        r'cloudflare.*?(error|blocked|denied)'
        r'|ray\s+id\s*:\s*[0-9a-f]+'
        r'|__cf_chl|cf-ray:'
        r'|error\s+1\d{3}\s+access\s+denied'
        r'|sorry,\s+you\s+have\s+been\s+blocked',
        re.I
    )
    if _CF_BLOCK_RE.search(output):
        return None

    # ── v6.2.16: WAF 보안도메인 302 리다이렉트 조기 종료 ─────────────────────────
    # 302 → igear/securecp/cloudbric 등 보안 도메인 = WAF 페이로드 차단.
    # 이는 취약점 증거가 아님 → 오탐 방지. IP 전체 차단도 아님 (특정 페이로드 차단).
    if _WAF_SECURITY_REDIRECT.search(output.lower()):
        return None

    # ── v4.9.4: Oracle 실패 조기 감지 ─────────────────────────────────────────
    # 추출된 값이 동일 문자 10개 이상 반복(aaa...) → oracle 실패로 인한 오탐 → 즉시 None
    if _ORACLE_FAILURE_REPEATED.search(output):
        return None

    # ── v6.2.66: 미니파이 JS 출력 감지 — credential 오탐 방지 ─────────────────
    # JS chunk 다운로드 결과(Next.js, webpack 등)이면 credential 패턴 건너뜀
    _is_js_chunk_output = bool(_MINIFIED_JS_CONTEXT.search(output))

    # ── v4.9.4: LFI php://filter 오탐 방지 ────────────────────────────────────
    # php://filter 요청이 감지됐는데 응답에 실제 base64 파일 내용 없고 HTML 페이지면
    # → 서버가 홈페이지/에러페이지로 리다이렉트한 것 → LFI 아님
    _skip_lfi = False
    if _PHP_FILTER_IN_OUTPUT.search(output) or _PHP_FILTER_IN_OUTPUT.search(code_snippet):
        # php://filter 테스트가 있음 → 실제 base64 파일 내용 있는지 확인
        _has_b64_content = bool(_BASE64_FILE_BLOCK.search(output))
        _has_html_redirect = bool(_LFI_REDIRECT_HTML.search(output))
        if _has_html_redirect and not _has_b64_content:
            # HTML 페이지가 응답 + base64 없음 → 리다이렉트 오탐 → LFI 검사 건너뜀
            _skip_lfi = True

    # ── v4.8.0: SQLi 컨텍스트 사전 검사 ──────────────────────────────────────
    # code_snippet 또는 output에 SQLi 키워드가 있으면 credential 검사를 SQLi 이후로
    _sqli_context = (
        _SQLI_CONTEXT_KEYWORDS.search(code_snippet)
        or _SQLI_CONTEXT_KEYWORDS.search(output)
    )

    if _sqli_context:
        # SQLi 컨텍스트 확인됨 → SQLi 패턴 먼저, credential은 SQLi 없을 때만
        checks = [
            (FINDING_RCE,         SEVERITY_CRITICAL, _RCE_PATTERNS),
            (FINDING_LFI,         SEVERITY_CRITICAL, _LFI_PATTERNS),
            (FINDING_AUTH_BYPASS, SEVERITY_CRITICAL, _AUTH_BYPASS_PATTERNS),
            (FINDING_SQLI,        SEVERITY_HIGH,     _SQLI_PATTERNS),   # SQLi 우선
            (FINDING_CREDENTIAL,  SEVERITY_CRITICAL, _CRED_PATTERNS),   # credential 후순위
            (FINDING_SSRF,        SEVERITY_HIGH,     _SSRF_PATTERNS),
            (FINDING_XSS,         SEVERITY_HIGH,     _XSS_PATTERNS),
        ]
    else:
        checks = [
            (FINDING_RCE,         SEVERITY_CRITICAL, _RCE_PATTERNS),
            (FINDING_LFI,         SEVERITY_CRITICAL, _LFI_PATTERNS),
            (FINDING_AUTH_BYPASS, SEVERITY_CRITICAL, _AUTH_BYPASS_PATTERNS),
            (FINDING_CREDENTIAL,  SEVERITY_CRITICAL, _CRED_PATTERNS),
            (FINDING_SSRF,        SEVERITY_HIGH,     _SSRF_PATTERNS),
            (FINDING_XSS,         SEVERITY_HIGH,     _XSS_PATTERNS),
            (FINDING_SQLI,        SEVERITY_HIGH,     _SQLI_PATTERNS),
        ]

    # v6.2.145: XSS 오탐 사전 판단 플래그
    # 서버 자체 생성 alert() + 코드에 XSS 페이로드 없음 → XSS 검사 건너뜀
    _skip_xss = False
    if _SERVER_ALERT_PATTERN.search(output) and not _XSS_PAYLOAD_IN_CODE.search(code_snippet):
        _skip_xss = True
    # 코드에도 XSS 페이로드가 없고 출력에 script+alert가 서버 응답 형태이면 오탐 가능성 高
    if not _XSS_PAYLOAD_IN_CODE.search(code_snippet) and not _XSS_PAYLOAD_IN_CODE.search(output):
        _skip_xss = True

    for vtype, sev, patterns in checks:
        # v4.9.4: LFI 오탐 방지 — php://filter+HTML redirect 조합이면 LFI 검사 건너뜀
        if vtype == FINDING_LFI and _skip_lfi:
            continue
        # v6.2.66: JS chunk 다운로드 출력 — credential 패턴 건너뜀 (미니파이 JS 오탐 방지)
        if vtype == FINDING_CREDENTIAL and _is_js_chunk_output:
            continue
        # v6.2.145: 서버 자체 생성 alert() 오탐 방지 — XSS 페이로드 미포함 시 건너뜀
        if vtype == FINDING_XSS and _skip_xss:
            continue
        for pat in patterns:
            if pat.search(output):
                return (vtype, sev)
    return None


def _extract_payload(output: str) -> str:
    """출력에서 페이로드/쿼리 라인 추출 (최대 300자)"""
    # payload = 또는 query = 또는 url = 로 시작하는 라인 우선
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r'^(payload|query|url|request|inject)\s*[=:]', stripped, re.I):
            return stripped[:300]
    # 없으면 URL 패턴에서
    m = re.search(r'https?://\S+', output)
    if m:
        return m.group(0)[:300]
    return output[:300].strip()


# ─── FindingsExporter ──────────────────────────────────────────────────────────

class FindingsExporter:
    """실시간 발견 누적 저장기.

    사용법:
        exporter = FindingsExporter(target="http://target.com")
        exporter.process(code_output_str)   # 매 코드 실행 후 호출
        exporter.save()                     # 세션 종료 시 저장
    """

    def __init__(self, target: str = "", output_dir: str | None = None) -> None:
        self.target = target
        self._findings: list[Finding] = []
        self._finding_hashes: set[str] = set()   # 중복 방지

        if output_dir:
            self._dir = Path(output_dir)
        else:
            # Desktop/dump/<target> 에 저장
            import platform
            safe = (target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:40]
            if platform.system() == "Darwin":
                base = Path.home() / "Desktop" / "dump" / safe
            elif platform.system() == "Windows":
                try:
                    import winreg
                    k = winreg.OpenKey(
                        winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                    )
                    base = Path(winreg.QueryValueEx(k, "Desktop")[0]) / "dump" / safe
                except Exception:
                    base = Path.home() / "Desktop" / "dump" / safe
            else:
                base = Path(os.environ.get("XDG_DESKTOP_DIR", str(Path.home() / "Desktop"))) / "dump" / safe

            _env_dir = os.environ.get("BINGO_REPORTS_DIR", "").strip()
            self._dir = Path(_env_dir) / safe if _env_dir else base

        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            self._dir = Path.cwd()

    # ── 공개 API ──────────────────────────────────────────────────────────────

    def process(
        self,
        output: str,
        code_snippet: str = "",
        extra_notes: str = "",
    ) -> Optional[Finding]:
        """코드 실행 출력에서 발견 탐지 후 내부 저장. 발견 시 Finding 반환."""
        if not output or len(output.strip()) < 10:
            return None

        # v4.8.0: code_snippet 전달 — SQLi 컨텍스트 기반 우선순위 조정
        detected = _detect_vuln_type(output, code_snippet=code_snippet)
        if not detected:
            return None

        vtype, severity = detected
        payload = code_snippet or _extract_payload(output)
        evidence = output[:2000]

        # 중복 제거: evidence 앞 200자 해시
        import hashlib
        _hash = hashlib.md5(
            (vtype + evidence[:200]).encode("utf-8", errors="ignore")
        ).hexdigest()[:12]
        if _hash in self._finding_hashes:
            return None
        self._finding_hashes.add(_hash)

        finding = Finding(
            id=f"BINGO-{len(self._findings)+1:04d}",
            vuln_type=vtype,
            severity=severity,
            target=self.target,
            payload=payload[:500],
            evidence=evidence,
            notes=extra_notes,
        )
        self._findings.append(finding)
        return finding

    def mark_confirmed(self, finding: Finding, screenshot_path: str = "") -> None:
        """Playwright 등 2차 검증 후 confirmed 플래그 세팅."""
        finding.confirmed = True
        if screenshot_path:
            finding.screenshot_path = screenshot_path

    def save(self) -> Path | None:
        """JSON 파일로 저장 후 경로 반환. 발견이 없으면 None."""
        if not self._findings:
            return None
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = (self.target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        path = self._dir / f"findings_{safe}_{ts}.json"
        data = {
            "bingo_version": _get_version(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "total": len(self._findings),
            "critical": sum(1 for f in self._findings if f.severity == SEVERITY_CRITICAL),
            "high": sum(1 for f in self._findings if f.severity == SEVERITY_HIGH),
            "confirmed": sum(1 for f in self._findings if f.confirmed),
            "findings": [f.to_dict() for f in self._findings],
        }
        try:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            # fallback to cwd
            path = Path.cwd() / f"findings_{safe}_{ts}.json"
            try:
                path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                return None
        return path

    def summary(self) -> str:
        """발견 요약 1줄"""
        total = len(self._findings)
        if not total:
            return ""
        crit = sum(1 for f in self._findings if f.severity == SEVERITY_CRITICAL)
        high = sum(1 for f in self._findings if f.severity == SEVERITY_HIGH)
        conf = sum(1 for f in self._findings if f.confirmed)
        parts = []
        if crit:
            parts.append(f"CRITICAL:{crit}")
        if high:
            parts.append(f"HIGH:{high}")
        if conf:
            parts.append(f"confirmed:{conf}")
        return f"[FINDINGS] total={total} " + " ".join(parts)

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    def extract_xss_urls(self, output: str) -> list[str]:
        """출력에서 XSS payload가 포함된 URL 추출 (Playwright 검증용)"""
        urls = []
        # <script>, %3Cscript, onerror= 등이 포함된 URL
        for m in _XSS_URL_PATTERN.finditer(output):
            urls.append(m.group(0))
        # 일반 URL + XSS 패턴
        for line in output.splitlines():
            stripped = line.strip()
            if re.search(r'https?://', stripped) and re.search(
                r'(<|%3C|%22|javascript:|onerror=|onload=)', stripped, re.I
            ):
                m_url = re.search(r'https?://\S+', stripped)
                if m_url and m_url.group(0) not in urls:
                    urls.append(m_url.group(0))
        return urls[:5]  # 최대 5개


def _get_version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "unknown"
