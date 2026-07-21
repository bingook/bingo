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
FINDING_USER_ENUM   = "user_enumeration"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"

# ─── v6.2.177 Evidence Ladder (단일 판정 기준) ───────────────────────────────
# CONFIRMED  : 추출/실행/브라우저 검증 — 보고서에서만 "已确认/Confirmed" 허용
# PROBABLE   : TRUE≠FALSE / time-based — 취약점 후보로 유지, Confirmed 금지
# POTENTIAL  : 모호한 신호 — 유지, Confirmed 금지
# BLOCKED    : WAF/동일크기/가짜해시 — 차단 이벤트 (취약점 확정 아님)
# NONE       : 신호 없음
CONF_CONFIRMED    = "confirmed"
CONF_PROBABLE     = "probable"
CONF_POTENTIAL    = "potential"
CONF_QUARANTINED  = "quarantined"
CONF_BLOCKED      = "blocked"
CONF_INCONCLUSIVE = "inconclusive"  # legacy alias → potential 취급
CONF_NONE         = "none"

# ladder 순위 (높을수록 확정)
_LADDER_RANK = {
    CONF_NONE: 0,
    CONF_BLOCKED: 1,
    CONF_QUARANTINED: 2,
    CONF_INCONCLUSIVE: 2,
    CONF_POTENTIAL: 3,
    CONF_PROBABLE: 4,
    CONF_CONFIRMED: 5,
}

REASON_BLOCKED_WAF_SAME_SIZE = "blocked_by_waf_same_size"
REASON_ORACLE_PRECHECK_FAIL  = "oracle_precheck_failed"
REASON_LOGIN_FORM_ONLY       = "login_form_only"
REASON_PLACEHOLDER_HASH      = "placeholder_hash"
REASON_PAGE_CONTAMINATION    = "page_contamination"
REASON_WAF_BLOCK_PAGE        = "waf_block_page"
REASON_NOT_VULNERABLE        = "not_vulnerable"
REASON_CF_BLOCK              = "cloudflare_block"
REASON_WAF_REDIRECT          = "waf_security_redirect"
REASON_BOOLEAN_DIFF          = "boolean_true_false_diff"
REASON_XPATH_EXTRACT         = "xpath_error_extract"
REASON_DB_TABLE_EXTRACT      = "db_table_extract"
REASON_REAL_CREDENTIAL       = "real_credential_extract"
REASON_RCE_PROOF             = "rce_command_output"
REASON_TIME_BASED            = "time_based_delay"
REASON_TIME_PRECHECK_FAIL    = "time_based_threshold_failed"
REASON_XSS_BROWSER           = "xss_browser_confirmed"
REASON_STRONG_OVERRIDE       = "strong_proof_overrides_fp"
REASON_PATTERN_MATCH         = "pattern_match_unverified"
REASON_PUBLIC_ARTIFACT       = "public_dependency_artifact"
REASON_STACK_TRACE_DISC      = "stack_trace_disclosure"
REASON_ADMIN_USER_ENUM       = "admin_username_enumeration"


@dataclass
class EvidenceVerdict:
    """v6.2.177: Evidence Ladder 단일 판정 결과."""
    tier: str          # confirmed|probable|potential|blocked|none
    reason_code: str
    vuln_hint: str = ""  # sqli|rce|credential|xss|... 또는 ""
    detail: str = ""

    @property
    def is_vuln_candidate(self) -> bool:
        return self.tier in (CONF_CONFIRMED, CONF_PROBABLE, CONF_POTENTIAL)

    @property
    def may_claim_confirmed(self) -> bool:
        return self.tier == CONF_CONFIRMED


@dataclass
class Finding:
    id: str
    vuln_type: str
    severity: str
    target: str
    payload: str
    evidence: str           # 실제 응답/결과 (잘린 최대 2000자)
    timestamp: float = field(default_factory=time.time)
    confirmed: bool = False  # Evidence Ladder CONFIRMED 만 True
    screenshot_path: str = ""
    notes: str = ""
    # confirmed|probable|potential|blocked|inconclusive
    confidence: str = CONF_POTENTIAL
    reason_code: str = ""
    scope_key: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_str"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        d["may_claim_confirmed"] = bool(self.confirmed or self.confidence == CONF_CONFIRMED)
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
_XSS_ACTIVE_PAYLOAD = re.compile(
    r'(?:<script|onerror\s*=|onload\s*=|javascript:|'
    r'<(?:img|svg|body)[^>]+on\w+\s*=|%3c(?:script|img|svg|body))',
    re.I,
)
_XSS_TEST_EVIDENCE = re.compile(
    r'(?:bINg0XsS\w*|BINGO[_-]?XSS|PAYLOAD[_ -]?REFLECTED|'
    r'XSS.{0,40}(?:confirmed|executed|browser\s+verified))',
    re.I,
)
_XSS_NEGATIVE_EVIDENCE = re.compile(
    r'NOT\s+REFLECTED|not\s+reflected|미반사|未反射|未找到\s*payload|'
    r'payload\s+not\s+found|browser_confirmed\s*[=:]\s*false|'
    r'browser\s+confirmed\s*[=:]\s*false|XSS_CANDIDATE|escaped|saniti[sz]ed|'
    r'no\s+xss|not\s+vulnerable|被过滤|过滤|被拦截|拦截|不存在|'
    r'(?:status|状态)\s*[:=]?\s*(?:403|404)\b|'
    r'\b(?:403|404)\s*/\s*\d+B\b|Location\s*=\s*N/A',
    re.I,
)
_XSS_TRIGGER_NOTICE = re.compile(
    r'\[XSS_TRIGGER_DETECTED\]|TOOL_CALL:\{[^}\n]*"xss_autotest"',
    re.I,
)
_XSS_POSITIVE_EVIDENCE = re.compile(
    r'window\.__BINGO_XSS__\s*=\s*1|browser_confirmed\s*[=:]\s*true|'
    r'browser\s+confirmed\s*[=:]\s*true|PAYLOAD[_ -]?REFLECTED|'
    r'unescaped\s+reflection|dialog\s+(?:opened|observed)|'
    r'XSS.{0,40}(?:confirmed|executed|browser\s+verified|success)',
    re.I,
)


def _xss_negative_only(output: str) -> bool:
    return bool(_XSS_NEGATIVE_EVIDENCE.search(output)) and not bool(
        _XSS_POSITIVE_EVIDENCE.search(output)
    )

_ACTIVE_HTTP_TEST = re.compile(
    r'\b(?:curl|wget|httpx|requests\.(?:get|post|request)|'
    r'session\.(?:get|post|request)|urllib|fetch\s*\(|page\.goto|dom_xss_test|'
    r'http_(?:get|post)|sqli_autoexploit|ssrf_check|lfi_check|rce_check)\b',
    re.I,
)
_ACTIVE_TEST_PAYLOADS = {
    FINDING_SQLI: re.compile(
        r'(?:union\s+(?:all\s+)?select|(?:or|and)\s+[\'"\d]+\s*=\s*[\'"\d]+'
        r'|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|extractvalue\s*\('
        r'|updatexml\s*\(|information_schema|sql.?inject|\bsqli\b)',
        re.I,
    ),
    FINDING_SSRF: re.compile(
        r'(?:169\.254\.(?:169\.254|170\.2)|metadata\.google\.internal|'
        r'127\.0\.0\.1|localhost|\[?::1\]?|gopher://|dict://|file://|\bssrf\b)',
        re.I,
    ),
    FINDING_LFI: re.compile(
        r'(?:\.\./|%2e%2e|php://filter|/etc/(?:passwd|shadow|hosts)|'
        r'/proc/self/environ|boot\.ini|win\.ini|\blfi\b|local.?file.?inclusion)',
        re.I,
    ),
    FINDING_RCE: re.compile(
        r'(?:[;&|`]\s*(?:id|whoami|uname|cat|type|dir)\b|\$\([^)]*\)|'
        r'[\'\"]?(?:cmd|command|exec|shell)[\'\"]?\s*[=:]|\brce\b|remote.?code.?execution)',
        re.I,
    ),
    FINDING_AUTH_BYPASS: re.compile(
        r'(?:/admin(?:/|\b)|authorization|bearer\s+|cookie\s*[=:]|'
        r'jwt|auth.?bypass|login.?bypass|role\s*[=:]\s*[\'\"]?admin)',
        re.I,
    ),
    FINDING_CREDENTIAL: re.compile(
        r'(?:credential|password|passwd|hash|dump|extract|\bsqli\b|sql.?inject)',
        re.I,
    ),
}


def _execution_code(code_snippet: str, execution_context: dict | None) -> str:
    if execution_context:
        scripts = execution_context.get("scripts", [])
        structured = "\n".join(
            str(item.get("code", ""))
            for item in scripts
            if isinstance(item, dict)
        )
        if structured.strip():
            return structured
    return code_snippet or ""


def _finding_scope(
    vtype: str,
    output: str,
    code_snippet: str,
    execution_context: dict | None = None,
) -> str:
    """Build a stable endpoint/parameter identity for reversible verdicts."""
    from urllib.parse import parse_qs, urlsplit

    code = _execution_code(code_snippet, execution_context)
    combined = code + "\n" + output[:1000]
    url_match = re.search(r'https?://[^\s\'"<>]+', combined, re.I)
    endpoint = ""
    query_param = ""
    if url_match:
        raw_url = url_match.group(0).rstrip("),.;}")
        parsed = urlsplit(raw_url)
        endpoint = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
        query = parse_qs(parsed.query)
        if query:
            query_param = next(iter(query))

    param_match = re.search(
        r'[\'\"](?:param|parameter)[\'\"]\s*:\s*[\'\"]([A-Za-z_][\w-]*)'
        r'|\bparam(?:eter)?\s*[=:]\s*[\'\"]?([A-Za-z_][\w-]*)',
        combined,
        re.I,
    )
    param = next((group for group in (param_match.groups() if param_match else ()) if group), "")
    param = param or query_param
    return f"{vtype}|{endpoint or 'unknown'}|{param or 'unknown'}"


def _scopes_compatible(left: str, right: str) -> bool:
    try:
        left_type, left_endpoint, left_param = left.split("|", 2)
        right_type, right_endpoint, right_param = right.split("|", 2)
    except ValueError:
        return left == right
    endpoint_match = (
        left_endpoint == right_endpoint
        or "unknown" in (left_endpoint, right_endpoint)
    )
    param_match = left_param == right_param or "unknown" in (left_param, right_param)
    return left_type == right_type and endpoint_match and param_match


def _potential_disposition(
    vtype: str,
    output: str,
    code_snippet: str,
    execution_context: dict | None = None,
) -> tuple[str, str]:
    """Return keep/quarantine/reject for pattern-only evidence."""
    code = _execution_code(code_snippet, execution_context)
    if vtype == FINDING_XSS:
        if _xss_negative_only(output):
            return "reject", "xss_negative_verification"
        if _XSS_TRIGGER_NOTICE.search(output) and not _XSS_POSITIVE_EVIDENCE.search(output):
            return "reject", "xss_trigger_notice_without_evidence"
        if _XSS_TEST_EVIDENCE.search(output):
            return "keep", ""
        if _ACTIVE_HTTP_TEST.search(code) and _XSS_ACTIVE_PAYLOAD.search(code):
            return "keep", ""
        if _SERVER_ALERT_PATTERN.search(output):
            return "reject", "xss_server_alert_false_positive"
        return "quarantine", "xss_pattern_without_active_test"

    payload_pattern = _ACTIVE_TEST_PAYLOADS.get(vtype)
    if payload_pattern and _ACTIVE_HTTP_TEST.search(code) and payload_pattern.search(code):
        return "keep", ""
    return "quarantine", f"{vtype}_pattern_without_active_test"

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
    re.compile(
        r'(?:^|\s|\[CREDENTIAL\]\s*)(?:admin|root|sa)\s*:\s*'
        r'([a-zA-Z0-9@._\-!$%^&*+]{6,})(?=\s|$)',
        re.I,
    ),
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

# A control response that is an HTTP/WAF block is not a Boolean oracle.  Keep
# this deliberately scoped to control-pair parsing so ordinary HTTP 403 pages
# can still be retained as protected/indeterminate evidence elsewhere.
_CONTROL_BLOCK_RE = re.compile(
    r'\b(?:HTTP(?:/\d(?:\.\d)?)?\s*)?403\b'
    r'|\b199B\b|\b598B\b'
    r'|\b(?:waf|firewall|security\s+policy|access\s+denied|request\s+blocked)\b'
    r'|요청이\s*차단|보안\s*정책\s*위반|차단\s*되었습니다',
    re.I,
)

# Labels/form templates are not disclosure.  A real disclosure requires a
# non-baseline record/value; labels with ROWS=0 are a blocked observation.
_INFO_LABEL_ONLY_RE = re.compile(
    r'(?:personal\s*=\s*true|보호자|환자명|환자\s*정보|guardian|patient)'
    r'.{0,240}?(?:rows?\s*[=:]\s*0|결과\s*없음|no\s+records?|empty)',
    re.I | re.S,
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

# v4.9.4 / v6.2.174: Oracle 실패 오탐 억제 패턴
# 추출된 값이 동일 문자 반복이면 oracle 실패 (따옴표 유무·숫자 포함)
_ORACLE_FAILURE_REPEATED = re.compile(
    r'(?:'
    r'[\'"]([a-zA-Z0-9~!@#])\1{7,}[\'"]'   # 'aaaaaaaa' / "00000000" / '~~~~~~~~'
    r'|(?<![a-zA-Z0-9])([a-zA-Z0-9~!@#])\2{9,}(?![a-zA-Z0-9])'  # 따옴표 없는 aaaa... / 0000...
    r')'
)
# oracle 무효 경고가 명시된 경우 (다국어 + 도구 자체 경고)
_ORACLE_FAILURE_WARNING = re.compile(
    r'oracle\s*(?:可能)?(?:无效|invalid|unstable|不稳定|失效|unreliable|失败|失敗)'
    r'|⚠️\s*oracle'
    r'|oracle\s*might\s*be\s*invalid'
    r'|oracle\s*pre-?check\s*(?:fail|FAILED)'
    r'|Oracle预检失败'
    r'|TRUE/FALSE\s*(?:无法区分|indistinguishable|구분\s*불가)'
    r'|SQLI_ORACLE_REJECTED'
    r'|SQLI_EXTRACTION_FAILURE'
    r'|SQLI_NO_VALID_CHANNEL'
    r'|Boolean\s+oracle\s+may\s+be\s+unreliable'
    r'|WAF\s*(?:全部拦截|全部拦截|屏蔽所有|blocking\s+all)'
    r'|oracle\s*all-?same'
    r'|Oracle全同字符',
    re.I
)

# v6.2.174: 로그인 폼 HTML만 파싱한 경우 credential 오탐 방지
_LOGIN_FORM_ONLY = re.compile(
    r'(?:\[LOGIN\s+SIZE\]|\[FORM\]|\[INPUTS\]|loginFrm|login_check\.php'
    r'|placeholder=["\'](?:아이디|비밀번호|ID|Password|用户名|密码))',
    re.I,
)
# v6.2.174: 깨진 oracle이 만든 가짜 해시/자격증명 (전부 0, 순차 hex 등)
_FAKE_CRED_VALUE = re.compile(
    r'(?:'
    r'\[CREDENTIAL\]\s*\S+\s*:\s*(?:0{8,}|a{8,}|A{8,}|f{8,}|F{8,}|x{8,}|0123456789abcdef)'
    r'|(?:hash|password|passwd|pwd)\s*[:=]\s*[\'"]?(?:0{8,}|a{8,}|0123456789abcdef)[\'"]?'
    r'|Hash:\s*(?:0{6,}|0123456789abcdef)'
    r')',
    re.I,
)


_PUBLIC_DEP_ARTIFACT_PATH_RE = re.compile(
    r'(?m)(?:^|\s)(?:OPEN\s+)?'
    r'(/(?:composer\.(?:json|lock)|vendor/composer/installed\.json))'
    r'\s*->\s*200\b[^\n]{0,700}',
    re.I,
)
_PUBLIC_DEP_ARTIFACT_CONTENT_RE = re.compile(
    r'"require"\s*:\s*\{'
    r'|"_readme"\s*:\s*\['
    r'|"packages"\s*:\s*\['
    r'|"name"\s*:\s*"[^"]+/[^"]+"'
    r'|\bPKG\s+[a-z0-9_.-]+/[a-z0-9_.-]+@?v?\d',
    re.I,
)
_STACK_TRACE_DISCLOSURE_RE = re.compile(
    r'(?:Fatal\s+error:\s*Uncaught|Uncaught\s+(?:TypeError|Error|Exception)|'
    r'Traceback\s+\(most\s+recent\s+call\s+last\))'
    r'.{0,900}?'
    r'(?:called\s+in\s+/[^\s<]+|Stack\s+trace|/[A-Za-z0-9_./-]+\.(?:php|py|jsp|asp|aspx))',
    re.I | re.S,
)
_ADMIN_ENUM_CONTEXT_RE = re.compile(
    r'ADMIN\s+ENUM|USER(?:NAME)?[_ -]?ENUM|/admin/|res_login\.php',
    re.I,
)
_ADMIN_ENUM_MISSING_RE = re.compile(
    r'not_registered|등록되지\s*않은|未注册|不存在|no\s+such\s+user|user\s+not\s+found',
    re.I,
)
_ADMIN_ENUM_BAD_PASSWORD_RE = re.compile(
    r'bad_password|비밀번호가\s*맞지|密码.{0,12}(?:错误|不正确)|'
    r'incorrect\s+password|wrong\s+password|password\s+incorrect',
    re.I,
)


def _matching_lines(output: str, pattern: re.Pattern, *, limit: int = 18) -> str:
    """Return compact, line-preserving evidence excerpts."""
    lines: list[str] = []
    for line in (output or "").splitlines():
        if pattern.search(line):
            lines.append(line.strip()[:420])
        if len(lines) >= limit:
            break
    return "\n".join(lines)[:2000]


def _public_dependency_artifact_observation(output: str) -> dict | None:
    """Detect public dependency manifests from real HTTP 200 response lines."""
    if not output:
        return None
    paths = sorted({m.group(1) for m in _PUBLIC_DEP_ARTIFACT_PATH_RE.finditer(output)})
    if not paths or not _PUBLIC_DEP_ARTIFACT_CONTENT_RE.search(output):
        return None
    evidence_re = re.compile(
        r'(?:composer\.(?:json|lock)|vendor/composer/installed\.json|'
        r'\bPKG\s+[a-z0-9_.-]+/[a-z0-9_.-]+@?v?\d)',
        re.I,
    )
    evidence = _matching_lines(output, evidence_re) or "\n".join(paths)
    return {
        "vuln_type": FINDING_INFO_DISC,
        "severity": SEVERITY_MEDIUM,
        "confidence": CONF_CONFIRMED,
        "confirmed": True,
        "reason_code": REASON_PUBLIC_ARTIFACT,
        "scope_suffix": "public_dependency_artifact",
        "evidence": evidence,
        "payload": ", ".join(paths),
        "notes": f"ladder:confirmed:{REASON_PUBLIC_ARTIFACT}",
    }


def _stack_trace_disclosure_observation(output: str) -> dict | None:
    """Detect server stack/error disclosure with filesystem/class context."""
    if not output:
        return None
    match = _STACK_TRACE_DISCLOSURE_RE.search(output)
    if not match:
        return None
    evidence = _matching_lines(
        output,
        re.compile(r'Fatal\s+error|Uncaught|Traceback|called\s+in\s+/', re.I),
        limit=10,
    ) or match.group(0)[:2000]
    return {
        "vuln_type": FINDING_INFO_DISC,
        "severity": SEVERITY_LOW,
        "confidence": CONF_CONFIRMED,
        "confirmed": True,
        "reason_code": REASON_STACK_TRACE_DISC,
        "scope_suffix": "stack_trace_disclosure",
        "evidence": evidence,
        "payload": _extract_payload(output),
        "notes": f"ladder:confirmed:{REASON_STACK_TRACE_DISC}",
    }


def _admin_username_enum_observation(output: str) -> dict | None:
    """Detect login differential: unknown user != known user wrong password."""
    if not output or not _ADMIN_ENUM_CONTEXT_RE.search(output):
        return None
    if not (_ADMIN_ENUM_MISSING_RE.search(output) and _ADMIN_ENUM_BAD_PASSWORD_RE.search(output)):
        return None
    evidence = _matching_lines(
        output,
        re.compile(
            r'ADMIN\s+ENUM|ENUM\s+\S+\s*->|try\s+\S+/\S+\s*->|'
            r'not_registered|bad_password|등록되지\s*않은|비밀번호가\s*맞지',
            re.I,
        ),
        limit=16,
    )
    return {
        "vuln_type": FINDING_USER_ENUM,
        "severity": SEVERITY_MEDIUM,
        "confidence": CONF_CONFIRMED,
        "confirmed": True,
        "reason_code": REASON_ADMIN_USER_ENUM,
        "scope_suffix": "admin_username_enumeration",
        "evidence": evidence[:2000],
        "payload": "admin login response differential",
        "notes": f"ladder:confirmed:{REASON_ADMIN_USER_ENUM}",
    }


def _deterministic_runtime_observations(output: str) -> list[dict]:
    """Executor-owned evidence interpretation for non-payload findings.

    These observations come from concrete HTTP response lines, not from model
    conclusions. They must be promoted before generic SQLi/XSS regex handling,
    otherwise useful target facts are lost as pattern-only noise.
    """
    observations: list[dict] = []
    for builder in (
        _public_dependency_artifact_observation,
        _stack_trace_disclosure_observation,
        _admin_username_enum_observation,
    ):
        item = builder(output)
        if item:
            observations.append(item)
    return observations

_AUTH_BYPASS_PATTERNS = [
    re.compile(r'(관리자|admin)\s*(패널|panel|dashboard|로그인|login)\s*(성공|접근|완료|OK)', re.I),
    # v6.2.10: Set-Cookie 단독으론 auth_bypass 아님 — 제거 (세션쿠키 오탐 다수 발생)
    # re.compile(r'Set-Cookie:.*?(admin|session|auth|jwt)', re.I),  ← 삭제됨
    # HTTP 200 + admin — URL 경로가 실제로 admin이어야 함 (응답 헤더 텍스트 아님)
    re.compile(r'(Location|URL):\s*.*?/admin(?:/|$)', re.I),
    re.compile(r'(welcome|dashboard|admin)\s*-\s*(admin|root|manager)', re.I),
]


def _time_based_measurement(output: str) -> tuple[bool, str] | None:
    """Parse explicit request timing measurements, never process runtime elapsed."""
    structured = re.search(
        r'\[TIME_BASED\].{0,240}?baseline\s*[=:]\s*(\d+(?:\.\d+)?)\s*s?'
        r'.{0,120}?payload\s*[=:]\s*(\d+(?:\.\d+)?)\s*s?'
        r'.{0,120}?threshold\s*[=:]\s*(\d+(?:\.\d+)?)\s*s?'
        r'.{0,80}?samples?\s*[=:]\s*(\d+)',
        output,
        re.I | re.S,
    )
    if structured:
        baseline, payload, threshold = map(float, structured.group(1, 2, 3))
        samples = int(structured.group(4))
        verified = samples >= 3 and payload >= threshold and payload >= baseline + 2.0
        return verified, (
            f"baseline={baseline:.2f}s payload={payload:.2f}s "
            f"threshold={threshold:.2f}s samples={samples}"
        )

    baseline_match = re.search(
        r'(?:baseline(?:\s+(?:response\s+)?time)?|基准响应时间|기준\s*응답\s*시간)'
        r'\s*[=:：]\s*(\d+(?:\.\d+)?)\s*s',
        output,
        re.I,
    )
    measurements = re.findall(
        r'\[(?:sleep|sleep_num|sleep_cmmt|benchmark)[^]]*\].{0,80}?'
        r'(?:response\s*time|响应时间|응답\s*시간|elapsed|耗时)\s*[=:：]\s*'
        r'(\d+(?:\.\d+)?)\s*s.{0,80}?'
        r'(?:threshold|阈值|임계값)\s*[=:：]\s*(\d+(?:\.\d+)?)\s*s',
        output,
        re.I,
    )
    if baseline_match and measurements:
        baseline = float(baseline_match.group(1))
        values = [(float(value), float(threshold)) for value, threshold in measurements]
        passing = [value for value, threshold in values if value >= threshold and value >= baseline + 2.0]
        verified = len(passing) >= 2
        detail = (
            f"baseline={baseline:.2f}s passing={len(passing)}/{len(values)} "
            f"max={max(value for value, _ in values):.2f}s"
        )
        return verified, detail
    return None


def _evidence_ladder(output: str, code_snippet: str = "") -> EvidenceVerdict:
    """v6.2.177 Type A — Evidence Ladder 단일 판정 엔진.

    규칙 (근본):
      1) CONFIRMED만 "已确认/Confirmed/Critical Confirmed" 허용
         = 데이터 추출 / RCE 출력 / 브라우저 XSS / 실자격증명
      2) PROBABLE = TRUE≠FALSE / time-based — 취약점 후보로 반드시 유지
      3) POTENTIAL = 패턴만 맞음 — 유지, Confirmed 금지
      4) BLOCKED = WAF/동일크기/가짜해시 — 차단 이벤트 (확정 아님)
      5) 상위 티어가 있으면 하위 FP(blocked)로 절대 덮어쓰지 않음
    """
    if not output or len(output.strip()) < 10:
        return EvidenceVerdict(CONF_NONE, "", detail="empty")

    code = code_snippet or ""
    blob = output + "\n" + code

    # ═══════════════ TIER 5: CONFIRMED (100%급 증거만) ═══════════════
    if re.search(r'\buid=\d+\([^)]+\)\s+gid=\d+', output, re.I):
        return EvidenceVerdict(CONF_CONFIRMED, REASON_RCE_PROOF, FINDING_RCE, "uid/gid")

    if re.search(r'window\.__BINGO_XSS__\s*=\s*1', output):
        return EvidenceVerdict(CONF_CONFIRMED, REASON_XSS_BROWSER, FINDING_XSS, "bingo xss marker")

    structured_observations = _deterministic_runtime_observations(output)
    if structured_observations:
        first = structured_observations[0]
        return EvidenceVerdict(
            CONF_CONFIRMED,
            str(first.get("reason_code") or REASON_STRONG_OVERRIDE),
            str(first.get("vuln_type") or FINDING_INFO_DISC),
            str(first.get("scope_suffix") or "structured observation"),
        )

    # Explicit SQLi negative markers must outrank all SQLi extraction
    # heuristics.  A homepage/CMS fingerprint such as "FOUND: g5_" is not a
    # database extraction, especially when the same run prints
    # SQLI_EXTRACTION_FAILURE / SQLI_NO_VALID_CHANNEL.
    _sqli_context = bool(re.search(
        r'\bSQLI_|sqli|sql\s*injection|sql\s*注入|oracle|boolean|blind|'
        r'TRUE/FALSE|BENCHMARK|SLEEP|GET_LOCK|EXTRACTVALUE|UPDATEXML',
        blob,
        re.I,
    ))
    _sqli_negative = bool(
        _ORACLE_FAILURE_WARNING.search(output)
        or (_sqli_context and _ORACLE_FAILURE_REPEATED.search(output))
    )
    if _sqli_negative:
        return EvidenceVerdict(CONF_BLOCKED, REASON_ORACLE_PRECHECK_FAIL, FINDING_SQLI, "oracle fail")

    if re.search(
        r'XPATH\s+syntax\s+error[^\n]{0,80}~[A-Za-z0-9_.\-]{2,80}~'
        r'|~[A-Za-z0-9_.\-]{2,80}~[^\n]{0,40}XPATH',
        output, re.I
    ):
        if not re.search(
            r'~(?:오전|오후|월요일|화요일|수요일|목요일|금요일|토요일|일요일)',
            output, re.I
        ):
            return EvidenceVerdict(CONF_CONFIRMED, REASON_XPATH_EXTRACT, FINDING_SQLI, "xpath extract")

    if re.search(
        r'->\s*DATA:\s*[~\'"]?([A-Za-z][A-Za-z0-9_.\-]{1,63})[~\'"]?',
        output, re.I
    ):
        if not re.search(
            r'->\s*DATA:\s*.*(?:오전|오후|월요일|화요일|수요일|목요일|금요일|토요일|일요일'
            r'|<html|<!DOCTYPE|해킹방지)',
            output, re.I
        ):
            return EvidenceVerdict(CONF_CONFIRMED, REASON_XPATH_EXTRACT, FINDING_SQLI, "data extract")

    _db_table_extract = bool(re.search(
        r'(?:Database\s+confirmed|DB\s+name|Current\s+database|database\(\)|'
        r'数据库名|数据库名称)\s*[:=：]\s*[\'"]?(?!a{4,}|0{4,})[a-zA-Z][\w]{1,40}'
        r'|(?:Found\s+tables?|TABLES_EXTRACTED|SHOW\s+TABLES)\s*[:=：]\s*\[[^\]]+\]'
        r'|(?:table(?:_name)?|TABLE_EXISTS)\s+[\w.]+\s*:\s*EXISTS'
        r'|\[\+\]\s*Table\s+exists(?::|\()\s*[a-zA-Z0-9_]+',
        output, re.I
    ))
    _db_table_code_context = bool(re.search(
        r'information_schema|SHOW\s+TABLES|table_schema|database\(\)|@@version|'
        r'sqli_autoexploit|sqlmap|ghauri|UNION\s+SELECT|EXTRACTVALUE|UPDATEXML',
        blob, re.I
    ))
    if _db_table_extract and _db_table_code_context:
        return EvidenceVerdict(CONF_CONFIRMED, REASON_DB_TABLE_EXTRACT, FINDING_SQLI, "db/table")

    if re.search(
        r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,}|A{6,}|0123456789abcdef)\S{6,}',
        output, re.I
    ) and not _FAKE_CRED_VALUE.search(output):
        return EvidenceVerdict(CONF_CONFIRMED, REASON_REAL_CREDENTIAL, FINDING_CREDENTIAL, "real cred")

    # Explicit negative verification outranks heuristic probable signals.
    if _ORACLE_FAILURE_REPEATED.search(output) or _ORACLE_FAILURE_WARNING.search(output):
        return EvidenceVerdict(CONF_BLOCKED, REASON_ORACLE_PRECHECK_FAIL, FINDING_SQLI, "oracle fail")

    timing = _time_based_measurement(output)
    if timing:
        if timing[0]:
            return EvidenceVerdict(CONF_PROBABLE, REASON_TIME_BASED, FINDING_SQLI, timing[1])
        return EvidenceVerdict(
            CONF_BLOCKED,
            REASON_TIME_PRECHECK_FAIL,
            FINDING_SQLI,
            timing[1],
        )

    if _INFO_LABEL_ONLY_RE.search(output):
        return EvidenceVerdict(
            CONF_BLOCKED,
            REASON_NOT_VULNERABLE,
            FINDING_INFO_DISC,
            "labels/template only; no records",
        )

    # ═══════════════ TIER 4: PROBABLE (실 oracle, Confirmed 아님) ═══════════════
    _m_t = re.search(
        r'(?:TRUE|1\s*=\s*1|2\s*>\s*1).{0,60}?(\d{2,6})\s*B',
        output, re.I | re.S
    )
    _m_f = re.search(
        r'(?:FALSE|1\s*=\s*0|1\s*=\s*2|1\s*>\s*2).{0,60}?(\d{2,6})\s*B',
        output, re.I | re.S
    )
    if _m_t and _m_f:
        # WAF/protection pages can differ in size and status.  They prove only
        # that the controls were filtered, never that the backend evaluated SQL.
        if _CONTROL_BLOCK_RE.search(output):
            return EvidenceVerdict(
                CONF_BLOCKED,
                REASON_WAF_BLOCK_PAGE,
                FINDING_SQLI,
                "control response blocked/protected",
            )
        try:
            _tb, _fb = int(_m_t.group(1)), int(_m_f.group(1))
            if abs(_tb - _fb) >= 200:
                return EvidenceVerdict(
                    CONF_PROBABLE, REASON_BOOLEAN_DIFF, FINDING_SQLI,
                    f"true={_tb}B false={_fb}B",
                )
        except ValueError:
            pass

    # ═══════════════ TIER 1: BLOCKED (확정 금지, 이벤트만) ═══════════════
    # CONFIRMED/PROBABLE가 없을 때만 적용 — 실탐을 FP로 덮지 않음
    _NOT_VULN_RE = re.compile(
        r'NOT\s+vulnerable\s*[❌✗×⛔]'
        r'|→\s*NOT\s+vulnerable'
        r'|DB\s+errors\s+found:\s*None'
        r'|boolean\s+oracle.*?fail'
        r'|SQLI_EXTRACTION_FAILURE'
        r'|SQLI_NO_VALID_CHANNEL'
        r'|Oracle预检失败'
        r'|oracle\s*pre-?check\s*FAIL'
        r'|Boolean\s+字符提取已禁用'
        r'|Boolean\s+character\s+extraction\s+disabled',
        re.I
    )
    if _NOT_VULN_RE.search(output):
        return EvidenceVerdict(CONF_BLOCKED, REASON_NOT_VULNERABLE, "", "tool not-vuln")

    if _m_t and _m_f:
        try:
            if int(_m_t.group(1)) == int(_m_f.group(1)):
                return EvidenceVerdict(
                    CONF_BLOCKED, REASON_BLOCKED_WAF_SAME_SIZE, FINDING_SQLI, "same size"
                )
        except ValueError:
            pass
    _same = re.search(
        r'(?:TRUE|1=1|2>1).{0,40}?(\d{2,4})B'
        r'.{0,120}?'
        r'(?:FALSE|1=0|1=2|1>2).{0,40}?\1B',
        output, re.I | re.S
    )
    if _same:
        return EvidenceVerdict(CONF_BLOCKED, REASON_BLOCKED_WAF_SAME_SIZE, FINDING_SQLI, "same size")

    if len(output) <= 2000 and (_WAF_BLOCK_KO.search(output) or _WAF_BLOCK_EN.search(output)):
        return EvidenceVerdict(CONF_BLOCKED, REASON_WAF_BLOCK_PAGE, "", "waf page")

    _CF_BLOCK_RE = re.compile(
        r'cloudflare.*?(error|blocked|denied)'
        r'|ray\s+id\s*:\s*[0-9a-f]+'
        r'|__cf_chl|cf-ray:'
        r'|error\s+1\d{3}\s+access\s+denied'
        r'|sorry,\s+you\s+have\s+been\s+blocked',
        re.I
    )
    if _CF_BLOCK_RE.search(output):
        return EvidenceVerdict(CONF_BLOCKED, REASON_CF_BLOCK, "", "cloudflare")

    if re.search(
        r'(?:해킹방지|요청이\s*차단|security\s+system|blocked\s+by\s+waf).{0,80}?\b(\d{2,4})B\b'
        r'|\b49[0-9]B\b.{0,40}?(?:해킹방지|WAF|차단)',
        output, re.I | re.S
    ) and (_SQLI_CONTEXT_KEYWORDS.search(output) or _SQLI_CONTEXT_KEYWORDS.search(code)):
        return EvidenceVerdict(CONF_BLOCKED, REASON_WAF_BLOCK_PAGE, FINDING_SQLI, "waf 490B")

    if re.search(r'(?:updatexml|extractvalue)\s*\(', blob, re.I):
        _has_xpath = bool(re.search(
            r'XPATH\s+syntax\s+error|xpath\s+error|~[a-zA-Z0-9_.\-]{2,80}~',
            output, re.I
        ))
        _page = bool(re.search(
            r'->\s*DATA:\s*.*(?:오전|오후|월요일|화요일|수요일|목요일|금요일|토요일|일요일'
            r'|<html|<!DOCTYPE|해킹방지|요청이\s*차단)',
            output, re.I
        ))
        _empty = bool(re.search(r'->\s*DATA:\s*(?:None|null|\(empty)?\s*$', output, re.I | re.M))
        if (_page or _empty) and not _has_xpath:
            return EvidenceVerdict(CONF_BLOCKED, REASON_PAGE_CONTAMINATION, FINDING_SQLI, "page contam")

    if _WAF_SECURITY_REDIRECT.search(output.lower()):
        return EvidenceVerdict(CONF_BLOCKED, REASON_WAF_REDIRECT, "", "waf redirect")

    if _FAKE_CRED_VALUE.search(output):
        return EvidenceVerdict(CONF_BLOCKED, REASON_PLACEHOLDER_HASH, FINDING_CREDENTIAL, "fake hash")

    _login_only = bool(_LOGIN_FORM_ONLY.search(output)) and not re.search(
        r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,})\S{4,}', output, re.I
    )
    if _login_only and any(p.search(output) for p in _CRED_PATTERNS):
        return EvidenceVerdict(CONF_BLOCKED, REASON_LOGIN_FORM_ONLY, FINDING_CREDENTIAL, "login form")

    # ═══════════════ TIER 3: POTENTIAL (패턴만, Confirmed 금지) ═══════════════
    # 실제 타입은 _detect_vuln_type_raw 가 결정 — 여기서는 "후보 있음"만
    return EvidenceVerdict(CONF_POTENTIAL, REASON_PATTERN_MATCH, "", "pattern scan")


def _strong_vuln_proof(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """하위 호환 래퍼 → Evidence Ladder."""
    v = _evidence_ladder(output, code_snippet)
    if v.tier == CONF_CONFIRMED:
        return ("confirmed", v.reason_code)
    if v.tier == CONF_PROBABLE:
        return ("potential", v.reason_code)  # legacy: probable을 potential로 노출
    return None


def _assess_evidence(output: str, code_snippet: str = "") -> tuple[str, str]:
    """하위 호환 래퍼 → Evidence Ladder.

    Returns status: 'blocked' | 'ok' | 'strong'
    """
    v = _evidence_ladder(output, code_snippet)
    if v.tier == CONF_CONFIRMED:
        return ("strong", v.reason_code)
    if v.tier == CONF_PROBABLE:
        return ("strong", f"potential:{v.reason_code}")
    if v.tier == CONF_BLOCKED:
        return ("blocked", v.reason_code)
    return ("ok", v.reason_code or "")


def _detect_vuln_type_raw(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """패턴만으로 유형/심각도 탐지 (ladder 무시). blocked 억제는 호출측 책임."""
    _is_login_form_only = bool(_LOGIN_FORM_ONLY.search(output)) and not re.search(
        r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,})\S{4,}', output, re.I
    )
    _is_js_chunk_output = bool(_MINIFIED_JS_CONTEXT.search(output))

    _skip_lfi = False
    if _PHP_FILTER_IN_OUTPUT.search(output) or _PHP_FILTER_IN_OUTPUT.search(code_snippet):
        _has_b64_content = bool(_BASE64_FILE_BLOCK.search(output))
        _has_html_redirect = bool(_LFI_REDIRECT_HTML.search(output))
        if _has_html_redirect and not _has_b64_content:
            _skip_lfi = True

    _sqli_context = (
        _SQLI_CONTEXT_KEYWORDS.search(code_snippet)
        or _SQLI_CONTEXT_KEYWORDS.search(output)
    )
    _lfi_test_context = bool(
        _ACTIVE_HTTP_TEST.search(code_snippet)
        and _ACTIVE_TEST_PAYLOADS[FINDING_LFI].search(code_snippet)
    )

    if _sqli_context:
        checks = [
            (FINDING_RCE,         SEVERITY_CRITICAL, _RCE_PATTERNS),
            (FINDING_LFI,         SEVERITY_CRITICAL, _LFI_PATTERNS),
            (FINDING_AUTH_BYPASS, SEVERITY_CRITICAL, _AUTH_BYPASS_PATTERNS),
            (FINDING_SQLI,        SEVERITY_HIGH,     _SQLI_PATTERNS),
            (FINDING_CREDENTIAL,  SEVERITY_CRITICAL, _CRED_PATTERNS),
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

    _skip_xss = False
    if _SERVER_ALERT_PATTERN.search(output) and not _XSS_PAYLOAD_IN_CODE.search(code_snippet):
        _skip_xss = True
    if _xss_negative_only(output):
        _skip_xss = True
    if not _XSS_PAYLOAD_IN_CODE.search(code_snippet) and not _XSS_PAYLOAD_IN_CODE.search(output):
        _skip_xss = True

    for vtype, sev, patterns in checks:
        if vtype == FINDING_LFI and _skip_lfi:
            continue
        if vtype == FINDING_CREDENTIAL and _is_js_chunk_output:
            continue
        if vtype == FINDING_CREDENTIAL and _is_login_form_only:
            continue
        if vtype == FINDING_XSS and _skip_xss:
            continue
        for pat in patterns:
            # A bare "password=..." is credential-shaped unless an LFI payload
            # actively requested a configuration file.
            if vtype == FINDING_LFI and pat is _LFI_PATTERNS[-1] and not _lfi_test_context:
                continue
            if pat.search(output):
                return (vtype, sev)
    return None


def _detect_vuln_type(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """출력 텍스트에서 취약점 유형과 심각도 탐지. 없으면 None.

    v6.2.177: Evidence Ladder blocked만 억제. confirmed/probable/potential은 탐지 유지.
    """
    v = _evidence_ladder(output, code_snippet)
    if v.tier == CONF_BLOCKED:
        return None
    if v.vuln_hint and v.tier in (CONF_CONFIRMED, CONF_PROBABLE):
        if v.vuln_hint in (FINDING_INFO_DISC, FINDING_USER_ENUM):
            sev = SEVERITY_MEDIUM
        else:
            sev = SEVERITY_CRITICAL if v.tier == CONF_CONFIRMED else SEVERITY_HIGH
        if v.vuln_hint == FINDING_SQLI and v.tier == CONF_PROBABLE:
            sev = SEVERITY_HIGH
        return (v.vuln_hint, sev)
    return _detect_vuln_type_raw(output, code_snippet)


def _extract_payload(output: str) -> str:
    """출력에서 페이로드/쿼리 라인 추출 (최대 300자)"""
    for line in output.splitlines():
        stripped = line.strip()
        if re.match(r'^(payload|query|url|request|inject)\s*[=:]', stripped, re.I):
            return stripped[:300]
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
        self._quarantined: list[Finding] = []
        # IDs are session-stable.  They must not depend on the current list
        # length because invalidation/rejection removes entries from that list.
        self._finding_sequence = 0
        self._quarantine_sequence = 0
        self._finding_hashes: set[str] = set()   # 중복 방지
        self._quarantine_hashes: set[str] = set()
        self._blocked_reasons: set[str] = set()  # v6.2.175: blocked reason 중복 방지
        self.last_autocorrection: str = ""
        self.last_quarantine_reason: str = ""
        self.autocorrections: list[str] = []
        self.autocorrection_counts: dict[str, int] = {}
        self.quarantine_counts: dict[str, int] = {}
        self.quarantine_revalidation_runs: int = 0

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

    def _next_finding_id(self) -> str:
        self._finding_sequence += 1
        return f"BINGO-{self._finding_sequence:04d}"

    def _next_quarantine_id(self) -> str:
        self._quarantine_sequence += 1
        return f"BINGO-Q{self._quarantine_sequence:04d}"

    # ── 공개 API ──────────────────────────────────────────────────────────────

    def process(
        self,
        output: str,
        code_snippet: str = "",
        extra_notes: str = "",
        execution_context: dict | None = None,
    ) -> Optional[Finding]:
        """Evidence Ladder 단일 경로로 finding 생성.

        v6.2.177 근본 규칙:
          CONFIRMED → confirmed=True, Critical 허용, 보고서 已确认 허용
          PROBABLE  → confirmed=False, HIGH, 취약점 유지 (지우지 않음)
          POTENTIAL → confirmed=False, 패턴 매칭 시만 기록
          BLOCKED   → LOW 차단 이벤트 1회 (확정 아님)
          NONE      → 무시
          상위 티어가 나오면 기존 하위(blocked) finding 자동 승격
        """
        self.last_autocorrection = ""
        self.last_quarantine_reason = ""
        if not output or len(output.strip()) < 10:
            return None

        structured = self._add_deterministic_runtime_observations(
            output,
            code_snippet=code_snippet,
            extra_notes=extra_notes,
        )
        if structured:
            return structured[0]

        verdict = _evidence_ladder(output, code_snippet=code_snippet)
        if verdict.tier == CONF_NONE:
            return None

        # Deterministic application-generated alert responses are known false
        # positives even when raw type detection intentionally skips XSS.
        active_code = _execution_code(code_snippet, execution_context)
        if (
            verdict.tier == CONF_POTENTIAL
            and _SERVER_ALERT_PATTERN.search(output)
            and not (
                _ACTIVE_HTTP_TEST.search(active_code)
                and _XSS_ACTIVE_PAYLOAD.search(active_code)
            )
        ):
            self._record_autocorrection("xss_server_alert_false_positive")
            return None

        import hashlib
        evidence = output[:2000]
        payload = (code_snippet or _extract_payload(output))[:500]
        hinted_type = verdict.vuln_hint or FINDING_SQLI
        scope_key = _finding_scope(
            hinted_type, output, code_snippet, execution_context
        )

        # ── BLOCKED: 차단 이벤트만 ──────────────────────────────────────────
        if verdict.tier == CONF_BLOCKED:
            if verdict.reason_code in (
                REASON_BLOCKED_WAF_SAME_SIZE,
                REASON_ORACLE_PRECHECK_FAIL,
                REASON_TIME_PRECHECK_FAIL,
                REASON_NOT_VULNERABLE,
            ):
                self._invalidate_probable_findings(
                    FINDING_SQLI,
                    scope_key,
                    f"invalidated_by_{verdict.reason_code}",
                )
            if verdict.reason_code in self._blocked_reasons:
                return None
            _sqli_ctx = bool(
                verdict.vuln_hint == FINDING_SQLI
                or _SQLI_CONTEXT_KEYWORDS.search(code_snippet)
                or _SQLI_CONTEXT_KEYWORDS.search(output)
                or verdict.reason_code in (
                    REASON_BLOCKED_WAF_SAME_SIZE,
                    REASON_ORACLE_PRECHECK_FAIL,
                    REASON_PAGE_CONTAMINATION,
                    REASON_WAF_BLOCK_PAGE,
                )
            )
            _cred_ctx = verdict.reason_code in (REASON_LOGIN_FORM_ONLY, REASON_PLACEHOLDER_HASH)
            if not _sqli_ctx and not _cred_ctx and verdict.reason_code not in (
                REASON_NOT_VULNERABLE, REASON_CF_BLOCK, REASON_WAF_REDIRECT
            ):
                return None
            self._blocked_reasons.add(verdict.reason_code)
            vtype = FINDING_CREDENTIAL if _cred_ctx else (
                FINDING_SQLI if _sqli_ctx else FINDING_INFO_DISC
            )
            _hash = hashlib.md5(
                (f"blocked:{verdict.reason_code}:" + evidence[:120]).encode("utf-8", errors="ignore")
            ).hexdigest()[:12]
            if _hash in self._finding_hashes:
                return None
            self._finding_hashes.add(_hash)
            finding = Finding(
                id=self._next_finding_id(),
                vuln_type=vtype,
                severity=SEVERITY_LOW,
                target=self.target,
                payload=payload,
                evidence=evidence,
                notes=extra_notes or f"ladder:blocked:{verdict.reason_code}",
                confidence=CONF_BLOCKED,
                reason_code=verdict.reason_code,
                scope_key=scope_key,
            )
            self._findings.append(finding)
            return finding

        # ── CONFIRMED / PROBABLE / POTENTIAL ───────────────────────────────
        detected = _detect_vuln_type_raw(output, code_snippet)
        if verdict.vuln_hint:
            vtype = verdict.vuln_hint
            if detected and detected[0] == verdict.vuln_hint:
                severity = detected[1]
            elif vtype == FINDING_SQLI:
                severity = SEVERITY_CRITICAL if verdict.tier == CONF_CONFIRMED else SEVERITY_HIGH
            elif vtype in (FINDING_RCE, FINDING_CREDENTIAL, FINDING_LFI):
                severity = SEVERITY_CRITICAL
            elif vtype in (FINDING_INFO_DISC, FINDING_USER_ENUM):
                severity = SEVERITY_MEDIUM
            else:
                severity = SEVERITY_HIGH
        elif detected:
            vtype, severity = detected
        else:
            # potential인데 패턴도 없으면 finding 안 만듦 (노이즈 방지)
            if verdict.tier == CONF_POTENTIAL:
                return None
            vtype, severity = FINDING_SQLI, SEVERITY_HIGH

        scope_key = _finding_scope(vtype, output, code_snippet, execution_context)

        # Pattern-only candidates use a fail-open quarantine. Only deterministic
        # false positives are rejected; unknown execution styles remain reviewable.
        if verdict.tier == CONF_POTENTIAL:
            action, reason = _potential_disposition(
                vtype, output, code_snippet, execution_context
            )
            if action == "reject":
                self._record_autocorrection(reason)
                return None
            if action == "quarantine":
                self._quarantine_candidate(
                    vtype=vtype,
                    output=output,
                    code_snippet=code_snippet,
                    reason=reason,
                    extra_notes=extra_notes,
                    execution_context=execution_context,
                    scope_key=scope_key,
                )
                return None

        # ladder → confidence / confirmed / severity 매핑
        if verdict.tier == CONF_CONFIRMED:
            confidence, confirmed = CONF_CONFIRMED, True
            if vtype == FINDING_SQLI:
                severity = SEVERITY_CRITICAL
        elif verdict.tier == CONF_PROBABLE:
            confidence, confirmed = CONF_PROBABLE, False
            # Confirmed Critical 과장 금지 — HIGH + probable
            if severity == SEVERITY_CRITICAL and vtype == FINDING_SQLI:
                severity = SEVERITY_HIGH
        else:  # POTENTIAL
            confidence, confirmed = CONF_POTENTIAL, False
            if severity == SEVERITY_CRITICAL:
                # Pattern-only evidence can never carry CRITICAL severity.
                severity = SEVERITY_HIGH

        scoped_existing = next(
            (
                finding
                for finding in self._findings
                if finding.vuln_type == vtype
                and finding.scope_key == scope_key
                and finding.confidence != CONF_BLOCKED
            ),
            None,
        )
        if scoped_existing:
            self._promote_to_tier(
                vtype, confidence, confirmed, verdict.reason_code, evidence, scope_key
            )
            return None

        _hash = hashlib.md5(
            (f"{verdict.tier}:{vtype}:" + evidence[:200]).encode("utf-8", errors="ignore")
        ).hexdigest()[:12]
        if _hash in self._finding_hashes:
            self._promote_to_tier(
                vtype, confidence, confirmed, verdict.reason_code, evidence, scope_key
            )
            return None
        self._finding_hashes.add(_hash)

        finding = Finding(
            id=self._next_finding_id(),
            vuln_type=vtype,
            severity=severity,
            target=self.target,
            payload=payload,
            evidence=evidence,
            notes=extra_notes or f"ladder:{verdict.tier}:{verdict.reason_code}",
            confirmed=confirmed,
            confidence=confidence,
            reason_code=verdict.reason_code or REASON_PATTERN_MATCH,
            scope_key=scope_key,
        )
        self._findings.append(finding)
        self._promote_to_tier(
            vtype, confidence, confirmed, verdict.reason_code, evidence, scope_key
        )
        return finding

    def _add_deterministic_runtime_observations(
        self,
        output: str,
        *,
        code_snippet: str = "",
        extra_notes: str = "",
    ) -> list[Finding]:
        """Add concrete non-payload observations before regex vuln handling."""
        observations = _deterministic_runtime_observations(output)
        if not observations:
            return []
        import hashlib

        added: list[Finding] = []
        target_scope = self.target or "unknown"
        for obs in observations:
            vtype = str(obs.get("vuln_type") or FINDING_INFO_DISC)
            reason = str(obs.get("reason_code") or REASON_STRONG_OVERRIDE)
            scope_suffix = str(obs.get("scope_suffix") or reason)
            scope_key = f"{vtype}|{target_scope}|{scope_suffix}"
            existing = next(
                (
                    finding
                    for finding in self._findings
                    if finding.vuln_type == vtype
                    and finding.scope_key == scope_key
                    and finding.reason_code == reason
                ),
                None,
            )
            if existing:
                continue

            evidence = str(obs.get("evidence") or output[:2000])[:2000]
            payload = str(obs.get("payload") or code_snippet or _extract_payload(output))[:500]
            finding_hash = hashlib.md5(
                (f"structured:{reason}:{scope_key}:" + evidence[:180]).encode(
                    "utf-8", errors="ignore"
                )
            ).hexdigest()[:12]
            if finding_hash in self._finding_hashes:
                continue
            self._finding_hashes.add(finding_hash)

            finding = Finding(
                id=self._next_finding_id(),
                vuln_type=vtype,
                severity=str(obs.get("severity") or SEVERITY_MEDIUM),
                target=self.target,
                payload=payload,
                evidence=evidence,
                notes=extra_notes or str(obs.get("notes") or f"ladder:confirmed:{reason}"),
                confirmed=bool(obs.get("confirmed", True)),
                confidence=str(obs.get("confidence") or CONF_CONFIRMED),
                reason_code=reason,
                scope_key=scope_key,
            )
            self._findings.append(finding)
            added.append(finding)
        return added

    def _quarantine_candidate(
        self,
        vtype: str,
        output: str,
        code_snippet: str,
        reason: str,
        extra_notes: str,
        execution_context: dict | None,
        scope_key: str,
    ) -> None:
        import hashlib
        evidence = output[:2000]
        qhash = hashlib.md5(
            (f"quarantine:{vtype}:" + evidence[:200]).encode("utf-8", errors="ignore")
        ).hexdigest()[:12]
        self.last_quarantine_reason = reason
        self.quarantine_counts[reason] = self.quarantine_counts.get(reason, 0) + 1
        if qhash in self._quarantine_hashes:
            return
        self._quarantine_hashes.add(qhash)
        context_source = "runtime" if execution_context else "legacy"
        finding = Finding(
            id=self._next_quarantine_id(),
            vuln_type=vtype,
            severity=SEVERITY_LOW,
            target=self.target,
            payload=(code_snippet or _extract_payload(output))[:500],
            evidence=evidence,
            notes=extra_notes or f"quarantine:{reason}:source={context_source}",
            confirmed=False,
            confidence=CONF_QUARANTINED,
            reason_code=reason,
            scope_key=scope_key,
        )
        self._quarantined.append(finding)

    def revalidate_quarantined(self) -> int:
        """Run the deterministic quarantine audit before report generation."""
        self.quarantine_revalidation_runs += 1
        # Confirmed/probable findings of the same type supersede quarantined noise,
        # while unresolved items remain isolated for manual or future verification.
        proven_types = {
            f.vuln_type
            for f in self._findings
            if f.confidence == CONF_CONFIRMED
        }
        before = len(self._quarantined)
        if proven_types:
            self._quarantined = [
                q for q in self._quarantined if q.vuln_type not in proven_types
            ]
            self._quarantine_hashes = {
                __import__("hashlib").md5(
                    (f"quarantine:{q.vuln_type}:" + (q.evidence or "")[:200]).encode(
                        "utf-8", errors="ignore"
                    )
                ).hexdigest()[:12]
                for q in self._quarantined
            }
        return before - len(self._quarantined)

    def _record_autocorrection(self, reason: str) -> None:
        self.last_autocorrection = reason
        self.autocorrection_counts[reason] = self.autocorrection_counts.get(reason, 0) + 1
        if reason not in self.autocorrections:
            self.autocorrections.append(reason)

    def _invalidate_probable_findings(
        self,
        vtype: str,
        scope_key: str,
        reason: str,
    ) -> int:
        """Move contradicted probable findings into quarantine."""
        invalidated = [
            finding
            for finding in self._findings
            if finding.vuln_type == vtype
            and finding.confidence == CONF_PROBABLE
            and _scopes_compatible(finding.scope_key, scope_key)
        ]
        for finding in invalidated:
            self._findings.remove(finding)
            # Preserve the original ID when moving a finding to quarantine so
            # report references and audit history remain stable.
            finding.confidence = CONF_QUARANTINED
            finding.confirmed = False
            finding.severity = SEVERITY_LOW
            finding.reason_code = reason
            finding.notes = (finding.notes or "") + f" | {reason}"
            self._quarantined.append(finding)
            self.last_quarantine_reason = reason
            self.quarantine_counts[reason] = self.quarantine_counts.get(reason, 0) + 1
        if invalidated:
            self._finding_hashes.clear()
            self._record_autocorrection(reason)
        return len(invalidated)

    def reject_finding(self, finding: Finding, reason: str) -> bool:
        """Remove a candidate after a deterministic negative verification."""
        if finding not in self._findings or finding.confirmed:
            return False
        self._findings.remove(finding)
        import hashlib
        finding_hash = hashlib.md5(
            (f"{finding.confidence}:{finding.vuln_type}:" + (finding.evidence or "")[:200]).encode(
                "utf-8", errors="ignore"
            )
        ).hexdigest()[:12]
        self._finding_hashes.discard(finding_hash)
        self._record_autocorrection(reason)
        return True

    def _promote_to_tier(
        self,
        vtype: str,
        confidence: str,
        confirmed: bool,
        reason_code: str,
        evidence: str,
        scope_key: str = "",
    ) -> None:
        """하위 티어(blocked/potential) finding을 상위 ladder로 승격."""
        new_rank = _LADDER_RANK.get(confidence, 0)
        for f in self._findings:
            if f.vuln_type != vtype:
                continue
            if scope_key and f.scope_key and not _scopes_compatible(f.scope_key, scope_key):
                continue
            old_rank = _LADDER_RANK.get(f.confidence, 0)
            if new_rank <= old_rank:
                continue
            f.confidence = confidence
            f.confirmed = confirmed
            f.reason_code = reason_code or f.reason_code
            f.notes = (f.notes or "") + f" | promoted:{reason_code}"
            if confirmed:
                f.severity = SEVERITY_CRITICAL if vtype in (
                    FINDING_SQLI, FINDING_RCE, FINDING_CREDENTIAL, FINDING_LFI
                ) else f.severity
            elif confidence == CONF_PROBABLE and f.severity == SEVERITY_LOW:
                f.severity = SEVERITY_HIGH
            if evidence and len(evidence) > len(f.evidence or ""):
                f.evidence = evidence[:2000]
            break

    def _promote_blocked(
        self,
        vtype: str,
        confidence: str,
        confirmed: bool,
        reason_code: str,
        evidence: str,
    ) -> None:
        """하위 호환 → _promote_to_tier."""
        self._promote_to_tier(vtype, confidence, confirmed, reason_code, evidence)

    def mark_confirmed(self, finding: Finding, screenshot_path: str = "") -> None:
        """Playwright 등 2차 검증 = Ladder CONFIRMED 승격."""
        finding.confirmed = True
        finding.confidence = CONF_CONFIRMED
        finding.reason_code = REASON_XSS_BROWSER
        if screenshot_path:
            finding.screenshot_path = screenshot_path

    def try_promote_from_output(self, output: str, code_snippet: str = "") -> Optional[Finding]:
        """후속 추출 결과로 ladder 재평가."""
        return self.process(output, code_snippet=code_snippet)

    def save(self) -> Path | None:
        """JSON 파일로 저장 후 경로 반환. 발견이 없으면 None."""
        if not self._findings and not self._quarantined:
            return None
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = (self.target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        path = self._dir / f"findings_{safe}_{ts}.json"
        _stats = self.stats()
        data = {
            "bingo_version": _get_version(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "autocorrection_count": sum(self.autocorrection_counts.values()),
            "autocorrections": list(self.autocorrections),
            "autocorrection_counts": dict(self.autocorrection_counts),
            "quarantine_count": len(self._quarantined),
            "quarantine_reason_counts": dict(self.quarantine_counts),
            "quarantine_revalidation_runs": self.quarantine_revalidation_runs,
            **_stats,
            "findings": [f.to_dict() for f in self._findings],
            "quarantined": [f.to_dict() for f in self._quarantined],
        }
        try:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            path = Path.cwd() / f"findings_{safe}_{ts}.json"
            try:
                path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                return None
        return path

    def stats(self) -> dict:
        """v6.2.177: Evidence Ladder 집계 — confirmed만 Critical Confirmed."""
        total = len(self._findings)
        confirmed = sum(1 for f in self._findings if f.confirmed or f.confidence == CONF_CONFIRMED)
        probable = sum(1 for f in self._findings if f.confidence == CONF_PROBABLE)
        blocked = sum(1 for f in self._findings if f.confidence == CONF_BLOCKED)
        quarantined = len(self._quarantined)
        potential = sum(
            1 for f in self._findings
            if f.confidence in (CONF_POTENTIAL, CONF_INCONCLUSIVE)
        )
        potential_critical = sum(
            1 for f in self._findings
            if f.severity == SEVERITY_CRITICAL
            and not f.confirmed
            and f.confidence not in (CONF_BLOCKED, CONF_CONFIRMED)
        )
        potential_high = sum(
            1 for f in self._findings
            if f.severity == SEVERITY_HIGH
            and not f.confirmed
            and f.confidence not in (CONF_BLOCKED, CONF_CONFIRMED)
        )
        critical_confirmed = sum(
            1 for f in self._findings
            if f.severity == SEVERITY_CRITICAL and (f.confirmed or f.confidence == CONF_CONFIRMED)
        )
        high_confirmed = sum(
            1 for f in self._findings
            if f.severity == SEVERITY_HIGH and (f.confirmed or f.confidence == CONF_CONFIRMED)
        )
        return {
            "total": total,
            "critical": critical_confirmed,
            "high": high_confirmed,
            "probable": probable,
            "potential": potential,
            "potential_critical": potential_critical,
            "potential_high": potential_high,
            "blocked": blocked,
            "quarantined": quarantined,
            "confirmed": confirmed,
            "reason_codes": sorted({f.reason_code for f in self._findings if f.reason_code}),
        }

    def summary(self) -> str:
        """Evidence Ladder 요약 — Confirmed만 CRITICAL, 후보는 PROBABLE/POTENTIAL."""
        if not self._findings:
            return ""
        s = self.stats()
        parts = []
        if s["confirmed"]:
            parts.append(f"confirmed:{s['confirmed']}")
        if s["critical"]:
            parts.append(f"CRITICAL:{s['critical']}")
        if s.get("probable"):
            parts.append(f"PROBABLE:{s['probable']}")
        if s["potential_critical"]:
            parts.append(f"POTENTIAL_CRITICAL:{s['potential_critical']}")
        if s["high"]:
            parts.append(f"HIGH:{s['high']}")
        if s["potential_high"]:
            parts.append(f"POTENTIAL_HIGH:{s['potential_high']}")
        if s["blocked"]:
            parts.append(f"blocked:{s['blocked']}")
        if s["quarantined"]:
            parts.append(f"quarantined:{s['quarantined']}")
        return f"[FINDINGS] total={s['total']} " + " ".join(parts)

    def ground_truth_block(self) -> str:
        """보고서/progress/next_steps용 Evidence Ladder ground truth."""
        s = self.stats()
        lines = [
            "EVIDENCE LADDER (only confirmed may claim 已确认/Confirmed):",
            f"total={s['total']} confirmed={s['confirmed']} probable={s.get('probable', 0)} "
            f"potential={s.get('potential', 0)} blocked={s['blocked']} "
            f"quarantined={s.get('quarantined', 0)} critical_confirmed={s['critical']}",
            f"reason_codes={s['reason_codes'] or []}",
            f"autocorrections={self.autocorrection_counts or {}}",
        ]
        for f in self._findings:
            lines.append(
                f"- id={f.id} type={f.vuln_type} sev={f.severity} "
                f"tier={f.confidence} confirmed={f.confirmed} "
                f"reason={f.reason_code or '-'} notes={(f.notes or '')[:60]}"
            )
        for q in self._quarantined:
            lines.append(
                f"- id={q.id} type={q.vuln_type} sev=LOW "
                f"tier=quarantined confirmed=False reason={q.reason_code}"
            )
        return "\n".join(lines)

    def verification_backlog(self, limit: int = 5) -> list[dict]:
        """Return unresolved candidates with a concrete independent verifier."""
        if limit <= 0:
            return []
        profiles = {
            FINDING_SQLI: (
                "sqli_autoexploit",
                "Require a DB-specific error, stable TRUE/FALSE controls, or at least "
                "3 payload timing samples above the baseline threshold.",
            ),
            FINDING_XSS: (
                "xss_autotest",
                "Require browser JavaScript execution; reflection alone is not proof.",
            ),
            FINDING_SSRF: (
                "ssrf_autotest",
                "Require a response absent from baseline and a non-reflected internal-service signature.",
            ),
            FINDING_LFI: (
                "lfi_autotest",
                "Require exact target file content such as a passwd record, not a path string.",
            ),
            FINDING_RCE: (
                "cmdi_autotest",
                "Require a unique command canary or exact OS command output from a control comparison.",
            ),
            FINDING_AUTH_BYPASS: (
                "idor_autotest",
                "Compare authenticated and unauthenticated sessions against the same object and endpoint.",
            ),
            FINDING_CREDENTIAL: (
                "manual_control",
                "Require a real extracted secret bound to an account or a successful authentication check.",
            ),
            FINDING_INFO_DISC: (
                "manual_control",
                "Require sensitive response data absent from the normal baseline response.",
            ),
            FINDING_USER_ENUM: (
                "manual_control",
                "Require a stable login differential between an unknown account and a known account with a wrong password.",
            ),
        }
        unresolved = [
            finding
            for finding in self._findings
            if finding.confidence in (CONF_PROBABLE, CONF_POTENTIAL, CONF_INCONCLUSIVE)
        ] + list(self._quarantined)
        backlog: list[dict] = []
        seen_scopes: set[str] = set()
        for finding in unresolved:
            dedupe_key = finding.scope_key or f"{finding.vuln_type}|{finding.id}"
            if dedupe_key in seen_scopes:
                continue
            seen_scopes.add(dedupe_key)
            tool, proof = profiles.get(
                finding.vuln_type,
                ("manual_control", "Repeat the request with a negative control and require a reproducible difference."),
            )
            try:
                _, endpoint, parameter = finding.scope_key.split("|", 2)
            except ValueError:
                endpoint, parameter = self.target or "unknown", "unknown"
            backlog.append({
                "id": finding.id,
                "type": finding.vuln_type,
                "tier": finding.confidence,
                "endpoint": endpoint if endpoint != "unknown" else self.target or "unknown",
                "parameter": parameter,
                "tool": tool,
                "required_evidence": proof,
            })
            if len(backlog) >= limit:
                break
        return backlog

    def evidence_flags(self) -> dict:
        """next_steps 필터용 — probable/potential SQLi는 계속 추적."""
        texts = " ".join(
            (f.evidence or "") + " " + (f.notes or "") + " " + (f.payload or "")
            for f in self._findings
            if f.confidence != CONF_BLOCKED
        ).lower()
        has_upload = bool(re.search(
            r'upload|multipart|file\s*input|enctype\s*=\s*[\'"]multipart'
            r'|웹쉘|webshell|\.php\s*upload|파일\s*업로드',
            texts, re.I
        ))
        has_real_cred = bool(re.search(
            r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,}|0123456789abcdef)\S{4,}',
            texts, re.I
        )) or any(
            f.vuln_type == FINDING_CREDENTIAL and f.confidence == CONF_CONFIRMED
            for f in self._findings
        )
        has_confirmed_sqli = any(
            f.vuln_type == FINDING_SQLI and (f.confirmed or f.confidence == CONF_CONFIRMED)
            for f in self._findings
        )
        has_potential_sqli = any(
            f.vuln_type == FINDING_SQLI
            and f.confidence in (CONF_PROBABLE, CONF_POTENTIAL, CONF_INCONCLUSIVE, CONF_CONFIRMED)
            for f in self._findings
        )
        has_admin_panel = bool(re.search(r'/adm(?:in)?/|관리자\s*패널|admin\s*panel', texts, re.I))
        return {
            "has_upload": has_upload,
            "has_real_cred": has_real_cred,
            "has_confirmed_sqli": has_confirmed_sqli,
            "has_potential_sqli": has_potential_sqli,
            "has_admin_panel": has_admin_panel,
            "confirmed_count": sum(1 for f in self._findings if f.confirmed),
            "probable_count": sum(1 for f in self._findings if f.confidence == CONF_PROBABLE),
            "potential_count": sum(
                1 for f in self._findings
                if f.confidence in (CONF_POTENTIAL, CONF_INCONCLUSIVE, CONF_PROBABLE)
            ),
            "blocked_count": sum(1 for f in self._findings if f.confidence == CONF_BLOCKED),
        }

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

    @property
    def quarantined(self) -> list[Finding]:
        return list(self._quarantined)

    def extract_xss_urls(self, output: str) -> list[str]:
        """출력에서 XSS payload가 포함된 URL 추출 (Playwright 검증용)"""
        urls = []
        for m in _XSS_URL_PATTERN.finditer(output):
            urls.append(m.group(0))
        for line in output.splitlines():
            stripped = line.strip()
            if re.search(r'https?://', stripped) and re.search(
                r'(<|%3C|%22|javascript:|onerror=|onload=)', stripped, re.I
            ):
                m_url = re.search(r'https?://\S+', stripped)
                if m_url and m_url.group(0) not in urls:
                    urls.append(m_url.group(0))
        return urls[:5]


def _get_version() -> str:
    try:
        from .. import __version__
        return __version__
    except Exception:
        return "unknown"
