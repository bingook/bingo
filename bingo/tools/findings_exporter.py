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

# v6.2.175: 증거 신뢰도 3상태 (+ potential)
CONF_CONFIRMED    = "confirmed"
CONF_BLOCKED      = "blocked"
CONF_INCONCLUSIVE = "inconclusive"
CONF_POTENTIAL    = "potential"

REASON_BLOCKED_WAF_SAME_SIZE = "blocked_by_waf_same_size"
REASON_ORACLE_PRECHECK_FAIL  = "oracle_precheck_failed"
REASON_LOGIN_FORM_ONLY       = "login_form_only"
REASON_PLACEHOLDER_HASH      = "placeholder_hash"
REASON_PAGE_CONTAMINATION    = "page_contamination"
REASON_WAF_BLOCK_PAGE        = "waf_block_page"
REASON_NOT_VULNERABLE        = "not_vulnerable"
REASON_CF_BLOCK              = "cloudflare_block"
REASON_WAF_REDIRECT          = "waf_security_redirect"
# v6.2.176: 실탐 승격 reason
REASON_BOOLEAN_DIFF          = "boolean_true_false_diff"
REASON_XPATH_EXTRACT         = "xpath_error_extract"
REASON_DB_TABLE_EXTRACT      = "db_table_extract"
REASON_REAL_CREDENTIAL       = "real_credential_extract"
REASON_RCE_PROOF             = "rce_command_output"
REASON_TIME_BASED            = "time_based_delay"
REASON_STRONG_OVERRIDE       = "strong_proof_overrides_fp"


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
    # v6.2.175: 보고서/요약/next_steps가 공유하는 근거
    confidence: str = CONF_INCONCLUSIVE  # confirmed|blocked|inconclusive|potential
    reason_code: str = ""

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
    r'|SQLI_EXTRACTION_FAILURE'
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

_AUTH_BYPASS_PATTERNS = [
    re.compile(r'(관리자|admin)\s*(패널|panel|dashboard|로그인|login)\s*(성공|접근|완료|OK)', re.I),
    # v6.2.10: Set-Cookie 단독으론 auth_bypass 아님 — 제거 (세션쿠키 오탐 다수 발생)
    # re.compile(r'Set-Cookie:.*?(admin|session|auth|jwt)', re.I),  ← 삭제됨
    # HTTP 200 + admin — URL 경로가 실제로 admin이어야 함 (응답 헤더 텍스트 아님)
    re.compile(r'(Location|URL):\s*.*?/admin(?:/|$)', re.I),
    re.compile(r'(welcome|dashboard|admin)\s*-\s*(admin|root|manager)', re.I),
]


def _strong_vuln_proof(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """v6.2.176 Type A: 오탐 필터보다 우선하는 실탐 증거.

    Returns:
        (proof_level, reason_code) or None
        proof_level: 'confirmed' (추출/실행 증명) | 'potential' (oracle 차이 등)
    """
    if not output:
        return None

    # 1) RCE: uid= / whoami
    if re.search(r'\buid=\d+\([^)]+\)\s+gid=\d+', output, re.I):
        return ("confirmed", REASON_RCE_PROOF)

    # 2) Boolean TRUE/FALSE 응답 크기 차이 (동일 크기 아님 → 실 oracle)
    _m_t = re.search(
        r'(?:TRUE|1\s*=\s*1|2\s*>\s*1).{0,60}?(\d{2,6})\s*B',
        output, re.I | re.S
    )
    _m_f = re.search(
        r'(?:FALSE|1\s*=\s*0|1\s*=\s*2|1\s*>\s*2).{0,60}?(\d{2,6})\s*B',
        output, re.I | re.S
    )
    if _m_t and _m_f:
        try:
            _tb, _fb = int(_m_t.group(1)), int(_m_f.group(1))
            # 최소 200B 차이 → WAF 동일차단이 아닌 실제 boolean 차이
            if abs(_tb - _fb) >= 200:
                return ("potential", REASON_BOOLEAN_DIFF)
        except ValueError:
            pass

    # 3) XPATH/EXTRACTVALUE 실제 에러 추출 (~dbname~ / XPATH syntax error)
    if re.search(
        r'XPATH\s+syntax\s+error[^\n]{0,80}~[A-Za-z0-9_.\-]{2,80}~'
        r'|~[A-Za-z0-9_.\-]{2,80}~[^\n]{0,40}XPATH'
        r'|->\s*DATA:\s*[~\'"]?[A-Za-z][A-Za-z0-9_.\-]{1,63}[~\'"]?'
        r'(?!\s*(?:오전|오후|월요일|화요일|<html|<!DOCTYPE|해킹방지))',
        output, re.I
    ):
        # 페이지 오염(시간/요일)만이면 제외 — xpath 토큰이 명확할 때만
        if not re.search(
            r'->\s*DATA:\s*.*(?:오전|오후|월요일|화요일|수요일|목요일|금요일|토요일|일요일)',
            output, re.I
        ):
            return ("confirmed", REASON_XPATH_EXTRACT)

    # 4) DB/테이블 실추출 (EXISTS + 실제 이름, 반복문자 제외)
    if re.search(
        r'(?:database|db_name|schema)\s*[=:]\s*[\'"]?(?!a{4,}|0{4,})[a-zA-Z][\w]{1,40}'
        r'|table(?:_name)?\s+[\w]+\s*:\s*EXISTS'
        r'|\[?\s*(?:g5_|wp_|information_schema)[\w]*\s*\]?\s*(?:EXISTS|found|존재)',
        output, re.I
    ) and not _ORACLE_FAILURE_REPEATED.search(output):
        return ("confirmed", REASON_DB_TABLE_EXTRACT)

    # 5) 실제 자격증명 (플레이스홀더 제외)
    if re.search(
        r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,}|A{6,}|0123456789abcdef)\S{6,}',
        output, re.I
    ) and not _FAKE_CRED_VALUE.search(output):
        return ("confirmed", REASON_REAL_CREDENTIAL)

    # 6) Time-based: SLEEP/BENCHMARK + 지연 확인
    if (
        re.search(r'(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(', output + " " + code_snippet, re.I)
        and re.search(
            r'(?:delay|elapsed|took|응답\s*시간|耗时)\s*[=: ]*\s*(?:[5-9]|[1-9]\d+)(?:\.\d+)?\s*s'
            r'|time.?based.{0,40}(?:confirm|success|취약|vulnerable)',
            output, re.I
        )
    ):
        return ("potential", REASON_TIME_BASED)

    # 7) XSS 브라우저 확인 마커
    if re.search(r'window\.__BINGO_XSS__\s*=\s*1|XSS\s+(?:confirmed|브라우저\s*실행\s*확인)', output, re.I):
        return ("confirmed", "xss_browser_confirmed")

    return None


def _assess_evidence(output: str, code_snippet: str = "") -> tuple[str, str]:
    """v6.2.175/176 Type A: 출력을 confirmed/blocked/ok 분류.

    Returns:
        (status, reason_code)
        status: 'blocked' | 'ok' | 'strong'
        - strong: 실탐 증거가 FP 신호를 이김 (process에서 potential/confirmed 승격)
    """
    # ── v6.2.176: 강한 실탐 증거가 있으면 FP blocked를 절대 우선하지 않음 ──
    _proof = _strong_vuln_proof(output, code_snippet)
    if _proof:
        _level, _rc = _proof
        return ("strong", _rc if _level == "confirmed" else f"potential:{_rc}")

    _NOT_VULN_RE = re.compile(
        r'NOT\s+vulnerable\s*[❌✗×⛔]'
        r'|→\s*NOT\s+vulnerable'
        r'|DB\s+errors\s+found:\s*None'
        r'|boolean\s+oracle.*?fail'
        r'|SQLI_EXTRACTION_FAILURE'
        r'|Oracle预检失败'
        r'|oracle\s*pre-?check\s*FAIL'
        r'|Boolean\s+字符提取已禁用'
        r'|Boolean\s+character\s+extraction\s+disabled',
        re.I
    )
    # 주의: confirmed=false JSON 덤프는 실탐 억제에 쓰지 않음 (오탐 방지용 메타가 실탐을 죽임)
    if _NOT_VULN_RE.search(output):
        return ("blocked", REASON_NOT_VULNERABLE)

    if len(output) <= 2000 and (
        _WAF_BLOCK_KO.search(output) or _WAF_BLOCK_EN.search(output)
    ):
        return ("blocked", REASON_WAF_BLOCK_PAGE)

    _CF_BLOCK_RE = re.compile(
        r'cloudflare.*?(error|blocked|denied)'
        r'|ray\s+id\s*:\s*[0-9a-f]+'
        r'|__cf_chl|cf-ray:'
        r'|error\s+1\d{3}\s+access\s+denied'
        r'|sorry,\s+you\s+have\s+been\s+blocked',
        re.I
    )
    if _CF_BLOCK_RE.search(output):
        return ("blocked", REASON_CF_BLOCK)

    _same_waf_size = re.search(
        r'(?:TRUE|1=1|2>1).{0,40}?(\d{2,4})B'
        r'.{0,120}?'
        r'(?:FALSE|1=0|1=2|1>2).{0,40}?\1B',
        output, re.I | re.S
    )
    if _same_waf_size:
        return ("blocked", REASON_BLOCKED_WAF_SAME_SIZE)

    # 정상 대용량 vs payload 소형(WAF) — 490B 차단 페이지 단독 패턴
    if re.search(
        r'(?:해킹방지|요청이\s*차단|security\s+system|blocked\s+by\s+waf).{0,80}?\b(\d{2,4})B\b'
        r'|\b49[0-9]B\b.{0,40}?(?:해킹방지|WAF|차단)',
        output, re.I | re.S
    ):
        if _SQLI_CONTEXT_KEYWORDS.search(output) or _SQLI_CONTEXT_KEYWORDS.search(code_snippet):
            return ("blocked", REASON_WAF_BLOCK_PAGE)

    if re.search(r'(?:updatexml|extractvalue)\s*\(', output, re.I):
        _has_xpath_err = bool(re.search(
            r'XPATH\s+syntax\s+error|xpath\s+error|~[a-zA-Z0-9_.\-]{2,80}~',
            output, re.I
        ))
        _page_contam = bool(re.search(
            r'->\s*DATA:\s*.*(?:오전|오후|월요일|화요일|수요일|목요일|금요일|토요일|일요일'
            r'|<html|<!DOCTYPE|해킹방지|요청이\s*차단)',
            output, re.I
        ))
        _data_empty = bool(re.search(r'->\s*DATA:\s*(?:None|null|\(empty)?\s*$', output, re.I | re.M))
        if (_page_contam or _data_empty) and not _has_xpath_err:
            return ("blocked", REASON_PAGE_CONTAMINATION)

    if _WAF_SECURITY_REDIRECT.search(output.lower()):
        return ("blocked", REASON_WAF_REDIRECT)

    if _ORACLE_FAILURE_REPEATED.search(output) or _ORACLE_FAILURE_WARNING.search(output):
        return ("blocked", REASON_ORACLE_PRECHECK_FAIL)

    if _FAKE_CRED_VALUE.search(output):
        return ("blocked", REASON_PLACEHOLDER_HASH)

    _is_login_form_only = bool(_LOGIN_FORM_ONLY.search(output)) and not re.search(
        r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,})\S{4,}', output, re.I
    )
    if _is_login_form_only and _CRED_PATTERNS and any(p.search(output) for p in _CRED_PATTERNS):
        return ("blocked", REASON_LOGIN_FORM_ONLY)

    return ("ok", "")


def _detect_vuln_type(output: str, code_snippet: str = "") -> tuple[str, str] | None:
    """출력 텍스트에서 취약점 유형과 심각도 탐지. 없으면 None.
    우선순위: RCE > LFI > AUTH_BYPASS > CREDENTIAL > SSRF > XSS > SQLi

    v4.8.0 수정: SQLi 컨텍스트(code_snippet에 EXTRACTVALUE/SLEEP 등) 포함 시
    CREDENTIAL보다 SQLi를 우선 분류 — 오분류 방지.

    v4.9.4 수정:
    - LFI 오탐 방지: php://filter 요청인데 HTML 응답(homepage redirect)이면 LFI 아님
    - Oracle 실패 억제: 추출값이 'aaa...' 반복 문자이면 credential/sqli 오탐 억제

    v6.2.175: WAF/oracle blocked는 _assess_evidence()에서 처리.
              여기서는 ok/strong 경로의 패턴 매칭만 수행.
    """
    # ── v6.2.175/176: blocked만 None. strong/ok는 계속 탐지 ──
    _status, _reason = _assess_evidence(output, code_snippet)
    if _status == "blocked":
        return None

    # ── v6.2.174: 로그인 폼 HTML만 있고 실제 추출 자격증명 없음 → credential 금지 ──
    _is_login_form_only = bool(_LOGIN_FORM_ONLY.search(output)) and not re.search(
        r'\[CREDENTIAL\]\s*\S+\s*:\s*(?!0{6,}|a{6,})\S{4,}', output, re.I
    )

    # ── v6.2.66: 미니파이 JS 출력 감지 — credential 오탐 방지 ─────────────────
    _is_js_chunk_output = bool(_MINIFIED_JS_CONTEXT.search(output))

    # ── v4.9.4: LFI php://filter 오탐 방지 ────────────────────────────────────
    _skip_lfi = False
    if _PHP_FILTER_IN_OUTPUT.search(output) or _PHP_FILTER_IN_OUTPUT.search(code_snippet):
        _has_b64_content = bool(_BASE64_FILE_BLOCK.search(output))
        _has_html_redirect = bool(_LFI_REDIRECT_HTML.search(output))
        if _has_html_redirect and not _has_b64_content:
            _skip_lfi = True

    # ── v4.8.0: SQLi 컨텍스트 사전 검사 ──────────────────────────────────────
    _sqli_context = (
        _SQLI_CONTEXT_KEYWORDS.search(code_snippet)
        or _SQLI_CONTEXT_KEYWORDS.search(output)
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
            if pat.search(output):
                return (vtype, sev)
    return None


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
        self._finding_hashes: set[str] = set()   # 중복 방지
        self._blocked_reasons: set[str] = set()  # v6.2.175: blocked reason 중복 방지

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
        """코드 실행 출력에서 발견 탐지 후 내부 저장. 발견 시 Finding 반환.

        v6.2.175:
          - blocked(WAF/oracle) → CRITICAL SQLi 금지, LOW+confidence=blocked 1회 기록
          - 미확인 CRITICAL → confidence=potential
        v6.2.176:
          - strong proof → FP blocked 무시, potential/confirmed 승격
          - 이전 blocked SQLi finding이 있으면 동일 타입을 confirmed/potential로 승격
        """
        if not output or len(output.strip()) < 10:
            return None

        status, reason = _assess_evidence(output, code_snippet=code_snippet)
        proof = _strong_vuln_proof(output, code_snippet)

        # ── strong: 실탐 증거 → FP 억제 무시하고 정상 finding (+ 승격) ─────────
        if status == "strong" or proof:
            _level, _prc = proof if proof else (
                ("confirmed", reason) if not str(reason).startswith("potential:")
                else ("potential", reason.split(":", 1)[-1])
            )
            # 패턴 탐지 시도 (실패해도 strong proof면 SQLi/RCE로 강제)
            detected = None
            # _detect_vuln_type은 blocked만 막음 — strong은 통과
            try:
                detected = _detect_vuln_type(output, code_snippet=code_snippet)
            except Exception:
                detected = None
            if detected:
                vtype, severity = detected
            elif _prc in (REASON_RCE_PROOF,):
                vtype, severity = FINDING_RCE, SEVERITY_CRITICAL
            elif _prc in (REASON_REAL_CREDENTIAL,):
                vtype, severity = FINDING_CREDENTIAL, SEVERITY_CRITICAL
            else:
                vtype, severity = FINDING_SQLI, SEVERITY_HIGH

            # CRITICAL 미확인은 potential 유지; confirmed proof면 승격
            if _level == "confirmed":
                confidence = CONF_CONFIRMED
                confirmed = True
                if severity == SEVERITY_HIGH and vtype == FINDING_SQLI:
                    severity = SEVERITY_CRITICAL  # 추출 증명된 SQLi
            else:
                confidence = CONF_POTENTIAL
                confirmed = False
                # potential SQLi는 HIGH 유지 (CRITICAL Confirmed 과장 방지)
                if severity == SEVERITY_CRITICAL and vtype == FINDING_SQLI:
                    severity = SEVERITY_HIGH

            evidence = output[:2000]
            import hashlib
            _hash = hashlib.md5(
                (f"strong:{vtype}:" + evidence[:200]).encode("utf-8", errors="ignore")
            ).hexdigest()[:12]
            if _hash in self._finding_hashes:
                # 중복이어도 기존 blocked → 승격 시도
                self._promote_blocked(vtype, confidence, confirmed, _prc, evidence)
                return None
            self._finding_hashes.add(_hash)

            finding = Finding(
                id=f"BINGO-{len(self._findings)+1:04d}",
                vuln_type=vtype,
                severity=severity,
                target=self.target,
                payload=(code_snippet or _extract_payload(output))[:500],
                evidence=evidence,
                notes=extra_notes or f"strong:{_prc}",
                confirmed=confirmed,
                confidence=confidence,
                reason_code=_prc or REASON_STRONG_OVERRIDE,
            )
            self._findings.append(finding)
            self._promote_blocked(vtype, confidence, confirmed, _prc, evidence)
            return finding

        # ── blocked: SQLi Critical 오탐 대신 차단 이벤트 1회 기록 ──────────────
        if status == "blocked":
            if reason in self._blocked_reasons:
                return None
            _sqli_ctx = bool(
                _SQLI_CONTEXT_KEYWORDS.search(code_snippet)
                or _SQLI_CONTEXT_KEYWORDS.search(output)
                or reason in (
                    REASON_BLOCKED_WAF_SAME_SIZE,
                    REASON_ORACLE_PRECHECK_FAIL,
                    REASON_PAGE_CONTAMINATION,
                    REASON_WAF_BLOCK_PAGE,
                )
            )
            _cred_ctx = reason in (REASON_LOGIN_FORM_ONLY, REASON_PLACEHOLDER_HASH)
            if not _sqli_ctx and not _cred_ctx and reason not in (
                REASON_NOT_VULNERABLE, REASON_CF_BLOCK, REASON_WAF_REDIRECT
            ):
                return None
            self._blocked_reasons.add(reason)
            vtype = FINDING_CREDENTIAL if _cred_ctx else (
                FINDING_SQLI if _sqli_ctx else FINDING_INFO_DISC
            )
            evidence = output[:2000]
            import hashlib
            _hash = hashlib.md5(
                (f"blocked:{reason}:" + evidence[:120]).encode("utf-8", errors="ignore")
            ).hexdigest()[:12]
            if _hash in self._finding_hashes:
                return None
            self._finding_hashes.add(_hash)
            finding = Finding(
                id=f"BINGO-{len(self._findings)+1:04d}",
                vuln_type=vtype,
                severity=SEVERITY_LOW,
                target=self.target,
                payload=(code_snippet or _extract_payload(output))[:500],
                evidence=evidence,
                notes=extra_notes or f"blocked:{reason}",
                confidence=CONF_BLOCKED,
                reason_code=reason,
            )
            self._findings.append(finding)
            return finding

        detected = _detect_vuln_type(output, code_snippet=code_snippet)
        if not detected:
            return None

        vtype, severity = detected
        payload = code_snippet or _extract_payload(output)
        evidence = output[:2000]

        import hashlib
        _hash = hashlib.md5(
            (vtype + evidence[:200]).encode("utf-8", errors="ignore")
        ).hexdigest()[:12]
        if _hash in self._finding_hashes:
            return None
        self._finding_hashes.add(_hash)

        confidence = CONF_POTENTIAL if severity == SEVERITY_CRITICAL else CONF_INCONCLUSIVE
        finding = Finding(
            id=f"BINGO-{len(self._findings)+1:04d}",
            vuln_type=vtype,
            severity=severity,
            target=self.target,
            payload=payload[:500],
            evidence=evidence,
            notes=extra_notes,
            confidence=confidence,
            reason_code="",
        )
        self._findings.append(finding)
        return finding

    def _promote_blocked(
        self,
        vtype: str,
        confidence: str,
        confirmed: bool,
        reason_code: str,
        evidence: str,
    ) -> None:
        """v6.2.176: 이전 blocked finding을 strong proof로 승격 (실탐 누락 방지)."""
        for f in self._findings:
            if f.confidence != CONF_BLOCKED:
                continue
            if f.vuln_type != vtype and not (
                vtype == FINDING_SQLI and f.vuln_type == FINDING_SQLI
            ):
                continue
            f.confidence = confidence
            f.confirmed = confirmed
            if confirmed:
                f.severity = SEVERITY_CRITICAL if vtype in (
                    FINDING_SQLI, FINDING_RCE, FINDING_CREDENTIAL, FINDING_LFI
                ) else f.severity
            elif confidence == CONF_POTENTIAL and f.severity == SEVERITY_LOW:
                f.severity = SEVERITY_HIGH if vtype == FINDING_SQLI else SEVERITY_MEDIUM
            f.reason_code = reason_code or REASON_STRONG_OVERRIDE
            f.notes = (f.notes or "") + f" | promoted:{reason_code}"
            if evidence and len(evidence) > len(f.evidence or ""):
                f.evidence = evidence[:2000]
            # blocked reason 집합에서 제거해 재기록 가능하게
            if f.reason_code in self._blocked_reasons:
                self._blocked_reasons.discard(
                    getattr(f, "_orig_block_reason", None) or ""
                )
            break

    def mark_confirmed(self, finding: Finding, screenshot_path: str = "") -> None:
        """Playwright 등 2차 검증 후 confirmed 플래그 세팅."""
        finding.confirmed = True
        finding.confidence = CONF_CONFIRMED
        finding.reason_code = finding.reason_code or "verified"
        if screenshot_path:
            finding.screenshot_path = screenshot_path

    def try_promote_from_output(self, output: str, code_snippet: str = "") -> Optional[Finding]:
        """외부에서 strong proof 재평가용 (세션 후속 추출 결과 반영)."""
        return self.process(output, code_snippet=code_snippet)

    def save(self) -> Path | None:
        """JSON 파일로 저장 후 경로 반환. 발견이 없으면 None."""
        if not self._findings:
            return None
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = (self.target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        path = self._dir / f"findings_{safe}_{ts}.json"
        _stats = self.stats()
        data = {
            "bingo_version": _get_version(),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            **_stats,
            "findings": [f.to_dict() for f in self._findings],
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
        """v6.2.175: confirmed / potential / blocked 분리 집계."""
        total = len(self._findings)
        confirmed = sum(1 for f in self._findings if f.confirmed or f.confidence == CONF_CONFIRMED)
        blocked = sum(1 for f in self._findings if f.confidence == CONF_BLOCKED)
        potential_critical = sum(
            1 for f in self._findings
            if f.severity == SEVERITY_CRITICAL and not f.confirmed and f.confidence != CONF_BLOCKED
        )
        potential_high = sum(
            1 for f in self._findings
            if f.severity == SEVERITY_HIGH and not f.confirmed and f.confidence != CONF_BLOCKED
        )
        # confirmed=0 이면 CRITICAL 카운트는 0 (과장 금지) — potential로만 표시
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
            "potential_critical": potential_critical,
            "potential_high": potential_high,
            "blocked": blocked,
            "confirmed": confirmed,
            "reason_codes": sorted({f.reason_code for f in self._findings if f.reason_code}),
        }

    def summary(self) -> str:
        """발견 요약 1줄 — confirmed=0이면 CRITICAL 대신 POTENTIAL_* 표기."""
        if not self._findings:
            return ""
        s = self.stats()
        parts = []
        if s["confirmed"]:
            parts.append(f"confirmed:{s['confirmed']}")
        if s["critical"]:
            parts.append(f"CRITICAL:{s['critical']}")
        if s["potential_critical"]:
            parts.append(f"POTENTIAL_CRITICAL:{s['potential_critical']}")
        if s["high"]:
            parts.append(f"HIGH:{s['high']}")
        if s["potential_high"]:
            parts.append(f"POTENTIAL_HIGH:{s['potential_high']}")
        if s["blocked"]:
            parts.append(f"blocked:{s['blocked']}")
        return f"[FINDINGS] total={s['total']} " + " ".join(parts)

    def ground_truth_block(self) -> str:
        """보고서/progress/next_steps에 주입할 FINDINGS GROUND TRUTH 텍스트."""
        s = self.stats()
        lines = [
            f"total={s['total']} confirmed={s['confirmed']} "
            f"critical={s['critical']} potential_critical={s['potential_critical']} "
            f"blocked={s['blocked']}",
            f"reason_codes={s['reason_codes'] or []}",
        ]
        for f in self._findings:
            lines.append(
                f"- id={f.id} type={f.vuln_type} sev={f.severity} "
                f"confirmed={f.confirmed} confidence={f.confidence} "
                f"reason={f.reason_code or '-'} notes={(f.notes or '')[:60]}"
            )
        return "\n".join(lines)

    def evidence_flags(self) -> dict:
        """next_steps 고위험 액션 필터용 증거 플래그."""
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
        # v6.2.176: potential SQLi도 실탐 후보 — next_steps에서 검증/우회 유지
        has_potential_sqli = any(
            f.vuln_type == FINDING_SQLI and f.confidence in (CONF_POTENTIAL, CONF_INCONCLUSIVE, CONF_CONFIRMED)
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
            "potential_count": sum(
                1 for f in self._findings
                if f.confidence in (CONF_POTENTIAL, CONF_INCONCLUSIVE) and f.confidence != CONF_BLOCKED
            ),
            "blocked_count": sum(1 for f in self._findings if f.confidence == CONF_BLOCKED),
        }

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings)

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
