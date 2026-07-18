"""
Zero Hallucination Engine v5.0
================================
목표: LLM 출력의 환각률 = 0 (zero hallucination)

기존 4-단계 환각 방지 (PhantomGuard v2.0.0):
  ① 팬텀 모드 감지
  ② 구캐시 차단
  ③ 타겟 오인 방지
  ④ 자기수정 루프 탈출
  + HTTP-0건 클레임 차단
  + SPA 오탐 차단
  + VPN 가상 IP 탐지

Zero Hallucination v5.0 — 신규 5개 레이어:

  Layer 1: FactRegistry       — 실행 결과에서 사실 추출·등록 (증거 앵커)
  Layer 2: ClaimAnchorValidator — 모든 취약점 주장을 등록된 사실에 연결
  Layer 3: NumericHallucinationGuard — IP/포트/버전/상태코드 숫자 환각 차단
  Layer 4: InferenceMeter     — 추론 비율 측정 (30% 초과 시 교정)
  Layer 5: ContextPoisonGuard — 이전 세션 오염 탐지 (크로스 세션 사실 유출)

  통합: ZeroHalEngine — 5개 레이어 순서대로 실행하는 파이프라인

원칙:
  - 기능 차단 없음: 모든 발견이 기록됨 (등급 구분만)
  - 숫자는 증거에서 온다: 스캔/HTTP 응답에 없는 숫자는 환각
  - 추론은 제한된다: 전체 응답의 30% 이내만 허용
  - 크로스 세션 누출 없음: 이전 타겟 정보는 새 세션에 유출 불가
"""
from __future__ import annotations

import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# Layer 1: FactRegistry
# ══════════════════════════════════════════════════════════════════════════════

# 사실 카테고리
FACT_IP           = "ip"
FACT_PORT         = "port"
FACT_STATUS       = "status_code"
FACT_VERSION      = "version"
FACT_HEADER       = "header"
FACT_PATH         = "path"
FACT_COOKIE       = "cookie"
FACT_HASH         = "hash"
FACT_DOMAIN       = "domain"
FACT_CVE          = "cve"

# 실행 결과에서 사실 추출 패턴
_FACT_EXTRACTORS: dict[str, list[re.Pattern]] = {
    FACT_IP: [
        re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b'),
    ],
    FACT_PORT: [
        re.compile(r'\bport[s]?\s*[:\-]?\s*(\d{2,5})\b', re.IGNORECASE),
        re.compile(r'\b(\d{2,5})/(?:tcp|udp)\s+open', re.IGNORECASE),
        re.compile(r'open\s+port[s]?\s*[:\-]?\s*(\d{2,5})', re.IGNORECASE),
    ],
    FACT_STATUS: [
        re.compile(r'STATUS[:\s_-]+(\d{3})\b', re.IGNORECASE),
        re.compile(r'HTTP/[12][\.\d]*\s+(\d{3})\b'),
        re.compile(r'\[(\d{3})/\d+B\]'),
        re.compile(r'<Response\s*\[(\d{3})\]>'),
        re.compile(r'\bstatus_code\s*=\s*(\d{3})\b', re.IGNORECASE),
    ],
    FACT_VERSION: [
        re.compile(r'(?:Apache|Nginx|IIS|PHP|Python|OpenSSH|MySQL|nginx)[/\s]+(\d+\.\d+[.\d]*)', re.IGNORECASE),
        re.compile(r'Server:\s*\S+/(\d+\.\d+[.\d]*)', re.IGNORECASE),
        re.compile(r'X-Powered-By:\s*\S+/(\d+\.\d+[.\d]*)', re.IGNORECASE),
    ],
    FACT_HEADER: [
        re.compile(r'((?:Server|Content-Type|X-Powered-By|Set-Cookie|X-Frame-Options|X-XSS-Protection|Content-Security-Policy)[:\s]+[^\n]{3,80})', re.IGNORECASE),
    ],
    FACT_PATH: [
        re.compile(r'\[(?:200|301|302|403|404)/\d+B\]\s+(\/[^\s\]\n]{1,200})', re.IGNORECASE),
        re.compile(r'Found\s+(?:endpoint|path)\s*[:\-]?\s*(\/[^\s\n]{1,200})', re.IGNORECASE),
    ],
    FACT_COOKIE: [
        re.compile(r'Set-Cookie:\s*([^;\n]{3,100})', re.IGNORECASE),
        re.compile(r'session(?:_id|id)?\s*[=:]\s*([a-zA-Z0-9_\-]{8,80})', re.IGNORECASE),
    ],
    FACT_DOMAIN: [
        re.compile(r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'),
    ],
    FACT_CVE: [
        re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE),
    ],
}

# 가상 IP / 로컬 IP → 사실 등록 제외
_SKIP_IPS: frozenset[str] = frozenset({
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "192.168.0.1", "10.0.0.1",
})
_LOCAL_IP_RE = re.compile(r'^(?:127\.|10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|::1$|0\.0\.0\.0$)')


@dataclass
class RegisteredFact:
    category: str
    value: str
    source_id: str          # exec 블록 ID / "manual"
    timestamp: float = field(default_factory=time.time)
    evidence_hash: str = ""

    def __post_init__(self):
        if not self.evidence_hash:
            raw = f"{self.category}:{self.value}:{self.source_id}"
            self.evidence_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def __eq__(self, other) -> bool:
        if not isinstance(other, RegisteredFact):
            return False
        return self.category == other.category and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.category, self.value))


class FactRegistry:
    """
    Layer 1 — 실행 결과에서 검증된 사실을 등록하고 조회하는 저장소.

    모든 숫자(IP, 포트, 상태코드, 버전), 헤더, 쿠키, 경로를
    실제 HTTP 실행 결과에서 추출해 등록함.

    등록된 사실만 LLM 출력에서 인용 가능.
    등록되지 않은 숫자/주장 → NumericHallucinationGuard가 차단.
    """

    def __init__(self):
        self._facts: dict[str, set[RegisteredFact]] = {cat: set() for cat in _FACT_EXTRACTORS}
        self._exec_count: int = 0

    def register_from_exec(self, exec_output: str) -> int:
        """실행 결과에서 사실 자동 추출·등록. 등록된 사실 수 반환."""
        if not exec_output.strip():
            return 0
        self._exec_count += 1
        exec_id = f"exec_{self._exec_count}"
        count = 0
        for cat, patterns in _FACT_EXTRACTORS.items():
            for pat in patterns:
                for m in pat.finditer(exec_output):
                    val = m.group(1).strip() if m.lastindex else m.group(0).strip()
                    val = val[:200]
                    # IP 필터링
                    if cat == FACT_IP:
                        if val in _SKIP_IPS or _LOCAL_IP_RE.match(val):
                            continue
                        # 유효한 IP 형식 확인
                        parts = val.split(".")
                        if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p):
                            continue
                    # 포트 필터링
                    if cat == FACT_PORT:
                        try:
                            p = int(val)
                            if not (1 <= p <= 65535):
                                continue
                        except ValueError:
                            continue
                    fact = RegisteredFact(category=cat, value=val, source_id=exec_id)
                    if fact not in self._facts[cat]:
                        self._facts[cat].add(fact)
                        count += 1
        return count

    def register_manual(self, category: str, value: str, source: str = "manual") -> RegisteredFact:
        """수동 사실 등록 (타겟 URL, 사용자 입력 정보 등)."""
        fact = RegisteredFact(category=category, value=value, source_id=source)
        self._facts.setdefault(category, set()).add(fact)
        return fact

    def is_registered(self, category: str, value: str) -> bool:
        """해당 카테고리에 값이 등록되어 있으면 True."""
        for f in self._facts.get(category, set()):
            if f.value.lower() == value.lower():
                return True
        return False

    def get_all(self, category: str) -> list[str]:
        """카테고리의 등록된 모든 값 반환."""
        return [f.value for f in self._facts.get(category, set())]

    def has_any_facts(self) -> bool:
        return any(self._facts.values())

    def summary(self) -> str:
        lines = ["[FactRegistry]"]
        for cat, fset in self._facts.items():
            if fset:
                vals = ", ".join(list({f.value for f in fset})[:5])
                lines.append(f"  {cat}: {len(fset)}건 [{vals}...]")
        return "\n".join(lines) if len(lines) > 1 else "[FactRegistry: 등록된 사실 없음]"


# ══════════════════════════════════════════════════════════════════════════════
# Layer 2: ClaimAnchorValidator
# ══════════════════════════════════════════════════════════════════════════════

# Definite claims only. Hypotheses such as "test possible SQLi" remain executable.
_CLAIM_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sqli", re.compile(r'(SQLi?|SQL\s*injection).{0,30}(?:found|detected|confirmed|발견|확인|존재|验证|发现)', re.IGNORECASE)),
    ("xss", re.compile(r'(XSS).{0,30}(?:found|detected|confirmed|발견|확인|존재|验证|发现)', re.IGNORECASE)),
    ("rce", re.compile(r'(RCE|Remote\s*Code\s*Execution).{0,30}(?:found|detected|confirmed|발견|확인|존재)', re.IGNORECASE)),
    ("ssrf", re.compile(r'(SSRF).{0,30}(?:found|detected|confirmed|발견|확인)', re.IGNORECASE)),
    ("idor", re.compile(r'(IDOR|Insecure\s*Direct\s*Object).{0,30}(?:found|detected|confirmed|발견|확인)', re.IGNORECASE)),
    ("admin", re.compile(r'(admin|관리자)\s+(?:panel|page|계정|패널)\s+(?:found|accessed|접근|발견)', re.IGNORECASE)),
    ("credential", re.compile(r'(?:credential|password|비밀번호|자격증명)\s+(?:found|extracted|obtained|발견|추출)', re.IGNORECASE)),
    ("login", re.compile(r'(?:login|로그인)\s+(?:successful|success|성공|확인)', re.IGNORECASE)),
    ("port", re.compile(r'(?:port|포트)\s+\d{2,5}\s+(?:open|열림|开放)', re.IGNORECASE)),
    ("cve", re.compile(r'(?:CVE-\d{4}-\d{4,7})\s+(?:confirmed|vulnerable|취약|확인)', re.IGNORECASE)),
]

# 증거 앵커 마커 (실제 증거가 응답에 포함된 경우)
_EVIDENCE_ANCHORS: list[re.Pattern] = [
    re.compile(r'\[\d{3}/\d+B\]'),                   # Bingo 실행 결과 포맷
    re.compile(r'STATUS[:\s]+\d{3}'),
    re.compile(r'HTTP/[12][\.\d]*\s+\d{3}'),
    re.compile(r'curl\s+-s[kX\s]+'),
    re.compile(r'requests\.(get|post|put|delete)'),
    re.compile(r'response_body\s*[:=]'),
    re.compile(r'evidence_hash\s*[:=]'),
    re.compile(r'r\.status_code'),
]

_CLAIM_EVIDENCE: dict[str, re.Pattern] = {
    "sqli": re.compile(
        r'You have an error in your SQL syntax|ORA-\d{4,}|SQLSTATE\[|'
        r'\[TIME_BASED\][^\n]*samples=(?:[3-9]|\d{2,})|'
        r'\[(?:SQLI_CONFIRMED|BOOLEAN_ORACLE)\]|'
        r'TRUE\s+\d+B[^\n]*FALSE\s+\d+B',
        re.IGNORECASE,
    ),
    "xss": re.compile(r'XSS_BROWSER_CONFIRMED|browser execution confirmed|dialog\s*=\s*alert', re.IGNORECASE),
    "rce": re.compile(r'uid=\d+\([^)]+\).*gid=\d+|root:x:0:0:[^\n]*:/root:|RCE_CANARY_[A-Za-z0-9_-]+', re.IGNORECASE),
    "ssrf": re.compile(r'ami-id|instance-id|AccessKeyId|metadata-flavor\s*:\s*google|"subscriptionId"', re.IGNORECASE),
    "idor": re.compile(r'IDOR_CONTROL_VERIFIED|other_user_id\s*=.+data_returned\s*=\s*true', re.IGNORECASE),
    "admin": re.compile(r'(?:HTTP_STATUS:200|\[200[^]]*\]).{0,160}/adm(?:in)?/', re.IGNORECASE),
    "credential": re.compile(r'\[CREDENTIAL\]\s*\S+\s*:\s*\S+', re.IGNORECASE),
    "login": re.compile(r'LOGIN_CONTROL_VERIFIED|login_verified\s*=\s*true|Set-Cookie:[^\n]+\nLocation:[^\n]+', re.IGNORECASE),
    "port": re.compile(r'\d{1,5}/tcp\s+open\b|PORT\s+\d+\s+OPEN', re.IGNORECASE),
    "cve": re.compile(r'CVE_VERIFIED|EXPLOIT_CANARY_VERIFIED', re.IGNORECASE),
}


@dataclass
class ClaimAnchorResult:
    unanchored_claims: list[str] = field(default_factory=list)
    anchored_claims: list[str] = field(default_factory=list)
    has_evidence: bool = False

    @property
    def is_clean(self) -> bool:
        return len(self.unanchored_claims) == 0


class ClaimAnchorValidator:
    """
    Layer 2 — 취약점 주장과 증거 사실을 연결 검증.

    LLM 응답에 취약점 주장이 있으면:
    - 같은 응답 혹은 exec_output에 실제 증거 앵커가 있는지 확인
    - FactRegistry에 관련 사실이 등록되어 있는지 확인
    - 없으면 → 미앵커(unanchored) 주장으로 분류
    """

    def validate(
        self,
        response_text: str,
        exec_output: str,
        registry: FactRegistry,
    ) -> ClaimAnchorResult:
        combined = response_text + "\n" + exec_output
        result = ClaimAnchorResult()

        # 증거 앵커 존재 여부
        result.has_evidence = any(p.search(exec_output) for p in _EVIDENCE_ANCHORS)

        # 클레임마다 같은 취약점 유형의 실행 증거를 요구한다. 일반 HTTP 200이나
        # 다른 유형의 사실은 현재 클레임을 앵커링하지 못한다.
        for claim_type, pat in _CLAIM_PATTERNS:
            m = pat.search(response_text)
            if m:
                claim_text = m.group(0)[:100]
                evidence_pattern = _CLAIM_EVIDENCE[claim_type]
                if evidence_pattern.search(exec_output):
                    result.anchored_claims.append(claim_text)
                else:
                    result.unanchored_claims.append(claim_text)

        return result

    def block_msg(self, result: ClaimAnchorResult, target: str, lang: str = "ko") -> str:
        claims_str = "\n".join(f"  - {c}" for c in result.unanchored_claims[:5])
        msgs = {
            "ko": (
                f"[⛔ 증거 미앵커 클레임 차단 — Zero Hallucination v5]\n\n"
                f"다음 취약점 주장에 실제 HTTP 실행 증거가 없습니다:\n{claims_str}\n\n"
                f"■ 실제 HTTP 요청 없이 취약점을 '발견/확인'하는 것은 환각입니다.\n"
                f"■ 먼저 bash+curl로 실행 후 주장하세요:\n"
                f"  curl -sk -m 10 '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:300])\"\n"
                f"■ 실행 결과 없는 VERIFIED/CONFIRMED 클레임 금지."
            ),
            "zh": (
                f"[⛔ 无证据声明拦截 — Zero Hallucination v5]\n\n"
                f"以下漏洞声明缺乏真实HTTP执行证据:\n{claims_str}\n\n"
                f"■ 没有执行HTTP请求就声明漏洞是幻觉。请用bash+curl执行:\n"
                f"  curl -sk -m 10 '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:300])\""
            ),
            "en": (
                f"[⛔ UNANCHORED CLAIM BLOCKED — Zero Hallucination v5]\n\n"
                f"Vulnerability claims without real HTTP execution evidence:\n{claims_str}\n\n"
                f"■ Claiming vulnerabilities without executing HTTP requests is HALLUCINATION.\n"
                f"  Use bash+curl: curl -sk -m 10 '{target}' | python3 -c \"import sys; r=sys.stdin.read(); print(r[:300])\"\n"
                f"■ NO VERIFIED/CONFIRMED claims without evidence."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# Layer 3: NumericHallucinationGuard
# ══════════════════════════════════════════════════════════════════════════════

# LLM 응답에서 구체적 숫자 클레임 패턴
_NUMERIC_CLAIM_PATTERNS: dict[str, list[re.Pattern]] = {
    FACT_PORT: [
        re.compile(r'port\s+(\d{2,5})\s+(?:is\s+)?(?:open|열려|开放)', re.IGNORECASE),
        re.compile(r'(\d{2,5})/tcp\s+open', re.IGNORECASE),
        re.compile(r'발견된\s+포트[:\s]+(\d{2,5})', re.IGNORECASE),
    ],
    FACT_STATUS: [
        re.compile(r'(?:returned?|returned?s?|응답|반환|返回)\s+(?:status\s+)?(\d{3})\b', re.IGNORECASE),
        re.compile(r'HTTP\s+(\d{3})\s+(?:OK|Found|Forbidden|Not\s+Found)', re.IGNORECASE),
    ],
    FACT_IP: [
        re.compile(r'(?:server|host|IP|address)[:\s]+(\d{1,3}(?:\.\d{1,3}){3})\b', re.IGNORECASE),
        re.compile(r'실제\s+(?:IP|서버\s+IP)[:\s]+(\d{1,3}(?:\.\d{1,3}){3})\b', re.IGNORECASE),
    ],
    FACT_VERSION: [
        re.compile(r'(?:running|version|실행 중|버전)[:\s]+\S+/(\d+\.\d+[.\d]*)', re.IGNORECASE),
        re.compile(r'Apache/(\d+\.\d+[.\d]*)', re.IGNORECASE),
        re.compile(r'nginx/(\d+\.\d+[.\d]*)', re.IGNORECASE),
        re.compile(r'PHP/(\d+\.\d+[.\d]*)', re.IGNORECASE),
    ],
}


@dataclass
class NumericGuardResult:
    hallucinated: list[tuple[str, str]] = field(default_factory=list)   # (category, value)
    verified: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.hallucinated) == 0


class NumericHallucinationGuard:
    """
    Layer 3 — LLM 응답의 구체적 숫자가 FactRegistry에 등록된 사실인지 검증.

    등록된 사실 없는 포트, IP, 버전, 상태코드 = 숫자 환각.
    단, FactRegistry가 비어있으면 (스캔 전) 검사 스킵.
    """

    def validate(self, response_text: str, registry: FactRegistry) -> NumericGuardResult:
        result = NumericGuardResult()

        # FactRegistry에 사실이 없으면 스킵 (아직 스캔 전)
        if not registry.has_any_facts():
            return result

        for cat, patterns in _NUMERIC_CLAIM_PATTERNS.items():
            registered_vals = {v.lower() for v in registry.get_all(cat)}
            for pat in patterns:
                for m in pat.finditer(response_text):
                    val = m.group(1).strip()
                    if val.lower() in registered_vals:
                        result.verified.append((cat, val))
                    else:
                        # 관련 카테고리에 등록된 사실이 있을 때만 환각으로 판정
                        if registered_vals:
                            result.hallucinated.append((cat, val))

        return result

    def block_msg(
        self,
        result: NumericGuardResult,
        registry: FactRegistry,
        lang: str = "ko",
    ) -> str:
        hal_list = "\n".join(
            f"  - [{cat}] '{val}' → 등록 없음"
            for cat, val in result.hallucinated[:5]
        )
        reg_sample = {}
        for cat, val in result.hallucinated:
            vals = registry.get_all(cat)[:3]
            if vals:
                reg_sample[cat] = vals
        reg_str = "\n".join(
            f"  - [{cat}] 등록된 실제값: {', '.join(vals)}"
            for cat, vals in reg_sample.items()
        )
        msgs = {
            "ko": (
                f"[⛔ 숫자 환각 차단 — Zero Hallucination v5]\n\n"
                f"다음 숫자값이 실제 실행 결과와 일치하지 않습니다:\n{hal_list}\n\n"
                f"■ 실제 등록된 값:\n{reg_str}\n\n"
                f"■ LLM이 만들어낸 숫자를 사용하지 마십시오.\n"
                f"■ 실제 nmap/requests/curl 실행 결과의 숫자만 사용하세요."
            ),
            "zh": (
                f"[⛔ 数字幻觉拦截 — Zero Hallucination v5]\n\n"
                f"以下数值与真实执行结果不符:\n{hal_list}\n\n"
                f"■ 真实注册值:\n{reg_str}\n\n"
                f"■ 请勿使用LLM生成的数字，只使用真实扫描/HTTP结果中的值。"
            ),
            "en": (
                f"[⛔ NUMERIC HALLUCINATION BLOCKED — Zero Hallucination v5]\n\n"
                f"These numeric values do not match real execution results:\n{hal_list}\n\n"
                f"■ Actually registered values:\n{reg_str}\n\n"
                f"■ Do NOT use LLM-generated numbers. Use only real scan/HTTP output values."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# Layer 4: InferenceMeter
# ══════════════════════════════════════════════════════════════════════════════

# 증거 마커 (실제 증거가 있음을 나타내는 패턴)
_EVIDENCE_MARKERS: list[re.Pattern] = [
    re.compile(r'\[\d{3}/\d+B\]'),
    re.compile(r'STATUS[:\s]+\d{3}', re.IGNORECASE),
    re.compile(r'r\.status_code\s*==\s*\d{3}'),
    re.compile(r'HTTP/[12][\.\d]*\s+\d{3}'),
    re.compile(r'curl\s+-s'),
    re.compile(r'requests\.(get|post|put|delete)\(', re.IGNORECASE),
    re.compile(r'evidence_hash'),
    re.compile(r'VERIFIED|LIKELY|INFERRED', re.IGNORECASE),
    re.compile(r'실제\s+(?:HTTP|응답|결과|확인)'),
    re.compile(r'真实\s*(?:HTTP|响应|确认)'),
]

# 추론/추측 패턴 (확인 없는 가정)
_INFERENCE_MARKERS: list[re.Pattern] = [
    # 영문
    re.compile(r'\b(?:probably|likely|maybe|might|could|possibly|appears?\s+to|seems?\s+to|I\s+(?:think|believe|assume|suspect))\b', re.IGNORECASE),
    re.compile(r'\b(?:should\s+be|would\s+be|expected?\s+to|assuming|hypothesis)\b', re.IGNORECASE),
    re.compile(r'\b(?:based\s+on\s+(?:my|the|general)|typically|usually|often|common(?:ly)?)\b', re.IGNORECASE),
    # 한국어
    re.compile(r'(?:아마|추정|추측|추론|가능성|~일\s*것|~겠|~인\s*것\s*같|아닐까|수도\s*있|보통은|일반적으로)', re.IGNORECASE),
    re.compile(r'(?:판단됩니다|생각됩니다|보입니다|예상됩니다|될\s*것\s*같습니다)', re.IGNORECASE),
    # 중국어
    re.compile(r'(?:可能|也许|大概|推测|推断|猜测|应该是|估计|通常|一般来说|或许)', re.IGNORECASE),
    re.compile(r'(?:看起来|似乎|感觉|应该|可能是|大约)', re.IGNORECASE),
]

# 추론 허용 임계값
_MAX_INFERENCE_RATIO = 0.35   # 35% 초과 시 경고
_CRITICAL_RATIO      = 0.60   # 60% 초과 시 차단


@dataclass
class InferenceMeterResult:
    evidence_count: int = 0
    inference_count: int = 0
    ratio: float = 0.0
    is_critical: bool = False

    @property
    def is_clean(self) -> bool:
        return self.ratio <= _MAX_INFERENCE_RATIO


class InferenceMeter:
    """
    Layer 4 — LLM 응답에서 추론 비율 측정.

    evidence_count / (evidence_count + inference_count) 기반.
    60% 이상 추론 → 차단.
    35-60% → 경고 (교정 주입).
    """

    def measure(self, response_text: str) -> InferenceMeterResult:
        result = InferenceMeterResult()

        for pat in _EVIDENCE_MARKERS:
            result.evidence_count += len(pat.findall(response_text))

        for pat in _INFERENCE_MARKERS:
            result.inference_count += len(pat.findall(response_text))

        total = result.evidence_count + result.inference_count
        if total > 0:
            result.ratio = result.inference_count / total
        else:
            # 증거도 추론도 없으면 중립 (비어있는 응답)
            result.ratio = 0.0

        result.is_critical = result.ratio >= _CRITICAL_RATIO
        return result

    def warn_msg(self, result: InferenceMeterResult, lang: str = "ko") -> str:
        pct = int(result.ratio * 100)
        msgs = {
            "ko": (
                f"[⚠️ 높은 추론 비율 감지 — {pct}%]\n\n"
                f"응답의 {pct}%가 추론/추측 기반입니다 (허용 최대: {int(_MAX_INFERENCE_RATIO*100)}%).\n"
                f"증거: {result.evidence_count}건 / 추론: {result.inference_count}건\n\n"
                f"■ 추론 대신 실제 HTTP 요청을 실행하세요.\n"
                f"■ 'probably', '추정', '추측' 표현을 사용하기 전에 실제로 확인하세요."
            ),
            "zh": (
                f"[⚠️ 高推断比例检测 — {pct}%]\n\n"
                f"响应中{pct}%基于推断/猜测 (最大允许: {int(_MAX_INFERENCE_RATIO*100)}%).\n"
                f"证据: {result.evidence_count}条 / 推断: {result.inference_count}条\n\n"
                f"■ 请执行真实HTTP请求而非推断。"
            ),
            "en": (
                f"[⚠️ HIGH INFERENCE RATIO — {pct}%]\n\n"
                f"{pct}% of response is inference/speculation (max allowed: {int(_MAX_INFERENCE_RATIO*100)}%).\n"
                f"Evidence: {result.evidence_count} / Inference: {result.inference_count}\n\n"
                f"■ Execute real HTTP requests instead of guessing."
            ),
        }
        return msgs.get(lang, msgs["en"])

    def block_msg(self, result: InferenceMeterResult, lang: str = "ko") -> str:
        pct = int(result.ratio * 100)
        msgs = {
            "ko": (
                f"[⛔ 과다 추론 차단 — {pct}% 추론 ({int(_CRITICAL_RATIO*100)}% 초과)]\n\n"
                f"응답의 {pct}%가 실증 없는 추론입니다. 이것은 환각 위험입니다.\n"
                f"증거: {result.evidence_count}건 / 추론: {result.inference_count}건\n\n"
                f"■ 즉시 실제 HTTP 요청을 실행하고 결과를 바탕으로 응답하세요.\n"
                f"■ 'probably', 'likely', '추정됩니다' 같은 표현은\n"
                f"  반드시 실제 증거 확인 후에만 사용하세요."
            ),
            "zh": (
                f"[⛔ 过度推断拦截 — {pct}% 推断 (超过{int(_CRITICAL_RATIO*100)}%)]\n\n"
                f"响应中{pct}%是无证据推断，存在幻觉风险。\n"
                f"证据: {result.evidence_count}条 / 推断: {result.inference_count}条\n\n"
                f"■ 立即执行真实HTTP请求，基于结果作答。"
            ),
            "en": (
                f"[⛔ EXCESSIVE INFERENCE BLOCKED — {pct}% inference (>{int(_CRITICAL_RATIO*100)}%)]\n\n"
                f"{pct}% of response is unverified inference — hallucination risk.\n"
                f"Evidence: {result.evidence_count} / Inference: {result.inference_count}\n\n"
                f"■ Execute real HTTP requests immediately and base responses on actual results."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# Layer 5: ContextPoisonGuard
# ══════════════════════════════════════════════════════════════════════════════

_DOMAIN_EXTRACT_RE = re.compile(r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})', re.IGNORECASE)

# 이전 세션 사실이 유출될 때 나타나는 패턴
_CROSS_SESSION_PATTERNS: list[re.Pattern] = [
    re.compile(r'from\s+(?:previous|last|earlier)\s+(?:session|scan|test)', re.IGNORECASE),
    re.compile(r'이전\s+(?:세션|스캔|테스트)(?:에서|의)\s+', re.IGNORECASE),
    re.compile(r'상기\s+(?:발견|취약점|스캔)', re.IGNORECASE),
    re.compile(r'上次\s*(?:会话|扫描|测试)(?:中|发现)', re.IGNORECASE),
    re.compile(r'之前\s*(?:找到|发现|确认)', re.IGNORECASE),
]


@dataclass
class ContextPoisonResult:
    poisoned: bool = False
    leaked_domains: list[str] = field(default_factory=list)
    cross_session_refs: list[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return not self.poisoned


class ContextPoisonGuard:
    """
    Layer 5 — 이전 세션의 컨텍스트가 현재 세션으로 유출되는 것 탐지.

    이전 타겟의 도메인/IP가 현재 응답에 나타나거나,
    "이전 세션에서 발견" 같은 크로스 세션 참조가 있으면 차단.
    """

    def __init__(self):
        self._previous_targets: set[str] = set()
        self._current_target: str = ""

    def set_current_target(self, target: str):
        if self._current_target and self._current_target != target:
            # 타겟 변경 → 이전 타겟을 기록
            self._previous_targets.add(self._current_target)
        self._current_target = target

    def add_previous_target(self, target: str):
        self._previous_targets.add(target)

    def _extract_domain(self, url: str) -> str:
        m = _DOMAIN_EXTRACT_RE.search(url)
        return m.group(1).lower() if m else url.lower()

    def check(self, response_text: str) -> ContextPoisonResult:
        result = ContextPoisonResult()

        # 크로스 세션 참조 패턴 탐지
        for pat in _CROSS_SESSION_PATTERNS:
            m = pat.search(response_text)
            if m:
                result.cross_session_refs.append(m.group(0)[:80])
                result.poisoned = True

        # 이전 타겟 도메인 유출 탐지
        if self._previous_targets:
            current_domain = self._extract_domain(self._current_target)
            prev_domains = {self._extract_domain(t) for t in self._previous_targets}
            found_domains = {m.group(1).lower() for m in _DOMAIN_EXTRACT_RE.finditer(response_text)}
            for d in found_domains:
                if d in prev_domains and d != current_domain:
                    # 현재 세션 도메인이 아닌 이전 타겟 도메인
                    result.leaked_domains.append(d)
                    result.poisoned = True

        return result

    def warn_msg(self, result: ContextPoisonResult, lang: str = "ko") -> str:
        leaks = ", ".join(result.leaked_domains[:3])
        refs = ", ".join(result.cross_session_refs[:2])
        msgs = {
            "ko": (
                f"[⚠️ 컨텍스트 오염 경고 — Zero Hallucination v5]\n\n"
                + (f"이전 세션 도메인 유출: {leaks}\n" if leaks else "")
                + (f"크로스 세션 참조: {refs}\n" if refs else "")
                + f"\n■ 현재 세션 타겟: {self._current_target}\n"
                f"■ 이전 세션 정보를 현재 분석에 혼용하지 마십시오.\n"
                f"■ 현재 타겟에 대한 신선한 HTTP 요청을 실행하세요."
            ),
            "zh": (
                f"[⚠️ 上下文污染警告 — Zero Hallucination v5]\n\n"
                + (f"历史会话域名泄露: {leaks}\n" if leaks else "")
                + (f"跨会话引用: {refs}\n" if refs else "")
                + f"\n■ 当前会话目标: {self._current_target}\n"
                f"■ 禁止在当前分析中混用历史会话信息。"
            ),
            "en": (
                f"[⚠️ CONTEXT POISONING — Zero Hallucination v5]\n\n"
                + (f"Previous session domain leaked: {leaks}\n" if leaks else "")
                + (f"Cross-session reference detected: {refs}\n" if refs else "")
                + f"\n■ Current session target: {self._current_target}\n"
                f"■ Do NOT mix previous session data into current analysis.\n"
                f"■ Execute fresh HTTP requests for current target."
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# ZeroHalResult — 파이프라인 결과
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ZeroHalResult:
    """5-Layer 파이프라인 통합 결과."""
    blocked: bool = False
    warned: bool = False
    block_reason: str = ""         # "UNANCHORED_CLAIM" | "NUMERIC_HAL" | "EXCESS_INFERENCE" | "CONTEXT_POISON"
    inject_message: Optional[str] = None
    facts_registered: int = 0
    inference_ratio: float = 0.0
    layer_results: dict = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return not self.blocked and not self.warned


# ══════════════════════════════════════════════════════════════════════════════
# ZeroHalEngine — 5-Layer 통합 파이프라인
# ══════════════════════════════════════════════════════════════════════════════

class ZeroHalEngine:
    """
    Zero Hallucination Engine v5.0 — 5-Layer 제로 환각 파이프라인.

    사용법 (engine.py / terminal.py):
        engine = ZeroHalEngine(session_target="https://target.com", lang="ko")
        # 실행 결과 받을 때마다:
        engine.register_exec(exec_output)
        # LLM 응답 처리 시:
        result = engine.process(response_text, exec_output)
        if result.blocked:
            inject(result.inject_message)
        elif result.warned:
            inject_soft(result.inject_message)
    """

    def __init__(self, session_target: str = "", lang: str = "ko"):
        self.lang = lang
        self.session_target = session_target

        # 5개 레이어 인스턴스
        self.registry          = FactRegistry()
        self.claim_anchor      = ClaimAnchorValidator()
        self.numeric_guard     = NumericHallucinationGuard()
        self.inference_meter   = InferenceMeter()
        self.context_poison    = ContextPoisonGuard()

        # 초기 타겟 설정
        if session_target:
            self.context_poison.set_current_target(session_target)
            # 타겟 도메인을 FactRegistry에 등록
            try:
                from urllib.parse import urlparse
                domain = urlparse(session_target).netloc or session_target
                if domain:
                    self.registry.register_manual(FACT_DOMAIN, domain, source="session_target")
            except Exception:
                pass

        # 통계
        self._total_processed: int = 0
        self._blocked_count: int = 0
        self._facts_total: int = 0

    def update_target(self, new_target: str):
        """세션 타겟 변경."""
        self.session_target = new_target
        self.context_poison.set_current_target(new_target)
        try:
            from urllib.parse import urlparse
            domain = urlparse(new_target).netloc or new_target
            if domain:
                self.registry.register_manual(FACT_DOMAIN, domain, source="session_target")
        except Exception:
            pass

    def register_exec(self, exec_output: str) -> int:
        """
        실행 결과를 FactRegistry에 등록.
        exec 블록이 끝날 때마다 호출.
        """
        count = self.registry.register_from_exec(exec_output)
        self._facts_total += count
        return count

    def process(
        self,
        response_text: str,
        exec_output: str = "",
    ) -> ZeroHalResult:
        """
        5-Layer 파이프라인 실행.

        우선순위:
          Layer 2 (ClaimAnchor) > Layer 3 (Numeric) > Layer 4 (Inference) > Layer 5 (Context) > Layer 1 (FactRegistry stats)

        exec_output가 있으면 먼저 Layer 1 등록 수행.
        """
        self._total_processed += 1

        # Layer 1: exec_output에서 사실 등록
        if exec_output:
            self.register_exec(exec_output)

        result = ZeroHalResult(facts_registered=self._facts_total)

        # Layer 2: 클레임 앵커 검증
        anchor_result = self.claim_anchor.validate(response_text, exec_output, self.registry)
        result.layer_results["claim_anchor"] = anchor_result
        if not anchor_result.is_clean:
            result.blocked = True
            result.block_reason = "UNANCHORED_CLAIM"
            result.inject_message = self.claim_anchor.block_msg(anchor_result, self.session_target, self.lang)
            self._blocked_count += 1
            return result

        # Layer 3: 숫자 환각 검증
        numeric_result = self.numeric_guard.validate(response_text, self.registry)
        result.layer_results["numeric"] = numeric_result
        if not numeric_result.is_clean:
            result.blocked = True
            result.block_reason = "NUMERIC_HAL"
            result.inject_message = self.numeric_guard.block_msg(numeric_result, self.registry, self.lang)
            self._blocked_count += 1
            return result

        # Layer 4: 추론 비율 측정
        inference_result = self.inference_meter.measure(response_text)
        result.inference_ratio = inference_result.ratio
        result.layer_results["inference"] = inference_result
        if inference_result.is_critical:
            result.blocked = True
            result.block_reason = "EXCESS_INFERENCE"
            result.inject_message = self.inference_meter.block_msg(inference_result, self.lang)
            self._blocked_count += 1
            return result
        elif not inference_result.is_clean:
            result.warned = True
            result.inject_message = self.inference_meter.warn_msg(inference_result, self.lang)

        # Layer 5: 컨텍스트 오염 탐지
        poison_result = self.context_poison.check(response_text)
        result.layer_results["context_poison"] = poison_result
        if not poison_result.is_clean:
            result.warned = True
            result.block_reason = result.block_reason or "CONTEXT_POISON"
            warn_msg = self.context_poison.warn_msg(poison_result, self.lang)
            result.inject_message = (result.inject_message or "") + "\n\n" + warn_msg if result.inject_message else warn_msg

        return result

    def get_stats(self) -> dict:
        return {
            "total_processed": self._total_processed,
            "blocked": self._blocked_count,
            "facts_registered": self._facts_total,
            "registry_summary": self.registry.summary(),
        }

    def stats_banner(self, lang: str = "") -> str:
        lang = lang or self.lang
        s = self.get_stats()
        msgs = {
            "ko": (
                f"[🛡️ Zero Hallucination v5 통계]\n"
                f"  처리: {s['total_processed']}건 | 차단: {s['blocked']}건\n"
                f"  등록된 사실: {s['facts_registered']}건\n"
                f"  {s['registry_summary']}"
            ),
            "zh": (
                f"[🛡️ 零幻觉 v5 统计]\n"
                f"  处理: {s['total_processed']} | 拦截: {s['blocked']}\n"
                f"  注册事实: {s['facts_registered']}\n"
                f"  {s['registry_summary']}"
            ),
            "en": (
                f"[🛡️ Zero Hallucination v5 Stats]\n"
                f"  Processed: {s['total_processed']} | Blocked: {s['blocked']}\n"
                f"  Facts registered: {s['facts_registered']}\n"
                f"  {s['registry_summary']}"
            ),
        }
        return msgs.get(lang, msgs["en"])


# ══════════════════════════════════════════════════════════════════════════════
# 전역 싱글턴
# ══════════════════════════════════════════════════════════════════════════════

_global_zero_hal: Optional[ZeroHalEngine] = None


def get_zero_hal(session_target: str = "", lang: str = "ko") -> ZeroHalEngine:
    """전역 ZeroHalEngine 싱글턴 반환 (없으면 생성)."""
    global _global_zero_hal
    if _global_zero_hal is None:
        _global_zero_hal = ZeroHalEngine(session_target=session_target, lang=lang)
    elif session_target and _global_zero_hal.session_target != session_target:
        _global_zero_hal.update_target(session_target)
    return _global_zero_hal


def reset_zero_hal(session_target: str = "", lang: str = "ko") -> ZeroHalEngine:
    """전역 ZeroHalEngine 초기화 후 새 인스턴스 반환."""
    global _global_zero_hal
    _global_zero_hal = ZeroHalEngine(session_target=session_target, lang=lang)
    return _global_zero_hal
