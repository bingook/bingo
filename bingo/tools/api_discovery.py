"""
API Discovery — 3-Layer 통합 엔드포인트 탐지 엔진
=============================================================================
LAYER 1 (정적): Swagger/OpenAPI/GraphQL 문서 프로빙
LAYER 2 (JS):   JS 파일에서 fetch/axios/route 패턴 추출
LAYER 3 (동적): Playwright 브라우저로 XHR/fetch 실시간 인터셉트

evidence_level: VERIFIED (200 확인) / DYNAMIC (브라우저 캡처) / INFERRED (패턴만)
Zero-Hallucination: 실제 HTTP 응답/브라우저 트래픽에서만 출력
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Optional, Callable
from urllib.parse import urljoin, urlparse

import requests

# ── Discovery document paths to probe ──────────────────────────────────────
_DISCOVERY_PATHS = [
    # OpenAPI / Swagger
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v1/openapi.json",
    "/api-docs",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs/swagger.json",
    "/docs/openapi.json",
    # Google-style discovery
    "/$discovery/rest",
    "/discovery/v1/apis",
    # GraphQL
    "/graphql",
    "/graphiql",
    "/graphql/schema",
    "/api/graphql",
    # WSDL / SOAP
    "/api?wsdl",
    "/service?wsdl",
    # RAML
    "/api/raml",
    # Generic API roots
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/api/latest",
    "/wp-json",                 # WordPress
    "/.well-known/openapi.json",
    "/actuator/mappings",       # Spring Boot
]

# ── Headers that suggest an API doc response ────────────────────────────────
_API_DOC_CONTENT_TYPES = {
    "application/json",
    "application/x-yaml",
    "text/yaml",
    "application/yaml",
}

# ── JSON keys that confirm a Swagger/OpenAPI document ───────────────────────
_SWAGGER_KEYS = {"swagger", "openapi", "info", "paths", "definitions", "components"}

_TIMEOUT = 8

# ── 파라미터 추론 — 템플릿에서 실제 테스트 값 생성 ─────────────────────────
_PARAM_TEST_VALUES: dict[str, list[str]] = {
    "id":    ["1", "2", "3", "100", "admin", "0", "-1"],
    "uuid":  ["00000000-0000-0000-0000-000000000001"],
    "hash":  ["a" * 32],
}

_INTERESTING_KW = {"admin", "user", "auth", "login", "token", "secret",
                   "password", "config", "debug", "internal", "manage",
                   "upload", "export", "import", "backup", "key", "credential"}


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str
    description: str = ""
    parameters: list[str] = field(default_factory=list)
    evidence_level: str = "INFERRED"


@dataclass
class DiscoveryDoc:
    url: str
    doc_type: str          # "openapi", "swagger", "graphql", "google", "wordpress", "generic"
    version: str = ""
    title: str = ""
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    raw_paths: list[str] = field(default_factory=list)
    evidence_level: str = "VERIFIED"


@dataclass
class ApiDiscoveryResult:
    target: str
    docs_found: list[DiscoveryDoc] = field(default_factory=list)
    total_endpoints: int = 0
    interesting_paths: list[str] = field(default_factory=list)   # admin/user/auth paths
    error: str = ""


@dataclass
class ParamTestResult:
    """파라미터 추론 후 실제 테스트한 엔드포인트 결과"""
    template: str          # /api/user/{id}
    tested_url: str        # /api/user/1
    status: int
    content_type: str = ""
    is_unauth: bool = False   # 401/403 없이 JSON 반환
    response_size: int = 0


@dataclass
class FullDiscoveryResult:
    """3-Layer 통합 탐지 최종 결과"""
    target: str
    # Layer 1: 정적 문서
    swagger_result: ApiDiscoveryResult | None = None
    # Layer 2: JS 분석
    js_endpoints: list[str] = field(default_factory=list)
    js_secrets: list[tuple] = field(default_factory=list)
    js_admin_paths: list[str] = field(default_factory=list)
    # Layer 3: 동적 캡처
    dynamic_templates: list[str] = field(default_factory=list)
    dynamic_unauth: list[str] = field(default_factory=list)       # 미인증 접근 가능 엔드포인트
    # 파라미터 추론 테스트
    param_tests: list[ParamTestResult] = field(default_factory=list)
    # 통합 요약
    all_interesting: list[str] = field(default_factory=list)      # 모든 레이어의 흥미 경로
    total_unique: int = 0
    errors: list[str] = field(default_factory=list)


class ApiDiscoveryScanner:
    """Probes a target URL for API discovery documents and extracts endpoint lists."""

    def __init__(self, target: str, session: Optional[requests.Session] = None):
        self.target = target.rstrip("/")
        self.base = self._base_url(target)
        self.sess = session or requests.Session()
        self.sess.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "application/json,text/html,*/*",
        })
        self.sess.verify = False

    # ── Public API ──────────────────────────────────────────────────────────

    def scan(self) -> ApiDiscoveryResult:
        result = ApiDiscoveryResult(target=self.target)
        for path in _DISCOVERY_PATHS:
            url = urljoin(self.base, path)
            doc = self._probe(url)
            if doc:
                result.docs_found.append(doc)
                result.total_endpoints += len(doc.endpoints)
        result.interesting_paths = self._collect_interesting(result)
        return result

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _base_url(target: str) -> str:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _probe(self, url: str) -> Optional[DiscoveryDoc]:
        try:
            r = self.sess.get(url, timeout=_TIMEOUT, allow_redirects=False)
        except Exception:
            return None

        if r.status_code not in (200, 206):
            return None

        ct = r.headers.get("Content-Type", "").lower()

        # Try JSON parse
        try:
            data = r.json()
            return self._parse_json_doc(url, data)
        except Exception:
            pass

        # GraphQL introspection endpoint check
        if "graphql" in url.lower() and r.status_code == 200:
            return DiscoveryDoc(
                url=url,
                doc_type="graphql",
                title="GraphQL Endpoint",
                evidence_level="VERIFIED",
            )

        # WordPress REST API
        if "wp-json" in url and r.status_code == 200:
            return self._parse_wordpress(url, r.text)

        # Generic JSON API root
        if any(t in ct for t in _API_DOC_CONTENT_TYPES) or ct.startswith("application/json"):
            try:
                data = r.json()
                if isinstance(data, dict) and any(k in data for k in _SWAGGER_KEYS):
                    return self._parse_json_doc(url, data)
            except Exception:
                pass

        return None

    def _parse_json_doc(self, url: str, data: dict) -> Optional[DiscoveryDoc]:
        if not isinstance(data, dict):
            return None

        # Determine type and version
        if "openapi" in data:
            doc_type = "openapi"
            version = data.get("openapi", "")
        elif "swagger" in data:
            doc_type = "swagger"
            version = data.get("swagger", "")
        elif "kind" in data and data.get("kind") == "discovery#restDescription":
            doc_type = "google"
            version = data.get("version", "")
        else:
            doc_type = "generic"
            version = ""

        title = ""
        if "info" in data and isinstance(data["info"], dict):
            title = data["info"].get("title", "")

        endpoints: list[DiscoveredEndpoint] = []
        raw_paths: list[str] = []

        # OpenAPI / Swagger paths
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            for path, methods in paths.items():
                raw_paths.append(path)
                if isinstance(methods, dict):
                    for method, detail in methods.items():
                        if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
                            continue
                        desc = ""
                        params: list[str] = []
                        if isinstance(detail, dict):
                            desc = detail.get("summary", detail.get("description", ""))
                            for p in detail.get("parameters", []):
                                if isinstance(p, dict):
                                    params.append(p.get("name", ""))
                        endpoints.append(DiscoveredEndpoint(
                            path=path,
                            method=method.upper(),
                            description=desc[:120],
                            parameters=params,
                            evidence_level="VERIFIED",
                        ))

        # Google Discovery Document resources
        resources = data.get("resources", {})
        if isinstance(resources, dict):
            for rname, rdata in resources.items():
                if isinstance(rdata, dict):
                    for mname, mdata in rdata.get("methods", {}).items():
                        if isinstance(mdata, dict):
                            path = mdata.get("flatPath", mdata.get("path", ""))
                            raw_paths.append(path)
                            endpoints.append(DiscoveredEndpoint(
                                path=path,
                                method=mdata.get("httpMethod", "GET"),
                                description=mdata.get("description", "")[:120],
                                evidence_level="VERIFIED",
                            ))

        return DiscoveryDoc(
            url=url,
            doc_type=doc_type,
            version=version,
            title=title,
            endpoints=endpoints,
            raw_paths=raw_paths,
            evidence_level="VERIFIED",
        )

    def _parse_wordpress(self, url: str, text: str) -> Optional[DiscoveryDoc]:
        endpoints: list[DiscoveredEndpoint] = []
        try:
            data = json.loads(text)
            routes = data.get("routes", {})
            for path, info in routes.items():
                methods = info.get("methods", ["GET"])
                endpoints.append(DiscoveredEndpoint(
                    path=path,
                    method=",".join(methods),
                    evidence_level="VERIFIED",
                ))
        except Exception:
            pass
        return DiscoveryDoc(
            url=url,
            doc_type="wordpress",
            title="WordPress REST API",
            endpoints=endpoints,
            evidence_level="VERIFIED",
        )

    @staticmethod
    def _collect_interesting(result: ApiDiscoveryResult) -> list[str]:
        found: list[str] = []
        for doc in result.docs_found:
            for ep in doc.endpoints:
                low = ep.path.lower()
                if any(k in low for k in _INTERESTING_KW):
                    found.append(f"{ep.method} {ep.path}")
        return list(dict.fromkeys(found))  # deduplicate, preserve order


# ═══════════════════════════════════════════════════════════════════════
# 파라미터 추론 테스터
# ═══════════════════════════════════════════════════════════════════════

class ParamInferenceTester:
    """
    템플릿 엔드포인트 ({id}, {uuid}, {hash})를 발견하면
    실제 값으로 치환해 HTTP 테스트 수행
    """

    _TEMPLATE_RE = re.compile(r"\{(id|uuid|hash)\}")

    def __init__(self, base_url: str, session: Optional[requests.Session] = None):
        self.base = base_url.rstrip("/")
        self.sess = session or requests.Session()
        self.sess.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "application/json,*/*",
        })
        self.sess.verify = False

    def test_templates(self, templates: list[str], max_per_template: int = 3) -> list[ParamTestResult]:
        results: list[ParamTestResult] = []
        for tmpl in templates:
            if not self._TEMPLATE_RE.search(tmpl):
                continue
            for placeholder, values in _PARAM_TEST_VALUES.items():
                if f"{{{placeholder}}}" not in tmpl:
                    continue
                for val in values[:max_per_template]:
                    tested = tmpl.replace(f"{{{placeholder}}}", val)
                    url = self.base + tested
                    try:
                        r = self.sess.get(url, timeout=_TIMEOUT, allow_redirects=True)
                        ct = r.headers.get("Content-Type", "")
                        is_unauth = r.status_code == 200 and "json" in ct
                        results.append(ParamTestResult(
                            template=tmpl,
                            tested_url=tested,
                            status=r.status_code,
                            content_type=ct[:80],
                            is_unauth=is_unauth,
                            response_size=len(r.content),
                        ))
                        break  # 첫 번째 성공한 값으로 충분
                    except Exception:
                        pass
        return results


# ═══════════════════════════════════════════════════════════════════════
# 3-Layer 통합 풀 스캔
# ═══════════════════════════════════════════════════════════════════════

def run_full_discovery(
    target: str,
    session: Optional[requests.Session] = None,
    get_fn: Optional[Callable] = None,
    cookies: dict | None = None,
    extra_headers: dict | None = None,
    run_dynamic: bool = True,
    dynamic_timeout: int = 30,
    lang: str = "ko",
) -> tuple[FullDiscoveryResult, str]:
    """
    3-Layer API 탐지 통합 실행.

    Args:
        target:          스캔 대상 URL
        session:         재사용할 requests.Session (없으면 신규 생성)
        get_fn:          JS 분석용 커스텀 HTTP GET 함수: (url) -> (status_code, text)
        cookies:         Playwright 세션 쿠키
        extra_headers:   Playwright 추가 헤더
        run_dynamic:     Playwright 동적 캡처 실행 여부
        dynamic_timeout: 동적 캡처 타임아웃(초)
        lang:            출력 언어 (ko/zh/en)

    Returns:
        (FullDiscoveryResult, formatted_report_string)
    """
    result = FullDiscoveryResult(target=target)
    sess = session or requests.Session()
    sess.verify = False
    sess.headers.update({"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"})

    # ── LAYER 1: 정적 문서 프로빙 ──────────────────────────────────
    try:
        scanner = ApiDiscoveryScanner(target, session=sess)
        swagger = scanner.scan()
        result.swagger_result = swagger
    except Exception as exc:
        result.errors.append(f"[LAYER1] {exc}")

    # ── LAYER 2: JS 정적 분석 ──────────────────────────────────────
    try:
        from .js_analyzer import JsAutoAnalyzer  # type: ignore

        if get_fn is None:
            def _default_get(url: str):
                try:
                    r = sess.get(url, timeout=_TIMEOUT, allow_redirects=True)
                    return r.status_code, r.text
                except Exception:
                    return 0, ""
            _get = _default_get
        else:
            _get = get_fn

        # 메인 페이지 HTML 가져오기
        main_status, main_html = _get(target)
        if main_status == 200 and main_html:
            parsed = urlparse(target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            analyzer = JsAutoAnalyzer(get_fn=_get, base_url=base_url)
            js_report = analyzer.run(html=main_html)
            result.js_endpoints = js_report.all_endpoints
            result.js_secrets = [(t, k, v) for t, k, v in js_report.all_secrets]
            result.js_admin_paths = js_report.all_admin_paths
    except Exception as exc:
        result.errors.append(f"[LAYER2] {exc}")

    # ── LAYER 3: Playwright 동적 캡처 ─────────────────────────────
    if run_dynamic:
        try:
            from .api_dynamic_capture import capture_dynamic_apis  # type: ignore
            dyn_result, _ = capture_dynamic_apis(
                target=target,
                cookies=cookies,
                headers=extra_headers,
                timeout_sec=dynamic_timeout,
                lang=lang,
            )
            result.dynamic_templates = dyn_result.unique_templates
            result.dynamic_unauth = [
                f"{cr.method} {cr.template} [{cr.status}]"
                for cr in dyn_result.interesting
                if cr.is_unauth
            ]
            if not dyn_result.playwright_available:
                result.errors.append(f"[LAYER3] {dyn_result.error}")
        except Exception as exc:
            result.errors.append(f"[LAYER3] {exc}")

    # ── 파라미터 추론 테스트 ───────────────────────────────────────
    try:
        templates_to_test: list[str] = []
        # Swagger에서 경로 수집
        if result.swagger_result:
            for doc in result.swagger_result.docs_found:
                templates_to_test.extend(doc.raw_paths)
        # 동적 캡처에서 수집
        templates_to_test.extend(result.dynamic_templates)
        # 중복 제거
        templates_to_test = list(dict.fromkeys(templates_to_test))

        if templates_to_test:
            tester = ParamInferenceTester(target, session=sess)
            result.param_tests = tester.test_templates(templates_to_test, max_per_template=2)
    except Exception as exc:
        result.errors.append(f"[PARAM_TEST] {exc}")

    # ── 통합 흥미 경로 집계 ────────────────────────────────────────
    interesting_set: set[str] = set()

    if result.swagger_result:
        for p in result.swagger_result.interesting_paths:
            interesting_set.add(f"[SWAGGER] {p}")

    for ep in result.js_endpoints:
        if any(k in ep.lower() for k in _INTERESTING_KW):
            interesting_set.add(f"[JS] GET {ep}")

    for adm in result.js_admin_paths:
        interesting_set.add(f"[JS_ADMIN] {adm}")

    for u in result.dynamic_unauth:
        interesting_set.add(f"[DYN_UNAUTH] {u}")

    for pt in result.param_tests:
        if pt.is_unauth:
            interesting_set.add(f"[PARAM_UNAUTH] {pt.tested_url} [{pt.status}]")

    result.all_interesting = sorted(interesting_set)

    # 전체 고유 엔드포인트 수
    all_ep_set: set[str] = set()
    if result.swagger_result:
        for doc in result.swagger_result.docs_found:
            for ep in doc.endpoints:
                all_ep_set.add(f"{ep.method}:{ep.path}")
    for ep in result.js_endpoints:
        all_ep_set.add(f"GET:{ep}")
    for tmpl in result.dynamic_templates:
        all_ep_set.add(f"DYN:{tmpl}")
    result.total_unique = len(all_ep_set)

    # ── 보고서 포맷 ────────────────────────────────────────────────
    report = _format_full_result(result, lang=lang)
    return result, report


def _format_full_result(result: FullDiscoveryResult, lang: str = "ko") -> str:
    _labels = {
        "ko": {
            "title":   "API 탐지 통합 보고서",
            "target":  "타겟",
            "l1":      "LAYER1 (Swagger/OpenAPI)",
            "l2":      "LAYER2 (JS 정적 분석)",
            "l3":      "LAYER3 (동적 브라우저 캡처)",
            "param":   "파라미터 추론 테스트",
            "interesting": "★ 고가치 엔드포인트",
            "total":   "총 고유 엔드포인트",
            "secrets": "하드코딩 시크릿",
            "admin":   "관리자 경로",
            "unauth":  "미인증 접근 가능",
            "errors":  "오류",
        },
        "zh": {
            "title":   "API探测综合报告",
            "target":  "目标",
            "l1":      "LAYER1 (Swagger/OpenAPI)",
            "l2":      "LAYER2 (JS静态分析)",
            "l3":      "LAYER3 (动态浏览器捕获)",
            "param":   "参数推断测试",
            "interesting": "★ 高价值端点",
            "total":   "总唯一端点数",
            "secrets": "硬编码密钥",
            "admin":   "管理员路径",
            "unauth":  "未授权可访问",
            "errors":  "错误",
        },
        "en": {
            "title":   "API Discovery Full Report",
            "target":  "Target",
            "l1":      "LAYER1 (Swagger/OpenAPI)",
            "l2":      "LAYER2 (JS Static Analysis)",
            "l3":      "LAYER3 (Dynamic Browser Capture)",
            "param":   "Parameter Inference Tests",
            "interesting": "★ High-Value Endpoints",
            "total":   "Total Unique Endpoints",
            "secrets": "Hardcoded Secrets",
            "admin":   "Admin Paths",
            "unauth":  "Unauthenticated Access",
            "errors":  "Errors",
        },
    }
    lb = _labels.get(lang, _labels["en"])
    lines: list[str] = [
        f"╔══ {lb['title']} {'═' * 30}",
        f"║ {lb['target']}: {result.target}",
        f"║ {lb['total']}: {result.total_unique}",
        "╠" + "═" * 50,
    ]

    # LAYER 1
    if result.swagger_result and result.swagger_result.docs_found:
        lines.append(f"║ [{lb['l1']}]")
        for doc in result.swagger_result.docs_found:
            lines.append(f"║   {doc.doc_type.upper()} — {doc.url}  ({len(doc.endpoints)} endpoints)")
    else:
        lines.append(f"║ [{lb['l1']}] — not found")

    # LAYER 2
    js_count = len(result.js_endpoints)
    sec_count = len(result.js_secrets)
    adm_count = len(result.js_admin_paths)
    lines.append(f"║ [{lb['l2']}] endpoints={js_count}  secrets={sec_count}  admin={adm_count}")
    for adm in result.js_admin_paths[:10]:
        lines.append(f"║   [{lb['admin']}] {adm}")
    for st, k, v in result.js_secrets[:5]:
        lines.append(f"║   [{lb['secrets']}:{st}] {k}={v[:40]}")

    # LAYER 3
    dyn_count = len(result.dynamic_templates)
    unauth_count = len(result.dynamic_unauth)
    lines.append(f"║ [{lb['l3']}] templates={dyn_count}  unauth={unauth_count}")
    for u in result.dynamic_unauth[:10]:
        lines.append(f"║   [{lb['unauth']}] {u}")

    # 파라미터 추론 결과
    if result.param_tests:
        lines.append(f"║ [{lb['param']}]")
        for pt in result.param_tests[:15]:
            flag = f" ← {lb['unauth'].upper()}" if pt.is_unauth else ""
            lines.append(f"║   {pt.tested_url}  [{pt.status}]  {pt.response_size}B{flag}")

    # 고가치 통합 목록
    if result.all_interesting:
        lines.append(f"║ {lb['interesting']}")
        for p in result.all_interesting[:30]:
            lines.append(f"║   {p}")

    if result.errors:
        lines.append(f"║ [{lb['errors']}]")
        for e in result.errors:
            lines.append(f"║   {e}")

    lines.append("╚" + "═" * 50)
    return "\n".join(lines)
