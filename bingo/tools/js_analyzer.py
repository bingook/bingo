"""
JS Auto-Analyzer — JS 파일에서 API 엔드포인트·시크릿·숨겨진 경로 자동 추출
=============================================================================
1. 사이트 크롤 → JS 파일 URL 수집
2. 각 JS 파일 다운로드 → 분석
3. 추출 항목:
   - API 엔드포인트 (/api/v1/..., /admin/..., fetch('...'))
   - 하드코딩 자격증명 (API 키, 비밀번호, 토큰)
   - 숨겨진 관리자 경로
   - GraphQL 쿼리/뮤테이션
   - WebSocket 엔드포인트 (ws://, wss://)
   - 환경변수 노출 (process.env.xxx, REACT_APP_xxx)
"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlparse


# ══════════════════════════════════════════════════════════════
# 탐지 패턴
# ══════════════════════════════════════════════════════════════

# API 엔드포인트 패턴
ENDPOINT_PATTERNS = [
    # fetch / axios / XMLHttpRequest
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"]((?:/[^`'"#?\s]{2,})[^`'"]*)[`'"]""",
    r"""url\s*[=:]\s*[`'"]((?:/api|/v\d|/admin|/manage)[^`'"#?\s]{1,100})[`'"]""",
    r"""(?:baseURL|apiUrl|API_URL|apiBase)\s*[=:]\s*[`'"](https?://[^`'"#?\s]+)[`'"]""",
    # route 정의
    r"""(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*[`'"](/[^`'"#?\s]{1,100})[`'"]""",
    # 일반 경로 문자열 (최소 2세그먼트)
    r"""[`'"]((?:/[a-z0-9_\-]{1,30}){2,5}(?:\.(?:php|asp|aspx|jsp|do|action))?)[`'"]""",
]

# 시크릿/자격증명 패턴
SECRET_PATTERNS = [
    (r"""(?:api[_-]?key|apikey)\s*[=:]\s*[`'"]([A-Za-z0-9\-_]{16,})[`'"]""", "API_KEY"),
    (r"""(?:secret|secretKey|client_secret)\s*[=:]\s*[`'"]([A-Za-z0-9\-_+/=]{16,})[`'"]""", "SECRET"),
    (r"""(?:password|passwd|pwd)\s*[=:]\s*[`'"]([^`'"]{4,})[`'"]""", "PASSWORD"),
    (r"""(?:token|access_token|auth_token)\s*[=:]\s*[`'"]([A-Za-z0-9\-_.]{16,})[`'"]""", "TOKEN"),
    (r"""(?:bearer)\s+([A-Za-z0-9\-_.]{20,})""", "BEARER"),
    (r"""AKIA[0-9A-Z]{16}""", "AWS_ACCESS_KEY"),
    (r"""(?:aws_secret|AWS_SECRET)\s*[=:]\s*[`'"]([A-Za-z0-9/+]{40})[`'"]""", "AWS_SECRET"),
    (r"""process\.env\.([A-Z_]{4,})\s*[=:]\s*[`'"]([^`'"]{4,})[`'"]""", "ENV_VAR"),
    (r"""REACT_APP_([A-Z_]+)\s*=\s*(.{4,100})""", "REACT_ENV"),
    # 한국 사이트 특화
    (r"""(?:db_?pass|db_?pwd|dbpassword)\s*[=:]\s*[`'"]([^`'"]{4,})[`'"]""", "DB_PASSWORD"),
    (r"""(?:admin_?pass|adminpwd)\s*[=:]\s*[`'"]([^`'"]{4,})[`'"]""", "ADMIN_PASSWORD"),
]

# 숨겨진 관리자 경로 패턴
ADMIN_PATH_PATTERNS = [
    r"""[`'"](/(?:admin|manage|manager|dashboard|console|panel|backend|cms|mng|adm)[^`'"#?\s]{0,80})[`'"]""",
    r"""[`'"](/(?:setup|install|config|configuration|phpinfo|debug|test)[^`'"#?\s]{0,80})[`'"]""",
    r"""[`'"](/(?:api/admin|api/v\d/admin|api/management)[^`'"#?\s]{0,80})[`'"]""",
    # 한국 사이트 특화 관리 경로
    r"""[`'"](/(?:adm|manage|boadmin|gnuboard|xe|rhymix|zbxe)[^`'"#?\s]{0,80})[`'"]""",
]

# GraphQL 패턴
GRAPHQL_PATTERNS = [
    r"""(?:query|mutation|subscription)\s+(\w+)\s*\{""",
    r"""gql`([^`]{10,})`""",
    r"""graphql\s*\(\s*`([^`]{10,})`""",
]

# WebSocket 패턴
WS_PATTERNS = [
    r"""(?:new WebSocket|new SockJS)\s*\(\s*[`'"]((?:wss?|ws)://[^`'"]+)[`'"]""",
    r"""[`'"]((?:wss?://)[^`'"#?\s]+)[`'"]""",
]


@dataclass
class JsAnalysisResult:
    js_url: str
    endpoints: list[str] = field(default_factory=list)
    secrets: list[tuple[str, str, str]] = field(default_factory=list)  # (type, key, value)
    admin_paths: list[str] = field(default_factory=list)
    graphql_ops: list[str] = field(default_factory=list)
    ws_endpoints: list[str] = field(default_factory=list)
    file_size: int = 0


@dataclass
class SiteJsReport:
    target: str
    js_files_found: int
    js_files_analyzed: int
    all_endpoints: list[str] = field(default_factory=list)
    all_secrets: list[tuple[str, str, str]] = field(default_factory=list)
    all_admin_paths: list[str] = field(default_factory=list)
    all_ws: list[str] = field(default_factory=list)
    high_value: list[str] = field(default_factory=list)  # 즉시 테스트 대상


# ══════════════════════════════════════════════════════════════
# JS 파일 URL 수집
# ══════════════════════════════════════════════════════════════

JS_URL_PATTERN = re.compile(
    r"""<script[^>]+src\s*=\s*['"]((?:[^'"]*\.js(?:\?[^'"]*)?|[^'"]*chunk[^'"]*|[^'"]*bundle[^'"]*))[^'"]*['"]""",
    re.I,
)

COMMON_JS_PATHS = [
    "/static/js/main.chunk.js",
    "/static/js/bundle.js",
    "/static/js/0.chunk.js",
    "/js/app.js",
    "/js/main.js",
    "/js/bundle.js",
    "/assets/js/app.js",
    "/dist/app.js",
    "/dist/bundle.js",
    "/build/static/js/main.chunk.js",
    "/webpack-stats.json",
    "/asset-manifest.json",  # React 앱 manifest → JS 파일 목록
]


def collect_js_urls(html: str, base_url: str, extra_check_fn: Callable[[str], int] | None = None) -> list[str]:
    """HTML에서 JS 파일 URL 수집 + 일반 경로 자동 탐지"""
    found: list[str] = []
    seen: set[str] = set()

    # HTML에서 script src 추출
    for m in JS_URL_PATTERN.finditer(html):
        src = m.group(1)
        full = urljoin(base_url, src)
        if full not in seen:
            seen.add(full)
            found.append(full)

    # asset-manifest.json 파싱 (React 앱)
    if "asset-manifest.json" in html or "/static/js/" in html:
        manifest_url = urljoin(base_url, "/asset-manifest.json")
        found.insert(0, manifest_url)

    return found


# ══════════════════════════════════════════════════════════════
# JS 파일 분석 엔진
# ══════════════════════════════════════════════════════════════

def analyze_js_content(js_content: str, js_url: str, base_url: str = "") -> JsAnalysisResult:
    """JS 파일 내용 분석 → 엔드포인트, 시크릿, 관리자 경로 추출"""
    result = JsAnalysisResult(js_url=js_url, file_size=len(js_content))

    seen_ep: set[str] = set()
    seen_adm: set[str] = set()

    # ── API 엔드포인트 추출 ──────────────────────────────────
    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, js_content, re.I):
            ep = m.group(1).strip()
            if len(ep) > 3 and ep not in seen_ep:
                # 노이즈 필터
                if not re.match(r'^(?:https?://|//)', ep):
                    ep_full = urljoin(base_url, ep) if base_url else ep
                else:
                    ep_full = ep
                if ep_full not in seen_ep:
                    seen_ep.add(ep_full)
                    result.endpoints.append(ep_full)

    # ── 시크릿 추출 ──────────────────────────────────────────
    for pat, secret_type in SECRET_PATTERNS:
        for m in re.finditer(pat, js_content, re.I):
            groups = m.groups()
            if len(groups) >= 2:
                key, val = groups[0], groups[1]
            elif len(groups) == 1:
                key, val = secret_type, groups[0]
            else:
                key, val = secret_type, m.group(0)

            # 명백한 오탐 필터
            if val in ("undefined", "null", "true", "false", "", "YOUR_KEY"):
                continue
            if re.match(r'^x+$', val, re.I):  # xxxx placeholder
                continue
            result.secrets.append((secret_type, str(key)[:50], str(val)[:100]))

    # ── 관리자 경로 추출 ─────────────────────────────────────
    for pat in ADMIN_PATH_PATTERNS:
        for m in re.finditer(pat, js_content, re.I):
            adm = m.group(1)
            if adm not in seen_adm:
                seen_adm.add(adm)
                result.admin_paths.append(adm)

    # ── GraphQL 추출 ─────────────────────────────────────────
    for pat in GRAPHQL_PATTERNS:
        for m in re.finditer(pat, js_content, re.I | re.S):
            op = m.group(1).strip()[:100]
            if op not in result.graphql_ops:
                result.graphql_ops.append(op)

    # ── WebSocket 추출 ───────────────────────────────────────
    for pat in WS_PATTERNS:
        for m in re.finditer(pat, js_content, re.I):
            ws = m.group(1)
            if ws not in result.ws_endpoints:
                result.ws_endpoints.append(ws)

    return result


# ══════════════════════════════════════════════════════════════
# 전체 사이트 JS 스캔 컨트롤러
# ══════════════════════════════════════════════════════════════

class JsAutoAnalyzer:
    """
    사이트 전체 JS 파일 자동 분석 컨트롤러.
    AI 코드 블록에서 직접 호출 가능.
    """

    def __init__(
        self,
        get_fn: Callable[[str], tuple[int, str]],  # url → (status, body)
        base_url: str,
        log_fn: Callable[[str], None] | None = None,
        max_js_files: int = 20,
        max_js_size: int = 2_000_000,  # 2MB
    ):
        self._get = get_fn
        self.base_url = base_url.rstrip("/")
        self.log = log_fn or (lambda s: None)
        self.max_js_files = max_js_files
        self.max_js_size = max_js_size

    def run(self, html: str = "") -> SiteJsReport:
        """
        전체 사이트 JS 분석 실행.
        html: 메인 페이지 HTML (없으면 자동 fetch)
        """
        if not html:
            status, html = self._get(self.base_url)
            self.log(f"[JS] 메인 페이지: {status}")

        # asset-manifest.json 먼저 시도 (React 앱)
        js_urls = self._collect_from_manifest()

        # HTML에서 script src 추출
        js_urls += collect_js_urls(html, self.base_url)

        # 중복 제거
        seen: set[str] = set()
        unique_js: list[str] = []
        for u in js_urls:
            if u not in seen:
                seen.add(u)
                unique_js.append(u)

        self.log(f"[JS] JS 파일 발견: {len(unique_js)}개")

        report = SiteJsReport(
            target=self.base_url,
            js_files_found=len(unique_js),
            js_files_analyzed=0,
        )

        # 각 JS 파일 분석
        ep_seen: set[str] = set()
        adm_seen: set[str] = set()

        for js_url in unique_js[:self.max_js_files]:
            status, content = self._get(js_url)
            if status != 200 or not content:
                continue
            if len(content) > self.max_js_size:
                self.log(f"[JS] 크기 초과 건너뜀: {js_url} ({len(content)//1024}KB)")
                content = content[:self.max_js_size]

            self.log(f"[JS] 분석: {js_url} ({len(content)//1024}KB)")
            r = analyze_js_content(content, js_url, self.base_url)
            report.js_files_analyzed += 1

            for ep in r.endpoints:
                if ep not in ep_seen:
                    ep_seen.add(ep)
                    report.all_endpoints.append(ep)

            report.all_secrets.extend(r.secrets)

            for adm in r.admin_paths:
                if adm not in adm_seen:
                    adm_seen.add(adm)
                    report.all_admin_paths.append(adm)

            report.all_ws.extend(r.ws_endpoints)

        # 즉시 테스트 대상 선별
        report.high_value = self._pick_high_value(report)

        self.log(
            f"[JS✓] 완료: 엔드포인트 {len(report.all_endpoints)}개 | "
            f"시크릿 {len(report.all_secrets)}개 | "
            f"관리자 경로 {len(report.all_admin_paths)}개"
        )
        return report

    def _collect_from_manifest(self) -> list[str]:
        """asset-manifest.json / webpack-stats.json에서 JS URL 추출"""
        urls: list[str] = []
        for path in ["/asset-manifest.json", "/webpack-stats.json", "/staticfiles/js/"]:
            status, body = self._get(self.base_url + path)
            if status == 200 and body.strip().startswith("{"):
                try:
                    data = json.loads(body)
                    for v in self._flatten_json(data):
                        if isinstance(v, str) and v.endswith(".js"):
                            urls.append(urljoin(self.base_url, v))
                except Exception:
                    pass
        return urls

    @staticmethod
    def _flatten_json(obj, depth: int = 0) -> list:
        if depth > 5:
            return []
        if isinstance(obj, dict):
            result = []
            for v in obj.values():
                result.extend(JsAutoAnalyzer._flatten_json(v, depth + 1))
            return result
        if isinstance(obj, list):
            result = []
            for v in obj:
                result.extend(JsAutoAnalyzer._flatten_json(v, depth + 1))
            return result
        return [obj]

    @staticmethod
    def _pick_high_value(report: SiteJsReport) -> list[str]:
        """즉시 테스트할 고가치 항목 선별"""
        hv: list[str] = []
        for ep in report.all_endpoints:
            if re.search(r'/admin|/manage|/api/.*user|/api/.*member|/internal', ep, re.I):
                hv.append(f"[ENDPOINT] {ep}")
        for sec_type, key, val in report.all_secrets:
            hv.append(f"[SECRET:{sec_type}] {key}={val[:30]}...")
        for adm in report.all_admin_paths:
            hv.append(f"[ADMIN_PATH] {adm}")
        return hv[:30]


JS_ANALYZER_SUMMARY = """
=== JS AUTO-ANALYZER (AI AUTO-SELECT) ===

Trigger: run at START of every assessment (after initial recon)
Steps:
  [1] Fetch main page HTML
  [2] Collect JS file URLs (script src + asset-manifest.json)
  [3] For each JS file: extract endpoints, secrets, admin paths, GraphQL, WebSocket
  [4] Prioritize: admin paths → secrets → API endpoints → GraphQL

from bingo.tools.js_analyzer import JsAutoAnalyzer
analyzer = JsAutoAnalyzer(get_fn=lambda u: (r.status_code, r.text), base_url=TARGET)
report = analyzer.run(html=main_page_html)
# report.all_secrets  → hardcoded keys/passwords
# report.all_admin_paths → /admin/... hidden paths
# report.high_value   → immediate test targets (sorted by priority)
"""
