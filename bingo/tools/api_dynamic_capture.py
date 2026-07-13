"""
API Dynamic Capture — Playwright 기반 실시간 API 트래픽 인터셉트
=============================================================================
목적: 정적 JS 분석으로 찾지 못하는 동적 API 엔드포인트를 브라우저 자동화로 캡처
동작:
  1. Playwright Chromium으로 타겟 사이트 접속
  2. XHR / fetch / WebSocket 요청 실시간 인터셉트
  3. 링크 클릭 · 폼 제출 · 탭 전환으로 API 트리거 확대
  4. 발견된 엔드포인트 파라미터 패턴 자동 추론
  5. 인증 없이 접근 가능한 엔드포인트 즉시 표시 (UNAUTH 플래그)
Playwright 미설치 시 graceful fallback — 에러 없이 빈 결과 반환
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs

_PLAYWRIGHT_OK = False
try:
    from playwright.sync_api import sync_playwright, Page, Request, Route
    _PLAYWRIGHT_OK = True
except ImportError:
    pass


# ── 파라미터 패턴 정규화 ─────────────────────────────────────────────
_PARAM_RE = re.compile(r"/\d{1,12}(?=/|$)")          # /123/ → /{id}/
_UUID_RE  = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", re.I)
_HASH_RE  = re.compile(r"/[0-9a-f]{24,64}(?=/|$)", re.I)

# 캡처 제외 URL 패턴
_SKIP_HOSTS = {"fonts.googleapis.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
               "analytics.google.com", "www.google-analytics.com",
               "connect.facebook.net", "pagead2.googlesyndication.com"}
_SKIP_EXT   = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
               ".woff2", ".ttf", ".eot", ".css", ".map"}

# 클릭 탐색 CSS 셀렉터 (API를 트리거할 가능성이 높은 UI 요소)
_CLICK_SELECTORS = [
    "a[href]:not([href='#']):not([href^='javascript'])",
    "button[type='button'], button:not([type])",
    "[role='tab']",
    "[data-toggle]",
    ".nav-item a, .menu-item a",
    "[onclick]",
]

# 폼 자동 제출 (로그인 제외, 검색·필터 폼만)
_FORM_SKIP_KEYWORDS = {"login", "signin", "logout", "register", "signup", "password"}


@dataclass
class CapturedRequest:
    method: str
    url: str
    path: str                           # URL path 부분만
    template: str                       # 파라미터 추론 후 템플릿 (예: /api/user/{id})
    query_params: dict[str, list[str]]  # ?foo=bar → {"foo": ["bar"]}
    post_body: str                      # POST body (최대 2KB)
    status: int = 0
    content_type: str = ""
    is_api: bool = False
    is_unauth: bool = False             # 401/403 없이 데이터 반환 시 True
    resource_type: str = ""             # xhr / fetch / websocket
    evidence_level: str = "DYNAMIC"


@dataclass
class DynamicCaptureResult:
    target: str
    captured: list[CapturedRequest] = field(default_factory=list)
    unique_templates: list[str] = field(default_factory=list)   # 중복 제거 + 파라미터 템플릿
    interesting: list[CapturedRequest] = field(default_factory=list)  # admin/auth/secret 경로
    playwright_available: bool = True
    error: str = ""
    elapsed_sec: float = 0.0


# ── 헬퍼 ────────────────────────────────────────────────────────────

def _normalize_template(path: str) -> str:
    """숫자 ID / UUID / 해시를 {id} 플레이스홀더로 대체"""
    t = _UUID_RE.sub("/{uuid}", path)
    t = _HASH_RE.sub("/{hash}", t)
    t = _PARAM_RE.sub("/{id}", t)
    return t


def _is_api_url(url: str) -> bool:
    parsed = urlparse(url)
    p = parsed.path.lower()
    return (
        any(seg in p for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/",
                                  "/graphql", "/rpc", "/service", "/action"))
        or parsed.path.endswith((".json", ".xml"))
        or "application/json" in url  # fallback
    )


def _is_interesting(path: str) -> bool:
    kw = {"admin", "user", "auth", "login", "token", "secret", "password",
          "config", "debug", "internal", "manage", "upload", "download",
          "export", "import", "backup", "key", "credential"}
    low = path.lower()
    return any(k in low for k in kw)


def _should_skip(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname in _SKIP_HOSTS:
        return True
    ext = "." + parsed.path.rsplit(".", 1)[-1].lower() if "." in parsed.path else ""
    return ext in _SKIP_EXT


# ── 메인 캡처 엔진 ───────────────────────────────────────────────────

class ApiDynamicCapture:
    """
    Playwright 기반 동적 API 트래픽 캡처

    Usage:
        result = ApiDynamicCapture(target).run(timeout_sec=30, max_clicks=20)
    """

    def __init__(self, target: str, cookies: dict | None = None, headers: dict | None = None):
        self.target = target.rstrip("/")
        parsed = urlparse(target)
        self.base_host = parsed.hostname or ""
        self.cookies = cookies or {}
        self.extra_headers = headers or {}

    def run(self, timeout_sec: int = 30, max_clicks: int = 20) -> DynamicCaptureResult:
        if not _PLAYWRIGHT_OK:
            return DynamicCaptureResult(
                target=self.target,
                playwright_available=False,
                error="playwright not installed — run: pip install playwright && playwright install chromium",
            )

        result = DynamicCaptureResult(target=self.target)
        captured_map: dict[str, CapturedRequest] = {}
        t0 = time.time()

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-web-security",
                    ],
                )
                ctx = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                               "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                    ignore_https_errors=True,
                    extra_http_headers=self.extra_headers,
                )
                if self.cookies:
                    ctx.add_cookies([
                        {"name": k, "value": v, "domain": self.base_host, "path": "/"}
                        for k, v in self.cookies.items()
                    ])

                page = ctx.new_page()

                # 네비게이터 webdriver 숨기기 (stealth)
                page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                """)

                # ── 요청 이벤트 리스너 ──────────────────────────────
                def on_request(req: Request):
                    url = req.url
                    rt = req.resource_type  # "xhr" | "fetch" | "websocket" | "document" | ...
                    if rt not in ("xhr", "fetch", "websocket", "document"):
                        return
                    if _should_skip(url):
                        return
                    parsed = urlparse(url)
                    # 같은 호스트 OR API처럼 생긴 외부 URL만
                    if parsed.hostname and parsed.hostname != self.base_host and not _is_api_url(url):
                        return

                    path = parsed.path or "/"
                    template = _normalize_template(path)
                    qs = parse_qs(parsed.query)

                    # POST body (최대 2KB)
                    try:
                        body_raw = req.post_data or ""
                        body = body_raw[:2048] if body_raw else ""
                    except Exception:
                        body = ""

                    key = f"{req.method}:{template}"
                    if key not in captured_map:
                        cr = CapturedRequest(
                            method=req.method,
                            url=url,
                            path=path,
                            template=template,
                            query_params=qs,
                            post_body=body,
                            is_api=_is_api_url(url) or rt in ("xhr", "fetch"),
                            resource_type=rt,
                        )
                        captured_map[key] = cr

                def on_response(resp):
                    url = resp.url
                    parsed = urlparse(url)
                    path = parsed.path or "/"
                    template = _normalize_template(path)
                    key_candidates = [
                        f"{resp.request.method}:{template}",
                        f"GET:{template}",
                    ]
                    for k in key_candidates:
                        if k in captured_map:
                            captured_map[k].status = resp.status
                            ct = resp.headers.get("content-type", "")
                            captured_map[k].content_type = ct
                            # 인증 없이 JSON 데이터 반환 = 미인증 접근 의심
                            if resp.status == 200 and "json" in ct:
                                captured_map[k].is_unauth = True
                            break

                page.on("request", on_request)
                page.on("response", on_response)

                # ── 메인 페이지 로드 ─────────────────────────────────
                try:
                    page.goto(self.target, timeout=timeout_sec * 1000, wait_until="networkidle")
                except Exception:
                    try:
                        page.goto(self.target, timeout=timeout_sec * 1000, wait_until="domcontentloaded")
                    except Exception:
                        pass

                page.wait_for_timeout(2000)

                # ── 링크/버튼 클릭으로 API 트리거 확대 ──────────────
                clicked = 0
                for sel in _CLICK_SELECTORS:
                    if clicked >= max_clicks:
                        break
                    try:
                        elements = page.query_selector_all(sel)
                        for el in elements[:5]:  # 셀렉터당 최대 5개
                            if clicked >= max_clicks:
                                break
                            try:
                                href = el.get_attribute("href") or ""
                                text = (el.inner_text() or "").lower()
                                # 외부 링크나 다운로드 스킵
                                if href.startswith(("http://", "https://")) and self.base_host not in href:
                                    continue
                                if any(kw in text for kw in ("logout", "delete", "remove", "탈퇴")):
                                    continue
                                el.click(timeout=3000)
                                page.wait_for_timeout(1200)
                                clicked += 1
                            except Exception:
                                pass
                    except Exception:
                        pass

                # ── 폼 제출로 검색/필터 API 트리거 ─────────────────
                try:
                    forms = page.query_selector_all("form")
                    for form in forms[:3]:
                        try:
                            action = form.get_attribute("action") or ""
                            if any(k in action.lower() for k in _FORM_SKIP_KEYWORDS):
                                continue
                            # 텍스트 입력 필드에 테스트 값 입력
                            inputs = form.query_selector_all("input[type='text'], input[type='search'], input:not([type])")
                            for inp in inputs[:2]:
                                try:
                                    inp.fill("test", timeout=1000)
                                except Exception:
                                    pass
                            # submit
                            submit_btn = form.query_selector("button[type='submit'], input[type='submit']")
                            if submit_btn:
                                submit_btn.click(timeout=3000)
                                page.wait_for_timeout(1500)
                        except Exception:
                            pass
                except Exception:
                    pass

                # ── 스크롤 다운 (lazy-load API 트리거) ───────────────
                try:
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

                ctx.close()
                browser.close()

        except Exception as exc:
            result.error = str(exc)

        # ── 결과 정리 ────────────────────────────────────────────────
        result.captured = list(captured_map.values())
        templates_seen: set[str] = set()
        for cr in result.captured:
            t = cr.template
            if t not in templates_seen:
                templates_seen.add(t)
                result.unique_templates.append(t)
            if _is_interesting(cr.path):
                result.interesting.append(cr)

        result.elapsed_sec = round(time.time() - t0, 1)
        return result

    # ── 포맷터 ───────────────────────────────────────────────────────

    @staticmethod
    def format_result(result: DynamicCaptureResult, lang: str = "ko") -> str:
        if not result.playwright_available:
            msgs = {
                "ko": f"[동적 API 캡처] Playwright 미설치 → 설치 후 재시도\n  {result.error}",
                "zh": f"[动态API捕获] Playwright未安装 → 安装后重试\n  {result.error}",
                "en": f"[Dynamic API Capture] Playwright not installed → install and retry\n  {result.error}",
            }
            return msgs.get(lang, msgs["en"])

        headers = {
            "ko": (
                f"[동적 API 캡처 완료] {result.target}\n"
                f"  ├ 캡처된 요청: {len(result.captured)}개\n"
                f"  ├ 고유 템플릿: {len(result.unique_templates)}개\n"
                f"  ├ 흥미 경로:  {len(result.interesting)}개\n"
                f"  └ 소요시간:   {result.elapsed_sec}s"
            ),
            "zh": (
                f"[动态API捕获完成] {result.target}\n"
                f"  ├ 捕获请求数: {len(result.captured)}\n"
                f"  ├ 唯一模板数: {len(result.unique_templates)}\n"
                f"  ├ 高价值路径: {len(result.interesting)}\n"
                f"  └ 耗时:      {result.elapsed_sec}s"
            ),
            "en": (
                f"[Dynamic API Capture Done] {result.target}\n"
                f"  ├ Captured requests: {len(result.captured)}\n"
                f"  ├ Unique templates:  {len(result.unique_templates)}\n"
                f"  ├ Interesting paths: {len(result.interesting)}\n"
                f"  └ Elapsed:           {result.elapsed_sec}s"
            ),
        }

        lines = [headers.get(lang, headers["en"]), ""]

        # 흥미 경로 우선 출력
        if result.interesting:
            section = {"ko": "★ 흥미 엔드포인트", "zh": "★ 高价值端点", "en": "★ Interesting Endpoints"}
            lines.append(f"  {section.get(lang, section['en'])}")
            for cr in result.interesting[:20]:
                flag = " [UNAUTH]" if cr.is_unauth else ""
                qs_str = ""
                if cr.query_params:
                    qs_str = "?" + "&".join(f"{k}={v[0]}" for k, v in list(cr.query_params.items())[:4])
                lines.append(f"    {cr.method:6s} {cr.template}{qs_str}  [{cr.status}]{flag}")
            lines.append("")

        # 전체 API 엔드포인트 목록
        api_only = [cr for cr in result.captured if cr.is_api]
        if api_only:
            section = {"ko": "API 엔드포인트 목록", "zh": "API端点列表", "en": "API Endpoints"}
            lines.append(f"  {section.get(lang, section['en'])}")
            for cr in api_only[:50]:
                flag = " [UNAUTH]" if cr.is_unauth else ""
                lines.append(f"    {cr.method:6s} {cr.template}  [{cr.status}]{flag}")

        if result.error:
            lines.append(f"\n  [ERROR] {result.error}")

        return "\n".join(lines)


# ── 외부에서 사용하기 쉬운 단일 함수 ────────────────────────────────

def capture_dynamic_apis(
    target: str,
    cookies: dict | None = None,
    headers: dict | None = None,
    timeout_sec: int = 30,
    max_clicks: int = 20,
    lang: str = "ko",
) -> tuple[DynamicCaptureResult, str]:
    """
    메인 진입점.
    Returns: (DynamicCaptureResult, formatted_string)
    """
    cap = ApiDynamicCapture(target, cookies=cookies, headers=headers)
    result = cap.run(timeout_sec=timeout_sec, max_clicks=max_clicks)
    text = ApiDynamicCapture.format_result(result, lang=lang)
    return result, text
