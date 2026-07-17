"""bingo/tools/playwright_engine.py — Playwright 기반 브라우저 자동화 (v2.9.0)

기능:
  - 관리자 패널 로그인 후 스크린샷 자동 촬영
  - JS 렌더링이 필요한 페이지 완전 렌더링 후 소스 추출
  - DOM XSS 자동 주입 및 실행 확인
  - 동적 파라미터/폼 탐색
  - Playwright 미설치 시 graceful fallback (requests 기반)
"""
from __future__ import annotations

import base64
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class BrowserResult:
    url: str
    title: str = ""
    screenshot_b64: str = ""   # base64 PNG
    page_source: str = ""
    js_executed: bool = False
    cookies: list[dict] = field(default_factory=list)
    console_logs: list[str] = field(default_factory=list)


@dataclass
class PlaywrightReport:
    target: str
    screenshots: list[BrowserResult] = field(default_factory=list)
    dom_xss_confirmed: list[str] = field(default_factory=list)
    dynamic_params: list[str] = field(default_factory=list)

    def summary(self) -> str:
        ss_count = len(self.screenshots)
        xss_count = len(self.dom_xss_confirmed)
        return (
            f"[PLAYWRIGHT] {self.target} | 스크린샷:{ss_count} | DOM XSS:{xss_count}"
        )


# ── Playwright 가용성 체크 ─────────────────────────────────────────────────────

def _playwright_available() -> bool:
    try:
        import importlib
        importlib.import_module("playwright.sync_api")
        return True
    except ImportError:
        return False


# ── 스크린샷 저장 helper ───────────────────────────────────────────────────────

def _save_screenshot(png: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(png)


# ══════════════════════════════════════════════════════════════════════════════
# Playwright 기반 엔진 (설치된 경우)
# ══════════════════════════════════════════════════════════════════════════════

class _PlaywrightEngine:
    """Playwright sync API 래퍼"""

    def __init__(self, headless: bool = True, timeout: int = 30_000) -> None:
        from playwright.sync_api import sync_playwright  # type: ignore
        self._pw = sync_playwright().__enter__()
        self.browser = self._pw.chromium.launch(headless=headless)
        self.timeout = timeout

    def close(self) -> None:
        try:
            self.browser.close()
            self._pw.__exit__(None, None, None)
        except Exception:
            pass

    def screenshot_page(self, url: str, cookies: dict | None = None) -> BrowserResult:
        ctx = self.browser.new_context(ignore_https_errors=True)
        if cookies:
            ctx.add_cookies([
                {"name": k, "value": v, "url": url}
                for k, v in cookies.items()
            ])
        page = ctx.new_page()
        logs: list[str] = []
        page.on("console", lambda msg: logs.append(msg.text))

        try:
            page.goto(url, timeout=self.timeout, wait_until="networkidle")
            title = page.title()
            source = page.content()
            png = page.screenshot(full_page=True)
            b64 = base64.b64encode(png).decode()
            browser_cookies = ctx.cookies()
        except Exception as e:
            return BrowserResult(url=url, console_logs=[str(e)])
        finally:
            ctx.close()

        return BrowserResult(
            url=url,
            title=title,
            screenshot_b64=b64,
            page_source=source,
            js_executed=True,
            cookies=browser_cookies,
            console_logs=logs,
        )

    def login_and_screenshot(
        self,
        login_url: str,
        username_sel: str,
        password_sel: str,
        submit_sel: str,
        username: str,
        password: str,
        success_url_pattern: str = "",
    ) -> BrowserResult:
        ctx = self.browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        logs: list[str] = []
        page.on("console", lambda msg: logs.append(msg.text))

        try:
            page.goto(login_url, timeout=self.timeout)
            page.fill(username_sel, username)
            page.fill(password_sel, password)
            page.click(submit_sel)
            page.wait_for_load_state("networkidle", timeout=self.timeout)
            current_url = page.url
            title = page.title()
            source = page.content()
            png = page.screenshot(full_page=True)
            b64 = base64.b64encode(png).decode()
            cookies = ctx.cookies()
        except Exception as e:
            return BrowserResult(url=login_url, console_logs=[str(e)])
        finally:
            ctx.close()

        return BrowserResult(
            url=current_url,
            title=title,
            screenshot_b64=b64,
            page_source=source,
            js_executed=True,
            cookies=cookies,
            console_logs=logs,
        )

    def inject_dom_xss(self, url: str, param: str) -> bool | None:
        """DOM XSS 주입 후 alert 실행 여부 확인"""
        payload = "<img src=x onerror=window.__BINGO_XSS__=1>"
        xss_url = url + (
            "&" if "?" in url else "?"
        ) + f"{param}={urllib.parse.quote(payload)}"

        ctx = self.browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        try:
            page.goto(xss_url, timeout=self.timeout, wait_until="load")
            result = page.evaluate("() => window.__BINGO_XSS__")
            return result == 1
        except Exception:
            return None
        finally:
            ctx.close()


# ══════════════════════════════════════════════════════════════════════════════
# Fallback (requests 기반)
# ══════════════════════════════════════════════════════════════════════════════

class _RequestsFallback:
    def screenshot_page(self, url: str, cookies: dict | None = None) -> BrowserResult:
        try:
            import requests  # type: ignore
            resp = requests.get(url, cookies=cookies or {}, timeout=10, verify=False)
            return BrowserResult(
                url=url, title="", page_source=resp.text, js_executed=False
            )
        except Exception as e:
            return BrowserResult(url=url, console_logs=[str(e)])

    def login_and_screenshot(self, *args, **kwargs) -> BrowserResult:
        return BrowserResult(url="", console_logs=["playwright 미설치 — 스크린샷 불가"])

    def inject_dom_xss(self, url: str, param: str) -> bool | None:
        return None

    def close(self) -> None:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# 공개 인터페이스
# ══════════════════════════════════════════════════════════════════════════════

class PlaywrightEngine:
    """Playwright 자동화 엔진 (미설치 시 requests fallback)"""

    def __init__(self, headless: bool = True, timeout: int = 30_000) -> None:
        if _playwright_available():
            self._engine: _PlaywrightEngine | _RequestsFallback = _PlaywrightEngine(headless, timeout)
            self.available = True
        else:
            self._engine = _RequestsFallback()
            self.available = False

    def close(self) -> None:
        self._engine.close()

    def screenshot(self, url: str, cookies: dict | None = None) -> BrowserResult:
        return self._engine.screenshot_page(url, cookies)

    def login_screenshot(
        self,
        login_url: str,
        username: str,
        password: str,
        username_sel: str = "input[name='username'],input[type='email'],#username",
        password_sel: str = "input[type='password'],#password",
        submit_sel: str = "button[type='submit'],input[type='submit']",
    ) -> BrowserResult:
        return self._engine.login_and_screenshot(
            login_url, username_sel, password_sel, submit_sel, username, password
        )

    def dom_xss_test(self, url: str, params: list[str]) -> list[str]:
        confirmed, _, _ = self.dom_xss_test_detailed(url, params)
        return confirmed

    def dom_xss_test_detailed(self, url: str, params: list[str]) -> tuple[list[str], int, int]:
        """Return confirmed params, completed checks, and execution errors."""
        confirmed = []
        completed = 0
        errors = 0
        for p in params:
            result = self._engine.inject_dom_xss(url, p)
            if result is None:
                errors += 1
                continue
            completed += 1
            if result:
                confirmed.append(p)
        return confirmed, completed, errors

    def auto_scan(self, url: str, params: list[str] | None = None) -> PlaywrightReport:
        report = PlaywrightReport(target=url)
        br = self.screenshot(url)
        report.screenshots.append(br)
        if params and self.available:
            report.dom_xss_confirmed = self.dom_xss_test(url, params)
        return report

    @staticmethod
    def install_hint() -> str:
        return "pip install playwright && python -m playwright install chromium"
