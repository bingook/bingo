"""
playwright_recon.py — JS 렌더링 정찰 모듈

사용 조건 (자동 판단):
  - 응답 body가 작은데 JS 프레임워크 감지됨 (SPA)
  - CAPTCHA / bot 감지 응답
  - 링크/파라미터가 0개인데 200 응답

설치 (자동 처리):
  pip install playwright
  playwright install chromium
"""
from __future__ import annotations

import os
import sys
import subprocess
import re
import platform
from typing import Optional


# ── Playwright 사용 가능 여부 확인 ──────────────────────────────────
def is_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa
        return True
    except ImportError:
        return False


def install(console=None) -> bool:
    """Playwright 자동 설치 (pip + chromium 바이너리)."""
    def _log(msg: str):
        if console:
            console.print(msg)
        else:
            print(msg)

    try:
        _log("  [playwright] pip install playwright...")
        r1 = subprocess.run(
            [sys.executable, "-m", "pip", "install", "playwright", "-q"],
            capture_output=True, text=True, timeout=120
        )
        if r1.returncode != 0:
            _log(f"  [playwright] pip 설치 실패: {r1.stderr[:200]}")
            return False

        _log("  [playwright] chromium 다운로드 중 (~150MB, 잠시 대기)...")
        r2 = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, text=True, timeout=300
        )
        if r2.returncode != 0:
            _log(f"  [playwright] chromium 설치 실패: {r2.stderr[:200]}")
            return False

        _log("  [playwright] ✔ 설치 완료")
        return True
    except Exception as e:
        _log(f"  [playwright] 설치 오류: {e}")
        return False


# ── JS 렌더링 필요 여부 자동 판단 ────────────────────────────────────
def needs_playwright(status: int, body: str, url: str) -> bool:
    """urllib/httpx로 받은 응답 분석 후 Playwright 필요 여부 반환."""
    if status not in (200, 201):
        return False

    body_low = body.lower()

    # SPA 프레임워크 감지
    spa_signals = [
        'react.development', 'react.production', '__react',
        'vue.js', 'vue.min.js', '__vue__',
        'angular.min.js', 'ng-app', 'ng-version',
        'next.js', '__next',
        'nuxt', '__nuxt',
        'ember.js',
    ]
    has_spa = any(s in body_low for s in spa_signals)

    # 응답이 너무 작은데 JS 있는 경우
    has_js_src = '<script src=' in body_low
    body_small = len(body) < 2000

    # CAPTCHA / bot 감지
    has_captcha = any(s in body_low for s in [
        'captcha', 'recaptcha', 'hcaptcha', 'cf-turnstile',
        'cloudflare ray', 'just a moment', 'checking your browser',
        'ddos-guard', 'bot detection',
    ])

    # <div id="app"></div> or <div id="root"></div> 패턴 (SPA shell)
    has_spa_shell = bool(re.search(r'<div\s+id=["\'](?:app|root|main)["\']>\s*</div>', body, re.I))

    return has_spa or (body_small and has_js_src) or has_captcha or has_spa_shell


# ── Playwright 정찰 실행 ─────────────────────────────────────────────
def recon(url: str, timeout_ms: int = 15000) -> dict:
    """
    Playwright로 JS 렌더링 후 정찰.
    반환: {
        'html': str,
        'title': str,
        'links': list[str],
        'param_urls': list[str],
        'forms': list[dict],
        'cookies': dict,
        'screenshot_b64': str | None,
        'error': str | None,
    }
    """
    result = {
        'html': '',
        'title': '',
        'links': [],
        'param_urls': [],
        'forms': [],
        'cookies': {},
        'screenshot_b64': None,
        'error': None,
    }

    # Windows asyncio 정책 처리
    if platform.system() == 'Windows':
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
    except ImportError:
        result['error'] = 'playwright not installed'
        return result

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-web-security',
                ]
            )
            ctx = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
                viewport={'width': 1280, 'height': 800},
                ignore_https_errors=True,
            )
            page = ctx.new_page()

            # 불필요한 리소스 차단 (속도 향상)
            page.route('**/*.{png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot}',
                       lambda route: route.abort())

            try:
                page.goto(url, timeout=timeout_ms, wait_until='networkidle')
            except PwTimeout:
                # networkidle 타임아웃 시 domcontentloaded로 재시도
                try:
                    page.goto(url, timeout=timeout_ms, wait_until='domcontentloaded')
                except Exception:
                    pass

            # 쿠키 수집
            cookies = ctx.cookies()
            result['cookies'] = {c['name']: c['value'] for c in cookies}

            # 렌더링된 HTML
            html = page.content()
            result['html'] = html
            result['title'] = page.title()

            # 링크 수집
            hrefs = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
            result['links'] = list(dict.fromkeys(h for h in hrefs if h.startswith('http')))

            # 파라미터 포함 URL
            result['param_urls'] = [l for l in result['links'] if '?' in l and '=' in l]

            # 폼 수집
            forms = page.eval_on_selector_all('form', '''forms => forms.map(f => ({
                action: f.action,
                method: f.method || "GET",
                inputs: Array.from(f.querySelectorAll("input,select,textarea"))
                    .map(i => ({ name: i.name, type: i.type, value: i.value }))
            }))''')
            result['forms'] = forms

            # 스크린샷 (base64)
            try:
                import base64
                ss = page.screenshot(type='png', full_page=False)
                result['screenshot_b64'] = base64.b64encode(ss).decode()
            except Exception:
                pass

            browser.close()

    except Exception as e:
        result['error'] = str(e)

    return result


def format_result(r: dict, base_url: str = '') -> str:
    """정찰 결과를 AI에게 전달할 텍스트로 변환."""
    lines = ["=== PLAYWRIGHT_RECON (JS-rendered) ==="]
    if r.get('error'):
        lines.append(f"  ERROR: {r['error']}")
        return "\n".join(lines)

    lines.append(f"  title: {r.get('title', '')}")
    lines.append(f"  html_length: {len(r.get('html', ''))}B")

    if r.get('cookies'):
        lines.append(f"  cookies: {r['cookies']}")

    links = r.get('links', [])
    param_urls = r.get('param_urls', [])
    lines.append(f"  links_found: {len(links)}")
    lines.append(f"  param_urls_found: {len(param_urls)}")

    if param_urls:
        lines.append("  PARAM_URLS (JS-rendered — attack these):")
        for u in param_urls[:20]:
            lines.append(f"    {u}")

    forms = r.get('forms', [])
    if forms:
        lines.append(f"  forms_found: {len(forms)}")
        for i, f in enumerate(forms[:5]):
            inputs = [inp.get('name', '?') for inp in f.get('inputs', []) if inp.get('name')]
            lines.append(f"    form[{i}]: action={f.get('action','')} method={f.get('method','GET')} inputs={inputs}")

    return "\n".join(lines)
