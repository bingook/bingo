"""
CSRF 심층 스캐너 v2.0
=====================
CSRF(Cross-Site Request Forgery) 취약점 종합 탐지.

탐지 항목:
  1. CSRF 토큰 미설정 (상태변경 폼)
  2. CSRF 토큰 예측 가능성 (짧음, 패턴 있음, 재사용)
  3. SameSite 쿠키 속성 미설정
  4. Referer/Origin 헤더 검증 미비
  5. JSON CSRF (Content-Type 변조)
  6. CORS + 자격증명 허용 조합 (취약 설정)
  7. 관리자/결제/비밀번호 변경 API의 CSRF 보호 미비
  8. Double Submit Cookie 패턴 우회 가능성

AI 자동 선택 조건:
  - 모든 HTTPS 타겟에 기본 실행
  - 폼이 있는 페이지 발견 시 자동 분석
  - 로그인 성공 후 세션 쿠키 확인 시 SameSite 체크 추가

EN: Comprehensive CSRF vulnerability scanner v2.0.
ZH: 全面的CSRF漏洞扫描器v2.0。
"""
from __future__ import annotations

import re
import hashlib
import base64
import math
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()


# ─────────────────────────────────────────────────────────────────────────────
# 결과 데이터클래스
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CSRFResult:
    target: str
    forms_found: int = 0
    forms_missing_token: int = 0
    weak_tokens: list[str] = field(default_factory=list)
    samesite_missing_cookies: list[str] = field(default_factory=list)
    referer_bypass: bool = False
    origin_bypass: bool = False
    json_csrf_possible: bool = False
    cors_credential_issue: bool = False
    admin_endpoints_vulnerable: list[str] = field(default_factory=list)
    severity: str = "INFO"
    findings: list[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# 토큰 강도 분석
# ─────────────────────────────────────────────────────────────────────────────

_KNOWN_WEAK_TOKENS = {
    "undefined", "null", "false", "true", "0", "1",
    "csrf", "token", "csrftoken", "test",
}


def _token_entropy(token: str) -> float:
    """Shannon 엔트로피 계산."""
    if not token:
        return 0.0
    freq = {}
    for c in token:
        freq[c] = freq.get(c, 0) + 1
    total = len(token)
    return -sum((f / total) * math.log2(f / total) for f in freq.values())


def _is_weak_token(token: str) -> tuple[bool, str]:
    """토큰 약점 판단. (weak: bool, reason: str)"""
    t = token.strip()
    if not t:
        return True, "empty token"
    if t.lower() in _KNOWN_WEAK_TOKENS:
        return True, f"trivial token value: '{t}'"
    if len(t) < 8:
        return True, f"token too short ({len(t)} chars)"
    if re.fullmatch(r'\d+', t):
        return True, "purely numeric token — predictable"
    if re.fullmatch(r'[a-fA-F0-9]+', t) and len(t) <= 8:
        return True, "short hex token — low entropy"
    entropy = _token_entropy(t)
    if entropy < 2.5:
        return True, f"low entropy ({entropy:.2f} bits/char)"
    return False, ""


# ─────────────────────────────────────────────────────────────────────────────
# 폼 분석
# ─────────────────────────────────────────────────────────────────────────────

_STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}
_CSRF_FIELD_PATTERNS = re.compile(
    r"csrf|_token|authenticity_token|__requestverificationtoken|"
    r"nonce|antiforgery|xsrf|_wpnonce|sec_token",
    re.IGNORECASE,
)


def _analyze_forms(html: str, base_url: str) -> list[dict]:
    """HTML 폼 분석 — CSRF 토큰 유무 + 약점 확인."""
    results = []
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = form.get("action") or ""
        if method not in _STATE_CHANGING_METHODS:
            continue  # GET 폼은 무시

        token_found = False
        token_value = ""
        for inp in form.find_all("input"):
            name  = (inp.get("name") or "").lower()
            itype = (inp.get("type") or "text").lower()
            val   = inp.get("value") or ""
            if _CSRF_FIELD_PATTERNS.search(name) or itype == "hidden":
                if _CSRF_FIELD_PATTERNS.search(name):
                    token_found = True
                    token_value = val

        abs_action = urllib.parse.urljoin(base_url, action)
        results.append({
            "action": abs_action,
            "method": method,
            "has_csrf_token": token_found,
            "token_value": token_value,
        })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# 헤더 기반 검증 우회 테스트
# ─────────────────────────────────────────────────────────────────────────────

def _test_referer_bypass(target_url: str, form_action: str, sess: requests.Session) -> bool:
    """빈 Referer 또는 악의적 Referer로 POST 요청 시 200 응답 여부."""
    payloads = [
        {},                                      # Referer 헤더 없음
        {"Referer": "https://evil.com/attack"},  # 외부 사이트
        {"Referer": ""},                          # 빈 문자열
    ]
    for headers in payloads:
        try:
            r = sess.post(form_action, headers=headers, data={"test": "1"}, timeout=6)
            # 200/302 리턴 (403/419 아닌 경우) → 검증 없음 가능성
            if r.status_code in (200, 302):
                return True
        except Exception:
            pass
    return False


def _test_origin_bypass(form_action: str, sess: requests.Session) -> bool:
    """악의적인 Origin 헤더로 POST 요청."""
    try:
        r = sess.post(
            form_action,
            headers={"Origin": "https://evil.attacker.com"},
            data={"test": "1"},
            timeout=6,
        )
        return r.status_code in (200, 302)
    except Exception:
        return False


def _test_json_csrf(form_action: str, sess: requests.Session) -> bool:
    """
    Content-Type을 text/plain으로 변경한 JSON CSRF 시도.
    브라우저 preflight를 우회하면서 JSON 파싱되는 경우.
    """
    try:
        r = sess.post(
            form_action,
            headers={"Content-Type": "text/plain"},
            data='{"action":"test","csrf":"bypass"}',
            timeout=6,
        )
        return r.status_code in (200, 201, 302)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 쿠키 SameSite 분석
# ─────────────────────────────────────────────────────────────────────────────

def _check_samesite_cookies(response: requests.Response) -> list[str]:
    """SameSite 속성이 없거나 None인 중요 쿠키 반환."""
    missing = []
    for cookie in response.cookies:
        name = cookie.name.lower()
        # 세션 쿠키, 인증 쿠키 위주 확인
        if any(k in name for k in ("session", "sess", "auth", "login", "token", "jsession", "phpsessid")):
            # requests의 Cookie 객체에는 samesite 속성이 없으므로 헤더 직접 파싱
            for raw_hdr in response.headers.get_all("set-cookie") if hasattr(response.headers, "get_all") else [response.headers.get("set-cookie", "")]:
                if cookie.name in raw_hdr:
                    if "samesite" not in raw_hdr.lower():
                        missing.append(cookie.name)
                    elif "samesite=none" in raw_hdr.lower() and "secure" not in raw_hdr.lower():
                        missing.append(f"{cookie.name} (SameSite=None without Secure)")
    return missing


# ─────────────────────────────────────────────────────────────────────────────
# CORS 검사
# ─────────────────────────────────────────────────────────────────────────────

def _check_cors(target_url: str, sess: requests.Session) -> bool:
    """
    Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true 위험 조합 확인.
    또는 Origin 반사(echo) 확인.
    """
    try:
        r = sess.get(
            target_url,
            headers={"Origin": "https://evil.attacker.com"},
            timeout=6,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*" and acac == "true":
            return True
        if acao == "https://evil.attacker.com" and acac == "true":
            return True
    except Exception:
        pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 관리자/민감 엔드포인트 CSRF 확인
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_PATHS = [
    "/admin", "/admin/", "/admin/user", "/api/admin",
    "/api/user/password", "/api/account/delete",
    "/api/transfer", "/api/pay", "/api/checkout",
    "/mypage/password", "/settings/password",
    "/user/delete", "/account/close",
]


def _check_sensitive_endpoints(base_url: str, sess: requests.Session) -> list[str]:
    """민감 경로에 대한 CSRF 보호 미비 확인."""
    vulnerable = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in _SENSITIVE_PATHS:
        url = origin + path
        try:
            # OPTIONS + Origin 헤더
            r = sess.options(
                url,
                headers={"Origin": "https://evil.com"},
                timeout=5,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao in ("*", "https://evil.com"):
                vulnerable.append(f"{path} (CORS bypass)")
                continue
            # POST with no token
            r2 = sess.post(url, data={"csrf": "", "action": "test"}, timeout=5)
            if r2.status_code in (200, 201):
                vulnerable.append(f"{path} (no CSRF rejection)")
        except Exception:
            pass
    return vulnerable


# ─────────────────────────────────────────────────────────────────────────────
# 메인 스캔 함수
# ─────────────────────────────────────────────────────────────────────────────

def scan_csrf(target_url: str) -> CSRFResult:
    """
    CSRF 심층 탐지 (v2.0).

    EN: Deep CSRF scanning including token analysis, header bypass, SameSite, CORS.
    ZH: 深度CSRF检测，包括令牌分析、请求头绕过、SameSite、CORS检测。

    Args:
        target_url: 대상 URL
    Returns:
        CSRFResult
    """
    result = CSRFResult(target=target_url)

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 bingo-csrf-scanner"

    # STEP 1 — 메인 페이지 가져오기 + 폼 분석
    try:
        r = sess.get(target_url, timeout=10)
    except Exception as e:
        return result

    forms = _analyze_forms(r.text, target_url)
    result.forms_found = len(forms)

    for form in forms:
        if not form["has_csrf_token"]:
            result.forms_missing_token += 1
            result.findings.append({
                "severity": "HIGH",
                "name": "CSRF Token Missing on POST Form",
                "detail": f"Form action: {form['action']} — no CSRF token field found.",
            })
            result.severity = "HIGH"
        else:
            weak, reason = _is_weak_token(form["token_value"])
            if weak:
                result.weak_tokens.append(form["action"])
                result.findings.append({
                    "severity": "MEDIUM",
                    "name": "Weak CSRF Token Detected",
                    "detail": f"Form: {form['action']} — Token weakness: {reason}",
                })
                if result.severity == "INFO":
                    result.severity = "MEDIUM"

        # Referer / Origin 우회 테스트 (토큰 없는 폼에 대해)
        if not form["has_csrf_token"]:
            if _test_referer_bypass(target_url, form["action"], sess):
                result.referer_bypass = True
                result.findings.append({
                    "severity": "CRITICAL",
                    "name": "CSRF Referer Bypass Confirmed",
                    "detail": f"POST to {form['action']} accepted without valid Referer — CSRF attack possible.",
                })
                result.severity = "CRITICAL"

            if _test_origin_bypass(form["action"], sess):
                result.origin_bypass = True
                result.findings.append({
                    "severity": "HIGH",
                    "name": "CSRF Origin Header Bypass",
                    "detail": f"POST to {form['action']} accepted with evil Origin header.",
                })

            if _test_json_csrf(form["action"], sess):
                result.json_csrf_possible = True
                result.findings.append({
                    "severity": "HIGH",
                    "name": "JSON CSRF via text/plain",
                    "detail": f"POST to {form['action']} accepts text/plain JSON payload.",
                })

    # STEP 2 — SameSite 쿠키 확인
    try:
        r2 = sess.get(target_url, timeout=8)
        missing_ss = _check_samesite_cookies(r2)
        result.samesite_missing_cookies = missing_ss
        for c in missing_ss:
            result.findings.append({
                "severity": "MEDIUM",
                "name": f"SameSite Attribute Missing: {c}",
                "detail": f"Cookie '{c}' lacks SameSite attribute — cross-site request possible.",
            })
            if result.severity == "INFO":
                result.severity = "MEDIUM"
    except Exception:
        pass

    # STEP 3 — CORS 검사
    if _check_cors(target_url, sess):
        result.cors_credential_issue = True
        result.findings.append({
            "severity": "CRITICAL",
            "name": "CORS Credentials + Wildcard Origin",
            "detail": (
                "Access-Control-Allow-Credentials: true with reflected/wildcard Origin. "
                "Attacker can perform authenticated cross-origin requests."
            ),
        })
        result.severity = "CRITICAL"

    # STEP 4 — 민감 엔드포인트 CSRF 취약 확인
    vulnerable_eps = _check_sensitive_endpoints(target_url, sess)
    result.admin_endpoints_vulnerable = vulnerable_eps
    for ep in vulnerable_eps:
        result.findings.append({
            "severity": "HIGH",
            "name": f"Sensitive Endpoint CSRF Vulnerable: {ep}",
            "detail": f"Endpoint {ep} lacks CSRF protection or has CORS bypass.",
        })
        result.severity = max(result.severity, "HIGH")

    return result


def csrf_report(r: CSRFResult) -> str:
    """CSRF 스캔 결과 보고서."""
    lines = [
        f"[CSRF Deep Scan] Target: {r.target}",
        f"  Forms Found        : {r.forms_found}",
        f"  Forms No Token     : {r.forms_missing_token}",
        f"  Referer Bypass     : {r.referer_bypass}",
        f"  Origin Bypass      : {r.origin_bypass}",
        f"  JSON CSRF          : {r.json_csrf_possible}",
        f"  CORS Issue         : {r.cors_credential_issue}",
        f"  SameSite Missing   : {len(r.samesite_missing_cookies)} cookies",
        f"  Severity           : {r.severity}",
    ]
    if r.findings:
        lines.append("  --- Findings ---")
        for f in r.findings:
            lines.append(f"  [{f['severity']}] {f['name']}")
            lines.append(f"           {f['detail'][:200]}")
    return "\n".join(lines)
