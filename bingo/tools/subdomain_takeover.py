"""bingo/tools/subdomain_takeover.py — 서브도메인 탈취 스캐너 (v2.6.0)"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Callable

# ── 탈취 가능한 서비스 핑거프린트 ─────────────────────────────────────────────
TAKEOVER_SIGNATURES: list[dict] = [
    {"service": "AWS S3",           "cname": ".s3.amazonaws.com",      "body_sig": "NoSuchBucket",          "severity": "CRITICAL"},
    {"service": "AWS S3 Website",   "cname": ".s3-website",            "body_sig": "NoSuchBucket",          "severity": "CRITICAL"},
    {"service": "GitHub Pages",     "cname": ".github.io",             "body_sig": "There isn't a GitHub Pages site here", "severity": "CRITICAL"},
    {"service": "Heroku",           "cname": ".herokudns.com",         "body_sig": "No such app",           "severity": "CRITICAL"},
    {"service": "Heroku",           "cname": "herokuapp.com",          "body_sig": "No such app",           "severity": "CRITICAL"},
    {"service": "Shopify",          "cname": ".myshopify.com",         "body_sig": "Sorry, this shop is currently unavailable", "severity": "HIGH"},
    {"service": "Fastly",           "cname": ".fastly.net",            "body_sig": "Fastly error: unknown domain", "severity": "HIGH"},
    {"service": "Azure",            "cname": ".azurewebsites.net",     "body_sig": "404 Web Site not found", "severity": "CRITICAL"},
    {"service": "Azure CDN",        "cname": ".azureedge.net",         "body_sig": "The resource you are looking for", "severity": "HIGH"},
    {"service": "Zendesk",          "cname": ".zendesk.com",           "body_sig": "Help Center Closed",    "severity": "HIGH"},
    {"service": "Tumblr",           "cname": ".tumblr.com",            "body_sig": "There's nothing here", "severity": "MEDIUM"},
    {"service": "WordPress",        "cname": ".wordpress.com",         "body_sig": "Do you want to register",  "severity": "MEDIUM"},
    {"service": "Ghost",            "cname": ".ghost.io",              "body_sig": "The thing you were looking for is no longer here", "severity": "MEDIUM"},
    {"service": "Surge.sh",         "cname": ".surge.sh",              "body_sig": "project not found",    "severity": "MEDIUM"},
    {"service": "Bitbucket",        "cname": ".bitbucket.io",          "body_sig": "Repository not found", "severity": "HIGH"},
    {"service": "Cargo",            "cname": ".cargocollective.com",   "body_sig": "If you're moving your domain away from Cargo", "severity": "MEDIUM"},
    {"service": "Webflow",          "cname": ".proxy.webflow.com",     "body_sig": "The page you are looking for doesn't exist", "severity": "MEDIUM"},
    {"service": "Netlify",          "cname": ".netlify.app",           "body_sig": "Not found - Request ID", "severity": "HIGH"},
    {"service": "Vercel",           "cname": ".vercel.app",            "body_sig": "The deployment could not be found", "severity": "HIGH"},
    {"service": "Strikingly",       "cname": ".strikinglydns.com",     "body_sig": "page not found",       "severity": "MEDIUM"},
    {"service": "Readme.io",        "cname": ".readme.io",             "body_sig": "Project doesnt exist", "severity": "MEDIUM"},
    {"service": "Intercom",         "cname": ".custom.intercom.help",  "body_sig": "This page is reserved for future use", "severity": "MEDIUM"},
    # Naver/Kakao (한국)
    {"service": "Naver Blog",       "cname": ".blog.me",               "body_sig": "존재하지 않는 블로그",   "severity": "MEDIUM"},
    {"service": "Cafe24",           "cname": ".cafe24.com",            "body_sig": "등록되지 않은 도메인",   "severity": "HIGH"},
]

# ── 자주 쓰이는 서브도메인 ────────────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "webmail", "email",
    "api", "api2", "rest", "dev", "staging", "stage", "test", "beta", "demo",
    "admin", "portal", "dashboard", "manage", "manager", "cms", "wp", "blog",
    "shop", "store", "payment", "pay", "billing", "invoice",
    "cdn", "static", "assets", "img", "images", "media", "upload", "uploads",
    "old", "legacy", "backup", "bak", "archive",
    "vpn", "remote", "rdp", "ssh", "ftp", "sftp",
    "ns", "ns1", "ns2", "dns", "mx",
    "status", "monitor", "health", "ping", "metrics",
    "support", "help", "docs", "wiki", "kb",
    "m", "mobile", "app", "api-v1", "api-v2",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "deploy",
    "jira", "confluence", "slack", "zoom",
    # 한국 특화
    "www2", "corp", "biz", "co",
]


@dataclass
class TakeoverFinding:
    subdomain: str
    cname: str
    service: str
    status: int
    body_evidence: str
    severity: str
    takeover_possible: bool
    instructions: str = ""


@dataclass
class TakeoverReport:
    domain: str
    subdomains_checked: int = 0
    findings: list[TakeoverFinding] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[TakeoverFinding]:
        return [f for f in self.findings if f.takeover_possible]


class SubdomainTakeoverScanner:
    """서브도메인 CNAME 댕글링 탐지 + 탈취 가능성 자동 분석"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        domain: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.domain = domain.lstrip("*. ")
        self.headers = headers or {"User-Agent": "Mozilla/5.0"}

    def _resolve_cname(self, subdomain: str) -> str | None:
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", subdomain],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().rstrip(".")
            return cname or None
        except Exception:
            return None

    def _check_signature(self, url: str) -> tuple[int, str]:
        try:
            status, body = self.req(url, "GET", self.headers, "")
            return status, body
        except Exception:
            return 0, ""

    def scan_subdomain(self, subdomain: str) -> TakeoverFinding | None:
        full = f"{subdomain}.{self.domain}" if "." not in subdomain else subdomain
        cname = self._resolve_cname(full)
        if not cname:
            return None

        for sig in TAKEOVER_SIGNATURES:
            if sig["cname"].lstrip(".") in cname:
                url = f"http://{full}"
                status, body = self._check_signature(url)
                takeover = sig["body_sig"].lower() in body.lower()
                instr = _takeover_instructions(sig["service"], full, cname)
                return TakeoverFinding(
                    subdomain=full, cname=cname,
                    service=sig["service"], status=status,
                    body_evidence=body[:200], severity=sig["severity"],
                    takeover_possible=takeover,
                    instructions=instr if takeover else "",
                )
        return None

    def scan_all(self, extra_subdomains: list[str] | None = None) -> TakeoverReport:
        report = TakeoverReport(domain=self.domain)
        subs = list(set(COMMON_SUBDOMAINS + (extra_subdomains or [])))
        report.subdomains_checked = len(subs)

        for sub in subs:
            finding = self.scan_subdomain(sub)
            if finding:
                report.findings.append(finding)

        return report


def _takeover_instructions(service: str, subdomain: str, cname: str) -> str:
    instructions = {
        "AWS S3":        f"1. aws s3 mb s3://{subdomain}\n2. aws s3 website s3://{subdomain} --index-document index.html\n3. Upload index.html to confirm takeover",
        "GitHub Pages":  f"1. Create GitHub repo: {subdomain.split('.')[0]}.github.io\n2. Add CNAME file with content: {subdomain}\n3. Verify via GitHub Pages settings",
        "Heroku":        f"1. heroku create {subdomain.replace('.', '-')}\n2. heroku domains:add {subdomain}\n3. Test with curl -H 'Host: {subdomain}' https://xxx.herokuapp.com/",
        "Netlify":       f"1. netlify deploy --prod\n2. netlify domains:add {subdomain}\n3. Verify DNS propagation",
        "Azure":         f"1. az webapp create --name {subdomain.split('.')[0]}\n2. az webapp config hostname add --hostname {subdomain}\n3. Verify domain ownership",
    }
    return instructions.get(service, f"Register a new account/project on {service} and claim domain: {subdomain}")
