"""bingo/tools/recon_engine.py — 도메인/자산 레콘 엔진 (v2.6.0)"""
from __future__ import annotations

import json
import re
import socket
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

# ── 공통 포트 ─────────────────────────────────────────────────────────────────
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2222, 3000, 3306, 3389, 4000, 4443,
    5000, 5432, 5900, 6379, 6443, 7000, 7443, 8000, 8080, 8081,
    8082, 8083, 8088, 8090, 8099, 8200, 8443, 8444, 8500, 8888,
    9000, 9090, 9092, 9200, 9300, 9443, 10000, 10250, 15672, 27017,
]

# ── 기술 핑거프린트 시그니처 ──────────────────────────────────────────────────
TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress":    ["wp-content", "wp-includes", "wp-login.php", "wordpress"],
    "Drupal":       ["Drupal", "drupal.js", "sites/all"],
    "Joomla":       ["Joomla", "/components/com_", "joomla"],
    "Laravel":      ["laravel_session", "XSRF-TOKEN", "laravel"],
    "Django":       ["csrfmiddlewaretoken", "django", "__django_session"],
    "Spring Boot":  ["X-Application-Context", "spring", "Spring Boot"],
    "React":        ["_reactRootContainer", "react.min.js", "__NEXT_DATA__"],
    "Vue.js":       ["__vue__", "vue.js", "vue.min.js"],
    "jQuery":       ["jquery.min.js", "jQuery"],
    "ASP.NET":      ["__VIEWSTATE", "ASP.NET_SessionId", "aspnet"],
    "PHP":          ["X-Powered-By: PHP", ".php", "PHPSESSID"],
    "Nginx":        ["nginx", "Server: nginx"],
    "Apache":       ["Server: Apache", "Apache/"],
    "Cloudflare":   ["CF-RAY", "cloudflare", "__cflb"],
    "AWS":          ["x-amz-request-id", "AmazonS3", "aws"],
    # 한국 기술스택
    "GnuBoard":     ["gnuboard", "g5_", "board.php"],
    "XpressEngine": ["rhymix", "xe_", "XE_SITE_KEY"],
    "Cafe24":       ["cafe24", "Cafe24 Corp"],
}


@dataclass
class ReconAsset:
    domain: str
    ip: str | None
    open_ports: list[int] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    status: int = 0
    title: str = ""
    waf: str = ""
    cdn: str = ""


@dataclass
class ReconReport:
    target: str
    assets: list[ReconAsset] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    open_services: dict = field(default_factory=dict)  # port → service
    cert_sans: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return (
            f"Assets: {len(self.assets)} | "
            f"Open ports: {sum(len(a.open_ports) for a in self.assets)} | "
            f"Tech fingerprinted: {sum(len(a.technologies) for a in self.assets)}"
        )


class ReconEngine:
    """도메인/자산 레콘 자동화 엔진"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        domain: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.domain = domain.lstrip("https://").lstrip("http://").split("/")[0]
        self.headers = headers or {"User-Agent": "Mozilla/5.0"}

    # ── DNS 조회 ──────────────────────────────────────────────────────────────
    def resolve_ip(self, host: str) -> str | None:
        """VPN 우회 DNS 조회 — dig @8.8.8.8 사용 (v3.6.7)."""
        import re as _re
        for ns in ("8.8.8.8", "1.1.1.1"):
            try:
                out = subprocess.check_output(
                    ["dig", f"@{ns}", "+short", "+time=5", "+tries=2", host],
                    timeout=10, text=True, stderr=subprocess.DEVNULL,
                ).strip()
                ips = [ln for ln in out.splitlines()
                       if _re.match(r"^\d+\.\d+\.\d+\.\d+$", ln)]
                if ips:
                    return ips[0]
            except Exception:
                continue
        try:
            return socket.gethostbyname(host)
        except Exception:
            return None

    # ── crt.sh 인증서 투명성 서브도메인 ──────────────────────────────────────
    def enum_subdomains_crtsh(self) -> list[str]:
        subs: set[str] = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            status, resp = self.req(url, "GET", self.headers, "")
            if status == 200:
                entries = json.loads(resp)
                for e in entries:
                    name = e.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if self.domain in sub:
                            subs.add(sub)
        except Exception:
            pass
        return sorted(subs)

    # ── 포트 스캔 ─────────────────────────────────────────────────────────────
    def port_scan(self, host: str, ports: list[int] | None = None, timeout: float = 1.0) -> list[int]:
        open_ports = []
        scan_ports = ports or COMMON_PORTS
        for port in scan_ports:
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                sock.close()
                open_ports.append(port)
            except Exception:
                pass
        return open_ports

    # ── 기술 핑거프린팅 ───────────────────────────────────────────────────────
    def fingerprint_tech(self, url: str) -> tuple[list[str], dict, int, str]:
        techs: list[str] = []
        resp_headers: dict = {}
        status = 0
        title = ""
        try:
            status, body = self.req(url, "GET", self.headers, "")
            for tech, patterns in TECH_SIGNATURES.items():
                if any(p.lower() in body.lower() for p in patterns):
                    techs.append(tech)
            # 타이틀
            m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
            if m:
                title = m.group(1).strip()
        except Exception:
            pass
        return techs, resp_headers, status, title

    # ── WAF 탐지 ──────────────────────────────────────────────────────────────
    def detect_waf_cdn(self, url: str) -> tuple[str, str]:
        waf = ""
        cdn = ""
        try:
            _, body = self.req(url, "GET", self.headers, "")
            waf_sigs = {
                "Cloudflare": ["cf-ray", "cloudflare"],
                "AWS WAF": ["x-amzn-requestid", "awselb"],
                "Akamai": ["x-check-cacheable", "akamai"],
                "Imperva": ["incapsula", "x-iinfo"],
                "F5 BIG-IP": ["bigip", "f5-"],
            }
            for name, sigs in waf_sigs.items():
                if any(s in body.lower() for s in sigs):
                    waf = name
                    break
            cdn_sigs = {
                "Cloudflare": "cf-ray",
                "Fastly": "x-fastly",
                "AWS CloudFront": "x-amz-cf-id",
                "Akamai": "x-akamai",
            }
            for name, sig in cdn_sigs.items():
                if sig in body.lower():
                    cdn = name
                    break
        except Exception:
            pass
        return waf, cdn

    # ── 이메일 수집 ───────────────────────────────────────────────────────────
    def harvest_emails(self, url: str) -> list[str]:
        try:
            _, body = self.req(url, "GET", self.headers, "")
            return list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)))
        except Exception:
            return []

    def full_recon(self, fast: bool = False) -> ReconReport:
        report = ReconReport(target=self.domain)

        # 서브도메인
        subs = self.enum_subdomains_crtsh()

        base_url = f"https://{self.domain}"
        techs, hdrs, status, title = self.fingerprint_tech(base_url)
        waf, cdn = self.detect_waf_cdn(base_url)
        ip = self.resolve_ip(self.domain)
        emails = self.harvest_emails(base_url)
        report.emails.extend(emails)

        open_ports = self.port_scan(self.domain) if not fast else []
        asset = ReconAsset(
            domain=self.domain, ip=ip,
            open_ports=open_ports, technologies=techs,
            subdomains=subs, headers=hdrs,
            status=status, title=title, waf=waf, cdn=cdn,
        )
        report.assets.append(asset)

        # 서브도메인 빠른 프로빙 (상위 20개)
        for sub in subs[:20]:
            sub_url = f"https://{sub}"
            t2, h2, s2, ti2 = self.fingerprint_tech(sub_url)
            ip2 = self.resolve_ip(sub)
            report.assets.append(ReconAsset(
                domain=sub, ip=ip2, technologies=t2, status=s2, title=ti2,
            ))

        return report
