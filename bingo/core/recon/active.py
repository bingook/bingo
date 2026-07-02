"""
bingo/core/recon/active.py — 액티브 자산 수집 모듈 v1.0 (v3.5.22)

외부 툴이 없어도 Python 소켓으로 동작하고,
툴이 있으면 자동으로 활용 (httpx, subfinder, amass, nmap, masscan)

기능:
  • 서브도메인 브루트포스 (내장 워드리스트 + subfinder/amass 래퍼)
  • HTTP 프로빙 (httpx 래퍼 → Python urllib 폴백)
  • 포트 스캔 (Python socket → nmap 래퍼)
  • JS 엔드포인트 마이닝 (API 경로 자동 추출)
  • WAF 지문 감지
  • 기술 스택 자동 식별
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path


# ── 데이터 구조 ──────────────────────────────────────────────────────────────

@dataclass
class LiveHost:
    url: str
    ip: str = ""
    status: int = 0
    title: str = ""
    technologies: list[str] = field(default_factory=list)
    server: str = ""
    content_length: int = 0
    redirect_url: str = ""
    waf: str = ""
    interesting: bool = False   # P0/P1 징후 있음


@dataclass
class PortResult:
    host: str
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)  # port → service name


@dataclass
class ActiveResult:
    target: str
    live_hosts: list[LiveHost] = field(default_factory=list)
    port_results: list[PortResult] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    new_subdomains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        total_ports = sum(len(p.open_ports) for p in self.port_results)
        interesting = [h for h in self.live_hosts if h.interesting]
        return (
            f"  🌐 Live Hosts   : {len(self.live_hosts)}\n"
            f"  ⚠️  Interesting  : {len(interesting)}\n"
            f"  🔌 Open Ports   : {total_ports}\n"
            f"  🔗 JS Endpoints : {len(self.js_endpoints)}\n"
            f"  📋 New Subs     : {len(self.new_subdomains)}"
        )


# ── 포트 정의 ─────────────────────────────────────────────────────────────────

HIGH_RISK_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    1433:  "MSSQL",
    1521:  "Oracle",
    2375:  "Docker API ⚡",
    2379:  "etcd k8s ⚡",
    3306:  "MySQL",
    3389:  "RDP",
    4848:  "GlassFish Admin",
    5432:  "PostgreSQL",
    5900:  "VNC",
    5984:  "CouchDB",
    6379:  "Redis ⚡",
    7001:  "WebLogic",
    8009:  "AJP Ghostcat",
    8080:  "HTTP Alt",
    8161:  "ActiveMQ",
    8443:  "HTTPS Alt",
    8888:  "Jupyter Notebook ⚡",
    9000:  "Portainer/Sonar",
    9090:  "Prometheus/Jenkins",
    9200:  "Elasticsearch ⚡",
    9300:  "ES Transport",
    11211: "Memcached ⚡",
    27017: "MongoDB ⚡",
    50000: "Jenkins",
}

# 즉각 RCE/데이터 덤프 가능한 포트 (P0)
P0_PORTS = {2375, 6379, 9200, 11211, 27017, 8888, 2379}
P1_PORTS = {4848, 8161, 7001, 50000, 5984, 5432, 1433, 3306}

_UA = "bingo-recon/3.5.22"


# ── 서브도메인 수집 ───────────────────────────────────────────────────────────

# 내장 워드리스트 (자주 쓰이는 서브도메인)
_WORDLIST: list[str] = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "shop", "blog", "cdn", "static", "assets", "img", "media",
    "portal", "dashboard", "app", "mobile", "m", "login",
    "vpn", "git", "jenkins", "jira", "confluence", "kibana",
    "monitor", "status", "health", "uat", "qa", "prod", "beta",
    "internal", "corp", "intranet", "secure", "auth",
    "sso", "id", "account", "payment", "checkout", "store",
    "forum", "community", "support", "docs", "wiki",
    "api2", "api3", "apiv2", "apiv3", "v1", "v2", "backend",
    "office", "remote", "webmail", "smtp",
    "ns1", "ns2", "mx", "mx1", "mx2",
    "old", "legacy", "archive", "backup",
    "demo", "sandbox", "lab", "pre", "stg",
    "crm", "erp", "oa", "hr", "finance", "ops",
    "mysql", "db", "database", "redis", "mongo", "elastic", "es",
    "s3", "storage", "files", "download", "upload",
    "search", "suggest",
    # 한국 특화
    "bbs", "board", "xe", "gnuboard", "cafe",
    "member", "user", "manage", "manager",
    "order", "delivery", "coupon", "point",
    "news", "notice", "event", "promotion",
    "mypage", "myinfo", "myaccount",
    "web", "web2", "new", "test2", "dev2",
    "open", "openapi", "gateway",
    "ws", "wss", "socket", "push",
]


def subdomain_bruteforce(
    domain: str,
    wordlist: list[str] | None = None,
    max_workers: int = 150,
    timeout: float = 1.2,
) -> list[str]:
    """내장 워드리스트 기반 서브도메인 DNS 브루트포스"""
    if wordlist is None:
        wordlist = _WORDLIST

    found: list[str] = []
    _prev_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    def _check(word: str) -> str | None:
        fqdn = f"{word}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None)
            return fqdn
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check, w): w for w in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    socket.setdefaulttimeout(_prev_timeout)
    return sorted(found)


def subfinder_enum(domain: str, timeout: int = 90) -> list[str]:
    """subfinder CLI 래퍼 (설치된 경우 사용, 없으면 빈 리스트)"""
    try:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-all", "-silent", "-timeout", "8"],
            capture_output=True, text=True, timeout=timeout,
        ).stdout
        return [line.strip() for line in out.strip().split("\n") if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []


def amass_enum(domain: str, timeout: int = 120) -> list[str]:
    """amass passive 래퍼"""
    try:
        out = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-nocolor"],
            capture_output=True, text=True, timeout=timeout,
        ).stdout
        return [line.strip() for line in out.strip().split("\n") if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []


# ── HTTP 프로빙 ───────────────────────────────────────────────────────────────

_WAF_HEADERS: dict[str, str] = {
    "cf-ray":             "Cloudflare",
    "x-sucuri-id":        "Sucuri",
    "x-fw-server":        "Fastly",
    "server-timing":      "Akamai (possible)",
    "x-guard":            "TrusGuard (KR)",
    "x-cloudbric":        "Cloudbric (KR)",
    "x-kinx":             "KINX CDN (KR)",
}

_TECH_PATTERNS: list[tuple[str, str, str]] = [
    # (type, header/body, pattern)
    ("header", "server",       "apache"),
    ("header", "server",       "nginx"),
    ("header", "server",       "iis"),
    ("header", "server",       "cloudflare"),
    ("header", "x-powered-by", "php"),
    ("header", "x-powered-by", "asp.net"),
    ("header", "x-powered-by", "express"),
    ("cookie", "PHPSESSID",    ""),
    ("cookie", "ASP.NET_SessionId", ""),
    ("cookie", "JSESSIONID",   ""),
    ("body",   "",             "wp-content"),
    ("body",   "",             "wp-includes"),
    ("body",   "",             "gnuboard"),
    ("body",   "",             "xe_site_key"),
    ("body",   "",             "__next_data__"),
    ("body",   "",             "react_root"),
    ("body",   "",             "__vue__"),
    ("body",   "",             "spring boot"),
    ("body",   "",             "laravel"),
]


def _fingerprint(headers: dict[str, str], body: str, cookies: str) -> tuple[list[str], str]:
    """기술 스택 + WAF 감지"""
    techs: list[str] = []
    waf = ""
    body_lower = body.lower()

    # WAF
    for hdr, waf_name in _WAF_HEADERS.items():
        if hdr in headers:
            waf = waf_name
            break

    # 기술스택
    for kind, key, val in _TECH_PATTERNS:
        if kind == "header":
            hdr_val = headers.get(key, "").lower()
            if val in hdr_val:
                techs.append(key.title())
        elif kind == "cookie":
            if key.lower() in cookies.lower():
                techs.append(key)
        elif kind == "body":
            if val in body_lower:
                techs.append(val.title())

    return list(dict.fromkeys(techs)), waf  # 중복 제거, 순서 유지


def probe_python(
    subdomains: list[str],
    ports: list[int] | None = None,
    timeout: float = 6.0,
    max_workers: int = 60,
) -> list[LiveHost]:
    """Python urllib 기반 HTTP 프로빙 (외부 툴 불필요)"""
    if ports is None:
        ports = [443, 80, 8443, 8080, 3000, 5000]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    live: list[LiveHost] = []

    def _probe(subdomain: str, port: int) -> LiveHost | None:
        scheme = "https" if port in (443, 8443, 4443) else "http"
        port_str = f":{port}" if port not in (80, 443) else ""
        url = f"{scheme}://{subdomain}{port_str}"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw_body = resp.read(16384)
                body = raw_body.decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in dict(resp.headers).items()}
                cookies = headers.get("set-cookie", "")

                # 타이틀
                tm = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.I)
                title = tm.group(1).strip() if tm else ""

                techs, waf = _fingerprint(headers, body, cookies)

                # P0/P1 경로 감지
                interesting = any(
                    p in url for p in [
                        "/admin", "/manager", "/phpmyadmin", "/adminer",
                        "/.env", "/.git", "/swagger", "/actuator",
                    ]
                )

                return LiveHost(
                    url=url,
                    status=resp.status,
                    title=title,
                    server=headers.get("server", ""),
                    technologies=techs,
                    waf=waf,
                    content_length=int(headers.get("content-length", 0)),
                    interesting=interesting,
                )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 429):
                return LiveHost(
                    url=url,
                    status=e.code,
                    interesting=(e.code == 403),  # 403은 WAF 뒤 뭔가 있음
                )
            return None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for sub in subdomains:
            for port in ports:
                futures.append(executor.submit(_probe, sub, port))
        for future in as_completed(futures):
            r = future.result()
            if r:
                live.append(r)

    return live


def probe_httpx(subdomains: list[str], ports: list[int] | None = None) -> list[LiveHost]:
    """httpx CLI 래퍼 (없으면 Python 폴백)"""
    if not subdomains:
        return []

    try:
        subprocess.run(["httpx", "-version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return probe_python(subdomains, ports)

    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(subdomains))
            tmp = f.name

        port_list = ",".join(map(str, ports or [80, 443, 8080, 8443, 8888, 3000, 5000, 9090]))
        cmd = [
            "httpx", "-l", tmp,
            "-title", "-status-code", "-tech-detect",
            "-ip", "-server", "-content-length",
            "-ports", port_list,
            "-threads", "60",
            "-follow-redirects",
            "-json", "-silent",
            "-timeout", "6",
        ]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
        Path(tmp).unlink(missing_ok=True)

        live: list[LiveHost] = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                host = LiveHost(
                    url=d.get("url", ""),
                    ip=d.get("host") or (d.get("a") or [""])[0],
                    status=d.get("status-code", 0),
                    title=d.get("title", ""),
                    technologies=d.get("tech", []),
                    server=d.get("webserver", ""),
                    content_length=d.get("content-length", 0),
                )
                live.append(host)
            except (json.JSONDecodeError, KeyError):
                continue
        return live

    except Exception:
        return probe_python(subdomains, ports)


# ── 포트 스캔 ─────────────────────────────────────────────────────────────────

def port_scan_python(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 0.6,
    max_workers: int = 150,
) -> PortResult:
    """Python socket 기반 포트 스캔 (nmap 없어도 동작)"""
    if ports is None:
        ports = list(HIGH_RISK_PORTS.keys())

    open_ports: list[int] = []

    def _check(port: int) -> int | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port if result == 0 else None
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check, p): p for p in ports}
        for f in as_completed(futures):
            r = f.result()
            if r is not None:
                open_ports.append(r)

    services = {p: HIGH_RISK_PORTS.get(p, "unknown") for p in open_ports}
    return PortResult(host=host, open_ports=sorted(open_ports), services=services)


def port_scan_nmap(host: str, args: str = "-T4 -F --open") -> PortResult:
    """nmap 래퍼 (없으면 Python 폴백)"""
    try:
        cmd = ["nmap"] + args.split() + ["-oG", "-", host]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout
        ports = [int(m) for m in re.findall(r"(\d+)/open", out)]
        return PortResult(host=host, open_ports=sorted(ports),
                         services={p: HIGH_RISK_PORTS.get(p, "?") for p in ports})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return port_scan_python(host)


def masscan_scan(targets: list[str], rate: int = 300) -> list[PortResult]:
    """masscan 래퍼 (설치된 경우)"""
    if not targets:
        return []
    try:
        subprocess.run(["masscan", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    ports = ",".join(map(str, HIGH_RISK_PORTS.keys()))
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            tmp = f.name

        out_file = tmp + ".json"
        cmd = [
            "masscan", "-iL", tmp,
            "-p", ports,
            "--rate", str(rate),
            "-oJ", out_file,
        ]
        subprocess.run(cmd, capture_output=True, timeout=120)
        Path(tmp).unlink(missing_ok=True)

        if not Path(out_file).exists():
            return []

        raw = Path(out_file).read_text()
        Path(out_file).unlink(missing_ok=True)
        data = json.loads(raw)

        host_ports: dict[str, list[int]] = {}
        for entry in data:
            ip = entry.get("ip", "")
            port = entry.get("ports", [{}])[0].get("port", 0)
            if ip and port:
                host_ports.setdefault(ip, []).append(port)

        return [
            PortResult(host=h, open_ports=sorted(ps),
                      services={p: HIGH_RISK_PORTS.get(p, "?") for p in ps})
            for h, ps in host_ports.items()
        ]
    except Exception:
        return []


# ── JS 엔드포인트 마이닝 ──────────────────────────────────────────────────────

_EP_PATTERN = re.compile(
    r"""['"]((?:/api|/v\d|/user|/admin|/auth|/login|/register|/account|/service|/system)[^'"<>\s]{1,150})['"]""",
    re.I,
)

_SECRET_PATTERN = re.compile(
    r"""(?:api[_-]?key|apikey|secret|password|token|auth)['":\s=]+['"]([A-Za-z0-9/+_\-]{20,})['"]""",
    re.I,
)


def mine_js_endpoints(url: str) -> tuple[list[str], list[str]]:
    """
    URL → JS 파일들에서 API 엔드포인트 + 시크릿 패턴 추출
    
    Returns:
        (endpoints, potential_secrets)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints: set[str] = set()
    secrets: list[str] = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            html = resp.read(1000000).decode("utf-8", errors="replace")

        # JS 파일 경로 추출
        js_paths = re.findall(r"""src=["']([^"']+\.js(?:[?#][^"']*)?)["']""", html, re.I)

        for js_path in js_paths[:25]:
            if not js_path.startswith("http"):
                js_path = urllib.parse.urljoin(url, js_path)
            try:
                js_req = urllib.request.Request(js_path, headers={"User-Agent": _UA})
                with urllib.request.urlopen(js_req, timeout=8, context=ctx) as jr:
                    content = jr.read(3000000).decode("utf-8", errors="replace")

                for m in _EP_PATTERN.findall(content):
                    endpoints.add(m)
                for s in _SECRET_PATTERN.findall(content):
                    secrets.append(s[:50] + "…")
            except Exception:
                continue

    except Exception:
        pass

    return sorted(endpoints), list(dict.fromkeys(secrets))[:20]


# ── 통합 액티브 수집 ──────────────────────────────────────────────────────────

def run_active(
    domain: str,
    subdomains: list[str] | None = None,
    ips: list[str] | None = None,
    do_bruteforce: bool = True,
    do_port_scan: bool = True,
    do_js_mining: bool = True,
    verbose: bool = True,
) -> ActiveResult:
    """
    통합 액티브 수집 파이프라인

    Args:
        domain        : 대상 도메인
        subdomains    : 이미 수집된 서브도메인 (없으면 내부에서 수집)
        ips           : 이미 수집된 IP 목록 (포트 스캔에 사용)
        do_bruteforce : 서브도메인 브루트포스 여부
        do_port_scan  : 포트 스캔 여부
        do_js_mining  : JS 엔드포인트 마이닝 여부
        verbose       : 진행 상황 출력
    """
    result = ActiveResult(target=domain)
    _p = print if verbose else (lambda *a, **k: None)

    # 1. 서브도메인 수집
    all_subs = list(subdomains or [])

    if do_bruteforce:
        _p(f"  [1/4] 🔎 서브도메인 수집...")

        # subfinder 먼저 시도 (빠름)
        sf = subfinder_enum(domain)
        if sf:
            _p(f"       subfinder: {len(sf)}개")
            all_subs.extend(sf)

        # 내장 워드리스트 브루트포스
        bf = subdomain_bruteforce(domain)
        _p(f"       브루트포스: {len(bf)}개 발견")
        all_subs.extend(bf)

        all_subs = sorted(set(all_subs))
        result.new_subdomains = all_subs
        _p(f"       총 {len(all_subs)}개 서브도메인")
    else:
        result.new_subdomains = all_subs

    if not all_subs:
        all_subs = [domain]

    # 2. HTTP 프로빙
    _p(f"  [2/4] 🌐 HTTP 프로빙 ({len(all_subs)} 호스트)...")
    result.live_hosts = probe_httpx(all_subs)
    if not result.live_hosts:
        result.live_hosts = probe_python(all_subs)
    interesting = [h for h in result.live_hosts if h.interesting]
    _p(f"       생존: {len(result.live_hosts)}개  ⚠️ 즉시 확인: {len(interesting)}개")

    # 3. 포트 스캔
    if do_port_scan and ips:
        _p(f"  [3/4] 🔌 포트 스캔 ({len(ips)} IPs)...")

        # masscan 먼저 시도
        masscan_results = masscan_scan(ips[:20])
        if masscan_results:
            result.port_results = masscan_results
        else:
            # Python socket 스캔 (느리지만 의존성 없음)
            for ip in ips[:15]:
                pr = port_scan_python(ip)
                if pr.open_ports:
                    result.port_results.append(pr)

        total_open = sum(len(p.open_ports) for p in result.port_results)
        risky = sum(
            len(set(p.open_ports) & P0_PORTS)
            for p in result.port_results
        )
        _p(f"       {total_open} 포트 열림  🔴 즉각 위험: {risky}")
    else:
        _p(f"  [3/4] 🔌 포트 스캔 건너뜀 (IP 없음 또는 비활성화)")

    # 4. JS 마이닝
    if do_js_mining:
        _p(f"  [4/4] 🔗 JS 엔드포인트 마이닝...")
        all_endpoints: set[str] = set()
        all_secrets: list[str] = []

        # 상태 200인 호스트 우선
        probe_targets = [
            h.url for h in result.live_hosts
            if h.status == 200
        ][:8]

        for url in probe_targets:
            try:
                eps, secs = mine_js_endpoints(url)
                all_endpoints.update(eps)
                all_secrets.extend(secs)
            except Exception:
                continue

        result.js_endpoints = sorted(all_endpoints)
        if all_secrets:
            # secrets는 별도 필드로 반환
            result._js_secrets = list(dict.fromkeys(all_secrets))  # type: ignore
        _p(f"       {len(result.js_endpoints)} 엔드포인트  🔑 시크릿 패턴: {len(all_secrets)}")

    return result
