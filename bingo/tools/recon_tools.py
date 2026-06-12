"""
bingo Recon Tools — 정찰 모듈
- 서브도메인 열거
- 포트 스캔
- 기술 스택 핑거프린팅
- 디렉터리 브루트포스
- Google Dork 생성
- 헤더/SSL 분석
"""
from __future__ import annotations
import re, socket, ssl, time, threading, queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import httpx as _httpx
    _CLIENT = _httpx.Client(follow_redirects=True, verify=False, timeout=8,
                            headers={"User-Agent": "Mozilla/5.0 (bingo-recon/2.0)"})
except ImportError:
    _CLIENT = None


# ── 기술 스택 핑거프린팅 시그니처 ─────────────────────────────────
_TECH_SIGS = {
    # 서버
    "Apache":        [("header", "server", "apache")],
    "Nginx":         [("header", "server", "nginx")],
    "IIS":           [("header", "server", "microsoft-iis")],
    "LiteSpeed":     [("header", "server", "litespeed")],
    # 언어/프레임워크
    "PHP":           [("header", "x-powered-by", "php"), ("cookie", "PHPSESSID", "")],
    "ASP.NET":       [("header", "x-powered-by", "asp.net"), ("cookie", "ASP.NET_SessionId", "")],
    "Django":        [("cookie", "csrftoken", ""), ("header", "x-frame-options", "sameorigin")],
    "Laravel":       [("cookie", "laravel_session", "")],
    "Spring":        [("cookie", "JSESSIONID", ""), ("header", "x-application-context", "")],
    "Express":       [("header", "x-powered-by", "express")],
    "Ruby on Rails": [("cookie", "_session_id", ""), ("header", "x-runtime", "")],
    # CMS
    "WordPress":     [("body", "", "wp-content"), ("body", "", "wp-includes")],
    "Joomla":        [("body", "", "joomla"), ("cookie", "joomla_user_state", "")],
    "Drupal":        [("body", "", "drupal"), ("cookie", "Drupal.visitor", "")],
    "Magento":       [("body", "", "Mage.Cookies"), ("cookie", "frontend", "")],
    # CDN/Proxy
    "Cloudflare":    [("header", "cf-ray", ""), ("header", "server", "cloudflare")],
    "Varnish":       [("header", "x-varnish", ""), ("header", "via", "varnish")],
    # DB (헤더 기반)
    "MySQL":         [("body", "", "mysql_connect"), ("body", "", "MySQL Query")],
    "MongoDB":       [("body", "", "MongoDB"), ("body", "", "mongo")],
}

# ── 공통 서브도메인 목록 ──────────────────────────────────────────
_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "shop", "blog", "cdn", "static", "assets", "img", "media",
    "portal", "dashboard", "app", "mobile", "m", "login",
    "vpn", "git", "jenkins", "jira", "confluence", "kibana",
    "monitor", "status", "health", "uat", "qa", "prod", "beta",
    "internal", "corp", "intranet", "extranet", "secure", "auth",
    "sso", "id", "account", "payment", "checkout", "store",
    "forum", "community", "support", "help", "docs", "wiki",
    "mysql", "db", "database", "redis", "elasticsearch", "mongo",
    "smtp", "mx", "ns1", "ns2", "dns", "webmail", "remote",
    "cpanel", "whm", "plesk", "phpmyadmin", "backup", "old",
]

# ── 디렉터리 브루트포스 공통 목록 ────────────────────────────────
_DIR_WORDLIST = [
    "admin", "administrator", "login", "panel", "dashboard", "manager",
    "wp-admin", "wp-login.php", "phpmyadmin", "phpinfo.php", "info.php",
    "config", "conf", "backup", "bak", "old", "temp", "tmp",
    "upload", "uploads", "files", "file", "images", "img", "static",
    "assets", "api", "api/v1", "api/v2", "swagger", "swagger-ui",
    ".git", ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "server-status", "server-info", "elmah.axd", "trace.axd",
    "web.config", "app.config", "settings.php", "config.php", "db.php",
    "database.php", "connect.php", "connection.php", "setup.php",
    "install.php", "update.php", "upgrade.php", "test.php", "debug.php",
    "shell.php", "cmd.php", "c99.php", "r57.php", "webshell.php",
    "console", "terminal", "shell", "exec", "command",
    "logs", "log", "error.log", "access.log", "debug.log",
    "cgi-bin", "cgi", "scripts",
]


class Recon:
    """정찰 클래스 — 타겟에 대한 모든 정보 수집."""

    def __init__(self, target: str):
        # URL 또는 도메인 모두 허용
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc.split(":")[0]
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.findings: dict = {
            "target": target,
            "domain": self.domain,
            "ip": None,
            "technologies": [],
            "subdomains": [],
            "open_ports": [],
            "directories": [],
            "headers": {},
            "ssl": {},
            "dorks": [],
        }

    # ── IP 조회 ──────────────────────────────────────────────────
    def resolve_ip(self) -> str | None:
        try:
            ip = socket.gethostbyname(self.domain)
            self.findings["ip"] = ip
            print(f"[RECON] IP: {ip}")
            return ip
        except Exception as e:
            print(f"[RECON] IP resolve failed: {e}")
            return None

    # ── 기술 스택 핑거프린팅 ─────────────────────────────────────
    def fingerprint(self) -> list[str]:
        """헤더 + 쿠키 + 바디 기반 기술 스택 탐지."""
        if _CLIENT is None:
            return []
        try:
            r = _CLIENT.get(self.target)
            hdr = {k.lower(): v.lower() for k, v in r.headers.items()}
            hdr_str = str(hdr)
            body = r.text.lower()[:10000]
            cookie_str = str(r.cookies).lower()

            techs = []
            for tech, sigs in _TECH_SIGS.items():
                for (src, key, val) in sigs:
                    matched = False
                    if src == "header":
                        if key:
                            matched = key in hdr and (not val or val in hdr.get(key, ""))
                        else:
                            matched = val in hdr_str
                    elif src == "body":
                        matched = val.lower() in body
                    elif src == "cookie":
                        matched = key.lower() in cookie_str
                    if matched:
                        techs.append(tech)
                        break

            self.findings["technologies"] = list(set(techs))
            print(f"[RECON] Technologies: {self.findings['technologies']}")
            return self.findings["technologies"]
        except Exception as e:
            print(f"[RECON] Fingerprint failed: {e}")
            return []

    # ── HTTP 헤더 보안 분석 ───────────────────────────────────────
    def analyze_headers(self) -> dict:
        """보안 관련 헤더 분석."""
        if _CLIENT is None:
            return {}
        try:
            r = _CLIENT.get(self.target)
            hdr = dict(r.headers)
            self.findings["headers"] = hdr

            missing = []
            security_headers = [
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
                "X-XSS-Protection", "Referrer-Policy",
                "Permissions-Policy", "Cache-Control",
            ]
            for h in security_headers:
                if h.lower() not in {k.lower() for k in hdr}:
                    missing.append(h)

            if missing:
                print(f"[HEADERS] Missing security headers: {missing}")
            else:
                print(f"[HEADERS] All security headers present")

            # 민감한 헤더 노출 체크
            exposed = []
            for key, val in hdr.items():
                if any(x in key.lower() for x in ["x-powered-by", "server", "x-aspnet"]):
                    exposed.append(f"{key}: {val}")
                    print(f"[HEADERS] Info leak: {key}: {val}")

            return {"missing": missing, "exposed": exposed, "all": hdr}
        except Exception as e:
            print(f"[RECON] Header analysis failed: {e}")
            return {}

    # ── SSL/TLS 분석 ─────────────────────────────────────────────
    def analyze_ssl(self) -> dict:
        """SSL 인증서 및 프로토콜 분석."""
        result = {}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(5)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                proto = s.version()

            result["protocol"] = proto
            result["subject"] = dict(x[0] for x in cert.get("subject", []))
            result["issuer"]  = dict(x[0] for x in cert.get("issuer", []))
            result["expires"] = cert.get("notAfter", "")
            result["san"]     = [x[1] for x in cert.get("subjectAltName", [])]

            self.findings["ssl"] = result
            print(f"[SSL] Protocol: {proto}, Issuer: {result.get('issuer',{}).get('organizationName','?')}")
            print(f"[SSL] SANs: {result['san'][:5]}")
            return result
        except Exception as e:
            print(f"[SSL] Analysis failed: {e}")
            return {}

    # ── 서브도메인 열거 ───────────────────────────────────────────
    def enumerate_subdomains(self, wordlist: list[str] | None = None,
                              threads: int = 30) -> list[str]:
        """DNS 브루트포스로 서브도메인 열거."""
        wordlist = wordlist or _SUBDOMAIN_WORDLIST
        found = []

        def check(sub: str) -> str | None:
            fqdn = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except Exception:
                return None

        print(f"[RECON] Subdomain enum: {len(wordlist)} words, {threads} threads...")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(check, sub): sub for sub in wordlist}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    found.append(result)
                    print(f"[SUBDOMAIN] Found: {result}")

        self.findings["subdomains"] = found
        print(f"[RECON] Subdomains found: {len(found)}")
        return found

    # ── 포트 스캔 ────────────────────────────────────────────────
    def scan_ports(self, ports: list[int] | None = None, timeout: float = 1.0,
                   threads: int = 50) -> list[int]:
        """TCP 포트 스캔."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521,
                     3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 8888,
                     9200, 9300, 11211, 27017, 27018]

        ip = self.findings.get("ip") or self.resolve_ip()
        if not ip:
            return []

        open_ports = []
        print(f"[SCAN] Scanning {len(ports)} ports on {ip}...")

        def check_port(port: int) -> int | None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(check_port, p): p for p in ports}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    open_ports.append(result)
                    svc = _PORT_SERVICES.get(result, "unknown")
                    print(f"[PORT] {result}/tcp OPEN ({svc})")

        open_ports.sort()
        self.findings["open_ports"] = open_ports
        return open_ports

    # ── 디렉터리 브루트포스 ───────────────────────────────────────
    def dir_brute(self, wordlist: list[str] | None = None,
                  threads: int = 20, extensions: list[str] | None = None) -> list[dict]:
        """디렉터리/파일 브루트포스."""
        if _CLIENT is None:
            return []
        wordlist = wordlist or _DIR_WORDLIST
        extensions = extensions or ["", ".php", ".asp", ".aspx", ".jsp", ".html", ".txt", ".bak"]

        targets = []
        for word in wordlist:
            if "." in word:
                targets.append(word)
            else:
                for ext in extensions:
                    targets.append(word + ext)

        found = []
        print(f"[DIR] Brute forcing {len(targets)} paths...")

        def check_path(path: str) -> dict | None:
            url = f"{self.base_url}/{path.lstrip('/')}"
            try:
                r = _CLIENT.get(url)
                if r.status_code not in (404, 400, 410):
                    item = {"url": url, "status": r.status_code, "size": len(r.text)}
                    print(f"[DIR] {r.status_code} {url} ({len(r.text)}B)")
                    return item
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(check_path, p): p for p in targets}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    found.append(result)

        self.findings["directories"] = found
        return found

    # ── Google Dork 생성 ─────────────────────────────────────────
    def generate_dorks(self) -> list[str]:
        """타겟에 맞는 Google Dork 목록 생성."""
        d = self.domain
        dorks = [
            f'site:{d} filetype:php',
            f'site:{d} filetype:sql',
            f'site:{d} filetype:env',
            f'site:{d} filetype:log',
            f'site:{d} inurl:admin',
            f'site:{d} inurl:login',
            f'site:{d} inurl:upload',
            f'site:{d} inurl:config',
            f'site:{d} inurl:backup',
            f'site:{d} intitle:"index of"',
            f'site:{d} intitle:"phpMyAdmin"',
            f'site:{d} "password" filetype:txt',
            f'site:{d} "DB_PASSWORD" OR "db_password"',
            f'site:{d} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf',
            f'inurl:{d} wp-content/uploads',
            f'"{d}" "internal server error"',
        ]
        self.findings["dorks"] = dorks
        print(f"[DORK] Generated {len(dorks)} dorks for {d}")
        for dork in dorks:
            print(f"  {dork}")
        return dorks

    # ── 전체 정찰 자동화 ─────────────────────────────────────────
    def run_all(self, subdomains: bool = True, ports: bool = True,
                dirs: bool = True) -> dict:
        """전체 정찰 자동 실행."""
        print(f"\n{'='*50}")
        print(f"[RECON] Full recon: {self.target}")
        print(f"{'='*50}")

        self.resolve_ip()
        self.fingerprint()
        self.analyze_headers()
        self.analyze_ssl()
        self.generate_dorks()

        if ports:
            self.scan_ports()
        if subdomains:
            self.enumerate_subdomains()
        if dirs:
            self.dir_brute()

        return self.findings


# ── 포트 서비스 이름 ──────────────────────────────────────────────
_PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB",
}
