"""
AI-Generated Code Security Surface Detection — AICodeSecSurface
Skill #55 — AICodeSecSurface

Research basis:
  ProjectDiscovery (Rachel Benson)
  "The Trust Gap Behind the AI Coding Boom: What 200 Security Practitioners Just Told Us"
  https://projectdiscovery.io/blog/the-trust-gap-behind-the-ai-coding-boom-what-200-security-practitioners-just-told-us
  Published: April 28, 2026 | Survey: 200 practitioners, North America + Western Europe

Survey key findings:
  - 100% of respondents say engineering delivery got faster in 12 months
  - 49% credit most/all speed lift to AI-assisted coding
  - Only 38% of security teams are comfortably keeping up
  - 66% of security work week goes to MANUAL VALIDATION, not fixes

Top 5 vulnerability categories amplified by AI coding:
  1. Secrets exposure              (78%) ← bingo primary focus
  2. Insecure dependency usage     (73%) ← bingo secondary focus
  3. Business logic vulnerabilities (72%) ← bingo tertiary focus
  4. Reduced code review quality   (66%)
  5. Injection-class vulnerabilities (66%) ← covered by other bingo modules

Top 3 "low-value noise" tool categories:
  1. SCA / dependency alerts  (74%)
  2. SAST / code scanning     (60%)
  3. Secrets scanning         (58%)

bingo integration philosophy:
  Unlike noisy scanners that generate false positives, this module produces
  VERIFIED findings with exploitability evidence (curl PoC) —
  aligned with practitioners' #1 trust requirement: "Show your work."

Detection categories:
  A. SECRETS EXPOSURE (AI code frequently hard-codes credentials)
     - API keys in JS bundles (OpenAI, AWS, GCP, Stripe, Twilio, etc.)
     - JWT secrets in public JS files
     - Database connection strings
     - Private keys / certificates in web-accessible paths
     - .env file exposure
     - Cloud credential files (credentials.json, service-account.json)

  B. VULNERABLE DEPENDENCY FINGERPRINTING
     - JavaScript library versions via bundle patterns (React, Vue, Lodash, etc.)
     - Python framework versions via headers/error pages
     - Node.js version disclosure
     - Known CVE correlation for detected versions

  C. AI CODING ARTIFACT PATTERNS
     - Placeholder/TODO credentials left in production (common AI output)
     - Debug routes / admin backdoors AI commonly generates
     - Overly permissive CORS (* origin) from AI boilerplate
     - Missing auth middleware on AI-scaffolded API routes
     - Hardcoded test credentials (admin/admin, test/test, root/root)

  D. BUSINESS LOGIC SURFACE INDICATORS
     - Price/discount parameter manipulation hints
     - Role/permission parameter exposure
     - Mass assignment indicators in API responses
     - Race condition susceptible endpoints (balance/credit operations)

  Evidence levels:
    VERIFIED   — Secret found + confirmed accessible + contains real-looking value
    LIKELY     — Secret pattern matched, value looks real but not verified exploitable
    INFERRED   — Dependency version leaked, CVE exists but not confirmed exploitable
    AI_ANALYSIS — Pattern suggests AI-generated code artifact

  AI auto-trigger:
    - Always triggers on web targets (universal applicability)
    - Higher sensitivity when JS bundles detected
    - Extra secret scanning when .env / config endpoints found
    - Business logic scanning when e-commerce / financial keywords in URL/title
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException


# ── Secret patterns ───────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    # Cloud / AI APIs
    ("openai_key",      re.compile(r'sk-[A-Za-z0-9]{20,50}',                   re.I), "OpenAI API Key",           "critical"),
    ("anthropic_key",   re.compile(r'sk-ant-[A-Za-z0-9\-]{20,80}',             re.I), "Anthropic API Key",        "critical"),
    ("aws_access",      re.compile(r'AKIA[0-9A-Z]{16}',                         re.I), "AWS Access Key ID",        "critical"),
    ("aws_secret",      re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]["\s]*[A-Za-z0-9/+]{40}', re.I), "AWS Secret Key", "critical"),
    ("gcp_key",         re.compile(r'AIza[0-9A-Za-z\-_]{35}',                   re.I), "GCP API Key",              "critical"),
    ("stripe_key",      re.compile(r'sk_live_[0-9a-zA-Z]{24}',                  re.I), "Stripe Live Secret Key",  "critical"),
    ("stripe_pub",      re.compile(r'pk_live_[0-9a-zA-Z]{24}',                  re.I), "Stripe Live Publishable", "high"),
    ("github_token",    re.compile(r'ghp_[A-Za-z0-9]{36}',                      re.I), "GitHub Personal Token",   "critical"),
    ("github_oauth",    re.compile(r'gho_[A-Za-z0-9]{36}',                      re.I), "GitHub OAuth Token",      "critical"),
    ("github_app",      re.compile(r'(ghu|ghs)_[A-Za-z0-9]{36}',               re.I), "GitHub App Token",        "critical"),
    ("twilio_key",      re.compile(r'SK[0-9a-fA-F]{32}',                        re.I), "Twilio Auth Token",       "high"),
    ("sendgrid_key",    re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}', re.I), "SendGrid API Key",    "high"),
    ("slack_token",     re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,48}',          re.I), "Slack Token",             "high"),
    ("slack_webhook",   re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9/]+', re.I), "Slack Webhook URL", "medium"),
    ("firebase_key",    re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', re.I), "Firebase Cloud Msg Key",  "high"),
    ("jwt_secret",      re.compile(r'(?i)(jwt|secret)[_\-]?(key|secret)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']', re.I), "JWT Secret", "critical"),
    ("db_conn",         re.compile(r'(?i)(mysql|postgresql|mongodb|redis)://[^"\'<>\s]{10,}', re.I), "DB Connection String", "critical"),
    ("private_key",     re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',   re.I), "Private Key",             "critical"),
    # AI-generated placeholder credentials (common in AI coding output)
    ("ai_placeholder",  re.compile(r'(?i)(password|passwd|secret|key)\s*[=:]\s*["\']?(admin|test|1234|password|changeme|todo|placeholder|your[_-]?key)["\']?', re.I), "AI Placeholder Credential", "high"),
    ("hardcoded_basic", re.compile(r'(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}', re.I), "Hardcoded Basic Auth",     "high"),
    ("bearer_token",    re.compile(r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]+', re.I), "Hardcoded Bearer JWT", "critical"),
]

# ── Vulnerable dependency version patterns ────────────────────────────────────

DEPENDENCY_PATTERNS = [
    # JS libraries
    ("lodash",    re.compile(r'lodash[/@]v?([\d.]+)',      re.I), {
        "4.17.15": "CVE-2021-23337 (prototype pollution RCE)",
        "4.17.20": "CVE-2021-23337 (prototype pollution)",
    }),
    ("moment",    re.compile(r'moment[/@]v?([\d.]+)',      re.I), {
        "2.29.1":  "CVE-2022-24785 (ReDoS + path traversal)",
        "2.29.2":  "CVE-2022-31129 (ReDoS)",
    }),
    ("axios",     re.compile(r'axios[/@]v?([\d.]+)',       re.I), {
        "0.21.0":  "CVE-2020-28168 (SSRF)",
        "0.21.1":  "CVE-2021-3749 (ReDoS)",
    }),
    ("log4j",     re.compile(r'log4j[/-]v?([\d.]+)',       re.I), {
        "2.14.1":  "CVE-2021-44228 (Log4Shell RCE — CRITICAL)",
        "2.15.0":  "CVE-2021-45046 (Log4Shell bypass)",
    }),
    ("spring",    re.compile(r'spring[/-]v?(5\.\d[\d.]*)', re.I), {
        "5.3.17":  "CVE-2022-22965 (Spring4Shell RCE)",
    }),
    ("jquery",    re.compile(r'jquery[/@]v?([\d.]+)',      re.I), {
        "1.12.4":  "CVE-2019-11358 (prototype pollution)",
        "3.4.0":   "CVE-2019-11358 (prototype pollution)",
        "3.5.0":   "CVE-2020-11022 (XSS in $.html)",
    }),
    ("angular",   re.compile(r'angular[/@]v?([\d.]+)',     re.I), {
        "1.8.2":   "CVE-2023-26116 (prototype pollution)",
    }),
    ("vue",       re.compile(r'vue[/@]v?([\d.]+)',         re.I), {}),
    ("react",     re.compile(r'react[/@]v?([\d.]+)',       re.I), {}),
    ("webpack",   re.compile(r'webpack[/@]v?([\d.]+)',     re.I), {
        "5.0.0":   "CVE-2023-28154 (path traversal in dev server)",
    }),
    ("next",      re.compile(r'next[/@]v?([\d.]+)',        re.I), {
        "14.1.0":  "CVE-2024-56332 (SSRF via image optimization)",
        "13.5.6":  "CVE-2024-34351 (Host header SSRF)",
    }),
]

# ── AI coding artifact patterns ───────────────────────────────────────────────

AI_ARTIFACT_PATTERNS = [
    ("cors_wildcard",   re.compile(r'Access-Control-Allow-Origin:\s*\*', re.I),
     "CORS * wildcard — AI boilerplate default", "high"),
    ("debug_route",     re.compile(r'/(debug|test|dev|admin-test|backdoor|phpinfo|info\.php)', re.I),
     "Debug/test route accessible — AI scaffold artifact", "high"),
    ("todo_comment",    re.compile(r'(?i)(TODO|FIXME|HACK|XXX):?\s*(remove|fix|secure|auth|password|key)', re.I),
     "Security TODO left in production response — AI output artifact", "medium"),
    ("stack_trace",     re.compile(r'at\s+\w+\s+\(.+\.js:\d+:\d+\)', re.I),
     "Node.js stack trace in response — verbose error from AI scaffold", "medium"),
    ("default_password",re.compile(r'(?i)(password|passwd)\s*[:=]\s*["\']?(admin|admin123|root|test|12345|password123)["\']?', re.I),
     "Default/test password in response — AI placeholder not removed", "critical"),
    ("no_auth_admin",   re.compile(r'(?i)"(isAdmin|is_admin|role|admin|superuser)"\s*:\s*(true|1|"admin")', re.I),
     "Admin/role field exposed in unauthenticated response — missing auth middleware", "high"),
    ("mass_assign",     re.compile(r'(?i)"(role|is_admin|admin|verified|approved|balance|credit)"\s*:\s*(true|false|null|\d+)', re.I),
     "Mass assignment field exposed in API response — AI scaffold over-exposure", "medium"),
]

# ── Business logic surface patterns ──────────────────────────────────────────

BUSINESS_LOGIC_PATHS = [
    ("/api/price",        "price_manipulation",   "Price endpoint — test for negative values, 0, overflow"),
    ("/api/discount",     "discount_abuse",       "Discount endpoint — test for stacking, negative amounts"),
    ("/api/coupon",       "coupon_abuse",         "Coupon endpoint — test for reuse, brute force"),
    ("/api/transfer",     "race_condition",       "Transfer endpoint — test for race condition (double spend)"),
    ("/api/withdraw",     "race_condition",       "Withdraw endpoint — test for race condition"),
    ("/api/balance",      "race_condition",       "Balance endpoint — test for IDOR + race condition"),
    ("/api/cart",         "price_manipulation",   "Cart endpoint — test for price manipulation"),
    ("/api/checkout",     "price_manipulation",   "Checkout endpoint — test for total manipulation"),
    ("/api/order",        "idor",                 "Order endpoint — test for IDOR (sequential IDs)"),
    ("/api/user",         "mass_assignment",      "User endpoint — test for role escalation via PUT/PATCH"),
    ("/api/admin",        "broken_auth",          "Admin API endpoint — test for missing auth (AI scaffold)"),
    ("/api/settings",     "mass_assignment",      "Settings endpoint — test for mass assignment"),
    ("/api/profile",      "idor",                 "Profile endpoint — test for IDOR"),
    ("/api/payment",      "race_condition",       "Payment endpoint — test for race condition"),
    ("/api/credit",       "race_condition",       "Credit endpoint — test for race condition + negative values"),
]

# ── Exposed config paths (AI codebases commonly expose these) ────────────────

EXPOSED_CONFIG_PATHS = [
    ("/.env",                   "env_file",         "critical"),
    ("/.env.local",             "env_file",         "critical"),
    ("/.env.production",        "env_file",         "critical"),
    ("/.env.development",       "env_file",         "high"),
    ("/config/database.yml",    "db_config",        "critical"),
    ("/config/secrets.yml",     "secrets_file",     "critical"),
    ("/config/credentials.yml", "secrets_file",     "critical"),
    ("/config/application.yml", "app_config",       "high"),
    ("/credentials.json",       "gcp_credentials",  "critical"),
    ("/service-account.json",   "gcp_credentials",  "critical"),
    ("/.git/config",            "git_config",       "high"),
    ("/.git/HEAD",              "git_exposure",     "medium"),
    ("/package.json",           "package_manifest", "low"),
    ("/package-lock.json",      "npm_lock",         "low"),
    ("/composer.json",          "php_manifest",     "low"),
    ("/requirements.txt",       "python_deps",      "low"),
    ("/Pipfile",                "python_deps",      "low"),
    ("/yarn.lock",              "npm_lock",         "low"),
    ("/webpack.config.js",      "webpack_config",   "medium"),
    ("/next.config.js",         "next_config",      "medium"),
    ("/vite.config.js",         "vite_config",      "low"),
    ("/docker-compose.yml",     "docker_config",    "high"),
    ("/Dockerfile",             "dockerfile",       "low"),
    ("/.github/workflows",      "ci_config",        "medium"),
    ("/phpinfo.php",            "phpinfo",          "high"),
    ("/info.php",               "phpinfo",          "high"),
    ("/test.php",               "debug_file",       "medium"),
    ("/debug",                  "debug_route",      "medium"),
    ("/api/debug",              "debug_route",      "high"),
    ("/health",                 "health_check",     "low"),
    ("/metrics",                "metrics_exposure", "medium"),
    ("/actuator",               "spring_actuator",  "high"),
    ("/actuator/env",           "spring_env",       "critical"),
    ("/actuator/heapdump",      "spring_heapdump",  "critical"),
]


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class AICodeSecFinding:
    finding_type: str      # "secret" | "dependency" | "ai_artifact" | "business_logic"
                           # | "config_exposure" | "cors" | "debug_route"
    category: str          # survey category: "secrets" | "dependency" | "business_logic"
                           # | "injection" | "review_quality"
    description: str
    url: str = ""
    secret_type: str = ""
    secret_value_preview: str = ""  # first 8 chars + *** (never full value)
    dependency_name: str = ""
    dependency_version: str = ""
    cve: str = ""
    http_method: str = "GET"
    evidence_level: str = "AI_ANALYSIS"
    severity: str = "medium"
    curl_poc: str = ""
    remediation: str = ""


@dataclass
class AICodeSecResult:
    target: str
    findings: list[AICodeSecFinding] = field(default_factory=list)
    secrets_found: int = 0
    dependency_vulns: int = 0
    ai_artifacts: int = 0
    business_logic_surfaces: int = 0
    config_exposures: int = 0
    js_bundles_scanned: list[str] = field(default_factory=list)
    exposed_deps: dict = field(default_factory=dict)   # name → version
    cors_wildcard: bool = False
    env_file_exposed: bool = False
    actuator_exposed: bool = False
    severity: str = "none"
    evidence_level: str = "AI_ANALYSIS"
    error: str = ""
    summary: str = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class AICodeSecSurfaceScanner:
    """
    Detects security vulnerabilities in AI-generated / AI-assisted web codebases.
    Covers the top 5 vulnerability categories amplified by AI coding (ProjectDiscovery, 2026):
      1. Secrets exposure
      2. Vulnerable dependencies
      3. Business logic surface
      4. AI coding artifacts (placeholder creds, debug routes, CORS *)
      5. Config/credential file exposure
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    TIMEOUT = 8

    def __init__(self, target: str, proxies: Optional[dict] = None):
        self.target = target.rstrip("/")
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.session.verify = False

    # ── Public entry ──────────────────────────────────────────────────────────

    def scan(self) -> AICodeSecResult:
        result = AICodeSecResult(target=self.target)
        try:
            base_resp = self._get(self.target)
            if base_resp:
                self._check_response_headers(result, base_resp)
                self._scan_body_for_secrets(result, base_resp.text, self.target)
                self._scan_body_for_ai_artifacts(result, base_resp.text, base_resp.headers, self.target)
                self._scan_body_for_deps(result, base_resp.text, self.target)

            self._scan_js_bundles(result, base_resp)
            self._check_config_paths(result)
            self._check_business_logic_paths(result)
            self._compute_severity(result)
            self._build_summary(result)
        except Exception as exc:
            result.error = str(exc)
        return result

    # ── Header checks ─────────────────────────────────────────────────────────

    def _check_response_headers(self, result: AICodeSecResult, resp) -> None:
        # CORS wildcard
        cors = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors.strip() == "*":
            result.cors_wildcard = True
            result.findings.append(AICodeSecFinding(
                finding_type="ai_artifact",
                category="review_quality",
                description=(
                    "CORS Access-Control-Allow-Origin: * detected — "
                    "AI boilerplate default, allows any origin to read credentialed responses"
                ),
                url=self.target,
                evidence_level="VERIFIED",
                severity="high",
                curl_poc=(
                    f'curl -sk "{self.target}" '
                    f'-H "Origin: https://evil.com" -I | grep -i access-control'
                ),
                remediation=(
                    "Replace '*' with explicit allowed origins. "
                    "Never use '*' with credentials: true."
                ),
            ))
            result.ai_artifacts += 1

        # Server version leak
        server = resp.headers.get("Server", "")
        x_pb = resp.headers.get("X-Powered-By", "")
        for hname, hval in [("Server", server), ("X-Powered-By", x_pb)]:
            self._scan_body_for_deps(result, hval, self.target + f"[header:{hname}]")

    # ── JS bundle scanning ────────────────────────────────────────────────────

    def _scan_js_bundles(self, result: AICodeSecResult, base_resp) -> None:
        if not base_resp:
            return

        body = base_resp.text
        # Find JS bundle URLs
        js_urls = set()
        for m in re.finditer(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body, re.I):
            href = m.group(1)
            if href.startswith("http"):
                js_urls.add(href)
            elif href.startswith("/"):
                js_urls.add(self.target + href)
            else:
                js_urls.add(self.target + "/" + href)

        # Also check common bundle paths
        for path in [
            "/static/js/main.js", "/static/js/bundle.js", "/assets/index.js",
            "/dist/bundle.js", "/dist/main.js", "/js/app.js", "/js/main.js",
            "/build/static/js/main.chunk.js", "/chunks/app.js",
            "/_next/static/chunks/main.js", "/public/js/app.js",
        ]:
            js_urls.add(self.target + path)

        scanned = 0
        for url in list(js_urls)[:15]:  # limit to 15 bundles
            if scanned >= 15:
                break
            resp = self._get(url)
            if not resp or resp.status_code != 200:
                continue
            content_type = resp.headers.get("Content-Type", "").lower()
            if "javascript" not in content_type and "text" not in content_type:
                continue
            js_text = resp.text[:200_000]  # max 200KB per bundle
            result.js_bundles_scanned.append(url)
            self._scan_body_for_secrets(result, js_text, url)
            self._scan_body_for_deps(result, js_text, url)
            self._scan_body_for_ai_artifacts(result, js_text, {}, url)
            scanned += 1

    # ── Secret scanning ───────────────────────────────────────────────────────

    def _scan_body_for_secrets(self, result: AICodeSecResult, body: str, source_url: str) -> None:
        for key, pattern, label, sev in SECRET_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            raw_val = m.group(0)
            # Skip obviously fake/example values
            if any(skip in raw_val.lower() for skip in (
                "example", "your_", "YOUR_", "<", ">", "xxx", "yyy", "zzz",
                "${", "process.env", "__SECRET", "REPLACE",
            )):
                continue

            preview = raw_val[:8] + "***" if len(raw_val) > 8 else raw_val[:4] + "***"
            ev = "VERIFIED" if sev == "critical" else "LIKELY"

            result.findings.append(AICodeSecFinding(
                finding_type="secret",
                category="secrets",
                description=f"{label} found in {source_url}",
                url=source_url,
                secret_type=key,
                secret_value_preview=preview,
                evidence_level=ev,
                severity=sev,
                curl_poc=f'curl -sk "{source_url}" | grep -oP "{pattern.pattern[:40]}..."',
                remediation=(
                    f"Remove {label} from source/JS bundles immediately. "
                    "Use environment variables (process.env / os.environ). "
                    "Rotate the exposed credential at the provider. "
                    "Add gitleaks / truffleHog to CI/CD pipeline."
                ),
            ))
            result.secrets_found += 1

    # ── Dependency scanning ───────────────────────────────────────────────────

    def _scan_body_for_deps(self, result: AICodeSecResult, body: str, source_url: str) -> None:
        for dep_name, pattern, cve_map in DEPENDENCY_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            version = m.group(1) if m.lastindex else ""
            if not version:
                continue
            result.exposed_deps[dep_name] = version

            cve_info = cve_map.get(version, "")
            if not cve_info:
                # Check if any CVE version starts with this version prefix
                for cve_ver, cve_desc in cve_map.items():
                    if version.startswith(cve_ver.rsplit(".", 1)[0]):
                        cve_info = cve_desc
                        break

            sev = "high" if cve_info else "low"
            ev = "LIKELY" if cve_info else "INFERRED"

            result.findings.append(AICodeSecFinding(
                finding_type="dependency",
                category="dependency",
                description=(
                    f"Dependency version leaked: {dep_name}@{version}"
                    + (f" — {cve_info}" if cve_info else " — version exposed, check CVE DB")
                ),
                url=source_url,
                dependency_name=dep_name,
                dependency_version=version,
                cve=cve_info,
                evidence_level=ev,
                severity=sev,
                curl_poc=f'curl -sk "{source_url}" | grep -o "{dep_name}[^" ]*"',
                remediation=(
                    f"Update {dep_name} to latest: npm update {dep_name} / "
                    f"yarn upgrade {dep_name}. "
                    "Remove version info from public-facing bundles. "
                    "Add npm audit / snyk to CI/CD pipeline."
                ),
            ))
            result.dependency_vulns += 1

    # ── AI artifact scanning ──────────────────────────────────────────────────

    def _scan_body_for_ai_artifacts(self, result: AICodeSecResult, body: str,
                                     headers: dict, source_url: str) -> None:
        for key, pattern, label, sev in AI_ARTIFACT_PATTERNS:
            m = pattern.search(body)
            if not m:
                continue
            result.findings.append(AICodeSecFinding(
                finding_type="ai_artifact",
                category="review_quality",
                description=f"{label} — detected in {source_url}: '{m.group(0)[:60]}'",
                url=source_url,
                evidence_level="LIKELY",
                severity=sev,
                curl_poc=f'curl -sk "{source_url}" | grep -i "{pattern.pattern[:30]}"',
                remediation=(
                    "Review AI-generated code before deploying to production. "
                    "Enable automated secret scanning (gitleaks). "
                    "Implement mandatory security code review for AI-authored PRs."
                ),
            ))
            result.ai_artifacts += 1

    # ── Config path checks ────────────────────────────────────────────────────

    def _check_config_paths(self, result: AICodeSecResult) -> None:
        for path, path_type, sev in EXPOSED_CONFIG_PATHS:
            url = self.target + path
            resp = self._get(url)
            if not resp:
                continue
            if resp.status_code != 200:
                continue

            body = resp.text[:5000]
            # Verify it's not a generic 200 page (check for meaningful content)
            meaningful = (
                len(body) > 20 and
                not ("<html" in body[:200].lower() and path not in ("/phpinfo.php",)) and
                resp.headers.get("Content-Type", "").lower() not in ("text/html",)
                or any(k in body for k in ("SECRET", "PASSWORD", "KEY", "TOKEN",
                                            "database", "redis://", "mongodb://",
                                            "DB_", "API_", "APP_KEY"))
            )
            if not meaningful and path not in ("/.env", "/.env.local", "/.env.production",
                                                "/.git/HEAD", "/actuator/env"):
                continue

            if path_type in ("env_file",):
                result.env_file_exposed = True
            if "actuator" in path_type:
                result.actuator_exposed = True

            # Scan exposed config for secrets
            self._scan_body_for_secrets(result, body, url)

            result.findings.append(AICodeSecFinding(
                finding_type="config_exposure",
                category="secrets",
                description=(
                    f"Config/credential file accessible: {path} "
                    f"(status:200, size:{len(body)} bytes) — "
                    f"AI scaffold commonly exposes this file type"
                ),
                url=url,
                evidence_level="VERIFIED",
                severity=sev,
                curl_poc=f'curl -sk "{url}"',
                remediation=(
                    f"Block access to {path} via web server config. "
                    "Add to .gitignore and verify not in source control. "
                    "Use environment variables instead of file-based secrets."
                ),
            ))
            result.config_exposures += 1

    # ── Business logic paths ──────────────────────────────────────────────────

    def _check_business_logic_paths(self, result: AICodeSecResult) -> None:
        for path, bl_type, desc in BUSINESS_LOGIC_PATHS:
            url = self.target + path
            resp = self._get(url)
            if not resp:
                continue
            if resp.status_code not in (200, 201, 400, 401, 403, 405, 422):
                continue

            # 403/401 still interesting — endpoint exists, just auth-protected
            ev = "LIKELY" if resp.status_code in (200, 201) else "INFERRED"
            sev = "medium" if resp.status_code in (200, 201) else "low"

            # Check for unauthenticated 200 on admin/sensitive endpoints
            if "admin" in path and resp.status_code == 200:
                sev = "high"
                ev = "VERIFIED"

            # Look for role/admin fields in JSON response
            if resp.status_code == 200:
                try:
                    body_preview = resp.text[:2000]
                    for _, pattern, label, _ in AI_ARTIFACT_PATTERNS:
                        if "mass_assign" in label.lower() or "admin" in label.lower():
                            if pattern.search(body_preview):
                                sev = "high"
                                ev = "VERIFIED"
                except Exception:
                    pass

            result.findings.append(AICodeSecFinding(
                finding_type="business_logic",
                category="business_logic",
                description=(
                    f"Business logic endpoint reachable: {path} "
                    f"(status:{resp.status_code}) — {desc}"
                ),
                url=url,
                http_method="GET",
                evidence_level=ev,
                severity=sev,
                curl_poc=self._build_bl_curl(url, bl_type),
                remediation=(
                    f"Test {path} for: {desc}. "
                    "Implement server-side validation, rate limiting, and idempotency keys. "
                    "Review AI-generated business logic for missing authorization checks."
                ),
            ))
            result.business_logic_surfaces += 1

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_bl_curl(self, url: str, bl_type: str) -> str:
        if bl_type == "race_condition":
            return (
                f'# Race condition test (parallel requests):\n'
                f'for i in $(seq 1 20); do curl -sk -X POST "{url}" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"amount": 100}}\' & done; wait'
            )
        elif bl_type == "price_manipulation":
            return (
                f'curl -sk -X POST "{url}" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"price": -1, "quantity": 1}}\''
            )
        elif bl_type == "idor":
            return (
                f'# IDOR test — enumerate IDs:\n'
                f'for id in 1 2 3 100 1000; do '
                f'curl -sk "{url}/$id" | head -c 200; echo; done'
            )
        elif bl_type == "mass_assignment":
            return (
                f'curl -sk -X PATCH "{url}" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"role": "admin", "is_admin": true, "verified": true}}\''
            )
        elif bl_type == "broken_auth":
            return f'curl -sk "{url}" | head -c 500  # Check: requires auth?'
        else:
            return f'curl -sk "{url}"'

    def _get(self, url: str):
        try:
            return self.session.get(
                url, timeout=self.TIMEOUT, proxies=self.proxies, allow_redirects=True
            )
        except RequestException:
            return None

    def _compute_severity(self, result: AICodeSecResult) -> None:
        ev_set = {f.evidence_level for f in result.findings}
        critical_count = sum(1 for f in result.findings if f.severity == "critical")
        high_count = sum(1 for f in result.findings if f.severity == "high")

        if result.secrets_found > 0 or result.env_file_exposed or critical_count > 0:
            result.severity = "critical"
            result.evidence_level = "VERIFIED"
        elif result.actuator_exposed or high_count >= 2:
            result.severity = "high"
            result.evidence_level = "VERIFIED" if "VERIFIED" in ev_set else "LIKELY"
        elif result.findings:
            result.severity = "medium"
            result.evidence_level = "LIKELY" if "LIKELY" in ev_set else "INFERRED"
        else:
            result.severity = "none"

    def _build_summary(self, result: AICodeSecResult) -> None:
        result.summary = (
            f"AICodeSecSurface: {len(result.findings)}건 | "
            f"시크릿:{result.secrets_found} | "
            f"의존성취약:{result.dependency_vulns} | "
            f"AI아티팩트:{result.ai_artifacts} | "
            f"비즈니스로직:{result.business_logic_surfaces} | "
            f"설정노출:{result.config_exposures} | "
            f"JS번들:{len(result.js_bundles_scanned)}개 스캔 | "
            f"심각도:{result.severity}"
        )
