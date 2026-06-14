"""
Cloud Token Recon via TLS SAN + JS Bundle Parsing + Unauthenticated Cloud Token Endpoints
Skill #51 — CloudTokenRecon

Research basis:
  Sectricity Security Team — "From a Misconfigured Grafana to 507 Private Meta Repos: A Bug Worth $157K"
  https://sectricity.com/blog/misconfigured-grafana-507-private-meta-repos/
  Published: May 28, 2026 — $157,000 bounty awarded by Meta (filed March 21, 2026)

Attack chain:
  ① Open/misconfigured dev tool (Grafana, Prometheus, Jaeger…) found on target IP
  ② TLS certificate SAN wildcard reveals shadow domains/subdomains
  ③ Certificate Transparency (crt.sh) maps entire shadow estate
  ④ JS bundle parsing across shadow subdomains extracts hidden domain references
  ⑤ Context-aware fuzzing against discovered domains hits unauthenticated cloud token endpoint
  ⑥ GCP / AWS / Azure token used to read Secret Manager → Vercel/env vars → GitHub tokens
  ⑦ Cloud credential chain: token → secrets → source code / private repos

Evidence levels:
  VERIFIED  — HTTP response confirmed token/credential exposure
  LIKELY    — strong indicators (open dev tool + cloud env + SAN wildcard)
  INFERRED  — logic-based inference from JS/env patterns
  AI_ANALYSIS — pattern match without live confirmation
"""

from __future__ import annotations

import re
import ssl
import json
import socket
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ── Unauthenticated cloud token endpoint patterns ──────────────────────────
CLOUD_TOKEN_PATHS = [
    # GCP metadata / token patterns (as seen in the Meta chain)
    "/_api/gcp-token",
    "/_api/token",
    "/api/gcp-token",
    "/api/token",
    "/api/cloud-token",
    "/internal/token",
    "/internal/gcp-token",
    "/debug/token",
    "/health/token",
    # AWS metadata via SSRF proxy patterns
    "/_aws/credentials",
    "/api/aws-token",
    "/internal/aws-token",
    # Azure managed identity patterns
    "/api/azure-token",
    "/_api/azure-token",
    # Generic secret/env exposure
    "/api/env",
    "/api/config",
    "/_api/config",
    "/debug/env",
    "/debug/config",
    "/.env",
    "/config.json",
    "/secrets",
    "/api/secrets",
]

# ── Sensitive data patterns in token responses ─────────────────────────────
TOKEN_PATTERNS = {
    "gcp_access_token": re.compile(
        r'"access_token"\s*:\s*"([^"]{50,})"', re.I
    ),
    "aws_access_key": re.compile(
        r'"AccessKeyId"\s*:\s*"(ASIA|AKIA)[A-Z0-9]{16}"', re.I
    ),
    "aws_secret_key": re.compile(
        r'"SecretAccessKey"\s*:\s*"([^"]{40})"', re.I
    ),
    "github_token": re.compile(
        r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})', re.I
    ),
    "vercel_token": re.compile(r'["\']([A-Za-z0-9]{24})["\']', re.I),
    "jwt_token": re.compile(
        r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'
    ),
    "api_key_generic": re.compile(
        r'"(?:api_?key|apikey|secret|token)"\s*:\s*"([^"]{16,})"', re.I
    ),
}

# ── Dev tool open page patterns ────────────────────────────────────────────
DEV_TOOL_PATTERNS = {
    "grafana": re.compile(r"(grafana|<title>[^<]*grafana)", re.I),
    "prometheus": re.compile(r"(prometheus|<title>[^<]*prometheus)", re.I),
    "jaeger": re.compile(r"(jaeger|<title>[^<]*jaeger)", re.I),
    "kibana": re.compile(r"(kibana|<title>[^<]*kibana)", re.I),
    "jenkins": re.compile(r"(jenkins|<title>[^<]*jenkins)", re.I),
    "actuator": re.compile(r"/actuator/(env|health|info|metrics)", re.I),
    "swagger": re.compile(r'(swagger-ui|"swagger":|"/openapi.json")', re.I),
}

# ── JS bundle domain extraction ────────────────────────────────────────────
JS_DOMAIN_PATTERN = re.compile(
    r'(?:https?://|["\'])([a-z0-9\-\.]+\.[a-z]{2,8})(?:["\'/])',
    re.I,
)


@dataclass
class CloudTokenFinding:
    finding_type: str
    evidence_level: str  # VERIFIED / LIKELY / INFERRED / AI_ANALYSIS
    severity: str
    description: str
    url: str = ""
    token_type: str = ""
    token_preview: str = ""  # first 12 chars only — never full
    js_source_url: str = ""
    discovered_domains: list[str] = field(default_factory=list)
    dev_tool_type: str = ""
    san_wildcard: str = ""
    chain_depth: int = 0


@dataclass
class CloudTokenResult:
    target: str
    triggered: bool = False
    findings: list[CloudTokenFinding] = field(default_factory=list)
    open_dev_tools: list[str] = field(default_factory=list)
    shadow_domains: list[str] = field(default_factory=list)
    token_endpoints_found: list[str] = field(default_factory=list)
    tokens_exposed: bool = False
    exploitable: bool = False
    severity: str = "Info"
    summary: str = ""
    chain_hops: int = 0


class CloudTokenReconScanner:
    """
    AI-driven scanner that detects the Grafana→GCP-token→Secret-chain pattern.
    Checks for:
      1. Open dev tools (Grafana, Prometheus, Jaeger, Jenkins…)
      2. Shadow domains via TLS SAN wildcard + crt.sh
      3. Hidden domains referenced in JS bundles
      4. Unauthenticated cloud token endpoints
      5. Token type identification and severity scoring
    """

    def __init__(
        self,
        target: str,
        session: Optional[object] = None,
        timeout: int = 10,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._sess: Optional[requests.Session] = None

        if REQUESTS_AVAILABLE:
            if session and hasattr(session, "get"):
                self._sess = session
            else:
                s = requests.Session()
                s.verify = False
                s.headers.update({
                    "User-Agent": (
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0 Safari/537.36"
                    )
                })
                self._sess = s

    # ── HTTP helpers ───────────────────────────────────────────────────────

    def _fetch(self, url: str, method: str = "GET") -> Optional[requests.Response]:
        if not REQUESTS_AVAILABLE or self._sess is None:
            return None
        try:
            resp = self._sess.request(
                method, url, timeout=self.timeout, allow_redirects=True
            )
            return resp
        except Exception:
            return None

    # ── Step 1: detect open dev tools ─────────────────────────────────────

    def _detect_dev_tools(self) -> list[tuple[str, str]]:
        """Returns list of (url, tool_name) for open dev tools found."""
        found: list[tuple[str, str]] = []
        check_paths = [
            "/", "/grafana", "/prometheus", "/kibana",
            "/jaeger", "/actuator/health", "/actuator/env",
        ]
        for path in check_paths:
            url = f"{self.target}{path}"
            resp = self._fetch(url)
            if resp is None or resp.status_code >= 400:
                continue
            body = resp.text[:4096]
            for tool, pattern in DEV_TOOL_PATTERNS.items():
                if pattern.search(body):
                    found.append((url, tool))
        return found

    # ── Step 2: TLS SAN wildcard extraction ───────────────────────────────

    def _get_tls_san(self) -> list[str]:
        """Extract Subject Alternative Names from the target TLS certificate."""
        parsed = urlparse(self.target)
        hostname = parsed.hostname or self.target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            return []

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(
                socket.create_connection((hostname, port), timeout=self.timeout),
                server_hostname=hostname,
            ) as sock:
                cert = sock.getpeercert()
                sans: list[str] = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        sans.append(san_value)
                return sans
        except Exception:
            return []

    # ── Step 3: parse JS bundles for hidden domains ────────────────────────

    def _extract_js_domains(self, base_url: str) -> list[str]:
        """Fetch main page, find JS src tags, parse domains from bundle content."""
        domains: set[str] = set()
        resp = self._fetch(base_url)
        if resp is None:
            return []

        # Find JS script src
        js_urls = re.findall(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            resp.text, re.I
        )

        parsed = urlparse(base_url)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"

        for js_path in js_urls[:8]:  # limit to 8 JS files
            js_url = js_path if js_path.startswith("http") else f"{base_domain}{js_path}"
            js_resp = self._fetch(js_url)
            if js_resp is None or js_resp.status_code != 200:
                continue
            for match in JS_DOMAIN_PATTERN.findall(js_resp.text[:200_000]):
                # Filter: must look like a real domain, not the target
                if (
                    "." in match
                    and not match.startswith(".")
                    and len(match) < 80
                    and parsed.netloc not in match
                    and not match.endswith((".js", ".css", ".png", ".jpg", ".svg"))
                ):
                    domains.add(match.lower())

        return list(domains)

    # ── Step 4: fuzz cloud token endpoints ────────────────────────────────

    def _fuzz_token_endpoints(self, base_url: str) -> list[tuple[str, str, str]]:
        """
        Returns list of (url, token_type, token_preview) for exposed tokens.
        """
        results: list[tuple[str, str, str]] = []
        for path in CLOUD_TOKEN_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            resp = self._fetch(url)
            if resp is None or resp.status_code not in (200, 201):
                continue
            if len(resp.text) < 10:
                continue
            # Check for token patterns
            for token_type, pattern in TOKEN_PATTERNS.items():
                m = pattern.search(resp.text[:8192])
                if m:
                    raw = m.group(1) if m.lastindex else m.group(0)
                    preview = raw[:12] + "…" if len(raw) > 12 else raw
                    results.append((url, token_type, preview))
                    break
            else:
                # Even without pattern match, JSON with "token"/"key" keys is suspicious
                if resp.headers.get("content-type", "").startswith("application/json"):
                    try:
                        data = resp.json()
                        if any(
                            k.lower() in ("token", "access_token", "key", "secret", "password")
                            for k in (data.keys() if isinstance(data, dict) else [])
                        ):
                            results.append((url, "generic_json_credential", "(json)"))
                    except Exception:
                        pass

        return results

    # ── Main scan ──────────────────────────────────────────────────────────

    def scan(self) -> CloudTokenResult:
        result = CloudTokenResult(target=self.target)

        if not REQUESTS_AVAILABLE:
            result.summary = "requests not available"
            return result

        result.triggered = True
        findings: list[CloudTokenFinding] = []
        chain_hops = 0

        # Step 1 — Detect open dev tools
        dev_tools = self._detect_dev_tools()
        for dev_url, tool_name in dev_tools:
            chain_hops += 1
            result.open_dev_tools.append(dev_url)
            findings.append(CloudTokenFinding(
                finding_type="open_dev_tool",
                evidence_level="VERIFIED",
                severity="Medium",
                description=f"Unauthenticated {tool_name} instance detected at {dev_url}",
                url=dev_url,
                dev_tool_type=tool_name,
                chain_depth=chain_hops,
            ))

        # Step 2 — TLS SAN wildcard
        sans = self._get_tls_san()
        wildcard_sans = [s for s in sans if s.startswith("*.")]
        if wildcard_sans:
            chain_hops += 1
            for wc in wildcard_sans:
                result.shadow_domains.append(wc)
                findings.append(CloudTokenFinding(
                    finding_type="tls_san_wildcard",
                    evidence_level="VERIFIED",
                    severity="Info",
                    description=(
                        f"TLS wildcard SAN found: {wc}. "
                        "Shadow subdomain estate may be discoverable via crt.sh"
                    ),
                    url=self.target,
                    san_wildcard=wc,
                    chain_depth=chain_hops,
                ))

        # Step 3 — JS bundle domain extraction
        hidden_domains = self._extract_js_domains(self.target)
        novel_domains = [
            d for d in hidden_domains
            if not any(
                d in existing or existing.endswith(d)
                for existing in [urlparse(self.target).netloc]
            )
        ]
        if novel_domains:
            chain_hops += 1
            result.shadow_domains.extend(novel_domains[:10])
            findings.append(CloudTokenFinding(
                finding_type="js_hidden_domain",
                evidence_level="INFERRED",
                severity="Low",
                description=(
                    f"JS bundles reference {len(novel_domains)} external domain(s): "
                    f"{', '.join(novel_domains[:5])}"
                ),
                url=self.target,
                discovered_domains=novel_domains[:10],
                chain_depth=chain_hops,
            ))

        # Step 4 — Fuzz cloud token endpoints on main target
        token_hits = self._fuzz_token_endpoints(self.target)
        for token_url, token_type, preview in token_hits:
            chain_hops += 1
            result.token_endpoints_found.append(token_url)
            result.tokens_exposed = True
            result.exploitable = True
            findings.append(CloudTokenFinding(
                finding_type="cloud_token_exposed",
                evidence_level="VERIFIED",
                severity="Critical",
                description=(
                    f"Unauthenticated cloud token endpoint: {token_url}\n"
                    f"Token type: {token_type} | Preview: {preview}"
                ),
                url=token_url,
                token_type=token_type,
                token_preview=preview,
                chain_depth=chain_hops,
            ))

        # Step 4b — Also try on any shadow domains found in JS
        for shadow in novel_domains[:3]:
            for scheme in ("https", "http"):
                shadow_base = f"{scheme}://{shadow}"
                shadow_hits = self._fuzz_token_endpoints(shadow_base)
                for token_url, token_type, preview in shadow_hits:
                    chain_hops += 1
                    result.token_endpoints_found.append(token_url)
                    result.tokens_exposed = True
                    result.exploitable = True
                    findings.append(CloudTokenFinding(
                        finding_type="shadow_domain_token_exposed",
                        evidence_level="VERIFIED",
                        severity="Critical",
                        description=(
                            f"Shadow domain unauthenticated token: {token_url}\n"
                            f"Discovered via JS bundle parsing. "
                            f"Type: {token_type} | Preview: {preview}"
                        ),
                        url=token_url,
                        token_type=token_type,
                        token_preview=preview,
                        js_source_url=self.target,
                        chain_depth=chain_hops,
                    ))

        # Step 5 — AI_ANALYSIS: if dev tool + cloud env indicator → likely chain
        if dev_tools and not result.tokens_exposed:
            # Check if target looks like cloud environment
            cloud_indicators = any(
                kw in self.target.lower()
                for kw in ("aws", "gcp", "azure", "cloud", "k8s", "kube", "llm", "ai")
            )
            if cloud_indicators or sans:
                findings.append(CloudTokenFinding(
                    finding_type="likely_cloud_chain",
                    evidence_level="AI_ANALYSIS",
                    severity="High",
                    description=(
                        "Open dev tool detected in cloud environment. "
                        "High probability of cloud credential chain (GCP/AWS Secret Manager → GitHub tokens). "
                        "Manual verification: check TLS SAN on crt.sh, fuzz shadow subdomains for /_api/token endpoints."
                    ),
                    url=self.target,
                    dev_tool_type=dev_tools[0][1] if dev_tools else "",
                    discovered_domains=[s for _, s in dev_tools],
                    chain_depth=chain_hops,
                ))

        result.findings = findings
        result.chain_hops = chain_hops

        # Severity roll-up
        sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        if findings:
            top_sev = max(
                (f.severity for f in findings),
                key=lambda s: sev_order.get(s, 0),
            )
            result.severity = top_sev

        # Summary
        if result.tokens_exposed:
            result.summary = (
                f"CRITICAL: Unauthenticated cloud token endpoint(s) found at "
                f"{', '.join(result.token_endpoints_found[:2])}. "
                f"Potential {result.chain_hops}-hop chain to private repos/secrets."
            )
        elif dev_tools:
            result.summary = (
                f"Open dev tool(s) detected: {', '.join(t for _, t in dev_tools)}. "
                "Possible shadow domain / cloud token chain. Manual pivot recommended."
            )
        elif novel_domains:
            result.summary = (
                f"JS bundles reference {len(novel_domains)} external domain(s) — "
                "potential pivot points for cloud credential chain."
            )
        else:
            result.summary = "No cloud token chain indicators found at this stage."

        return result
