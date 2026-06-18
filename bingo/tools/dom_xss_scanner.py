"""bingo/tools/dom_xss_scanner.py — DOM XSS 정적/동적 스캐너 (v2.6.0)"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

# ── DOM XSS 위험 Source ───────────────────────────────────────────────────────
SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"document\.cookie",
    r"localStorage\.getItem",
    r"sessionStorage\.getItem",
    r"history\.state",
    r"postMessage",
    r"URLSearchParams",
    r"new\s+URL\(",
]

# ── DOM XSS 위험 Sink ─────────────────────────────────────────────────────────
SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\(",
    r"document\.writeln\(",
    r"eval\(",
    r"setTimeout\(\s*['\"`]",
    r"setInterval\(\s*['\"`]",
    r"new\s+Function\(",
    r"location\.href\s*=",
    r"location\.assign\(",
    r"location\.replace\(",
    r"\.src\s*=",
    r"\.action\s*=",
    r"insertAdjacentHTML\(",
    r"jQuery\.parseHTML\(",
    r"\$\(.*\)\.html\(",
    r"angular\.element",
    r"React\.createElement\(.+dangerouslySetInnerHTML",
    r"v-html\s*=",
]

# ── 취약 라이브러리 패턴 ──────────────────────────────────────────────────────
VULN_LIBS = [
    (r"jquery[-/]1\.[0-8]\.",          "jQuery < 1.9 — XSS via .html()"),
    (r"angular\.js.+1\.[0-5]\.",       "AngularJS < 1.6 — Sandbox Escape"),
    (r"bootstrap[/-]3\.[0-3]\.",       "Bootstrap 3.x — XSS in tooltip"),
    (r"dompurify[/-]1\.",              "DOMPurify < 2.0 — bypass possible"),
]


@dataclass
class DomXssFinding:
    source: str
    sink: str
    js_file: str
    evidence: str
    line_number: int
    severity: str
    confirmed: bool  # 정적 분석은 False, 동적은 True
    exploit_hint: str = ""


@dataclass
class DomXssReport:
    target: str
    findings: list[DomXssFinding] = field(default_factory=list)
    vuln_libs: list[str] = field(default_factory=list)
    js_files_analyzed: int = 0

    @property
    def high_risk(self) -> list[DomXssFinding]:
        return [f for f in self.findings if f.severity in ("HIGH", "CRITICAL")]


class DomXssScanner:
    """DOM XSS 정적 소스/싱크 분석 + 취약 라이브러리 탐지"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    def _fetch_js(self, url: str) -> str:
        try:
            _, body = self.req(url, "GET", self.headers, "")
            return body
        except Exception:
            return ""

    def _extract_js_urls(self, html: str, base: str) -> list[str]:
        urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
        result = []
        for u in urls:
            if u.startswith("http"):
                result.append(u)
            elif u.startswith("//"):
                result.append("https:" + u)
            elif u.startswith("/"):
                parsed_base = re.match(r'https?://[^/]+', base)
                if parsed_base:
                    result.append(parsed_base.group(0) + u)
            else:
                result.append(base.rstrip("/") + "/" + u)
        return result[:30]  # 최대 30개

    def analyze_js(self, js_code: str, filename: str) -> list[DomXssFinding]:
        findings = []
        lines = js_code.split("\n")

        for lineno, line in enumerate(lines, 1):
            # Source 탐지
            detected_source = next(
                (s for s in SOURCES if re.search(s, line)), None
            )
            if not detected_source:
                continue

            # 같은 라인 또는 ±5줄에 Sink 있는지 확인
            context_start = max(0, lineno - 5)
            context_end = min(len(lines), lineno + 5)
            context = "\n".join(lines[context_start:context_end])

            detected_sink = next(
                (s for s in SINKS if re.search(s, context)), None
            )

            if detected_sink:
                # 고위험 조합 판단
                critical_sinks = [r"eval\(", r"document\.write", r"\.innerHTML\s*=", r"location\.href\s*="]
                sev = "HIGH" if any(re.search(cs, detected_sink) for cs in critical_sinks) else "MEDIUM"

                exploit_hint = _generate_exploit_hint(detected_source, detected_sink)

                findings.append(DomXssFinding(
                    source=detected_source,
                    sink=detected_sink,
                    js_file=filename,
                    evidence=line.strip()[:200],
                    line_number=lineno,
                    severity=sev,
                    confirmed=False,
                    exploit_hint=exploit_hint,
                ))

        return findings

    def detect_vuln_libs(self, html: str) -> list[str]:
        found = []
        for pattern, desc in VULN_LIBS:
            if re.search(pattern, html, re.I):
                found.append(desc)
        return found

    def test_url_fragment_reflection(self, url: str) -> DomXssFinding | None:
        """URL 해시가 JS에서 innerHTML 등에 직접 반영되는지 탐지"""
        test_url = url + "#<img src=x onerror=alert(1)>"
        try:
            _, resp = self.req(test_url, "GET", self.headers, "")
            if '<img src=x onerror=alert(1)>' in resp:
                return DomXssFinding(
                    source="location.hash",
                    sink="innerHTML/document.write",
                    js_file="server-rendered",
                    evidence="Hash value reflected in HTML",
                    line_number=0,
                    severity="CRITICAL",
                    confirmed=True,
                    exploit_hint=f"PoC: {url}#<script>alert(1)</script>",
                )
        except Exception:
            pass
        return None

    def full_scan(self) -> DomXssReport:
        report = DomXssReport(target=self.base)

        _, html = self.req(self.base, "GET", self.headers, "")
        report.vuln_libs = self.detect_vuln_libs(html)

        js_urls = self._extract_js_urls(html, self.base)
        report.js_files_analyzed = len(js_urls)

        for js_url in js_urls:
            js_code = self._fetch_js(js_url)
            if js_code:
                findings = self.analyze_js(js_code, js_url)
                report.findings.extend(findings)

        # URL 해시 반영 테스트
        frag = self.test_url_fragment_reflection(self.base)
        if frag:
            report.findings.append(frag)

        return report


def _generate_exploit_hint(source: str, sink: str) -> str:
    hints = {
        ("location.hash", "innerHTML"): "PoC: URL#<img src=x onerror=alert(1)>",
        ("location.search", "innerHTML"): "PoC: URL?q=<img src=x onerror=alert(1)>",
        ("location.hash", "eval"): "PoC: URL#alert(1)",
        ("document.referrer", "innerHTML"): "PoC: Link via malicious referrer with XSS payload",
    }
    for (src, snk), hint in hints.items():
        if src in source and snk.split("\\")[0] in sink:
            return hint
    return "Manual verification required — trace source to sink flow"
