"""
WhiteboxAnalyzer — 소스코드/HTML 기반 취약점 힌트 추출 (v3.2.82)

Shannon 방식 채용:
- 소스코드/HTML 일부만 있어도 동작
- 코드에서 공격 경로(파라미터, 엔드포인트, 쿼리 패턴) 추출
- 라이브 블랙박스 테스트의 정밀도 향상
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AttackHint:
    """코드 분석으로 발견된 공격 힌트."""
    vuln_type: str          # sqli / xss / ssrf / auth / idor / rce
    endpoint: str           # /api/login  or  unknown
    param: str              # username / id / url / ...
    evidence: str           # 코드 스니펫 (최대 120자)
    file_hint: str = ""     # 파일명 또는 라인 힌트
    confidence: str = "medium"  # high / medium / low


@dataclass
class WhiteboxResult:
    hints: list[AttackHint] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    raw_code: str = ""

    def has_hints(self) -> bool:
        return bool(self.hints or self.endpoints or self.params)

    def summary(self) -> str:
        lines = []
        if self.tech_stack:
            lines.append(f"스택: {', '.join(self.tech_stack)}")
        if self.endpoints:
            lines.append(f"엔드포인트 {len(self.endpoints)}개 발견")
        if self.params:
            lines.append(f"파라미터 {len(self.params)}개 발견")
        if self.hints:
            by_type: dict[str, int] = {}
            for h in self.hints:
                by_type[h.vuln_type] = by_type.get(h.vuln_type, 0) + 1
            for vt, cnt in by_type.items():
                lines.append(f"{vt.upper()} 취약 가능성 {cnt}개")
        return " | ".join(lines) if lines else "분석 완료 (특이사항 없음)"

    def to_context_injection(self, target_url: str = "") -> str:
        """AI에게 전달할 화이트박스 컨텍스트 문자열 생성."""
        lines = ["[WHITEBOX CONTEXT — 소스코드 분석 결과]"]
        if target_url:
            lines.append(f"Target URL: {target_url}")
            lines.append(
                "Hybrid Mode: combine source code hints below with live blackbox "
                f"testing against {target_url}"
            )
        if self.tech_stack:
            lines.append(f"Tech Stack: {', '.join(self.tech_stack)}")
        if self.endpoints:
            # URL이 있으면 절대 경로로 조합
            if target_url:
                base = target_url.rstrip("/")
                combined = [
                    f"{base}{ep}" if ep.startswith("/") else f"{base}/{ep}"
                    for ep in self.endpoints[:20]
                ]
                lines.append(f"Full URLs to test: {', '.join(combined)}")
            else:
                lines.append(f"Endpoints: {', '.join(self.endpoints[:20])}")
        if self.params:
            lines.append(f"Parameters: {', '.join(self.params[:30])}")
        if self.forms:
            for f in self.forms[:5]:
                action = f.get('action', '?')
                if target_url and action.startswith("/"):
                    action = target_url.rstrip("/") + action
                lines.append(f"Form: action={action} params={f.get('params', [])}")
        if self.hints:
            lines.append("Attack Hints:")
            for h in self.hints[:15]:
                endpoint = h.endpoint
                if target_url and endpoint.startswith("/"):
                    endpoint = target_url.rstrip("/") + endpoint
                lines.append(
                    f"  [{h.vuln_type.upper()}] {endpoint} param={h.param} "
                    f"confidence={h.confidence} — {h.evidence[:80]}"
                )
        lines.append("[/WHITEBOX CONTEXT]")
        return "\n".join(lines)


class WhiteboxAnalyzer:
    """소스코드/HTML/JS에서 공격 힌트를 추출."""

    # ── SQL 인젝션 패턴 ──────────────────────────────────────────────
    _SQLI_PATTERNS = [
        (r'(?i)(SELECT|INSERT|UPDATE|DELETE|WHERE).*?\$_(GET|POST|REQUEST|COOKIE)\s*\[', "high"),
        (r'(?i)mysql_query\s*\(.*?\$', "high"),
        (r'(?i)mysqli?_query\s*\(.*?(\$_GET|\$_POST|\$_REQUEST)', "high"),
        (r'(?i)execute\s*\(.*?f["\'].*?\{', "high"),       # Python f-string in SQL
        (r'(?i)cursor\.execute\s*\(.*?%s.*?%\s*\(', "high"),
        (r'(?i)\"SELECT.*?\"\s*\+\s*\w+', "medium"),       # Java/JS string concat
        (r'(?i)\.query\s*\([^)]*\+\s*req\.(query|params|body)', "high"),  # Node.js
    ]

    # ── XSS 패턴 ─────────────────────────────────────────────────────
    _XSS_PATTERNS = [
        (r'(?i)echo\s+\$_(GET|POST|REQUEST|COOKIE)', "high"),
        (r'(?i)document\.write\s*\(.*?(location|search|hash)', "high"),
        (r'(?i)innerHTML\s*=.*?(location|search|hash|document\.URL)', "high"),
        (r'(?i)res\.send\s*\(.*?req\.(query|params|body)', "medium"),
        (r'(?i)\{\{.*?\|.*?safe\}\}', "medium"),            # Django/Jinja2 |safe
        (r'dangerouslySetInnerHTML', "high"),               # React
    ]

    # ── SSRF 패턴 ────────────────────────────────────────────────────
    _SSRF_PATTERNS = [
        (r'(?i)(urllib|requests|curl|fetch|http\.get)\s*[\.(].{0,30}(\$_GET|\$_POST|req\.(query|body|params))', "high"),
        (r'(?i)file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)', "high"),
        (r'(?i)(url|uri|endpoint|target|host)\s*=\s*req\.(query|params|body)', "medium"),
    ]

    # ── 인증 우회 패턴 ───────────────────────────────────────────────
    _AUTH_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*==\s*["\']', "high"),   # 하드코딩 비교
        (r'(?i)if\s*\(\s*\$_SESSION\[.{0,30}\]\s*\)', "medium"),
        (r'(?i)(admin|root|test|debug)\s*:\s*(admin|root|test|1234|password)', "high"),
        (r'(?i)jwt\.verify\s*\(.*?algorithms\s*=\s*\[', "medium"),
        (r'(?i)(token|key|secret)\s*=\s*["\'][a-zA-Z0-9+/]{20,}', "high"),
    ]

    # ── RCE 패턴 ─────────────────────────────────────────────────────
    _RCE_PATTERNS = [
        (r'(?i)(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST)', "high"),
        (r'(?i)(subprocess|os\.system|os\.popen)\s*\(.*?request\.(args|form|data)', "high"),
        (r'(?i)eval\s*\(\s*\$_(GET|POST|REQUEST)', "high"),
        (r'(?i)child_process\.exec\s*\(.*?req\.(query|params|body)', "high"),
    ]

    # ── 기술 스택 탐지 ───────────────────────────────────────────────
    _TECH_PATTERNS = {
        "PHP": [r'<\?php', r'\$_GET', r'\$_POST', r'mysqli_', r'PDO::'],
        "Python/Django": [r'from django', r'request\.GET', r'request\.POST', r'HttpResponse'],
        "Python/Flask": [r'from flask', r'@app\.route', r'request\.args', r'request\.form'],
        "Node.js/Express": [r'require\(["\']express["\']', r'app\.(get|post|put|delete)\(', r'req\.params'],
        "Java/Spring": [r'@RestController', r'@RequestMapping', r'@GetMapping', r'HttpServletRequest'],
        "Ruby/Rails": [r'params\[:', r'render\s+json:', r'def\s+\w+\s*$'],
        "ASP.NET": [r'Request\.QueryString', r'Request\.Form', r'Response\.Write'],
    }

    def analyze(self, code: str, file_hint: str = "") -> WhiteboxResult:
        """코드 문자열 분석 → WhiteboxResult 반환."""
        result = WhiteboxResult(raw_code=code)

        # 기술 스택 탐지
        for tech, patterns in self._TECH_PATTERNS.items():
            if any(re.search(p, code) for p in patterns):
                result.tech_stack.append(tech)

        # HTML 파싱 (폼/엔드포인트)
        self._extract_html_context(code, result)

        # 취약점 패턴 매칭
        self._match_patterns(code, self._SQLI_PATTERNS, "sqli", result, file_hint)
        self._match_patterns(code, self._XSS_PATTERNS, "xss", result, file_hint)
        self._match_patterns(code, self._SSRF_PATTERNS, "ssrf", result, file_hint)
        self._match_patterns(code, self._AUTH_PATTERNS, "auth", result, file_hint)
        self._match_patterns(code, self._RCE_PATTERNS, "rce", result, file_hint)

        # 파라미터 추출
        self._extract_params(code, result)

        return result

    def analyze_path(self, path: str) -> WhiteboxResult:
        """파일/디렉토리 경로에서 코드를 읽어 분석."""
        import os
        p = Path(os.path.expandvars(os.path.expanduser(path.strip())))
        combined = WhiteboxResult()

        if p.is_file():
            try:
                code = p.read_text(encoding="utf-8", errors="ignore")
                r = self.analyze(code, file_hint=p.name)
                self._merge(combined, r)
            except Exception:
                pass
        elif p.is_dir():
            exts = {".php", ".py", ".js", ".ts", ".html", ".htm", ".jsp", ".asp", ".aspx", ".rb"}
            for f in sorted(p.rglob("*"))[:50]:  # 최대 50개 파일
                if f.suffix.lower() in exts and f.is_file():
                    try:
                        code = f.read_text(encoding="utf-8", errors="ignore")
                        r = self.analyze(code, file_hint=f.name)
                        self._merge(combined, r)
                    except Exception:
                        continue
        return combined

    def _extract_html_context(self, code: str, result: WhiteboxResult) -> None:
        # 폼 액션 추출
        for m in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', code, re.IGNORECASE):
            action = m.group(1)
            if action not in result.endpoints:
                result.endpoints.append(action)
            # 해당 폼의 파라미터 추출
            form_params = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', code[m.start():m.start()+2000], re.IGNORECASE)
            if form_params:
                result.forms.append({"action": action, "params": form_params})
                for p in form_params:
                    if p not in result.params:
                        result.params.append(p)

        # API 엔드포인트 추출 (/api/xxx, /user/xxx)
        for m in re.finditer(r'["\'](\/(api|user|admin|auth|login|upload|search|query|v\d+)[^\s"\'<>]+)["\']', code, re.IGNORECASE):
            ep = m.group(1)
            if ep not in result.endpoints:
                result.endpoints.append(ep)

        # href/src URL 추출
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\'#][^"\']*\?[^"\']+)["\']', code, re.IGNORECASE):
            url = m.group(1)
            # 파라미터 파싱
            if "?" in url:
                path, qs = url.split("?", 1)
                if path not in result.endpoints:
                    result.endpoints.append(path)
                for kv in qs.split("&"):
                    k = kv.split("=")[0]
                    if k and k not in result.params:
                        result.params.append(k)

    def _extract_params(self, code: str, result: WhiteboxResult) -> None:
        # GET/POST 파라미터 이름 추출
        for pattern in [
            r'\$_GET\s*\[["\'](\w+)["\']',
            r'\$_POST\s*\[["\'](\w+)["\']',
            r'\$_REQUEST\s*\[["\'](\w+)["\']',
            r'request\.args\.get\s*\(["\'](\w+)["\']',
            r'request\.form\.get\s*\(["\'](\w+)["\']',
            r'req\.(?:query|body|params)\.(\w+)',
            r'params\[:(\w+)\]',
            r'Request\.QueryString\s*\[["\'](\w+)["\']',
        ]:
            for m in re.finditer(pattern, code):
                p = m.group(1)
                if p not in result.params:
                    result.params.append(p)

    def _match_patterns(self, code: str, patterns: list, vuln_type: str,
                        result: WhiteboxResult, file_hint: str) -> None:
        for pat, confidence in patterns:
            for m in re.finditer(pat, code):
                snippet = code[max(0, m.start()-20):m.end()+40].replace("\n", " ").strip()
                # 주변에서 엔드포인트 힌트 추출
                surrounding = code[max(0, m.start()-200):m.end()+200]
                ep_match = re.search(r'["\'](\/([\w/\-]+))["\']', surrounding)
                endpoint = ep_match.group(1) if ep_match else "unknown"
                param_match = re.search(
                    r'(?:\$_(?:GET|POST|REQUEST)\s*\[["\'](\w+)["\']|'
                    r'req\.(?:query|body|params)\.(\w+)|'
                    r'request\.(?:args|form)\.get\s*\(["\'](\w+)["\'])',
                    surrounding
                )
                param = next((g for g in (param_match.groups() if param_match else []) if g), "?")

                hint = AttackHint(
                    vuln_type=vuln_type,
                    endpoint=endpoint,
                    param=param,
                    evidence=snippet[:120],
                    file_hint=file_hint,
                    confidence=confidence,
                )
                result.hints.append(hint)
                break  # 파일당 패턴당 1개만

    def _merge(self, base: WhiteboxResult, other: WhiteboxResult) -> None:
        for ep in other.endpoints:
            if ep not in base.endpoints:
                base.endpoints.append(ep)
        for p in other.params:
            if p not in base.params:
                base.params.append(p)
        base.hints.extend(other.hints)
        base.forms.extend(other.forms)
        for ts in other.tech_stack:
            if ts not in base.tech_stack:
                base.tech_stack.append(ts)
        base.raw_code += "\n" + other.raw_code
