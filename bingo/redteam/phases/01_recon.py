"""
Phase 01 — 정찰 (Reconnaissance)
서브도메인, 기술스택, DNS, 민감 파일, 관리자 패널
"""
from __future__ import annotations
import re
import socket
import time
from urllib.parse import urlparse

from ...tools.http_probe import HttpProbe
from ...tools.executor import ToolExecutor
from ...tools.registry import ToolRegistry
from ..session import RedTeamSession


def run(target: str, session: RedTeamSession, on_progress=None) -> list[dict]:
    log = on_progress or (lambda s: None)
    probe = HttpProbe(target, delay=0.3)
    executor = ToolExecutor()
    findings: list[dict] = []

    log("▶ 01. 정찰 시작")

    # 1. 기술 스택 핑거프린팅 (Python 내장)
    log("  [1/6] 기술스택 핑거프린팅...")
    fp = probe.fingerprint()
    session.metadata["tech"] = fp
    if fp["tech"]:
        findings.append({
            "type": "fingerprint",
            "severity": "info",
            "title": f"기술스택 식별: {', '.join(fp['tech'])}",
            "detail": str(fp),
        })
        log(f"  → 기술스택: {fp['tech']}, CMS: {fp.get('cms','?')}")

    # 2. DNS / IP 정보
    log("  [2/6] DNS 조회...")
    domain = urlparse(target).hostname or target
    try:
        ip = socket.gethostbyname(domain)
        findings.append({
            "type": "dns",
            "severity": "info",
            "title": f"DNS: {domain} → {ip}",
            "detail": f"IP: {ip}",
        })
        log(f"  → IP: {ip}")
    except Exception as e:
        log(f"  → DNS 실패: {e}")

    # 3. subfinder (설치된 경우)
    if ToolRegistry.available("subfinder"):
        log("  [3/6] 서브도메인 탐색 (subfinder)...")
        r = executor.subfinder(domain)
        subs = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if subs:
            findings.append({
                "type": "subdomains",
                "severity": "info",
                "title": f"서브도메인 {len(subs)}개 발견",
                "detail": "\n".join(subs[:20]),
                "subdomains": subs,
            })
            log(f"  → 서브도메인 {len(subs)}개: {subs[:5]}")
    else:
        log("  [3/6] subfinder 미설치 — 스킵 (go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)")

    # 4. 민감 파일 탐색 (Python 내장)
    log("  [4/6] 민감 파일 탐색...")
    sensitive = probe.scan_sensitive_files()
    for item in sensitive:
        sev = "critical" if item["status"] == 200 else "low"
        findings.append({
            "type": "sensitive_file",
            "severity": sev,
            "title": f"민감 파일: {item['path']} [{item['status']}]",
            "detail": str(item),
        })
    if sensitive:
        log(f"  → 민감 파일 {len(sensitive)}개 발견")

    # 5. 관리자 패널 탐색
    log("  [5/6] 관리자 패널 탐색...")
    admin_panels = probe.check_admin_panels()
    for panel in admin_panels:
        sev = "high" if panel.get("has_login_form") else "medium"
        findings.append({
            "type": "admin_panel",
            "severity": sev,
            "title": f"관리자 패널: {panel['path']} [{panel['status']}]",
            "detail": str(panel),
        })
    if admin_panels:
        log(f"  → 관리자 패널 {len(admin_panels)}개 발견")

    # 6. WAF 탐지
    log("  [6/6] WAF 탐지...")
    r403 = probe.get(target + "?id=1'", timeout=8)
    if r403.status == 403:
        findings.append({"type": "waf", "severity": "info",
                         "title": "WAF 탐지 (403)", "detail": "Generic WAF"})
        log("  → WAF 탐지됨 (403)")
    elif r403.status == 406:
        findings.append({"type": "waf", "severity": "info",
                         "title": "WAF 탐지 (406)", "detail": "Nginx/OpenResty WAF"})
        log("  → WAF 탐지됨 (406 — Nginx/OpenResty)")

    log(f"✓ Phase 01 완료: {len(findings)}개 발견")
    return findings
