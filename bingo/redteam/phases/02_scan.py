"""
Phase 02 — 취약점 스캔 (Vulnerability Scanning)
nuclei, nmap, SQLi 초기 탐지
"""
from __future__ import annotations
import re
from urllib.parse import urlparse

from ...tools.http_probe import HttpProbe
from ...tools.executor import ToolExecutor
from ...tools.registry import ToolRegistry
from ...tools.sqli import SqliScanner
from ..session import RedTeamSession


def run(target: str, session: RedTeamSession, on_progress=None) -> list[dict]:
    log = on_progress or (lambda s: None)
    probe = HttpProbe(target, delay=0.3)
    executor = ToolExecutor()
    scanner = SqliScanner(probe, on_progress=log)
    findings: list[dict] = []

    log("▶ 02. 취약점 스캔 시작")

    # 1. nuclei (설치된 경우 — 가장 핫한 취약점 스캐너)
    if ToolRegistry.available("nuclei"):
        log("  [1/4] nuclei 스캔 (critical/high/medium)...")
        r = executor.nuclei(target, severity="critical,high,medium")
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        for line in lines[:30]:
            findings.append({
                "type": "nuclei",
                "severity": "high",
                "title": f"nuclei: {line[:120]}",
                "detail": line,
            })
        if lines:
            log(f"  → nuclei: {len(lines)}개 취약점 발견")
        else:
            log("  → nuclei: 취약점 없음")
    else:
        log("  [1/4] nuclei 미설치 — 스킵 (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")

    # 2. nmap 포트 스캔
    if ToolRegistry.available("nmap"):
        log("  [2/4] nmap 포트/서비스 스캔...")
        domain = urlparse(target).hostname or target
        r = executor.nmap(domain, flags="-sV --open -p 21,22,25,80,443,3306,8080,8443")
        if "open" in r.stdout:
            open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', r.stdout)
            for port, service in open_ports:
                sev = "high" if service in ("mysql", "ssh", "ftp") else "info"
                findings.append({
                    "type": "open_port",
                    "severity": sev,
                    "title": f"열린 포트: {port}/tcp ({service})",
                    "detail": f"port={port} service={service}",
                })
            log(f"  → 열린 포트 {len(open_ports)}개")
    else:
        log("  [2/4] nmap 미설치 — 스킵 (brew install nmap)")

    # 3. SQLi 초기 탐지 (Python 내장)
    log("  [3/4] SQL 인젝션 초기 탐지...")

    # 정찰 단계 결과에서 URL 파라미터 포함 링크 찾기
    r_home = probe.get("/")
    import re as _re
    urls_with_params = _re.findall(
        r'href=["\']([^"\']*\?[^"\']+)["\']', r_home.body
    )

    sqli_targets = [target + "?id=1"]  # 기본 테스트
    for u in urls_with_params[:5]:
        if u.startswith("http"):
            sqli_targets.append(u)
        else:
            sqli_targets.append(target.rstrip("/") + "/" + u.lstrip("/"))

    for url in sqli_targets[:5]:
        result = scanner.full_scan(url)
        if result.vulnerable:
            for vuln in result.vulns:
                findings.append({
                    "type": "sqli",
                    "severity": "critical",
                    "title": f"SQL 인젝션: {url} param={vuln.parameter} ({vuln.vuln_type})",
                    "detail": f"payload={vuln.payload}\nevidence={vuln.evidence}",
                    "url": url,
                    "param": vuln.parameter,
                    "payload": vuln.payload,
                    "vuln_type": vuln.vuln_type,
                })
            log(f"  → SQLi 발견: {url}")

    # 4. XSS 기초 탐지
    log("  [4/4] XSS 기초 탐지...")
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "'\"<>"]
    r_home2 = probe.get("/search?q=" + xss_payloads[0])
    if xss_payloads[0] in r_home2.body and r_home2.status == 200:
        findings.append({
            "type": "xss",
            "severity": "high",
            "title": "Reflected XSS: /search?q=",
            "detail": f"payload={xss_payloads[0]}이 그대로 반환됨",
        })

    log(f"✓ Phase 02 완료: {len(findings)}개 발견")
    return findings
