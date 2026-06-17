"""
Phase 01 — 정찰 (Reconnaissance)
서브도메인, 기술스택, DNS, 민감 파일, 관리자 패널

v2.3.18 변경:
  - harvest_usernames(): 사이트 이메일/author/Contact 페이지에서 실제 아이디 수집
  - 수집 아이디 × 공통 비밀번호 패턴 크로스조인 → lahyl:lahy12025 계열 커버
  - 브루트포스 max_attempts 25 → 50 (조합 수 증가에 맞춰)
  - API 502/503/504 → "백엔드 서비스 존재 가능" Medium 으로 분류 + 보고서 반영

v2.3.17 변경:
  - path_dict.py 연동으로 스킬 라이브러리 지식을 스캔 시작 전에 사전 로드
  - 기술스택 핑거프린팅 → 스택별 특화 경로 자동 선택 (최대 80+ 경로)
  - API 엔드포인트 미인증 접근 탐색 추가 (/api/coordinates 등)
  - 관리자 패널 발견 시 약한 비밀번호 브루트포스 자동 실행
"""
from __future__ import annotations
import re
import socket
import time
from urllib.parse import urlparse

from ...tools.http_probe import HttpProbe
from ...tools.executor import ToolExecutor
from ...tools.registry import ToolRegistry
from ...tools.path_dict import get_admin_paths, get_api_paths, get_weak_credentials
from ..session import RedTeamSession


def run(target: str, session: RedTeamSession, on_progress=None) -> list[dict]:
    log = on_progress or (lambda s: None)
    probe = HttpProbe(target, delay=0.3)
    executor = ToolExecutor()
    findings: list[dict] = []
    domain = urlparse(target).hostname or target

    log("▶ 01. 정찰 시작")

    # ── Step 1: 기술 스택 핑거프린팅 (최우선 — 이후 경로 선택에 사용) ──
    log("  [1/8] 기술스택 핑거프린팅...")
    fp = probe.fingerprint()
    session.metadata["tech"] = fp
    tech_stack = fp.get("tech", [])
    if fp["cms"]:
        tech_stack = list(set(tech_stack + [fp["cms"]]))
    if fp["tech"]:
        findings.append({
            "type": "fingerprint",
            "severity": "info",
            "title": f"기술스택 식별: {', '.join(fp['tech'])}",
            "detail": str(fp),
        })
        log(f"  → 기술스택: {tech_stack}, CMS: {fp.get('cms','?')}")

    # ── Step 2: 스킬 라이브러리 지식으로 경로 사전 로드 ─────────────────
    # 핵심 수정: 기존에는 13개 하드코딩 → 이제 기술스택 기반 동적 생성
    log(f"  [2/8] 경로 사전 로드 (기술스택: {tech_stack or ['기본']})...")
    admin_paths = get_admin_paths(tech_stack)
    api_paths = get_api_paths(tech_stack)
    log(f"  → 관리자 경로 {len(admin_paths)}개, API 경로 {len(api_paths)}개 준비")
    session.metadata["admin_paths_count"] = len(admin_paths)
    session.metadata["api_paths_count"] = len(api_paths)

    # ── Step 3: DNS / IP 정보 ───────────────────────────────────────────
    log("  [3/8] DNS 조회...")
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

    # ── Step 4: subfinder ───────────────────────────────────────────────
    if ToolRegistry.available("subfinder"):
        log("  [4/8] 서브도메인 탐색 (subfinder)...")
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
        log("  [4/8] subfinder 미설치 — 스킵")

    # ── Step 5: 민감 파일 탐색 ─────────────────────────────────────────
    log("  [5/8] 민감 파일 탐색...")
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

    # ── Step 6: 관리자 패널 탐색 (기술스택 기반 동적 경로 사용) ──────────
    log(f"  [6/8] 관리자 패널 탐색 ({len(admin_paths)}개 경로)...")
    admin_panels = probe.check_admin_panels(extra_paths=admin_paths)
    login_panels = []  # 브루트포스 대상
    for panel in admin_panels:
        sev = "high" if panel.get("has_login_form") else "medium"
        if panel.get("status") == 403:
            sev = "low"
        findings.append({
            "type": "admin_panel",
            "severity": sev,
            "title": f"관리자 패널: {panel['path']} [{panel['status']}]",
            "detail": str(panel),
        })
        if panel.get("has_login_form"):
            login_panels.append(panel)
    if admin_panels:
        accessible = [p for p in admin_panels if p.get("status") == 200]
        log(f"  → 관리자 패널 {len(admin_panels)}개 발견 (접근 가능: {len(accessible)}개)")

    # ── Step 7: API 엔드포인트 미인증 접근 탐색 ───────────────────────────
    # 이용자 제보: /api/coordinates 탐지 못함 → 이제 사전 탐색
    log(f"  [7/8] API 엔드포인트 탐색 ({len(api_paths)}개 경로)...")
    api_found = probe.discover_api_endpoints(paths=api_paths)
    for ep in api_found:
        st = ep.get("status", 0)
        if st in (200, 201) and ep.get("is_json"):
            sev = "high"
        elif st in (200, 201):
            sev = "medium"
        elif st in (401, 403):
            sev = "info"
        elif st in (502, 503, 504):
            # Bad Gateway — 백엔드 서비스 존재 가능성
            sev = "medium"
        else:
            sev = "info"
        note = ep.get("note", "")
        findings.append({
            "type": "api_endpoint",
            "severity": sev,
            "title": (
                f"API 엔드포인트: {ep['path']} [{st}]"
                + (" (JSON)" if ep.get("is_json") else "")
                + (f" — {note}" if note else "")
            ),
            "detail": f"url={ep['url']} size={ep.get('size',0)} preview={ep.get('preview','')[:100]}",
            "url": ep.get("url", ""),
            "path": ep["path"],
        })
    accessible_api = [e for e in api_found if e.get("status") in (200, 201)]
    proxy_error_api = [e for e in api_found if e.get("status") in (502, 503, 504)]
    if accessible_api:
        log(f"  → API 엔드포인트 {len(accessible_api)}개 미인증 접근 성공!")
        session.metadata["unauth_api"] = [e["path"] for e in accessible_api]
    if proxy_error_api:
        log(f"  → API 프록시 오류 {len(proxy_error_api)}개 (백엔드 서비스 존재 가능)")
        session.metadata["proxy_error_api"] = [e["path"] for e in proxy_error_api]
    if api_found and not accessible_api and not proxy_error_api:
        log(f"  → API 엔드포인트 {len(api_found)}개 발견 (인증 필요)")

    # ── Step 8: 아이디 수집 + 약한 비밀번호 브루트포스 ──────────────────
    # v2.3.18: harvest_usernames()로 사이트 자체 아이디 수집 → 크로스조인
    # 이용자 제보: lahyl:lahy12025 — 비표준 아이디+아이디앞4자+연도 패턴 커버
    if login_panels:
        log(f"  [8/8] 아이디 수집 + 약한 비밀번호 브루트포스 ({len(login_panels)}개 로그인 폼)...")

        # 사이트에서 아이디 수집
        log("    → 사이트 아이디 수집 중 (이메일/author/페이지)...")
        harvested = probe.harvest_usernames()
        if harvested:
            log(f"    → 수집된 아이디: {harvested[:8]}")
        session.metadata["harvested_usernames"] = harvested

        # 동적 조합: 표준 아이디 + 수집 아이디 × 공통 비밀번호 패턴
        weak_creds = get_weak_credentials(domain, extra_usernames=harvested)
        session.metadata["brute_creds_count"] = len(weak_creds)
        log(f"    → 총 {len(weak_creds)}개 조합 생성 (수집 아이디 {len(harvested)}개 포함)")
        all_successes = []

        for panel in login_panels[:3]:  # 최대 3개 패널
            login_url = panel["path"]
            log(f"    → {login_url} 브루트포스 중 (최대 50회)...")

            # user_field / pass_field 자동 감지
            r_form = probe.get(login_url, timeout=8)
            user_field = "username"
            pass_field = "password"
            if r_form.body:
                names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', r_form.body, re.I)
                for n in names:
                    if any(kw in n.lower() for kw in ["user", "id", "email", "login", "아이디"]):
                        user_field = n
                    elif any(kw in n.lower() for kw in ["pass", "pwd", "password", "비밀"]):
                        pass_field = n
                log(f"      폼 필드: {user_field} / {pass_field}")

            successes = probe.brute_admin_login(
                login_url, weak_creds,
                user_field=user_field, pass_field=pass_field,
                max_attempts=50,   # 25 → 50 (조합 수 증가에 맞춰 확대)
            )
            all_successes.extend(successes)

        for s in all_successes:
            findings.append({
                "type": "weak_credential",
                "severity": "critical",
                "title": f"약한 비밀번호: {s['username']}:{s['password']} @ {s['url']}",
                "detail": f"status={s['status']} evidence={s['evidence'][:100]}",
                "username": s["username"],
                "password": s["password"],
                "url": s["url"],
            })
        if all_successes:
            log(f"  → ⚠ 약한 비밀번호 {len(all_successes)}개 발견!")
        else:
            log(f"  → 브루트포스: 성공 없음 (시도 완료)")
    else:
        log("  [8/8] 로그인 폼 없음 — 브루트포스 스킵")

    # ── WAF 탐지 ────────────────────────────────────────────────────────
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
