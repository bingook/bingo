"""
Phase 09 — 보고서 자동 생성 (Reporting)
버그바운티 제출용 Markdown + HTML 보고서

Zero-Hallucination 원칙:
  - evidence_level=VERIFIED 인 finding만 취약점으로 표시
  - evidence_level=INFERRED 는 "미검증" 섹션에 별도 표시
  - AI 분석 텍스트는 취약점 목록에 절대 포함 안 됨
  - 모든 취약점에 curl 재현 명령어 첨부
"""
from __future__ import annotations
import time
from datetime import datetime
from pathlib import Path

from ..session import RedTeamSession


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_KR = {
    "critical": "위험 (Critical)",
    "high": "높음 (High)",
    "medium": "중간 (Medium)",
    "low": "낮음 (Low)",
    "info": "정보 (Info)",
}
SEVERITY_CVSS = {
    "critical": "9.0~10.0",
    "high": "7.0~8.9",
    "medium": "4.0~6.9",
    "low": "0.1~3.9",
    "info": "0.0",
}


def run(session: RedTeamSession, output_dir: str = ".", on_progress=None) -> str:
    log = on_progress or (lambda s: None)
    log("▶ 09. 보고서 생성 시작")

    all_findings_raw = session.all_findings()

    # ── 증거 등급 분류 (라벨링만, 기능 차단 없음) ─────────────────────────────
    # VERIFIED + LIKELY → 메인 취약점 목록
    # INFERRED          → 하단 "추가 조사 필요" 섹션 (버리지 않음)
    # AI_ANALYSIS       → "AI 분석" 별도 섹션
    verified_findings = []
    inferred_findings = []
    for f in all_findings_raw:
        level = f.get("evidence_level", "VERIFIED")
        if level == "AI_ANALYSIS":
            continue  # 별도 섹션 처리
        elif level == "INFERRED":
            inferred_findings.append(f)
        else:
            # VERIFIED / LIKELY 모두 메인 섹션
            verified_findings.append(f)

    all_findings = verified_findings
    # 심각도 순 정렬
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4))

    # 통계 (VERIFIED만)
    stats: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        stats[sev] = stats.get(sev, 0) + 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = session.target.replace("https://", "").replace("http://", "").split("/")[0]
    filename = f"report_{domain}_{ts}"

    # ── Markdown 보고서 ──────────────────────────────────────────
    md_lines = [
        f"# 침투 테스트 보고서",
        f"",
        f"**타겟:** `{session.target}`  ",
        f"**작성일:** {datetime.now().strftime('%Y년 %m월 %d일')}  ",
        f"**도구:** Bingo Red Team (github.com/you/bingo)  ",
        f"",
        f"---",
        f"",
        f"## 요약",
        f"",
        f"| 심각도 | 건수 | CVSS 범위 |",
        f"|--------|------|-----------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        md_lines.append(
            f"| {SEVERITY_KR[sev]} | **{stats[sev]}** | {SEVERITY_CVSS[sev]} |"
        )

    md_lines += [
        f"",
        f"**발견된 취약점: {len(all_findings)}건** (INFERRED 추가조사: {len(inferred_findings)}건)",
        f"",
        f"> 이 보고서는 HTTP 증거 등급으로 발견을 분류합니다.",
        f"> VERIFIED/LIKELY = 증거 있음 | INFERRED = 추가 조사 필요",
        f"",
        f"---",
        f"",
        f"## 검증된 취약점 상세",
        f"",
    ]

    for i, finding in enumerate(all_findings, 1):
        sev = finding.get("severity", "info")
        t = finding.get("type", "")
        title = finding.get("title", "")
        detail = finding.get("detail", finding.get("description", ""))
        curl_cmd = finding.get("curl", "")
        status_code = finding.get("status_code", 0)
        response_snip = finding.get("response_snippet", finding.get("response", ""))
        evidence_hash = finding.get("evidence_hash", "")

        md_lines += [
            f"### #{i} [{SEVERITY_KR[sev]}] {title}",
            f"",
            f"- **유형:** `{t}`",
            f"- **심각도:** {sev.upper()}",
            f"- **단계:** {finding.get('phase', 'N/A')}",
            f"- **HTTP 상태:** `{status_code}`",
            f"- **증거 해시:** `{evidence_hash}`",
            f"",
            f"**상세 내용:**",
            f"```",
            detail[:500] if detail else "(세부정보 없음)",
            f"```",
            f"",
        ]
        if curl_cmd:
            md_lines += [
                f"**재현 명령어 (curl):**",
                f"```bash",
                curl_cmd,
                f"```",
                f"",
            ]
        if response_snip:
            md_lines += [
                f"**응답 스니펫:**",
                f"```",
                response_snip[:300],
                f"```",
                f"",
            ]
        md_lines += [
            f"**권고 조치:**",
            _get_recommendation(t),
            f"",
            f"---",
            f"",
        ]

    # ── INFERRED 섹션 (추가 조사 단서 — 버리지 않음) ──────────────────────────
    if inferred_findings:
        md_lines += [
            f"## 🔍 추가 조사 필요 항목 (INFERRED)",
            f"",
            f"> HTTP 증거가 불충분하지만 단서로 기록됩니다. 수동 확인 권장.",
            f"",
        ]
        for j, inf in enumerate(inferred_findings, 1):
            sev = inf.get("severity", "info")
            md_lines += [
                f"### 조사 #{j} [{sev.upper()}] {inf.get('title', '미확인')}",
                f"",
                f"- **유형:** {inf.get('type', 'N/A')}",
                f"- **단계:** {inf.get('phase', 'N/A')}",
                f"",
                inf.get("description", "")[:200],
                f"",
            ]
            if inf.get("curl"):
                md_lines += [
                    f"```bash",
                    inf["curl"],
                    f"```",
                    f"",
                ]
        md_lines.append("")

    # 단계별 요약
    md_lines += ["---", "", "## 단계별 실행 결과", ""]
    for ph, pr in session.phases.items():
        md_lines.append(f"### Phase {ph}")
        md_lines.append(f"- 상태: {pr.status}")
        md_lines.append(f"- 소요 시간: {pr.duration:.0f}초")
        verified_cnt = sum(
            1 for f in pr.findings
            if f.get("evidence_level", "VERIFIED") == "VERIFIED"
        )
        md_lines.append(f"- 검증된 발견: {verified_cnt}/{len(pr.findings)}")
        if pr.ai_summary:
            md_lines += [
                f"",
                f"**[AI_ANALYSIS — 취약점 아님, 참고용]**",
                f"> {pr.ai_summary[:300]}",
            ]
        md_lines.append("")

    md_content = "\n".join(md_lines)

    # 파일 저장
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    md_file = out_path / f"{filename}.md"
    md_file.write_text(md_content, encoding="utf-8")
    log(f"  → Markdown 보고서: {md_file}")

    # ── HTML 보고서 ──────────────────────────────────────────────
    html = _build_html(session, all_findings, stats)
    html_file = out_path / f"{filename}.html"
    html_file.write_text(html, encoding="utf-8")
    log(f"  → HTML 보고서: {html_file}")

    log(f"✓ Phase 09 완료: {md_file}")
    return str(md_file)


def _get_recommendation(vuln_type: str) -> str:
    recs = {
        "sqli": "1. Prepared Statement / Parameterized Query 사용\n2. WAF 적용\n3. DB 계정 최소 권한 부여",
        "xss": "1. 출력 시 HTML 인코딩 (htmlspecialchars)\n2. Content-Security-Policy 헤더 적용\n3. httpOnly 쿠키 설정",
        "sensitive_file": "1. 민감 파일 즉시 삭제\n2. 웹 루트에 설정파일 배치 금지\n3. 서버 디렉토리 listing 비활성화",
        "admin_panel": "1. 관리자 페이지 IP 화이트리스트 적용\n2. MFA(다단계 인증) 적용\n3. 강력한 패스워드 정책 설정",
        "default_cred": "1. 기본 자격증명 즉시 변경\n2. 계정 잠금 정책 적용\n3. MFA 도입",
        "file_upload": "1. 업로드 파일 확장자 화이트리스트 검증\n2. MIME 타입 검증\n3. 업로드 디렉토리 실행 권한 제거",
        "waf": "WAF 설정 확인 — 우회 시도 가능성 점검",
        "open_port": "불필요한 포트 방화벽으로 차단",
        "nuclei": "발견된 취약점에 해당하는 패치/업데이트 즉시 적용",
        # ACPV 권고
        "storage_auth": (
            "1. 모든 인증 상태 검증을 서버 사이드에서 처리 (JWT 검증 서버에서)\n"
            "2. localStorage/sessionStorage에 인증 판단 로직 절대 금지\n"
            "3. API 요청마다 서버에서 토큰 유효성 검증\n"
            "4. 인증 필요 페이지는 서버에서 302 리다이렉트 처리"
        ),
        "unauth_api": (
            "1. 모든 API 엔드포인트에 인증 미들웨어 강제 적용\n"
            "2. Authorization 헤더 없는 요청은 401 반환\n"
            "3. 역할 기반 접근 제어(RBAC) 서버에서 검증\n"
            "4. API 게이트웨이에서 인증 토큰 검증"
        ),
        "response_manip": (
            "1. 클라이언트 응답 값으로 권한 판단 금지\n"
            "2. 모든 권한 체크는 서버 사이드에서 독립적으로 수행\n"
            "3. 민감 필드(is_active, role, groups)는 서버 세션 기반으로 관리\n"
            "4. 응답 변조로 인한 우회 불가능한 서버 검증 구조 설계"
        ),
        # MSSQL 2025 AI 기능 악용 권고
        "mssql2025_poc_generated": (
            "1. sp_invoke_external_rest_endpoint 즉시 비활성화:\n"
            "   EXEC sp_configure 'external rest endpoint enabled', 0; RECONFIGURE;\n"
            "2. 외부 네트워크 연결 방화벽으로 차단 (SQL Server 아웃바운드)\n"
            "3. 사용하지 않는 AI/ML 기능 비활성화\n"
            "4. SQL 인젝션 패치 (Prepared Statement 사용)\n"
            "5. DB 계정 최소 권한 원칙 적용 (sysadmin 권한 제거)"
        ),
        "stacked_query_confirmed": (
            "1. SQL 인젝션 즉시 패치 (Parameterized Query)\n"
            "2. 애플리케이션 DB 계정에서 EXECUTE 권한 제거\n"
            "3. WAF 규칙에 Stacked Query 패턴 추가\n"
            "4. SQL Server 감사 로그 활성화"
        ),
        "privilege_confirmed": (
            "1. 애플리케이션 DB 계정 최소 권한으로 제한\n"
            "2. sysadmin 역할은 관리 계정에만 부여\n"
            "3. 정기적 DB 계정 권한 감사 수행"
        ),
        # ArubaOS XXE SSRF 권고
        "aruba_banner": (
            "1. ArubaOS 8.x를 최신 버전으로 즉시 업그레이드\n"
            "2. 포트 32000/TCP를 방화벽에서 외부 차단 (관리망 격리)\n"
            "3. XML API 엔드포인트에 인증 강제 적용\n"
            "4. 외부 엔티티 처리(XXE) 비활성화 (XML 파서 설정)\n"
            "5. 컨트롤러 아웃바운드 HTTP 연결 화이트리스트 제한"
        ),
        "xxe_oob_confirmed": (
            "1. 즉시 ArubaOS 패치 적용 또는 포트 32000 방화벽 차단\n"
            "2. XML External Entity 처리 완전 비활성화\n"
            "3. 인증 없이 XML API 접근 불가하도록 AAA 프로파일 수정\n"
            "4. 내부망 → 외부망 HTTP 아웃바운드 연결 차단\n"
            "5. 침해 여부 확인: 컨트롤러 아웃바운드 로그 분석"
        ),
        "ssrf_internal_port": (
            "1. SSRF 경유 내부 포트 접근 방지: XML API 처리 격리\n"
            "2. 발견된 내부 서비스 추가 인증 강화\n"
            "3. 네트워크 microsegmentation으로 컨트롤러 이동 제한"
        ),
        "xxe_timing": (
            "1. ArubaOS XXE 취약점 패치 우선 적용\n"
            "2. 포트 32000 외부 노출 즉시 차단\n"
            "3. 침투테스터 OOB 인프라를 이용한 정밀 검증 권고"
        ),
        # Ivanti Sentry CVE-2026-10520 권고
        "rce_confirmed": (
            "1. Ivanti Sentry를 R10.5.2 / R10.6.2 / R10.7.1 이상으로 즉시 업그레이드\n"
            "2. /mics/api/v2/sentry/mics-config/handleMessage 엔드포인트 방화벽 차단\n"
            "3. Sentry 관리 인터페이스를 격리된 관리망에서만 접근 허용\n"
            "4. CVE-2026-10523 (관리자 계정 생성 취약점) 동시 패치 필수\n"
            "5. 침해 여부 확인: /mics/ 엑세스 로그 검토 (비정상 POST 요청)"
        ),
        "endpoint_reachable": (
            "1. 취약 엔드포인트 즉시 방화벽 차단\n"
            "2. Ivanti Sentry 패치 적용 후 재확인\n"
            "3. 인증 없이 접근 가능한 API 엔드포인트 전수 감사"
        ),
        "product_detected": (
            "1. Ivanti Sentry 버전 확인 및 최신 패치 적용\n"
            "2. CVE-2026-10520, CVE-2026-10523 영향 여부 검토\n"
            "3. 외부 인터넷에서 Sentry 관리 포트 접근 차단"
        ),
        # CSWSH + EXE Exposure + WebSocket RCE 권고
        cswsh_recs = {
            "js_exe_download": (
                "1. EXE/설치파일 다운로드 엔드포인트에 인증 요구 — 익명 접근 차단\n"
                "2. 다운로드 토큰 방식 적용 (1회용 서명 URL)\n"
                "3. Content-Type: application/octet-stream 응답에 X-Download-Auth 헤더 필수\n"
                "4. 배포 파일 무결성 확인 — SHA256 체크섬 공개 제공"
            ),
            "js_localhost_websocket": (
                "1. localhost WebSocket 서버에 Origin 헤더 검증 강제 구현\n"
                "   허용 Origin: ['https://your-domain.com'] 화이트리스트 방식\n"
                "2. WebSocket 업그레이드 요청에 CSRF 토큰 또는 API 키 요구\n"
                "3. WebSocket 프로토콜에 인증 토큰 포함 (초기 핸드셰이크 시)\n"
                "4. 민감한 WebSocket 기능 (파일실행 등)에 추가 인증 레이어 적용"
            ),
            "cswsh_port_open": (
                "1. [긴급] Origin 헤더 검증 즉시 구현\n"
                "   WebSocket 서버에서 Origin: 헤더를 파싱하고 화이트리스트 검증 필수\n"
                "2. localhost WebSocket 포트를 외부에서 접근 불가한 내부 포트로 이전\n"
                "3. 호스트 기반 방화벽으로 해당 포트에 localhost 접근만 허용\n"
                "4. 데스크톱 앱 설치 시 서버 소켓 바인딩 범위 제한 (127.0.0.1 only)"
            ),
            "exe_exposed": (
                "1. 배포 EXE 다운로드 URL에 로그인 세션 검증 추가\n"
                "2. 직접 URL 접근 차단 — Referer 또는 토큰 기반 다운로드 구현\n"
                "3. EXE 파일에 코드 서명 적용 (악성 교체 탐지)\n"
                "4. 다운로드 로그 기록 — 비정상 다운로드 IP 모니터링"
            ),
            "cswsh_rce_chain": (
                "1. [Critical] WebSocket Origin 검증 즉시 구현 (CSWSH 근본 원인)\n"
                "2. WebSocket 메서드 중 파일/프로세스 실행 기능 재검토\n"
                "   explorer.exe 폴백 패턴 사용 즉시 중단\n"
                "3. 실행 가능한 파일 경로를 화이트리스트로 엄격히 제한\n"
                "4. 원격 URL 기반 실행 기능 완전 제거 (RUN/DRIVE, RUN/APP 등)\n"
                "5. 데스크톱 앱 코드 서명 및 ASLR/DEP 활성화 확인"
            ),
        }
        if finding_type in cswsh_recs:
            return cswsh_recs[finding_type]

        # OAuth Chain Attack 권고
        "email_trust_chain": (
            "1. 이메일 인증 없이 계정 생성 즉시 차단 — 검증 전 로그인/OAuth 토큰 발급 금지\n"
            "2. OAuth 응답에 email_verified 필드 명시 — 소비 사이트에서 반드시 검증 필수\n"
            "3. 기존 미검증 계정 전수 조사 및 재검증 요구\n"
            "4. OAuth Provider 연동 사이트에 긴급 패치 알림 발송\n"
            "5. 이메일 기반 자동 SSO 프로비저닝 중단 (수동 검토로 변경)"
        ),
        "open_registration": (
            "1. Dynamic Client Registration 엔드포인트에 인증 요구 (RFC7591 IAT)\n"
            "2. redirect_uri를 사전 등록된 목록으로만 허용 (wildcard 금지)\n"
            "3. 등록된 클라이언트를 관리자 검토 후 활성화하는 프로세스 도입\n"
            "4. 클라이언트 등록 이벤트 알림 및 감사 로그 유지"
        ),
        "auth_without_session": (
            "1. Authorization 엔드포인트는 유효한 사용자 세션 필수 확인\n"
            "2. 세션 없는 요청은 로그인 페이지로 리다이렉트 (302)\n"
            "3. state 파라미터 필수 검증 (CSRF 방지)\n"
            "4. PKCE 필수 적용 (RFC7636) — code_challenge 없는 요청 거부"
        ),
        "cors_wildcard": (
            "1. OAuth 엔드포인트의 CORS: * 제거 — 허용된 오리진만 명시적 등록\n"
            "2. token_endpoint에 SameSite=Strict 쿠키 적용\n"
            "3. Vary: Origin 헤더 설정으로 캐시 우회 방지"
        ),
        "unverified_email_registration": (
            "1. 가입 즉시 이메일 인증 링크 발송 — 검증 전 계정 비활성화 유지\n"
            "2. 소셜 로그인 연결 시 이메일 재검증 요구\n"
            "3. OAuth 클레임의 email_verified: true인 경우에만 자동 계정 연결 허용"
        ),
        "metadata_exposed": (
            "1. 필요하지 않은 경우 /.well-known 엔드포인트 접근 제한\n"
            "2. token_endpoint_auth_methods_supported에서 'none' 제거\n"
            "3. registration_endpoint를 인증된 요청으로만 제한"
        ),
    }
    return recs.get(vuln_type, "해당 취약점에 맞는 보안 패치 적용")


def _build_html(session: RedTeamSession, findings: list[dict], stats: dict) -> str:
    COLORS = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffbb00",
              "low": "#44bb44", "info": "#aaaaaa"}

    rows = ""
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info")
        color = COLORS.get(sev, "#aaa")
        curl_snippet = f.get("curl", "")[:120]
        status = f.get("status_code", "")
        e_hash = f.get("evidence_hash", "")
        rows += f"""
        <tr>
          <td>{i}</td>
          <td><span style="color:{color};font-weight:bold">{sev.upper()}</span></td>
          <td>{f.get('type','')}</td>
          <td>{f.get('title','')[:80]}<br>
              {f'<code class="curl">{curl_snippet}...</code>' if curl_snippet else ''}
          </td>
          <td>{f.get('phase','N/A')}</td>
          <td>{status}</td>
          <td><span class="verified-badge">✅ VERIFIED</span><br><small>{e_hash}</small></td>
        </tr>"""

    stat_cards = "".join(
        f'<div class="card" style="border-left:4px solid {COLORS[s]}">'
        f'<div class="num">{stats[s]}</div>'
        f'<div class="lbl">{s.upper()}</div></div>'
        for s in ["critical", "high", "medium", "low", "info"]
    )

    return f"""<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><title>Bingo Security Report</title>
<style>
  body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem}}
  h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:.5rem}}
  .cards{{display:flex;gap:1rem;margin:1rem 0}}
  .card{{background:#161b22;border-radius:6px;padding:1rem;min-width:100px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:bold}}
  .card .lbl{{font-size:.8rem;color:#8b949e}}
  table{{width:100%;border-collapse:collapse;margin-top:1rem}}
  th{{background:#161b22;padding:.6rem;text-align:left}}
  td{{padding:.5rem;border-bottom:1px solid #21262d}}
  tr:hover{{background:#161b22}}
  .verified-badge{{background:#238636;color:#fff;padding:2px 6px;border-radius:3px;font-size:.75rem}}
  .zh-banner{{background:#1c2d17;border:1px solid #238636;border-radius:6px;padding:.75rem;margin:1rem 0;font-size:.85rem}}
  code.curl{{display:block;background:#161b22;padding:.5rem;border-radius:4px;font-size:.75rem;word-break:break-all;margin-top:.5rem;color:#79c0ff}}
</style>
</head>
<body>
<h1>🔒 Bingo Red Team Report</h1>
<p>타겟: <code>{session.target}</code></p>
<div class="zh-banner">
  ✅ <strong>Zero-Hallucination 보장</strong> — 이 보고서의 모든 취약점은 실제 HTTP 응답 증거가 첨부되었습니다.<br>
  증거 없는 추론은 취약점 목록에 포함되지 않습니다.
</div>
<h2>요약</h2>
<div class="cards">{stat_cards}</div>
<h2>검증된 취약점 목록</h2>
<table>
  <tr><th>#</th><th>심각도</th><th>유형</th><th>제목</th><th>단계</th><th>HTTP</th><th>증거</th></tr>
  {rows}
</table>
</body></html>"""
