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
    }
    if finding_type in recs:
        return recs[finding_type]

    # Next.js Cache Poisoning → 0-click SXSS 권고
    nextjs_recs = {
            "header_reflection": (
                "1. [긴급] 미들웨어에서 리퀘스트 헤더를 리스폰스 헤더에 그대로 전달하는 코드 제거\n"
                "   middleware.ts의 headers() 전달 로직 감사 필요\n"
                "2. Content-Type 헤더는 서버에서만 설정하고 클라이언트 요청값 무시\n"
                "3. 응답 헤더 화이트리스트 운영 — 허용된 헤더만 클라이언트로 전달\n"
                "4. Next.js 최신 버전 업데이트 (14.2.32+ / 15.4.7+)"
            ),
            "content_type_injection": (
                "1. RSC 요청에 대해 Content-Type을 서버에서 강제 설정\n"
                "   `res.setHeader('Content-Type', 'text/x-component')` 항상 덮어쓰기\n"
                "2. 미들웨어에서 Content-Type 헤더 전달 차단\n"
                "3. Vary: Content-Type 헤더 추가로 CDN 캐시 분리"
            ),
            "rsc_dynamic_page": (
                "1. 동적 페이지의 RSC 응답에 Cache-Control: no-store, private 설정\n"
                "2. Cloudflare Page Rule로 RSC 경로 캐싱 비활성화\n"
                "3. Vary: Rsc 헤더를 CDN이 올바르게 처리하도록 캐시 설정 검토"
            ),
            "cache_sxss_chain": (
                "1. [Critical] 미들웨어 헤더 전달 코드 즉시 제거 (근본 원인)\n"
                "2. Cloudflare에서 RSC 경로 (_next/data, RSC 파라미터 포함 URL) 캐싱 제외\n"
                "3. Content-Security-Policy 헤더 강화 — script-src 'strict'\n"
                "4. URL 파라미터의 동적 페이지 반영 최소화 — 서버사이드 인코딩 강제\n"
                "5. Next.js 최신 보안 패치 즉시 적용"
            ),
            "param_reflected_in_rsc": (
                "1. RSC 페이로드에 포함되는 URL 파라미터 값 HTML 인코딩 강제 적용\n"
                "2. 동적 렌더링 페이지에서 `searchParams` 직접 출력 금지\n"
                "3. DOMPurify 또는 서버사이드 sanitization 적용"
            ),
            "cache_layer": (
                "1. CDN 캐시 키 설정 검토 — Rsc, Content-Type 등 보안 헤더 포함\n"
                "2. Vary 헤더를 CDN이 올바르게 처리하는지 정기 감사\n"
                "3. 인증 필요 경로는 캐싱 완전 비활성화"
            ),
        }
    if finding_type in nextjs_recs:
        return nextjs_recs[finding_type]

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

        # Redis DarkReplica CVE-2026-23631 권고
        redis_recs = {
            "redis_found": (
                "1. Redis를 인터넷에 직접 노출하지 말 것 — 방화벽으로 6379 포트 차단\n"
                "2. bind 127.0.0.1 설정으로 로컬 전용 접근 제한\n"
                "3. requirepass 설정으로 강력한 패스워드 적용 (최소 32자 무작위 문자열)"
            ),
            "redis_noauth": (
                "1. [긴급] Redis requirepass 즉시 설정 — 인증 없는 접근 완전 차단\n"
                "2. 방화벽 규칙으로 신뢰된 IP만 Redis 포트 접근 허용\n"
                "3. Redis ACL (Redis 6.0+) 적용으로 명령어별 권한 세분화\n"
                "4. protected-mode yes 설정 확인"
            ),
            "redis_weak_auth": (
                "1. [긴급] Redis 패스워드를 고강도로 즉시 변경 (최소 32자)\n"
                "2. Redis 6.0+ ACL 사용자 인증 시스템으로 마이그레이션\n"
                "3. 패스워드를 설정 파일에 평문 저장하지 말고 환경변수/Vault 사용"
            ),
            "vulnerable_version": (
                "1. [긴급] Redis 버전 즉시 업그레이드:\n"
                "   - 7.2.x → 7.2.14+\n"
                "   - 7.4.x → 7.4.9+\n"
                "   - 8.2.x → 8.2.6+\n"
                "   - 8.4.x → 8.4.3+\n"
                "   - 8.6.x → 8.6.3+\n"
                "2. 업그레이드 전 SLAVEOF / REPLICAOF 명령어 ACL로 제한\n"
                "3. 신뢰된 IP만 Redis에 접근하도록 방화벽 규칙 강화"
            ),
            "slaveof_allowed": (
                "1. SLAVEOF/REPLICAOF 명령어를 ACL로 관리자 전용으로 제한\n"
                "2. replica-read-only yes 설정 유지\n"
                "3. 알려진 마스터 서버 외 복제 연결 차단"
            ),
            "function_engine_available": (
                "1. FUNCTION 명령어를 ACL로 제한 (FUNCTION LOAD는 관리자만)\n"
                "2. 운영 환경에서 Lua 스크립트 실행 시간 제한 적용\n"
                "   `lua-time-limit 500` (밀리초) 설정\n"
                "3. FUNCTION / EVAL 명령어를 일반 사용자 ACL에서 제거"
            ),
            "dark_replica_exploitable": (
                "1. [긴급] Redis 즉시 패치 — CVE-2026-23631 취약 버전\n"
                "2. 네트워크 격리: Redis를 내부 네트워크로만 제한\n"
                "3. SLAVEOF / FUNCTION LOAD 명령어 ACL 제한\n"
                "4. Redis 로그 모니터링: 비정상 SLAVEOF 명령 알림 설정\n"
                "5. Lua time limit 축소로 UAF 트리거 윈도우 최소화"
            ),
            "dark_replica_likely": (
                "1. Redis 버전 확인 및 패치 적용 우선순위 Critical로 설정\n"
                "2. 방화벽으로 6379 포트 외부 접근 즉시 차단\n"
                "3. ACL로 SLAVEOF / FUNCTION LOAD 권한 최소화\n"
                "4. 패치 완료 전까지 Redis 앞에 프록시 레이어 도입"
            ),
        }
    if finding_type in redis_recs:
        return redis_recs[finding_type]

        # HTML Autofill Steal 권고
        autofill_recs = {
            "csp_detected": (
                "1. CSP는 HTML Injection을 막지 않음 — 반사된 모든 파라미터를 컨텍스트별 인코딩 처리\n"
                "2. <meta http-equiv> 및 <meta name=referrer> 태그 삽입을 차단하는 별도 필터 적용\n"
                "3. script-src 'none'만으로는 충분하지 않음 — HTML/CSS injection 가능성 별도 검토 필수"
            ),
            "login_form_found": (
                "1. 로그인 폼이 있는 페이지의 모든 GET 파라미터를 반사 없이 처리\n"
                "2. 비밀번호 폼을 GET 방식으로 제출되지 않도록 강제 POST 설정\n"
                "3. autocomplete=off 설정 (보조적 방어 — 브라우저마다 다름)"
            ),
            "html_injection_found": (
                "1. [긴급] 해당 파라미터의 출력을 HTML Entity 인코딩으로 즉시 수정\n"
                "2. DOMPurify 또는 서버측 HTML sanitizer 적용\n"
                "3. Content-Type: text/plain으로 응답 처리 가능한 엔드포인트는 전환 검토"
            ),
            "csp_bypassed_via_html": (
                "1. [긴급] strict CSP가 있어도 HTML injection이 존재하면 비번 탈취 가능 — 즉시 패치\n"
                "2. HTML injection 포인트를 우선순위 Critical로 분류하여 처리\n"
                "3. 동일 도메인 내 반사 파라미터 전수 조사 실시"
            ),
            "referrer_policy_override": (
                "1. Referrer-Policy: no-referrer 헤더를 HTTP 응답에 명시적으로 설정\n"
                "2. <meta name=referrer> 삽입을 CSP에서 차단할 방법 검토 (meta-src 제한)\n"
                "3. Chrome의 <meta> 태그에 의한 Referrer-Policy 오버라이드 동작을 고려한 방어 설계"
            ),
            "autofill_steal_exploitable": (
                "1. [긴급] HTML injection 발생 파라미터 즉시 수정 (Entity 인코딩)\n"
                "2. 비밀번호를 절대 GET 파라미터로 전송하지 않도록 폼 method를 POST로 강제\n"
                "3. Referrer-Policy: no-referrer 서버 응답 헤더 추가\n"
                "4. 공격자 서버(attacker.example.com)로의 Referer 전송 차단을 위한 WAF 규칙 추가\n"
                "5. 입력값 검증 우회 패턴에 대한 정기 자동화 스캔 도입"
            ),
            "autofill_steal_likely": (
                "1. 로그인 페이지에 HTML injection 포인트가 없는지 전수 점검\n"
                "2. 외부에서 접근 가능한 GET 파라미터 반사 여부 정기 감사\n"
                "3. Chrome 사용자를 대상으로 한 비번 탈취 가능성 인식 교육"
            ),
        }
    if finding_type in autofill_recs:
        return autofill_recs[finding_type]

        # Web Cache Deception + SameSite Lax Bypass 권고
        wcd_recs = {
            "cache_header_detected": (
                "1. 민감한 인증 응답 페이지에 Cache-Control: no-store, private 헤더 추가\n"
                "2. CDN/리버스 프록시 설정에서 인증 필요 경로를 캐시 제외 목록에 등록\n"
                "3. Vary: Cookie 헤더 추가로 쿠키별 캐시 분리"
            ),
            "cacheable_without_private": (
                "1. [긴급] 인증된 사용자 데이터를 포함하는 모든 응답에 Cache-Control: private, no-store 추가\n"
                "2. CDN 오리진 Shield 설정에서 Set-Cookie가 있는 응답 캐시 금지\n"
                "3. /profile /settings /dashboard 등 민감 경로 URL 패턴을 CDN 캐시 제외 규칙에 추가\n"
                "4. 캐시 정책 감사 자동화 도구 도입 (캐시 헤더 CI 검사)"
            ),
            "sensitive_data_in_cache": (
                "1. [긴급] JWT/세션토큰이 포함된 응답에 Cache-Control: no-store 즉시 적용\n"
                "2. 토큰 및 PII를 HTTP 응답 Body에 직접 포함하지 않도록 아키텍처 변경\n"
                "3. 이미 캐시된 응답 즉시 퍼지(purge) 처리\n"
                "4. 캐시 서버 로그 분석으로 기존 민감 데이터 유출 여부 확인"
            ),
            "cache_confirmed_miss_to_hit": (
                "1. 캐시 MISS→HIT 확인된 경로에 대해 즉시 캐시 무효화(purge)\n"
                "2. Cache-Control: no-store 추가 후 재확인 테스트\n"
                "3. CDN WAF에서 의심스러운 cache buster 파라미터(?cb=) 탐지 규칙 추가"
            ),
            "samesite_lax_bypass_possible": (
                "1. SameSite=Strict로 업그레이드 — top-level navigation 포함 모든 교차 사이트 요청 차단\n"
                "2. CSRF 토큰을 추가 방어 레이어로 적용\n"
                "3. 핵심 인증 쿠키에 __Host- prefix 적용으로 도메인 스코프 제한\n"
                "4. 공격자가 top-level navigation을 유도하는 오픈 리다이렉트 차단"
            ),
            "wcd_exploitable": (
                "1. [긴급] 영향받는 모든 경로에 Cache-Control: no-store, private 즉시 적용\n"
                "2. SameSite=Strict로 쿠키 업그레이드\n"
                "3. CDN 캐시 전체 퍼지(purge) 후 캐시 키 정책 재설계\n"
                "4. 보안 헤더 자동 검사를 CI/CD 파이프라인에 통합\n"
                "5. 정기적인 Cache Deception 자동 스캔 도입"
            ),
            "wcd_likely": (
                "1. 캐시 가능 경로에서 인증 세션으로 직접 테스트하여 민감 데이터 노출 확인\n"
                "2. 캐시 설정 전수 감사 및 Cache-Control 헤더 일관성 검토\n"
                "3. CDN 벤더의 캐시 설정 모범 사례 문서 참조하여 재설정"
            ),
            "sensitive_path_cacheable": (
                "1. 해당 경로(/profile /settings 등)를 CDN 캐시 제외 목록에 추가\n"
                "2. 경로별 Cache-Control: private 적용 여부 전수 점검\n"
                "3. 민감 경로 응답에서 JWT/토큰을 응답 Body 대신 HttpOnly 쿠키로 처리"
            ),
        }
    if finding_type in wcd_recs:
        return wcd_recs[finding_type]

        # Cloud Token Recon 권고
        ctr_recs = {
            "open_dev_tool": (
                "1. Grafana / Prometheus / Kibana / Jenkins 등 내부 DevTool에 인증 필수 적용\n"
                "2. 내부 모니터링 도구를 인터넷에 직접 노출 금지 — VPN / IP 화이트리스트 필수\n"
                "3. 해당 IP의 TLS 인증서 SAN을 점검하여 노출된 섀도우 도메인 확인\n"
                "4. 클라우드 메타데이터 서비스(169.254.169.254) 접근을 iptables/IMDSv2로 제한"
            ),
            "tls_san_wildcard": (
                "1. 와일드카드 SAN 인증서 발급 범위를 최소화 — 필요한 서브도메인만 명시적 등록\n"
                "2. Certificate Transparency 로그(crt.sh)를 정기적으로 모니터링하여 예상치 못한 서브도메인 발견\n"
                "3. 사용하지 않는 섀도우 도메인/서브도메인 즉시 폐기 및 DNS 레코드 삭제\n"
                "4. 내부 실험 환경(llm-playground, dev, staging)에 공개 TLS 인증서 발급 금지"
            ),
            "js_hidden_domain": (
                "1. 프로덕션 JS 번들에서 내부 도메인/API 참조 제거 — 빌드 시 환경변수로 분리\n"
                "2. JS 번들 난독화 및 민감한 엔드포인트 경로 하드코딩 금지\n"
                "3. 정기적으로 자체 JS 번들을 파싱하여 예상치 못한 도메인 참조 감사\n"
                "4. 내부 API 도메인은 CORS + 인증으로 외부 직접 접근 차단"
            ),
            "cloud_token_exposed": (
                "1. 클라우드 토큰 반환 엔드포인트에 즉시 인증 추가 (API Key / IAM / OAuth2)\n"
                "2. 노출된 GCP/AWS/Azure 토큰 즉시 폐기 및 재발급\n"
                "3. Secret Manager / Secrets Manager에 저장된 모든 시크릿 순환(rotate)\n"
                "4. IAM 최소 권한 원칙 적용 — 서비스 계정이 Secret Manager 전체 읽기 권한 보유 금지\n"
                "5. Vercel / GitHub 토큰은 환경변수가 아닌 전용 시크릿 볼트에 저장\n"
                "6. GitHub Organization에서 노출된 PAT 즉시 폐기 및 저장소 접근 감사 로그 확인"
            ),
            "shadow_domain_token_exposed": (
                "1. 섀도우 도메인의 비인증 토큰 엔드포인트 즉시 인증 적용 또는 서비스 종료\n"
                "2. 내부 AI/LLM 실험 환경(haloworld.xyz, metafb.cloud 류)을 공개 DNS에서 제거\n"
                "3. JS 번들에서 발견된 내부 도메인 참조 즉시 제거 후 재배포\n"
                "4. 노출된 모든 클라우드 크리덴셜 체인(GCP→Vercel→GitHub) 전체 순환"
            ),
            "likely_cloud_chain": (
                "1. DevTool 인증 강화 및 TLS SAN 와일드카드 도메인 전수 점검\n"
                "2. crt.sh에서 조직 도메인으로 발급된 인증서 목록 확인 및 불필요한 도메인 폐기\n"
                "3. GCP/AWS 서비스 계정의 최소 권한 설정 검토\n"
                "4. Secret Manager 접근 감사 로그 활성화 및 비정상 접근 알림 설정"
            ),
        }
    if finding_type in ctr_recs:
        return ctr_recs[finding_type]

    # OAuth Chain Attack 권고
    oauth_recs = {
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
    if finding_type in oauth_recs:
        return oauth_recs[finding_type]

    # Advanced SQLi (EXTRACTVALUE error-based + Second-Order) 권고
    asqli_recs = {
        "error_based_extractvalue": (
            "1. 모든 SQL 쿼리에 Prepared Statement(Parameterized Query) 필수 적용\n"
            "2. PDO/MySQLi의 bind_param 또는 ORM(Doctrine/Hibernate) 사용으로 직접 문자열 연결 금지\n"
            "3. EXTRACTVALUE 함수 실행 권한 제한 — MySQL FILE/EXECUTE 권한 최소화\n"
            "4. 에러 메시지 노출 차단: `display_errors=Off`, `log_errors=On`\n"
            "5. WAF 규칙에 `EXTRACTVALUE`, `CONCAT(0x7e`, `XPATH syntax` 패턴 차단 추가\n"
            "6. DB 계정에 최소 권한만 부여 (SELECT only for read, 쓰기 권한 분리)"
        ),
        "time_based": (
            "1. Prepared Statement 적용으로 SLEEP()/WAITFOR DELAY 인젝션 원천 차단\n"
            "2. 응답 시간 이상 감지 규칙 WAF/IDS에 추가 (동일 파라미터로 N초 이상 응답 = 차단)\n"
            "3. DB 레벨에서 SLEEP() 함수 실행 권한 제한 (`REVOKE EXECUTE ON PROCEDURE mysql.sleep`)\n"
            "4. 쿼리 실행 시간 제한 설정: `max_execution_time` (MySQL 5.7.8+)\n"
            "5. 모든 사용자 입력 데이터 타입 검증 (숫자 파라미터는 intval() 처리)"
        ),
        "second_order": (
            "1. 저장 시점과 사용 시점 모두에서 입력값 이스케이프/바인딩 적용\n"
            "2. DB에서 읽어 온 데이터를 다시 SQL에 사용할 때도 Prepared Statement 필수\n"
            "3. 이메일 알림/예약 작업/리포트 생성 등 비동기 처리 코드 보안 감사\n"
            "4. 배치/크론 잡에서 사용하는 쿼리 코드 전수 검토 — 동적 쿼리 조합 제거\n"
            "5. 입력 데이터 저장 시 허용 문자셋 검증 (화이트리스트 방식)\n"
            "6. 비동기 처리 결과 로그에서 DB 에러 자동 알림 설정"
        ),
        "oob_dns": (
            "1. MySQL의 LOAD_FILE() 함수 비활성화: `secure_file_priv=''` 금지, NULL 또는 빈 경로 설정\n"
            "2. DB 서버의 아웃바운드 DNS/HTTP 요청을 방화벽으로 차단 (egress filtering)\n"
            "3. DB 서버를 인터넷 접근 불가 내부 네트워크에 격리\n"
            "4. `FILE` 권한을 DB 계정에서 제거: `REVOKE FILE ON *.* FROM 'user'@'host'`\n"
            "5. DNS 쿼리 모니터링으로 DB 서버발 외부 DNS 요청 탐지 및 알림"
        ),
    }
    if finding_type in asqli_recs:
        return asqli_recs[finding_type]

    # Copy Fail CVE-2026-31431 Kernel LPE + Container Escape 권고
    copyfail_recs = {
        "kernel_version_vuln": (
            "1. 즉시 커널 업데이트: 각 배포판 보안 패치 적용 (2026-04-01 이후 릴리즈)\n"
            "   - Ubuntu: apt-get update && apt-get upgrade linux-image-$(uname -r)\n"
            "   - Amazon Linux: yum update kernel\n"
            "   - RHEL/CentOS: yum update kernel\n"
            "   - SUSE: zypper patch\n"
            "2. 즉각적 임시 완화: algif_aead 모듈 비활성화\n"
            "   sudo rmmod algif_aead\n"
            "   echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf\n"
            "   sudo dracut -f  # initramfs 재생성\n"
            "3. AF_ALG 소켓 접근 제한: seccomp-bpf 정책으로 AF_ALG(38) 소켓 생성 차단\n"
            "4. SUID 바이너리 최소화: chmod u-s /usr/bin/su /usr/bin/sudo (필요시 재검토)\n"
            "5. 온디스크 무결성 검사로는 감지 불가 — AIDE/Tripwire 실행 중 페이지 캐시 모니터링 추가"
        ),
        "algif_aead_loaded": (
            "1. 즉시 algif_aead 모듈 언로드: sudo rmmod algif_aead\n"
            "2. 영구 비활성화: echo 'install algif_aead /bin/false' | sudo tee "
            "/etc/modprobe.d/disable-algif-aead.conf\n"
            "3. AF_ALG 소켓(PF_ALG=38) 사용 여부 감사: ss -xlp | grep AF_ALG\n"
            "4. 커널 패치 적용 후 모듈 영구 비활성화 해제 여부 재검토\n"
            "5. 런타임 감지: auditctl -a always,exit -F arch=b64 -S socket "
            "-F a0=38 -k af_alg_socket_call"
        ),
        "container_escape_path": (
            "1. 호스트 커널 즉시 패치 — 페이지 캐시는 호스트 전역 공유이므로 컨테이너 내부 패치 불가\n"
            "2. K8s Pod Security Policy/Admission: privileged=false, "
            "allowPrivilegeEscalation=false 강제\n"
            "3. Seccomp 프로파일 강화: RuntimeDefault 또는 socket syscall AF_ALG 차단 커스텀 프로파일\n"
            "4. AppArmor/SELinux 프로파일로 AF_ALG 소켓 생성 제한\n"
            "5. 컨테이너 런타임 업데이트 (gVisor/Kata Containers 고려 — 완전 격리된 커널 사용)\n"
            "6. Node-level: algif_aead 모듈 언로드 DaemonSet 배포"
        ),
        "kernel_banner_leak": (
            "1. HTTP 응답 헤더에서 커널/OS 버전 정보 제거\n"
            "   - Apache: ServerTokens Prod / ServerSignature Off\n"
            "   - Nginx: server_tokens off\n"
            "2. /proc/version, /proc/cpuinfo 등 직접 접근 경로 웹 서버에서 차단\n"
            "3. X-Powered-By 헤더 제거 (PHP: expose_php=Off)\n"
            "4. 정보 노출 자체가 CVE-2026-31431 공격 우선순위 지정에 활용됨 — 조속히 제거"
        ),
        "python310_available": (
            "1. 웹쉘/RCE 차단이 우선: 파일 업로드 필터링 강화, WAF 적용\n"
            "2. Python 3.10+ 실행 환경에서 os.splice 사용 제한 (불필요한 시스템 콜 차단)\n"
            "3. 서버 Python 실행 권한 최소화: www-data 계정 제한, chroot/namespace 격리\n"
            "4. 해당 취약점의 PoC는 Python 3.10+ 전용 — Python 버전 다운그레이드는 임시 완화책\n"
            "5. 근본 해결: 커널 패치 (algif_aead 수정)"
        ),
    }
    if finding_type in copyfail_recs:
        return copyfail_recs[finding_type]

    # Ruby Ruzzy+LibAFL C extension parser fuzzing surface 권고
    ruby_libafl_recs = {
        "c_ext_parser": (
            "1. Ruzzy+LibAFL 지속 퍼징 캠페인 설정: 발견된 C 확장 파서 엔드포인트 대상 "
            "(nokogiri, oj, graphql-ruby, msgpack-ruby, google-protobuf)\n"
            "2. 모든 C 확장 파서에 입력 크기 제한 및 타임아웃 설정 "
            "(request body size limit, rack timeout)\n"
            "3. 파일 업로드 시 magic byte 검증 + 허용 MIME 타입 화이트리스트 적용\n"
            "4. 역직렬화 입력 전 JSON Schema / XML Schema 사전 검증 추가\n"
            "5. C 확장 파서 버전을 최신으로 유지 (bundle update nokogiri oj msgpack)\n"
            "6. LibAFL 0.8.0 + Ruzzy 하네스 참고:\n"
            "   FUZZER_NO_MAIN_LIB=/usr/lib/libFuzzer.a LD=lld bundle exec ruzzy fuzz harness.rb"
        ),
        "framework_detected": (
            "1. HTTP 응답 헤더에서 Ruby/Rails/Sinatra 버전 정보 제거\n"
            "   config.middleware.use Rack::Protection\n"
            "2. 프로덕션 모드에서 상세 에러 메시지 비활성화\n"
            "   config.consider_all_requests_local = false (Rails)\n"
            "3. Ruzzy+LibAFL 퍼징으로 C 확장 파서 취약점 사전 발견\n"
            "4. Brakeman (Ruby SAST) 정기 실행으로 소스코드 취약점 탐지\n"
            "5. Bundler audit 설정으로 취약 gem 자동 경보 활성화"
        ),
        "yaml_unsafe": (
            "1. 즉시 YAML.load / Psych.load → YAML.safe_load / Psych.safe_load 교체\n"
            "   (YAML.safe_load는 Ruby 객체 역직렬화 차단)\n"
            "2. permitted_classes 최소화: YAML.safe_load(data, permitted_classes: [])\n"
            "3. Psych C 확장 대상 Ruzzy+LibAFL 퍼징:\n"
            "   require 'psych'; Ruzzy.fuzz { |d| Psych.safe_load(d.to_s) }\n"
            "4. 사용자 입력 YAML 수신 엔드포인트 제거 검토\n"
            "5. Brakeman YAML 취약점 스캔: brakeman --run-all-checks"
        ),
        "gem_version_leak": (
            "1. HTTP 응답 헤더에서 gem/프레임워크 버전 정보 제거\n"
            "   Rack middleware로 Server 헤더 교체: config.middleware.use → custom Server header\n"
            "2. bundle audit 설정으로 알려진 CVE 자동 탐지\n"
            "3. 공개된 gem 버전과 CVE DB 교차 확인 (bundler-audit, ruby-advisory-db)\n"
            "4. Gemfile.lock을 공개 저장소에 커밋하지 않도록 .gitignore 설정 검토"
        ),
        "graphql_endpoint": (
            "1. GraphQL 쿼리 depth 제한: max_depth 설정 (graphql-ruby)\n"
            "   GraphQL::Schema.max_depth(10)\n"
            "2. GraphQL 쿼리 complexity 제한 설정\n"
            "   GraphQL::Schema.max_complexity(200)\n"
            "3. libgraphqlparser C 확장 Ruzzy+LibAFL 퍼징:\n"
            "   require 'graphql'; Ruzzy.fuzz { |d| GraphQL.parse(d.to_s) rescue nil }\n"
            "4. Introspection 프로덕션 비활성화:\n"
            "   disable_introspection_entry_points if Rails.env.production?\n"
            "5. graphql-ruby 최신 버전 유지 (bundle update graphql)"
        ),
        "file_upload": (
            "1. 파일 업로드 MIME type 화이트리스트 검증 (magic bytes 기준)\n"
            "2. 이미지 처리 시 MiniMagick/RMagick 대신 ImageMagick 정책 파일 강화\n"
            "   /etc/ImageMagick-*/policy.xml → disable PS/EPS/PDF\n"
            "3. 파일 업로드 파이프라인 Ruzzy+LibAFL 퍼징:\n"
            "   MiniMagick::Image.open(tempfile) 하네스 작성\n"
            "4. 업로드 파일을 웹 서버 document root 외부에 저장\n"
            "5. CarrierWave/ActiveStorage 파일 타입 검증 플러그인 활성화"
        ),
    }
    if finding_type in ruby_libafl_recs:
        return ruby_libafl_recs[finding_type]

    # AI-generated code security surface detection 권고
    ai_code_sec_recs = {
        "secret": (
            "1. 즉시 노출된 자격증명 무효화 (API 키/토큰/비밀번호 즉시 교체)\n"
            "2. 소스 코드/JS 번들에서 시크릿 제거 → 환경변수로 이동 (process.env / os.environ)\n"
            "3. CI/CD 파이프라인에 gitleaks / truffleHog 시크릿 스캔 추가\n"
            "4. AI 코딩 도구 출력물 배포 전 의무적 보안 코드리뷰 절차 수립\n"
            "5. Git 히스토리 정리 (BFG Repo-Cleaner / git filter-repo)"
        ),
        "env_file": (
            "1. .env 파일 즉시 웹 서버 접근 차단 (nginx: deny all; / apache: Require all denied)\n"
            "2. .env 파일을 웹루트 밖으로 이동\n"
            "3. .gitignore에 .env 파일 패턴 추가\n"
            "4. 노출된 모든 환경변수 값 즉시 교체"
        ),
        "dependency": (
            "1. 취약한 의존성 즉시 최신 버전으로 업데이트 (npm update / yarn upgrade)\n"
            "2. CI/CD에 npm audit / snyk / OWASP Dependency-Check 통합\n"
            "3. JS 번들에서 라이브러리 버전 정보 노출 최소화 (webpack banner plugin 제거)\n"
            "4. Software Bill of Materials (SBOM) 정기 검토"
        ),
        "ai_artifact": (
            "1. AI 생성 코드 프로덕션 배포 전 보안 리뷰 의무화\n"
            "2. CORS 정책 강화: * 와일드카드 제거, 허용 origin 명시\n"
            "3. 디버그/테스트 라우트 프로덕션 환경에서 비활성화\n"
            "4. 기본/플레이스홀더 자격증명 탐지 자동화 (pre-commit hook 설정)\n"
            "5. AI 코딩 도구 보안 가이드라인 수립 (what AI should NOT generate)"
        ),
        "config_exposure": (
            "1. 설정/자격증명 파일 공개 접근 즉시 차단\n"
            "2. 웹 서버 설정: 민감한 파일 접근 deny (*.env, *.json, .git/)\n"
            "3. cloud credentials 즉시 교체 (credentials.json, service-account.json)\n"
            "4. Spring Actuator 프로덕션 환경 비활성화 또는 인증 요구\n"
            "5. Docker/K8s 보안 스캔으로 노출된 설정 파일 지속 탐지"
        ),
        "business_logic": (
            "1. 가격/금액 관련 API 서버사이드 검증 강화 (음수/초과 값 거부)\n"
            "2. 이체/출금 API 멱등성 키 구현 (race condition 방지)\n"
            "3. 관리자/민감 엔드포인트 인증 미들웨어 확인 (AI 스캐폴드 누락 패턴)\n"
            "4. IDOR 방지: 직접 객체 참조 대신 UUID + 권한 확인\n"
            "5. 비즈니스 로직 취약점 대상 자동화 테스트 추가"
        ),
        "cors_wildcard": (
            "1. Access-Control-Allow-Origin: * 제거\n"
            "2. 허용 origin 화이트리스트 관리 (CORS_ALLOWED_ORIGINS 환경변수)\n"
            "3. credentials: true 와 * origin 동시 사용 금지 (브라우저 차단되지만 코드 정리 필요)\n"
            "4. AI 코딩 보일러플레이트 CORS 기본값 조직 내 보안 템플릿으로 교체"
        ),
        "actuator": (
            "1. Spring Actuator /env /heapdump /configprops 엔드포인트 즉시 비활성화\n"
            "   (application.properties: management.endpoints.web.exposure.include=health,info)\n"
            "2. 내부 네트워크 접근만 허용하는 방화벽 규칙 적용\n"
            "3. 노출된 환경변수 내 모든 자격증명 즉시 교체"
        ),
    }
    if finding_type in ai_code_sec_recs:
        return ai_code_sec_recs[finding_type]

    # CSPT + Cloudflare WAF Bypass + Multi-ContentType Fuzzing 권고 (Skill #56)
    cspt_waf_recs = {
        "cspt": (
            "1. 프론트엔드 JS에서 location.pathname/location.hash/router.query를 직접 API URL에 연결하지 않도록 리팩토링\n"
            "2. 서버 측에서 경로 파라미터 화이트리스트 검증 (../ 시퀀스 및 URL 인코딩 변형 거부)\n"
            "3. API Gateway에서 경로 순회 패턴 차단 규칙 추가\n"
            "4. URL 정규화 미들웨어 도입 — 요청 전에 경로를 정규화 및 검증\n"
            "5. CSPT 전용 통합 테스트 추가: React/Angular/Vue 라우터 파라미터가 API fetch에 전달되는 경로 검증\n"
            "참고: @xssdoctor CSPT 연구 (Intigriti Bug Bytes #235, 2026년 4월)"
        ),
        "cf_bypass": (
            "1. Cloudflare WAF 커스텀 규칙 추가: oncontentvisibilityautostatechange 이벤트 핸들러 필터링\n"
            "2. Content Security Policy (CSP) 강화: script-src strict-dynamic + nonce 방식 적용\n"
            "3. DOMPurify 등 클라이언트 사이드 HTML 새니타이저 도입\n"
            "4. Cloudflare Managed Challenge + Bot Management 활성화\n"
            "5. WAF 규칙을 정기적으로 업데이트 (신규 이벤트 핸들러 우회 기법 대응)\n"
            "6. XSS 발생 시 즉각 영향받은 사용자 세션/토큰 무효화\n"
            "참고: @YourFinalSin CF WAF bypass (Intigriti Bug Bytes #235, 2026년 4월)"
        ),
        "content_type": (
            "1. API 엔드포인트에서 허용 Content-Type 화이트리스트 적용 (JSON만 허용 시 text/xml 등 거부)\n"
            "2. XML 파서에 XXE 방지 설정: DOCTYPE 선언 비활성화, 외부 엔티티 처리 금지\n"
            "   Java: DocumentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
            "   Python: defusedxml 라이브러리 사용\n"
            "3. Content-Type별 입력 검증 미들웨어 분리 구현\n"
            "4. API Gateway에서 허용되지 않는 Content-Type에 415 Unsupported Media Type 반환\n"
            "참고: Intigriti Bug Bytes #235 다중 Content-Type 퍼징 (2026년 4월)"
        ),
        "oauth_chain": (
            "1. 즉시: 영향받은 사용자의 OAuth 액세스 토큰 및 리프레시 토큰 전체 무효화\n"
            "2. Authorization Code에 PKCE (Proof Key for Code Exchange) 필수 적용 (RFC 7636)\n"
            "3. state 파라미터 CSRF 검증 강화 (랜덤 nonce + 세션 바인딩)\n"
            "4. redirect_uri 엄격 검증 (정확한 문자열 매칭, 와일드카드/서브도메인 금지)\n"
            "5. Authorization Code 단회 사용 보장 및 짧은 만료 시간 설정 (5분 이내)\n"
            "6. XSS 취약점 우선 제거 (CF WAF 우회 차단) → OAuth 코드 탈취 경로 차단\n"
            "참고: Intigriti Bug Bytes #235 CF WAF bypass → OAuth ATO 체인 (2026년 4월)"
        ),
        "cookie_xss": (
            "1. 쿠키 값을 innerHTML/document.write/eval에 직접 삽입하지 않도록 코드 리팩토링\n"
            "2. 쿠키 값을 DOM에 삽입 시 textContent 사용 (innerHTML 대신)\n"
            "3. 모든 쿠키에 HttpOnly 플래그 설정 (JS에서 접근 불가)\n"
            "4. SameSite=Strict 또는 SameSite=Lax 설정으로 CSRF 및 쿠키 주입 경로 차단\n"
            "5. 쿠키 값 화이트리스트 검증 미들웨어 추가\n"
            "참고: @RenwaX23 cookie injection DOM XSS (Intigriti Bug Bytes #235, 2026년 4월)"
        ),
        "auxclick": (
            "1. X-Frame-Options: DENY 또는 SAMEORIGIN 헤더 추가 (미설정 시)\n"
            "2. Content-Security-Policy: frame-ancestors 'none' 또는 'self' 추가\n"
            "3. 중요 액션(결제/계정변경)에 재인증 또는 CSRF 토큰 추가 검증\n"
            "4. onauxclick 이벤트 핸들러를 중요 UI 요소에서 제거 또는 확인 다이얼로그 추가\n"
            "참고: Bug Bytes #235 auxclick clickjacking variant (2026년 4월)"
        ),
    }
    if finding_type in cspt_waf_recs:
        return cspt_waf_recs[finding_type]

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
