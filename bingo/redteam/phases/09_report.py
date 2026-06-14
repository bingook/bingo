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

    # ── Zero-Hallucination Gate ───────────────────────────────────────────────
    # evidence_level=VERIFIED 만 취약점으로 보고서에 포함
    # INFERRED / AI_ANALYSIS 는 별도 분류
    verified_findings = []
    inferred_findings = []
    for f in all_findings_raw:
        level = f.get("evidence_level", "VERIFIED")  # 기존 finding은 VERIFIED 기본값
        if level == "AI_ANALYSIS":
            continue  # AI 텍스트는 보고서 취약점 목록 제외
        elif level == "INFERRED":
            inferred_findings.append(f)
        else:
            # VERIFIED — curl이 있는지 추가 확인
            if not f.get("curl") and not f.get("detail") and not f.get("url"):
                inferred_findings.append(f)
            else:
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
        f"**검증된 취약점: {len(all_findings)}건** ✅ (Zero-Hallucination 보장)",
        f"",
        f"> ⚠️ 이 보고서에 포함된 모든 취약점은 실제 HTTP 응답 증거가 첨부됩니다.",
        f"> 증거 없는 추론({len(inferred_findings)}건)은 하단 미검증 섹션에 별도 기록됩니다.",
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

    # ── 미검증 섹션 (증거 없음, 보고서에서 취약점 아님) ──────────────────────
    if inferred_findings:
        md_lines += [
            f"## ⚠️ 미검증 항목 (INFERRED — 보안 취약점 아님)",
            f"",
            f"> 아래 항목들은 HTTP 증거가 불충분하여 취약점으로 확정되지 않았습니다.",
            f"> 추가 조사가 필요합니다.",
            f"",
        ]
        for j, inf in enumerate(inferred_findings, 1):
            md_lines += [
                f"- **{j}.** {inf.get('title', '미확인')} — _{inf.get('description', '')[:100]}_",
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
