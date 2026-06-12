"""
bingo Multi-Agent — Cursor처럼 전문 에이전트들이 동시에 독립 작업.

에이전트 구성:
  ReconAgent   — 서브도메인, 포트, 기술 스택, 디렉터리
  SQLiAgent    — SQL 인젝션 탐지 + 완전 덤프
  WebVulnAgent — XSS/SSRF/LFI/SSTI/CMDi/CORS
  AuthAgent    — 로그인 폼 탐지, 기본 자격증명, 세션 분석

에이전트 간 통신:
  - ReconAgent 완료 → 발견된 파라미터/서브도메인을 SQLi/WebVuln에 공유
  - SQLi 결과 → agent_state에 자동 저장
  - 모든 에이전트 결과 → 통합 보고서
"""
from __future__ import annotations
import sys, os, shutil
from pathlib import Path
from typing import Any

from .parallel_runner import ParallelRunner, Task

def _get_t(key: str, default: str = "") -> str:
    try:
        from ..i18n import t
        return t(key, default)
    except Exception:
        return default or key


def _ensure_tools_installed() -> None:
    """~/.bingo/ 에 모든 툴 파일 자동 설치."""
    bingo_dir = Path.home() / ".bingo"
    bingo_dir.mkdir(exist_ok=True)
    tools_dir = Path(__file__).parent.parent / "tools"

    for module in ["agent_tools.py", "recon_tools.py", "web_tools.py", "auth_tools.py"]:
        src = tools_dir / module
        dst = bingo_dir / module
        if src.exists() and (not dst.exists() or src.stat().st_mtime > dst.stat().st_mtime):
            shutil.copy2(src, dst)

    # 경로 등록
    bingo_path = str(bingo_dir)
    if bingo_path not in sys.path:
        sys.path.insert(0, bingo_path)


# ── 에이전트 함수들 ───────────────────────────────────────────────

def _recon_agent(target_url: str) -> dict:
    """정찰 에이전트 — 기술 스택, 포트, 서브도메인, 디렉터리."""
    try:
        from recon_tools import Recon
        r = Recon(target_url)
        r.resolve_ip()
        r.fingerprint()
        r.analyze_headers()
        r.analyze_ssl()
        r.scan_ports()
        r.dir_brute()
        return r.findings
    except ImportError:
        # recon_tools 없으면 기본 httpx로
        try:
            import httpx
            client = httpx.Client(verify=False, timeout=8, follow_redirects=True)
            r = client.get(target_url)
            return {
                "status": r.status_code,
                "server": r.headers.get("server", "unknown"),
                "technologies": [h for h in r.headers if "powered" in h.lower()],
            }
        except Exception as e:
            return {"error": str(e)}


def _sqli_agent(target_url: str) -> dict:
    """SQLi 에이전트 — WAF 탐지 + UNION/Boolean/Time 자동 선택."""
    try:
        from agent_tools import T
        t = T(target_url)
        result: dict = {"target": target_url, "injectable": False}

        waf = t.detect_waf()
        result["waf"] = waf

        # 에러 기반 확인
        import re
        _, _, body = t.inject("'")
        err = t.has_sql_error(body)
        if err:
            result["type"] = "error-based"
            result["injectable"] = True

        # UNION 시도
        db = t.union_extract_marked("database()")
        if db:
            result["injectable"] = True
            result["method"] = "UNION"
            result["database"] = db
            tables_raw = t.union_extract_marked(
                f"SELECT GROUP_CONCAT(table_name SEPARATOR ',') "
                f"FROM information_schema.tables WHERE table_schema=database()"
            )
            result["tables"] = tables_raw.split(",") if tables_raw else []
            return result

        # Boolean 시도
        if t.calibrate_boolean():
            result["injectable"] = True
            result["method"] = "Boolean Blind"
            db = t.bool_extract_string("database()")
            result["database"] = db
            result["tables"]   = t.dump_tables(db) if db else []
            return result

        return result
    except Exception as e:
        return {"error": str(e)}


def _webvuln_agent(target_url: str) -> list[dict]:
    """웹 취약점 에이전트 — XSS/SSRF/LFI/SSTI/CORS."""
    try:
        from web_tools import WebScanner
        ws = WebScanner(target_url)
        ws.scan_cors()
        ws.scan_open_redirect()
        if ws.params:
            ws.scan_xss()
            ws.scan_ssrf()
            ws.scan_lfi()
            ws.scan_ssti()
            ws.scan_cmdi()
        return ws.findings
    except Exception as e:
        return [{"error": str(e)}]


def _auth_agent(target_url: str) -> dict:
    """인증 에이전트 — 로그인 폼, 기본 자격증명, 세션."""
    try:
        from auth_tools import Auth
        a = Auth(target_url)
        form = a.detect_login_form()
        result: dict = {"form_found": form is not None}
        if form:
            creds = a.test_default_creds(form)
            result["default_creds"] = creds
            sess = a.analyze_session()
            result["session"] = sess
        return result
    except Exception as e:
        return {"error": str(e)}


# ── 메인 멀티 에이전트 ────────────────────────────────────────────

class MultiAgent:
    """
    Cursor처럼 전문 에이전트들이 동시에 독립 작업을 수행.

    Args:
        console: Rich Console 인스턴스 (없으면 기본 콘솔 사용)
    """

    def __init__(self, console=None):
        self.console = console
        self._results: dict = {}

    def run(self, target_url: str, agents: list[str] | None = None) -> dict:
        """
        지정된 에이전트들을 병렬 실행.

        실행 전략:
          Phase 1 (동시): Recon + SQLi + WebVuln + Auth
          Phase 2: Recon 결과를 바탕으로 추가 SQLi/WebVuln 타겟 자동 보강

        agents: ["recon", "sqli", "webvuln", "auth"] 중 선택 (기본: 전체)
        """
        # 툴 자동 설치
        _ensure_tools_installed()

        available = {
            "recon":   Task("🔍 Recon",   _recon_agent,   args=(target_url,), timeout=90),
            "sqli":    Task("💉 SQLi",    _sqli_agent,    args=(target_url,), timeout=120),
            "webvuln": Task("🌐 WebVuln", _webvuln_agent, args=(target_url,), timeout=90),
            "auth":    Task("🔑 Auth",    _auth_agent,    args=(target_url,), timeout=60),
        }

        selected_names = agents or list(available.keys())
        tasks = [available[n] for n in selected_names if n in available]

        if not tasks:
            return {}

        runner = ParallelRunner(max_workers=len(tasks))

        if self.console:
            self._results = runner.run_with_progress(tasks, console=self.console)
        else:
            self._results = runner.run(tasks)

        # ── Phase 2: Recon 결과 → 추가 공격 타겟 보강 ─────────────
        self._phase2_enrich(target_url)

        self._print_summary()
        return self._results

    def _phase2_enrich(self, target_url: str) -> None:
        """
        Recon 결과를 SQLi/WebVuln 에이전트에 피드백.
        발견된 서브도메인 / 디렉터리에 추가 스캔 수행.
        """
        recon = self._results.get("🔍 Recon") or {}
        if not recon or recon.get("error"):
            return

        extra_targets = []

        # 발견된 디렉터리 중 파라미터가 있는 URL 추가
        dirs = recon.get("directories", [])
        for d in dirs:
            url = d.get("url", "")
            if "?" in url and url not in [target_url]:
                extra_targets.append(url)

        # 발견된 서브도메인 추가 (최대 3개)
        subs = recon.get("subdomains", [])[:3]
        for sub in subs:
            scheme = target_url.split("://")[0]
            extra_targets.append(f"{scheme}://{sub}/")

        if not extra_targets:
            return

        if self.console:
            self.console.print(
                f"\n[dim cyan]⚡ Phase 2: {len(extra_targets)} {_get_t('dir_found', 'targets')} — {_get_t('scanning', 'Scanning')}...[/dim cyan]"
            )

        # 추가 타겟에 SQLi + WebVuln 병렬 실행
        extra_tasks = []
        for i, url in enumerate(extra_targets[:5]):  # 최대 5개
            extra_tasks.append(Task(f"💉 SQLi-{i+2}", _sqli_agent,    args=(url,), timeout=60))
            extra_tasks.append(Task(f"🌐 Web-{i+2}",  _webvuln_agent, args=(url,), timeout=60))

        if extra_tasks:
            runner2 = ParallelRunner(max_workers=min(len(extra_tasks), 6))
            extra_results = runner2.run(extra_tasks)
            # 결과 통합
            self._results.update(extra_results)

    def _on_start(self, task: Task) -> None:
        pass  # run_with_progress가 Live로 처리

    def _on_done(self, task: Task) -> None:
        pass

    def _on_error(self, task: Task) -> None:
        pass

    def _print_summary(self) -> None:
        """스캔 결과 요약 출력."""
        try:
            from rich.panel import Panel
            from rich.text import Text
            from rich.console import Console

            console = self.console or Console()
            lines = []

            # Recon 요약
            recon = self._results.get("🔍 Recon") or {}
            if recon and not recon.get("error"):
                lines.append(f"[bold cyan]📡 Recon[/bold cyan]")
                lines.append(f"  IP: {recon.get('ip', 'N/A')}")
                techs = recon.get('technologies', [])
                if techs:
                    lines.append(f"  Techs: {', '.join(techs[:5])}")
                ports = recon.get('open_ports', [])
                if ports:
                    lines.append(f"  Ports: {ports}")
                dirs = recon.get('directories', [])
                if dirs:
                    lines.append(f"  Dirs: {len(dirs)} found ({', '.join(d['url'].split('/')[-1] for d in dirs[:3])})")

            # SQLi 요약
            sqli = self._results.get("💉 SQLi") or {}
            if sqli and not sqli.get("error"):
                lines.append(f"\n[bold red]💉 SQLi[/bold red]")
                if sqli.get("injectable"):
                    lines.append(f"  🔴 VULNERABLE — {sqli.get('method', '?')}")
                    lines.append(f"  DB: {sqli.get('database', 'N/A')}")
                    tables = sqli.get('tables', [])
                    if tables:
                        lines.append(f"  Tables: {', '.join(tables[:5])}")
                    if sqli.get('waf'):
                        lines.append(f"  WAF: {sqli['waf']}")
                else:
                    lines.append(f"  ✅ Not injectable")

            # WebVuln 요약
            web = self._results.get("🌐 WebVuln") or []
            if web and not (isinstance(web, list) and web and web[0].get("error")):
                lines.append(f"\n[bold yellow]🌐 Web Vulns[/bold yellow]")
                for f in web[:5]:
                    sev = f.get("severity", "?")
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "⚪")
                    lines.append(f"  {icon} {f.get('type', '?')}: {str(f.get('detail',''))[:60]}")
                if len(web) > 5:
                    lines.append(f"  ... +{len(web)-5} more")

            # Auth 요약
            auth = self._results.get("🔑 Auth") or {}
            if auth and not auth.get("error"):
                lines.append(f"\n[bold green]🔑 Auth[/bold green]")
                creds = auth.get("default_creds", [])
                if creds:
                    lines.append(f"  🔴 Default creds found: {creds}")
                else:
                    lines.append(f"  ✅ No default creds")
                sess_issues = (auth.get("session") or {}).get("issues", [])
                if sess_issues:
                    for issue in sess_issues[:3]:
                        lines.append(f"  ⚠️  {issue}")

            if lines:
                console.print(Panel(
                    "\n".join(lines),
                    title="[bold]BINGO MULTI-AGENT RESULTS[/bold]",
                    border_style="cyan",
                    expand=False,
                ))
        except Exception:
            pass
