from __future__ import annotations
import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Iterator

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.markdown import Markdown
from rich.rule import Rule
from rich.prompt import Prompt
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles import Style as PTStyle
from prompt_toolkit.formatted_text import HTML

from ..models.base import Message, StreamChunk
from ..lang.strings import get_strings, SUPPORTED_LANGS

# ── 색상 팔레트 (해커 그린 테마) ──────────────────────────────────
THEME = {
    "primary":   "#00ff41",   # 매트릭스 그린
    "secondary": "#00d4aa",   # 시안
    "accent":    "#ff6b35",   # 오렌지 (강조)
    "dim":       "#4a4a4a",
    "user_bg":   "#0d1117",
    "ai_bg":     "#0d1117",
    "border":    "#00ff41",
    "error":     "#ff3333",
    "warn":      "#ffcc00",
    "success":   "#00ff41",
}

BANNER = r"""
[#00ff41]
  ██████╗ ██╗███╗   ██╗ ██████╗  ██████╗ 
  ██╔══██╗██║████╗  ██║██╔════╝ ██╔═══██╗
  ██████╔╝██║██╔██╗ ██║██║  ███╗██║   ██║
  ██╔══██╗██║██║╚██╗██║██║   ██║██║   ██║
  ██████╔╝██║██║ ╚████║╚██████╔╝╚██████╔╝
  ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ [/#00ff41]
[#00d4aa]  AI Terminal  ·  v0.1.0  ·  Multi-Model[/#00d4aa]
"""

PT_STYLE = PTStyle.from_dict({
    "": "#00ff41",
    "prompt": "#00ff41 bold",
})


class BingoTerminal:
    """Bingo 메인 터미널 UI"""

    def __init__(self, config, strings: dict):
        self.config = config
        self.s = strings
        self.console = Console(highlight=False)
        self.history: list[Message] = []
        self._session: PromptSession | None = None

    # ── 공개 진입점 ───────────────────────────────────────────────
    def run(self) -> None:
        self._clear()
        self._print_banner()
        self._init_session()

        if not self.config.get_active_model_config():
            self._warn(self.s["no_model_configured"])
            self._cmd_model()

        self._chat_loop()

    # ── 배너 / 상태 표시 ──────────────────────────────────────────
    def _print_banner(self) -> None:
        self.console.print(BANNER)
        model_cfg = self.config.get_active_model_config()
        status = f"[{THEME['secondary']}]{model_cfg.display_name()}[/]" if model_cfg else f"[{THEME['warn']}]no model[/]"
        lang_label = SUPPORTED_LANGS.get(self.config.lang, self.config.lang)
        self.console.print(
            f"  [{THEME['dim']}]lang:[/] {lang_label}   "
            f"[{THEME['dim']}]model:[/] {status}\n"
        )

    def _print_status_bar(self) -> None:
        model_cfg = self.config.get_active_model_config()
        name = model_cfg.display_name() if model_cfg else "—"
        now = datetime.now().strftime("%H:%M")
        self.console.print(
            Rule(
                f"[{THEME['dim']}]{name}  ·  {now}[/]",
                style=THEME["dim"],
            )
        )

    # ── 채팅 루프 ─────────────────────────────────────────────────
    def _chat_loop(self) -> None:
        while True:
            try:
                user_input = self._get_input()
            except (KeyboardInterrupt, EOFError):
                self.console.print(f"\n[{THEME['primary']}]{self.s['goodbye']}[/]")
                break

            if not user_input.strip():
                continue

            # 슬래시 명령어
            if user_input.startswith("/"):
                self._handle_command(user_input.strip())
                continue

            # 일반 메시지 → AI 응답
            self._send_message(user_input.strip())

    def _get_input(self) -> str:
        model_cfg = self.config.get_active_model_config()
        model_name = model_cfg.display_name() if model_cfg else "no-model"
        return self._session.prompt(
            HTML(f'<ansigreen><b>❯</b></ansigreen> '),
            style=PT_STYLE,
        )

    # ── 메시지 전송 + 스트리밍 출력 ──────────────────────────────
    def _send_message(self, text: str) -> None:
        # 사용자 메시지 출력
        self._print_user(text)

        model_cfg = self.config.get_active_model_config()
        if not model_cfg:
            self._error(self.s["no_model_configured"])
            return

        from ..models.registry import ModelRegistry
        model = ModelRegistry.build(model_cfg)

        self.history.append(Message(role="user", content=text))

        # 스트리밍 응답 출력
        full_response = self._stream_response(model.chat_stream(self.history))

        if full_response:
            self.history.append(Message(role="assistant", content=full_response))

    def _stream_response(self, stream: Iterator[StreamChunk]) -> str:
        full = ""
        first = True

        self.console.print(f"\n[{THEME['secondary']}]bingo[/] [{THEME['dim']}]▸[/]", end=" ")

        with Live(console=self.console, refresh_per_second=20, transient=False) as live:
            buf = Text()
            for chunk in stream:
                if chunk.error:
                    live.stop()
                    self._error(f"{self.s['api_error']}: {chunk.error}")
                    return ""
                if chunk.text:
                    full += chunk.text
                    buf.append(chunk.text, style="white")
                    live.update(buf)

        # 마크다운 렌더링 (코드블록, 볼드 등)
        if "```" in full or "**" in full or "# " in full:
            self.console.print()
            self.console.print(Markdown(full))
        
        self.console.print()
        return full

    # ── 사용자 메시지 출력 ────────────────────────────────────────
    def _print_user(self, text: str) -> None:
        self.console.print(
            f"\n[{THEME['accent']}]{self.s['you']}[/] [{THEME['dim']}]▸[/] "
            f"[white]{text}[/]"
        )

    # ── 슬래시 명령어 ─────────────────────────────────────────────
    def _handle_command(self, cmd: str) -> None:
        parts = cmd.split(None, 1)
        name = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        dispatch = {
            "/help":    self._cmd_help,
            "/clear":   self._cmd_clear,
            "/model":   self._cmd_model,
            "/config":  self._cmd_config,
            "/history": self._cmd_history,
            "/export":  self._cmd_export,
            "/lang":    self._cmd_lang,
            "/quit":    self._cmd_quit,
            "/exit":    self._cmd_quit,
            "/tools":   self._cmd_tools,
            "/skill":   self._cmd_skill,
        }
        fn = dispatch.get(name)
        if fn:
            fn()
        elif name == "/scan":
            if arg:
                self._cmd_scan(arg)
            else:
                self._warn("Usage: /scan <url>  예) /scan https://target.co.kr")
        elif name == "/waf":
            if arg:
                self._cmd_waf(arg)
            else:
                self._warn("Usage: /waf <url>  예) /waf https://target.co.kr")
        else:
            self._warn(f"알 수 없는 명령어: {name}  (/help 참고)")

    def _cmd_help(self) -> None:
        self.console.print(
            Panel(
                self.s["help_text"],
                title=f"[{THEME['primary']}]BINGO COMMANDS[/]",
                border_style=THEME["primary"],
            )
        )

    def _cmd_clear(self) -> None:
        self._clear()
        self._print_banner()

    def _cmd_quit(self) -> None:
        self.console.print(f"[{THEME['primary']}]{self.s['goodbye']}[/]")
        sys.exit(0)

    def _cmd_history(self) -> None:
        if not self.history:
            self._info(self.s["history_empty"])
            return
        for i, m in enumerate(self.history, 1):
            color = THEME["accent"] if m.role == "user" else THEME["secondary"]
            label = self.s["you"] if m.role == "user" else "bingo"
            preview = m.content[:120].replace("\n", " ")
            self.console.print(f"[{color}]{i:3}. {label}[/] — {preview}")

    def _cmd_export(self) -> None:
        if not self.history:
            self._info(self.s["history_empty"])
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path.cwd() / f"bingo_chat_{ts}.md"
        lines = [f"# Bingo Chat — {ts}\n"]
        for m in self.history:
            label = self.s["you"] if m.role == "user" else "bingo"
            lines.append(f"## {label}\n{m.content}\n")
        path.write_text("\n".join(lines), encoding="utf-8")
        self._success(f"{self.s['export_saved']}: {path}")

    def _cmd_config(self) -> None:
        table = Table(
            title=f"[{THEME['primary']}]{self.s['config_view']}[/]",
            border_style=THEME["primary"],
            show_header=True,
        )
        table.add_column("Key", style=THEME["secondary"])
        table.add_column("Value", style="white")
        table.add_row("lang", self.config.lang)
        table.add_row("active_model", self.config.active_model or "—")
        table.add_row("models", str(len(self.config.models)))
        self.console.print(table)

    def _cmd_lang(self) -> None:
        self.console.print(f"\n[{THEME['primary']}]{self.s['select_lang']}[/]")
        for i, (code, label) in enumerate(SUPPORTED_LANGS.items(), 1):
            self.console.print(f"  [{THEME['secondary']}]{i}[/] — {label}")
        choice = Prompt.ask(
            f"[{THEME['primary']}]>[/]",
            choices=list(SUPPORTED_LANGS.keys()) + ["1", "2", "3"],
        )
        mapping = {str(i+1): k for i, k in enumerate(SUPPORTED_LANGS)}
        lang = mapping.get(choice, choice)
        if lang in SUPPORTED_LANGS:
            self.config.lang = lang
            self.config.save()
            self.s = get_strings(lang)
            self._success(self.s["lang_saved"])

    def _cmd_model(self) -> None:
        from ..models.registry import BUILTIN_PROVIDERS
        from ..models.base import ModelConfig

        self.console.print(f"\n[{THEME['primary']}]{self.s['select_model']}[/]\n")

        # 기존 모델 목록
        if self.config.models:
            self.console.print(f"  [{THEME['secondary']}]── 저장된 모델[/]")
            for i, m in enumerate(self.config.models, 1):
                mark = "✓" if m.display_name() == self.config.active_model else " "
                self.console.print(f"  [{THEME['primary']}]{mark} {i}[/] — {m.display_name()}")
            self.console.print()

        # 신규 추가
        providers = list(BUILTIN_PROVIDERS.items())
        self.console.print(f"  [{THEME['secondary']}]── 새 모델 추가[/]")
        for i, (pid, info) in enumerate(providers, len(self.config.models) + 1):
            self.console.print(f"  [{THEME['dim']}]{i}[/] — {info['label']}")

        raw = Prompt.ask(f"\n[{THEME['primary']}]번호 선택[/]").strip()
        try:
            idx = int(raw) - 1
        except ValueError:
            return

        # 기존 모델 전환
        if 0 <= idx < len(self.config.models):
            self.config.active_model = self.config.models[idx].display_name()
            self.config.save()
            self._success(self.s["model_saved"])
            return

        # 신규 등록
        new_idx = idx - len(self.config.models)
        if 0 <= new_idx < len(providers):
            pid, info = providers[new_idx]
            api_key = Prompt.ask(
                f"[{THEME['primary']}]{info['label']} {self.s['enter_api_key']}[/]",
                password=True,
            )
            default_url = info["base_url"]
            url_input = Prompt.ask(
                f"[{THEME['primary']}]{self.s['enter_base_url']}[/] [{THEME['dim']}]({default_url})[/]",
            ).strip()
            base_url = url_input or default_url

            default_model = info["default_model"]
            model_input = Prompt.ask(
                f"[{THEME['primary']}]{self.s['model_name_prompt']}[/] [{THEME['dim']}]({default_model})[/]",
            ).strip()
            model_name = model_input or default_model

            alias = Prompt.ask(
                f"[{THEME['primary']}]별칭 (선택, 엔터 스킵)[/]",
            ).strip()

            cfg = ModelConfig(
                provider=pid,
                model=model_name,
                api_key=api_key,
                base_url=base_url,
                alias=alias or "",
            )
            self.config.add_model(cfg)
            self.config.active_model = cfg.display_name()
            self.config.save()
            self._success(self.s["model_saved"])

    # ── Red Team 명령어 ───────────────────────────────────────────

    def _cmd_scan(self, url: str = "") -> None:
        if not url:
            url = Prompt.ask(f"[{THEME['primary']}]타겟 URL[/]").strip()
        if not url:
            return

        self.console.print(f"\n[{THEME['error']}]🎯 Red Team 스캔: {url}[/]")
        self.console.print(f"[{THEME['dim']}]채팅 창 내에서 실행 — 상세 결과는 'bingo scan {url}' 사용[/]\n")

        from ..tools.http_probe import HttpProbe
        from ..tools.waf_bypass import WafDetector
        from ..redteam.phases import __init__ as _  # noqa

        probe = HttpProbe(url, delay=0.3)

        # 빠른 정찰
        with self.console.status(f"[{THEME['secondary']}]정찰 중...[/]"):
            fp = probe.fingerprint()
            sensitive = probe.scan_sensitive_files()
            admin = probe.check_admin_panels()

            # WAF
            detector = WafDetector(probe)
            waf = detector.detect(url)

        # 결과 출력
        table = Table(title=f"[{THEME['primary']}]빠른 스캔 결과[/]",
                      border_style=THEME["primary"], show_header=True)
        table.add_column("항목", style=THEME["secondary"])
        table.add_column("결과", style="white")

        table.add_row("기술스택", ", ".join(fp.get("tech", [])) or "불명")
        table.add_row("CMS", fp.get("cms", "불명"))
        table.add_row("WAF", f"{waf.waf_type} ({waf.confidence})" if waf.detected else "없음")
        table.add_row("민감파일", str(len(sensitive)) + "개")
        table.add_row("관리자패널", str(len(admin)) + "개")
        self.console.print(table)

        if sensitive:
            self.console.print(f"\n[{THEME['error']}]⚠ 민감 파일:[/]")
            for s in sensitive[:5]:
                self.console.print(f"  [{THEME['warn']}]{s['path']}[/] [{s['status']}]")

        if admin:
            self.console.print(f"\n[{THEME['error']}]⚠ 관리자 패널:[/]")
            for a in admin[:3]:
                self.console.print(f"  [{THEME['warn']}]{a['path']}[/] [{a['status']}]")

        self.console.print(f"\n[{THEME['dim']}]전체 자동화 스캔: bingo scan {url}[/]\n")

    def _cmd_waf(self, url: str = "") -> None:
        if not url:
            url = Prompt.ask(f"[{THEME['primary']}]타겟 URL[/]").strip()
        if not url:
            return

        from ..tools.http_probe import HttpProbe
        from ..tools.waf_bypass import WafDetector, WafBypassEngine

        self.console.print(f"\n[{THEME['warn']}]🛡 WAF 분석: {url}[/]")
        probe = HttpProbe(url)
        detector = WafDetector(probe)

        with self.console.status(f"[{THEME['warn']}]WAF 탐지 중...[/]"):
            result = detector.detect(url)

        if result.detected:
            self.console.print(f"[{THEME['error']}]탐지: {result.waf_type}  신뢰도: {result.confidence}[/]")
            self.console.print(f"[{THEME['dim']}]증거: {result.evidence}[/]")
            self.console.print(f"\n[{THEME['secondary']}]우선 우회 전략:[/]")
            for i, s in enumerate(result.bypass_priority, 1):
                self.console.print(f"  {i}. {s}")

            self.console.print(f"\n[{THEME['warn']}]자동 우회 시도 중...[/]")
            engine = WafBypassEngine(
                probe,
                on_progress=lambda m: self.console.print(f"[{THEME['dim']}]{m}[/]")
            )
            success, attempt = engine.auto_bypass(url + "?id=1", "' OR 1=1--")
            if success and attempt:
                self.console.print(f"[{THEME['success']}]✓ 우회 성공: {attempt.technique}[/]")
                self.console.print(f"[{THEME['success']}]페이로드: {attempt.payload_modified}[/]")
            else:
                self.console.print(f"[{THEME['error']}]우회 실패 — /waf 결과를 AI에게 물어보세요[/]")

            # AI에게 우회 전략 물어보기
            bypass_summary = engine.get_bypass_summary(result.waf_type)
            ai_prompt = (
                f"WAF 탐지됨: {result.waf_type}\n"
                f"우회 시도 실패\n\n{bypass_summary}\n\n"
                f"이 WAF에 대한 최적 우회 페이로드 5개를 제시해주세요."
            )
            self.console.print(f"\n[{THEME['secondary']}]AI 분석 요청 중...[/]")
            self._stream_response(ai_prompt)
        else:
            self.console.print(f"[{THEME['success']}]WAF 없음 — 직접 공격 가능[/]")

    def _cmd_tools(self) -> None:
        from ..tools.registry import ToolRegistry
        self.console.print()
        table = Table(title=f"[{THEME['primary']}]설치된 도구[/]",
                      border_style=THEME["primary"])
        table.add_column("도구", style=THEME["secondary"])
        table.add_column("상태", justify="center")
        table.add_column("버전 / 설치 방법", style=THEME["dim"])

        for name, info in ToolRegistry.scan_all().items():
            if info.available:
                table.add_row(name, f"[{THEME['success']}]✓[/]", info.version[:50])
            else:
                table.add_row(name, f"[{THEME['error']}]✗[/]", info.install_hint[:60])
        self.console.print(table)

    def _cmd_skill(self, keyword: str = "") -> None:
        from ..skills.engine import SkillEngine
        engine = SkillEngine()

        if keyword:
            results = engine.search(keyword)
            if results:
                self.console.print(f"\n[{THEME['secondary']}]스킬 검색: {keyword}[/]")
                for r in results[:15]:
                    self.console.print(f"  [{THEME['primary']}]{r['module']}[/] → {r['skill']}")
            else:
                self.console.print(f"[{THEME['dim']}]'{keyword}' 검색 결과 없음[/]")
        else:
            table = Table(title=f"[{THEME['primary']}]CyberSecurity-Skills 39 모듈[/]",
                          border_style=THEME["primary"])
            table.add_column("ID", style=THEME["secondary"], width=4)
            table.add_column("모듈", style="white")
            table.add_column("스킬 수", justify="right")
            for mod in engine.list_all():
                table.add_row(mod["id"], mod["en"], str(len(mod["skills"])))
            self.console.print(table)
            self.console.print(f"[{THEME['dim']}]/skill <키워드>  로 검색  예) /skill sqli[/]")

    # ── 유틸 ──────────────────────────────────────────────────────
    def _init_session(self) -> None:
        hist_path = Path.home() / ".config" / "bingo" / "history"
        hist_path.parent.mkdir(parents=True, exist_ok=True)
        self._session = PromptSession(
            history=FileHistory(str(hist_path)),
            auto_suggest=AutoSuggestFromHistory(),
            mouse_support=False,
        )

    def _clear(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _info(self, msg: str) -> None:
        self.console.print(f"[{THEME['dim']}]  ℹ  {msg}[/]")

    def _warn(self, msg: str) -> None:
        self.console.print(f"[{THEME['warn']}]  ⚠  {msg}[/]")

    def _error(self, msg: str) -> None:
        self.console.print(f"[{THEME['error']}]  ✖  {msg}[/]")

    def _success(self, msg: str) -> None:
        self.console.print(f"[{THEME['success']}]  ✔  {msg}[/]")
