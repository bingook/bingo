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
from prompt_toolkit.completion import Completer, Completion, WordCompleter

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
[#00d4aa]  AI Terminal  ·  v1.0.1  ·  Multi-Model[/#00d4aa]
"""

PT_STYLE = PTStyle.from_dict({
    "": "#00ff41",
    "prompt": "#00ff41 bold",
})


SLASH_COMMANDS = [
    ("/help",    "도움말 표시"),
    ("/clear",   "화면 초기화"),
    ("/model",   "AI 모델 변경"),
    ("/config",  "설정 보기"),
    ("/history", "대화 기록 보기"),
    ("/export",  "대화 기록 파일로 저장"),
    ("/lang",    "언어 변경"),
    ("/scan",    "빠른 레드팀 스캔  /scan <url>"),
    ("/waf",     "WAF 탐지 + 자동 우회  /waf <url>"),
    ("/crack",   "해시 크랙  /crack [hash]  (인자 없으면 자동 추출)"),
    ("/tools",   "도구 목록 + 자동 설치  /tools [install <name>|all]"),
    ("/skill",   "스킬 검색  /skill <keyword>"),
    ("/stop",    "자동 크랙 중단"),
    ("/quit",    "종료"),
]


class _SlashCompleter(Completer):
    """/ 입력 시 슬래시 명령어 자동완성 (설명 포함)"""

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        word = text.split()[0] if text.split() else "/"
        for cmd, desc in SLASH_COMMANDS:
            if cmd.startswith(word) or word == "/":
                yield Completion(
                    cmd,
                    start_position=-len(word),
                    display=cmd,
                    display_meta=desc,
                )


class BingoTerminal:
    """Bingo 메인 터미널 UI"""

    def __init__(self, config, strings: dict):
        self.config = config
        self.s = strings
        self.console = Console(highlight=False)
        self.history: list[Message] = []
        self._session: PromptSession | None = None
        # 자동 저장 경로 — 세션 시작 시 결정
        self._session_log_path: Path | None = None
        # 자동 크랙 중단 플래그
        self._stop_crack_flag = threading.Event()

    # ── 공개 진입점 ───────────────────────────────────────────────
    def run(self) -> None:
        self._clear()
        self._print_banner()
        self._init_session()
        self._init_session_log()

        if not self.config.get_active_model_config():
            self._warn(self.s["no_model_configured"])
            self._cmd_model()

        # 멀티턴 워밍업 히스토리 주입 (PentAGI 기법 — 세션 시작 시 AI가 이미
        # 성공적으로 작업한 기록을 심어 거부율을 대폭 낮춤)
        self._inject_warmup_history()

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

    # ── 세션 로그 ─────────────────────────────────────────────────
    def _init_session_log(self) -> None:
        """세션 시작 시 자동 저장 경로 초기화"""
        logs_dir = Path.home() / ".config" / "bingo" / "sessions"
        logs_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._session_log_path = logs_dir / f"session_{ts}.md"
        # 헤더 기록
        model_cfg = self.config.get_active_model_config()
        model_name = model_cfg.display_name() if model_cfg else "unknown"
        header = (
            f"# Bingo Session — {ts}\n"
            f"**model:** {model_name}\n\n"
            "---\n\n"
        )
        self._session_log_path.write_text(header, encoding="utf-8")
        self.console.print(
            f"[{THEME['dim']}]📝 세션 자동 저장: {self._session_log_path}[/]\n"
        )

    def _append_to_session_log(self, role: str, content: str) -> None:
        """대화 한 턴을 세션 로그에 추가"""
        if not self._session_log_path:
            return
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            label = "**YOU**" if role == "user" else "**bingo**"
            with open(self._session_log_path, "a", encoding="utf-8") as f:
                f.write(f"### {label} `{ts}`\n{content}\n\n")
        except Exception:
            pass

    # ── 채팅 루프 ─────────────────────────────────────────────────
    def _chat_loop(self) -> None:
        while True:
            try:
                user_input = self._get_input()
            except (KeyboardInterrupt, EOFError):
                self.console.print(f"\n[{THEME['primary']}]{self.s['goodbye']}[/]")
                if self._session_log_path:
                    self.console.print(
                        f"[{THEME['dim']}]💾 세션 저장됨: {self._session_log_path}[/]"
                    )
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
    def _inject_warmup_history(self) -> None:
        """세션 시작 시 워밍업 대화를 히스토리에 주입 (멀티턴 에스컬레이션 기법)"""
        from ..models.system_prompt import get_warmup_history
        model_cfg = self.config.get_active_model_config()
        provider = model_cfg.provider if model_cfg else "deepseek"
        for msg in get_warmup_history(provider):
            self.history.append(Message(role=msg["role"], content=msg["content"]))

    def _get_system_message(self, skill_context: str = "") -> Message:
        """모델 공급자에 맞는 시스템 프롬프트 반환 (스킬 컨텍스트 포함)"""
        from ..models.system_prompt import get_pentest_system_prompt
        model_cfg = self.config.get_active_model_config()
        provider = model_cfg.provider if model_cfg else "deepseek"
        system_text = get_pentest_system_prompt(provider)
        if skill_context:
            system_text += "\n\n---\n## RELEVANT SKILL REFERENCES\n" + skill_context
        return Message(role="system", content=system_text)

    def _get_skill_context(self, text: str) -> str:
        """사용자 입력에서 관련 스킬 자동 검색 후 AI 컨텍스트 문자열 반환"""
        from ..skills.engine import SkillEngine
        engine = SkillEngine()
        results = engine.search(text)
        if not results:
            return ""
        parts = []
        for r in results[:3]:
            prompt = engine.get_skill_prompt(r["id"])
            if prompt:
                parts.append(prompt)
        return "\n\n".join(parts)

    def _auto_waf_scan(self, text: str) -> str:
        """
        메시지에서 URL을 감지하면 즉시 WAF 스캔 + 자동 우회 시도.
        결과를 AI 컨텍스트 문자열로 반환 — AI가 실제 스캔 결과 기반으로 응답.
        """
        import re
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        if not urls:
            return ""

        url = urls[0].rstrip("/?,")
        results = []
        try:
            from ..tools.http_probe import HttpProbe
            from ..tools.waf_bypass import WafDetector, WafBypassEngine

            self.console.print(
                f"\n[{THEME['warn']}]🛡 WAF 자동 스캔: {url}[/]", end=" "
            )

            probe = HttpProbe(url, timeout=8)
            detector = WafDetector(probe)

            with self.console.status(f"[{THEME['warn']}]탐지 중...[/]"):
                waf_result = detector.detect(url)

            if waf_result.detected:
                self.console.print(
                    f"[{THEME['error']}]WAF 탐지: {waf_result.waf_type}[/]"
                )
                # 자동 우회 시도
                engine = WafBypassEngine(probe)
                bypass_ok, attempt = engine.auto_bypass(
                    url + "?id=1", "' OR 1=1--"
                )

                # WAF 우회 결과 → sqlmap 인자로 변환
                sqlmap_args = engine.to_sqlmap_args(waf_result, attempt if bypass_ok else None)
                sqlmap_cmd = (
                    f'sqlmap -u "{url}?PARAM=1" '
                    f"{sqlmap_args} "
                    f"--dbs --batch"
                )

                bypass_line = (
                    f"bypass_success=True\n"
                    f"bypass_technique={attempt.technique}\n"
                    f"bypass_payload={attempt.payload_modified}"
                    if bypass_ok and attempt
                    else "bypass_success=False"
                )
                results.append(
                    f"WAF_SCAN_RESULT:\n"
                    f"  url={url}\n"
                    f"  waf_detected=True\n"
                    f"  waf_type={waf_result.waf_type}\n"
                    f"  confidence={waf_result.confidence}\n"
                    f"  {bypass_line}\n\n"
                    f"SQLMAP_COMMAND (use this exact command — WAF bypass already applied):\n"
                    f"  {sqlmap_cmd}"
                )
                if bypass_ok and attempt:
                    self.console.print(
                        f"[{THEME['success']}]✓ 우회 성공: {attempt.technique} → sqlmap 인자 자동 적용됨[/]"
                    )
                    self.console.print(
                        f"[{THEME['dim']}]  {sqlmap_cmd[:80]}...[/]"
                    )
                else:
                    self.console.print(
                        f"[{THEME['warn']}]우회 기법 탐색 중 — AI가 추가 전략 적용[/]"
                    )
            else:
                self.console.print(f"[{THEME['success']}]WAF 없음[/]")
                results.append(
                    f"WAF_SCAN_RESULT:\n"
                    f"  url={url}\n"
                    f"  waf_detected=False\n\n"
                    f"SQLMAP_COMMAND (no WAF — direct attack):\n"
                    f'  sqlmap -u "{url}?PARAM=1" --batch --random-agent --dbs'
                )

            # 빠른 핑거프린트
            with self.console.status(f"[{THEME['dim']}]핑거프린트...[/]"):
                fp = probe.fingerprint()
            if fp:
                tech = ", ".join(fp.get("tech", [])) or "unknown"
                results.append(f"[FINGERPRINT]\nurl={url}\ntech_stack={tech}\ncms={fp.get('cms','unknown')}\n[/FINGERPRINT]")

        except Exception as e:
            results.append(f"[WAF_SCAN_ERROR]\n{e}\n[/WAF_SCAN_ERROR]")

        return "\n\n".join(results)

    def _build_messages(self, skill_context: str = "") -> list[Message]:
        """시스템 프롬프트 + 스킬 컨텍스트 + 대화 히스토리 합치기"""
        return [self._get_system_message(skill_context)] + self.history

    def _send_message(self, text: str) -> None:
        # 사용자 메시지 출력
        self._print_user(text)

        model_cfg = self.config.get_active_model_config()
        if not model_cfg:
            self._error(self.s["no_model_configured"])
            return

        from ..models.registry import ModelRegistry
        from ..models.system_prompt import detect_refusal, rephrase_refused_request, wrap_task
        model = ModelRegistry.build(model_cfg)

        # 관련 스킬 자동 조회
        skill_context = self._get_skill_context(text)

        # URL 감지 시 실제 WAF 스캔 실행 → 결과를 AI 컨텍스트에 주입
        waf_context = self._auto_waf_scan(text)
        if waf_context:
            skill_context = waf_context + ("\n\n" + skill_context if skill_context else "")

        # PentAGI식 XML 태스크 래핑 (보안 관련 요청만)
        _security_keywords = (
            "sqli", "sql", "inject", "waf", "bypass", "shell", "rce", "lfi",
            "admin", "db", "database", "exploit", "scan", "payload", "xss",
            "해킹", "공격", "취약", "인젝션", "우회", "침투", "스캔", "추출",
            "웹쉘", "관리자", "비밀번호", "크랙",
        )
        text_lower = text.lower()
        if any(kw in text_lower for kw in _security_keywords):
            wrapped_text = wrap_task(text)
        else:
            wrapped_text = text

        self.history.append(Message(role="user", content=wrapped_text))
        self._append_to_session_log("user", text)

        # 시스템 프롬프트 + 스킬 컨텍스트 포함한 전체 메시지로 스트리밍
        full_response = self._stream_response(
            model.chat_stream(self._build_messages(skill_context))
        )

        # 거부 감지 → XML 태스크 재구성 후 재시도 (PentAGI 기법)
        if full_response and detect_refusal(full_response):
            self.history.pop()
            rephrased = rephrase_refused_request(text, model_cfg.provider)
            self.history.append(Message(role="user", content=rephrased))
            self.console.print(f"\n[{THEME['warn']}]⚡ 요청 재구성 중...[/]")
            full_response = self._stream_response(
                model.chat_stream(self._build_messages(skill_context))
            )

        if full_response:
            self.history.append(Message(role="assistant", content=full_response))
            self._append_to_session_log("assistant", full_response)
            # AI 응답에 해시가 있으면 자동 크랙 알림
            self._notify_hashes_found(full_response)

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
            "/skill":   self._cmd_skill,
        }
        fn = dispatch.get(name)
        if fn:
            fn()
        elif name == "/tools":
            self._cmd_tools(arg)
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
        elif name == "/crack":
            self._cmd_crack(arg)
        elif name == "/stop":
            self._stop_crack_flag.set()
            self.console.print(f"[{THEME['warn']}]⏹ 크랙 중단 신호 전송됨[/]")
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

    def _notify_hashes_found(self, text: str) -> None:
        """AI 응답에서 해시 감지 시 자동 온라인 조회 → 오프라인 크랙 파이프라인 실행"""
        from ..tools.hash_crack import extract_hashes_from_text
        hashes = extract_hashes_from_text(text)
        if not hashes:
            return
        self.console.print(
            f"\n[{THEME['warn']}]🔑 해시 {len(hashes)}개 감지 — 자동 크랙 시작 "
            f"([bold]/stop[/bold] 으로 중단 가능)[/]"
        )
        # 별도 스레드에서 실행 (채팅 블로킹 방지)
        self._stop_crack_flag.clear()
        t = threading.Thread(
            target=self._auto_crack_pipeline,
            args=(hashes,),
            daemon=True,
        )
        t.start()

    def _auto_crack_pipeline(self, hashes: list[str]) -> None:
        """
        자동 크랙 파이프라인 (백그라운드 스레드)
        Step 1: 온라인 해시 조회 (여러 사이트 순서대로)
        Step 2: 미해결 해시 → 오프라인 크랙 (john/hashcat/python)
        /stop 입력 시 즉시 중단
        """
        from ..tools.hash_lookup import OnlineHashLookup, LookupResult
        from ..tools.hash_crack import HashCracker
        from rich.table import Table as RichTable

        def log(msg: str) -> None:
            if not self._stop_crack_flag.is_set():
                self.console.print(f"[{THEME['dim']}]{msg}[/]")

        cracked: dict[str, str] = {}   # hash → plaintext
        pending = list(hashes)

        # ── Step 1: 온라인 조회 ──────────────────────────────────────
        self.console.print(f"[{THEME['secondary']}]  ① 온라인 해시 조회 중...[/]")
        lookup = OnlineHashLookup(on_progress=log)

        for h in list(pending):
            if self._stop_crack_flag.is_set():
                self.console.print(f"[{THEME['warn']}]⏹ 크랙 중단됨[/]")
                return
            result: LookupResult = lookup.lookup(h)
            if result.found and result.plaintext:
                cracked[h] = result.plaintext
                self.console.print(
                    f"  [{THEME['success']}]✓ [{result.source}] "
                    f"{h[:25]}... → [bold]{result.plaintext}[/bold][/]"
                )
                pending.remove(h)

        # ── Step 2: 오프라인 크랙 ────────────────────────────────────
        if pending and not self._stop_crack_flag.is_set():
            self.console.print(
                f"[{THEME['secondary']}]  ② 오프라인 크랙 ({len(pending)}개 남음)...[/]"
            )
            cracker = HashCracker(on_progress=log)

            for h in list(pending):
                if self._stop_crack_flag.is_set():
                    self.console.print(f"[{THEME['warn']}]⏹ 크랙 중단됨[/]")
                    break
                result = cracker.crack(h)
                if result.cracked and result.plaintext:
                    cracked[h] = result.plaintext
                    self.console.print(
                        f"  [{THEME['success']}]✓ [오프라인/{result.method}] "
                        f"{h[:25]}... → [bold]{result.plaintext}[/bold][/]"
                    )
                    pending.remove(h)

        # ── 결과 테이블 ──────────────────────────────────────────────
        if self._stop_crack_flag.is_set() and not cracked:
            return

        table = RichTable(
            title=f"[{THEME['primary']}]🔓 크랙 결과[/]",
            border_style=THEME["primary"],
        )
        table.add_column("해시", style=THEME["dim"])
        table.add_column("평문", style=f"bold {THEME['error']}")
        table.add_column("방법", style=THEME["dim"])

        for h in hashes:
            if h in cracked:
                table.add_row(h, cracked[h], "✓")
            else:
                table.add_row(h[:40] + ("..." if len(h) > 40 else ""),
                              "[dim]미해결[/dim]", "✗")

        self.console.print(table)

        # 세션 로그에 저장
        if cracked:
            lines = ["## 🔓 자동 크랙 결과\n"]
            for h, p in cracked.items():
                lines.append(f"- `{h}` → **{p}**\n")
            self._append_to_session_log("assistant", "".join(lines))

        self.console.print(
            f"[{THEME['dim']}](크랙 완료 — 결과가 세션 로그에 저장됨)[/]"
        )

    def _cmd_crack(self, arg: str = "") -> None:
        """
        /crack <hash>          — 단일 해시 크랙
        /crack                 — 최근 AI 응답에서 해시 자동 추출 후 크랙
        /crack --wordlist /path/to/list.txt <hash>
        """
        from ..tools.hash_crack import HashCracker, extract_hashes_from_text, detect_hash_type
        from rich.table import Table as RichTable

        wordlist = None
        hashes: list[str] = []

        # 인자 파싱
        tokens = arg.split()
        i = 0
        while i < len(tokens):
            if tokens[i] in ("--wordlist", "-w") and i + 1 < len(tokens):
                wordlist = tokens[i + 1]
                i += 2
            else:
                hashes.append(tokens[i])
                i += 1

        # 인자 없으면 최근 AI 응답에서 자동 추출
        if not hashes:
            last_ai = next(
                (m.content for m in reversed(self.history) if m.role == "assistant"),
                None,
            )
            if last_ai:
                hashes = extract_hashes_from_text(last_ai)

        if not hashes:
            self.console.print(
                f"[{THEME['warn']}]크랙할 해시가 없습니다.[/]\n"
                f"[{THEME['dim']}]사용법:\n"
                f"  /crack <hash>          — 직접 입력\n"
                f"  /crack                 — 최근 AI 응답에서 자동 추출\n"
                f"  /crack -w /path/rockyou.txt <hash>[/]"
            )
            return

        self.console.print(
            f"\n[{THEME['warn']}]🔓 해시 크랙 시작 ({len(hashes)}개) — "
            f"[bold]/stop[/bold] 으로 중단[/]\n"
        )
        self._stop_crack_flag.clear()
        # 워드리스트 지정 시 HashCracker에 직접 전달해 실행 (동기)
        if wordlist:
            from ..tools.hash_crack import HashCracker
            cracker = HashCracker(
                wordlist=wordlist,
                on_progress=lambda m: self.console.print(f"[{THEME['dim']}]{m}[/]"),
            )
            for h in hashes:
                if self._stop_crack_flag.is_set():
                    break
                r = cracker.crack(h)
                if r.cracked:
                    self.console.print(
                        f"  [{THEME['success']}]✓ {h[:30]}... → [bold]{r.plaintext}[/bold][/]"
                    )
                else:
                    self.console.print(f"  [{THEME['dim']}]✗ {h[:30]}... 미해결[/]")
        else:
            # 파이프라인 (온라인 → 오프라인)
            self._auto_crack_pipeline(hashes)

    def _cmd_tools(self, arg: str = "") -> None:
        from ..tools.registry import ToolRegistry
        from ..tools.executor import _GO_TOOLS, _PKG_TOOLS

        # ── /tools install <name|all> ────────────────────────────────
        tokens = arg.split()
        if tokens and tokens[0].lower() in ("install", "add"):
            targets = tokens[1:] if len(tokens) > 1 else []
            if not targets:
                self._warn("사용법: /tools install <도구명>  또는  /tools install all")
                return
            if targets == ["all"]:
                missing = [t.name for t in ToolRegistry.missing_tools()]
                targets = missing

            self.console.print(f"\n[{THEME['warn']}]📦 도구 자동 설치: {', '.join(targets)}[/]\n")
            for tool_name in targets:
                self._install_tool_interactive(tool_name)
            return

        # ── 도구 현황 테이블 ────────────────────────────────────────
        self.console.print()
        all_tools = ToolRegistry.scan_all()
        available_cnt = sum(1 for i in all_tools.values() if i.available)
        missing_list = [(n, i) for n, i in all_tools.items() if not i.available]

        table = Table(
            title=f"[{THEME['primary']}]Bingo Tools  ({available_cnt}/{len(all_tools)} 설치됨)[/]",
            border_style=THEME["primary"],
        )
        table.add_column("#", style=THEME["dim"], width=3)
        table.add_column("도구", style=THEME["secondary"])
        table.add_column("유형", style=THEME["dim"])
        table.add_column("상태", justify="center")
        table.add_column("버전 / 설치 방법", style=THEME["dim"])

        _type_label = {
            **{t: "Go Binary" for t in _GO_TOOLS},
            **{t: "pkg-mgr" for t in _PKG_TOOLS},
            "sqlmap": "Python", "wafw00f": "Python",
            "curl": "builtin", "python3": "builtin",
        }

        for i, (name, info) in enumerate(all_tools.items(), 1):
            typ = _type_label.get(name, "tool")
            if info.available:
                table.add_row(
                    str(i), name, typ,
                    f"[{THEME['success']}]✓[/]",
                    (info.version or "설치됨")[:55],
                )
            else:
                table.add_row(
                    str(i), name, typ,
                    f"[{THEME['error']}]✗[/]",
                    info.install_hint[:55],
                )
        self.console.print(table)

        # ── 없는 도구가 있으면 자동 설치 제안 ──────────────────────
        if not missing_list:
            self.console.print(
                f"[{THEME['success']}]모든 도구가 설치되어 있습니다.[/]\n"
            )
            return

        self.console.print(
            f"\n[{THEME['warn']}]{len(missing_list)}개 도구 미설치.[/]  "
            f"[{THEME['dim']}]자동 설치 옵션:[/]"
        )
        for i, (n, _) in enumerate(missing_list, 1):
            typ = _type_label.get(n, "tool")
            method = "GitHub Releases" if n in _GO_TOOLS else "brew/apt/pip"
            self.console.print(
                f"  [{THEME['secondary']}]{i}[/] — [{THEME['primary']}]{n}[/]"
                f"  [{THEME['dim']}]({typ}, {method})[/]"
            )
        self.console.print(
            f"\n  [{THEME['dim']}]설치: /tools install <도구명>  또는  /tools install all[/]\n"
            f"  [{THEME['dim']}]예)  /tools install nmap nuclei ffuf[/]\n"
            f"  [{THEME['dim']}]예)  /tools install all[/]\n"
        )

        # 바로 설치할지 물어보기
        try:
            ans = self._session.prompt(
                HTML('<ansiyellow>지금 없는 도구를 모두 설치할까요? (y/N) </ansiyellow>'),
                style=PT_STYLE,
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return

        if ans in ("y", "yes", "예"):
            self.console.print(
                f"\n[{THEME['warn']}]📦 {len(missing_list)}개 도구 자동 설치 시작...[/]\n"
            )
            for name, _ in missing_list:
                self._install_tool_interactive(name)
        else:
            self.console.print(
                f"[{THEME['dim']}]나중에 /tools install <이름> 으로 개별 설치 가능[/]"
            )

    def _install_tool_interactive(self, tool_name: str) -> None:
        """단일 도구 자동 설치 with 진행 상황 출력"""
        from ..tools.registry import ToolRegistry, _find_binary
        from ..tools.executor import _GO_TOOLS, _PKG_TOOLS
        import shutil

        self.console.print(
            f"[{THEME['secondary']}]  ▸ {tool_name}[/] 설치 시도...",
            end=" "
        )
        log_lines: list[str] = []

        def log(msg: str) -> None:
            log_lines.append(msg)
            self.console.print(f"\n    [{THEME['dim']}]{msg}[/]", end="")

        success = False

        try:
            if tool_name in _GO_TOOLS:
                from ..tools.downloader import download_tool
                path = download_tool(tool_name, log)
                success = path is not None and path.exists()
            elif tool_name in _PKG_TOOLS:
                from ..tools.installer import install_tool
                success = install_tool(tool_name, log)
            elif tool_name in ("sqlmap", "wafw00f"):
                from ..tools.installer import install_tool
                success = install_tool(tool_name, log)
        except Exception as e:
            log(f"오류: {e}")

        if success:
            ToolRegistry._cache.pop(tool_name, None)
            self.console.print(f"\n  [{THEME['success']}]✓ {tool_name} 설치 완료[/]")
        else:
            self.console.print(f"\n  [{THEME['error']}]✗ {tool_name} 설치 실패 — Python 폴백 사용[/]")

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
            completer=_SlashCompleter(),
            complete_while_typing=True,
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
