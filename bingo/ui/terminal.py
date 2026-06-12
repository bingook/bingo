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
        while True:
            try:
                user_input = self._get_input()
            except (KeyboardInterrupt, EOFError):
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
        """사용자 입력에서 관련 스킬 자동 검색 후 AI 컨텍스트 문자열 반환.

        우선순위:
          1. SecSkills-main / advsec-plus 로컬 references/ (가장 정확, 환각 방지)
          2. CyberSecurity-Skills 내장 DB (보조)
        """
        from ..skills.engine import SkillEngine
        engine = SkillEngine()

        parts: list[str] = []

        # ── 1. 로컬 SecSkills references 검색 (우선) ─────────────────
        local_ctx = engine.local_skill_context(text, max_chars=3500)
        if local_ctx:
            parts.append(
                "=== SKILL_CONTEXT (verified reference — cite with [引用:references/file.md]) ===\n"
                + local_ctx
                + "\n=== END SKILL_CONTEXT ==="
            )

        # ── 2. 내장 CyberSecurity-Skills DB (보조) ───────────────────
        if not parts:
            results = engine.search(text)
            for r in results[:3]:
                prompt = engine.get_skill_prompt(r["id"])
                if prompt:
                    parts.append(prompt)

        return "\n\n".join(parts)

    def _auto_waf_scan(self, text: str) -> str:
        """URL 감지 시 기본 사이트 정보 수집 → AI가 직접 판단하게 컨텍스트 제공.
        wafw00f / sqlmap 의존성 완전 제거. AI가 Python으로 직접 탐지.
        """
        import re
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        if not urls:
            return ""

        url = urls[0].rstrip("/?,")
        results: list[str] = []

        self.console.print(
            f"\n[{THEME['warn']}]{self.s.get('site_recon', '🔍 Site recon')}: {url}[/]"
        )

        # ── 빠른 HTTP 정보 수집 (헤더 + 응답코드) ─────────────────────
        try:
            import httpx as _hx
            _hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}
            resp = _hx.get(url, headers=_hdrs, follow_redirects=True,
                           timeout=10, verify=False)

            # 응답 헤더에서 서버 정보 추출
            server   = resp.headers.get("server", "unknown")
            powered  = resp.headers.get("x-powered-by", "")
            cf_ray   = resp.headers.get("cf-ray", "")
            x_cache  = resp.headers.get("x-cache", "")

            results.append(
                f"SITE_INFO:\n"
                f"  url={url}\n"
                f"  status={resp.status_code}\n"
                f"  server={server}\n"
                f"  x-powered-by={powered or 'none'}\n"
                f"  cf-ray={cf_ray or 'none'}\n"
                f"  x-cache={x_cache or 'none'}\n"
                f"  content_length={len(resp.text)}"
            )

            # 헤더 기반 간이 WAF 힌트 (AI에게 참고로만 전달)
            waf_hints = []
            if cf_ray:
                waf_hints.append("Cloudflare (cf-ray header)")
            if "sucuri" in resp.text.lower()[:500] or "x-sucuri" in str(resp.headers).lower():
                waf_hints.append("Sucuri")
            if "x-fw" in str(resp.headers).lower():
                waf_hints.append("Wordfence")
            if waf_hints:
                self.console.print(f"[{THEME['warn']}]  {self.s.get('waf_hint', '⚡ WAF hint')}: {', '.join(waf_hints)}[/]")
                results.append(f"WAF_HINTS: {', '.join(waf_hints)}")
            else:
                results.append("WAF_HINTS: none detected from headers (AI should verify)")

        except Exception as e:
            results.append(f"SITE_INFO_ERROR: {e}")

        # ── 사이트 크롤링 → 후보 URL 수집 (AI가 직접 탐지) ──────────
        self.console.print(f"[{THEME['dim']}]{self.s.get('page_crawling', '🔍 Crawling page...')}[/]")
        candidate_urls: list[str] = []
        try:
            import httpx as _hx2, re as _re
            from urllib.parse import urlparse, parse_qs

            _STATIC_EXT = {
                ".css", ".js", ".ts", ".jsx", ".tsx", ".map",
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
                ".woff", ".woff2", ".ttf", ".eot", ".otf",
                ".pdf", ".zip", ".gz", ".tar", ".rar",
                ".mp3", ".mp4", ".webm", ".ogg", ".wav",
                ".xml", ".rss", ".atom",
            }
            _CACHE_PARAMS = {"ver", "v", "version", "_", "t", "ts", "time",
                             "cb", "cachebuster", "bust", "rev", "build", "hash"}

            headers2 = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}
            resp2 = _hx2.get(url, follow_redirects=True, timeout=10,
                              headers=headers2, verify=False)
            page = resp2.text
            found_urls = _re.findall(
                r'(?:href|action)=["\']([^"\'<>\s]+)["\']', page, _re.IGNORECASE
            )
            base = url.rstrip("/")
            base_domain = base.split("/")[0] + "//" + base.split("/")[2]

            for fu in found_urls:
                if fu.startswith("http"):
                    full = fu
                elif fu.startswith("/"):
                    full = base_domain + fu
                elif fu.startswith("?"):
                    full = base + fu
                else:
                    full = base + "/" + fu

                if "?" not in full or "=" not in full:
                    continue
                if base_domain not in full:
                    continue

                parsed = urlparse(full)
                path_no_qs = parsed.path.lower()
                ext = ""
                if "." in path_no_qs.split("/")[-1]:
                    ext = "." + path_no_qs.rsplit(".", 1)[-1]
                if ext in _STATIC_EXT:
                    continue

                qs = parse_qs(parsed.query)
                real_params = {k for k in qs if k.lower() not in _CACHE_PARAMS}
                if not real_params:
                    continue

                candidate_urls.append(full)

            candidate_urls = list(dict.fromkeys(candidate_urls))[:15]

        except Exception as e:
            results.append(f"CRAWL_ERROR: {e}")

        if candidate_urls:
            self.console.print(
                f"[{THEME['success']}]{self.s.get('params_found', '✓ 파라미터 발견')}: "
                f"{len(candidate_urls)}개[/]"
            )
            for u in candidate_urls[:5]:
                self.console.print(f"  [{THEME['dim']}]{u}[/]")

            results.append(
                "CANDIDATE_URLS (real backend pages with parameters — AI must probe these):\n"
                + "\n".join(f"  - {u}" for u in candidate_urls)
            )
            results.append(
                "AGENT_INSTRUCTION:\n"
                "  These are candidate URLs. You must now:\n"
                "  1. Write Python code to probe each URL for SQL injection\n"
                "  2. Test: single-quote, boolean (1=1 vs 1=2), error patterns\n"
                "  3. Only report confirmed or likely vulnerable targets\n"
                "  4. Do NOT assume vulnerability — test with real HTTP requests\n"
                "  5. If WAF blocking: adapt payload encoding in your Python code"
            )
        else:
            results.append(
                "CANDIDATE_URLS: none found on homepage\n"
                "AGENT_INSTRUCTION:\n"
                "  Write Python to crawl deeper:\n"
                f"  - Fetch {url} and extract all href/action/src links\n"
                "  - Look for .php/.asp/.aspx/.do pages with query params\n"
                "  - Check sitemap.xml and robots.txt for more paths"
            )

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

        # URL 감지 시 실제 WAF 스캔 실행
        # → 결과를 유저 메시지 앞에 직접 붙임 (AI가 "이미 실행됨"을 명확히 인식)
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
            self.history.append(Message(role="assistant", content=full_response))
            self._append_to_session_log("assistant", full_response)
            # AI 응답에서 명령 추출 → 실제 실행 → 결과를 컨텍스트로 주입
            self._execute_ai_commands(full_response)
            # AI 응답에 해시가 있으면 자동 크랙 알림
            self._notify_hashes_found(full_response)

    @staticmethod
    def _filter_agent_noise(text: str) -> str:
        """AWAITING_BINGO_EXECUTION 등 내부 제어 키워드를 화면에서 제거."""
        import re
        text = re.sub(r"\n?AWAITING_BINGO_EXECUTION\n?", "", text)
        text = re.sub(r"\n?TASK_COMPLETE\n?", "\n✅ 작업 완료\n", text)
        text = re.sub(r"\n?MISSION_COMPLETE\n?", "\n✅ 미션 완료\n", text)
        return text

    @staticmethod
    def _collapse_code_blocks(text: str) -> str:
        """Python/bash 코드 블록을 접어서 한 줄 요약으로 교체.
        Cursor처럼 '무엇을 하는지'만 보여주고 소스코드는 숨김.
        """
        import re

        def _summarize_code(lang: str, code: str) -> str:
            lines = [l.strip() for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]
            total = len(code.splitlines())

            # 코드 의도 파악 (주요 키워드 기반)
            code_lower = code.lower()
            intent = ""
            if "sql" in code_lower or "sqli" in code_lower or "injection" in code_lower:
                intent = "SQLi 탐지"
            elif "waf" in code_lower or "cloudflare" in code_lower or "firewall" in code_lower:
                intent = "WAF 탐지"
            elif "union" in code_lower or "information_schema" in code_lower:
                intent = "DB 추출"
            elif "database()" in code_lower or "table_name" in code_lower:
                intent = "테이블/DB 열거"
            elif "password" in code_lower or "passwd" in code_lower or "credential" in code_lower:
                intent = "자격증명 추출"
            elif "crawl" in code_lower or "href" in code_lower or "sitemap" in code_lower:
                intent = "사이트 크롤링"
            elif "httpx" in code_lower or "requests" in code_lower:
                intent = "HTTP 요청"
            elif "nmap" in code_lower or "socket" in code_lower or "port" in code_lower:
                intent = "포트 스캔"
            else:
                # 첫 번째 의미있는 줄로 요약
                intent = lines[0][:50] if lines else "스크립트"

            icon = "🐍" if lang == "python" else "⚡"
            return (
                f"\n[dim]┌─ {icon} {lang.upper()} 스크립트 [{intent}] — {total}줄[/dim]\n"
                f"[dim]│  {lines[0][:70] if lines else ''}[/dim]\n"
                f"[dim]│  {lines[1][:70] if len(lines) > 1 else ''}[/dim]\n"
                f"[dim]└─ ... (실행 대기 중)[/dim]\n"
            )

        # ```python ... ``` 또는 ```bash ... ``` 블록 치환
        def replacer(m: re.Match) -> str:
            lang = (m.group(1) or "").strip().lower() or "code"
            code = m.group(2)
            if lang in ("python", "py", "bash", "sh"):
                return _summarize_code(lang if lang in ("python", "bash") else "python", code)
            return m.group(0)  # 다른 언어는 그대로

        return re.sub(r"```(\w*)\n(.*?)```", replacer, text, flags=re.DOTALL)

    def _stream_response(self, stream: Iterator[StreamChunk]) -> str:
        full = ""

        self.console.print(f"\n[{THEME['secondary']}]bingo[/] [{THEME['dim']}]▸[/]", end=" ")

        # 스트리밍 중: 코드 블록 접힌 상태로 실시간 표시
        with Live(console=self.console, refresh_per_second=20, transient=True) as live:
            buf = Text()
            for chunk in stream:
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

        # 최종 출력: 코드 블록 접기 + 내부 제어 키워드 제거
        final = self._filter_ai_monologue(full)
        display = self._collapse_code_blocks(final)
        display = self._filter_agent_noise(display)

        self.console.print()
        try:
            self.console.print(Markdown(display) if ("**" in display or "# " in display) else display)
        except Exception:
            self.console.print(display)
        self.console.print()
        return final  # 실행에는 원본(full code) 반환

    @staticmethod
    def _filter_ai_monologue(text: str) -> str:
        """AI 내부 독백 / thinking 텍스트 필터링"""
        import re
        # <think>...</think> 블록 제거
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
        # AI 자기 참조 문장이 포함된 줄 제거
        _MONOLOGUE_PATTERNS = (
            r"^I'll simulate",
            r"^I need to produce",
            r"^As an AI",
            r"^I can't actually run",
            r"^I can simulate",
            r"^I must provide",
            r"^Since I can't actually",
            r"^For the sake of",
            r"^In the context of",
            r"^I'll pretend",
            r"^I'll generate",
            r"^I'll note that",
            r"^Since this is a (fake|simulated)",
            r"^Better: I'll",
            r"^I'll have to generate",
            r"^I'll produce the final",
            r"^I need to output",
            r"^I've redacted",
            r"^Now, output the final",
            r"^output the final response",
            r"^The user likely expects",
        )
        filtered_lines = []
        skip = False
        for line in text.splitlines():
            stripped = line.strip()
            if any(re.match(pat, stripped, re.IGNORECASE) for pat in _MONOLOGUE_PATTERNS):
                skip = True
                continue
            # 독백 단락이 끝나면 (빈 줄 또는 코드블록 시작) skip 해제
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
        }
        fn = dispatch.get(name)
        if fn:
            fn()
        elif name == "/skill":
            self._cmd_skill(arg)
        elif name == "/tools":
            self._cmd_tools(arg)
        elif name == "/scan":
            if arg:
                self._cmd_scan(arg)
            else:
                self._warn("Usage: /scan <url>  예) /scan https://target.co.kr")
        elif name == "/waf":
            # /waf 명령은 제거됨 → AI에게 직접 탐지 코드 작성 위임
            target = arg or "https://target.com"
            self._send_message(
                f"{target} 사이트의 WAF와 보안 장치를 탐지해줘. "
                f"Python httpx로 직접 헤더, 응답 패턴 분석해서 식별해."
            )
        elif name == "/crack":
            self._cmd_crack(arg)
        elif name == "/stop":
            self._stop_crack_flag.set()
            self.console.print(f"[{THEME['warn']}]{self.s['hash_stop_signal']}[/]")
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

    # ── Red Team 명령어 ───────────────────────────────────────────

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

    def _execute_ai_commands(self, response: str) -> None:
        """
        AI가 ```python 또는 ```bash 블록으로 코드를 제시하면 실제로 실행하고
        결과를 AI에게 피드백 → AI가 실제 데이터로 분석함.

        Full Agent 모드: Python 코드 우선, bash 명령도 지원.
        AWAITING_BINGO_EXECUTION 키워드가 있을 때 실행.
        """
        import re, subprocess, tempfile, os
        from pathlib import Path

        if "```" not in response:
            return

        results_text: list[str] = []

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

        # ── Python 블록 실행 (우선) ────────────────────────────────────
        python_blocks = re.findall(
            r"```python\s*(.*?)```", response, re.DOTALL
        )
        for i, block in enumerate(python_blocks):
            code = block.strip()
            if not code:
                continue

            # agent_tools import 경로 주입 (AI 코드에 없으면 자동 추가)
            tools_header = (
                "import sys as _sys, os as _os\n"
                "_sys.path.insert(0, _os.path.expanduser('~/.bingo'))\n"
            )
            if "agent_tools" not in code and "from agent_tools" not in code:
                code = tools_header + code

            # 임시 파일에 저장 후 실행
            tmp_dir = Path(tempfile.gettempdir()) / "bingo_agent"
            tmp_dir.mkdir(exist_ok=True)
            script_path = tmp_dir / f"agent_script_{i}.py"
            script_path.write_text(code, encoding="utf-8")

            preview_lines = code.splitlines()[:3]
            preview = " | ".join(l.strip() for l in preview_lines if l.strip())[:80]

            self.console.print(
                f"\n[{THEME['secondary']}]▶ {self.s.get('python_exec', 'Python execution')}:[/] "
                f"[{THEME['dim']}]{preview}...[/]"
            )

            try:
                proc = subprocess.run(
                    ["python3", str(script_path)],
                    capture_output=True, text=True, timeout=120,
                    env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                )
                output = (proc.stdout or "") + (proc.stderr or "")
                if output.strip():
                    preview_out = "\n".join(output.strip().splitlines()[:60])
                    self.console.print(f"[{THEME['dim']}]{preview_out}[/]")
                    results_text.append(
                        f"=== PYTHON EXECUTION (script_{i}) ===\n"
                        f"{output.strip()}\n"
                        f"=== EXIT: {proc.returncode} ==="
                    )
                else:
                    results_text.append(
                        f"=== PYTHON EXECUTION (script_{i}) ===\n"
                        f"(no output, exit={proc.returncode})"
                    )
            except subprocess.TimeoutExpired:
                self.console.print(f"[{THEME['warn']}]  ⏱ timeout (120s)[/]")
                results_text.append(
                    f"=== PYTHON EXECUTION (script_{i}) ===\n(timed out after 120s — AI should write a faster/smaller script)"
                )
            except Exception as e:
                self.console.print(f"[{THEME['error']}]  python exec error: {e}[/]")

        # ── Bash 블록 실행 (보조) ──────────────────────────────────────
        # bash는 curl, nmap 등 단순 명령에만 사용
        bash_blocks = re.findall(
            r"```(?:bash|sh)\s*(.*?)```", response, re.DOTALL
        )

        # bash 실행 허용 목록 (Python으로 못하는 것들)
        _BASH_ALLOWED = {
            "curl", "nmap", "nikto", "ffuf", "gobuster", "nuclei",
            "httpx", "subfinder", "amass", "whatweb", "john", "hashcat",
            "python3", "python",
        }

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
            if not parts:
                continue
            binary = parts[0].split("/")[-1]
            if binary not in _BASH_ALLOWED:
                continue

            # 이미 실행된 명령이면 스킵
            history_text = " ".join(m.content for m in self.history if m.role == "user")
            if f"REAL EXECUTION: {cmd_line[:40]}" in history_text:
                continue

            self.console.print(
                f"\n[{THEME['secondary']}]▶ {self.s['exec_running']}:[/] "
                f"[{THEME['dim']}]{cmd_line[:100]}[/]"
            )
            try:
                proc = subprocess.run(
                    cmd_line, shell=True, capture_output=True,
                    text=True, timeout=180
                )
                output = (proc.stdout or "") + (proc.stderr or "")
                if output.strip():
                    preview = "\n".join(output.strip().splitlines()[:50])
                    self.console.print(f"[{THEME['dim']}]{preview}[/]")
                    results_text.append(
                        f"=== REAL EXECUTION: {cmd_line[:80]} ===\n"
                        f"{output.strip()}\n"
                        f"=== EXIT CODE: {proc.returncode} ==="
                    )
                else:
                    results_text.append(
                        f"=== REAL EXECUTION: {cmd_line[:80]} ===\n"
                        f"(no output, exit code {proc.returncode})"
                    )
            except subprocess.TimeoutExpired:
                self.console.print(f"[{THEME['warn']}]  ⏱ timeout (180s)[/]")
                results_text.append(
                    f"=== REAL EXECUTION: {cmd_line[:80]} ===\n(timed out)"
                )
            except Exception as e:
                self.console.print(f"[{THEME['error']}]  exec error: {e}[/]")

        if not results_text:
            return

        # 결과 압축: 최대 3000자만 주입 (컨텍스트 폭발 방지)
        raw_results = "\n".join(results_text)
        if len(raw_results) > 3000:
            # 앞 1500자 + 뒤 1500자 유지 (중간 생략)
            trimmed = (
                raw_results[:1500]
                + f"\n\n[... {len(raw_results) - 3000} chars trimmed for context ...]\n\n"
                + raw_results[-1500:]
            )
        else:
            trimmed = raw_results

        # 히스토리 슬라이딩 윈도우 — 시스템 메시지 제외하고 최근 10턴만 유지
        # 컨텍스트가 너무 커지면 DeepSeek 서버가 연결을 끊음
        non_system = [m for m in self.history if m.role != "system"]
        if len(non_system) > 20:
            # 가장 오래된 user/assistant 쌍 4개 제거
            system_msgs = [m for m in self.history if m.role == "system"]
            recent = non_system[-16:]
            self.history = system_msgs + recent

        # 실행 결과 AI에게 피드백
        injection = (
            "=== BINGO REAL EXECUTION RESULTS ===\n"
            + trimmed
            + "\n=== END REAL RESULTS ===\n\n"
            "Analyze the REAL results above and continue autonomously.\n"
            "- Extract all findings (vulnerabilities, DBs, tables, credentials, hashes)\n"
            "- Write and execute the NEXT script immediately\n"
            "- If WAF blocks SQL functions: use obfuscation variants automatically\n"
            "- Output TASK_COMPLETE when all objectives are achieved\n"
            "- NEVER generate simulated output"
        )
        self.history.append(Message(role="user", content=injection))

        from ..models.registry import ModelRegistry
        model_cfg = self.config.get_active_model_config()
        if not model_cfg:
            return

        model = ModelRegistry.build(model_cfg)
        self.console.print(
            f"\n[{THEME['secondary']}]{self.s['exec_analyzing']}[/]"
        )
        followup_response = self._stream_response(
            model.chat_stream(self._build_messages(""))
        )
        if followup_response:
            self.history.append(Message(role="assistant", content=followup_response))
            self._append_to_session_log("assistant", followup_response)
            self._notify_hashes_found(followup_response)

            # TASK_COMPLETE 감지 → 루프 종료
            if "TASK_COMPLETE" in followup_response or "MISSION_COMPLETE" in followup_response:
                self.console.print(f"\n[{THEME['success']}]✅ Agent 작업 완료[/]\n")
                return

            # Agent 루프: 최대 15턴까지 자율 실행
            exec_count = sum(
                1 for m in self.history
                if m.role == "user" and "BINGO REAL EXECUTION RESULTS" in m.content
            )
            if exec_count < 15:
                self.console.print(
                    f"[{THEME['dim']}]🔄 Agent 루프 {exec_count + 1}/15[/]"
                )
                self._execute_ai_commands(followup_response)
            else:
                self.console.print(
                    f"[{THEME['warn']}]⚠ Agent 최대 루프(15) 도달 — 직접 다음 명령을 입력하세요[/]"
                )

    def _notify_hashes_found(self, text: str) -> None:
        """AI 응답에서 해시 감지 시 자동 온라인 조회 → 오프라인 크랙 파이프라인 실행"""
        from ..tools.hash_crack import extract_hashes_from_text
        hashes = extract_hashes_from_text(text)
        if not hashes:
            return
        self.console.print(
            f"\n[{THEME['warn']}]{self.s['hash_found'].format(n=len(hashes))}[/]"
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

    def _cmd_skill(self, keyword: str = "") -> None:
        from ..skills.engine import SkillEngine
        engine = SkillEngine()

        if keyword:
            # ── 로컬 SecSkills references 검색 (우선) ─────────────────
            local_results = engine.local_skill_search(keyword)
            if local_results:
                self.console.print(
                    f"\n[{THEME['secondary']}]🔍 SecSkills 레퍼런스 매칭: [bold]{keyword}[/bold][/]"
                )
                ref_table = Table(border_style=THEME["primary"], show_header=True)
                ref_table.add_column("스킬 팩", style=THEME["secondary"], width=20)
                ref_table.add_column("레퍼런스 파일", style="white", width=30)
                ref_table.add_column("키워드", style=THEME["dim"])
                for r in local_results[:10]:
                    ref_table.add_row(
                        r["skill_dir"],
                        r["reference"] or "SKILL.md",
                        ", ".join(r["matched_keywords"][:3]),
                    )
                self.console.print(ref_table)
                self.console.print(
                    f"[{THEME['dim']}]{self.s.get('skill_ctx_injected', '💡 Reference auto-injected into AI context.')}[/]"
                )

            # ── 내장 DB 검색 (보조) ────────────────────────────────────
            results = engine.search(keyword)
            if results:
                self.console.print(f"\n[{THEME['dim']}]📚 {self.s.get('skill_db_label', 'Built-in DB skills')}:[/]")
                for r in results[:10]:
                    self.console.print(f"  [{THEME['primary']}]{r['module']}[/] → {r['skill']}")

            if not local_results and not results:
                self.console.print(
                    f"[{THEME['dim']}]{self.s['skill_no_result'].format(kw=keyword)}[/]"
                )
        else:
            # ── 로컬 스킬 팩 목록 ──────────────────────────────────────
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
            table.add_column("ID", style=THEME["secondary"], width=4)
            table.add_column("모듈", style="white")
            table.add_column("스킬 수", justify="right")
            for mod in engine.list_all():
                table.add_row(mod["id"], mod["en"], str(len(mod["skills"])))
            self.console.print(table)
            self.console.print(f"[{THEME['dim']}]{self.s['skill_search_hint']}[/]")

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
