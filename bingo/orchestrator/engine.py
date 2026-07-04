"""
bingo/orchestrator/engine.py — LLM 오케스트레이터 엔진  (v4.2.0)

【설계 철학】
  고정 6단계 파이프라인 대신, LLM이 매 스텝마다
  "현재 상태 → 최적 다음 액션"을 스스로 결정한다.

【흐름】
  1. Blackboard에서 현재 발견 사실 수집
  2. AttackChain에서 이미 수행한 단계 확인
  3. 의사결정 LLM 호출 → JSON 응답 파싱
     {action, type, reason, command, update_board, goal_achieved, confidence}
  4. HitlGate 위험도 확인 (선택)
  5. terminal._send_message(command) 실행
  6. 결과를 Blackboard·Chain에 기록
  7. 목표 달성 or max_steps 도달까지 반복

【보장】
  - send_fn (terminal._send_message) 은 직렬 실행 (동시 호출 없음)
  - stop() 호출 즉시 현 스텝 완료 후 종료
  - 오류 발생 시 로그에 기록, 다음 스텝 계속
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# ── 결정용 시스템 프롬프트 ──────────────────────────────────────────────
def _get_orch_system(lang: str = "ko") -> str:
    """Return the orchestrator system prompt with language-appropriate command examples."""
    _examples = {
        "zh": [
            "对目标 https://X.com 启动全面红队渗透测试，包含 WAF 探测、端口/服务枚举、CMS 识别、漏洞扫描。",
            "对 https://X.com 的登录、搜索、过滤参数进行 SQL 注入漏洞全面排查。",
            "利用 https://X.com 发现的 SQLi 进行数据库转储，目标：提取管理员账户。",
            "在 https://X.com 寻找文件上传漏洞并尝试上传 WebShell。",
            "全面探测 https://X.com 的 IDOR / 未授权 API 端点。",
            "整理 https://X.com 发现的全部漏洞，汇总最终渗透路径。",
        ],
        "en": [
            "Start a full red-team pentest against https://X.com — WAF detection, port/service enum, CMS fingerprint, vuln scan.",
            "Test all login/search/filter params at https://X.com for SQL injection.",
            "Dump the database via the discovered SQLi at https://X.com; goal: extract admin credentials.",
            "Find file-upload vulnerabilities at https://X.com and attempt WebShell upload.",
            "Enumerate all IDOR / unauthenticated API endpoints at https://X.com.",
            "Summarise all findings at https://X.com and produce a final attack-path report.",
        ],
        "ko": [
            "타겟 https://X.com 에 대해 전체 레드팀 침투 테스트를 시작해줘. WAF 탐지, 포트/서비스 열거, CMS 식별, 취약점 스캔 포함.",
            "https://X.com 의 로그인·검색·필터 파라미터에 SQL 인젝션 취약점 전수 조사해줘.",
            "https://X.com 에서 발견된 SQLi로 DB 덤프 진행해줘. 관리자 계정 추출 목표.",
            "https://X.com 에 파일 업로드 취약점 찾아서 웹쉘 업로드 시도해줘.",
            "https://X.com 의 IDOR/미인증 API 엔드포인트 전수 탐색해줘.",
            "https://X.com 에서 발견된 취약점 전체 정리하고 최종 침투 경로 요약해줘.",
        ],
    }
    lang_instruction = {
        "zh": (
            "IMPORTANT: ALL text fields ('action', 'reason', 'command') MUST be written in CHINESE (中文). "
            "No Korean, no English in those fields."
        ),
        "en": (
            "IMPORTANT: ALL text fields ('action', 'reason', 'command') MUST be written in ENGLISH. "
            "No Korean, no Chinese in those fields."
        ),
        "ko": (
            "IMPORTANT: ALL text fields ('action', 'reason', 'command') MUST be written in KOREAN (한국어). "
            "No English, no Chinese in those fields."
        ),
    }.get(lang, "IMPORTANT: ALL text fields ('action', 'reason', 'command') MUST be written in ENGLISH.")

    examples = _examples.get(lang, _examples["en"])
    example_block = "\n".join(f'- "{ex}"' for ex in examples)

    return f"""You are an autonomous penetration testing orchestrator for Bingo AI.
Your role: analyze current attack state and choose the OPTIMAL next action.

Rules:
- Choose based on discovered facts, not a fixed script
- Avoid repeating already-completed steps
- Escalate systematically: recon → vuln_scan → exploit → persist
- ALWAYS respond in valid JSON. No markdown, no explanation outside JSON.

{lang_instruction}

⚠️ MANDATORY TARGET RULE (NEVER VIOLATE):
- The "command" field MUST always explicitly include the exact TARGET URL from the TARGET field above.
- NEVER generate a command that omits the target URL. The executor has NO memory of the target.
- Every command must be self-contained and reference the target directly.

JSON format:
{{
  "action": "short action label",
  "type": "recon|vuln|exploit|persist|lateral|exfil|cred|access",
  "reason": "why this step now (1-2 sentences)",
  "command": "the exact prompt/command to send to the AI assistant — MUST include target URL",
  "update_board": {{}},
  "goal_achieved": false,
  "confidence": 0.8
}}

Command examples (note EVERY example includes the full target URL):
{example_block}

Set goal_achieved=true ONLY when the stated goal is confirmed complete."""

# ── 가능한 공격 타입 ────────────────────────────────────────────────────
_ATTACK_TYPES = {
    "recon":   "🔍",
    "vuln":    "🔴",
    "exploit": "💥",
    "persist": "🔒",
    "lateral": "↔️",
    "exfil":   "📤",
    "cred":    "🔑",
    "access":  "🚪",
}

# ── 스텝 기록 ───────────────────────────────────────────────────────────
@dataclass
class OrchStep:
    step_no: int
    action: str
    step_type: str
    reason: str
    command: str
    confidence: float
    goal_achieved: bool
    ts: float = field(default_factory=time.time)

    def icon(self) -> str:
        return _ATTACK_TYPES.get(self.step_type, "▪️")

    def short(self) -> str:
        return (
            f"{self.icon()} [{self.step_no:02d}] {self.action} "
            f"(conf={self.confidence:.0%})"
        )


# ── 메인 엔진 ───────────────────────────────────────────────────────────
class OrchestratorEngine:
    """
    LLM 기반 동적 공격 오케스트레이터.

    사용법 (terminal에서):
        engine = OrchestratorEngine(config, target, goal="관리자 로그인", max_steps=12)
        engine.start(send_fn=self._send_message, console=self.console)
        ...
        engine.stop()
    """

    def __init__(
        self,
        config: Any,
        target: str,
        goal: str = "",
        max_steps: int = 10,
        hitl_enabled: bool = True,
        step_delay: float = 3.0,
        lang: str = "ko",
    ) -> None:
        from ..lang.strings import get_strings as _get_strings
        self._s = _get_strings(lang)
        self._lang = lang

        self._config = config
        self._target = target.strip().rstrip("/")
        self._goal = goal or self._s.get("orch_ui_default_goal", "Obtain admin credentials and maximum privilege")
        self._max_steps = max_steps
        self._hitl_enabled = hitl_enabled
        self._step_delay = step_delay

        self._step: int = 0
        self._running: bool = False
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._log: List[OrchStep] = []
        self._error: Optional[str] = None

    # ── 상태 조회 ──────────────────────────────────────────────────────
    @property
    def running(self) -> bool:
        return self._running and (self._thread is not None and self._thread.is_alive())

    @property
    def step(self) -> int:
        return self._step

    @property
    def log(self) -> List[OrchStep]:
        return list(self._log)

    def summary(self) -> str:
        lines = [
            f"[ORCHESTRATOR] target={self._target}",
            f"  goal   : {self._goal}",
            f"  steps  : {self._step}/{self._max_steps}",
            f"  status : {'🟢 running' if self.running else '⏹ stopped'}",
        ]
        if self._log:
            lines.append("  history:")
            for s in self._log[-5:]:
                lines.append(f"    {s.short()}")
        if self._error:
            lines.append(f"  last error: {self._error}")
        return "\n".join(lines)

    # ── 시작 / 중지 ────────────────────────────────────────────────────
    def start(
        self,
        send_fn: Callable[[str], None],
        console: Any,
    ) -> None:
        if self.running:
            return
        self._stop_evt.clear()
        self._running = True
        self._error = None
        self._thread = threading.Thread(
            target=self._loop,
            args=(send_fn, console),
            daemon=True,
            name="bingo-orchestrator",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        self._running = False

    # ── LLM 결정 호출 ─────────────────────────────────────────────────
    def _call_decision_llm(self, prompt: str, board_ctx: str = "", chain_ctx: str = "") -> str:
        """결정 전용 미니 LLM 세션 (terminal 대화와 완전 분리).
        v4.0.0: Amplifier 연동 — CoT + RAG 자동 주입, 단 자기수정은 스킵 (속도 우선)
        """
        try:
            from ..models.registry import ModelRegistry
            model_cfg = self._config.get_active_model_config()
            if not model_cfg:
                return ""
            model = ModelRegistry.build(model_cfg)

            # ── v4.0.0: Amplifier 전처리 ──────────────────────────────────
            base_msgs = [
                {"role": "system", "content": _get_orch_system(self._lang)},
                {"role": "user",   "content": prompt},
            ]
            try:
                from ..core.amplifier import get_amplifier
                amp = get_amplifier(self._lang)
                msgs = amp.pre_process(
                    base_msgs,
                    target=self._target,
                    blackboard_ctx=board_ctx,
                    chain_ctx=chain_ctx,
                )
            except Exception:
                msgs = base_msgs

            result = ""
            # _amp_skip=True: 오케스트레이터 내부 LLM은 이중 앰플리파이어 방지
            for chunk in model.chat_stream(msgs, _amp_skip=True):
                # ★ v3.5.15: 정지 요청 시 즉시 LLM 결정 중단
                if self._stop_evt.is_set():
                    return ""
                result += chunk.text
                if chunk.done:
                    break
            return result
        except Exception as e:
            self._error = str(e)
            return ""

    # ── 결정 프롬프트 생성 ─────────────────────────────────────────────
    def _build_decision_prompt(
        self,
        board_ctx: str,
        chain_ctx: str,
    ) -> str:
        history_summary = ""
        if self._log:
            history_summary = "\n".join(
                f"  [{s.step_no}] {s.action}" for s in self._log[-5:]
            )
        return f"""TARGET: {self._target}
GOAL: {self._goal}
CURRENT STEP: {self._step + 1} / {self._max_steps}

=== BLACKBOARD (discovered facts) ===
{board_ctx or '(empty — no facts discovered yet)'}

=== ATTACK CHAIN (recent steps) ===
{chain_ctx}

=== ORCHESTRATOR HISTORY (last 5) ===
{history_summary or '(none)'}

Decide the single best next action to advance toward the goal.
Consider what is UNKNOWN and what attack surface remains unexplored.
Do NOT repeat an action already in the history.

⚠️ CRITICAL: The "command" field MUST contain the EXACT target URL: {self._target}
The executor has NO memory — every command must be 100% self-contained.
BAD:  "Run SQL injection test"  (no target URL)
GOOD: "Test SQL injection at {self._target}"  (includes full target URL)

Respond ONLY in JSON."""

    # ── JSON 파싱 ──────────────────────────────────────────────────────
    def _parse_decision(self, raw: str) -> Dict[str, Any]:
        default: Dict[str, Any] = {
            "action": f"step {self._step}",
            "type": "recon",
            "reason": "",
            "command": f"Continue vulnerability analysis of {self._target}",
            "update_board": {},
            "goal_achieved": False,
            "confidence": 0.5,
        }
        if not raw:
            return default
        # JSON 블록 추출
        m = re.search(r"\{[\s\S]*\}", raw)
        if not m:
            return default
        try:
            d = json.loads(m.group())
            default.update(d)
        except Exception:
            pass
        return default

    # ── 메인 루프 ──────────────────────────────────────────────────────
    def _loop(
        self,
        send_fn: Callable[[str], None],
        console: Any,
    ) -> None:
        from ..blackboard.store import BoardRegistry
        from ..chain.tracker import ChainRegistry
        from ..hitl.gate import global_gate

        board = BoardRegistry.get(self._target)
        session_id = f"orch_{re.sub(r'[^a-z0-9]', '_', self._target.lower())[:20]}"
        chain = ChainRegistry.get(session_id)
        gate  = global_gate()

        _print = lambda msg: console.print(msg)
        _s = self._s  # 다국어 문자열 shorthand

        # ── /tmp 환경 초기화: 타겟 등록 & 이전 세션 stale 파일 제거 ────────
        import os as _os
        _tmp_target = "/tmp/bingo_target.txt"
        try:
            with open(_tmp_target, "w") as _f:
                _f.write(self._target + "\n")
        except OSError:
            pass
        # 이전 세션에서 남겨진 stale 임시 파일 목록 (타겟 오염 위험)
        _stale_files = [
            "/tmp/reg_resp.txt", "/tmp/kc_cookie.txt", "/tmp/kc_admin.txt",
            "/tmp/kc_um.txt", "/tmp/kira_login.txt", "/tmp/kc_reg.txt",
            "/tmp/kc_reg2.txt", "/tmp/work_cookie.txt", "/tmp/n1_waf.txt",
            "/tmp/step_recalibrate.json",
        ]
        for _sf in _stale_files:
            try:
                if _os.path.exists(_sf):
                    _os.remove(_sf)
            except OSError:
                pass

        # ── v4.0.0: Amplifier 통계 시작 알림 ─────────────────────────────
        try:
            from ..core.amplifier import get_amplifier as _get_amp
            _amp_inst = _get_amp(self._lang)
            _print(
                f"[dim]{_s.get('amp_active', '⚡ [AMPLIFIER] CoT+RAG+SelfCorrect+Decompose ACTIVE')}[/dim]"
            )
        except Exception:
            pass

        # ── v4.1.0: ZeroHal Engine 초기화 알림 ────────────────────────────
        _zh_engine = None
        try:
            from ..core.zero_hal_v5 import reset_zero_hal
            _zh_engine = reset_zero_hal(session_target=self._target, lang=self._lang)
            _print(
                f"[dim]{_s.get('zerohal_active', '🛡️ [ZERO-HAL v5] 9-Layer Zero Hallucination ACTIVE')}[/dim]"
            )
        except Exception:
            pass

        # ── v4.2.0: AutoProxy Rotator 초기화 ─────────────────────────────
        _proxy_rotator = None
        try:
            from ..core.proxy_rotator import get_rotator as _get_rotator
            _proxy_rotator = _get_rotator(self._target, prefill=True)
            _proxy_rotator.start()
            _print(
                f"[dim]{_s.get('proxy_active', '🔄 [AUTO-PROXY] IP Block Detector + Free Proxy Pool ACTIVE')}[/dim]"
            )
        except Exception:
            pass

        _print(
            f"\n[bold cyan]{_s.get('orch_ui_started', '🤖 [ORCHESTRATOR] Started')}[/bold cyan]\n"
            f"  target : {self._target}\n"
            f"  goal   : {self._goal}\n"
            f"  steps  : max {self._max_steps}\n"
        )

        while self._step < self._max_steps and not self._stop_evt.is_set():
            self._step += 1
            _print(
                f"\n[bold cyan]{_s.get('orch_ui_step', 'ORCHESTRATOR STEP {step}/{total}').format(step=self._step, total=self._max_steps)}[/bold cyan]"
            )

            # 1. 현재 상태 수집
            board_ctx = board.as_context()
            chain_ctx = chain.summary() if chain.steps() else "(no steps yet)"

            # 2. 결정 요청 (v4.0.0: board_ctx + chain_ctx 를 Amplifier RAG에 전달)
            _print(f"[dim]{_s.get('orch_ui_deciding', '🧠 LLM deciding...')}[/dim]")
            decision_prompt = self._build_decision_prompt(board_ctx, chain_ctx)
            raw_decision = self._call_decision_llm(decision_prompt, board_ctx=board_ctx, chain_ctx=chain_ctx)

            if not raw_decision and not self._stop_evt.is_set():
                _print(f"[yellow]{_s.get('orch_ui_no_decision', '⚠ Decision LLM returned empty — running default scan')}[/yellow]")

            # 3. 파싱
            decision = self._parse_decision(raw_decision)
            action    = decision["action"]
            step_type = decision.get("type", "recon")
            reason    = decision.get("reason", "")
            command   = decision.get("command", "")
            conf      = float(decision.get("confidence", 0.5))
            goal_done = bool(decision.get("goal_achieved", False))
            board_upd = decision.get("update_board", {}) or {}

            icon = _ATTACK_TYPES.get(step_type, "▪️")
            _print(
                f"{icon} [bold]{action}[/bold] (conf={conf:.0%})\n"
                f"   reason: {reason}"
            )

            # 4. HitlGate (danger 여부 판단)
            if self._hitl_enabled and gate.is_dangerous(action):
                allowed = gate.check(action, target=self._target, lang=self._lang)
                if not allowed:
                    _print(f"[yellow]{_s.get('orch_ui_hitl_rejected', '🚫 [HITL] Rejected: {action}').format(action=action)}[/yellow]")
                    self._log.append(
                        OrchStep(self._step, f"[SKIPPED]{action}", step_type,
                                 reason, command, conf, False)
                    )
                    continue

            # 5. Blackboard 업데이트
            for k, v in board_upd.items():
                board.upsert(str(k), v)
                _print(f"[dim]  📌 board ← {k}: {v}[/dim]")

            # 6. AttackChain 기록
            chain.add(step_type, action, detail=reason, target=self._target)

            # 7. 로그 저장
            orch_step = OrchStep(
                self._step, action, step_type, reason, command, conf, goal_done
            )
            self._log.append(orch_step)

            # ── v4.2.0: 명령 실행 전 IP 차단 감지 → 자동 프록시 교체 ────────
            if _proxy_rotator is not None and not self._stop_evt.is_set():
                try:
                    _rotate_res = _proxy_rotator.auto_rotate_if_blocked()
                    if _rotate_res.rotated:
                        _br = _rotate_res.block_result
                        if _rotate_res.new_proxy:
                            _print(
                                f"[bold yellow]"
                                f"{_s.get('proxy_auto_rotated', '🔄 [AUTO-PROXY] IP blocked! Rotated → {url}').format(url=_rotate_res.new_proxy.url)}"
                                f"[/bold yellow]"
                            )
                        else:
                            _print(
                                f"[red]{_s.get('proxy_exhausted', '⚠ [AUTO-PROXY] All proxies exhausted — continuing direct')}[/red]"
                            )
                except Exception:
                    pass

            # 8. 실제 명령 실행
            if command and not self._stop_evt.is_set():
                # ── 타겟 URL 하드 주입 guardrail ──────────────────────────────
                # LLM이 command에 타겟 URL을 빠뜨린 경우 강제로 삽입.
                # AI 에이전트는 이전 대화 컨텍스트를 신뢰할 수 없으므로
                # 매 명령에 타겟이 명시되어야 한다.
                if self._target not in command:
                    _target_prefix = _s.get(
                        "orch_target_prefix",
                        "🎯 [TARGET: {target}]\n",
                    ).format(target=self._target)
                    command = _target_prefix + command
                _cmd_disp = f"{command[:120]}..." if len(command) > 120 else command
                _print(f"[cyan]{_s.get('orch_ui_executing', '▶ Executing: {cmd}').format(cmd=_cmd_disp)}[/cyan]")
                _exec_result = ""
                try:
                    send_fn(command)
                except Exception as e:
                    self._error = str(e)
                    _print(f"[red]{_s.get('orch_ui_exec_error', '❌ Execution error: {err}').format(err=e)}[/red]")

                # ── v4.1.0: ZeroHal FactRegistry에 실행 결과 사전 등록 ────────
                # decision 자체를 exec_output 대용으로 등록 (action/reason에 숫자 포함 시)
                if _zh_engine is not None:
                    _zh_engine.register_exec(raw_decision)

                # ★ v3.5.15: send_fn 완료 후 정지 요청 확인 → 즉시 루프 탈출
                if self._stop_evt.is_set():
                    break

            # ── v4.1.0: decision LLM 응답에 ZeroHal 검증 적용 ────────────────
            if _zh_engine is not None and raw_decision:
                try:
                    _zh_result = _zh_engine.process(raw_decision, exec_output=action)
                    if _zh_result.blocked:
                        _print(
                            f"[red]{_s.get('zerohal_blocked', '⛔ [ZERO-HAL] Blocked: {reason}').format(reason=_zh_result.block_reason)}[/red]"
                        )
                    elif _zh_result.warned and _zh_result.inject_message:
                        _print(
                            f"[yellow][ZERO-HAL WARN] {_zh_result.inject_message[:120]}[/yellow]"
                        )
                except Exception:
                    pass

            # 9. 목표 달성 확인
            if goal_done:
                _print(
                    f"\n[bold green]{_s.get('orch_ui_goal_done', '🎯 [ORCHESTRATOR] Goal achieved! ({step} steps)').format(step=self._step)}[/bold green]"
                )
                break

            # 10. 스텝 간 대기
            # ★ v3.5.15: wait()가 True(이벤트 설정됨) 반환 시 즉시 탈출
            if self._stop_evt.wait(timeout=self._step_delay):
                break  # 정지 요청 → 루프 즉시 종료

        if not goal_done:
            _print(
                f"\n[bold yellow]{_s.get('orch_ui_completed', '⏹ [ORCHESTRATOR] Completed (steps: {step}/{total})').format(step=self._step, total=self._max_steps)}[/bold yellow]"
            )

        # ── v4.2.0: 세션 종료 시 프록시 환경변수 정리 ──────────────────────
        if _proxy_rotator is not None:
            try:
                _stat = _proxy_rotator.status()
                _print(
                    f"[dim]{_s.get('proxy_session_end', '🔄 [AUTO-PROXY] Session ended | rotations={n} pool={p}').format(n=_stat['rotation_count'], p=_stat['pool_size'])}[/dim]"
                )
                _proxy_rotator.clear_env()
                _proxy_rotator.stop()
            except Exception:
                pass

        self._running = False

    # ── 결과 리포트 ────────────────────────────────────────────────────
    def report(self) -> str:
        if not self._log:
            return "(no steps executed)"
        lines = [
            f"[ORCHESTRATOR REPORT]",
            f"  target : {self._target}",
            f"  goal   : {self._goal}",
            f"  steps  : {self._step}",
            "",
            "STEP LOG:",
        ]
        for s in self._log:
            lines.append(f"  {s.short()}")
            if s.reason:
                lines.append(f"      ↳ {s.reason}")
        return "\n".join(lines)


# ── 글로벌 싱글톤 ───────────────────────────────────────────────────────
_global_orch: Optional[OrchestratorEngine] = None


def global_orchestrator() -> Optional[OrchestratorEngine]:
    return _global_orch


def set_global_orchestrator(eng: Optional[OrchestratorEngine]) -> None:
    global _global_orch
    _global_orch = eng
