"""
bingo Intelligence Engine — v6.2.159
SubAgent 위임 / Task Graph / Self-Reflection

- SubAgent: 독립 서브작업을 병렬 스레드로 위임
- TaskGraph: 미션 시작 전 공격 단계 사전 계획
- SelfReflection: N루프마다 에이전트 자기 평가 주입
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


def _nl(ko: str, zh: str, en: str) -> str:
    """현재 설정 언어에 맞는 문자열 반환."""
    try:
        from ..i18n import get_lang
        lang = get_lang()
    except Exception:
        lang = "en"
    return {"ko": ko, "zh": zh, "en": en}.get(lang, en)


# ─────────────────────────────────────────────────────────────────────────────
# 1. SubAgent 위임 패턴
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SubAgentResult:
    task_id: str
    task_desc: str
    status: str = "pending"   # pending / running / done / error
    output: str = ""
    error: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0


class SubAgentPool:
    """독립 서브작업을 백그라운드 스레드로 실행하는 경량 풀."""

    MAX_WORKERS = 4

    def __init__(self) -> None:
        self._results: dict[str, SubAgentResult] = {}
        self._lock = threading.Lock()
        self._active = 0

    def spawn(
        self,
        task_id: str,
        task_desc: str,
        fn: Callable[[], str],
    ) -> bool:
        """서브에이전트 작업 생성. 최대 MAX_WORKERS 동시 실행."""
        with self._lock:
            if self._active >= self.MAX_WORKERS:
                return False
            self._active += 1
            res = SubAgentResult(
                task_id=task_id,
                task_desc=task_desc,
                status="running",
                started_at=time.time(),
            )
            self._results[task_id] = res

        def _run():
            try:
                out = fn()
                with self._lock:
                    res.output = str(out)[:4096]
                    res.status = "done"
                    res.finished_at = time.time()
                    self._active -= 1
            except Exception as exc:
                with self._lock:
                    res.error = str(exc)[:512]
                    res.status = "error"
                    res.finished_at = time.time()
                    self._active -= 1

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return True

    def collect_done(self) -> list[SubAgentResult]:
        """완료된 서브작업 결과를 수집하고 목록에서 제거."""
        with self._lock:
            done = [r for r in self._results.values() if r.status in ("done", "error")]
            for r in done:
                del self._results[r.task_id]
        return done

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._results.values() if r.status == "running")

    def build_status_msg(self) -> str:
        """현재 실행 중인 서브작업 상태 요약 (AI 컨텍스트 주입용)."""
        with self._lock:
            running = [r for r in self._results.values() if r.status == "running"]
        if not running:
            return ""
        label = _nl("🔀 서브에이전트 실행중", "🔀 子代理运行中", "🔀 SubAgents running")
        lines = [label + f" ({len(running)}):"]
        for r in running:
            elapsed = int(time.time() - r.started_at)
            lines.append(f"  [{r.task_id}] {r.task_desc} (+{elapsed}s)")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Task Graph 미션 계획기
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TaskNode:
    node_id: str
    description: str
    depends_on: list[str] = field(default_factory=list)
    status: str = "pending"   # pending / running / done / skipped
    result_summary: str = ""


class TaskGraph:
    """
    미션 시작 시 목표를 단계별 그래프로 분해.
    의존성 있는 노드는 선행 노드 완료 후 실행.
    """

    # 표준 침투 단계 템플릿
    _TEMPLATE_WEB = [
        ("recon",     "Recon: subdomains, ports, tech stack, robots.txt",     []),
        ("crawl",     "Crawl: page/endpoint/param discovery",                  ["recon"]),
        ("sqli",      "SQL Injection: detect & extract DB",                    ["crawl"]),
        ("xss",       "XSS: reflected/stored/DOM injection",                   ["crawl"]),
        ("ssrf",      "SSRF/LFI: internal resource access",                    ["crawl"]),
        ("auth",      "Auth: login bruteforce, JWT bypass, session hijack",    ["crawl"]),
        ("exploit",   "Exploit: RCE, webshell, privilege escalation",          ["sqli", "auth"]),
        ("report",    "Report: consolidate & format findings",                  ["exploit", "xss", "ssrf"]),
    ]

    def __init__(self) -> None:
        self._nodes: dict[str, TaskNode] = {}

    def load_template(self, mission: str) -> None:
        """미션 키워드 분석 후 적절한 템플릿 로드."""
        self._nodes.clear()
        tmpl = self._TEMPLATE_WEB
        mission_lower = mission.lower()
        for node_id, desc, deps in tmpl:
            # 미션에 명시적으로 언급된 항목은 우선순위 높게 표시
            priority = "★ " if any(
                kw in mission_lower for kw in (node_id, node_id[:3])
            ) else ""
            self._nodes[node_id] = TaskNode(
                node_id=node_id,
                description=priority + desc,
                depends_on=deps,
            )

    def ready_nodes(self) -> list[TaskNode]:
        """현재 실행 가능한 노드 반환 (의존성 충족 + pending)."""
        done_ids = {n.node_id for n in self._nodes.values() if n.status == "done"}
        return [
            n for n in self._nodes.values()
            if n.status == "pending" and all(d in done_ids for d in n.depends_on)
        ]

    def mark_done(self, node_id: str, summary: str = "") -> None:
        if node_id in self._nodes:
            self._nodes[node_id].status = "done"
            self._nodes[node_id].result_summary = summary[:256]

    def mark_running(self, node_id: str) -> None:
        if node_id in self._nodes:
            self._nodes[node_id].status = "running"

    def skip(self, node_id: str) -> None:
        if node_id in self._nodes:
            self._nodes[node_id].status = "skipped"

    def is_complete(self) -> bool:
        return all(
            n.status in ("done", "skipped")
            for n in self._nodes.values()
        )

    def render(self) -> str:
        """에이전트 컨텍스트에 주입할 Task Graph 요약."""
        if not self._nodes:
            return ""
        icon = {"pending": "⬜", "running": "🔄", "done": "✅", "skipped": "⏭️"}
        label = _nl("📋 미션 Task Graph", "📋 任务图谱", "📋 Mission Task Graph")
        lines = [label + ":"]
        for n in self._nodes.values():
            ic = icon.get(n.status, "⬜")
            dep_str = f" ← {','.join(n.depends_on)}" if n.depends_on else ""
            lines.append(f"  {ic} [{n.node_id}] {n.description}{dep_str}")
            if n.result_summary:
                lines.append(f"       └─ {n.result_summary}")
        return "\n".join(lines)

    def next_hint(self) -> str:
        """다음 실행해야 할 작업 힌트."""
        ready = self.ready_nodes()
        if not ready:
            return ""
        targets = ", ".join(f"[{n.node_id}]" for n in ready[:3])
        return _nl(
            f"▶ 다음 단계: {targets}",
            f"▶ 下一步: {targets}",
            f"▶ Next steps: {targets}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Self-Reflection 주기적 자기평가
# ─────────────────────────────────────────────────────────────────────────────

class SelfReflector:
    """
    N루프마다 에이전트 히스토리를 분석해 자기평가 메시지를 생성.
    AI가 전략을 재검토하고 우선순위를 재설정하도록 유도.
    """

    REFLECT_EVERY = 15  # 몇 루프마다 반성 주입

    def __init__(self) -> None:
        self._last_reflect_loop: int = 0
        self._reflect_count: int = 0

    def should_reflect(self, loop_count: int) -> bool:
        if loop_count < 5:
            return False
        if (loop_count - self._last_reflect_loop) >= self.REFLECT_EVERY:
            return True
        return False

    def build_reflection_prompt(
        self,
        loop_count: int,
        found_vulns: list[str],
        failed_tools: list[str],
        target: str,
        task_graph: Optional[TaskGraph] = None,
    ) -> str:
        self._last_reflect_loop = loop_count
        self._reflect_count += 1

        found_str = ", ".join(found_vulns[:10]) if found_vulns else _nl("없음", "无", "none")
        failed_str = ", ".join(failed_tools[:10]) if failed_tools else _nl("없음", "无", "none")
        graph_str = task_graph.render() if task_graph else ""

        ko = (
            f"🧠 [SELF_REFLECTION #{self._reflect_count}] Loop {loop_count} 도달 — 전략 재평가\n"
            f"타겟: {target}\n"
            f"발견된 취약점: {found_str}\n"
            f"실패한 도구: {failed_str}\n"
            + (f"\n{graph_str}\n" if graph_str else "")
            + "질문:\n"
            "1) 현재까지 목표 달성도는?\n"
            "2) 낭비 중인 시도가 있는가?\n"
            "3) 놓친 공격 벡터는?\n"
            "4) 지금 당장 바꿔야 할 전략은?\n"
            "간략히 답하고 즉시 다음 최우선 작업을 실행하라."
        )
        zh = (
            f"🧠 [SELF_REFLECTION #{self._reflect_count}] 第{loop_count}循环 — 战略重评估\n"
            f"目标: {target}\n"
            f"已发现漏洞: {found_str}\n"
            f"失败工具: {failed_str}\n"
            + (f"\n{graph_str}\n" if graph_str else "")
            + "问题:\n"
            "1) 目标完成度如何？\n"
            "2) 是否有浪费的尝试？\n"
            "3) 是否遗漏了攻击向量？\n"
            "4) 现在需要立即改变的策略？\n"
            "简要回答后立即执行下一最高优先级任务。"
        )
        en = (
            f"🧠 [SELF_REFLECTION #{self._reflect_count}] Loop {loop_count} reached — strategy re-evaluation\n"
            f"Target: {target}\n"
            f"Vulns found: {found_str}\n"
            f"Failed tools: {failed_str}\n"
            + (f"\n{graph_str}\n" if graph_str else "")
            + "Questions:\n"
            "1) How much of the objective has been achieved?\n"
            "2) Are there wasted attempts?\n"
            "3) Any missed attack vectors?\n"
            "4) What strategy must change right now?\n"
            "Answer briefly and immediately execute the next top-priority task."
        )
        try:
            from ..i18n import get_lang
            lang = get_lang()
        except Exception:
            lang = "en"
        return {"ko": ko, "zh": zh, "en": en}.get(lang, en)

    def extract_found_vulns(self, history_texts: list[str]) -> list[str]:
        """히스토리에서 발견된 취약점 키워드 추출."""
        import re
        pattern = re.compile(
            r"\b(SQL[i]?|XSS|SSRF|LFI|RFI|SSTI|CMDi|RCE|IDOR|CSRF|XXE|"
            r"Open[\s_]?Redirect|CORS|JWT|OAuth|NoSQL|LDAP|Deserializ|"
            r"SQLiNJECTION|WebShell|Upload|Smuggl)\b",
            re.IGNORECASE,
        )
        found: dict[str, int] = {}
        for txt in history_texts[-30:]:
            for m in pattern.findall(txt):
                key = m.upper().replace(" ", "_").replace("-", "_")
                found[key] = found.get(key, 0) + 1
        return sorted(found, key=lambda k: -found[k])

    def extract_failed_tools(self, history_texts: list[str]) -> list[str]:
        """히스토리에서 실패한 도구 추출."""
        import re
        failed: set[str] = set()
        fail_pat = re.compile(r"(?:FAILED|ERROR|BLOCKED|WAF|403|timeout)[^\n]*?(\w+_\w+)", re.IGNORECASE)
        for txt in history_texts[-20:]:
            for m in fail_pat.findall(txt):
                if len(m) > 3:
                    failed.add(m[:30])
        return list(failed)[:8]
