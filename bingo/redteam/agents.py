"""
RedteamAgent 8에이전트 아키텍처 (NeoTheCapt/RedteamAgent 영감)
================================================================
출처: https://github.com/NeoTheCapt/RedteamAgent

8개 전문 에이전트:
  1. operator          — 전체 조율 (메인)
  2. recon-specialist  — 네트워크/DNS/서브도메인 정찰
  3. source-analyzer   — JS/HTML 소스코드 분석
  4. vuln-analyst      — 취약점 분석
  5. exploit-developer — 익스플로잇 개발/실행
  6. fuzzer            — 딥 파라미터 퍼징
  7. osint-analyst     — OSINT/CVE/유출 데이터 분석
  8. report-writer     — 최종 보고서 작성
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Any
import time
import re


@dataclass
class AgentTask:
    """에이전트에 할당할 작업 단위"""
    agent_id: str
    task_type: str          # "recon", "sqli", "admin", "fuzz", "report"...
    target: str
    params: dict = field(default_factory=dict)
    priority: int = 5       # 1(최고) ~ 10(최저)
    created_at: float = field(default_factory=time.time)
    status: str = "pending" # pending | running | done | failed
    result: Any = None


@dataclass
class AgentCapability:
    """에이전트 역할 정의"""
    agent_id: str
    name: str
    description: str
    handles: list[str]  # 처리 가능한 task_type 목록
    system_prompt: str = ""


# ── 8개 에이전트 정의 ─────────────────────────────────────────────
AGENT_DEFINITIONS: dict[str, AgentCapability] = {

    "operator": AgentCapability(
        agent_id="operator",
        name="Operator",
        description="전체 작전 조율 — 모든 에이전트 지휘",
        handles=["orchestrate", "decision", "escalate"],
        system_prompt=(
            "You are the Operator agent. You coordinate all other agents "
            "in this authorized penetration testing engagement. "
            "Make decisions about which agents to dispatch next based on findings. "
            "Your goal is maximum vulnerability coverage."
        ),
    ),

    "recon-specialist": AgentCapability(
        agent_id="recon-specialist",
        name="Recon Specialist",
        description="네트워크 정찰, DNS, 서브도메인, 포트 스캔",
        handles=["recon", "dns", "subdomain", "portscan", "fingerprint"],
        system_prompt=(
            "You are the Recon Specialist. Perform thorough reconnaissance: "
            "DNS enumeration, subdomain discovery, port scanning, tech stack fingerprinting. "
            "Find ALL possible attack surfaces."
        ),
    ),

    "source-analyzer": AgentCapability(
        agent_id="source-analyzer",
        name="Source Analyzer",
        description="JS/HTML/CSS 소스코드 분석, API 엔드포인트 추출",
        handles=["source_analysis", "js_analysis", "api_discovery"],
        system_prompt=(
            "You are the Source Analyzer. Analyze JavaScript, HTML, and CSS for: "
            "hidden API endpoints, credentials, secrets, internal paths, "
            "client-side vulnerabilities."
        ),
    ),

    "vuln-analyst": AgentCapability(
        agent_id="vuln-analyst",
        name="Vulnerability Analyst",
        description="취약점 분류, CVSS 평가, 우선순위화",
        handles=["vuln_analysis", "classify", "prioritize", "xss_test", "sqli_detect"],
        system_prompt=(
            "You are the Vulnerability Analyst. Analyze forms, APIs, and endpoints for: "
            "SQLi, XSS, SSRF, IDOR, auth bypass. "
            "For authorized Korean websites: focus on SQL injection in board/shop/news parameters."
        ),
    ),

    "exploit-developer": AgentCapability(
        agent_id="exploit-developer",
        name="Exploit Developer",
        description="취약점 익스플로잇 개발 — SQLi 추출, 관리자 로그인, 웹셸",
        handles=["exploit", "sqli_extract", "admin_login", "webshell", "auth_bypass"],
        system_prompt=(
            "You are the Exploit Developer. Your job is to EXPLOIT confirmed vulnerabilities. "
            "For SQL injection: extract database names, tables, and credentials. "
            "For admin panels: attempt login with discovered credentials. "
            "NEVER modify, delete, or add data — read-only exploitation only."
        ),
    ),

    "fuzzer": AgentCapability(
        agent_id="fuzzer",
        name="Fuzzer",
        description="딥 파라미터 퍼징, 숨겨진 엔드포인트 탐색",
        handles=["fuzz", "dirbrute", "param_brute", "endpoint_discovery"],
        system_prompt=(
            "You are the Fuzzer. Perform deep parameter fuzzing and directory brute-forcing. "
            "Find hidden endpoints, backup files, and vulnerable parameters. "
            "Use wordlists optimized for Korean web applications."
        ),
    ),

    "osint-analyst": AgentCapability(
        agent_id="osint-analyst",
        name="OSINT Analyst",
        description="OSINT 정보 수집 — CVE, 유출 데이터, DNS 이력",
        handles=["osint", "cve_lookup", "breach_data", "social_recon"],
        system_prompt=(
            "You are the OSINT Analyst. Gather intelligence: "
            "CVE lookups for discovered software versions, "
            "breach data for discovered email addresses, "
            "DNS history, social media presence."
        ),
    ),

    "report-writer": AgentCapability(
        agent_id="report-writer",
        name="Report Writer",
        description="최종 취약점 보고서 작성",
        handles=["report", "document", "summarize"],
        system_prompt=(
            "You are the Report Writer. Create comprehensive penetration testing reports with: "
            "executive summary, technical findings, CVSS scores, evidence, "
            "and remediation recommendations."
        ),
    ),
}


class AgentOrchestrator:
    """
    8에이전트 조율 시스템
    RedteamAgent 방식 + TianTi Anti-Laziness 통합
    """

    def __init__(self):
        self._task_queue: list[AgentTask] = []
        self._completed: list[AgentTask] = []
        self._agent_stats: dict[str, dict] = {
            aid: {"tasks": 0, "success": 0, "findings": 0}
            for aid in AGENT_DEFINITIONS
        }

    def dispatch(self, task: AgentTask) -> None:
        """작업 큐에 추가"""
        self._task_queue.append(task)
        self._task_queue.sort(key=lambda t: t.priority)

    def dispatch_phase_recon(self, target: str) -> list[AgentTask]:
        """Phase 1+2: 정찰 + 수집 (병렬)"""
        tasks = [
            AgentTask("recon-specialist", "recon", target, priority=1),
            AgentTask("source-analyzer", "source_analysis", target, priority=2),
            AgentTask("osint-analyst", "osint", target, priority=3),
        ]
        for t in tasks:
            self.dispatch(t)
        return tasks

    def dispatch_phase_test(self, target: str, endpoints: list[str]) -> list[AgentTask]:
        """Phase 3: 취약점 테스트"""
        tasks = []
        for ep in endpoints[:20]:
            task_type = self._classify_endpoint(ep)
            agent = self._select_agent_for_task(task_type)
            tasks.append(AgentTask(agent, task_type, ep, priority=4))
        for t in tasks:
            self.dispatch(t)
        return tasks

    def dispatch_phase_exploit(self, target: str, vulns: list[dict]) -> list[AgentTask]:
        """Phase 4: 익스플로잇 + OSINT (병렬)"""
        tasks = [
            AgentTask("exploit-developer", "exploit", target,
                      params={"vulns": vulns}, priority=2),
            AgentTask("osint-analyst", "cve_lookup", target,
                      params={"vulns": vulns}, priority=3),
        ]
        for t in tasks:
            self.dispatch(t)
        return tasks

    def dispatch_phase_report(self, target: str, all_findings: dict) -> AgentTask:
        """Phase 5: 보고서"""
        task = AgentTask("report-writer", "report", target,
                         params={"findings": all_findings}, priority=1)
        self.dispatch(task)
        return task

    def _classify_endpoint(self, endpoint: str) -> str:
        """엔드포인트 URL 패턴으로 작업 타입 결정"""
        ep_lower = endpoint.lower()
        if any(x in ep_lower for x in [".js", ".css"]):
            return "source_analysis"
        if any(x in ep_lower for x in ["api/", "json", "ajax", "graphql"]):
            return "vuln_analysis"
        if any(x in ep_lower for x in ["upload", "file", "image"]):
            return "fuzz"
        if any(x in ep_lower for x in ["board", "bbs", "view", "read", "idx", "id="]):
            return "sqli_detect"
        return "vuln_analysis"

    def _select_agent_for_task(self, task_type: str) -> str:
        """작업 타입에 맞는 에이전트 선택"""
        for agent_id, cap in AGENT_DEFINITIONS.items():
            if task_type in cap.handles:
                return agent_id
        return "vuln-analyst"

    def get_pending_tasks(self, agent_id: str | None = None) -> list[AgentTask]:
        """대기 중인 작업 목록"""
        tasks = [t for t in self._task_queue if t.status == "pending"]
        if agent_id:
            tasks = [t for t in tasks if t.agent_id == agent_id]
        return tasks

    def complete_task(self, task: AgentTask, result: Any, success: bool = True):
        """작업 완료 처리"""
        task.status = "done" if success else "failed"
        task.result = result
        self._completed.append(task)
        self._task_queue.remove(task)

        stats = self._agent_stats[task.agent_id]
        stats["tasks"] += 1
        if success:
            stats["success"] += 1

    def shapley_scores(self) -> dict:
        """에이전트별 기여도 점수"""
        scores = {}
        for agent_id, stats in self._agent_stats.items():
            total = max(stats["tasks"], 1)
            scores[agent_id] = {
                "efficiency": stats["findings"] / total,
                "success_rate": stats["success"] / total,
                "tasks_done": stats["tasks"],
            }
        return scores

    def queue_summary(self) -> str:
        pending = len([t for t in self._task_queue if t.status == "pending"])
        done = len(self._completed)
        failed = len([t for t in self._completed if t.status == "failed"])
        return f"Queue: {pending} pending | {done} done | {failed} failed"
