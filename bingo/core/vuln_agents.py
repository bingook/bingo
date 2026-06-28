"""
VulnAgentDispatcher — 취약점 유형별 전담 에이전트 분업 (v3.2.82)

Shannon에서 착안:
- 각 에이전트가 특정 취약점 유형에 집중 (SQLi / XSS / SSRF / Auth / RCE / IDOR)
- 화이트박스 힌트를 바탕으로 우선순위 산정
- 테스트 결과를 Proof-by-exploitation 방식으로 분류
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── 취약점 유형 정의 ──────────────────────────────────────────────────
VULN_TYPES = {
    "sqli":  "SQL Injection",
    "xss":   "Cross-Site Scripting",
    "ssrf":  "Server-Side Request Forgery",
    "auth":  "Authentication Bypass",
    "rce":   "Remote Code Execution",
    "idor":  "Insecure Direct Object Reference",
    "lfi":   "Local File Inclusion",
    "csrf":  "Cross-Site Request Forgery",
}

# ── 에이전트 시스템 프롬프트 (역할별) ────────────────────────────────
AGENT_PROMPTS = {
    "sqli": (
        "You are the SQL Injection specialist agent. "
        "Your ONLY job is to find and exploit SQL injection vulnerabilities. "
        "Focus on: error-based, union-based, blind boolean, time-based, out-of-band. "
        "Use sqlmap payloads if manual detection succeeds. "
        "Report ONLY confirmed exploits with full curl PoC."
    ),
    "xss": (
        "You are the XSS specialist agent. "
        "Your ONLY job is to find reflected, stored, and DOM-based XSS. "
        "Test all input fields, headers, and URL parameters. "
        "Craft context-aware payloads to bypass WAF/filters. "
        "Report ONLY with working JS execution proof."
    ),
    "ssrf": (
        "You are the SSRF specialist agent. "
        "Your ONLY job is to find Server-Side Request Forgery vectors. "
        "Test URL parameters, webhooks, file fetch features, and import functions. "
        "Try cloud metadata endpoints (169.254.169.254) and internal IP ranges. "
        "Report ONLY confirmed internal responses."
    ),
    "auth": (
        "You are the Authentication & Authorization specialist agent. "
        "Your ONLY job is to bypass login mechanisms and access controls. "
        "Test: default credentials, SQLi in login, JWT abuse, session fixation, "
        "IDOR, privilege escalation, forced browsing. "
        "Report ONLY with screenshot/response proof."
    ),
    "rce": (
        "You are the Remote Code Execution specialist agent. "
        "Your ONLY job is to find command injection and code execution vectors. "
        "Test: OS command injection, SSTI, deserialization, file upload to RCE. "
        "Report ONLY with confirmed command output in response."
    ),
    "idor": (
        "You are the IDOR/Access Control specialist agent. "
        "Your ONLY job is to find Insecure Direct Object References. "
        "Test: ID enumeration, UUID guessing, object parameter tampering. "
        "Report ONLY with proof of unauthorized data access."
    ),
}


@dataclass
class VulnProof:
    """Proof-by-exploitation 증거 레코드."""
    vuln_type: str
    endpoint: str
    param: str
    payload: str
    evidence: str           # 응답 스니펫 or 실행 결과
    severity: str           # critical / high / medium / low
    curl_poc: str = ""
    confirmed: bool = True  # 실제 PoC 확인된 것만 True


@dataclass
class AgentPlan:
    """에이전트 실행 계획."""
    agents: list[str] = field(default_factory=list)    # 실행할 에이전트 유형
    priority: list[str] = field(default_factory=list)  # 우선순위 순서
    context_injection: str = ""                         # 화이트박스 컨텍스트
    hints_by_type: dict = field(default_factory=dict)  # 유형별 힌트 목록


class VulnAgentDispatcher:
    """화이트박스 힌트 → 에이전트 실행 계획 생성."""

    # 기본 에이전트 실행 순서 (화이트박스 없을 때)
    DEFAULT_ORDER = ["sqli", "auth", "xss", "ssrf", "idor", "rce"]

    def build_plan(
        self,
        whitebox_result=None,
        user_specified: Optional[list[str]] = None,
    ) -> AgentPlan:
        """화이트박스 결과를 바탕으로 에이전트 실행 계획 수립."""
        plan = AgentPlan()

        if whitebox_result and whitebox_result.hints:
            # 힌트 기반 우선순위 계산
            type_counts: dict[str, int] = {}
            hints_by_type: dict[str, list] = {}
            for h in whitebox_result.hints:
                vt = h.vuln_type
                type_counts[vt] = type_counts.get(vt, 0) + 1
                hints_by_type.setdefault(vt, []).append(h)

            # 발견된 힌트 순으로 정렬
            sorted_types = sorted(type_counts, key=lambda x: -type_counts[x])
            # 나머지 DEFAULT_ORDER에서 추가
            for vt in self.DEFAULT_ORDER:
                if vt not in sorted_types:
                    sorted_types.append(vt)

            plan.priority = sorted_types
            plan.agents = sorted_types
            plan.hints_by_type = hints_by_type
            plan.context_injection = whitebox_result.to_context_injection()
        else:
            plan.priority = self.DEFAULT_ORDER[:]
            plan.agents = self.DEFAULT_ORDER[:]

        # 사용자 지정 에이전트가 있으면 그것만
        if user_specified:
            normalized = [u.lower().strip() for u in user_specified]
            plan.agents = [a for a in normalized if a in VULN_TYPES]
            plan.priority = plan.agents

        return plan

    def get_agent_system_prompt(self, vuln_type: str, base_system: str) -> str:
        """기존 시스템 프롬프트에 에이전트 특화 역할을 주입."""
        agent_role = AGENT_PROMPTS.get(vuln_type, "")
        if not agent_role:
            return base_system
        return (
            f"[SPECIALIZED AGENT ROLE]\n{agent_role}\n\n"
            f"[GENERAL SYSTEM INSTRUCTIONS]\n{base_system}"
        )

    def classify_proof(
        self,
        response_text: str,
        vuln_type: str,
        endpoint: str,
        param: str,
        payload: str,
    ) -> Optional[VulnProof]:
        """
        AI 응답에서 취약점 증거를 추출.
        '확인됨'이라는 표시가 있을 때만 VulnProof 반환.
        """
        import re

        confirmed_markers = [
            r"(?i)취약점\s*(확인|발견|검증)",
            r"(?i)(confirmed|verified|exploited|vulnerable)",
            r"(?i)(DB\s*(접근|추출)|credentials?\s*(leaked|extracted))",
            r"(?i)(RCE|코드\s*실행)\s*(성공|confirmed)",
            r"(?i)PoC.*curl|curl.*PoC",
            r"(?i)HTTP\s*\d{3}.*?sql.*?error",
        ]
        is_confirmed = any(re.search(m, response_text) for m in confirmed_markers)

        if not is_confirmed:
            return None

        # severity 추정
        severity = "medium"
        if vuln_type in ("rce", "sqli"):
            severity = "critical"
        elif vuln_type in ("auth", "ssrf"):
            severity = "high"

        # curl PoC 추출
        curl_match = re.search(r'(curl\s+.+?)(?:\n\n|\Z)', response_text, re.DOTALL)
        curl_poc = curl_match.group(1).strip() if curl_match else ""

        evidence_match = re.search(
            r'(?:응답|Response|Output|결과)[:\s]+(.{20,300})',
            response_text
        )
        evidence = evidence_match.group(1).strip() if evidence_match else response_text[:200]

        return VulnProof(
            vuln_type=vuln_type,
            endpoint=endpoint,
            param=param,
            payload=payload,
            evidence=evidence,
            severity=severity,
            curl_poc=curl_poc,
            confirmed=True,
        )


class ProofReport:
    """Proof-by-exploitation 기반 최종 리포트 생성."""

    def __init__(self):
        self.proofs: list[VulnProof] = []

    def add(self, proof: VulnProof) -> None:
        self.proofs.append(proof)

    def generate_markdown(self, target: str) -> str:
        if not self.proofs:
            return f"# {target} — Penetration Test Report\n\n취약점 없음 또는 PoC 미확인.\n"

        lines = [
            f"# {target} — Proof-by-Exploitation Report",
            f"\n**확인된 취약점 총 {len(self.proofs)}개**\n",
            "| # | 유형 | 엔드포인트 | 심각도 | 파라미터 |",
            "|---|------|-----------|--------|---------|",
        ]
        for i, p in enumerate(self.proofs, 1):
            lines.append(f"| {i} | {p.vuln_type.upper()} | `{p.endpoint}` | **{p.severity}** | `{p.param}` |")

        for i, p in enumerate(self.proofs, 1):
            lines.extend([
                f"\n---\n## #{i} {VULN_TYPES.get(p.vuln_type, p.vuln_type)} — {p.severity.upper()}",
                f"**엔드포인트:** `{p.endpoint}`",
                f"**파라미터:** `{p.param}`",
                f"**페이로드:** `{p.payload}`",
                f"\n**증거:**\n```\n{p.evidence}\n```",
            ])
            if p.curl_poc:
                lines.extend([f"\n**PoC:**\n```bash\n{p.curl_poc}\n```"])

        lines.append(
            "\n---\n> *본 보고서는 실제 익스플로잇이 확인된 취약점만 포함합니다.*\n"
            "> *(Proof-by-Exploitation — Bingo v3.2.82)*"
        )
        return "\n".join(lines)
