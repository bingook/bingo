"""
AI Agent — 각 단계 결과를 AI에게 전달하고 다음 행동을 자율 결정
AI가 "다음 단계에서 뭘 해야 하나"를 판단
"""
from __future__ import annotations
import json
from typing import Any

from ..skills.engine import SkillEngine


SYSTEM_PROMPT = """당신은 전문 모의침투 테스터(Red Team)입니다.
대상 시스템에 대한 단계별 스캔 결과를 분석하고, 다음 행동을 결정합니다.
CyberSecurity-Skills 39개 모듈(PTES 표준)을 기준으로 체계적으로 접근합니다.

응답 형식:
1. 현재 단계 결과 요약 (2-3줄)
2. 발견된 위험 취약점 (최대 5개)
3. 다음 권장 행동 (구체적 명령어 포함)
4. 보고서 요약용 1줄 요약
"""


class RedTeamAgent:
    """AI 기반 자율 판단 에이전트"""

    def __init__(self, model_config=None, skill_engine: SkillEngine | None = None):
        self.model_config = model_config
        self.skills = skill_engine or SkillEngine()

    def analyze_phase(
        self,
        phase: str,
        findings: list[dict],
        target: str,
        context: str = "",
    ) -> dict[str, Any]:
        """단계 결과 AI 분석 — next_action 반환"""
        if not self.model_config:
            return self._rule_based_decision(phase, findings)

        prompt = self._build_prompt(phase, findings, target, context)
        try:
            response = self._call_ai(prompt)
            return {
                "summary": response,
                "next_phases": self._extract_next_phases(phase, findings),
                "skip_reason": "",
            }
        except Exception as e:
            return self._rule_based_decision(phase, findings)

    def _rule_based_decision(self, phase: str, findings: list[dict]) -> dict:
        """AI 없이도 규칙 기반으로 다음 단계 결정"""
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]

        summary_lines = [f"Phase {phase} 결과: {len(findings)}개 발견"]
        if critical:
            summary_lines.append(f"⚠️  위험: {', '.join(f['title'][:40] for f in critical[:3])}")
        if high:
            summary_lines.append(f"🔴 높음: {', '.join(f['title'][:40] for f in high[:3])}")

        next_phases = self._extract_next_phases(phase, findings)

        return {
            "summary": "\n".join(summary_lines),
            "next_phases": next_phases,
            "skip_reason": "no_findings" if not findings else "",
        }

    def _extract_next_phases(self, current_phase: str, findings: list[dict]) -> list[str]:
        """현재 단계와 발견 내용에 따라 다음 단계 결정"""
        types = {f.get("type") for f in findings}

        if current_phase == "recon":
            return ["scan"]

        if current_phase == "scan":
            nexts = ["exploit"]
            if not findings:
                nexts = ["report"]  # 취약점 없으면 바로 보고서
            return nexts

        if current_phase == "exploit":
            nexts = ["report"]
            if "default_cred" in types or "data_extraction" in types:
                nexts = ["privesc", "report"]
            return nexts

        if current_phase == "privesc":
            return ["post", "report"]

        return ["report"]

    def _build_prompt(
        self, phase: str, findings: list[dict], target: str, context: str
    ) -> str:
        skill_ctx = self.skills.get_phase_prompt(phase)
        findings_str = json.dumps(findings[:10], ensure_ascii=False, indent=2)

        return f"""{SYSTEM_PROMPT}

타겟: {target}
현재 단계: {phase}

=== 스킬 참조 ===
{skill_ctx}

=== 스캔 결과 ===
{findings_str}

=== 추가 컨텍스트 ===
{context}

위 결과를 분석하고 다음 행동을 제안하세요."""

    def _call_ai(self, prompt: str) -> str:
        """설정된 AI 모델 호출"""
        from ..models.registry import ModelRegistry
        model = ModelRegistry.build(self.model_config)
        full_response = ""
        for chunk in model.chat_stream([{"role": "user", "content": prompt}]):
            full_response += chunk.text
        return full_response
