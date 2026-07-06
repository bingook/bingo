"""
Red Team Session — 단계별 결과를 저장하고 중단/재시작 지원
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class PhaseResult:
    phase: str
    status: str        # running / done / skipped / error
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    findings: list[dict] = field(default_factory=list)
    raw_output: str = ""
    ai_summary: str = ""

    def finish(self, findings: list[dict], summary: str = ""):
        self.status = "done"
        self.finished_at = time.time()
        self.findings = findings
        self.ai_summary = summary

    @property
    def duration(self) -> float:
        end = self.finished_at or time.time()
        return end - self.started_at


@dataclass
class RedTeamSession:
    target: str
    session_id: str = field(default_factory=lambda: str(int(time.time())))
    started_at: float = field(default_factory=time.time)
    phases: dict[str, PhaseResult] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # 세션 파일 경로
    @property
    def _path(self) -> Path:
        from pathlib import Path
        import sys, os
        if sys.platform == "win32":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        elif sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
        else:
            base = Path.home() / ".config"
        d = base / "bingo" / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{self.session_id}.json"

    def save(self):
        data = {
            "target": self.target,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "metadata": self.metadata,
            "phases": {k: asdict(v) for k, v in self.phases.items()},
        }
        self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, session_id: str) -> "RedTeamSession | None":
        import sys, os
        if sys.platform == "win32":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        elif sys.platform == "darwin":
            base = Path.home() / "Library" / "Application Support"
        else:
            base = Path.home() / ".config"
        p = base / "bingo" / "sessions" / f"{session_id}.json"
        if not p.exists():
            return None
        data = json.loads(p.read_text())
        s = cls(target=data["target"], session_id=data["session_id"],
                started_at=data["started_at"], metadata=data.get("metadata", {}))
        for k, v in data.get("phases", {}).items():
            pr = PhaseResult(**v)
            s.phases[k] = pr
        return s

    def add_finding(self, phase: str, finding_type_or_dict, finding_dict=None, severity=None):
        """
        finding을 세션에 추가. 절대 차단 없음.
        2가지 호출 형식 모두 지원:
          - add_finding(phase, finding_dict)                          ← 2인자 형식
          - add_finding(phase, type_name, data_dict, severity)        ← 4인자 형식
        evidence_level 자동 라벨링:
          - curl/url/status_code 있으면 → VERIFIED
          - 없으면 → LIKELY
        """
        # 4인자 형식: (phase, type_name, data_dict, severity) → dict로 병합
        if finding_dict is not None:
            base = dict(finding_dict) if isinstance(finding_dict, dict) else {}
            base["type"] = str(finding_type_or_dict)
            if severity is not None:
                base["severity"] = str(severity)
            finding = base
        else:
            # 2인자 형식: finding_type_or_dict 자체가 dict
            finding = finding_type_or_dict if isinstance(finding_type_or_dict, dict) else {"raw": finding_type_or_dict}

        if phase not in self.phases:
            self.phases[phase] = PhaseResult(phase=phase, status="running")

        # evidence_level이 없는 기존 finding 호환 — 라벨만 추가
        if "evidence_level" not in finding:
            has_strong_evidence = bool(
                finding.get("curl")
                or (finding.get("status_code", 0) > 0 and finding.get("url"))
                or finding.get("evidence_hash")
            )
            has_some_evidence = bool(
                finding.get("url")
                or finding.get("detail")
                or finding.get("description")
            )
            if has_strong_evidence:
                finding["evidence_level"] = "VERIFIED"
            elif has_some_evidence:
                finding["evidence_level"] = "LIKELY"
            else:
                finding["evidence_level"] = "INFERRED"

        self.phases[phase].findings.append(finding)

    def all_findings(self) -> list[dict]:
        result = []
        for pr in self.phases.values():
            for f in pr.findings:
                f["phase"] = pr.phase
                result.append(f)
        return result

    def get_phase_findings(self, phase: str) -> list[dict]:
        """특정 phase의 findings만 반환. phase가 없으면 빈 리스트."""
        pr = self.phases.get(phase)
        if pr is None:
            return []
        return list(pr.findings)

    def summary_table(self) -> str:
        lines = [f"Target: {self.target}", ""]
        for ph, pr in self.phases.items():
            icon = {"done": "✓", "running": "►", "error": "✗", "skipped": "–"}.get(pr.status, "?")
            lines.append(f"  {icon} {ph:12s} {len(pr.findings):3d} findings  ({pr.duration:.0f}s)")
        lines.append(f"\nTotal findings: {len(self.all_findings())}")
        return "\n".join(lines)
