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
        self._path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

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

    def add_finding(self, phase: str, finding: dict):
        if phase not in self.phases:
            self.phases[phase] = PhaseResult(phase=phase, status="running")
        self.phases[phase].findings.append(finding)

    def all_findings(self) -> list[dict]:
        result = []
        for pr in self.phases.values():
            for f in pr.findings:
                f["phase"] = pr.phase
                result.append(f)
        return result

    def summary_table(self) -> str:
        lines = [f"Target: {self.target}", ""]
        for ph, pr in self.phases.items():
            icon = {"done": "✓", "running": "►", "error": "✗", "skipped": "–"}.get(pr.status, "?")
            lines.append(f"  {icon} {ph:12s} {len(pr.findings):3d} findings  ({pr.duration:.0f}s)")
        lines.append(f"\nTotal findings: {len(self.all_findings())}")
        return "\n".join(lines)
