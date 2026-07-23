"""
bingo Rollback System — 실행 전 스냅샷 저장, /undo로 복원.

동작:
  - 에이전트 루프 시작 전 agent_state + history 자동 스냅샷
  - /undo 명령으로 최대 20단계 복원
  - 스냅샷은 Bingo workspace snapshots directory 에 저장
"""
from __future__ import annotations
import json, time, shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

from .local_state import workspace_state_dir


_SNAPSHOTS_DIR = workspace_state_dir() / "snapshots"
_MAX_SNAPSHOTS = 20


@dataclass
class Snapshot:
    ts:           float
    label:        str
    agent_state:  dict
    history_len:  int          # 히스토리 메시지 수 (복원 시 참고)
    extra:        dict = field(default_factory=dict)

    @property
    def timestamp_str(self) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")

    def to_dict(self) -> dict:
        return {
            "ts":          self.ts,
            "label":       self.label,
            "agent_state": self.agent_state,
            "history_len": self.history_len,
            "extra":       self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        return cls(
            ts=d["ts"], label=d["label"],
            agent_state=d["agent_state"],
            history_len=d.get("history_len", 0),
            extra=d.get("extra", {}),
        )


class RollbackManager:
    """
    Git-style state snapshot rollback manager.
    agent_state + conversation history를 실행 전 자동 저장.
    """

    def __init__(self):
        try:
            _SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass  # 권한 없어도 메모리 기반으로 동작
        self._snapshots: list[Snapshot] = self._load_all()

    # ── 스냅샷 저장 ───────────────────────────────────────────────
    def save(self, agent_state: dict, history_len: int, label: str = "") -> Snapshot:
        """현재 상태를 스냅샷으로 저장. 루프 시작 전 호출."""
        import copy
        snap = Snapshot(
            ts=time.time(),
            label=label or f"Loop #{len(self._snapshots)+1}",
            agent_state=copy.deepcopy(agent_state),
            history_len=history_len,
        )
        self._snapshots.append(snap)

        # 최대 개수 유지
        if len(self._snapshots) > _MAX_SNAPSHOTS:
            self._snapshots = self._snapshots[-_MAX_SNAPSHOTS:]

        self._persist(snap)
        return snap

    # ── 롤백 ──────────────────────────────────────────────────────
    def undo(self, steps: int = 1) -> Snapshot | None:
        """N단계 전 스냅샷으로 롤백. 복원된 스냅샷 반환."""
        if not self._snapshots:
            return None
        idx = max(0, len(self._snapshots) - steps - 1)
        snap = self._snapshots[idx]
        # 복원 후 그 이후 스냅샷 제거
        self._snapshots = self._snapshots[:idx + 1]
        return snap

    def latest(self) -> Snapshot | None:
        return self._snapshots[-1] if self._snapshots else None

    def list_snapshots(self) -> list[Snapshot]:
        return list(reversed(self._snapshots[-10:]))  # 최신 10개

    # ── 영속성 ────────────────────────────────────────────────────
    def _persist(self, snap: Snapshot) -> None:
        try:
            fname = _SNAPSHOTS_DIR / f"snap_{int(snap.ts*1000)}.json"
            fname.write_text(
                json.dumps(snap.to_dict(), ensure_ascii=False, indent=2)
            )
            # 오래된 파일 정리
            files = sorted(_SNAPSHOTS_DIR.glob("snap_*.json"))
            for old in files[:-_MAX_SNAPSHOTS]:
                old.unlink(missing_ok=True)
        except Exception:
            pass

    def _load_all(self) -> list[Snapshot]:
        snaps = []
        try:
            for f in sorted(_SNAPSHOTS_DIR.glob("snap_*.json")):
                try:
                    d = json.loads(f.read_text())
                    snaps.append(Snapshot.from_dict(d))
                except Exception:
                    pass
        except Exception:
            pass
        return snaps[-_MAX_SNAPSHOTS:]
