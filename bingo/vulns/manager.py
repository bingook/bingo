"""
bingo/vulns/manager.py — 취약점 관리 (SQLite CRUD)

발견된 취약점을 로컬 SQLite DB에 저장·조회·통계.
Bingo workspace state directory를 기본 위치로 사용.
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ..core.local_state import workspace_state_dir

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Vuln:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    target: str = ""
    severity: str = "medium"    # critical / high / medium / low / info
    status: str = "open"        # open / confirmed / fixed / false_positive
    description: str = ""
    poc: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def severity_order(self) -> int:
        return _SEVERITY_ORDER.get(self.severity.lower(), 99)


def _db_path() -> Path:
    p = workspace_state_dir() / "vulns.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


class VulnManager:
    """
    취약점 관리자.
    사용법:
        vm = VulnManager()
        vid = vm.add("SQLi in /api/login", "https://target.com", "critical", poc="' OR 1=1--")
        vm.list()   → List[Vuln]
        vm.update(vid, status="confirmed")
        vm.remove(vid)
        vm.stats()  → dict
    """

    def __init__(self, db: Optional[str] = None) -> None:
        self._db = db or str(_db_path())
        self._ensure_schema()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulns (
                    id          TEXT PRIMARY KEY,
                    title       TEXT NOT NULL,
                    target      TEXT DEFAULT '',
                    severity    TEXT DEFAULT 'medium',
                    status      TEXT DEFAULT 'open',
                    description TEXT DEFAULT '',
                    poc         TEXT DEFAULT '',
                    created_at  REAL,
                    updated_at  REAL
                )
            """)

    # ── CRUD ──────────────────────────────────────────────────────────
    def add(
        self,
        title: str,
        target: str = "",
        severity: str = "medium",
        description: str = "",
        poc: str = "",
    ) -> str:
        v = Vuln(
            title=title, target=target, severity=severity,
            description=description, poc=poc,
        )
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)",
                (v.id, v.title, v.target, v.severity, v.status,
                 v.description, v.poc, v.created_at, v.updated_at),
            )
        return v.id

    def get(self, vid: str) -> Optional[Vuln]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM vulns WHERE id=?", (vid,)).fetchone()
        return self._row_to_vuln(row) if row else None

    def list(
        self,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Vuln]:
        q = "SELECT * FROM vulns WHERE 1=1"
        params: list = []
        if target:
            q += " AND target LIKE ?"
            params.append(f"%{target}%")
        if severity:
            q += " AND severity=?"
            params.append(severity.lower())
        if status:
            q += " AND status=?"
            params.append(status.lower())
        q += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(q, params).fetchall()
        vulns = [self._row_to_vuln(r) for r in rows]
        return sorted(vulns, key=lambda v: v.severity_order())

    def update(self, vid: str, **kwargs) -> bool:
        allowed = {"title", "target", "severity", "status", "description", "poc"}
        sets = {k: v for k, v in kwargs.items() if k in allowed}
        if not sets:
            return False
        sets["updated_at"] = time.time()
        cols = ", ".join(f"{k}=?" for k in sets)
        vals = list(sets.values()) + [vid]
        with self._conn() as conn:
            cur = conn.execute(f"UPDATE vulns SET {cols} WHERE id=?", vals)
        return cur.rowcount > 0

    def remove(self, vid: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM vulns WHERE id=?", (vid,))
        return cur.rowcount > 0

    def clear(self) -> int:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM vulns")
        return cur.rowcount

    # ── 통계 ──────────────────────────────────────────────────────────
    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
            by_sev = {
                r[0]: r[1]
                for r in conn.execute(
                    "SELECT severity, COUNT(*) FROM vulns GROUP BY severity"
                ).fetchall()
            }
            by_status = {
                r[0]: r[1]
                for r in conn.execute(
                    "SELECT status, COUNT(*) FROM vulns GROUP BY status"
                ).fetchall()
            }
        return {"total": total, "by_severity": by_sev, "by_status": by_status}

    # ── 내부 유틸 ─────────────────────────────────────────────────────
    @staticmethod
    def _row_to_vuln(row: sqlite3.Row) -> Vuln:
        return Vuln(
            id=row["id"],
            title=row["title"],
            target=row["target"],
            severity=row["severity"],
            status=row["status"],
            description=row["description"],
            poc=row["poc"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
