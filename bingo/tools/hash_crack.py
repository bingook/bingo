"""
hash_crack.py — 오프라인 비밀번호 해시 크랙 도구

지원 해시 타입:
  bcrypt ($2y$, $2b$, $2a$)
  MD5 (32자 hex / $1$)
  SHA-1 (40자 hex)
  SHA-256 (64자 hex)
  SHA-512 ($6$)
  NTLM (32자 hex, 대문자)
  MySQL (41자 hex, *로 시작)
"""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import sys
import time


# ── 순수 Python MD4 구현 ──────────────────────────────────────────────
# Python 3.12 + macOS OpenSSL 3.x 에서 MD4가 제거됨 → 직접 구현
def _md4(data: bytes) -> bytes:
    """RFC 1320 MD4 — OpenSSL 없이 동작하는 순수 Python 구현."""
    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _lr(v, n): return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[i:i+64]))
        a, b, c, d = A, B, C, D

        for k in [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]:
            a = _lr(a + _f(b,c,d) + X[k], [3,7,11,19][k%4])
            a, b, c, d = d, a, b, c

        for k in [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]:
            a = _lr(a + _g(b,c,d) + X[k] + 0x5A827999, [3,5,9,13][k%4])
            a, b, c, d = d, a, b, c

        for k in [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]:
            a = _lr(a + _h(b,c,d) + X[k] + 0x6ED9EBA1, [3,9,11,15][k%4])
            a, b, c, d = d, a, b, c

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack("<4I", A, B, C, D)


def _ntlm_hash(password: str) -> str:
    """NTLM 해시 — MD4(UTF-16-LE). OpenSSL 의존 없이 동작."""
    try:
        # 먼저 OpenSSL 방식 시도 (Linux 등 지원 환경)
        return hashlib.new("md4", password.encode("utf-16-le")).hexdigest().upper()
    except (ValueError, Exception):
        # macOS Python 3.12+ 폴백: 순수 Python MD4
        return _md4(password.encode("utf-16-le")).hex().upper()
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# ── 기본 워드리스트 경로 (환경에 따라 자동 탐색) ─────────────────────────
_WORDLIST_CANDIDATES = [
    Path("/usr/share/wordlists/rockyou.txt"),
    Path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
    Path.home() / "wordlists" / "rockyou.txt",
    Path.home() / "Downloads" / "rockyou.txt",
    Path("/opt/rockyou.txt"),
]

# 기본 내장 패스워드 (워드리스트 없을 때 폴백)
_BUILTIN_PASSWORDS = [
    "password", "123456", "password123", "admin", "admin123", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master", "sunshine",
    "princess", "shadow", "superman", "michael", "football", "iloveyou",
    "1234567890", "abc123", "test", "test123", "root", "toor",
    "pass", "pass123", "000000", "111111", "123123", "654321",
    "password1", "password!", "P@ssw0rd", "Admin@123", "admin@123",
    "dndnloan", "dndnloan123", "loan123", "company", "company123",
]


@dataclass
class HashInfo:
    raw: str
    hash_type: str
    algorithm: str          # hashcat mode or 'bcrypt'
    hashcat_mode: int | None = None


@dataclass
class CrackResult:
    hash_raw: str
    hash_type: str
    cracked: bool
    plaintext: str | None = None
    method: str = ""
    elapsed: float = 0.0
    error: str = ""


def detect_hash_type(h: str) -> HashInfo:
    h = h.strip()
    if re.match(r"^\$2[yba]\$\d{2}\$.{53}$", h):
        return HashInfo(h, "bcrypt", "bcrypt", 3200)
    if re.match(r"^\$1\$.+\$.+$", h):
        return HashInfo(h, "md5crypt", "md5crypt", 500)
    if re.match(r"^\$6\$.+\$.+$", h):
        return HashInfo(h, "sha512crypt", "sha512crypt", 1800)
    if re.match(r"^\*[0-9A-Fa-f]{40}$", h):
        return HashInfo(h, "mysql41", "mysql41", 300)
    if re.match(r"^[0-9A-Fa-f]{16}$", h):
        # MySQL OLD_PASSWORD() — 16-char hex (MySQL 3.x / 4.0 스타일)
        return HashInfo(h, "mysql_old", "mysql_old_password", None)
    if re.match(r"^[0-9A-Fa-f]{32}$", h):
        # NTLM은 대문자, MD5는 소문자 경향
        if h == h.upper():
            return HashInfo(h, "ntlm", "ntlm", 1000)
        return HashInfo(h, "md5", "md5", 0)
    if re.match(r"^[0-9A-Fa-f]{40}$", h):
        return HashInfo(h, "sha1", "sha1", 100)
    if re.match(r"^[0-9A-Fa-f]{64}$", h):
        return HashInfo(h, "sha256", "sha256", 1400)
    if re.match(r"^[0-9A-Fa-f]{128}$", h):
        return HashInfo(h, "sha512", "sha512", 1700)
    return HashInfo(h, "unknown", "unknown", None)


def _find_wordlist() -> Path | None:
    for p in _WORDLIST_CANDIDATES:
        if p.exists():
            return p
    return None


def _crack_mysql41(hash_info: HashInfo, wordlist_path: Path | None,
                   log: Callable[[str], None]) -> CrackResult:
    """MySQL 4.1 크랙 — *SHA1(SHA1(password)) 형식"""
    start = time.time()
    # 앞의 * 제거 후 대문자 비교
    target = hash_info.raw.lstrip("*").upper()

    def compute(pwd: str) -> str:
        inner = hashlib.sha1(pwd.encode()).digest()
        return hashlib.sha1(inner).hexdigest().upper()

    for pwd in _BUILTIN_PASSWORDS:
        if compute(pwd) == target:
            return CrackResult(hash_info.raw, "mysql41", True,
                               pwd, "builtin_list", time.time() - start)

    if wordlist_path:
        log(f"  [crack] Loading wordlist for mysql41: {wordlist_path} ...")
        try:
            with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
                for i, line in enumerate(f):
                    pwd = line.rstrip("\n")
                    if compute(pwd) == target:
                        return CrackResult(hash_info.raw, "mysql41", True,
                                           pwd, "wordlist", time.time() - start)
                    if i % 500_000 == 0 and i > 0:
                        log(f"  [crack] mysql41 {i:,} tried...")
        except Exception as e:
            return CrackResult(hash_info.raw, "mysql41", False,
                               error=str(e), elapsed=time.time() - start)

    return CrackResult(hash_info.raw, "mysql41", False,
                       method="exhausted", elapsed=time.time() - start)


def _crack_mysql_old(hash_info: HashInfo, wordlist_path: Path | None,
                     log: Callable[[str], None]) -> CrackResult:
    """MySQL OLD_PASSWORD() — 16-char hash (MySQL 3.x / 4.0 알고리즘)"""
    start = time.time()
    target = hash_info.raw.lower()

    def _mysql_old_hash(pwd: str) -> str:
        # MySQL 3.x OLD_PASSWORD 알고리즘
        nr, nr2, add = 1345345333, 305419889, 7
        for c in pwd:
            if c == " " or c == "\t":
                continue
            tmp = ord(c)
            nr ^= (((nr & 63) + add) * tmp) + ((nr << 8) & 0xFFFFFFFF)
            nr2 += ((nr2 << 8) & 0xFFFFFFFF) ^ nr
            add += tmp
        r1 = nr & 0x7FFFFFFF
        r2 = nr2 & 0x7FFFFFFF
        return f"{r1:08x}{r2:08x}"

    for pwd in _BUILTIN_PASSWORDS:
        if _mysql_old_hash(pwd) == target:
            return CrackResult(hash_info.raw, "mysql_old", True,
                               pwd, "builtin_list", time.time() - start)

    if wordlist_path:
        log(f"  [crack] Loading wordlist for mysql_old: {wordlist_path} ...")
        try:
            with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
                for i, line in enumerate(f):
                    pwd = line.rstrip("\n")
                    if _mysql_old_hash(pwd) == target:
                        return CrackResult(hash_info.raw, "mysql_old", True,
                                           pwd, "wordlist", time.time() - start)
                    if i % 500_000 == 0 and i > 0:
                        log(f"  [crack] mysql_old {i:,} tried...")
        except Exception as e:
            return CrackResult(hash_info.raw, "mysql_old", False,
                               error=str(e), elapsed=time.time() - start)

    return CrackResult(hash_info.raw, "mysql_old", False,
                       method="exhausted", elapsed=time.time() - start)


def _crack_simple(hash_info: HashInfo, wordlist_path: Path | None,
                  log: Callable[[str], None]) -> CrackResult:
    """Python 레벨 크랙 (MD5 / SHA-1 / SHA-256 / SHA-512 / NTLM)"""
    start = time.time()
    algo = hash_info.algorithm
    target = hash_info.raw.lower()

    def compute(pwd: str) -> str:
        p = pwd.encode()
        if algo == "md5":
            return hashlib.md5(p).hexdigest()
        if algo == "sha1":
            return hashlib.sha1(p).hexdigest()
        if algo == "sha256":
            return hashlib.sha256(p).hexdigest()
        if algo == "sha512":
            return hashlib.sha512(p).hexdigest()
        if algo == "ntlm":
            return _ntlm_hash(pwd)
        return ""

    # 내장 패스워드 먼저
    for pwd in _BUILTIN_PASSWORDS:
        if compute(pwd) == target:
            return CrackResult(hash_info.raw, hash_info.hash_type, True,
                               pwd, "builtin_list", time.time() - start)

    # wordlist
    if wordlist_path:
        log(f"  [crack] Loading wordlist: {wordlist_path} ...")
        try:
            with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
                for i, line in enumerate(f):
                    pwd = line.rstrip("\n")
                    if compute(pwd) == target:
                        return CrackResult(hash_info.raw, hash_info.hash_type, True,
                                           pwd, "wordlist", time.time() - start)
                    if i % 500_000 == 0 and i > 0:
                        log(f"  [crack] Trying {i:,} ...")
        except Exception as e:
            return CrackResult(hash_info.raw, hash_info.hash_type, False,
                               error=str(e), elapsed=time.time() - start)

    return CrackResult(hash_info.raw, hash_info.hash_type, False,
                       method="wordlist_exhausted", elapsed=time.time() - start)


def _crack_bcrypt(hash_info: HashInfo, wordlist_path: Path | None,
                  log: Callable[[str], None]) -> CrackResult:
    """bcrypt 크랙 — hashcat 우선, 없으면 Python bcrypt 폴백"""
    start = time.time()

    # hashcat 시도
    hashcat_bin = _find_binary(["hashcat"])
    if hashcat_bin and wordlist_path:
        log(f"  [crack] Starting bcrypt crack with hashcat (may be slow)...")
        tmp_hash = Path("/tmp/bingo_hash.txt")
        tmp_hash.write_text(hash_info.raw + "\n")
        cmd = [
            hashcat_bin, "-m", "3200", "-a", "0",
            str(tmp_hash), str(wordlist_path),
            "--quiet", "--potfile-disable",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            # hashcat output: hash:plaintext
            for line in result.stdout.splitlines():
                if ":" in line and line.startswith("$2"):
                    plaintext = line.split(":", 1)[1]
                    return CrackResult(hash_info.raw, "bcrypt", True,
                                       plaintext, "hashcat", time.time() - start)
        except subprocess.TimeoutExpired:
            log("  [crack] hashcat timeout — falling back to Python")
        except Exception as e:
            log(f"  [crack] hashcat error: {e}")

    # Python bcrypt fallback
    try:
        import bcrypt as _bcrypt
        passwords = _BUILTIN_PASSWORDS[:]
        if wordlist_path:
            try:
                with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
                    passwords += [l.rstrip("\n") for _, l in zip(range(100_000), f)]
            except Exception:
                pass
        log(f"  [crack] bcrypt Python crack ({len(passwords):,} candidates)...")
        encoded = hash_info.raw.encode()
        for i, pwd in enumerate(passwords):
            if _bcrypt.checkpw(pwd.encode(), encoded):
                return CrackResult(hash_info.raw, "bcrypt", True,
                                   pwd, "python_bcrypt", time.time() - start)
            if i % 1000 == 0 and i > 0:
                log(f"  [crack] bcrypt {i:,} tried...")
    except ImportError:
        log("  [crack] bcrypt module not found — pip install bcrypt")

    return CrackResult(hash_info.raw, "bcrypt", False,
                       method="exhausted", elapsed=time.time() - start)


def _crack_with_john(hash_info: HashInfo, wordlist_path: Path | None,
                     log: Callable[[str], None]) -> CrackResult | None:
    """john the ripper로 크랙 시도"""
    john_bin = _find_binary(["john", "john-the-ripper"])
    if not john_bin:
        return None
    tmp_hash = Path("/tmp/bingo_john.txt")
    tmp_hash.write_text(hash_info.raw + "\n")
    cmd = [john_bin, str(tmp_hash)]
    if wordlist_path:
        cmd += [f"--wordlist={wordlist_path}"]
    try:
        start = time.time()
        log(f"  [crack] Running john...")
        subprocess.run(cmd, capture_output=True, timeout=60)
        # john --show
        show = subprocess.run([john_bin, "--show", str(tmp_hash)],
                              capture_output=True, text=True, timeout=10)
        for line in show.stdout.splitlines():
            if ":" in line and not line.startswith("0 password"):
                parts = line.split(":")
                if len(parts) >= 2:
                    return CrackResult(hash_info.raw, hash_info.hash_type, True,
                                       parts[1], "john", time.time() - start)
    except Exception as e:
        log(f"  [crack] john error: {e}")
    return None


def _find_binary(names: list[str]) -> str | None:
    import shutil
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


class HashCracker:
    """
    해시 크랙 엔진 — 자동 탐지 + 최적 방법 선택
    """

    def __init__(self, wordlist: str | None = None,
                 on_progress: Callable[[str], None] | None = None):
        self.log = on_progress or (lambda s: None)
        if wordlist:
            self.wordlist = Path(wordlist)
        else:
            self.wordlist = _find_wordlist()

    def crack(self, hash_value: str) -> CrackResult:
        """단일 해시 크랙"""
        info = detect_hash_type(hash_value.strip())
        self.log(f"  [crack] Hash type: {info.hash_type}")

        if self.wordlist:
            self.log(f"  [crack] Wordlist: {self.wordlist}")
        else:
            self.log("  [crack] No wordlist — using built-in passwords only")

        # john 먼저 시도 (빠름)
        john_result = _crack_with_john(info, self.wordlist, self.log)
        if john_result and john_result.cracked:
            return john_result

        # 타입별 크랙
        if info.hash_type == "bcrypt":
            return _crack_bcrypt(info, self.wordlist, self.log)
        elif info.hash_type == "mysql41":
            return _crack_mysql41(info, self.wordlist, self.log)
        elif info.hash_type == "mysql_old":
            return _crack_mysql_old(info, self.wordlist, self.log)
        elif info.hash_type in ("md5", "sha1", "sha256", "sha512", "ntlm", "md5crypt"):
            return _crack_simple(info, self.wordlist, self.log)
        else:
            self.log(f"  [crack] Unsupported hash type: {info.hash_type}")
            return CrackResult(hash_value, info.hash_type, False,
                               error="unsupported hash type")

    def crack_many(self, hashes: list[str]) -> list[CrackResult]:
        """여러 해시 일괄 크랙"""
        results = []
        for i, h in enumerate(hashes, 1):
            self.log(f"\n  [{i}/{len(hashes)}] {h[:30]}...")
            results.append(self.crack(h))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# 컨텍스트 기반 오탐 필터 (error code / tracking ID 등 false positive 제거)
# Context-aware false positive filter for hex strings misidentified as hashes
# 基于上下文的误报过滤（错误码/追踪ID等被误识别为哈希）
# ─────────────────────────────────────────────────────────────────────────────

# 주변 컨텍스트에 이 단어가 있으면 해시가 아닌 오류코드/추적ID로 판단
_FALSE_POSITIVE_CONTEXT_KEYWORDS = re.compile(
    r"error[\s_\-]?(?:code|id|num|number|track|ref|message)?"
    r"|오류[\s]?(?:코드|번호|추적|id)?"
    r"|tracking[\s_\-]?(?:id|code|number)?"
    r"|transaction[\s_\-]?(?:id|code)?"
    r"|reference[\s_\-]?(?:id|code|number)?"
    r"|request[\s_\-]?(?:id|code)?"
    r"|session[\s_\-]?(?:token|id)?"
    r"|correlation[\s_\-]?id"
    r"|trace[\s_\-]?(?:id|code)?"
    r"|incident[\s_\-]?(?:id|number)?"
    r"|ticket[\s_\-]?(?:id|number)?"
    r"|ref(?:erence)?[\s_\-]?no"
    r"|에러\s*(?:코드|번호)?"
    r"|추적\s*(?:코드|번호|ID)?"
    r"|오류\s*코드"
    r"|错误\s*(?:代码|编号|码)?"
    r"|跟踪\s*(?:ID|编号)?"
    r"|事务\s*(?:ID|编号)?",
    re.IGNORECASE,
)

# HTTP 4xx / 5xx 상태코드 컨텍스트
_HTTP_ERROR_STATUS_RE = re.compile(
    r"\b(?:4[0-9]{2}|5[0-9]{2})\s+(?:error|page|response|status|Bad|Not Found|Forbidden|"
    r"Internal|Service|Unauthorized|페이지|응답|오류)",
    re.IGNORECASE,
)

# 구체적인 에러코드 패턴: 전형적인 에러코드는 대/소문자 혼합 불규칙 + 특정 접두사 없음
# 실제 패스워드 해시: 소문자만(MD5/SHA) 또는 대문자만(NTLM) 일관성이 있음
def _is_error_context(candidate: str, surrounding: str) -> bool:
    """
    주어진 hex 문자열이 오류코드/추적ID일 가능성을 판단.

    True  → 오탐 (해시 크랙 건너뜀)
    False → 실제 해시일 가능성 있음 (크랙 진행)

    EN: Returns True if the candidate hex string is likely an error/tracking code.
    ZH: 如果候选字符串可能是错误码/追踪ID，返回True。
    """
    ctx = surrounding.lower()

    # 1. 주변에 오류코드/추적ID 키워드 존재
    if _FALSE_POSITIVE_CONTEXT_KEYWORDS.search(ctx):
        return True

    # 2. HTTP 4xx/5xx 페이지 컨텍스트
    if _HTTP_ERROR_STATUS_RE.search(surrounding):
        return True

    # 3. 32자 hex의 경우 대소문자 혼합(mixed-case)이면 에러코드일 가능성↑
    #    실제 MD5는 소문자만, NTLM은 대문자만 (크래킹 툴 출력 기준)
    if len(candidate) == 32:
        has_lower = any(c.islower() for c in candidate if c.isalpha())
        has_upper = any(c.isupper() for c in candidate if c.isalpha())
        if has_lower and has_upper:
            # 혼합 대소문자 → 에러코드 의심. 추가 키워드 없어도 오탐 처리
            # 단, DB dump / hash= 패턴이 명시적으로 있으면 허용
            _hash_signals = re.compile(
                r"password[\s_]?hash|hash[\s_]?:?\s*$|pwd[\s_]?hash|"
                r"ntlm[\s_]?hash|md5[\s_]?:|sha[\s_]?:|"
                r"해시[\s:]|비밀번호[\s]?해시|密码[\s]?哈希|哈希值",
                re.IGNORECASE,
            )
            if not _hash_signals.search(surrounding):
                return True

    # 4. 특정 접두/접미 패턴: "code=XXXX", "id=XXXX", "ref=XXXX"
    _code_prefix = re.compile(
        r"(?:code|id|ref|num|no|err|error|trace|tx|txn|token|key|guid|uuid)"
        r"[\s=:_\-]+$",
        re.IGNORECASE,
    )
    prefix_window = surrounding[-40:] if len(surrounding) >= 40 else surrounding
    if _code_prefix.search(prefix_window):
        return True

    # 5. UTF-16LE 인코딩된 문자열 오탐 필터
    #    예) 25004D0065006D006200650072002500 → 2바이트마다 '00' 반복 = UTF-16LE 텍스트
    #    NTLM 해시와 길이(32) + 대문자 패턴이 동일하지만 실제 크래킹 불가능
    if len(candidate) == 32:
        # 짝수 위치(0,2,4...) 또는 홀수 위치(1,3,5...) 바이트가 '00'이면 UTF-16LE
        pairs = [candidate[i:i+4] for i in range(0, 32, 4)]  # 4자 단위 (2바이트)
        low_bytes  = [p[2:4] for p in pairs]  # 각 2바이트 쌍의 하위 바이트
        high_bytes = [p[0:2] for p in pairs]  # 각 2바이트 쌍의 상위 바이트
        if all(b == "00" for b in low_bytes) or all(b == "00" for b in high_bytes):
            return True

    return False


def extract_hashes_from_text(text: str, strict: bool = True) -> list[str]:
    """
    텍스트에서 해시값 자동 추출 (컨텍스트 기반 오탐 필터 포함)

    strict=True (기본): 오류코드/추적ID 등 비밀번호 해시가 아닌 것 자동 제거.
    strict=False     : 기존 패턴 매칭만 (오탐 필터 건너뜀).

    EN: Extract password hashes from text with context-aware false positive filtering.
        Error codes, tracking IDs, HTTP error page codes are automatically excluded.
    ZH: 从文本中提取密码哈希，包含基于上下文的误报过滤。
        错误码、追踪ID、HTTP错误页面的十六进制字符串会被自动排除。
    """
    patterns = [
        # bcrypt: $2y$10$<53chars> — {50,60}으로 유연하게 처리 (마크다운 테이블 잘림 대비)
        r"\$2[yba]\$\d{2}\$[./A-Za-z0-9]{50,60}",
        r"\$1\$[^$\s|]+\$[./A-Za-z0-9]+",           # md5crypt
        r"\$6\$[^$\s|]+\$[./A-Za-z0-9]+",           # sha512crypt
        r"\*[0-9A-Fa-f]{40}",                        # MySQL41
        r"(?<![0-9a-fA-F])[0-9a-f]{128}(?![0-9a-fA-F])",   # SHA-512
        r"(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])",    # SHA-256
        r"(?<![0-9a-fA-F])[0-9a-f]{40}(?![0-9a-fA-F])",    # SHA-1
        r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])", # MD5 / NTLM
        # MySQL OLD_PASSWORD(): 16-char hex (컨텍스트 기반 — passwd= 앞뒤 등)
        r"(?<![0-9a-fA-F])[0-9a-fA-F]{16}(?![0-9a-fA-F])", # OLD_PASSWORD (idx 8)
    ]

    # $2y$…, $1$…, $6$…, *MySQL 패턴은 구조가 뚜렷해서 컨텍스트 필터 불필요
    _STRUCTURED_PATTERNS = {0, 1, 2, 3}

    # OLD_PASSWORD 16-char: 컨텍스트 키워드 필요 (오탐 방지)
    _OLD_PW_CONTEXT_RE = re.compile(
        r'(?:old_password|passwd|password|hash|pwd|pw)\s*[:=]', re.IGNORECASE
    )

    # v6.2.17: 파일명 캐시 버스팅 해시 탐지 정규식
    # 예: main.a39888f755d305910a0945e236ac1fc6.js, chunk.abc123.min.css
    _FILENAME_CACHE_RE = re.compile(
        r'[./\-_][0-9a-fA-F]{32,64}\.[a-zA-Z]{2,5}(?:[?&#\s"\')|]|$)',
    )

    found = []
    for idx, pat in enumerate(patterns):
        for m in re.finditer(pat, text):
            candidate = m.group(0).strip("| \t\n")
            if not candidate:
                continue

            # v6.2.17: 파일명 캐시 버스팅 해시 제외 (main.HASH.js, chunk.HASH.min.css 등)
            # 해시 앞뒤 컨텍스트로 파일명 패턴 감지
            pre_char_idx = max(0, m.start() - 1)
            pre_char = text[pre_char_idx] if m.start() > 0 else ''
            post_window = text[m.end():min(len(text), m.end() + 12)]
            # .HASH.ext 패턴: 앞에 '.' 이고 뒤에 '.확장자' 있으면 캐시 버스팅 해시
            if pre_char in './-_' and re.match(r'\.[a-zA-Z]{2,5}(?:[?&#\s"\')|]|$)', post_window):
                continue  # 파일명 캐시 버스팅 해시 → 오탐

            # OLD_PASSWORD 16-char(idx 8): passwd=/hash= 같은 컨텍스트 키워드 필수
            if idx == 8:
                ctx_start = max(0, m.start() - 60)
                ctx_end   = min(len(text), m.end() + 20)
                context_window = text[ctx_start:ctx_end]
                if not _OLD_PW_CONTEXT_RE.search(context_window):
                    continue  # 컨텍스트 없으면 오탐 — 건너뜀

            # 구조적 패턴(bcrypt/mysql 등)은 필터 건너뜀
            if strict and idx not in _STRUCTURED_PATTERNS:
                start = max(0, m.start() - 120)
                end   = min(len(text), m.end() + 80)
                surrounding = text[start : m.start()] + text[m.end() : end]
                if _is_error_context(candidate, surrounding):
                    continue  # 오탐 → 건너뜀

            if candidate not in found:
                found.append(candidate)

    return found
