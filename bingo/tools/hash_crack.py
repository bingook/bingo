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
import subprocess
import sys
import time
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
            return hashlib.new("md4", pwd.encode("utf-16-le")).hexdigest().upper()
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


def extract_hashes_from_text(text: str) -> list[str]:
    """
    텍스트에서 해시값 자동 추출
    AI 응답 / 덤프 결과 / 마크다운 테이블 등에서 해시를 파싱
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
    ]
    found = []
    for pat in patterns:
        matches = re.findall(pat, text)
        # 마크다운 테이블 구분자(|)로 잘린 경우 정리
        cleaned = [m.strip("| \t\n") for m in matches]
        found.extend(cleaned)
    return list(dict.fromkeys(found))  # 중복 제거, 순서 유지
