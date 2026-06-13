"""
hash_lookup.py — 온라인 해시 평문 조회

조회 순서:
  1. CrackStation (공개 API, 가장 빠름)
  2. hashes.com
  3. md5decrypt.net
  4. nivaura.com / cmd5.org (HTML 파싱)
"""

from __future__ import annotations

import re
import time
import urllib.parse
import urllib.request
import urllib.error
import json
from dataclasses import dataclass, field
from typing import Callable


TIMEOUT = 8  # 초

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/html,*/*",
}


@dataclass
class LookupResult:
    hash_raw: str
    found: bool
    plaintext: str | None = None
    source: str = ""
    error: str = ""


def _get(url: str, data: bytes | None = None, extra_headers: dict | None = None) -> str:
    req = urllib.request.Request(url, data=data, headers=_HEADERS)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="ignore")


# ── 1. CrackStation ───────────────────────────────────────────────────────────
def _crackstation(hashes: list[str]) -> dict[str, str]:
    """
    공개 API: https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
    POST https://crackstation.net/crack.js
    """
    body = urllib.parse.urlencode({
        "hash": "\n".join(hashes),
        "submit": "Crack Hashes",
    }).encode()
    try:
        html = _get("https://crackstation.net/crack.js", data=body,
                    extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        results: dict[str, str] = {}
        # 응답 형식: JSON array [{hash, type, result}]
        try:
            data = json.loads(html)
            for item in data:
                if item.get("cracked"):
                    results[item["hash"].lower()] = item["result"]
            return results
        except json.JSONDecodeError:
            pass
        # 폴백: HTML 파싱
        for h in hashes:
            pattern = rf"{re.escape(h)}.*?<td[^>]*>(.*?)</td>"
            m = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if m:
                plain = re.sub(r"<[^>]+>", "", m.group(1)).strip()
                if plain and plain.lower() not in ("not found", ""):
                    results[h.lower()] = plain
        return results
    except Exception:
        return {}


# ── 2. hashes.com ─────────────────────────────────────────────────────────────
def _hashes_com(hash_val: str) -> str | None:
    try:
        url = f"https://hashes.com/en/decrypt/hash"
        body = urllib.parse.urlencode({"hashes[]": hash_val, "submit": "submit"}).encode()
        html = _get(url, data=body,
                    extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        # "HASH:PLAINTEXT" 형태
        m = re.search(r"([0-9a-fA-F\$./]{20,}):([^\s<\"]{1,64})", html)
        if m:
            return m.group(2)
        # JSON 응답 형태
        try:
            data = json.loads(html)
            if isinstance(data, list) and data:
                return data[0].get("plaintext") or data[0].get("result")
        except Exception:
            pass
    except Exception:
        pass
    return None


# ── 3. md5decrypt.net ─────────────────────────────────────────────────────────
def _md5decrypt(hash_val: str) -> str | None:
    _ERROR_PATTERNS = [
        "CODE ERREUR", "ERREUR", "ERROR", "INVALID",
        "NOT FOUND", "NOTFOUND", "NO RESULT", "LIMIT",
        "RATE", "QUOTA", "UNAUTHORIZED", "FORBIDDEN",
    ]
    try:
        url = f"https://md5decrypt.net/Api/api.php?hash={hash_val}&hash_type=md5&email=bingook@proton.me&code=code1"
        resp = _get(url)
        if resp and resp.strip():
            resp_upper = resp.strip().upper()
            if any(pat in resp_upper for pat in _ERROR_PATTERNS):
                return None
            if len(resp.strip()) > 128:
                return None
            return resp.strip()
    except Exception:
        pass
    return None


# ── 4. nivaura.com ────────────────────────────────────────────────────────────
def _nivaura(hash_val: str) -> str | None:
    """SHA-1 / MD5 등 단순 해시"""
    try:
        url = f"https://www.nivaura.com/decrypt/?hash={hash_val}"
        html = _get(url)
        m = re.search(r"<div[^>]*class=[\"']?result[\"']?[^>]*>(.*?)</div>",
                      html, re.IGNORECASE | re.DOTALL)
        if m:
            plain = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if plain and len(plain) < 64:
                return plain
    except Exception:
        pass
    return None


# ── 5. cmd5.org (한국/중국 IP에서 잘 됨) ──────────────────────────────────────
def _cmd5(hash_val: str) -> str | None:
    try:
        url = f"https://www.cmd5.org/default.aspx"
        body = urllib.parse.urlencode({
            "__EVENTTARGET": "",
            "__EVENTARGUMENT": "",
            "TextBox1": hash_val,
            "Button1": "Decrypt",
        }).encode()
        html = _get(url, data=body,
                    extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
        m = re.search(r'id="Label1"[^>]*>(.*?)<', html, re.IGNORECASE | re.DOTALL)
        if m:
            plain = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if plain and len(plain) < 64 and plain.lower() not in ("", "not found"):
                return plain
    except Exception:
        pass
    return None


# ── 공개 API ─────────────────────────────────────────────────────────────────
class OnlineHashLookup:
    """
    여러 사이트를 순서대로 조회 — 첫 번째 성공 결과 반환
    bcrypt는 단방향이라 온라인 조회 불가 (건너뜀)
    """

    SITES = ["crackstation", "hashes.com", "md5decrypt", "nivaura", "cmd5"]

    def __init__(self, on_progress: Callable[[str], None] | None = None):
        self.log = on_progress or (lambda s: None)

    def lookup(self, hash_val: str) -> LookupResult:
        h = hash_val.strip()

        # bcrypt ($2y$/$2b$/$2a$) — includes per-hash salt, cannot be precomputed
        if h.startswith("$2"):
            self.log(
                f"  [online-lookup] ⚠ bcrypt detected — online DB lookup not possible\n"
                f"  [online-lookup]   Reason: bcrypt embeds a unique salt per hash (precomputed lookup impossible)\n"
                f"  [online-lookup]   → Switching to offline crack (john/hashcat/python)"
            )
            return LookupResult(h, False, error="bcrypt_no_online")

        # sha512crypt, md5crypt — also salted
        if h.startswith("$6$") or h.startswith("$1$"):
            self.log(
                f"  [online-lookup] ⚠ crypt hash detected — salted, online lookup not possible\n"
                f"  [online-lookup]   → Switching to offline crack"
            )
            return LookupResult(h, False, error="crypt_no_online")

        self.log(f"  [lookup] Starting online lookup: {h[:20]}...")

        # CrackStation (배치 처리 가능)
        self.log("  [lookup] → CrackStation")
        cs = _crackstation([h])
        if cs.get(h.lower()):
            return LookupResult(h, True, cs[h.lower()], "CrackStation")

        time.sleep(0.5)

        # hashes.com
        self.log("  [lookup] → hashes.com")
        r = _hashes_com(h)
        if r:
            return LookupResult(h, True, r, "hashes.com")

        time.sleep(0.5)

        # md5decrypt (MD5 전용)
        if len(h) == 32 and re.match(r"^[0-9a-f]{32}$", h):
            self.log("  [lookup] → md5decrypt.net")
            r = _md5decrypt(h)
            if r:
                return LookupResult(h, True, r, "md5decrypt.net")

        # nivaura
        self.log("  [lookup] → nivaura.com")
        r = _nivaura(h)
        if r:
            return LookupResult(h, True, r, "nivaura.com")

        time.sleep(0.3)

        # cmd5
        self.log("  [lookup] → cmd5.org")
        r = _cmd5(h)
        if r:
            return LookupResult(h, True, r, "cmd5.org")

        self.log("  [lookup] All sites exhausted — not found")
        return LookupResult(h, False)

    def lookup_many(self, hashes: list[str]) -> list[LookupResult]:
        results = []
        for i, h in enumerate(hashes, 1):
            self.log(f"\n  [{i}/{len(hashes)}] Looking up: {h[:30]}...")
            results.append(self.lookup(h))
        return results
