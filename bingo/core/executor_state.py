"""Executor-owned state helpers for Bingo's agent loop.

The model may propose actions, but this module owns the repeat/novelty policy:
what counts as target progress, what belongs to the action ledger, and when a
loop should stop and report instead of pivoting again.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse


LOW_VALUE_LEDGER_RE = re.compile(
    r"(?:"
    r"tool=(?:http_head|web_tech_detect|security_headers_check|clickjacking_autotest|"
    r"ssl_tls_scan|source_exposure_scan|js_secrets_extract|cors_autotest|"
    r"open_redirect_autotest|waf_detect)|"
    r"vector=(?:tomcat_admin|stack_leak|ajp_ghostcat)"
    r")",
    re.IGNORECASE,
)


def response_pattern_signature(response: str) -> str:
    """Short signature for repeated model-response pattern detection."""
    return hashlib.md5((response or "")[:200].encode()).hexdigest()[:12]


def repeated_response_pattern(signatures: list[str], *, window: int = 6, threshold: int = 4) -> bool:
    """Return True when recent response signatures show a repeated pattern."""
    if len(signatures) < window:
        return False
    sample = signatures[-window:]
    return max(sample.count(sig) for sig in set(sample)) >= threshold


def strip_action_ledger_skip_noise(text: str) -> str:
    """Remove executor skip control-plane lines before evidence heuristics."""
    if "[ACTION_LEDGER_SKIP]" not in (text or ""):
        return text or ""
    return "\n".join(
        line
        for line in (text or "").splitlines()
        if "[ACTION_LEDGER_SKIP]" not in line
        and "already done/blocked in the executor ledger" not in line
        and not line.strip().startswith(("signature=", "summary="))
    )


def ledger_skip_count(text: str) -> int:
    """Count executor-ledger skips in one tool-result batch."""
    return (text or "").count("[ACTION_LEDGER_SKIP]")


def low_value_reentry_count(text: str) -> int:
    """Count late-loop low-value executor families seen in ledger output.

    This does not mean the action is useless. It means that after enough loops,
    repeated infrastructure/header/Tomcat-family work without confirmed findings
    should produce a report instead of expanding the loop.
    """
    count = 0
    for line in (text or "").splitlines():
        if "ACTION_LEDGER" not in line:
            continue
        if LOW_VALUE_LEDGER_RE.search(line):
            count += 1
    return count


def no_progress_penalty(skip_count: int) -> int:
    """Aggressively age no-progress loops when the executor already skipped work."""
    return min(3, max(1, int(skip_count or 0)))


def has_meaningful_loop_progress(text: str) -> bool:
    """Return True only for execution evidence that advances the mission."""
    if not text:
        return False

    text = strip_action_ledger_skip_noise(text)
    if not text.strip():
        return False

    strong_patterns = (
        r"\bBINGO_SIGNAL\s*:",
        r"\bBINGO-\d{4,}\b(?=[^\n]{0,180}\b(?:tier|confidence|conf)\s*[:=]\s*confirmed\b)",
        r"\bBINGO-\d{4,}\b(?=[^\n]{0,180}\bconfirmed\s*[:=]\s*(?:true|yes|1)\b)",
        r"\b(?:CONFIRMED|VERIFIED)\b(?!\s*[:=]\s*(?:false|no|0)\b)",
        r"\bconfirmed\s*[:=]\s*(?:true|yes|1)\b",
        r"\bLEAK\s+True\b",
        r"(?:stack|trace|exception).{0,60}(?:leak|exposed|disclosed|confirmed)",
        r"(?:堆栈|异常).{0,30}(?:泄露|确认|已确认)",
        r"(?:스택|예외).{0,30}(?:노출|누출|확인)",
        r"javax\.el\.ELException|org\.apache\.jasper\.JasperException",
        r"(?:credential|password|passwd|username)\s*(?:found|extracted|[:=])",
        r"(?:자격증명|비밀번호|계정)\s*(?:발견|추출|[:=])",
        r"(?:凭据|密码|用户名)\s*(?:发现|提取|[:：=])",
        r"(?:database|table|column)\s+(?:name\s+)?(?:extracted|enumerated)",
        r"(?:DB|테이블|컬럼)\s*(?:추출|열거|확인)",
        r"(?:数据库|表名|列名)\s*(?:提取|枚举|确认)",
        r"(?:shell|RCE)\s*(?:obtained|confirmed|verified)",
        r"(?:셸|RCE)\s*(?:획득|확인)",
        r"(?:Shell|RCE)\s*(?:获取|确认)",
    )
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in strong_patterns):
        return True

    noise_host_markers = (
        "google.", "google-", "googletagmanager", "googleadservices",
        "doubleclick", "googlesyndication", "gstatic", "facebook.",
        "analytics", "hotjar", "clarity.ms", "adservice", "tracking",
        "tagmanager", "pixel",
    )
    noise_path_markers = (
        "/collect", "/gtm.js", "/analytics", "/pixel", "/beacon",
        "/tag/", "/ads/", "/adservice", "/favicon", "/robots.txt",
        "/sitemap.xml",
    )
    static_exts = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".mp3",
    )
    noise_params = {
        "random", "cv", "fst", "fmt", "bg", "rcb", "frm", "auid", "dt",
        "en", "dl", "dr", "sr", "vp", "cid", "tid", "gtm", "_ga", "_gl",
        "utm_source", "utm_medium", "utm_campaign",
    }
    high_value_path_markers = (
        "api", "auth", "jwt", "token", "login", "logout", "admin",
        "user", "member", "account", "mypage", "profile", "order",
        "payment", "checkout", "loan", "apply", "upload", "file",
        "storage", "download", "report", "search", "product", "cart",
        "graphql", "oauth", "password", "reset", "verify", "session",
        "callback",
    )
    high_value_params = (
        "id", "idx", "uid", "user", "userid", "user_id", "member",
        "member_id", "no", "seq", "token", "jwt", "redirect", "return",
        "next", "url", "uri", "file", "path", "q", "query", "search",
        "page", "order", "order_id", "product", "product_id", "callback",
        "loreqtno",
    )

    def actionable_endpoint(endpoint: str, param: str = "") -> bool:
        endpoint = endpoint.strip().strip("'\"`),]")
        param_l = (param or "").strip().lower()
        try:
            parsed = urlparse(endpoint)
        except Exception:
            parsed = None
        host = (parsed.netloc if parsed else "").lower()
        path = (parsed.path if parsed and parsed.path else endpoint).lower()
        if host and any(marker in host for marker in noise_host_markers):
            return False
        if any(marker in path for marker in noise_path_markers):
            return False
        if path.endswith(static_exts):
            return False
        if param_l in noise_params:
            return False
        if any(marker in path for marker in high_value_path_markers):
            return True
        return any(param_l == hv or param_l.endswith(hv) for hv in high_value_params)

    endpoint_param_re = re.compile(
        r"(?m)(https?://[^\s\"'<>]+|/[A-Za-z0-9_./?=&%:-]+)\s*->\s*([A-Za-z_][A-Za-z0-9_-]*)"
    )
    for match in endpoint_param_re.finditer(text):
        if actionable_endpoint(match.group(1), match.group(2)):
            return True

    explicit_endpoint_re = re.compile(
        r"(?:new\s+high[- ]value\s+endpoint|"
        r"高价值端点|"
        r"고가치\s*엔드포인트)\s*[:：]?\s*(https?://[^\s\"'<>]+|/[A-Za-z0-9_./?=&%:-]+)",
        re.IGNORECASE,
    )
    for match in explicit_endpoint_re.finditer(text):
        if actionable_endpoint(match.group(1)):
            return True

    return False


def doom_loop_cutoff_reason(
    *,
    no_progress_count: int,
    escape_attempts: int,
    loop_count: int,
    doom_detected: bool = False,
    confirmed_count: int = 0,
    ledger_skip_count: int = 0,
    ledger_skip_total: int = 0,
    ledger_skip_streak: int = 0,
    low_value_reentry_count: int = 0,
) -> str:
    """Return a stop reason when the agent loop should report instead of pivoting again."""
    if int(confirmed_count or 0) == 0:
        if int(ledger_skip_count or 0) >= 2 and int(loop_count or 0) >= 20:
            return "action ledger exhausted pending vectors"
        if int(ledger_skip_streak or 0) >= 2 and int(loop_count or 0) >= 20:
            return "repeated action ledger skip turns"
        if int(low_value_reentry_count or 0) >= 2 and int(loop_count or 0) >= 24:
            return "late low-value executor re-entry without confirmed findings"
        if int(ledger_skip_total or 0) >= 6 and int(loop_count or 0) >= 24:
            return "cumulative action ledger skips without confirmed findings"
    if not doom_detected and int(no_progress_count or 0) < 6:
        return ""
    next_escape_attempt = int(escape_attempts or 0) + 1
    if int(confirmed_count or 0) == 0 and int(loop_count or 0) >= 30:
        return "zero confirmed findings after excessive loops"
    if next_escape_attempt >= 2:
        return "repeated no-progress escape attempts"
    return ""


def action_ledger_signature(tool_name: str, args: dict) -> tuple[str, str]:
    """Build a stable action signature from model-proposed tool intent.

    The signature intentionally ignores script formatting so the executor can
    recognize the same probe even when the model rewrites the code.
    """
    name = str(tool_name or "").strip().lower() or "tool"
    if not isinstance(args, dict):
        args = {}
    text = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
    script = str(args.get("code") or args.get("script") or "")
    combined = f"{text}\n{script}"
    lowered = combined.lower()

    vector_rules = (
        ("ajp_ghostcat", r"\b(?:ajp|ghostcat|cping|8009)\b"),
        ("tomcat_admin", r"(?:tomcat|manager/html|host-manager|:8080|:8000|:8443)"),
        ("unauth_mypage", r"(?:/balance/mypage/|cust_limit|app_status|custinfo|receipt_account|certification)"),
        ("param_menuno", r"\bmenuno\b"),
        ("idor", r"\b(?:idor|seq|idx|object|unauth|未授权|미인증)\b"),
        ("login_form", r"(?:custlogin|/login|passwd|nm_cust|ssn)"),
        ("stack_leak", r"(?:stack|trace|exception|elException|jasperException|invalid_bingo|堆栈|异常|스택|예외)"),
        ("xss", r"\b(?:xss|alert\(|browser_confirmed|bingo0xss|bing0xss)\b"),
        ("sqli", r"\b(?:sqli|sql\s*inject|boolean|time.?based|sleep\(|waitfor)\b"),
        ("lfi", r"\b(?:lfi|path traversal|/etc/passwd|WEB-INF/web\.xml)\b"),
    )
    vector = "script"
    for label, pattern in vector_rules:
        if re.search(pattern, combined, re.IGNORECASE):
            vector = label
            break
    if name == "http_get" and vector == "script":
        vector = "http_get"

    url_values: list[str] = []
    for key in ("url", "base_url", "target", "endpoint"):
        if args.get(key):
            url_values.append(str(args.get(key)))
    url_values.extend(re.findall(r"https?://[^\s\"'<>),]+", combined))

    hosts: set[str] = set()
    ports: set[str] = set()
    paths: set[str] = set()
    for raw_url in url_values:
        raw_url = raw_url.strip().strip("'\"`),]")
        try:
            parsed = urlparse(raw_url)
        except Exception:
            continue
        if parsed.netloc:
            hosts.add(parsed.netloc.lower())
        if parsed.port:
            ports.add(str(parsed.port))
        if parsed.path and parsed.path != "/":
            paths.add(parsed.path.lower())

    for host, port in re.findall(
        r"\b((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})\s*:\s*(\d{2,5})\b",
        lowered,
        re.IGNORECASE,
    ):
        hosts.add(f"{host.lower()}:{port}")
        ports.add(port)
    for host, port in re.findall(
        r"['\"]((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})['\"]\s*,\s*(\d{2,5})",
        combined,
        re.IGNORECASE,
    ):
        hosts.add(f"{host.lower()}:{port}")
        ports.add(port)
    host_var = re.search(
        r"\bHOST\s*=\s*['\"]((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})['\"]",
        combined,
        re.IGNORECASE,
    )
    port_var = re.search(r"\bPORT\s*=\s*(\d{2,5})\b", combined, re.IGNORECASE)
    if host_var and port_var:
        hosts.add(f"{host_var.group(1).lower()}:{port_var.group(1)}")
        ports.add(port_var.group(1))

    for rel in re.findall(
        r"(?i)(/[^\s\"'<>),]*(?:\.do|manager/html|host-manager|WEB-INF/web\.xml)[^\s\"'<>),]*)",
        combined,
    ):
        paths.add(rel.lower().split("#", 1)[0])

    params: set[str] = set()
    for key in ("param", "parameter"):
        if args.get(key):
            params.add(str(args.get(key)).lower())
    for param in re.findall(
        r"\b(menuNo|returntype|seq|idx|id|no|uid|user_id|nm_cust|passwd|ssn|ph|token|redirect|file|path)\b",
        combined,
        re.IGNORECASE,
    ):
        params.add(param.lower())

    if vector == "script" and not (hosts or paths or params):
        fallback = hashlib.sha256(combined[:4096].encode("utf-8", errors="ignore")).hexdigest()[:12]
        parts = [name, vector, fallback]
    else:
        if vector in {"ajp_ghostcat", "tomcat_admin", "stack_leak", "unauth_mypage"}:
            selected_paths = sorted(paths)[:2]
        else:
            selected_paths = sorted(paths)[:5]
        parts = [
            name,
            vector,
            ",".join(sorted(hosts)[:4]),
            ",".join(sorted(ports)[:4]),
            ",".join(selected_paths),
            ",".join(sorted(params)[:6]),
        ]
    canonical = "|".join(parts)
    sig = hashlib.sha256(canonical.encode("utf-8", errors="ignore")).hexdigest()[:16]
    summary_bits = [f"tool={name}", f"vector={vector}"]
    if hosts:
        summary_bits.append(f"target={','.join(sorted(hosts)[:2])}")
    if paths:
        summary_bits.append(f"path={','.join(sorted(paths)[:3])}")
    if params:
        summary_bits.append(f"param={','.join(sorted(params)[:4])}")
    return sig, " ".join(summary_bits)


def action_ledger_result_status(
    output: str,
    *,
    success: bool = False,
    exit_code: int = -1,
    has_progress: bool | None = None,
) -> str:
    text = output or ""
    if re.search(
        r"(?:ReadTimeout|ConnectTimeout|TimeoutError|timed out|TIMEOUT|Request timeout|STATUS:000)",
        text,
        re.IGNORECASE,
    ):
        return "timeout"
    if re.search(
        r"(?:PYTHON_PRECHECK_SYNTAX_ERROR|SyntaxError|Traceback|JSON parse failed)",
        text,
        re.IGNORECASE,
    ):
        return "error"
    progress = has_meaningful_loop_progress(text) if has_progress is None else has_progress
    if progress:
        return "done"
    if success and exit_code == 0:
        return "no_progress"
    return "error"


def action_ledger_family_key(summary: str) -> str:
    parts: dict[str, str] = {}
    for token in (summary or "").split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        parts[key] = value
    vector = parts.get("vector", "unknown")
    target = parts.get("target", "")
    path = parts.get("path", "")
    param = parts.get("param", "")
    if not target and not path and not param:
        return ""
    if vector in {"ajp_ghostcat", "tomcat_admin", "stack_leak", "unauth_mypage"}:
        canonical = f"{vector}|{target}"
    elif vector in {"sqli", "xss", "idor", "param_menuno", "login_form", "lfi"}:
        canonical = f"{vector}|{target}|{path.split(',', 1)[0]}|{param}"
    else:
        canonical = f"{vector}|{target}|{path.split(',', 1)[0]}|{param.split(',', 1)[0]}"
    return "family:" + hashlib.sha256(canonical.encode("utf-8", errors="ignore")).hexdigest()[:16]


def action_ledger_entry_skip_reason(entry: dict, summary: str = "") -> str:
    status = str(entry.get("status") or "")
    attempts = int(entry.get("attempts") or 0)
    timeouts = int(entry.get("timeouts") or 0)
    if status == "done":
        return f"already done: {entry.get('summary') or summary}"
    if status == "blocked_timeout":
        return f"blocked_timeout after {timeouts} timeout(s): {entry.get('summary') or summary}"
    if status == "negative" and attempts >= 2:
        return f"negative/no-progress already tested {attempts} time(s): {entry.get('summary') or summary}"
    return ""


def action_ledger_context(ledger: dict | None, *, limit: int = 8) -> str:
    if not isinstance(ledger, dict) or not ledger:
        return ""
    priority = {"blocked_timeout": 0, "done": 1, "negative": 2, "timeout": 3}
    items = sorted(
        ledger.items(),
        key=lambda item: (
            priority.get(str(item[1].get("status")), 9),
            -int(item[1].get("last_loop") or 0),
        ),
    )[:limit]
    lines = [
        "\n[ACTION_LEDGER]",
        "Executor-owned state. Do not re-run status=done/blocked_timeout/negative actions; choose a pending distinct vector.",
    ]
    for sig, entry in items:
        lines.append(
            "- "
            f"sig={sig} kind={entry.get('kind', 'action')} status={entry.get('status')} attempts={entry.get('attempts', 0)} "
            f"timeouts={entry.get('timeouts', 0)} {entry.get('summary', '')}"
        )
    lines.append("[/ACTION_LEDGER]\n")
    return "\n".join(lines)


def meaningful_loop_progress_signature(text: str) -> str:
    """Stable signature for novel progress de-duplication."""
    if not text:
        return ""
    signal_re = re.compile(
        r"(?:"
        r"CONFIRMED|VERIFIED|credential|password|passwd|username|"
        r"database|table|column|endpoint|TRACE|clickjacking|csrf|"
        r"x-frame-options|frame-ancestors|content-security-policy|"
        r"RCE|shell|BINGO_SIGNAL|BINGO-\d{4,}|VULNERABLE|HIGH|CRITICAL|"
        r"LEAK\s+True|ELException|JasperException|stack|trace|exception|"
        r"堆栈|异常|스택|예외"
        r")",
        re.IGNORECASE,
    )
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or not signal_re.search(stripped):
            continue
        if re.search(
            r"^(?:#|import |from |def |for |if |elif |else:|try:|except |with |return |print\(|"
            r"[A-Za-z_][A-Za-z0-9_]*\s*=|r[\"']|f[\"'])",
            stripped,
        ):
            continue
        if re.search(r"\b(?:re\.search|re\.findall|for\s+\w+\s+in|body\.splitlines)\b", stripped):
            continue
        stripped = re.sub(
            r"BINGO(?:_[A-Z0-9]+){1,}|TRACE_[A-Z0-9_]+|[a-f0-9]{16,}",
            "<id>",
            stripped,
            flags=re.IGNORECASE,
        )
        stripped = re.sub(
            r"(for input string:)\s*(?:&quot;[^&]{0,160}&quot;|\"[^\"]{0,160}\"|'[^']{0,160}'|[^\s<]{1,160})",
            r"\1 <value>",
            stripped,
            flags=re.IGNORECASE,
        )
        stripped = re.sub(
            r"(NumberFormatException:)\s*.*",
            r"\1 <value>",
            stripped,
            flags=re.IGNORECASE,
        )
        stripped = re.sub(
            r"\b\d{3}/\d{3,8}B\b",
            "<status>/<size>",
            stripped,
            flags=re.IGNORECASE,
        )
        stripped = re.sub(r"\b\d{5,}\b", "<n>", stripped)
        lines.append(stripped.lower()[:240])
        if len(lines) >= 24:
            break
    if not lines:
        return ""
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
