from __future__ import annotations

import hashlib
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


def repeated_response_pattern(
    signatures: list[str],
    *,
    window: int = 6,
    threshold: int = 4,
) -> bool:
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
        and "already terminal/exhausted in the executor ledger" not in line
        and not line.strip().startswith(("signature=", "summary="))
    )


def ledger_skip_count(text: str) -> int:
    """Count executor-ledger skips in one tool-result batch."""
    return (text or "").count("[ACTION_LEDGER_SKIP]")


def low_value_reentry_count(text: str) -> int:
    """Count low-value executor families seen in ledger output."""
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


def target_drift_block_count(text: str) -> int:
    """Count target-scope guard blocks in one execution result batch."""
    haystack = text or ""
    return haystack.count("[TARGET_DRIFT_BLOCKED]") + haystack.count("TARGET_DOMAIN_MISMATCH")


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
        r"/(?:composer\.(?:json|lock)|vendor/composer/installed\.json)\s*->\s*200\b",
        r"\bPKG\s+[a-z0-9_.-]+/[a-z0-9_.-]+@?v?\d",
        r"(?:ADMIN\s+ENUM|USER(?:NAME)?[_ -]?ENUM).{0,400}"
        r"(?:not_registered|등록되지\s*않은|bad_password|비밀번호가\s*맞지)",
        r"(?:Fatal\s+error:\s*Uncaught|Uncaught\s+(?:TypeError|Error|Exception)).{0,500}"
        r"(?:called\s+in\s+/|Stack\s+trace)",
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
    target_drift_count: int = 0,
    target_drift_total: int = 0,
    target_drift_streak: int = 0,
) -> str:
    """Compatibility cutoff heuristic for legacy callers."""
    if int(target_drift_count or 0) > 0:
        if int(target_drift_streak or 0) >= 2:
            return "repeated target drift after scope lock"
        if int(target_drift_total or 0) >= 4:
            return "excessive target drift blocks"
    if int(confirmed_count or 0) > 0:
        if int(no_progress_count or 0) >= 4 and int(loop_count or 0) >= 10:
            return "confirmed evidence plateau; report current findings"
        if int(low_value_reentry_count or 0) >= 2 and int(loop_count or 0) >= 12:
            return "confirmed evidence reached; low-value re-entry exhausted"
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


def meaningful_loop_progress_signature(text: str) -> str:
    """Stable signature for novel progress de-duplication."""
    if not text:
        return ""
    signal_re = re.compile(
        r"(?:"
        r"CONFIRMED|VERIFIED|credential|password|passwd|username|"
        r"database|table|column|endpoint|TRACE|clickjacking|csrf|"
        r"x-frame-options|frame-ancestors|content-security-policy|"
        r"composer\.(?:json|lock)|vendor/composer/installed\.json|"
        r"ADMIN\s+ENUM|USER(?:NAME)?[_ -]?ENUM|not_registered|bad_password|"
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
