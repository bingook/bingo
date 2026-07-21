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

from .v7.loop_policy import (
    doom_loop_cutoff_reason,
    has_meaningful_loop_progress,
    ledger_skip_count,
    low_value_reentry_count,
    meaningful_loop_progress_signature,
    no_progress_penalty,
    repeated_response_pattern,
    response_pattern_signature,
    strip_action_ledger_skip_noise,
    target_drift_block_count,
)


LOW_VALUE_LEDGER_RE = re.compile(
    r"(?:"
    r"tool=(?:http_head|web_tech_detect|security_headers_check|clickjacking_autotest|"
    r"ssl_tls_scan|source_exposure_scan|js_secrets_extract|cors_autotest|"
    r"open_redirect_autotest|waf_detect)|"
    r"vector=(?:tomcat_admin|stack_leak|ajp_ghostcat)"
    r")",
    re.IGNORECASE,
)


def target_drift_domains(text: str) -> list[str]:
    """Extract blocked off-scope domains from target drift guard output."""
    domains: set[str] = set()
    for match in re.finditer(
        r"(?:Unauthorized external URL\(s\)|未授权外部域名URL|승인되지 않은 외부 도메인 URL|"
        r"Attack payload detected on unauthorized domain\(s\)|"
        r"Unauthorized external-domain .*? detected|"
        r"检测到对未授权外部域名的(?:攻击尝试|HTTP请求)|"
        r"승인되지 않은 외부 도메인에 (?:공격 시도|HTTP 요청) 감지)"
        r"\s*:\s*([^\n]+)",
        text or "",
        re.IGNORECASE,
    ):
        for value in re.split(r"[,，]\s*", match.group(1)):
            value = value.strip().strip("`'\" ")
            if value:
                domains.add(value)
    for match in re.finditer(
        r"https?://([a-zA-Z0-9._-]+(?::\d+)?)",
        text or "",
        re.IGNORECASE,
    ):
        domains.add(match.group(1).lower())
    return sorted(domains)


def target_scope_lock_notice(current_target: str, result_text: str) -> str:
    """Build a hard correction notice after any target drift block."""
    if target_drift_block_count(result_text) <= 0:
        return ""
    current_target = (current_target or "").strip() or "CURRENT_TARGET"
    blocked = [d for d in target_drift_domains(result_text) if current_target not in d]
    blocked_text = ", ".join(blocked[:6]) if blocked else "blocked external domain(s)"
    return (
        "\n[TARGET_SCOPE_LOCK]\n"
        f"AUTHORITATIVE_CURRENT_TARGET={current_target}\n"
        f"FORBIDDEN_DRIFT_DOMAIN={blocked_text}\n"
        "The executor blocked target drift. Do not claim the forbidden domain is confirmed. "
        "Do not use it in any next TOOL_CALL, script, Referer, Origin, Cookie scope, or BASE variable. "
        "Rewrite the next action against AUTHORITATIVE_CURRENT_TARGET only. "
        "A related service domain is allowed only after explicit TARGET_SCOPE_EXPANDED evidence from the current target response.\n"
        "[/TARGET_SCOPE_LOCK]\n"
    )


def canonical_action_args(tool_name: str, args: dict) -> dict:
    """Return executor-normalized args for stable action identity.

    This mirrors execution-time target canonicalization so the action ledger
    never stores model-drifted hosts as distinct identities.
    """
    if not isinstance(args, dict):
        return {}
    normalized = dict(args)
    name = str(tool_name or "").strip().lower()
    try:
        if name == "run_python" and "code" in normalized:
            from ..tools_ext.pentest_tools import _canonicalize_script_target_urls

            rewritten, _notice = _canonicalize_script_target_urls(
                str(normalized.get("code") or "")
            )
            normalized["code"] = rewritten
        elif name == "run_bash" and "script" in normalized:
            from ..tools_ext.pentest_tools import _canonicalize_script_target_urls

            rewritten, _notice = _canonicalize_script_target_urls(
                str(normalized.get("script") or "")
            )
            normalized["script"] = rewritten
        else:
            from ..tools_ext.pentest_tools import _canonicalize_tool_args_target_urls

            normalized, _notice = _canonicalize_tool_args_target_urls(normalized)
    except Exception:
        return dict(args)
    return normalized


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
        ("artifact_exposure", r"(?:composer\.(?:json|lock)|vendor/composer/installed\.json|package-lock\.json|yarn\.lock)"),
        ("user_enum", r"(?:ADMIN\s+ENUM|USER(?:NAME)?[_ -]?ENUM|not_registered|bad_password|등록되지\s*않은|비밀번호가\s*맞지)"),
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

    def _looks_transport_proxy_endpoint(host: str, port: str) -> bool:
        host_l = str(host or "").lower().strip("[]")
        port_s = str(port or "")
        if host_l not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
            return False
        if port_s not in {"9050", "9051", "1080", "1086", "1087", "7890", "7891", "8080", "8081", "8118"}:
            return False
        return bool(
            re.search(
                r"\b(?:proxy|proxies|socks5?|tor|BINGO_PROXY_URL|HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy)\b",
                combined,
                re.IGNORECASE,
            )
        )

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
        if _looks_transport_proxy_endpoint(host, port):
            continue
        hosts.add(f"{host.lower()}:{port}")
        ports.add(port)
    for host, port in re.findall(
        r"['\"]((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})['\"]\s*,\s*(\d{2,5})",
        combined,
        re.IGNORECASE,
    ):
        if _looks_transport_proxy_endpoint(host, port):
            continue
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


def action_ledger_identity(tool_name: str, args: dict) -> tuple[dict, str, str]:
    """Return normalized args plus stable signature/summary for one action."""
    normalized = canonical_action_args(tool_name, args)
    signature, summary = action_ledger_signature(tool_name, normalized)
    return normalized, signature, summary


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
        return f"timeout-exhausted after {timeouts} timeout(s): {entry.get('summary') or summary}"
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
        "Executor-owned state. Reuse status=done/blocked_timeout/negative action results and choose a pending distinct vector.",
    ]
    for sig, entry in items:
        lines.append(
            "- "
            f"sig={sig} kind={entry.get('kind', 'action')} status={entry.get('status')} attempts={entry.get('attempts', 0)} "
            f"timeouts={entry.get('timeouts', 0)} {entry.get('summary', '')}"
        )
    lines.append("[/ACTION_LEDGER]\n")
    return "\n".join(lines)


class ActionLedger:
    """Executor-owned mutable action ledger.

    The terminal should not implement ledger state transitions itself. It may
    still hold the object for session persistence, but all mutation rules live
    here so UI code remains a shell.
    """

    def __init__(self, entries: dict[str, dict] | None = None) -> None:
        self._entries: dict[str, dict] = dict(entries or {})

    @classmethod
    def coerce(cls, value: object) -> "ActionLedger":
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls(value)
        return cls()

    def export(self) -> dict[str, dict]:
        return self._entries

    def context(self, *, limit: int = 8) -> str:
        return action_ledger_context(self._entries, limit=limit)

    def skip_reason(self, signature: str, summary: str = "") -> str:
        if not signature:
            return ""
        entry = self._entries.get(signature)
        if entry:
            reason = action_ledger_entry_skip_reason(entry, summary)
            if reason:
                return reason
        family_key = action_ledger_family_key(summary)
        family = self._entries.get(family_key) if family_key else None
        if family:
            reason = action_ledger_entry_skip_reason(family, summary)
            if reason:
                return f"family {reason}"
        return ""

    def start(self, signature: str, summary: str = "", *, loop_count: int = 0) -> dict:
        if not signature:
            return {}
        family_key = action_ledger_family_key(summary)
        entry = self._entries.setdefault(
            signature,
            {
                "summary": summary,
                "attempts": 0,
                "timeouts": 0,
                "status": "pending",
                "first_loop": loop_count,
                "family": family_key,
            },
        )
        entry["family"] = family_key
        entry["summary"] = summary or entry.get("summary", "")
        entry["attempts"] = int(entry.get("attempts") or 0) + 1
        entry["last_loop"] = loop_count
        entry["status"] = "running"
        if family_key:
            family = self._entries.setdefault(
                family_key,
                {
                    "summary": summary,
                    "attempts": 0,
                    "timeouts": 0,
                    "status": "pending",
                    "first_loop": loop_count,
                    "family": family_key,
                    "kind": "family",
                },
            )
            family["summary"] = summary or family.get("summary", "")
            family["attempts"] = int(family.get("attempts") or 0) + 1
            family["last_loop"] = loop_count
            if family.get("status") not in {"done", "blocked_timeout", "negative"}:
                family["status"] = "running"
        return entry

    def finish(
        self,
        signature: str,
        summary: str = "",
        *,
        output: str = "",
        success: bool = False,
        exit_code: int = -1,
        loop_count: int = 0,
    ) -> dict:
        if not signature:
            return {}
        family_key = action_ledger_family_key(summary)
        entry = self._entries.setdefault(
            signature,
            {
                "summary": summary,
                "attempts": 0,
                "timeouts": 0,
                "status": "pending",
                "first_loop": loop_count,
                "family": family_key,
            },
        )
        entry["family"] = family_key
        status = action_ledger_result_status(
            output,
            success=success,
            exit_code=exit_code,
        )
        if status == "timeout":
            entry["timeouts"] = int(entry.get("timeouts") or 0) + 1
            status = "blocked_timeout" if int(entry["timeouts"]) >= 2 else "timeout"
        elif status == "no_progress" and int(entry.get("attempts") or 0) >= 2:
            status = "negative"
        entry["status"] = status
        entry["summary"] = summary or entry.get("summary", "")
        entry["last_exit_code"] = exit_code
        entry["last_success"] = bool(success)
        entry["last_loop"] = loop_count
        if family_key:
            family = self._entries.setdefault(
                family_key,
                {
                    "summary": summary,
                    "attempts": 0,
                    "timeouts": 0,
                    "status": "pending",
                    "first_loop": loop_count,
                    "family": family_key,
                    "kind": "family",
                },
            )
            family["summary"] = summary or family.get("summary", "")
            if status == "timeout":
                family["timeouts"] = int(family.get("timeouts") or 0) + 1
                if int(family["timeouts"]) >= 2:
                    family["status"] = "blocked_timeout"
                elif family.get("status") not in {"done", "blocked_timeout", "negative"}:
                    family["status"] = "timeout"
            elif status == "done":
                family["status"] = "done"
            elif status == "negative":
                family["status"] = "negative"
            elif status == "no_progress":
                if int(family.get("attempts") or 0) >= 3:
                    family["status"] = "negative"
                elif family.get("status") not in {"done", "blocked_timeout", "negative"}:
                    family["status"] = "no_progress"
            elif family.get("status") not in {"done", "blocked_timeout", "negative"}:
                family["status"] = status
            family["last_exit_code"] = exit_code
            family["last_success"] = bool(success)
            family["last_loop"] = loop_count
        return entry


# v7 owns loop-pressure heuristics. This module now keeps action-ledger and
# target-scope helpers while re-exporting the loop-policy compatibility API.
