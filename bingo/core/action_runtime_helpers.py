from __future__ import annotations

import codecs
import json
import re
from typing import Callable


def render_action_output_preview(output: str, mask_internal_markers: Callable[[str], str]) -> str:
    important = re.compile(
        r'(?:'
        r'HTTP/\d'
        r'|status[=:\s]+\d{3}'
        r'|\b(?:200|201|204|301|302|307|400|401|403|404|429|500|502)\b'
        r'|content-length\s*:\s*\d'
        r'|location\s*:\s*https?'
        r'|set-cookie\s*:'
        r'|server\s*:\s*\S'
        r'|x-powered-by|waf|cloudflare'
        r'|detected|found|error|exception'
        r'|---http_status|---size'
        r'|\[\+\]|\[-\]|\[!\]'
        r'|✅|❌|⚠|🔍|💥'
        r')',
        re.IGNORECASE,
    )
    html = re.compile(r'<[a-zA-Z/!]')
    header = re.compile(r'^[A-Za-z][A-Za-z0-9\-]+\s*:\s*\S')
    display_lines: list[str] = []
    html_run = 0
    header_run = 0
    suppressed_html = 0
    suppressed_header = 0
    for line in output.splitlines()[:120]:
        stripped = line.strip()
        if not stripped:
            continue
        if important.search(stripped):
            if suppressed_html:
                display_lines.append(f"  ⋯ {suppressed_html} HTML lines hidden")
                suppressed_html = 0
            if suppressed_header:
                display_lines.append(f"  ⋯ {suppressed_header} header lines hidden")
                suppressed_header = 0
            html_run = header_run = 0
            display_lines.append(line[:200])
            continue
        if header.match(stripped):
            header_run += 1
            html_run = 0
            if header_run <= 6:
                display_lines.append(line[:200])
            else:
                suppressed_header += 1
            continue
        if suppressed_header:
            display_lines.append(f"  ⋯ {suppressed_header} header lines hidden")
            suppressed_header = 0
        header_run = 0
        if len(html.findall(stripped)) >= 2 or (stripped.startswith("<") and stripped.endswith(">")):
            html_run += 1
            if html_run <= 3:
                display_lines.append(line[:200])
            else:
                suppressed_html += 1
            continue
        if suppressed_html:
            display_lines.append(f"  ⋯ {suppressed_html} HTML lines hidden")
            suppressed_html = 0
        html_run = 0
        display_lines.append(line[:200])
    if suppressed_html:
        display_lines.append(f"  ⋯ {suppressed_html} HTML lines hidden")
    if suppressed_header:
        display_lines.append(f"  ⋯ {suppressed_header} header lines hidden")
    return mask_internal_markers("\n".join(display_lines))


def format_action_result(tool_name: str, exit_code: int, success: bool, elapsed: float, output: str, result_extra: dict) -> str:
    return (
        f"=== TOOL_RESULT: {tool_name} ===\n"
        f"exit_code={exit_code}  success={success}  elapsed={elapsed}s\n"
        f"extra={json.dumps(result_extra, ensure_ascii=False, default=str)[:500]}\n"
        f"--- output ---\n{output}\n"
        f"=== END TOOL_RESULT ==="
    )


def format_action_cap_message(deferred_count: int, max_tools: int, max_web_requests: int) -> str:
    return (
        f"[ACTION_CAP] Deferred {deferred_count} action(s) "
        f"(max {max_tools} actions / {max_web_requests} web requests per turn). "
        f"Use one compact probe loop instead of flooding repeated web requests."
    )


def parse_internal_action_call(raw_json: str) -> tuple[str, dict, str | None]:
    call = raw_json.strip()
    try:
        parsed = json.loads(call)
        tool_name = str(parsed.get("name", ""))
        tool_args = parsed.get("args", {})
        if not isinstance(tool_args, dict):
            tool_args = {}
        return tool_name, tool_args, None
    except Exception as exc:
        recovered = False
        tool_name = ""
        tool_args: dict = {}
        try:
            name_match = re.search(r'"name"\s*:\s*"([^"]+)"', call)
            if name_match:
                tool_name = name_match.group(1)
                for field in ("script", "code", "url", "param", "base_value", "method", "headers", "post_data", "dump_table", "timeout"):
                    value_match = re.search(rf'"{field}"\s*:\s*"((?:[^"\\]|\\.)*)"', call, re.DOTALL)
                    if value_match:
                        try:
                            value = codecs.decode(value_match.group(1).encode(), "unicode_escape")
                        except Exception:
                            value = value_match.group(1)
                        tool_args[field] = value
                if "timeout" in tool_args:
                    try:
                        tool_args["timeout"] = int(str(tool_args["timeout"]))
                    except Exception:
                        tool_args.pop("timeout", None)
                recovered = bool(tool_args or tool_name)
        except Exception:
            pass
        if not recovered:
            return "", {}, f"JSON parse failed: {exc}"
        return tool_name, tool_args, None


def apply_action_request_policy(tool_name: str, tool_args: dict, http_get_done: int, max_http_get_per_turn: int) -> tuple[dict | None, str | None, int]:
    if tool_name != "http_get":
        return dict(tool_args), None, http_get_done
    if http_get_done >= max_http_get_per_turn:
        result = (
            f"=== TOOL_RESULT: http_get ===\n"
            f"exit_code=-95  success=false\n"
            f"--- output ---\n"
            f"[WEB_REQUEST_BATCH_CAP] max {max_http_get_per_turn} web requests/turn skipped.\n"
            f"Probe many hosts with one compact request loop instead of repeated single requests.\n"
            f"URL: {str(tool_args.get('url', ''))[:120]}\n"
            f"=== END TOOL_RESULT ==="
        )
        return None, result, http_get_done
    next_args = dict(tool_args)
    next_args["prefer_curl"] = True
    try:
        timeout_value = int(next_args.get("timeout", 10) or 10)
    except Exception:
        timeout_value = 10
    next_args["timeout"] = min(max(timeout_value, 3), 10)
    return next_args, None, http_get_done + 1


def format_action_parse_error(parse_error: str) -> str:
    return f"TOOL_RESULT:{{'name':'?','error':'{parse_error}','success':false}}"


def format_interrupted_action_result(tool_name: str, elapsed: float) -> str:
    return (
        f"=== TOOL_RESULT: {tool_name} ===\n"
        f"exit_code=-1  success=false  elapsed={elapsed}s\n"
        f"--- output ---\nINTERRUPTED mid-tool\n=== END TOOL_RESULT ==="
    )


def action_loop_limits() -> tuple[int, int]:
    return 10, 6


def format_action_batch_banner(total_actions: int, lang: str) -> str:
    return {
        "ko": f"⚙ 도구 {total_actions}개 실행 중… (진행 표시됨 / Ctrl+C=중단)",
        "zh": f"⚙ 正在执行 {total_actions} 个工具…（会显示进度 / Ctrl+C=中断）",
        "en": f"⚙ Running {total_actions} tools… (progress shown / Ctrl+C=stop)",
    }.get(lang, f"⚙ Running {total_actions} tools…")


def format_action_loop_interrupt(index: int, total_actions: int, lang: str) -> tuple[str, str]:
    stop_msg = {
        "ko": f"⏸ Ctrl+C — 남은 도구 {total_actions - index}개 스킵",
        "zh": f"⏸ Ctrl+C — 跳过剩余 {total_actions - index} 个工具",
        "en": f"⏸ Ctrl+C — skipped {total_actions - index} remaining tools",
    }.get(lang, "⏸ Interrupted")
    summary = (
        "=== INTERRUPTED by Ctrl+C — remaining actions skipped ===\n"
        "Summarize partial results. Do not re-emit the same action flood."
    )
    return stop_msg, summary
