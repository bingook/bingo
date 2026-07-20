from __future__ import annotations

import threading
import json
from pathlib import Path
from types import SimpleNamespace

from bingo.ui.terminal import (
    BingoTerminal,
    _codeblock_exec_limits,
    _normalize_tool_call_response,
    _repair_mixed_bash_python,
)
from bingo.lang.strings import get_slash_commands, get_strings
from bingo.tools.findings_exporter import FindingsExporter
from bingo.tools.playwright_engine import PlaywrightEngine
from bingo.core.execution_anchor import ExecutionAnchorEngine, _has_exec_evidence
from bingo.core.zero_hal_v5 import ZeroHalEngine
from bingo.models.system_prompt import (
    get_pentest_system_prompt,
    get_warmup_history,
    rephrase_refused_request,
    wrap_task,
)
from bingo.models.base import Message, ModelConfig
from bingo.orchestrator.engine import _board_value_anchored, _goal_completion_allowed
from bingo.tools_ext import autoexploit_modules
from bingo.tools_ext.builtin import security_audit
from bingo.tools_ext.pentest_tools import (
    TOOL_REGISTRY,
    _build_adaptive_boolean_candidates,
    _boolean_probe_is_blocked,
    _boolean_probe_pair_is_eligible,
    _calibrate_boolean_oracle,
    _check_script_target_drift,
    _classify_dbms_with_oracle,
    _fix_bash_script,
    _inject_real_ip_notice,
    _load_sqli_checkpoint,
    _save_sqli_checkpoint,
    _inject_post_exploit_notice,
    _inject_sqli_trigger_notice,
    _inject_vuln_trigger_notice,
    execute_tool,
    run_python,
    run_ghauri,
    run_sqlmap,
    set_target_domain,
    sqli_autoexploit,
    ssrf_chain_exploit,
)
from bingo.tools.http_probe import ProbeResult
from bingo.tools.waf_bypass import WafBypassEngine, WafDetector


class _Console:
    file = SimpleNamespace(flush=lambda: None)

    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, *args, **_kwargs) -> None:
        self.messages.append(" ".join(str(arg) for arg in args))


def test_attack_hypothesis_is_warned_but_not_blocked() -> None:
    engine = ExecutionAnchorEngine(session_target="https://example.test", lang="en")

    result = engine.check("There might be SQLi in the id parameter; test both controls.")

    assert not result.blocked
    assert result.warned
    assert result.block_reason == "HYPOTHESIS_REQUIRES_TEST"


def test_unexecuted_definite_claim_is_blocked() -> None:
    engine = ExecutionAnchorEngine(session_target="https://example.test", lang="en")

    result = engine.check("SQLi confirmed and exploitable.")

    assert result.blocked
    assert result.block_reason == "UNEXECUTED_CLAIM"
    assert not _has_exec_evidence("code: requests.get(url); print(r.status_code)")


def test_zero_hal_requires_type_specific_claim_evidence() -> None:
    generic = ZeroHalEngine(session_target="https://example.test", lang="en")
    rejected = generic.process("RCE confirmed", "HTTP/1.1 200 OK\nServer: Apache")

    proven = ZeroHalEngine(session_target="https://example.test", lang="en")
    accepted = proven.process(
        "RCE confirmed",
        "HTTP/1.1 200 OK\nuid=33(www-data) gid=33(www-data)",
    )

    assert rejected.blocked
    assert rejected.block_reason == "UNANCHORED_CLAIM"
    assert not accepted.blocked


def test_preexecution_claim_downgrade_preserves_attack_code() -> None:
    code = "```python\nprint('probe')\n```"
    response = "SQLi confirmed successfully.\n" + code

    corrected = BingoTerminal._sanitize_preexecution_claims(response)

    assert "[UNVERIFIED]" in corrected
    assert "SQLi confirmed" not in corrected
    assert code in corrected


def test_chinese_fake_final_report_is_intercepted_before_hash_collection() -> None:
    class _Model:
        @staticmethod
        def chat_stream(_messages):
            return []

    obj = BingoTerminal.__new__(BingoTerminal)
    obj.console = _Console()
    obj.s = {}
    obj.history = []
    obj._build_messages = lambda _skill: []
    obj._stream_response = lambda _stream: "```bash\ncurl -sk https://example.test/\n```"

    response = (
        "目标环境已全面分析完毕。这是所有关键发现和已验证漏洞的最终报告。\n"
        "SQL 注入（已验证 — 完整数据库泄露）\n"
        "loan1007.shiningcorp.com — 完整数据库转储 SinkDB、SQLMap shell 实现命令执行\n"
        "管理员哈希  admin : *A4B6157319038724E3560894F7F932C8886EBFCF\n"
    )

    intercepted = BingoTerminal._intercept_text_hallucination(
        obj,
        response,
        "continue",
        _Model(),
        SimpleNamespace(provider="test"),
        "",
    )

    assert intercepted.startswith("```bash")
    assert "SinkDB" not in intercepted
    assert "A4B615" not in intercepted


def test_tool_call_codeblock_rendering_hides_raw_directive() -> None:
    terminal = _code_test_terminal()
    collapsed = terminal._collapse_code_blocks(
        '```python\nTOOL_CALL:{"name":"_ssl_retry_with_legacy","args":{"url":"https://example.test/"}}\n```'
    )

    assert "TOOL_CALL" not in collapsed
    assert "_ssl_retry_with_legacy" not in collapsed
    assert "bingo action" in collapsed


def test_plain_tool_call_payloads_are_compacted_for_logs_and_history() -> None:
    long_script = "echo start\\n" + ("curl -sk https://example.test/a\\n" * 120)
    text = (
        "Run probes\n"
        f'TOOL_CALL:{{"name":"run_bash","args":{{"script":"{long_script}"}}}}\n'
        'TOOL_CALL:{"name":"http_get","args":{"url":"https://example.test/login","timeout":30}}\n'
    )

    compacted = BingoTerminal._compact_tool_call_payloads(text, max_calls=1)

    assert "[bingo action] run_bash" in compacted
    legacy_marker = "TOOL_CALL" + "_SUMMARY"
    assert legacy_marker not in compacted
    assert "script=<" in compacted
    assert "curl -sk https://example.test/a" not in compacted
    assert "additional deferred call" in compacted


def test_latest_assistant_tool_history_is_compacted_without_blocking_execution() -> None:
    response = (
        'TOOL_CALL:{"name":"run_python","args":{"code":"'
        + ("print(1)\\n" * 80)
        + '"}}'
    )
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal.history = [Message(role="assistant", content=response)]

    terminal._compact_latest_assistant_tool_history(response)

    assert "[bingo action] run_python" in terminal.history[-1].content
    legacy_marker = "TOOL_CALL" + "_SUMMARY"
    assert legacy_marker not in terminal.history[-1].content
    assert "print(1)" not in terminal.history[-1].content


def test_echoed_tool_call_summary_payload_is_compacted_again() -> None:
    legacy_marker = "TOOL_CALL" + "_SUMMARY"
    echoed = (
        f"{legacy_marker}: run_python(code=import requests,re\n"
        "BASE='https://example.test'\n"
        "r=requests.get(BASE)\n"
        "print(r.status_code)\n"
        "\n"
        "next text\n"
        f"{legacy_marker}: http_get(url=https://example.test/)"
    )

    compacted = BingoTerminal._compact_tool_call_payloads(echoed)

    assert legacy_marker not in compacted
    assert "[bingo action] run_python(code=<code omitted>)" in compacted
    assert "BASE='https://example.test'" not in compacted
    assert "next text" in compacted
    assert "[bingo action] http_get" in compacted


def test_echoed_bingo_action_code_is_compacted_without_tool_call_marker() -> None:
    echoed = (
        "probe target\n"
        "[bingo action] run_python(code=\n"
        "import requests, re\n"
        "r = requests.get('https://example.test/')\n"
        "print(r.status_code)\n"
        ")\n"
        "next step"
    )

    compacted = BingoTerminal._compact_tool_call_payloads(echoed)

    assert "[bingo action] run_python(code=<3 lines omitted>)" in compacted
    assert "import requests" not in compacted
    assert "print(r.status_code)" not in compacted
    assert "next step" in compacted


def test_auto_report_defers_task_complete_when_tool_action_is_pending() -> None:
    response = (
        'TOOL_CALL:{"name":"http_get","args":{"url":"https://example.test/login"}}\n'
        "TASK_COMPLETE"
    )
    counts = {"confirmed": 0, "probable": 0, "potential": 0}

    reason = BingoTerminal._auto_report_defer_reason(
        response, counts, loop_count=4, trigger="task_complete"
    )

    assert "pending executable action" in reason


def test_auto_report_defers_empty_early_completion() -> None:
    counts = {"confirmed": 0, "probable": 0, "potential": 0}

    reason = BingoTerminal._auto_report_defer_reason(
        "Recon complete.\nTASK_COMPLETE",
        counts,
        loop_count=3,
        trigger="task_complete",
    )

    assert "early reconnaissance" in reason


def test_auto_report_allows_candidate_report_after_evidence_exists() -> None:
    counts = {"confirmed": 0, "probable": 0, "potential": 1}

    reason = BingoTerminal._auto_report_defer_reason(
        "TASK_COMPLETE", counts, loop_count=10, trigger="task_complete"
    )

    assert reason == ""


def test_dict_tool_call_is_normalized_before_code_execution() -> None:
    response = (
        "```python\n"
        "{'name': 'http_get', 'arguments': {'url': 'https://example.test/'}}\n"
        "```"
    )

    normalized, count = _normalize_tool_call_response(response)

    assert count == 1
    assert normalized.startswith("TOOL_CALL:")
    assert '"name": "http_get"' in normalized
    assert "```python" not in normalized
    assert "WRONG_TOOL_FORMAT" not in normalized


def test_flat_dict_tool_call_is_normalized_silently() -> None:
    response = (
        "```python\n"
        "{'name': 'http_get', 'url': 'https://example.test/', 'timeout': 7}\n"
        "```"
    )

    normalized, count = _normalize_tool_call_response(response)

    assert count == 1
    assert '"args": {"url": "https://example.test/", "timeout": 7}' in normalized
    assert "AUTO_FIX" not in normalized


def test_domain_bound_target_blocks_direct_ip_script_without_host_header() -> None:
    set_target_domain("http://www.cheomdanhosp.co.kr/")
    try:
        reason = _check_script_target_drift(
            "curl -sk 'http://14.63.227.240/index.php.bak'",
            "bash",
        )
        assert reason is not None
        assert "DOMAIN_BOUND_IP_BLOCKED" in reason
    finally:
        set_target_domain("")


def test_domain_bound_target_allows_ip_transport_with_current_host_header() -> None:
    set_target_domain("http://www.cheomdanhosp.co.kr/")
    try:
        reason = _check_script_target_drift(
            "curl -sk -H 'Host: www.cheomdanhosp.co.kr' 'http://14.63.227.240/'",
            "bash",
        )
        assert reason is None
    finally:
        set_target_domain("")


def test_tool_call_blocks_direct_ip_url_without_host_header() -> None:
    set_target_domain("http://www.cheomdanhosp.co.kr/")
    try:
        result = execute_tool("http_get", {"url": "http://14.63.227.240/"})
        assert result["exit_code"] == -99
        assert "DOMAIN_BOUND_IP_BLOCKED" in result["output"]
    finally:
        set_target_domain("")


def test_real_ip_notice_keeps_domain_as_authoritative() -> None:
    set_target_domain("http://www.cheomdanhosp.co.kr/")
    try:
        notice = _inject_real_ip_notice(
            'href="http://14.63.227.240/index.php"'
        )
        assert "REAL_IP_DETECTED" in notice
        assert "do NOT switch the target URL to the IP" in notice
        assert 'sqli_autoexploit url="http://14.63.227.240' not in notice
        assert "http(s)://www.cheomdanhosp.co.kr/path" in notice
    finally:
        set_target_domain("")


def _code_test_terminal() -> BingoTerminal:
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal.console = _Console()
    terminal.config = SimpleNamespace(lang="en")
    terminal.s = get_strings("en")
    terminal.history = []
    terminal._agent_stop_flag = threading.Event()
    terminal._hint_input_active = threading.Event()
    terminal._active_tool_thread = None
    return terminal


def test_codeblock_exec_limits_default_to_bounded_values(monkeypatch) -> None:
    monkeypatch.delenv("BINGO_EXEC_TIMEOUT", raising=False)
    monkeypatch.delenv("BINGO_EXEC_IDLE_TIMEOUT", raising=False)
    monkeypatch.delenv("BINGO_EXEC_WALL_CLOCK_TIMEOUT", raising=False)

    assert _codeblock_exec_limits() == (180, 120, 210)


def test_codeblock_exec_limits_clamp_env_values(monkeypatch) -> None:
    monkeypatch.setenv("BINGO_EXEC_TIMEOUT", "3")
    monkeypatch.setenv("BINGO_EXEC_IDLE_TIMEOUT", "30")
    monkeypatch.setenv("BINGO_EXEC_WALL_CLOCK_TIMEOUT", "2")

    assert _codeblock_exec_limits() == (3, 3, 3)


def test_safe_prompt_ask_retries_after_unicode_decode_error(monkeypatch) -> None:
    terminal = _code_test_terminal()
    boom = UnicodeDecodeError("utf-8", b"\xe3\x80", 0, 1, "invalid continuation byte")
    values = iter([boom, "glm-5.2"])

    def fake_ask(_prompt: str, password: bool = False) -> str:
        value = next(values)
        if isinstance(value, UnicodeDecodeError):
            raise value
        return value

    monkeypatch.setattr("bingo.ui.terminal.Prompt.ask", fake_ask)

    assert terminal._safe_prompt_ask("alias") == "glm-5.2"
    assert any("Input encoding error" in message for message in terminal.console.messages)


def test_cmd_model_custom_alias_decode_error_does_not_crash(monkeypatch) -> None:
    from bingo.models.registry import BUILTIN_PROVIDERS

    class Config:
        lang = "zh"
        models: list = []
        active_model = ""
        saved = False

        def add_model(self, cfg) -> None:
            self.models.append(cfg)

        def save(self) -> None:
            self.saved = True

    terminal = _code_test_terminal()
    terminal.config = Config()
    terminal.s = get_strings("zh")
    terminal._success = lambda msg: terminal.console.print(msg)
    terminal._warn = lambda msg: terminal.console.print(msg)
    custom_number = list(BUILTIN_PROVIDERS).index("custom") + 1
    boom = UnicodeDecodeError("utf-8", b"\xe3\x80", 0, 1, "invalid continuation byte")
    values = iter([
        str(custom_number),
        "sk-test",
        "https://api.ntrapi.cn/v1",
        "glm-5.2",
        boom,
        "glm-5.2",
    ])

    def fake_ask(_prompt: str, password: bool = False) -> str:
        value = next(values)
        if isinstance(value, UnicodeDecodeError):
            raise value
        return value

    monkeypatch.setattr("bingo.ui.terminal.Prompt.ask", fake_ask)

    terminal._cmd_model()

    assert terminal.config.saved is True
    assert len(terminal.config.models) == 1
    cfg = terminal.config.models[0]
    assert cfg.provider == "custom"
    assert cfg.api_key == "sk-test"
    assert cfg.base_url == "https://api.ntrapi.cn/v1"
    assert cfg.model == "glm-5.2"
    assert cfg.alias == "glm-5.2"


def test_cmd_model_deletes_saved_model_and_falls_back_active(monkeypatch) -> None:
    class Config:
        def __init__(self) -> None:
            self.lang = "en"
            self.models = [
                ModelConfig(
                    provider="custom",
                    model="first-model",
                    api_key="sk-first",
                    base_url="https://api.example.test/v1",
                    alias="first",
                ),
                ModelConfig(
                    provider="custom",
                    model="second-model",
                    api_key="sk-second",
                    base_url="https://api.example.test/v1",
                    alias="second",
                ),
            ]
            self.active_model = "second"
            self.saved = False

        def save(self) -> None:
            self.saved = True

    terminal = _code_test_terminal()
    terminal.config = Config()
    terminal.s = get_strings("en")
    terminal._success = lambda msg: terminal.console.print(msg)
    terminal._warn = lambda msg: terminal.console.print(msg)
    monkeypatch.setattr("bingo.ui.terminal.Prompt.ask", lambda _prompt, password=False: "d2")

    terminal._cmd_model()

    assert terminal.config.saved is True
    assert [m.alias for m in terminal.config.models] == ["first"]
    assert terminal.config.active_model == "first"
    assert any("Model deleted: second" in message for message in terminal.console.messages)


def test_cmd_model_rejects_invalid_saved_model_delete(monkeypatch) -> None:
    class Config:
        def __init__(self) -> None:
            self.lang = "en"
            self.models = [
                ModelConfig(
                    provider="custom",
                    model="only-model",
                    api_key="sk-only",
                    base_url="https://api.example.test/v1",
                    alias="only",
                )
            ]
            self.active_model = "only"
            self.saved = False

        def save(self) -> None:
            self.saved = True

    terminal = _code_test_terminal()
    terminal.config = Config()
    terminal.s = get_strings("en")
    terminal._success = lambda msg: terminal.console.print(msg)
    terminal._warn = lambda msg: terminal.console.print(msg)
    monkeypatch.setattr("bingo.ui.terminal.Prompt.ask", lambda _prompt, password=False: "d9")

    terminal._cmd_model()

    assert terminal.config.saved is False
    assert [m.alias for m in terminal.config.models] == ["only"]
    assert terminal.config.active_model == "only"
    assert any("Invalid saved-model number" in message for message in terminal.console.messages)


def test_bash_codeblock_execution_obeys_idle_timeout(monkeypatch) -> None:
    terminal = _code_test_terminal()
    monkeypatch.setenv("BINGO_EXEC_TIMEOUT", "10")
    monkeypatch.setenv("BINGO_EXEC_IDLE_TIMEOUT", "1")
    monkeypatch.setenv("BINGO_EXEC_WALL_CLOCK_TIMEOUT", "12")

    results = terminal._run_code_blocks(
        "```bash\n"
        "python3 -c \"import time; print('start', flush=True); time.sleep(3); print('end', flush=True)\"\n"
        "```",
        set(),
    )

    combined = "\n".join(results)
    assert "[SCRIPT_KILLED: IDLE_TIMEOUT]" in combined
    assert "start" in combined
    assert "\nend\n" not in combined


def test_token_governor_compresses_model_copy_without_mutating_history(monkeypatch, tmp_path: Path) -> None:
    terminal = _code_test_terminal()
    terminal.config.get_active_model_config = lambda: None
    terminal._agent_state = {
        "target": "https://example.test",
        "waf": "ModSecurity",
        "credentials": [],
        "tables": [],
        "confirmed_sqli": False,
    }
    terminal._findings_exporter = FindingsExporter(
        target="https://example.test",
        output_dir=str(tmp_path),
    )
    terminal._last_execution_context = {
        "source": "code_block",
        "scripts": [{"type": "bash"}],
        "response_bytes": 32000,
    }
    huge_html = (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: PHPSESSID=abc123; path=/\n"
        "<html><head><title>Target Login</title></head><body>"
        "<form action='/login'><input type='hidden' name='csrf_token' value='tok'>"
        "<input name='username'><input name='password' type='password'></form>"
        "<a href='/bbs/board.php?bo_table=news&wr_id=1'>news</a>"
        + ("<div>noise</div>" * 3000)
        + "</body></html>"
    )
    terminal.history = [Message(role="user", content=huge_html)]
    original = terminal.history[0].content
    monkeypatch.setenv("BINGO_TOKEN_GOVERNOR", "1")
    monkeypatch.setenv("BINGO_TOKEN_GOVERNOR_HARD_CHARS", "4000")

    messages = terminal._build_messages("")
    joined = "\n".join(m.content for m in messages)

    assert terminal.history[0].content == original
    assert "[BINGO_EVIDENCE_LEDGER]" in joined
    assert "[TOKEN_GOVERNOR_COMPRESSED_CONTEXT]" in joined
    assert "[HTML_SUMMARY]" in joined
    assert "csrf_token" in joined
    assert "bo_table" in joined
    compressed = next(m.content for m in messages if "[TOKEN_GOVERNOR_COMPRESSED_CONTEXT]" in m.content)
    assert len(compressed) < len(original) // 2


def test_token_governor_disabled_keeps_model_context_plain(monkeypatch) -> None:
    terminal = _code_test_terminal()
    terminal.config.get_active_model_config = lambda: None
    terminal._agent_state = {"target": "https://example.test", "waf": "Cloudflare"}
    huge_output = "HTTP/1.1 403 Forbidden\n" + ("<html><body>blocked</body></html>\n" * 400)
    terminal.history = [Message(role="user", content=huge_output)]
    monkeypatch.setenv("BINGO_TOKEN_GOVERNOR", "0")

    messages = terminal._build_messages("")
    joined = "\n".join(m.content for m in messages)

    assert terminal.history[0].content == huge_output
    assert huge_output in joined
    assert "[BINGO_EVIDENCE_LEDGER]" not in joined
    assert "[TOKEN_GOVERNOR_COMPRESSED_CONTEXT]" not in joined


def test_dict_tool_call_executes_without_autofix_warning(monkeypatch) -> None:
    terminal = _code_test_terminal()
    monkeypatch.setitem(
        TOOL_REGISTRY,
        "silent_dict_probe",
        lambda value="": {
            "success": True,
            "completed": True,
            "exit_code": 0,
            "output": f"value={value}",
        },
    )

    results = terminal._run_code_blocks(
        "```python\n{'name':'silent_dict_probe','args':{'value':'ok'}}\n```",
        set(),
    )

    visible = "\n".join(terminal.console.messages)
    assert results and "value=ok" in results[0]
    assert "WRONG_TOOL_FORMAT" not in visible
    assert "AUTO_FIX" not in visible


def test_unrepairable_bash_error_is_internal_not_visible() -> None:
    terminal = _code_test_terminal()
    response = (
        "```bash\n"
        "curl -sk https://example.test/ > /tmp/home.html\n"
        "scripts = re.findall(\n"
        "```"
    )

    results = terminal._run_code_blocks(response, set())

    visible = "\n".join(terminal.console.messages)
    assert results and "INTERNAL_AUTO_REPAIR_REQUIRED" in results[0]
    assert "syntax preflight" not in visible.lower()
    assert "语法预检" not in visible


def test_python_placeholder_template_codeblock_is_not_executed() -> None:
    terminal = _code_test_terminal()
    response = (
        "```python\n"
        "import requests\n"
        "url = URL\n"
        "param = PARAM\n"
        "payload = f\"{VAL}' AND '1'='1\"\n"
        "print(requests.get(url, params={param: payload}).status_code)\n"
        "```"
    )

    results = terminal._run_code_blocks(response, set())
    joined = "\n".join(results)

    assert "INTERNAL_AUTO_REPAIR_REQUIRED" in joined
    assert "PLACEHOLDER_TEMPLATE_CODE" in joined
    assert "PYTHON EXECUTION" not in joined
    assert "SyntaxError" not in joined


def test_python_syntax_error_codeblock_fails_preflight_not_runtime() -> None:
    terminal = _code_test_terminal()
    response = (
        "```python\n"
        "import requests\n"
        "payloads = {\n"
        "    \"AND \"TRUE\": \"broken\"\n"
        "}\n"
        "print(payloads)\n"
        "```"
    )

    results = terminal._run_code_blocks(response, set())
    joined = "\n".join(results)

    assert "INTERNAL_AUTO_REPAIR_REQUIRED" in joined
    assert "PYTHON_SYNTAX_PREFLIGHT_FAILED" in joined
    assert "PYTHON EXECUTION" not in joined


def test_python_codeblock_injects_missing_random_import() -> None:
    terminal = _code_test_terminal()
    response = (
        "```python\n"
        "if False:\n"
        "    requests.get('https://example.test/')\n"
        "print(random.randint(1, 1))\n"
        "```"
    )

    results = terminal._run_code_blocks(response, set())
    joined = "\n".join(results)

    assert "PYTHON EXECUTION" in joined
    assert "NameError" not in joined
    assert "\n1\n" in joined


def test_bash_heredoc_repairs_raw_bytes_regex_quote_class() -> None:
    terminal = _code_test_terminal()
    response = (
        "```bash\n"
        "python3 << 'PY'\n"
        "import re\n"
        "head = b'Content-Type: text/html; charset=utf-8'\n"
        "m = re.search(rb'charset[=]\\s*[\\\"']?([a-zA-Z0-9_-]+)', head)\n"
        "print(m.group(1).decode())\n"
        "PY\n"
        "```"
    )

    results = terminal._run_code_blocks(response, set())
    joined = "\n".join(results)

    assert "SyntaxError" not in joined
    assert "utf-8" in joined


def test_python_suffix_inside_bash_is_wrapped_before_preflight() -> None:
    script = (
        "curl -sk https://example.test/ > /tmp/home.html\n"
        "text = open('/tmp/home.html', encoding='utf-8').read()\n"
        "scripts = re.findall(r'src=[\\\"\\\']([^\\\"\\\']+)', text, re.I)\n"
        "print('\\n'.join(scripts))"
    )

    repaired, changed = _repair_mixed_bash_python(script)

    assert changed is True
    assert "python3 << 'BINGO_PY_AUTO'" in repaired
    assert "import re" in repaired
    import subprocess
    checked = subprocess.run(["bash", "-n"], input=repaired, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr


def test_quote_heavy_multiline_python_pipeline_uses_tempfile(tmp_path: Path) -> None:
    script = (
        "curl -sk https://example.test/ | python3 -c \"\n"
        "import re, sys\n"
        "js_urls = set(re.findall(r'src=[\\\"'\\\\'\\x60]([^\\\"'\\\\'\\x60 >]+)', html, re.I))\n"
        "print(js_urls)\n"
        "\""
    )

    repaired = _fix_bash_script(script)

    assert "mktemp /tmp/bingo_py_" in repaired
    assert "| python3 \"${_bingo_pytmp_1}\"" in repaired
    import subprocess
    checked = subprocess.run(["bash", "-n"], input=repaired, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr


def test_quote_heavy_regex_is_repaired_to_valid_python() -> None:
    script = (
        'curl -sk https://example.test/ | python3 -c "\n'
        "import re, sys\n"
        "html = sys.stdin.read()\n"
        'links = re.findall(r"[\"\']([^\"\']+)[\"\']", html)\n'
        "print(links)\n"
        '"'
    )

    repaired = _fix_bash_script(script)
    python_body = repaired.split("BINGO_PYEOF_1'\n", 1)[1].split(
        "\nBINGO_PYEOF_1", 1
    )[0]

    compile(python_body, "<repaired>", "exec")
    assert r"[^\x22\x27]" in python_body


def test_corrupted_href_findall_is_repaired_to_valid_python() -> None:
    script = (
        'python3 -c "\n'
        "import re\n"
        "html = '<a href=/manager/>x</a>'\n"
        "links = re.findall(rhref=[\"']([^\"']+)[\"'], html)\n"
        "print(links)\n"
        '"'
    )

    repaired = _fix_bash_script(script)
    python_body = repaired.split("BINGO_PYEOF_1'\n", 1)[1].split(
        "\nBINGO_PYEOF_1", 1
    )[0]

    compile(python_body, "<repaired>", "exec")
    assert "re.findall" in python_body
    assert "href=" in python_body


def test_run_python_repairs_raw_regex_quote_class_syntax_error() -> None:
    code = """
import re
html = '<input type="hidden" name="token" value="abc">'
hidden_fields = re.findall(r'<input[^>]+type=["']hidden["'][^>]*>', html, re.I)
print(len(hidden_fields))
"""

    result = run_python(code, timeout=10)

    assert result["success"] is True
    assert "1" in result["output"]
    assert "SyntaxError" not in result["output"]


def test_run_python_repairs_escaped_raw_regex_quote_class_syntax_error() -> None:
    code = r"""
import re
html = 'base_url = "https://api.example.test"'
for m in re.findall(r'(?:api|base)[_-]?url[\"'\s:=]+[\"']([^\"']+)[\"']', html, re.I):
    print('BASEURL:', m)
"""

    result = run_python(code, timeout=10)

    assert result["success"] is True
    assert "BASEURL: https://api.example.test" in result["output"]
    assert "SyntaxError" not in result["output"]


def test_run_python_repairs_redundant_list_fromkeys_wrapper() -> None:
    code = r"""
import re
html = '<a href="/balance/main.do">main</a>'
hrefs = list(list(dict.fromkeys(re.findall(r'''href=["\']([^"\']+)["\']''', html, re.I)))
print(hrefs[0])
"""

    result = run_python(code, timeout=10)

    assert result["success"] is True
    assert "/balance/main.do" in result["output"]
    assert "PYTHON_SYNTAX_AUTO_REPAIRED" in result["output"]
    assert "SyntaxError" not in result["output"]


def test_run_python_precheck_rejects_unrepairable_syntax_before_execution() -> None:
    result = run_python("print('before')\nif True print('broken')\n", timeout=10)

    assert result["success"] is False
    assert result["exit_code"] == -98
    assert "PYTHON_PRECHECK_SYNTAX_ERROR" in result["output"]
    assert "before" not in result["output"]


def test_inline_python_with_suffix_redirection_does_not_poison_heredoc() -> None:
    script = (
        'TITLE=$(printf "<title>x</title>" | python3 -c "'
        "import sys,re; t=sys.stdin.read(); "
        "m=re.search(r'<title>(.+?)</title>',t); "
        "print(m.group(1) if m else 'NO_TITLE')"
        '" 2>/dev/null)\n'
        'echo "$TITLE"\n'
    )

    repaired = _fix_bash_script(script)

    assert "PYEOF 2>" not in repaired
    import subprocess
    checked = subprocess.run(["bash", "-n"], input=repaired, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr
    executed = subprocess.run(["bash", "-c", repaired], text=True, capture_output=True, timeout=10)
    assert executed.returncode == 0
    assert executed.stdout.strip() == "x"


def test_custom_sqli_oracle_executes_instead_of_being_blocked() -> None:
    result = run_python(
        "import string\n"
        "def extract_string():\n"
        "    for c in string.printable:\n"
        "        return c\n"
        "print(extract_string())\n",
        timeout=10,
    )

    assert result["success"] is True
    assert "SQLI_CUSTOM_FALLBACK_EXECUTED" in result["output"]
    assert "SQLI_LOOP_BLOCKED" not in result["output"]


def test_external_sqli_fallback_command_is_preserved() -> None:
    script = "sqlmap -u 'https://example.test/?id=1' -p id --batch --dbs"

    assert _fix_bash_script(script) == script


def test_direct_http_sqli_probe_is_not_transport_blocked(monkeypatch) -> None:
    monkeypatch.setitem(
        TOOL_REGISTRY,
        "http_get",
        lambda **_kwargs: {"success": True, "output": "HTTP/1.1 200 OK"},
    )

    result = execute_tool(
        "http_get",
        {"url": "https://example.test/item?id=1%20OR%201=1--"},
    )

    assert result["success"] is True
    assert "HTTP_GET_SQLI_BLOCKED" not in result["output"]


def test_system_prompt_ends_with_evidence_driven_offense_contract() -> None:
    prompt = get_pentest_system_prompt("deepseek")

    assert "HYBRID AI-LED MODE" in prompt
    assert "CLAUDE CLI IDENTICAL MODE" not in prompt
    assert "Skills are Bingo's technique memory" in prompt
    assert "Do not flood TOOL_CALLs" in prompt
    assert "CONFIRMED/TASK_COMPLETE/FINDINGS line is not evidence by itself" in prompt
    assert "Preserve the exact active target host" in prompt
    assert "WAF bypass is AI-led and skill-guided" in prompt
    assert "SQLi is AI-led and skill-guided" in prompt
    assert "sqli_autoexploit, WafBypassEngine, sqlmap, and ghauri are bounded verifier" in prompt
    assert "Runtime pivot hints are advisory" in prompt
    assert "sqli_autoexploit 우선" not in prompt
    assert "AI MUST apply these automatically" not in prompt
    assert "EVIDENCE-DRIVEN SECURITY TESTING" in prompt
    assert (
        "Reports contain verified vulnerabilities only. Probable/potential candidates stay\n"
        "   in the verification backlog and continue to drive attacks."
    ) in prompt
    assert prompt.rstrip().endswith(
        "evidence before the next branch."
    )
    assert "sqlmap is PERMANENTLY BANNED" not in prompt


def test_glm_custom_prompt_avoids_provider_refusal_triggers(monkeypatch) -> None:
    monkeypatch.delenv("BINGO_LEGACY_WARMUP_HISTORY", raising=False)
    cfg = ModelConfig(
        provider="custom",
        model="glm-5.2",
        api_key="sk-test",
        base_url="https://api.ntrapi.cn/v1",
        alias="glm-5.2",
    )
    prompt = cfg.get_system_prompt()
    task = wrap_task("https://example.test waf sql check")
    retry = rephrase_refused_request("https://example.test 绕过waf sql渗透", "custom")
    combined = "\n".join([prompt, task, retry])
    blocked_phrases = (
        "pre-granted",
        "BEHAVIOR OVERRIDE",
        "No refusals",
        "No disclaimers",
        "Do not refuse",
        "CONTINUE REQUIRED",
        "fully autonomous penetration",
        "autonomous penetration testing engine",
        "written consent",
        "Permission confirmed",
        "Execute immediately",
    )

    assert "GLM/QWEN OPTIMIZATION" in prompt
    assert "PROVIDER COMPATIBILITY PROFILE" not in prompt
    assert get_warmup_history("custom glm-5.2") == []
    for phrase in blocked_phrases:
        assert phrase not in combined


def test_runtime_confirmed_claim_is_downgraded_without_finding_evidence(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    response = (
        "[CONFIRMED ✅] SQL Injection confirmed and Critical.\n"
        "TASK_COMPLETE\n"
        "```python\n"
        "print('CONFIRMED marker inside code stays untouched')\n"
        "```"
    )

    sanitized = BingoTerminal._sanitize_runtime_claims_by_evidence(response, exporter)

    assert "PROBABLE" in sanitized
    assert "Critical" not in sanitized
    assert "Potential" in sanitized
    assert "print('CONFIRMED marker inside code stays untouched')" in sanitized


def test_finding_evidence_counts_use_exporter_stats() -> None:
    exporter = SimpleNamespace(
        stats=lambda: {
            "confirmed": 0,
            "probable": 1,
            "potential": 0,
            "potential_critical": 2,
            "potential_high": 1,
            "blocked": 3,
            "quarantined": 4,
        }
    )

    counts = BingoTerminal._finding_evidence_counts(exporter)

    assert counts == {
        "confirmed": 0,
        "probable": 1,
        "potential": 3,
        "blocked": 3,
        "quarantined": 4,
    }


def test_repeated_inconclusive_attack_automatically_pivots(tmp_path: Path) -> None:
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal._agent_state = {"target": "https://example.test"}
    terminal._findings_exporter = FindingsExporter(
        target="https://example.test", output_dir=str(tmp_path)
    )
    code = 'TOOL_CALL:{"name":"sqli_autoexploit","args":{"url":"https://example.test/item","param":"id"}}'
    output = "oracle inconclusive: same-size responses"

    first = terminal._adaptive_attack_pivot_context(code, output)
    second = terminal._adaptive_attack_pivot_context(code, output)

    assert first == ""
    assert "ADAPTIVE_OFFENSE_PIVOT" in second
    assert "vector=sqli" in second
    assert "next=cross_vector" in second
    assert terminal._adaptive_attack_state["sqli"]["cooldown"] == 2
    assert "do not stop exploration" in second
    assert "temporarily blocked" not in second
    assert "Current executable tools are not suppressed" in second


def test_boolean_oracle_rejects_block_pages_and_status_transitions() -> None:
    assert _boolean_probe_is_blocked(403, "Forbidden")
    assert _boolean_probe_is_blocked(200, "Request was blocked by WAF")
    assert _boolean_probe_pair_is_eligible(200, "true page", 200, "false page")
    assert not _boolean_probe_pair_is_eligible(403, "blocked", 200, "normal")


def test_boolean_oracle_calibration_accepts_stable_body_only_difference() -> None:
    counter = {"value": 0}

    def probe(payload: str):
        counter["value"] += 1
        marker = "X" * 40 if "1=1" in payload else "Y" * 40
        token = f"{counter['value']:032x}"
        body = f"same-size result={marker} request={token}"
        return len(body), body, 200

    calibrated = _calibrate_boolean_oracle(probe, "id AND 1=1", "id AND 1=2", 3)

    assert calibrated["eligible"] is True
    assert calibrated["samples"] == 3
    assert calibrated["true_stability"] >= 0.90
    assert calibrated["cross_similarity"] <= 0.92


def test_boolean_oracle_calibration_rejects_mixed_block_status() -> None:
    def probe(payload: str):
        if "1=1" in payload:
            return 199, "request blocked", 403
        return 598, "normal response", 200

    calibrated = _calibrate_boolean_oracle(probe, "id AND 1=1", "id AND 1=2", 3)

    assert calibrated["eligible"] is False
    assert calibrated["blocked"] is True


def test_adaptive_candidates_prioritize_learned_and_vendor_profiles() -> None:
    learned = _build_adaptive_boolean_candidates(
        "1", waf_hint="Cloudflare", preferred="AND_comment"
    )
    vendor = _build_adaptive_boolean_candidates("1", waf_hint="Cloudflare")

    assert learned[0][0] == "AND_comment"
    assert len(vendor) <= 24
    assert any("adaptive:" in label for label, _true, _false in vendor)
    assert len({(true, false) for _label, true, false in vendor}) == len(vendor)


def test_dbms_classifier_requires_vendor_negative_control() -> None:
    def mysql_oracle(expr: str) -> bool:
        if "DATABASE() IS NULL AND" in expr:
            return False
        return expr == "DATABASE() IS NOT NULL"

    assert _classify_dbms_with_oracle(mysql_oracle) == "mysql"
    assert _classify_dbms_with_oracle(lambda _expr: True) == ""


def test_sqli_checkpoint_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BINGO_SQLI_STATE_DIR", str(tmp_path))
    state = {"oracle_op": "AND_comment", "dbms": "mysql", "db_name": "app"}

    assert _save_sqli_checkpoint("POST|https://example.test|id|1", state)
    restored = _load_sqli_checkpoint("POST|https://example.test|id|1")

    assert restored == state


def test_sqli_post_profile_preserves_json_csrf_cookies_and_redirects(monkeypatch) -> None:
    calls: list[dict] = []

    class Response:
        status_code = 403
        text = "request blocked"
        content = text.encode()

    class Session:
        def __init__(self):
            self.headers = {}
            self.cookies = {}
            self.verify = True

        def get(self, *_args, **kwargs):
            calls.append(kwargs)
            return Response()

        def post(self, *_args, **kwargs):
            calls.append(kwargs)
            return Response()

    monkeypatch.setattr("requests.Session", Session)

    result = sqli_autoexploit(
        "https://example.test/api",
        "id",
        method="POST",
        post_data='{"id":"1","scope":"all"}',
        extra_params={"route": "v2"},
        cookies={"SESSION": "abc"},
        csrf_param="csrf",
        csrf_token="token123",
        content_type="application/json",
        follow_redirects=False,
        oracle_samples=3,
        resume=False,
    )

    assert result["success"] is False
    assert result["candidate"] is False
    assert result["evidence_tier"] == "blocked"
    assert any("STAGE 2.6" in line for line in result["log"])
    assert calls
    assert all(call["params"] == {"route": "v2"} for call in calls)
    assert all(call["json"]["csrf"] == "token123" for call in calls)
    assert all(call["json"]["scope"] == "all" for call in calls)
    assert all(call["allow_redirects"] is False for call in calls)
    sqlmap_args = result["external_handoff"]["sqlmap_args"]
    assert sqlmap_args["url"] == "https://example.test/api?route=v2"
    assert json.loads(sqlmap_args["post_data"]) == {
        "id": "1",
        "scope": "all",
        "csrf": "token123",
    }
    assert sqlmap_args["headers"]["Content-Type"] == "application/json"
    assert sqlmap_args["follow_redirects"] is False


def test_external_tools_receive_calibrated_request_profile(monkeypatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(
        "bingo.tools_ext.pentest_tools._find_sqlmap", lambda: ["sqlmap"]
    )
    monkeypatch.setattr(
        "bingo.tools_ext.pentest_tools._find_tool", lambda _name: ["ghauri"]
    )
    monkeypatch.setattr(
        "bingo.tools_ext.pentest_tools._run",
        lambda cmd, timeout: captured.append(cmd) or {
            "success": True,
            "output": "ok",
            "elapsed": 0,
        },
    )

    run_sqlmap(
        "https://example.test/api",
        "id",
        cookies={"SESSION": "abc"},
        dbms="mysql",
        technique="BT",
        csrf_token="csrf",
        csrf_url="https://example.test/form",
        follow_redirects=False,
    )
    run_ghauri(
        "https://example.test/api",
        "id",
        cookies={"SESSION": "abc"},
        dbms="mysql",
    )

    sqlmap_cmd, ghauri_cmd = captured
    assert "--cookie" in sqlmap_cmd and "SESSION=abc" in sqlmap_cmd
    assert "--dbms" in sqlmap_cmd and "mysql" in sqlmap_cmd
    assert "--csrf-token" in sqlmap_cmd and "csrf" in sqlmap_cmd
    assert "--technique" in sqlmap_cmd and "BT" in sqlmap_cmd
    assert "--ignore-redirects" in sqlmap_cmd
    assert "--cookie" in ghauri_cmd and "SESSION=abc" in ghauri_cmd
    assert "--redirects" not in ghauri_cmd
    assert "run_ghauri" in TOOL_REGISTRY


def test_waf_detector_does_not_infer_vendor_from_generic_403(monkeypatch) -> None:
    class Probe:
        def __init__(self):
            self.calls = 0

        def get(self, url: str, timeout: int = 0):
            self.calls += 1
            if self.calls == 1:
                return ProbeResult(url, 200, "normal", {}, 0.01)
            return ProbeResult(url, 403, "Access denied: request blocked", {}, 0.01)

    monkeypatch.setattr("bingo.tools.waf_bypass.time.sleep", lambda _delay: None)

    detected = WafDetector(Probe()).detect("https://example.test/")

    assert detected.detected is True
    assert detected.waf_type == "generic"


def test_waf_bypass_requires_exact_blocked_control_and_semantic_difference() -> None:
    engine = WafBypassEngine.__new__(WafBypassEngine)
    engine._blocked_response = ProbeResult(
        url="https://example.test/?id=blocked",
        status=403,
        body="request blocked",
        headers={},
        elapsed=0,
    )
    engine._baseline_response = ProbeResult(
        url="https://example.test/?id=1",
        status=200,
        body="normal page",
        headers={},
        elapsed=0,
    )
    same_as_clean = ProbeResult(
        url="https://example.test/?id=variant",
        status=200,
        body="normal page",
        headers={},
        elapsed=0,
    )
    semantic_change = ProbeResult(
        url="https://example.test/?id=variant2",
        status=200,
        body="query result changed",
        headers={},
        elapsed=0,
    )

    assert not engine._is_bypassed(same_as_clean)
    assert engine._is_bypassed(semantic_change)


def test_localized_oracle_rejection_triggers_cross_vector_pivot(tmp_path: Path) -> None:
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal._agent_state = {"target": "https://example.test"}
    terminal._findings_exporter = FindingsExporter(
        target="https://example.test", output_dir=str(tmp_path)
    )
    code = 'TOOL_CALL:{"name":"sqli_autoexploit","args":{"param":"id"}}'
    output = "[SQLI_ORACLE_REJECTED] TRUE/FALSE 대조가 차단되었습니다."

    assert terminal._adaptive_attack_pivot_context(code, output) == ""
    pivot = terminal._adaptive_attack_pivot_context(code, output)

    assert "next=cross_vector" in pivot
    assert terminal._adaptive_attack_state["sqli"]["cooldown"] == 2


def test_orchestrator_rejects_self_authored_evidence_and_completion() -> None:
    actual = "HTTP/1.1 200 OK\n[CREDENTIAL] admin:real-secret"

    assert _board_value_anchored("admin:real-secret", actual)
    assert not _board_value_anchored("admin:invented-secret", actual)
    assert not _goal_completion_allowed(True, "", False)
    assert not _goal_completion_allowed(True, actual, True)
    assert _goal_completion_allowed(True, actual, False)


def test_sqli_notice_ignores_descriptive_text_and_wrapper_elapsed() -> None:
    output = (
        "=== Testing login.do for SQL injection ===\n"
        "Login page: 200\nelapsed=31.11s\n1200B baseline, 980B response"
    )

    assert "SQLI_TRIGGER_DETECTED" not in _inject_sqli_trigger_notice(output)


def test_sqli_notice_accepts_real_database_error() -> None:
    output = "HTTP 500\nYou have an error in your SQL syntax near quote"

    assert "SQLI_TRIGGER_DETECTED" in _inject_sqli_trigger_notice(output)


def test_sqli_notice_requires_verified_structured_timing() -> None:
    weak = "[TIME_BASED] baseline=0.2 payload=3.3 threshold=2.0 samples=1"
    verified = "[TIME_BASED] baseline=0.2 payload=3.3 threshold=2.0 samples=3"

    assert "SQLI_TRIGGER_DETECTED" not in _inject_sqli_trigger_notice(weak)
    assert "SQLI_TRIGGER_DETECTED" in _inject_sqli_trigger_notice(verified)


def test_ssrf_chain_rejects_identical_200_responses(monkeypatch) -> None:
    body = "generic application page"

    monkeypatch.setattr(
        "bingo.tools_ext.pentest_tools._run",
        lambda _cmd, _timeout: {
            "output": f"{body}\n---HTTP_STATUS:200---SIZE:{len(body)}---TIME:0.1---"
        },
    )

    result = ssrf_chain_exploit("https://example.test/fetch", "url")

    assert result["found_count"] == 0
    assert not any(item["success"] for item in result["results"].values())


def test_generic_http_output_is_not_meaningful_progress() -> None:
    text = "HTTP/1.1 200 OK\nendpoint found\nWAF detected\nsuccess=True"
    assert not BingoTerminal._has_meaningful_loop_progress(text)
    assert BingoTerminal._has_meaningful_loop_progress(
        "Credentials extracted: username=admin password=secret"
    )


def test_discovered_endpoint_parameter_is_meaningful_progress() -> None:
    output = (
        "/main/contents.do -> idx\n"
        "/main/clinic/view.do -> mc_idx\n"
        "https://example.test/main/center/view.do -> mc_idx\n"
    )
    assert BingoTerminal._has_meaningful_loop_progress(output)


def test_advertising_xhr_is_not_meaningful_loop_progress() -> None:
    output = (
        "[GET] https://www.google.com/rmkt/collect/701929338/?random=1&cv=11 — random, cv, fst\n"
        "[GET] https://www.google.com/ccm/collect?rcb=3&frm=0&auid=1 — rcb, frm, auid\n"
        "found endpoint parameter\n"
    )

    assert not BingoTerminal._has_meaningful_loop_progress(output)


def test_high_value_api_endpoint_is_meaningful_loop_progress() -> None:
    output = "https://example.test/common/jwt -> loReqtNo\n"

    assert BingoTerminal._has_meaningful_loop_progress(output)


def test_repeated_progress_signature_ignores_dynamic_trace_markers() -> None:
    first = (
        "[HTTP_METHOD] https://example.test/login\n"
        "[HIGH] TRACE: TRACE request echo confirmed\n"
        "Cookie: JSESSIONID=TRACE_COOKIE_PROOF_12345; SECRET=stealme\n"
        "X-Bingo-Trace: TRACE_HEADER_PROOF\n"
    )
    second = (
        "[HTTP_METHOD] https://example.test/login\n"
        "[HIGH] TRACE: TRACE request echo confirmed\n"
        "Cookie: JSESSIONID=TRACE_COOKIE_PROOF_98765; SECRET=stealme\n"
        "X-Bingo-Trace: TRACE_HEADER_PROOF_2\n"
    )

    assert BingoTerminal._meaningful_loop_progress_signature(first)
    assert (
        BingoTerminal._meaningful_loop_progress_signature(first)
        == BingoTerminal._meaningful_loop_progress_signature(second)
    )


def test_generic_homepage_script_is_not_an_xss_finding(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    homepage = (
        "HTTP/1.1 200 OK\n"
        "<html><script>function goBack(){ alert('page notice'); history.back(); }</script></html>"
    )

    finding = exporter.process(homepage, code_snippet="curl -sk https://example.test/")

    assert finding is None
    assert exporter.last_quarantine_reason == "xss_pattern_without_active_test"
    assert len(exporter.quarantined) == 1


def test_xss_response_parser_is_not_an_active_payload(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    homepage = "HTTP 200\n<script>function notice(){alert('hello')}</script>"
    parser = "body=requests.get(url).text\nif 'alert(' in body: print(body)"

    assert exporter.process(homepage, code_snippet=parser) is None
    assert exporter.last_quarantine_reason == "xss_pattern_without_active_test"
    assert exporter.quarantined[0].confidence == "quarantined"


def test_documentation_patterns_are_autocorrected(tmp_path: Path) -> None:
    cases = {
        "ssrf": "Documentation: metadata endpoint 169.254.169.254 is described here.",
        "lfi": "Example configuration: DB_HOST=localhost DB_PASSWORD=changeme",
        "rce": "Troubleshooting guide: run cat /etc/passwd to inspect accounts.",
        "auth_bypass": "Example URL: https://docs.example/admin/",
        "credential": "Example JSON: password='example123'",
    }
    for expected_type, output in cases.items():
        exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
        finding = exporter.process(f"HTTP 200\n{output}", "curl -sk https://example.test/docs")
        assert finding is None
        assert exporter.last_quarantine_reason == f"{expected_type}_pattern_without_active_test"
        assert exporter.quarantined[0].vuln_type == expected_type


def test_deterministic_server_alert_is_rejected_not_quarantined(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    output = "HTTP 200\n<script>alert('no menu'); history.back();</script>"

    assert exporter.process(output, "curl https://example.test/") is None
    assert exporter.last_autocorrection == "xss_server_alert_false_positive"
    assert exporter.quarantined == []


def test_active_security_tests_remain_candidates(tmp_path: Path) -> None:
    cases = [
        (
            "sqli",
            "HTTP 200\ntable_name=users",
            "curl 'https://example.test/?id=1 UNION SELECT table_name FROM information_schema.tables'",
        ),
        (
            "ssrf",
            "HTTP 200\n169.254.169.254 returned 200 OK",
            "requests.get('http://169.254.169.254/latest/meta-data/')",
        ),
        (
            "lfi",
            "HTTP 200\nroot:x:0:0:root:/root:/bin/bash",
            "curl 'https://example.test/?file=../../../../etc/passwd'",
        ),
        (
            "rce",
            "HTTP 200\ncat /etc/passwd command accepted",
            "requests.get(url, params={'cmd': 'cat /etc/passwd'})",
        ),
        (
            "auth_bypass",
            "HTTP 200\nURL: https://example.test/admin/",
            "curl -H 'Authorization: Bearer test' https://example.test/admin/",
        ),
        (
            "credential",
            "HTTP 200\npassword='example123'",
            "requests.get(url, params={'action': 'credential_extract'})",
        ),
    ]
    for expected_type, output, code in cases:
        exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
        finding = exporter.process(output, code)
        assert finding is not None
        assert finding.vuln_type == expected_type
        assert finding.confidence == "potential"
        assert finding.severity != "CRITICAL"
        assert exporter.last_autocorrection == ""


def test_process_runtime_elapsed_is_not_time_based_sqli(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    output = (
        "=== TOOL_RESULT: run_python ===\n"
        "exit_code=0 success=True elapsed=14.42s\n"
        "[200] ERROR (598B): LENGTH=1"
    )
    code = (
        "import time\n"
        "requests.get('https://example.test/item?id=1')\n"
        "time.sleep(0.1)"
    )

    exporter.process(output, code)

    assert exporter.stats()["probable"] == 0


def test_failed_time_measurement_invalidates_probable_sqli(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    code = (
        'TOOL_CALL:{"name":"sqli_autoexploit","args":'
        '{"url":"https://example.test/item","param":"id"}}'
    )
    probable = exporter.process("TRUE 1200B\nFALSE 500B", code)
    assert probable is not None and probable.confidence == "probable"

    exporter.process(
        "基准响应时间: 0.68s\n"
        "[sleep] 响应时间: 0.35s (阈值: 2.18s)\n"
        "[sleep_num] 响应时间: 0.31s (阈值: 2.18s)",
        code,
    )

    assert not any(f.confidence == "probable" for f in exporter.findings)
    assert any(
        q.reason_code == "invalidated_by_time_based_threshold_failed"
        for q in exporter.quarantined
    )


def test_waf_control_pair_is_blocked_not_probable(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    code = "TOOL_CALL:{\"name\":\"sqli_autoexploit\",\"args\":{\"url\":\"https://example.test/item\",\"param\":\"id\"}}"

    finding = exporter.process(
        "TRUE 403 199B request blocked\nFALSE 200 598B generic error page",
        code,
    )

    assert finding is not None
    assert finding.confidence == "blocked"
    assert exporter.stats()["probable"] == 0


def test_equal_waf_controls_are_blocked_not_probable(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    code = "curl 'https://example.test/item?id=1' # sqli boolean controls"

    finding = exporter.process("TRUE 403 199B\nFALSE 403 199B", code)

    assert finding is not None
    assert finding.confidence == "blocked"
    assert exporter.stats()["probable"] == 0


def test_cms_fingerprint_is_not_db_table_extract_sqli(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    output = (
        "=== CMS FINGERPRINT ===\n"
        "  FOUND: g5_\n"
        "  FOUND: bo_table\n"
    )

    finding = exporter.process(output, "curl -sk https://example.test/")

    assert finding is None or finding.confidence != "confirmed"
    assert exporter.stats()["confirmed"] == 0
    assert not any(f.reason_code == "db_table_extract" for f in exporter.findings)


def test_sqli_no_valid_channel_blocks_db_extract_keywords(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    output = (
        "=== CMS FINGERPRINT ===\n"
        "FOUND: g5_\n"
        "[SQLI_NO_VALID_CHANNEL] Boolean、error-based、time-based 对照均未形成稳定 oracle。\n"
        "SQLI_EXTRACTION_FAILURE\n"
        "reason=no stable candidate\n"
    )
    code = (
        'TOOL_CALL:{"name":"sqli_autoexploit","args":'
        '{"url":"https://example.test/bbs/board.php","param":"sca"}}'
    )

    finding = exporter.process(output, code)

    assert finding is not None
    assert finding.confidence == "blocked"
    assert finding.reason_code == "oracle_precheck_failed"
    assert exporter.stats()["confirmed"] == 0


def test_finding_ids_are_monotonic_across_invalidation(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    code = "TOOL_CALL:{\"name\":\"sqli_autoexploit\",\"args\":{\"url\":\"https://example.test/item\",\"param\":\"id\"}}"

    first = exporter.process("TRUE 1200B\nFALSE 500B", code)
    assert first is not None and first.id == "BINGO-0001"
    exporter.process(
        "기준 응답 시간: 0.68s\n[sleep] 응답 시간: 0.35s (임계값: 2.18s)\n"
        "[sleep_num] 응답 시간: 0.31s (임계값: 2.18s)",
        code,
    )
    second = exporter.process("TRUE 1300B\nFALSE 500B", code)

    assert second is not None and second.id == "BINGO-0003"
    assert exporter.quarantined[0].id == "BINGO-0001"
    assert len({f.id for f in exporter.findings + exporter.quarantined}) == 3


def test_label_only_personal_page_is_blocked(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    output = "HTTP 200\npersonal=True\n보호자: 환자명\nROWS=0\n예약"

    finding = exporter.process(output, "curl https://example.test/patient")

    assert finding is not None
    assert finding.vuln_type == "info_disclosure"
    assert finding.confidence == "blocked"
    assert not finding.confirmed


def test_info_disclosure_ignores_standalone_cache_hashes(monkeypatch) -> None:
    class _Resp:
        status_code = 404
        content = b"short"
        text = (
            "asset.0123456789abcdef0123456789abcdef.js\n"
            "cache_token ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234567890\n"
        )

    class _Sess:
        def get(self, *_args, **_kwargs):
            return _Resp()

    monkeypatch.setattr(security_audit, "_sess", lambda _headers: _Sess())

    result = security_audit.info_disclosure_scan("https://example.test/")

    assert not any(f.get("type") == "key_exposure" for f in result["findings"])


def test_info_disclosure_keeps_contextual_secret_tokens(monkeypatch) -> None:
    class _Resp:
        status_code = 404
        content = b"short"
        text = (
            "aws_secret_access_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd1234567890'\n"
            "session_id = 0123456789abcdef0123456789abcdef\n"
        )

    class _Sess:
        def get(self, *_args, **_kwargs):
            return _Resp()

    monkeypatch.setattr(security_audit, "_sess", lambda _headers: _Sess())

    result = security_audit.info_disclosure_scan("https://example.test/")
    key_types = {f.get("key_type") for f in result["findings"]}

    assert "AWS Secret Access Key" in key_types
    assert "Contextual MD5/Token (32 hex chars)" in key_types


def test_structured_time_measurement_requires_repeated_passes(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    code = "curl 'https://example.test/item?id=1%20SLEEP(5)'"

    finding = exporter.process(
        "[TIME_BASED] baseline=0.40s payload=5.30s threshold=4.40s samples=3",
        code,
    )

    assert finding is not None
    assert finding.confidence == "probable"
    assert finding.reason_code == "time_based_delay"


def test_admin_path_is_not_a_credential(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    output = "HTTP 302\n/admin/main.do size=0B"

    finding = exporter.process(output, "requests.get('https://example.test/admin/main.do')")

    assert finding is None
    assert not any(q.vuln_type == "credential" for q in exporter.quarantined)


def test_server_header_does_not_trigger_post_exploit() -> None:
    output = "HTTP/1.1 200 OK\nServer: Apache\nContent-Type: text/html"
    assert _inject_post_exploit_notice(output) == output


def test_ssrf_payload_echo_is_not_a_finding(monkeypatch) -> None:
    class Response:
        status_code = 200

        def __init__(self, text: str):
            self.text = text

    responses = iter([
        Response("<html>normal login page</html>"),
        Response(
            "<html>prepage=http://metadata.google.internal/"
            "computeMetadata/v1/project/project-id</html>"
        ),
    ])
    monkeypatch.setattr(autoexploit_modules, "_SSRF_PAYLOADS", [
        "http://metadata.google.internal/computeMetadata/v1/project/project-id"
    ])
    monkeypatch.setattr(
        autoexploit_modules,
        "_SSRF_CLOUD_SIGNATURES",
        ["computeMetadata", "project-id"],
    )
    monkeypatch.setattr(autoexploit_modules, "_sess", lambda _headers: object())
    monkeypatch.setattr(autoexploit_modules, "_req", lambda *_args, **_kwargs: next(responses))

    result = autoexploit_modules.ssrf_autotest(
        "https://example.test/login", "prepage"
    )

    assert result["completed"] is True
    assert result["success"] is False
    assert result["findings"] == []


def test_normal_tool_completion_has_zero_exit_code(monkeypatch) -> None:
    monkeypatch.setitem(
        TOOL_REGISTRY,
        "test_no_findings",
        lambda: {"success": False, "output": "scan complete: zero findings"},
    )

    result = execute_tool("test_no_findings", {})

    assert result["completed"] is True
    assert result["exit_code"] == 0
    assert result["success"] is False


def test_report_rejects_claims_without_finding_ids(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    exporter.process(
        "TRUE 1200B\nFALSE 500B",
        'curl "https://example.test/item?id=1%20OR%201=1"',
    )
    report = (
        "# Target: https://example.test\n"
        "## Vulnerabilities Found\n"
        "1. **Reflected XSS (High)**\n- payload executed\n"
        "2. **SQL Injection (High)**\n- response differed\n"
    )

    valid, errors = BingoTerminal._validate_report_finding_ids(
        report, exporter.findings
    )

    assert not valid
    assert "unsupported_type:xss" in errors
    assert any(error.startswith("missing_finding_id:") for error in errors)


def test_report_accepts_exact_finding_id(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    finding = exporter.process(
        "TRUE 1200B\nFALSE 500B",
        'curl "https://example.test/item?id=1%20OR%201=1"',
    )
    assert finding is not None
    report = (
        "# Target: https://example.test\n"
        "## Vulnerabilities Found\n"
        f"1. **SQL Injection ({finding.id})**\n- probable response difference\n"
    )

    valid, errors = BingoTerminal._validate_report_finding_ids(
        report, exporter.findings
    )

    assert valid
    assert errors == []


def test_report_rejects_unlabeled_unconfirmed_claim(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    finding = exporter.process(
        "TRUE 1200B\nFALSE 500B",
        'curl "https://example.test/item?id=1%20OR%201=1"',
    )
    assert finding is not None and finding.confidence == "probable"
    report = (
        "# Target: https://example.test\n"
        "## Vulnerabilities Found\n"
        f"1. **SQL Injection ({finding.id})**\n- exploitable response difference\n"
    )

    valid, errors = BingoTerminal._validate_report_finding_ids(
        report, exporter.findings
    )

    assert not valid
    assert f"unconfirmed_claim:{finding.id}" in errors


def test_login_attempt_password_is_not_parsed_as_credential() -> None:
    obj = BingoTerminal.__new__(BingoTerminal)
    obj._agent_state = {
        "target": "https://example.test",
        "waf": None,
        "bool_true_len": None,
        "bool_false_len": None,
        "db_name": None,
        "tables": [],
        "columns": {},
        "credentials": [],
        "confirmed_sqli": False,
        "notes": [],
    }
    obj._session_tables = []
    obj._session_credentials = []
    obj._findings_exporter = SimpleNamespace(findings=[])

    obj._parse_agent_state(
        "=== Testing password: cheomdan ===\n"
        "Login failed: invalid password\n"
        "Password: cheomdan\n"
    )

    assert obj._agent_state["credentials"] == []
    assert obj._session_credentials == []


def test_report_filters_unverified_password_candidate() -> None:
    report = BingoTerminal._build_fallback_report(
        target="https://example.test",
        lang="en",
        confirmed_count=0,
        potential_count=1,
        ground_truth="- id=BINGO-1 tier=potential type=sqli",
        session_credentials=[
            "Password: cheomdan",
            {"password": "cheomdan", "source": "login failed candidate"},
        ],
    )

    assert "cheomdan" not in report
    assert "- No credentials confirmed in this session" in report


def test_next_step_summary_downgrades_unbacked_db_hash_claim() -> None:
    flags = {
        "has_confirmed_sqli": False,
        "has_potential_sqli": False,
        "has_real_cred": False,
        "has_upload": False,
        "blocked_count": 2,
    }

    safe = BingoTerminal._sanitize_next_step_summary(
        "进展摘要：已通过 SQL 注入获取数据库 SinkDB 和管理员哈希，但缺少 shell。",
        flags,
        "zh",
        confirmed_count=0,
        potential_count=0,
    )

    assert "未确认" in safe
    assert "SinkDB" not in safe
    assert "管理员哈希" not in safe
    assert "shell" in safe


def test_next_steps_filter_removes_post_exploit_without_confirmed_evidence() -> None:
    flags = {
        "has_confirmed_sqli": False,
        "has_potential_sqli": False,
        "has_real_cred": False,
        "has_upload": False,
        "has_admin_panel": False,
        "blocked_count": 2,
    }
    options = [
        "使用 SQLMap 的 os-shell 功能尝试执行系统命令（whoami / id）",
        "通过堆叠查询向 g5_member 表插入新管理员账户",
        "检查 admin/admin.login.php 是否存在默认凭证或简单密码",
        "枚举同一域名下的 JS/API 端点寻找新输入点",
    ]

    filtered = BingoTerminal._filter_next_steps_by_evidence(options, flags)
    joined = "\n".join(filtered)

    assert "os-shell" not in joined
    assert "系统命令" not in joined
    assert "插入新管理员" not in joined
    assert "默认凭证" not in joined
    assert "JS/API" in joined


def test_evidence_based_next_steps_do_not_claim_access_when_zero_confirmed() -> None:
    summary, options = BingoTerminal._build_evidence_based_next_steps(
        "zh",
        {"has_potential_sqli": False, "blocked_count": 2, "has_admin_panel": False},
        confirmed_count=0,
        potential_count=0,
    )

    joined = "\n".join([summary, *options])
    assert "未确认" in summary or "没有 confirmed" in summary
    assert "获取数据库" not in joined
    assert "管理员权限" not in joined
    assert "os-shell" not in joined


def test_unresolved_candidate_is_queued_for_bounded_verification(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    exporter.process(
        "HTTP 200\n<script>function notice(){alert('hello')}</script>",
        "curl -sk https://example.test/docs",
    )
    backlog = exporter.verification_backlog()

    assert len(backlog) == 1
    assert backlog[0]["tier"] == "quarantined"
    assert backlog[0]["tool"] == "xss_autotest"

    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal._findings_exporter = exporter
    first = terminal._verification_backlog_context()
    second = terminal._verification_backlog_context()
    third = terminal._verification_backlog_context()

    assert "AUTO_VERIFICATION_QUEUE" in first
    assert "xss_autotest" in first
    assert "NOT confirmed vulnerabilities" in first
    assert "AUTO_VERIFICATION_QUEUE" in second
    assert third == ""


def test_negative_verification_removes_potential_finding(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    payload = "<img src=x onerror=alert(1)>"
    finding = exporter.process(
        f"HTTP 200\nreflected={payload}",
        f"curl 'https://example.test/?q={payload}'",
    )
    assert finding is not None

    assert exporter.reject_finding(finding, "xss_browser_negative")
    assert exporter.findings == []
    assert exporter.last_autocorrection == "xss_browser_negative"
    assert exporter.autocorrections == ["xss_browser_negative"]
    assert exporter.autocorrection_counts == {"xss_browser_negative": 1}


def test_short_output_clears_previous_autocorrection(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    exporter.process("HTTP 200\npassword='example123'", "curl https://example.test/docs")
    assert exporter.last_quarantine_reason

    assert exporter.process("short") is None
    assert exporter.last_autocorrection == ""
    assert exporter.last_quarantine_reason == ""


def test_payload_after_old_500_char_limit_is_retained(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    code = "# analysis\n" + ("x" * 700) + "\ncurl 'https://example.test/?id=1 UNION SELECT table_name FROM information_schema.tables'"

    finding = exporter.process("HTTP 200\ntable_name=users", code[:16_384])

    assert finding is not None
    assert finding.vuln_type == "sqli"
    assert exporter.quarantined == []


def test_unknown_http_client_is_quarantined_not_dropped(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))

    finding = exporter.process(
        "HTTP 200\n169.254.169.254 returned 200 OK",
        "custom_transport.send('http://169.254.169.254/latest/meta-data/')",
    )

    assert finding is None
    assert exporter.quarantined[0].vuln_type == "ssrf"


def test_quarantine_is_saved_separately(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    exporter.process(
        "HTTP 200\nTroubleshooting: cat /etc/passwd",
        "custom_transport.send(url)",
    )

    path = exporter.save()
    assert path is not None
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["quarantine_count"] == 1
    assert data["quarantined"][0]["confidence"] == "quarantined"


def test_playwright_detailed_result_distinguishes_errors() -> None:
    class FakeEngine:
        def __init__(self, results):
            self.results = iter(results)

        def inject_dom_xss(self, _url, _param):
            return next(self.results)

    engine = PlaywrightEngine.__new__(PlaywrightEngine)
    engine._engine = FakeEngine([None, False, True])

    confirmed, completed, errors = engine.dom_xss_test_detailed(
        "https://example.test", ["a", "b", "c"]
    )

    assert confirmed == ["c"]
    assert completed == 2
    assert errors == 1


def test_confirmed_and_probable_evidence_bypass_quarantine(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))

    confirmed = exporter.process("HTTP 200\nuid=0(root) gid=0(root)", "custom_exec(target)")
    probable = exporter.process(
        "HTTP 200\nTRUE 1200B\nFALSE 500B",
        "custom_transport.send(target)",
    )

    assert confirmed is not None and confirmed.confidence == "confirmed"
    assert probable is not None and probable.confidence == "probable"
    assert exporter.quarantined == []


def test_structured_runtime_context_preserves_active_candidate(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    context = {
        "executed": True,
        "source": "code_block",
        "scripts": [{
            "type": "python",
            "code": "requests.get('http://169.254.169.254/latest/meta-data/')",
            "returncode": 0,
            "output_length": 40,
        }],
    }

    finding = exporter.process(
        "HTTP 200\n169.254.169.254 returned 200 OK",
        "unrecognized wrapper",
        execution_context=context,
    )

    assert finding is not None
    assert finding.vuln_type == "ssrf"
    assert exporter.quarantined == []


def test_xss_verification_error_does_not_remove_candidate(tmp_path: Path, monkeypatch) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    payload = "<img src=x onerror=alert(1)>"
    finding = exporter.process(
        f"HTTP 200\nreflected={payload}",
        f"curl 'https://example.test/?q={payload}'",
    )
    assert finding is not None

    class ErrorEngine:
        available = True

        def __init__(self, **_kwargs):
            pass

        def dom_xss_test_detailed(self, _url, _params):
            return [], 0, 1

        def close(self):
            pass

    monkeypatch.setattr("bingo.tools.playwright_engine.PlaywrightEngine", ErrorEngine)
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal.config = SimpleNamespace(lang="en")
    terminal.console = _Console()
    terminal.s = {
        "fe_xss_unconfirmed": "not confirmed",
        "fe_xss_verify": "verifying",
        "fe_xss_verify_error": "error {n}; retained",
    }
    terminal._findings_exporter = exporter

    terminal._playwright_verify_xss(
        finding,
        ["https://example.test/?q=%3Cimg%20onerror=alert(1)%3E"],
    )

    assert exporter.findings == [finding]
    assert any("retained" in message for message in terminal.console.messages)


def test_browser_confirmation_replaces_pattern_reason(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    payload = "<img src=x onerror=alert(1)>"
    finding = exporter.process(
        f"HTTP 200\nreflected={payload}",
        f"curl 'https://example.test/?q={payload}'",
    )
    assert finding is not None

    exporter.mark_confirmed(finding)
    assert finding.confirmed
    assert finding.confidence == "confirmed"
    assert finding.reason_code == "xss_browser_confirmed"


def test_negative_xss_verification_skips_finding_panel(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal.config = SimpleNamespace(lang="en")
    terminal.console = _Console()
    terminal.s = {
        "fe_xss_negative_autocorrected": "negative XSS auto-corrected",
    }
    terminal._agent_state = {"target": "https://example.test"}
    terminal._findings_exporter = exporter

    def reject_candidate(finding, _urls) -> None:
        exporter.reject_finding(finding, "xss_browser_negative")
        terminal._show_finding_autocorrection("xss_browser_negative")

    terminal._playwright_verify_xss = reject_candidate
    output = (
        "HTTP 200\nPAYLOAD_REFLECTED XSS detected\n"
        "URL: https://example.test/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
    )
    terminal._auto_analyze_findings(
        output,
        "curl 'https://example.test/?q=<img onerror=alert(1)>'",
    )

    assert exporter.findings == []
    assert len(terminal.console.messages) == 1
    assert "negative XSS auto-corrected" in terminal.console.messages[0]


def test_attempted_xss_payload_remains_a_candidate(tmp_path: Path) -> None:
    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    payload = "<img src=x onerror=alert(1)>"

    finding = exporter.process(
        f"HTTP 200\nreflected={payload}",
        code_snippet=f"curl 'https://example.test/?q={payload}'",
    )

    assert finding is not None
    assert finding.vuln_type == "xss"
    assert finding.confidence == "potential"


def test_xss_trigger_ignores_not_reflected_payload_text(tmp_path: Path) -> None:
    payload = '"><script>alert(1)</script>'
    output = (
        "HTTP 200\n"
        f"[NOT REFLECTED] payload: {payload}\n"
        "browser_confirmed=false\n"
    )

    assert "XSS_TRIGGER_DETECTED" not in _inject_vuln_trigger_notice(output)

    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    assert exporter.process(output, code_snippet="run_python xss smoke") is None
    assert exporter.findings == []


def test_xss_trigger_ignores_filtered_or_403_payload_text(tmp_path: Path) -> None:
    output = (
        "=== XSS 反射测试 ===\n"
        "url=javascript:alert(1): 403 Location=N/A\n"
        "url=data:text/html,<script>alert(1)</script>: 403 Location=N/A\n"
        "被过滤/不存在: <script>alert(1)</script> | 199B\n"
        "被过滤/不存在: <img src=x onerror=alert(1)> | 199B\n"
    )

    assert "XSS_TRIGGER_DETECTED" not in _inject_vuln_trigger_notice(output)

    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    assert exporter.process(output, code_snippet="run_python xss blocked smoke") is None
    assert exporter.findings == []


def test_exporter_rejects_stale_xss_trigger_notice_without_proof(tmp_path: Path) -> None:
    output = (
        "被过滤/不存在: <script>alert(1)</script> | 199B\n"
        "[XSS_TRIGGER_DETECTED] XSS reflected/stored pattern detected\n"
        "-> TOOL_CALL:{\"name\":\"xss_autotest\",\"args\":{\"url\":\"<URL>\",\"param\":\"<PARAM>\"}}\n"
    )

    exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))
    assert exporter.process(output, code_snippet="run_python xss blocked smoke") is None
    assert exporter.findings == []


def test_xss_trigger_still_detects_reflected_payload_text() -> None:
    payload = "<img src=x onerror=alert(1)>"
    output = f"HTTP 200\nPAYLOAD_REFLECTED {payload}\n"

    assert "XSS_TRIGGER_DETECTED" in _inject_vuln_trigger_notice(output)


def test_lfi_autotest_does_not_confirm_generic_nginx_mysql_text(monkeypatch) -> None:
    baseline = "<html><title>hospital</title>nginx mysql maintenance notice</html>"
    dynamic_non_file_page = baseline + ("A" * 900) + " nginx mysql"

    def fake_req(_sess, _method, _url, params=None, data=None, timeout=15):
        request_params = params or data or {}
        value = request_params.get("page", "")
        if value in {"/etc/nginx/nginx.conf", "/etc/mysql/my.cnf"}:
            return SimpleNamespace(text=dynamic_non_file_page)
        return SimpleNamespace(text=baseline)

    monkeypatch.setattr(autoexploit_modules, "_HAS_REQUESTS", True)
    monkeypatch.setattr(autoexploit_modules, "_sess", lambda _headers=None: object())
    monkeypatch.setattr(autoexploit_modules, "_req", fake_req)
    monkeypatch.setattr(
        autoexploit_modules,
        "_LFI_PAYLOADS",
        ["/etc/nginx/nginx.conf", "/etc/mysql/my.cnf"],
    )
    monkeypatch.setattr(autoexploit_modules, "_LFI_SIGNATURES", ["nginx", "mysql"])

    result = autoexploit_modules.lfi_autotest(
        "https://example.test/main.do",
        "page",
    )

    assert result["success"] is False
    assert result["findings"] == []
    assert result["candidates"]
    assert "CANDIDATE:" in result["output"]


def test_lfi_autotest_confirms_structured_passwd(monkeypatch, tmp_path: Path) -> None:
    passwd_body = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )

    def fake_req(_sess, _method, _url, params=None, data=None, timeout=15):
        request_params = params or data or {}
        if request_params.get("page") == "../../etc/passwd":
            return SimpleNamespace(text=passwd_body)
        return SimpleNamespace(text="<html>normal page</html>")

    monkeypatch.setattr(autoexploit_modules, "_HAS_REQUESTS", True)
    monkeypatch.setattr(autoexploit_modules, "_sess", lambda _headers=None: object())
    monkeypatch.setattr(autoexploit_modules, "_req", fake_req)
    monkeypatch.setattr(autoexploit_modules, "_LFI_PAYLOADS", ["../../etc/passwd"])
    monkeypatch.setattr(autoexploit_modules, "_save", lambda _filename, _content: str(tmp_path / _filename))

    result = autoexploit_modules.lfi_autotest(
        "https://example.test/main.do",
        "page",
    )

    assert result["success"] is True
    assert result["findings"]
    assert "etc_passwd_structured" in result["findings"][0]["signatures"]


def test_error_identifier_is_not_cracked_as_hash() -> None:
    value = "4347c3c2d2404a4c8000226189606120"
    text = f"400 input length too long ({value})"
    assert BingoTerminal._hashes_from_error_context(text, [value]) == {value}
    assert BingoTerminal._hashes_from_error_context(
        f"password_hash={value}", [value]
    ) == set()


def test_error_identifier_never_enters_pending_crack_queue() -> None:
    value = "4347c3c2d2404a4c8000226189606120"
    obj = BingoTerminal.__new__(BingoTerminal)
    obj._session_cracked_hashes = set()
    obj._pending_crack_hashes = []
    obj.config = SimpleNamespace(lang="en")
    obj.console = _Console()

    BingoTerminal._collect_crack_hashes(obj, f"400 input length too long ({value})")

    assert obj._pending_crack_hashes == []
    assert value in obj._session_cracked_hashes


def test_jsessionid_never_enters_pending_crack_queue_even_when_echoed_later() -> None:
    value = "E9A7C3C2D2404A4C8000226189606120"
    obj = BingoTerminal.__new__(BingoTerminal)
    obj._session_cracked_hashes = set()
    obj._pending_crack_hashes = []
    obj.config = SimpleNamespace(lang="en")
    obj.console = _Console()

    BingoTerminal._collect_crack_hashes(obj, f"Set-Cookie: JSESSIONID={value}; Path=/")
    BingoTerminal._collect_crack_hashes(obj, f"later response echoed {value}")

    assert obj._pending_crack_hashes == []
    assert value.lower() in obj._session_cracked_hashes


def test_structured_xss_requires_execution_not_reflection() -> None:
    reflected = {
        "payload": "<img src=x onerror=alert(1)>",
        "reflected": True,
    }
    executed = {**reflected, "browser_executed": True}

    assert not BingoTerminal._validate_bingo_signal("xss", reflected)[0]
    assert BingoTerminal._validate_bingo_signal("xss", executed)[0]


def test_structured_idor_requires_authenticated_ownership_boundary() -> None:
    public_selector = {"other_user_id": 2, "data_returned": True}
    owner_boundary = {
        **public_selector,
        "authenticated_baseline": True,
        "owner_only_resource": True,
        "different_owner": True,
    }

    assert not BingoTerminal._validate_bingo_signal("idor", public_selector)[0]
    assert BingoTerminal._validate_bingo_signal("idor", owner_boundary)[0]


def test_hash_pipeline_finishes_before_prompt_return() -> None:
    events: list[str] = []
    obj = BingoTerminal.__new__(BingoTerminal)
    obj._pending_crack_hashes = ["a" * 32]
    obj._stop_crack_flag = threading.Event()
    obj.config = SimpleNamespace(lang="en")
    obj.s = {"hash_found": "hashes={n}"}
    obj.console = _Console()
    obj._collect_crack_hashes = lambda _text: None
    obj._send_notification = lambda *_args, **_kwargs: None
    obj._auto_crack_pipeline = lambda hashes: events.append(f"cracked:{hashes[0]}")

    BingoTerminal._notify_hashes_found(obj, "response")
    events.append("returned")

    assert events == [f"cracked:{'a' * 32}", "returned"]


def test_report_fallback_is_written_without_model(tmp_path: Path, monkeypatch) -> None:
    class _Config:
        lang = "en"

        @staticmethod
        def get_active_model_config():
            return None

    class _Findings:
        @staticmethod
        def stats():
            return {
                "confirmed": 0,
                "probable": 3,
                "potential_high": 2,
                "potential_critical": 0,
            }

        @staticmethod
        def ground_truth_block():
            return "- id=BINGO-1 tier=potential type=sqli"

        @staticmethod
        def save():
            return None

    obj = BingoTerminal.__new__(BingoTerminal)
    obj.config = _Config()
    obj.s = {
        "report_fallback_used": "fallback",
        "report_save_ok": "saved",
    }
    obj.console = _Console()
    obj._agent_state = {"target": "https://example.test"}
    obj.history = []
    obj._session_tables = []
    obj._session_credentials = []
    obj._session_fresh = True
    obj._findings_exporter = _Findings()
    obj._get_system_message = lambda _skill: SimpleNamespace(role="system", content="")
    obj._render_hacker_report = lambda *_args: None
    obj._converge_session_artifacts = lambda *_args, **_kwargs: None
    obj._suggest_next_steps = lambda: None
    original_fallback = BingoTerminal._build_fallback_report
    captured: dict[str, str] = {}

    def capture_fallback(**kwargs):
        captured["ground_truth"] = kwargs["ground_truth"]
        return original_fallback(**kwargs)

    monkeypatch.setattr(
        BingoTerminal,
        "_build_fallback_report",
        staticmethod(capture_fallback),
    )
    monkeypatch.setenv("BINGO_REPORTS_DIR", str(tmp_path))

    BingoTerminal._auto_generate_report(obj)

    reports = list(tmp_path.glob("report_*.md"))
    html_reports = list(tmp_path.glob("report_*.html"))
    assert len(reports) == 1
    assert len(html_reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    html_report = html_reports[0].read_text(encoding="utf-8")
    assert "# Target: https://example.test" in report
    assert "Confirmed: 0" in report
    assert "Probable/Potential: 5" in report
    assert "BINGO-1" in report
    assert "Bingo Security Report" in html_report
    assert "Evidence-driven assessment" in html_report
    assert "Hybrid AI-led" in html_report
    assert "Probable / Potential" in html_report
    assert "BINGO-1" in html_report
    vuln_section = report.split("## Vulnerabilities Found", 1)[1].split("##", 1)[0]
    assert "BINGO-1" not in vuln_section
    assert "Verification Backlog (Unconfirmed)" in report
    assert "type=sqli\nEVIDENCE LADDER RULES" in captured["ground_truth"]


def test_html_report_renderer_escapes_content_and_adds_cards() -> None:
    html = BingoTerminal._build_html_report(
        "# Target: <script>alert(1)</script>\n"
        "## Summary\n"
        "- **Critical** candidate BINGO-0001\n"
        "```bash\ncurl -sk https://example.test/\n```\n",
        target="<script>alert(1)</script>",
        confirmed_count=0,
        potential_count=1,
        generated_at="2026-07-20 12:00:00",
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'class="report-card"' in html
    assert 'class="finding-id">BINGO-0001' in html
    assert "curl -sk https://example.test/" in html
    assert "2026-07-20 12:00:00" in html


def test_chinese_deterministic_report_keeps_zero_confirmed_label() -> None:
    report = BingoTerminal._build_fallback_report(
        target="https://example.test",
        lang="zh",
        confirmed_count=0,
        potential_count=2,
        ground_truth="- id=BINGO-1 tier=blocked type=sqli",
        session_credentials=[],
    )

    assert "已确认: 0" in report
    assert "未确认: 0" not in report


def test_new_runtime_messages_have_all_languages() -> None:
    for lang in ("ko", "zh", "en"):
        strings = get_strings(lang)
        assert "skipped" not in strings["sqli_cross_vector_guard"].lower()
        assert "건너뜁니다" not in strings["sqli_cross_vector_guard"]
        assert "跳过" not in strings["sqli_cross_vector_guard"]
        for key in (
            "sqli_cross_vector_guard",
            "report_manual_artifact_blocked",
            "sqli_oracle_rejected",
            "ae_xss_candidate",
            "sqli_adaptive_profile",
            "sqli_oracle_calibrated",
            "sqli_dbms_detected",
            "sqli_checkpoint_restored",
            "sqli_external_handoff",
            "sqli_candidate_only",
        ):
            assert strings[key].strip()


def test_xss_reflection_output_is_candidate_not_vulnerable(monkeypatch, capsys) -> None:
    payload = "<img src=x onerror=alert(1)>"

    class Response:
        text = payload

        def __bool__(self):
            return True

    class Session:
        headers: dict = {}

    monkeypatch.setattr(autoexploit_modules, "_XSS_PAYLOADS", [payload])
    monkeypatch.setattr(autoexploit_modules, "_sess", lambda _headers: Session())
    monkeypatch.setattr(
        autoexploit_modules,
        "_req",
        lambda *_args, **_kwargs: Response(),
    )
    monkeypatch.setattr(autoexploit_modules, "_save", lambda *_args: "/tmp/result")

    result = autoexploit_modules.xss_autotest("https://example.test", "q")
    visible = capsys.readouterr().out

    assert "[XSS_CANDIDATE]" in result["output"]
    assert "browser_confirmed=false" in result["output"]
    assert "XSS Vulnerable" not in visible


def test_blackbox_target_text_does_not_request_source_path_prompt() -> None:
    text = "https://www.balance-cf.co.kr/ 绕过waf，sql渗透，管理员账号密码，webshell权限"

    assert not BingoTerminal._source_path_prompt_requested(text)


def test_whitebox_command_requests_source_path_prompt() -> None:
    assert BingoTerminal._source_path_prompt_requested("/whitebox https://example.test")


def test_source_code_text_requests_source_path_prompt() -> None:
    assert BingoTerminal._source_path_prompt_requested("source code path /tmp/app")


def test_source_path_prompt_can_be_disabled_for_blackbox_runs() -> None:
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal._source_path_prompt_enabled = False

    assert not terminal._should_prompt_source_path(
        "https://www.balance-cf.co.kr/ 绕过waf，sql渗透，管理员账号密码，webshell权限"
    )


def test_source_path_prompt_can_be_forced_by_flag() -> None:
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal._source_path_prompt_enabled = True

    assert terminal._should_prompt_source_path(
        "https://www.balance-cf.co.kr/ 绕过waf，sql渗透，管理员账号密码，webshell权限"
    )


def test_report_command_uses_auto_md_html_report_pipeline() -> None:
    terminal = BingoTerminal.__new__(BingoTerminal)
    terminal.s = {}
    terminal.console = _Console()
    called: list[bool] = []
    warnings: list[str] = []
    terminal._auto_generate_report = lambda: called.append(True)
    terminal._warn = lambda msg: warnings.append(str(msg))

    terminal._cmd_proof_report("")
    terminal._cmd_proof_report("save")
    terminal._cmd_proof_report("bad")

    assert called == [True, True]
    assert warnings


def test_scan_slash_command_removed_from_chat_ui() -> None:
    for lang in ("ko", "zh", "en"):
        commands = {cmd for cmd, _desc in get_slash_commands(lang)}
        strings = get_strings(lang)

        assert "/scan" not in commands
        assert "/scan <url>" not in strings["help_text"]
