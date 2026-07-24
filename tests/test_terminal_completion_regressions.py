from __future__ import annotations

import threading
import json
from pathlib import Path
from types import SimpleNamespace

from bingo.ui.terminal import (
    BingoTerminal,
    _normalize_tool_call_response,
    _repair_mixed_bash_python,
)
from bingo.lang.strings import get_strings
from bingo.tools.findings_exporter import FindingsExporter
from bingo.tools.playwright_engine import PlaywrightEngine
from bingo.core.execution_anchor import ExecutionAnchorEngine, _has_exec_evidence
from bingo.core.zero_hal_v5 import ZeroHalEngine
from bingo.models.system_prompt import get_pentest_system_prompt
from bingo.orchestrator.engine import _board_value_anchored, _goal_completion_allowed
from bingo.tools_ext import autoexploit_modules
from bingo.tools_ext.pentest_tools import (
    TOOL_REGISTRY,
    _fix_bash_script,
    _inject_post_exploit_notice,
    _inject_sqli_trigger_notice,
    execute_tool,
    run_python,
    ssrf_chain_exploit,
)


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

    assert prompt.rstrip().endswith(
        "Reports contain verified vulnerabilities only. Probable/potential candidates stay\n"
        "   in the verification backlog and continue to drive attacks."
    )
    assert "sqlmap is PERMANENTLY BANNED" not in prompt


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
    assert "next=error" in second
    assert "do not repeat the same request" in second


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
            return "- id=BINGO-1 tier=potential type=sqli\n"

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
    monkeypatch.setenv("BINGO_REPORTS_DIR", str(tmp_path))

    BingoTerminal._auto_generate_report(obj)

    reports = list(tmp_path.glob("report_*.md"))
    assert len(reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    assert "# Target: https://example.test" in report
    assert "Confirmed: 0" in report
    assert "Probable/Potential: 5" in report
    assert "BINGO-1" in report
    vuln_section = report.split("## Vulnerabilities Found", 1)[1].split("##", 1)[0]
    assert "BINGO-1" not in vuln_section
    assert "Verification Backlog (Unconfirmed)" in report
