from __future__ import annotations

import threading
import json
from pathlib import Path
from types import SimpleNamespace

from bingo.ui.terminal import BingoTerminal
from bingo.tools.findings_exporter import FindingsExporter
from bingo.tools.playwright_engine import PlaywrightEngine


class _Console:
    file = SimpleNamespace(flush=lambda: None)

    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, *args, **_kwargs) -> None:
        self.messages.append(" ".join(str(arg) for arg in args))


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
