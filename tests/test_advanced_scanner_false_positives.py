from __future__ import annotations

from typing import Any

from bingo.tools_ext import pentest_tools
from bingo.tools_ext.builtin import advanced_scanners
from bingo.tools_ext.builtin import vuln_scanner_plus
from bingo.ui.terminal import BingoTerminal


class FakeResponse:
    def __init__(
        self,
        text: str = "",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.content = text.encode()


class FakeSession:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.headers: dict[str, str] = {}
        self.verify = False
        self.cookies: dict[str, str] = {}

    def get(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.handler("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.handler("POST", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> FakeResponse:
        return self.handler("OPTIONS", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        return self.handler(method.upper(), url, **kwargs)


def test_tech_fingerprint_prefers_java_cookie_and_do_extension(monkeypatch) -> None:
    def handler(_method: str, _url: str, **_kwargs: Any) -> FakeResponse:
        return FakeResponse(
            "<html><script src='/assets/app.php'></script></html>",
            cookies={"JSESSIONID": "abc"},
        )

    monkeypatch.setattr(advanced_scanners, "_sess", lambda _headers=None: FakeSession(handler))

    result = advanced_scanners.tech_fingerprint("https://example.test/main.do")

    assert result["backend"] == "java"
    assert result["confidence"]["java"] > result["confidence"].get("php", 0)


def test_shellshock_colon_heavy_html_is_not_confirmed(monkeypatch) -> None:
    colon_page = "<html><style>a:b;c:d;e:f;g:h</style><body>normal</body></html>"

    def handler(_method: str, _url: str, **_kwargs: Any) -> FakeResponse:
        return FakeResponse(colon_page)

    monkeypatch.setattr(advanced_scanners, "_sess", lambda _headers=None: FakeSession(handler))

    result = advanced_scanners.cve_scan("https://example.test/")

    assert result["success"] is False
    assert not any(f.get("cve") == "CVE-2014-6271" for f in result["findings"])


def test_http_method_403_is_blocked_not_put_delete_allowed(monkeypatch) -> None:
    def handler(method: str, _url: str, **_kwargs: Any) -> FakeResponse:
        if method == "OPTIONS":
            return FakeResponse("Forbidden", 403, headers={"Allow": "GET, POST, PUT, DELETE"})
        return FakeResponse("Forbidden", 403)

    monkeypatch.setattr(advanced_scanners, "_sess", lambda _headers=None: FakeSession(handler))

    result = advanced_scanners.http_method_scan("https://example.test/resource")

    assert result["success"] is False
    assert result["findings"] == []
    assert "PUT" not in result["allowed_methods"]
    assert "DELETE" not in result["allowed_methods"]


def test_param_fuzz_ignores_large_page_small_volatility(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(_method: str, _url: str, **kwargs: Any) -> FakeResponse:
        calls["n"] += 1
        if kwargs.get("params") or kwargs.get("data"):
            return FakeResponse("A" * 240210)
        return FakeResponse("A" * (240000 + (calls["n"] % 3) * 75))

    monkeypatch.setattr(advanced_scanners, "_sess", lambda _headers=None: FakeSession(handler))

    result = advanced_scanners.param_fuzz(
        "https://example.test/list",
        wordlist=["id", "page", "q"],
        max_params=3,
    )

    assert result["success"] is False
    assert result["found_params"] == []


def test_api_rate_limit_probe_is_observation_not_vulnerability(monkeypatch) -> None:
    def handler(_method: str, url: str, **_kwargs: Any) -> FakeResponse:
        if "/api/" in url or url.endswith("/health") or url.endswith("/status"):
            return FakeResponse("not found", 404)
        return FakeResponse("OK " * 30, 200)

    monkeypatch.setattr(advanced_scanners, "_sess", lambda _headers=None: FakeSession(handler))

    result = advanced_scanners.api_security_scan("https://example.test/login")

    assert result["success"] is False
    assert result["findings"] == []
    assert result["observations"]
    assert result["observations"][0]["evidence_tier"] == "observation"


def test_header_original_url_homepage_response_is_not_bypass(monkeypatch) -> None:
    homepage = "<html><head><meta http-equiv='refresh'></head><body>home</body></html>"

    def handler(method: str, url: str, **kwargs: Any) -> FakeResponse:
        headers = kwargs.get("headers") or {}
        if method == "GET" and url.endswith("/admin"):
            return FakeResponse("Forbidden", 403)
        if headers.get("X-Original-URL") == "/admin":
            return FakeResponse(homepage, 200)
        return FakeResponse(homepage, 200)

    monkeypatch.setattr(vuln_scanner_plus, "_sess", lambda _headers=None: FakeSession(handler))

    result = vuln_scanner_plus.header_injection_scan("https://example.test/")

    assert result["success"] is False
    assert not any(f.get("type") == "url_override" for f in result["findings"])


def test_sqli_post_without_body_get_profile_is_corrected_and_semantic_fail_dedup(monkeypatch) -> None:
    pentest_tools._SEMANTIC_ATTACK_LEDGER.clear()

    def fake_sqli_autoexploit(
        url: str,
        param: str,
        method: str = "GET",
        extra_params: dict | None = None,
    ) -> dict:
        return {
            "success": False,
            "evidence_tier": "none",
            "output": f"method={method} param={param} SQLI_EXTRACTION_FAILURE",
        }

    monkeypatch.setitem(pentest_tools.TOOL_REGISTRY, "sqli_autoexploit", fake_sqli_autoexploit)

    first = pentest_tools.execute_tool(
        "sqli_autoexploit",
        {
            "url": "https://example.test/search.do?idx=1",
            "param": "idx",
            "method": "POST",
            "extra_params": {"page": "1"},
        },
    )
    second = pentest_tools.execute_tool(
        "run_bash",
        {"script": "curl 'https://example.test/search.do?idx=%27%20AND%201%3D1--'"},
    )

    assert first["request_profile_corrected"] is True
    assert "method=GET" in first["output"]
    assert second["exit_code"] == -94
    assert "SEMANTIC_DEDUP_SKIP" in second["output"]

    pentest_tools._SEMANTIC_ATTACK_LEDGER.clear()


def test_fallback_report_no_backlog_has_no_probable_retest_recommendation() -> None:
    report = BingoTerminal._build_fallback_report(
        target="https://example.test",
        lang="en",
        confirmed_count=0,
        potential_count=0,
        ground_truth="- (none)",
        session_credentials=[],
    )

    assert "Re-test probable" not in report
    assert "No verified vulnerabilities" in report
