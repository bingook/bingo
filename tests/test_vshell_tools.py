from __future__ import annotations

import base64

import httpx

from bingo.tools_ext import vshell_tools
from bingo.tools_ext.pentest_tools import TOOL_REGISTRY, execute_tool
from bingo.tools_ext.vshell_tools import VshellClient, VshellConfig
from bingo.models.system_prompt import get_pentest_system_prompt


def _config() -> VshellConfig:
    return VshellConfig(
        url="https://vshell.test",
        token="test-token",
        basic_auth="Basic dGVzdDp0ZXN0",
        verify_tls=True,
        tunnel_host="vshell.test",
    )


def _client(handler) -> VshellClient:
    return VshellClient(_config(), transport=httpx.MockTransport(handler))


def test_vshell_has_no_embedded_credentials(monkeypatch) -> None:
    for name in ("VSHELL_URL", "VSHELL_TOKEN", "VSHELL_BASICAUTH"):
        monkeypatch.delenv(name, raising=False)

    result = vshell_tools.vshell_diagnose()

    assert result["success"] is False
    assert result["completed"] is False
    assert "VSHELL_TOKEN" in result["output"]


def test_vshell_client_sends_dual_auth_and_compact_json() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers["Authorization"]
        captured["token"] = request.headers["Token"]
        captured["body"] = request.content
        return httpx.Response(200, json={"code": 0, "result": {"ok": True}})

    client = _client(handler)
    try:
        payload = client.post("/api/test", {"id": "7", "command": "whoami"})
    finally:
        client.close()

    assert payload["code"] == 0
    assert captured == {
        "authorization": "Basic dGVzdDp0ZXN0",
        "token": "test-token",
        "body": b'{"id":"7","command":"whoami"}',
    }


def test_exec_cmd_returns_exact_agent_evidence_without_neighbor_retry(monkeypatch) -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"code": 0, "result": "C:\\Users\\tester>whoami\r\nlab\\tester\r\n"},
        )

    client = _client(handler)
    monkeypatch.setattr(vshell_tools, "_get_client", lambda: client)
    try:
        result = vshell_tools.vshell_exec_cmd(41, "whoami")
    finally:
        client.close()

    assert result["success"] is True
    assert result["evidence"]["client_id"] == 41
    assert "[VSHELL_EXEC_EVIDENCE] client_id=41" in result["output"]
    assert "lab\\tester" in result["output"]
    assert len(requests) == 1
    assert b'"id":"41"' in requests[0].content


def test_api_error_is_not_reported_as_success(monkeypatch) -> None:
    client = _client(lambda _request: httpx.Response(200, json={"code": 403, "message": "token expired"}))
    monkeypatch.setattr(vshell_tools, "_get_client", lambda: client)
    try:
        result = vshell_tools.vshell_server_info()
    finally:
        client.close()

    assert result["success"] is False
    assert result["completed"] is True
    assert result["evidence"]["authenticated_response"] is True
    assert "token expired" in result["output"]


def test_read_file_decodes_base64_and_marks_truncation(monkeypatch) -> None:
    encoded = base64.b64encode(b"alpha-beta-gamma").decode()
    client = _client(lambda _request: httpx.Response(200, json={"code": 0, "result": {"content": encoded}}))
    monkeypatch.setattr(vshell_tools, "_get_client", lambda: client)
    try:
        result = vshell_tools.vshell_read_file(7, "/tmp/result.txt", max_bytes=5)
    finally:
        client.close()

    assert result["success"] is True
    assert result["data"]["content"] == "alpha"
    assert result["data"]["truncated"] is True
    assert "[VSHELL_FILE_EVIDENCE]" in result["output"]


def test_async_dispatch_does_not_claim_execution(monkeypatch) -> None:
    client = _client(lambda _request: httpx.Response(200, json={"code": 0, "result": None}))
    monkeypatch.setattr(vshell_tools, "_get_client", lambda: client)
    try:
        result = vshell_tools.vshell_exec_async(9, "long-running-task")
    finally:
        client.close()

    assert result["success"] is True
    assert result["data"]["queued"] is True
    assert result["evidence"]["execution_confirmed"] is False


def test_vshell_tools_are_registered_and_execute_contract_is_preserved(monkeypatch) -> None:
    expected = {
        "vshell_diagnose",
        "vshell_exec_cmd",
        "vshell_read_file",
        "vshell_start_socks5",
        "vshell_tunnel_http",
        "vshell_tunnel_curl",
        "vshell_download_from_agent",
    }
    assert expected <= TOOL_REGISTRY.keys()

    monkeypatch.setattr(
        vshell_tools,
        "vshell_server_info",
        lambda: {"success": True, "completed": True, "exit_code": 0, "output": "ok"},
    )
    monkeypatch.setitem(TOOL_REGISTRY, "vshell_test_contract", vshell_tools.vshell_server_info)
    result = execute_tool("vshell_test_contract", {})

    assert result["success"] is True
    assert result["completed"] is True
    assert result["exit_code"] == 0


def test_deploy_can_execute_an_existing_remote_tool(monkeypatch) -> None:
    client = _client(lambda _request: httpx.Response(200, json={"code": 0, "result": "uid=0(root)"}))
    monkeypatch.setattr(vshell_tools, "_get_client", lambda: client)
    try:
        result = vshell_tools.vshell_deploy_tool(12, remote_path="/tmp/fscan", exec_args="-h 10.0.0.0/24")
    finally:
        client.close()

    assert result["success"] is True
    assert result["evidence"]["client_id"] == 12
    assert "uid=0(root)" in result["output"]


def test_start_tunnel_uses_server_inventory_for_auto_port(monkeypatch) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.content))
        if request.url.path == "/api/tunnel/list":
            client_id = b'"ClientId":5' in request.content
            items = (
                [{"Id": 91, "ClientId": 5, "Port": 10801, "RunStatus": False}]
                if client_id
                else [{"Id": 90, "ClientId": 3, "Port": 10800, "RunStatus": True}]
            )
            return httpx.Response(200, json={"code": 0, "result": {"items": items}})
        return httpx.Response(200, json={"code": 0, "result": None})

    client = _client(handler)
    monkeypatch.setattr(vshell_tools, "_get_client", lambda: client)
    try:
        result = vshell_tools.vshell_start_socks5(5)
    finally:
        client.close()

    assert result["success"] is True
    assert result["data"]["port"] == 10801
    assert result["data"]["proxy_url"] == "socks5h://vshell.test:10801"
    assert any(path == "/api/tunnel/start" for path, _body in calls)


def test_system_prompt_uses_vshell_without_replacing_existing_attack_path() -> None:
    prompt = get_pentest_system_prompt("deepseek")

    assert "VSHELL POST-EXPLOITATION CHAIN" in prompt
    assert "Never guess or increment a client_id" in prompt
    assert "must not stop the existing direct exploitation" in prompt
    assert "vshell_exec_cmd" in prompt
