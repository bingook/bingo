"""Native Vshell C2 tools for Bingo's evidence-driven tool pipeline.

The adapter intentionally implements the Vshell HTTP contract directly instead
of embedding an MCP server.  Bingo's TOOL_REGISTRY is synchronous, so native
sync functions avoid returning un-awaited coroutines and keep tool results in
the same structured format as the rest of Bingo.
"""
from __future__ import annotations

import base64
import json
import os
import posixpath
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..i18n import t


class VshellError(RuntimeError):
    """A sanitized configuration, transport, or API contract error."""


def _msg(key: str, default: str, **values: Any) -> str:
    text = t(key, default)
    try:
        return text.format(**values)
    except (KeyError, ValueError):
        return default.format(**values)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


@dataclass(frozen=True, slots=True)
class VshellConfig:
    """Runtime-only Vshell connection settings.

    Credentials are deliberately not given defaults and are never included in
    tool results.  Environment variables allow operators to use their existing
    secret management without committing tokens to Bingo.
    """

    url: str
    token: str
    basic_auth: str
    verify_tls: bool = True
    tunnel_host: str = ""
    yakit_proxy: str = "http://127.0.0.1:8081"

    @classmethod
    def from_env(cls) -> "VshellConfig":
        url = os.environ.get("VSHELL_URL", "").strip().rstrip("/")
        token = os.environ.get("VSHELL_TOKEN", "").strip()
        basic_auth = os.environ.get("VSHELL_BASICAUTH", "").strip()
        if not url or not token or not basic_auth:
            raise VshellError(
                _msg(
                    "vshell_not_configured",
                    "Vshell is not configured. Set VSHELL_URL, VSHELL_TOKEN, and VSHELL_BASICAUTH.",
                )
            )
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise VshellError(_msg("vshell_invalid_url", "Invalid VSHELL_URL: {url}", url=url))
        if not basic_auth.lower().startswith("basic "):
            basic_auth = f"Basic {basic_auth}"
        return cls(
            url=url,
            token=token,
            basic_auth=basic_auth,
            verify_tls=_env_bool("VSHELL_VERIFY_TLS", True),
            tunnel_host=os.environ.get("VSHELL_TUNNEL_HOST", "").strip() or parsed.hostname,
            yakit_proxy=os.environ.get("YAKIT_PROXY", "http://127.0.0.1:8081").strip(),
        )

    def cache_key(self) -> tuple[str, str, str, bool, str, str]:
        return (
            self.url,
            self.token,
            self.basic_auth,
            self.verify_tls,
            self.tunnel_host,
            self.yakit_proxy,
        )


class VshellClient:
    """Synchronous, pooled Vshell API client with strict response validation."""

    def __init__(self, config: VshellConfig, transport: httpx.BaseTransport | None = None):
        self.config = config
        self._http = httpx.Client(
            base_url=config.url,
            headers={
                "Authorization": config.basic_auth,
                "Token": config.token,
                "Content-Type": "application/json;charset=UTF-8",
            },
            timeout=httpx.Timeout(30.0),
            verify=config.verify_tls,
            transport=transport,
        )

    def close(self) -> None:
        self._http.close()

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        try:
            kwargs: dict[str, Any] = {"timeout": max(1, min(int(timeout), 125))}
            if method.upper() != "GET":
                kwargs["content"] = json.dumps(body or {}, separators=(",", ":"))
            response = self._http.request(method, path, **kwargs)
            response.raise_for_status()
            payload = response.json()
        except httpx.TimeoutException as exc:
            raise VshellError(_msg("vshell_timeout", "Vshell request timed out: {path}", path=path)) from exc
        except httpx.HTTPStatusError as exc:
            raise VshellError(
                _msg(
                    "vshell_http_error",
                    "Vshell HTTP error {status}: {path}",
                    status=exc.response.status_code,
                    path=path,
                )
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise VshellError(
                _msg("vshell_connection_error", "Vshell connection failed: {error}", error=str(exc))
            ) from exc
        if not isinstance(payload, dict):
            raise VshellError(_msg("vshell_invalid_response", "Vshell returned a non-object response."))
        return payload

    def get(self, path: str, timeout: int = 30) -> dict[str, Any]:
        return self.request("GET", path, timeout=timeout)

    def post(self, path: str, body: dict[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
        return self.request("POST", path, body=body, timeout=timeout)

    def upload(self, client_id: int, local_path: str, remote_path: str, timeout: int = 120) -> dict[str, Any]:
        path = Path(local_path).expanduser()
        if not path.is_file():
            raise VshellError(_msg("vshell_file_missing", "Local file does not exist: {path}", path=local_path))
        headers = {
            "Authorization": self.config.basic_auth,
            "Token": self.config.token,
            "ignoreCancelToken": "true",
        }
        try:
            with path.open("rb") as handle:
                response = self._http.post(
                    "/api/file/upload",
                    headers=headers,
                    files={"file": (path.name, handle, "application/octet-stream")},
                    data={"id": str(client_id), "path": remote_path or path.name},
                    timeout=max(1, min(timeout, 300)),
                )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise VshellError(
                _msg("vshell_connection_error", "Vshell connection failed: {error}", error=str(exc))
            ) from exc
        except ValueError as exc:
            raise VshellError(_msg("vshell_invalid_response", "Vshell returned a non-object response.")) from exc
        if not isinstance(payload, dict):
            raise VshellError(_msg("vshell_invalid_response", "Vshell returned a non-object response."))
        return payload


_CLIENT_LOCK = threading.Lock()
_CLIENT: VshellClient | None = None
_CLIENT_KEY: tuple[str, str, str, bool, str, str] | None = None


def _get_client() -> VshellClient:
    global _CLIENT, _CLIENT_KEY
    config = VshellConfig.from_env()
    key = config.cache_key()
    with _CLIENT_LOCK:
        if _CLIENT is None or _CLIENT_KEY != key:
            if _CLIENT is not None:
                _CLIENT.close()
            _CLIENT = VshellClient(config)
            _CLIENT_KEY = key
        return _CLIENT


def _api_ok(payload: dict[str, Any]) -> bool:
    return payload.get("code") == 0 or payload.get("success") is True


def _api_message(payload: dict[str, Any]) -> str:
    return str(payload.get("message") or payload.get("msg") or "Vshell API rejected the request")


def _json_output(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def _success(
    operation: str,
    endpoint: str,
    data: Any = None,
    output: str = "",
    client_id: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    evidence = {
        "source": "vshell_api",
        "operation": operation,
        "endpoint": endpoint,
        "authenticated_response": True,
    }
    if client_id is not None:
        evidence["client_id"] = client_id
    result: dict[str, Any] = {
        "success": True,
        "completed": True,
        "exit_code": 0,
        "output": output or _json_output(data),
        "data": data,
        "evidence": evidence,
    }
    result.update(extra)
    return result


def _failure(operation: str, endpoint: str, error: str, completed: bool = True) -> dict[str, Any]:
    return {
        "success": False,
        "completed": completed,
        "exit_code": 1,
        "output": f"[VSHELL_ERROR] {error}",
        "error": error,
        "evidence": {
            "source": "vshell_api",
            "operation": operation,
            "endpoint": endpoint,
            "authenticated_response": completed,
        },
    }


def _call(operation: str, endpoint: str, fn: Any) -> tuple[VshellClient | None, dict[str, Any] | None, dict[str, Any] | None]:
    try:
        client = _get_client()
        payload = fn(client)
    except VshellError as exc:
        return None, None, _failure(operation, endpoint, str(exc), completed=False)
    if not _api_ok(payload):
        return client, payload, _failure(operation, endpoint, _api_message(payload))
    return client, payload, None


def _extract_terminal_output(raw: Any, command: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    # Remove only an exact echoed command line. Never guess a different Agent's
    # prompt or retry against a neighboring client id.
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.rstrip().endswith(command):
            lines = lines[index + 1 :]
            break
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)[-20000:]


def vshell_server_info() -> dict:
    """Read Vshell server health and online Agent counts from authenticated API evidence."""
    endpoint = "/api/dashboard/info"
    _, payload, failure = _call("server_info", endpoint, lambda c: c.get(endpoint, timeout=10))
    if failure:
        return failure
    data = payload.get("result") or {}
    return _success("server_info", endpoint, data=data)


def vshell_list_clients(status: str = "online") -> dict:
    """List Vshell Agents; status accepts online, offline, or all."""
    endpoint = "/api/client/list"
    normalized = status.strip().lower()
    status_value: bool | str = True if normalized in {"online", "true", "1"} else False if normalized in {"offline", "false", "0"} else ""
    _, payload, failure = _call(
        "list_clients",
        endpoint,
        lambda c: c.post(endpoint, {"page": 1, "pageSize": 9999, "status": status_value}, timeout=15),
    )
    if failure:
        return failure
    result = payload.get("result") or {}
    clients = result.get("items") or []
    data = {
        "clients": clients,
        "total": result.get("total", len(clients)),
        "online": result.get("clientOnlineCount"),
        "filter": normalized,
    }
    return _success("list_clients", endpoint, data=data, count=len(clients))


def vshell_exec_cmd(client_id: int, command: str, timeout: int = 30) -> dict:
    """Execute a command on one exact Vshell Agent and return authenticated raw evidence."""
    endpoint = "/api/terminal/shell"
    timeout = max(1, min(int(timeout), 120))
    _, payload, failure = _call(
        "exec_cmd",
        endpoint,
        lambda c: c.post(endpoint, {"id": str(client_id), "command": command}, timeout=timeout + 5),
    )
    if failure:
        return failure
    output = _extract_terminal_output(payload.get("result"), command)
    marker = f"[VSHELL_EXEC_EVIDENCE] client_id={client_id} endpoint={endpoint}"
    rendered = f"{marker}\n{output}" if output else f"{marker}\n(no output)"
    return _success(
        "exec_cmd",
        endpoint,
        data={"client_id": client_id, "command": command, "output": output},
        output=rendered,
        client_id=client_id,
        command=command,
    )


def vshell_exec_async(client_id: int, command: str) -> dict:
    """Queue a command on a Vshell Agent without treating dispatch as execution evidence."""
    endpoint = "/api/terminal/exec"
    _, payload, failure = _call(
        "exec_async",
        endpoint,
        lambda c: c.post(endpoint, {"clientId": client_id, "command": command}, timeout=15),
    )
    if failure:
        return failure
    data = {"client_id": client_id, "command": command, "queued": True, "api_result": payload.get("result")}
    result = _success("exec_async", endpoint, data=data, client_id=client_id)
    result["evidence"]["execution_confirmed"] = False
    return result


def vshell_get_disks(client_id: int) -> dict:
    """List disks or filesystem roots visible to a Vshell Agent."""
    endpoint = "/api/file/getdisk"
    _, payload, failure = _call("get_disks", endpoint, lambda c: c.post(endpoint, {"id": client_id}, timeout=15))
    if failure:
        return failure
    return _success("get_disks", endpoint, data=payload.get("result") or [], client_id=client_id)


def vshell_list_dir(
    client_id: int,
    path: str,
    page: int = 1,
    page_size: int = 100,
    sort_by: str = "time",
    sort_order: str = "descend",
) -> dict:
    """List a remote directory on a Vshell Agent."""
    endpoint = "/api/file/ls"
    body = {
        "page": max(1, page),
        "pageSize": max(1, min(page_size, 1000)),
        "id": client_id,
        "path": path,
        "field": sort_by if sort_by in {"name", "time", "size"} else "time",
        "order": sort_order if sort_order in {"ascend", "descend"} else "descend",
    }
    _, payload, failure = _call("list_dir", endpoint, lambda c: c.post(endpoint, body, timeout=15))
    if failure:
        return failure
    result = payload.get("result") or {}
    items = result.get("items") or []
    return _success(
        "list_dir",
        endpoint,
        data={"path": path, "items": items, "total": result.get("total", len(items))},
        client_id=client_id,
        count=len(items),
    )


def vshell_read_file(client_id: int, path: str, max_bytes: int = 102400) -> dict:
    """Read and decode a text file from a Vshell Agent with a bounded preview."""
    endpoint = "/api/file/cat"
    directory, filename = posixpath.split(path.replace("\\", "/"))
    if not filename:
        return _failure("read_file", endpoint, _msg("vshell_full_path_required", "A complete file path is required: {path}", path=path), completed=False)
    directory = directory or "/"
    _, payload, failure = _call(
        "read_file",
        endpoint,
        lambda c: c.post(endpoint, {"id": str(client_id), "path": directory, "target": filename}, timeout=30),
    )
    if failure:
        return failure
    encoded = (payload.get("result") or {}).get("content", "")
    try:
        # Vshell versions differ on whether they include base64 padding.
        padded = str(encoded) + ("=" * (-len(str(encoded)) % 4))
        raw = base64.b64decode(padded, validate=False) if encoded else b""
    except (ValueError, TypeError) as exc:
        return _failure("read_file", endpoint, f"Invalid base64 file response: {exc}")
    limit = max(1, min(max_bytes, 5 * 1024 * 1024))
    preview = raw[:limit].decode("utf-8", errors="replace")
    output = f"[VSHELL_FILE_EVIDENCE] client_id={client_id} path={path} bytes={len(raw)}\n{preview}"
    return _success(
        "read_file",
        endpoint,
        data={"path": path, "size": len(raw), "truncated": len(raw) > limit, "content": preview},
        output=output,
        client_id=client_id,
    )


def vshell_write_file(client_id: int, path: str, content: str) -> dict:
    """Write text content to a file on a Vshell Agent."""
    endpoint = "/api/file/edit"
    _, payload, failure = _call(
        "write_file",
        endpoint,
        lambda c: c.post(endpoint, {"id": str(client_id), "path": path, "content": content}, timeout=30),
    )
    if failure:
        return failure
    data = {"client_id": client_id, "path": path, "bytes": len(content.encode("utf-8"))}
    return _success("write_file", endpoint, data=data, client_id=client_id)


def vshell_remove_file(client_id: int, path: str) -> dict:
    """Remove a file or directory from a Vshell Agent."""
    endpoint = "/api/file/rm"
    _, payload, failure = _call(
        "remove_file",
        endpoint,
        lambda c: c.post(endpoint, {"id": str(client_id), "path": path}, timeout=15),
    )
    if failure:
        return failure
    return _success("remove_file", endpoint, data={"client_id": client_id, "path": path, "removed": True}, client_id=client_id)


def vshell_upload_file(client_id: int, local_path: str, remote_path: str = "") -> dict:
    """Upload a local file to a Vshell Agent using the authenticated multipart API."""
    endpoint = "/api/file/upload"
    try:
        client = _get_client()
        payload = client.upload(client_id, local_path, remote_path)
    except VshellError as exc:
        return _failure("upload_file", endpoint, str(exc), completed=False)
    if not _api_ok(payload):
        return _failure("upload_file", endpoint, _api_message(payload))
    destination = payload.get("url") or remote_path or Path(local_path).name
    data = {"client_id": client_id, "local_path": str(Path(local_path).expanduser()), "remote_path": destination}
    return _success("upload_file", endpoint, data=data, client_id=client_id)


def vshell_download_to_server(client_id: int, remote_path: str, timeout: int = 30) -> dict:
    """Transfer an Agent file to the Vshell server and verify completion by polling progress."""
    endpoint = "/api/file/downloadtoserver"
    normalized = remote_path.replace("\\", "/")
    directory, filename = posixpath.split(normalized)
    if not filename:
        return _failure("download_to_server", endpoint, _msg("vshell_full_path_required", "A complete file path is required: {path}", path=remote_path), completed=False)
    directory = directory or "/"
    try:
        client = _get_client()
        listing = client.post(
            "/api/file/ls",
            {"page": 1, "pageSize": 1000, "id": client_id, "path": directory},
            timeout=15,
        )
        size = 0
        if _api_ok(listing):
            for item in (listing.get("result") or {}).get("items") or []:
                if item.get("name") == filename:
                    size = int(item.get("size") or 0)
                    break
        body = {"id": str(client_id), "path": directory, "target": filename}
        trigger = client.post(endpoint, body, timeout=15)
        if not _api_ok(trigger):
            return _failure("download_to_server", endpoint, _api_message(trigger))
        poll_body = {**body, "size": size}
        deadline = time.monotonic() + max(1, min(timeout, 300))
        progress = 0
        while time.monotonic() < deadline:
            time.sleep(0.5)
            status = client.post("/api/file/getdownloadper", poll_body, timeout=10)
            if not _api_ok(status):
                return _failure("download_to_server", "/api/file/getdownloadper", _api_message(status))
            progress = int((status.get("result") or {}).get("pre") or 0)
            if progress >= 100:
                data = {"client_id": client_id, "remote_path": remote_path, "size": size, "progress": progress}
                return _success("download_to_server", endpoint, data=data, client_id=client_id)
    except VshellError as exc:
        return _failure("download_to_server", endpoint, str(exc), completed=False)
    return _failure("download_to_server", endpoint, _msg("vshell_download_timeout", "Vshell download timed out at {progress}%.", progress=progress))


def vshell_deploy_tool(
    client_id: int,
    local_path: str = "",
    remote_path: str = "",
    exec_args: str = "",
    wait_result: bool = True,
) -> dict:
    """Upload a tool to one Agent and optionally execute it with verified output."""
    if not local_path:
        if not remote_path:
            return _failure(
                "deploy_tool",
                "/api/file/upload",
                _msg("vshell_deploy_path_required", "local_path or remote_path is required."),
                completed=False,
            )
        command = f'"{remote_path}" {exec_args}'.strip()
        return (
            vshell_exec_cmd(client_id, command, timeout=120)
            if wait_result
            else vshell_exec_async(client_id, command)
        )
    upload = vshell_upload_file(client_id, local_path, remote_path)
    if not upload.get("success"):
        return upload
    destination = upload["data"]["remote_path"]
    command = f'"{destination}" {exec_args}'.strip()
    if not wait_result:
        queued = vshell_exec_async(client_id, command)
        queued["upload"] = upload["data"]
        return queued
    executed = vshell_exec_cmd(client_id, command, timeout=120)
    executed["upload"] = upload["data"]
    return executed


def _tunnel_items(client: VshellClient, client_id: int = 0) -> list[dict[str, Any]]:
    payload = client.post(
        "/api/tunnel/list",
        {"page": 1, "pageSize": 1000, "ClientId": client_id},
        timeout=15,
    )
    if not _api_ok(payload):
        raise VshellError(_api_message(payload))
    return (payload.get("result") or {}).get("items") or []


def _select_tunnel_port(items: list[dict[str, Any]]) -> int:
    occupied = {int(item.get("Port") or 0) for item in items}
    for port in range(10800, 10901):
        if port not in occupied:
            return port
    raise VshellError(_msg("vshell_no_tunnel_port", "No free Vshell tunnel port in range 10800-10900."))


def vshell_start_socks5(client_id: int, port: int = 0, force: bool = False) -> dict:
    """Create and start a SOCKS5 pivot through a Vshell Agent."""
    endpoint = "/api/tunnel/add"
    try:
        client = _get_client()
        all_items = _tunnel_items(client)
        selected = int(port) if port else _select_tunnel_port(all_items)
        existing = next((item for item in all_items if int(item.get("Port") or 0) == selected), None)
        if existing and not force:
            return _failure("start_socks5", endpoint, _msg("vshell_port_in_use", "Vshell tunnel port is already in use: {port}", port=selected))
        if existing:
            existing_id = existing.get("Id")
            stopped = client.post("/api/tunnel/stop", {"id": existing_id}, timeout=15)
            if not _api_ok(stopped):
                return _failure("start_socks5", "/api/tunnel/stop", _api_message(stopped))
            deleted = client.post("/api/tunnel/del", {"id": existing_id}, timeout=15)
            if not _api_ok(deleted):
                return _failure("start_socks5", "/api/tunnel/del", _api_message(deleted))
        added = client.post(endpoint, {"ClientId": client_id, "Mode": "socks5", "Port": selected}, timeout=15)
        if not _api_ok(added):
            return _failure("start_socks5", endpoint, _api_message(added))
        tunnel_id = None
        for item in _tunnel_items(client, client_id):
            if int(item.get("Port") or 0) == selected and int(item.get("ClientId") or 0) == client_id:
                tunnel_id = item.get("Id")
                break
        if tunnel_id is None:
            return _failure("start_socks5", endpoint, _msg("vshell_tunnel_id_missing", "Tunnel was created but its ID was not returned by Vshell."))
        started = client.post("/api/tunnel/start", {"id": tunnel_id}, timeout=15)
        if not _api_ok(started):
            return _failure("start_socks5", "/api/tunnel/start", _api_message(started))
    except VshellError as exc:
        return _failure("start_socks5", endpoint, str(exc), completed=False)
    data = {
        "tunnel_id": tunnel_id,
        "client_id": client_id,
        "host": client.config.tunnel_host,
        "port": selected,
        "proxy_url": f"socks5h://{client.config.tunnel_host}:{selected}",
    }
    return _success("start_socks5", endpoint, data=data, client_id=client_id)


def vshell_stop_socks5(port: int) -> dict:
    """Stop and delete a Vshell SOCKS5 tunnel selected by port."""
    endpoint = "/api/tunnel/stop"
    try:
        client = _get_client()
        match = next((item for item in _tunnel_items(client) if int(item.get("Port") or 0) == int(port)), None)
        if match is None:
            return _failure("stop_socks5", endpoint, _msg("vshell_tunnel_missing", "No Vshell tunnel uses port {port}.", port=port))
        tunnel_id = match.get("Id")
        stopped = client.post(endpoint, {"id": tunnel_id}, timeout=15)
        if not _api_ok(stopped):
            return _failure("stop_socks5", endpoint, _api_message(stopped))
        deleted = client.post("/api/tunnel/del", {"id": tunnel_id}, timeout=15)
        if not _api_ok(deleted):
            return _failure("stop_socks5", "/api/tunnel/del", _api_message(deleted))
    except VshellError as exc:
        return _failure("stop_socks5", endpoint, str(exc), completed=False)
    return _success("stop_socks5", endpoint, data={"tunnel_id": tunnel_id, "port": port, "stopped": True})


def vshell_list_tunnels() -> dict:
    """List all Vshell pivot tunnels and their server-reported state."""
    endpoint = "/api/tunnel/list"
    try:
        client = _get_client()
        items = _tunnel_items(client)
    except VshellError as exc:
        return _failure("list_tunnels", endpoint, str(exc), completed=False)
    return _success("list_tunnels", endpoint, data={"tunnels": items, "count": len(items)})


def _parse_headers(headers: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in headers.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip():
                parsed[key.strip()] = value.strip()
    return parsed


def vshell_tunnel_http(
    port: int,
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    timeout: int = 30,
) -> dict:
    """Send an HTTP request through a verified Vshell SOCKS5 pivot using curl."""
    endpoint = "local:curl-socks5"
    try:
        client = _get_client()
        match = next((item for item in _tunnel_items(client) if int(item.get("Port") or 0) == int(port)), None)
        if match is None or not match.get("RunStatus"):
            return _failure("tunnel_http", endpoint, _msg("vshell_tunnel_inactive", "Vshell tunnel is not active on port {port}.", port=port))
        command = [
            "curl", "-sS", "-i", "--socks5-hostname", f"{client.config.tunnel_host}:{port}",
            "-X", method.upper(), "--max-time", str(max(1, min(timeout, 120))),
        ]
        for key, value in _parse_headers(headers).items():
            command.extend(["-H", f"{key}: {value}"])
        if body:
            command.extend(["--data-binary", body])
        command.append(url)
        started = time.monotonic()
        process = subprocess.run(command, capture_output=True, text=True, timeout=max(1, min(timeout, 120)) + 5)
    except FileNotFoundError:
        return _failure("tunnel_http", endpoint, _msg("vshell_curl_missing", "curl is required for Vshell tunnel HTTP requests."), completed=False)
    except subprocess.TimeoutExpired:
        return _failure("tunnel_http", endpoint, _msg("vshell_timeout", "Vshell request timed out: {path}", path=url))
    except VshellError as exc:
        return _failure("tunnel_http", endpoint, str(exc), completed=False)
    output = (process.stdout or process.stderr)[-20000:]
    ok = process.returncode == 0
    result = _success(
        "tunnel_http",
        endpoint,
        data={"url": url, "method": method.upper(), "port": port, "returncode": process.returncode},
        output=f"[VSHELL_TUNNEL_EVIDENCE] port={port} url={url}\n{output}",
        elapsed=round(time.monotonic() - started, 3),
    )
    if not ok:
        result.update(success=False, exit_code=process.returncode or 1)
    return result


def vshell_list_listeners() -> dict:
    """List Vshell listener configurations and current server-reported status."""
    endpoint = "/api/listener/list"
    _, payload, failure = _call(
        "list_listeners",
        endpoint,
        lambda c: c.post(endpoint, {"page": 1, "pageSize": 1000, "ListenerId": 0}, timeout=15),
    )
    if failure:
        return failure
    result = payload.get("result") or {}
    items = result.get("items") or []
    return _success("list_listeners", endpoint, data={"listeners": items, "total": result.get("total", len(items))})


def vshell_list_runners() -> dict:
    """List Vshell server-side runner tools available for Agent deployment."""
    endpoint = "/api/runner/list"
    _, payload, failure = _call("list_runners", endpoint, lambda c: c.get(endpoint, timeout=15))
    if failure:
        return failure
    items = payload.get("result") or []
    return _success("list_runners", endpoint, data={"runners": items, "count": len(items)})


def _http_probe(
    name: str,
    url: str,
    method: str,
    headers: dict[str, str],
    body: str,
    timeout: int,
    proxy: str | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with httpx.Client(proxy=proxy, verify=False, timeout=max(1, min(timeout, 120)), follow_redirects=False) as client:
            response = client.request(method.upper(), url, headers=headers, content=body or None)
        return {
            "engine": name,
            "success": True,
            "status": response.status_code,
            "elapsed": round(time.monotonic() - started, 3),
            "size": len(response.content),
            "headers": dict(response.headers),
            "body": response.text[:4000],
        }
    except httpx.HTTPError as exc:
        return {"engine": name, "success": False, "error": str(exc), "elapsed": round(time.monotonic() - started, 3)}


def _curl_probe(
    url: str,
    method: str,
    headers: dict[str, str],
    body: str,
    timeout: int,
) -> dict[str, Any]:
    started = time.monotonic()
    command = ["curl", "-sS", "-i", "-X", method.upper(), "--max-time", str(max(1, min(timeout, 120)))]
    for key, value in headers.items():
        command.extend(["-H", f"{key}: {value}"])
    if body:
        command.extend(["--data-binary", body])
    command.append(url)
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=max(1, min(timeout, 120)) + 5)
    except FileNotFoundError:
        return {"engine": "curl", "success": False, "error": "curl not installed"}
    except subprocess.TimeoutExpired:
        return {"engine": "curl", "success": False, "error": "timeout"}
    raw = process.stdout or process.stderr
    status = None
    first_line = raw.splitlines()[0] if raw else ""
    if first_line.startswith("HTTP/"):
        parts = first_line.split()
        if len(parts) > 1 and parts[1].isdigit():
            status = int(parts[1])
    return {
        "engine": "curl",
        "success": process.returncode == 0,
        "status": status,
        "returncode": process.returncode,
        "elapsed": round(time.monotonic() - started, 3),
        "size": len(raw.encode("utf-8", errors="replace")),
        "body": raw[:4000],
    }


def vshell_send_http(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    engine: str = "direct",
    timeout: int = 30,
) -> dict:
    """Send an HTTP probe through direct or Yakit transport and preserve raw response evidence."""
    proxy = None
    if engine.lower() == "yakit":
        proxy = os.environ.get("YAKIT_PROXY", "http://127.0.0.1:8081").strip()
    elif engine.lower() == "curl":
        data = _curl_probe(url, method, _parse_headers(headers), body, timeout)
        if not data["success"]:
            return _failure("send_http", "local:http", str(data.get("error") or data.get("body")), completed=False)
        output = f"[VSHELL_HTTP_EVIDENCE] engine=curl method={method.upper()} url={url}\n{_json_output(data)}"
        return _success("send_http", "local:http", data=data, output=output, elapsed=data["elapsed"])
    elif engine.lower() != "direct":
        return _failure("send_http", "local:http", f"Unknown engine: {engine}", completed=False)
    data = _http_probe(engine.lower(), url, method, _parse_headers(headers), body, timeout, proxy=proxy)
    if not data["success"]:
        return _failure("send_http", "local:http", str(data.get("error")), completed=False)
    output = f"[VSHELL_HTTP_EVIDENCE] engine={engine.lower()} method={method.upper()} url={url}\n{_json_output(data)}"
    return _success("send_http", "local:http", data=data, output=output, elapsed=data["elapsed"])


def vshell_compare_http(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    timeout: int = 30,
) -> dict:
    """Compare direct and Yakit HTTP transports without converting differences into findings."""
    proxy = os.environ.get("YAKIT_PROXY", "http://127.0.0.1:8081").strip()
    parsed = _parse_headers(headers)
    results = [
        _http_probe("direct", url, method, parsed, body, timeout),
        _http_probe("yakit", url, method, parsed, body, timeout, proxy=proxy),
        _curl_probe(url, method, parsed, body, timeout),
    ]
    successful = [item for item in results if item.get("success")]
    http_successful = [item for item in successful if item.get("status") is not None]
    comparison = {
        "engines": results,
        "comparable": len(http_successful) >= 2,
        "status_differs": len({item["status"] for item in http_successful}) > 1,
        "size_delta": (
            max(item["size"] for item in successful) - min(item["size"] for item in successful)
            if len(successful) >= 2
            else None
        ),
        "finding_confirmed": False,
    }
    return _success("compare_http", "local:http-compare", data=comparison)


def vshell_diagnose() -> dict:
    """Validate Vshell configuration, authentication, and server reachability."""
    endpoint = "/api/dashboard/info"
    missing = [name for name in ("VSHELL_URL", "VSHELL_TOKEN", "VSHELL_BASICAUTH") if not os.environ.get(name, "").strip()]
    if missing:
        return _failure(
            "diagnose",
            endpoint,
            _msg("vshell_missing_settings", "Missing Vshell settings: {settings}", settings=", ".join(missing)),
            completed=False,
        )
    started = time.monotonic()
    client, payload, failure = _call("diagnose", endpoint, lambda c: c.get(endpoint, timeout=5))
    if failure:
        return failure
    data = {
        "configured": True,
        "reachable": True,
        "authenticated": True,
        "url": client.config.url,
        "tunnel_host": client.config.tunnel_host,
        "verify_tls": client.config.verify_tls,
        "server": payload.get("result") or {},
        "latency": round(time.monotonic() - started, 3),
    }
    return _success("diagnose", endpoint, data=data)


VSHELL_TOOLS: dict[str, Any] = {
    "vshell_server_info": vshell_server_info,
    "vshell_list_clients": vshell_list_clients,
    "vshell_exec_cmd": vshell_exec_cmd,
    "vshell_exec_async": vshell_exec_async,
    "vshell_get_disks": vshell_get_disks,
    "vshell_list_dir": vshell_list_dir,
    "vshell_read_file": vshell_read_file,
    "vshell_write_file": vshell_write_file,
    "vshell_remove_file": vshell_remove_file,
    "vshell_upload_file": vshell_upload_file,
    "vshell_download_to_server": vshell_download_to_server,
    "vshell_download_from_agent": vshell_download_to_server,
    "vshell_deploy_tool": vshell_deploy_tool,
    "vshell_start_socks5": vshell_start_socks5,
    "vshell_stop_socks5": vshell_stop_socks5,
    "vshell_list_tunnels": vshell_list_tunnels,
    "vshell_tunnel_http": vshell_tunnel_http,
    "vshell_tunnel_curl": vshell_tunnel_http,
    "vshell_list_listeners": vshell_list_listeners,
    "vshell_list_runners": vshell_list_runners,
    "vshell_send_http": vshell_send_http,
    "vshell_compare_http": vshell_compare_http,
    "vshell_diagnose": vshell_diagnose,
}
