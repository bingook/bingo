"""Local filesystem locations for Bingo runtime state.

Product runtime state must live outside the repository so updates and commits do
not mix user artifacts with source files.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

APP_NAME = "bingo"


def _env_path(name: str) -> Path | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    return Path(raw).expanduser()


def _safe_name(value: str, fallback: str = "default") -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    while ".." in name:
        name = name.replace("..", "-")
    name = re.sub(r"-+", "-", name).strip(".-_")
    return name or fallback


def config_dir() -> Path:
    override = _env_path("BINGO_CONFIG_DIR")
    if override:
        return override
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / APP_NAME


def state_dir() -> Path:
    override = _env_path("BINGO_STATE_DIR")
    if override:
        return override
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / APP_NAME / "State"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME / "State"
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / APP_NAME


def cache_dir() -> Path:
    override = _env_path("BINGO_CACHE_DIR")
    if override:
        return override
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / APP_NAME / "Cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / APP_NAME
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / APP_NAME


def workspace_key(workspace: Path | str | None = None) -> str:
    root = Path(workspace or Path.cwd()).expanduser().resolve()
    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:12]
    return f"{_safe_name(root.name, 'workspace')}-{digest}"


def workspace_state_dir(workspace: Path | str | None = None) -> Path:
    return state_dir() / "workspaces" / workspace_key(workspace)


def session_dir(workspace: Path | str | None = None, session_id: str | None = None) -> Path:
    base = workspace_state_dir(workspace) / "sessions"
    if session_id:
        return base / _safe_name(session_id, "session")
    return base


def memory_dir(workspace: Path | str | None = None) -> Path:
    override = _env_path("BINGO_MEMORY_DIR")
    if override:
        return override
    return workspace_state_dir(workspace) / "memory"


def tools_dir() -> Path:
    override = _env_path("BINGO_TOOLS_DIR")
    if override:
        return override
    return state_dir() / "tools"


def knowledge_dir() -> Path:
    override = _env_path("BINGO_KNOWLEDGE_DIR")
    if override:
        return override
    return state_dir() / "knowledge"


def artifact_dir(workspace: Path | str | None = None) -> Path:
    override = _env_path("BINGO_ARTIFACTS_DIR")
    if override:
        return override
    return workspace_state_dir(workspace) / "artifacts"
