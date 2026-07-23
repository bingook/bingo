from pathlib import Path

from bingo.core import local_state


def test_config_state_cache_dir_env_overrides(monkeypatch, tmp_path):
    config = tmp_path / "config"
    state = tmp_path / "state"
    cache = tmp_path / "cache"
    monkeypatch.setenv("BINGO_CONFIG_DIR", str(config))
    monkeypatch.setenv("BINGO_STATE_DIR", str(state))
    monkeypatch.setenv("BINGO_CACHE_DIR", str(cache))

    assert local_state.config_dir() == config
    assert local_state.state_dir() == state
    assert local_state.cache_dir() == cache


def test_workspace_state_dir_is_stable_and_outside_workspace(monkeypatch, tmp_path):
    state = tmp_path / "state-root"
    workspace = tmp_path / "repo" / "bingo"
    workspace.mkdir(parents=True)
    monkeypatch.setenv("BINGO_STATE_DIR", str(state))

    first = local_state.workspace_state_dir(workspace)
    second = local_state.workspace_state_dir(Path(workspace))

    assert first == second
    assert first.parent == state / "workspaces"
    assert not first.is_relative_to(workspace)
    assert first.name.startswith("bingo-")


def test_session_dir_and_artifact_dir_are_workspace_scoped(monkeypatch, tmp_path):
    state = tmp_path / "state-root"
    workspace = tmp_path / "repo"
    monkeypatch.setenv("BINGO_STATE_DIR", str(state))
    monkeypatch.delenv("BINGO_ARTIFACTS_DIR", raising=False)

    workspace_dir = local_state.workspace_state_dir(workspace)

    assert local_state.session_dir(workspace) == workspace_dir / "sessions"
    assert local_state.session_dir(workspace, "run/../bad id") == workspace_dir / "sessions" / "run-bad-id"
    assert local_state.artifact_dir(workspace) == workspace_dir / "artifacts"


def test_artifact_dir_env_override(monkeypatch, tmp_path):
    artifacts = tmp_path / "artifacts"
    monkeypatch.setenv("BINGO_ARTIFACTS_DIR", str(artifacts))

    assert local_state.artifact_dir(tmp_path / "repo") == artifacts
