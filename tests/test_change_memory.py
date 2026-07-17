from __future__ import annotations

import subprocess
from pathlib import Path

from bingo.core.change_memory import (
    WORKTREE_START,
    ensure_post_commit_hook,
    record_commit,
    record_worktree_snapshot,
    workspace_memory_path,
)


def test_record_commit_prepends_once(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    memory_root = tmp_path / "memory"

    first = record_commit(repo, "HEAD", memory_root)
    second = record_commit(repo, "HEAD", memory_root)

    assert first == second == workspace_memory_path(repo, memory_root)
    content = first.read_text(encoding="utf-8")
    assert content.startswith("# Workspace Memory")
    assert content.count("<!-- commit:") == 1
    assert "### Files" in content
    assert "### Diff Stat" in content


def test_install_hook_preserves_existing_hook(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "--local", "core.hooksPath", ".git/hooks"],
        cwd=repo,
        check=True,
    )
    hook_dir = repo / ".git" / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    existing = hook_dir / "post-commit"
    existing.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
    existing.chmod(0o755)
    source = repo / "post-commit-source"
    source.write_text("#!/bin/sh\n# bingo-change-memory-hook\n", encoding="utf-8")

    installed = ensure_post_commit_hook(repo, source)
    installed_again = ensure_post_commit_hook(repo, source)

    assert installed_again == installed == existing
    assert "bingo-change-memory-hook" in installed.read_text(encoding="utf-8")
    assert (hook_dir / "post-commit.bingo-existing").read_text(encoding="utf-8").endswith(
        "echo existing\n"
    )
    assert installed.stat().st_mode & 0o111


def test_worktree_snapshot_is_replaced_by_commit_memory(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "--local", "core.hooksPath", ".git/hooks"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    tracked.write_text("before\nafter\n", encoding="utf-8")
    memory_root = tmp_path / "memory"

    snapshot = record_worktree_snapshot(repo, memory_root)
    assert snapshot is not None
    assert WORKTREE_START in snapshot.read_text(encoding="utf-8")
    assert "tracked.txt" in snapshot.read_text(encoding="utf-8")

    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "update tracked"], cwd=repo, check=True)
    record_commit(repo, "HEAD", memory_root)
    content = snapshot.read_text(encoding="utf-8")
    assert WORKTREE_START not in content
    assert "Code change: update tracked" in content
