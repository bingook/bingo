from __future__ import annotations

import subprocess
from pathlib import Path

from bingo.core.change_memory import (
    BINGO_AUTO_END,
    BINGO_AUTO_START,
    MAX_AUTO_BLOCK_BYTES,
    WORKTREE_END,
    WORKTREE_START,
    _worktree_fingerprint,
    bingo_project_memory_path,
    ensure_post_commit_hook,
    record_commit,
    record_worktree_snapshot,
    sync_bingo_project_memory,
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


def test_bingo_project_memory_sync_preserves_manual_notes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    tracked.write_text("before\nafter\n", encoding="utf-8")
    memory_root = repo / ".bingo" / "bingo-memory"

    project_memory = bingo_project_memory_path(repo)
    project_memory.parent.mkdir(parents=True, exist_ok=True)
    project_memory.write_text(
        "# Bingo Project Memory\n\n## Persistent Notes\n\n- manual note\n",
        encoding="utf-8",
    )

    record_worktree_snapshot(repo, memory_root)
    first = sync_bingo_project_memory(repo, memory_root)
    content = first.read_text(encoding="utf-8")
    assert "- manual note" in content
    assert BINGO_AUTO_START in content
    assert "Working tree snapshot" in content
    assert "tracked.txt" in content

    tracked.write_text("before\nafter\nagain\n", encoding="utf-8")
    record_worktree_snapshot(repo, memory_root)
    sync_bingo_project_memory(repo, memory_root)
    updated = project_memory.read_text(encoding="utf-8")
    assert "- manual note" in updated
    assert updated.count(BINGO_AUTO_START) == 1


def test_bingo_project_memory_sync_drops_stale_generated_tail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    tracked.write_text("before\nafter\n", encoding="utf-8")
    memory_root = repo / ".bingo" / "bingo-memory"

    project_memory = bingo_project_memory_path(repo)
    project_memory.parent.mkdir(parents=True, exist_ok=True)
    project_memory.write_text(
        "# Bingo Project Memory\n\n"
        "## Persistent Notes\n\n"
        "- manual note\n\n"
        f"{BINGO_AUTO_START}\nold auto\n{BINGO_AUTO_END}\n\n"
        "# Workspace Memory\n\n"
        "<!-- commit:old -->\n"
        "stale generated tail\n",
        encoding="utf-8",
    )

    record_worktree_snapshot(repo, memory_root)
    sync_bingo_project_memory(repo, memory_root)

    content = project_memory.read_text(encoding="utf-8")
    assert "- manual note" in content
    assert "old auto" not in content
    assert "stale generated tail" not in content
    assert content.count(BINGO_AUTO_START) == 1
    assert content.count(BINGO_AUTO_END) == 1


def test_bingo_project_memory_sync_drops_partial_generated_tail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    tracked.write_text("before\nafter\n", encoding="utf-8")
    memory_root = repo / ".bingo" / "bingo-memory"

    project_memory = bingo_project_memory_path(repo)
    project_memory.parent.mkdir(parents=True, exist_ok=True)
    project_memory.write_text(
        "# Bingo Project Memory\n\n"
        "## Persistent Notes\n\n"
        "- manual note\n\n"
        f"{BINGO_AUTO_START}\nold auto\n{BINGO_AUTO_END}\n\n"
        '"`\n'
        "- `stale generated highlight`\n"
        f"{WORKTREE_END}\n"
        f"{BINGO_AUTO_END}\n",
        encoding="utf-8",
    )

    record_worktree_snapshot(repo, memory_root)
    sync_bingo_project_memory(repo, memory_root)

    content = project_memory.read_text(encoding="utf-8")
    assert "- manual note" in content
    assert "old auto" not in content
    assert "stale generated highlight" not in content
    assert content.count(BINGO_AUTO_START) == 1
    assert content.count(BINGO_AUTO_END) == 1


def test_bingo_project_memory_sync_compacts_nested_workspace_history(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    memory_root = repo / ".bingo" / "bingo-memory"
    source = workspace_memory_path(repo, memory_root)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "# Workspace Memory\n\n"
        f"{WORKTREE_START}\n"
        "## Working tree snapshot (uncommitted)\n"
        "tracked.py\n"
        f"{WORKTREE_END}\n\n"
        "# Workspace Memory\n\n"
        "<!-- commit:new -->\n"
        "## Code change: latest safe change\n"
        "tracked.py\n\n"
        "# Workspace Memory\n\n"
        "<!-- commit:old -->\n"
        "## Code change: stale generated payload\n"
        "stale/generated/payload.txt\n",
        encoding="utf-8",
    )

    project_memory = sync_bingo_project_memory(repo, memory_root)
    content = project_memory.read_text(encoding="utf-8")

    assert "Working tree snapshot" in content
    assert "latest safe change" in content
    assert "stale generated payload" not in content
    assert "stale/generated/payload.txt" not in content


def test_worktree_highlights_skip_agents_and_bingo_instruction_noise(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / ".bingo").mkdir()
    (repo / "AGENTS.md").write_text("base\n", encoding="utf-8")
    (repo / ".bingo" / "instruction.md").write_text("base\n", encoding="utf-8")
    (repo / "tracked.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(
        ["git", "add", "AGENTS.md", ".bingo/instruction.md", "tracked.py"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    (repo / "AGENTS.md").write_text("base\nFORBIDDEN_PHRASE_TABLE\n", encoding="utf-8")
    (repo / ".bingo" / "instruction.md").write_text("base\nPROMPT_LAYER\n", encoding="utf-8")
    (repo / "tracked.py").write_text("value = 1\nvalue = 2\n", encoding="utf-8")

    memory_path = record_worktree_snapshot(repo, repo / ".bingo" / "bingo-memory")
    assert memory_path is not None
    content = memory_path.read_text(encoding="utf-8")
    assert "`value = 2`" in content
    assert "FORBIDDEN_PHRASE_TABLE" not in content
    assert "PROMPT_LAYER" not in content


def test_worktree_memory_ignores_bingo_generated_files_and_secret_lines(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    tracked = repo / "tracked.py"
    tracked.write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    (repo / ".bingo").mkdir(exist_ok=True)
    generated = repo / ".bingo" / "project-memory.md"
    generated.write_text("memory version 1\n", encoding="utf-8")

    first_fingerprint = _worktree_fingerprint(repo)
    generated.write_text("memory version 2\n", encoding="utf-8")
    second_fingerprint = _worktree_fingerprint(repo)
    assert first_fingerprint == second_fingerprint

    tracked.write_text(
        "value = 1\n"
        "API_KEY = 'sk-test-secret-value'\n"
        "safe_value = 2\n",
        encoding="utf-8",
    )
    memory_path = record_worktree_snapshot(repo, repo / ".bingo" / "bingo-memory")
    assert memory_path is not None
    content = memory_path.read_text(encoding="utf-8")
    assert ".bingo/project-memory.md" not in content
    assert "sk-test-secret-value" not in content
    assert "`safe_value = 2`" in content


def test_bingo_project_memory_auto_block_is_bounded(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    memory_root = repo / ".bingo" / "bingo-memory"
    source = workspace_memory_path(repo, memory_root)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        "# Workspace Memory\n\n"
        f"{WORKTREE_START}\n"
        "## Working tree snapshot (uncommitted)\n"
        + "\n".join(f"M file_{index}.py" for index in range(500))
        + f"\n{WORKTREE_END}\n\n"
        "# Workspace Memory\n\n"
        "<!-- commit:new -->\n"
        "## Code change: latest safe change\n"
        + ("large diff stat line\n" * 500),
        encoding="utf-8",
    )

    project_memory = sync_bingo_project_memory(repo, memory_root)
    content = project_memory.read_text(encoding="utf-8")
    auto_start = content.index(BINGO_AUTO_START)
    auto_end = content.index(BINGO_AUTO_END)
    auto_block = content[auto_start:auto_end]

    assert len(auto_block.encode("utf-8")) <= MAX_AUTO_BLOCK_BYTES + 800
    assert "Auto-captured workspace memory truncated" in auto_block
