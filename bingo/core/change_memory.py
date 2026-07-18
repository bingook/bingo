"""Persist Git changes into bingo's workspace memory.

The generated MEMORY.md is consumed automatically by ``core.memory`` on the
next bingo session. Entries are local to the workspace and are never committed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence


DEFAULT_MEMORY_ROOT = Path.home() / ".config" / "bingo" / "memory"
MAX_MEMORY_BYTES = 128 * 1024
MAX_HIGHLIGHTS = 30
WORKTREE_START = "<!-- working-tree:start -->"
WORKTREE_END = "<!-- working-tree:end -->"


def workspace_hash(cwd: str | Path) -> str:
    """Return the workspace identifier used by ``core.memory``."""
    return hashlib.md5(str(Path(cwd).resolve()).encode()).hexdigest()[:16]


def workspace_memory_path(
    cwd: str | Path,
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
) -> Path:
    return Path(memory_root).expanduser() / workspace_hash(cwd) / "MEMORY.md"


def _git(cwd: Path, args: Sequence[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.strip()


def _added_highlights(patch: str) -> list[str]:
    highlights: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        text = line[1:].strip()
        if not text or text.startswith(("#", "//", "*")):
            continue
        highlights.append(text[:180])
        if len(highlights) >= MAX_HIGHLIGHTS:
            break
    return highlights


def _without_worktree_snapshot(content: str) -> str:
    return re.sub(
        rf"\n?{re.escape(WORKTREE_START)}.*?{re.escape(WORKTREE_END)}\n?",
        "\n",
        content,
        flags=re.DOTALL,
    )


def render_commit_entry(cwd: str | Path, revision: str = "HEAD") -> tuple[str, str]:
    """Build one Markdown memory entry and return it with the full commit id."""
    repo = Path(cwd).resolve()
    commit_id = _git(repo, ["rev-parse", revision])
    metadata = _git(repo, ["show", "-s", "--format=%cI%x1f%B", commit_id])
    committed_at, _, message = metadata.partition("\x1f")
    subject, _, body = message.strip().partition("\n")
    name_status = _git(
        repo,
        ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", commit_id],
    )
    diff_stat = _git(repo, ["show", "--format=", "--stat", "--oneline", commit_id])
    patch = _git(repo, ["show", "--format=", "--unified=0", "--no-ext-diff", commit_id])
    highlights = _added_highlights(patch)

    lines = [
        f"<!-- commit:{commit_id} -->",
        f"## Code change: {subject}",
        f"- Commit: `{commit_id[:12]}`",
        f"- Recorded: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"- Committed: {committed_at}",
    ]
    if body.strip():
        lines.extend(["", "### Intent", body.strip()])
    if name_status:
        lines.extend(["", "### Files", "```text", name_status, "```"])
    if diff_stat:
        lines.extend(["", "### Diff Stat", "```text", diff_stat, "```"])
    if highlights:
        lines.extend(["", "### Added Highlights"])
        lines.extend(f"- `{line.replace('`', "'")}`" for line in highlights)
    lines.append("")
    return "\n".join(lines), commit_id


def record_commit(
    cwd: str | Path,
    revision: str = "HEAD",
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
) -> Path:
    """Prepend a commit entry to workspace memory, once per commit."""
    repo = Path(cwd).resolve()
    entry, commit_id = render_commit_entry(repo, revision)
    path = workspace_memory_path(repo, memory_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    existing = _without_worktree_snapshot(existing)
    marker = f"<!-- commit:{commit_id} -->"
    if marker in existing:
        return path

    header = (
        "# Workspace Memory\n\n"
        "> Automatically records committed code changes. Newest entries appear first.\n\n"
    )
    if existing.startswith("# Workspace Memory"):
        _, separator, remainder = existing.partition("\n\n")
        existing_body = remainder if separator else ""
        if existing_body.startswith("> Automatically records"):
            _, separator, existing_body = existing_body.partition("\n\n")
            if not separator:
                existing_body = ""
    else:
        existing_body = existing

    content = header + entry + "\n" + existing_body.lstrip()
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_MEMORY_BYTES:
        content = encoded[:MAX_MEMORY_BYTES].decode("utf-8", errors="ignore")
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    return path


def record_worktree_snapshot(
    cwd: str | Path,
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
) -> Path | None:
    """Replace the transient memory entry for current uncommitted changes."""
    repo = Path(cwd).resolve()
    status = _git(repo, ["status", "--short"])
    path = workspace_memory_path(repo, memory_root)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    existing = _without_worktree_snapshot(existing).rstrip()
    if not status:
        if path.exists():
            path.write_text(existing + "\n", encoding="utf-8")
        return path if path.exists() else None

    stat = _git(repo, ["diff", "--stat", "--", "."])
    patch = _git(repo, ["diff", "--unified=0", "--no-ext-diff", "--", "."])
    highlights = _added_highlights(patch)
    lines = [
        WORKTREE_START,
        "## Working tree snapshot (uncommitted)",
        f"- Captured: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        "",
        "### Status",
        "```text",
        status,
        "```",
    ]
    if stat:
        lines.extend(["", "### Diff Stat", "```text", stat, "```"])
    if highlights:
        lines.extend(["", "### Added Highlights"])
        lines.extend(f"- `{line.replace('`', "'")}`" for line in highlights)
    lines.extend([WORKTREE_END, ""])

    header = ""
    if not existing:
        header = (
            "# Workspace Memory\n\n"
            "> Automatically records committed code changes. Newest entries appear first.\n"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text((header + "\n".join(lines) + existing).rstrip() + "\n", encoding="utf-8")
    return path


def _worktree_fingerprint(repo: Path) -> str:
    """Hash dirty paths plus mtimes so repeated edits are not missed."""
    porcelain = _git(repo, ["status", "--porcelain=v1", "-z"])
    digest = hashlib.sha256(porcelain.encode())
    for entry in porcelain.split("\0"):
        if len(entry) < 4:
            continue
        path = repo / entry[3:]
        try:
            stat = path.stat()
            digest.update(f"{path}:{stat.st_mtime_ns}:{stat.st_size}".encode())
        except OSError:
            continue
    return digest.hexdigest()


def ensure_post_commit_hook(
    cwd: str | Path,
    source_hook: str | Path | None = None,
) -> Path:
    """Install the versioned post-commit hook without losing an existing hook."""
    repo = Path(cwd).resolve()
    source = Path(source_hook) if source_hook else repo / "scripts" / "git-hooks" / "post-commit"
    source = source.resolve()
    if not source.is_file():
        raise FileNotFoundError(source)

    hook_path_raw = _git(repo, ["rev-parse", "--git-path", "hooks/post-commit"])
    hook_path = Path(hook_path_raw)
    if not hook_path.is_absolute():
        hook_path = repo / hook_path
    hook_path.parent.mkdir(parents=True, exist_ok=True)

    installed_by_bingo = False
    if hook_path.exists():
        current = hook_path.read_text(encoding="utf-8", errors="replace")
        installed_by_bingo = "bingo-change-memory-hook" in current
        if installed_by_bingo and str(source) in current:
            return hook_path

    backup = hook_path.with_name("post-commit.bingo-existing")
    if hook_path.exists() and not installed_by_bingo:
        if backup.exists():
            raise FileExistsError(f"cannot preserve both {hook_path} and {backup}")
        hook_path.replace(backup)

    backup_block = ""
    if backup.exists():
        backup_q = shlex.quote(str(backup))
        backup_block = (
            f"if [ -x {backup_q} ]; then\n"
            f"    {backup_q} \"$@\" || exit $?\n"
            "fi\n\n"
        )
    source_q = shlex.quote(str(source))
    hook_path.write_text(
        "#!/bin/sh\n"
        "# bingo-change-memory-hook\n\n"
        + backup_block
        + f"exec {source_q} \"$@\"\n",
        encoding="utf-8",
    )
    hook_path.chmod(0o755)
    source.chmod(0o755)
    return hook_path


def bootstrap_change_memory(cwd: str | Path) -> tuple[Path, Path]:
    """Install automatic recording and backfill the current HEAD immediately."""
    repo = Path(cwd).resolve()
    hook_path = ensure_post_commit_hook(repo)
    memory_path = record_commit(repo, "HEAD")
    return hook_path, memory_path


def watch_worktree_changes(cwd: str | Path, poll_interval: float = 2.0) -> None:
    """Continuously mirror working-tree edits into transient workspace memory."""
    repo = Path(cwd).resolve()
    try:
        bootstrap_change_memory(repo)
    except Exception:
        # Memory recording must continue even if a custom hook cannot be wrapped.
        try:
            record_commit(repo, "HEAD")
        except Exception:
            pass
    last_fingerprint = ""
    while True:
        try:
            fingerprint = _worktree_fingerprint(repo)
            if fingerprint != last_fingerprint:
                record_worktree_snapshot(repo)
                last_fingerprint = fingerprint
        except Exception:
            pass
        time.sleep(max(0.5, poll_interval))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record a Git commit in bingo memory")
    parser.add_argument("--cwd", default=os.getcwd(), help="Git workspace path")
    parser.add_argument("--commit", default="HEAD", help="Commit revision to record")
    parser.add_argument("--memory-root", default=str(DEFAULT_MEMORY_ROOT))
    parser.add_argument("--install-hook", action="store_true")
    args = parser.parse_args(argv)
    if args.install_hook:
        ensure_post_commit_hook(args.cwd)
    path = record_commit(args.cwd, args.commit, args.memory_root)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
