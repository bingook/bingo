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
BINGO_MEMORY_FILE = Path(".bingo") / "project-memory.md"
BINGO_AUTO_START = "<!-- bingo-project-memory:auto:start -->"
BINGO_AUTO_END = "<!-- bingo-project-memory:auto:end -->"
HIGHLIGHT_SKIP_PATHS = {
    "AGENTS.md",
    ".bingo/instruction.md",
    ".bingo/project-memory.md",
}
WORKTREE_SKIP_PREFIXES = (".bingo/",)
SECRET_LINE_RE = re.compile(
    r'(?i)(?:api[_-]?key|secret|token|password|passwd|authorization|cookie|'
    r'sk-[A-Za-z0-9]|ghp_[A-Za-z0-9]|AKIA[0-9A-Z]{16}|-----BEGIN .*PRIVATE KEY-----)'
)


def workspace_hash(cwd: str | Path) -> str:
    """Return the workspace identifier used by ``core.memory``."""
    return hashlib.md5(str(Path(cwd).resolve()).encode()).hexdigest()[:16]


def workspace_memory_path(
    cwd: str | Path,
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
) -> Path:
    return Path(memory_root).expanduser() / workspace_hash(cwd) / "MEMORY.md"


def bingo_project_memory_path(cwd: str | Path) -> Path:
    """Return the project-local memory file that AGENTS.md tells Bingo to read."""
    return Path(cwd).resolve() / BINGO_MEMORY_FILE


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


def _skip_worktree_path(path: str) -> bool:
    normalized = path.strip().strip('"')
    if " -> " in normalized:
        return any(_skip_worktree_path(part) for part in normalized.split(" -> ", 1))
    return any(
        normalized == prefix.rstrip("/") or normalized.startswith(prefix)
        for prefix in WORKTREE_SKIP_PREFIXES
    )


def _worktree_status(cwd: Path) -> str:
    status = _git(cwd, ["status", "--short"])
    lines = []
    for line in status.splitlines():
        path = line[3:] if len(line) > 3 else ""
        if _skip_worktree_path(path):
            continue
        lines.append(line)
    return "\n".join(lines)


def _worktree_diff_args(*args: str) -> list[str]:
    return [
        "diff",
        *args,
        "--",
        ".",
        ":(exclude).bingo",
        ":(exclude).bingo/**",
    ]


def _added_highlights(patch: str) -> list[str]:
    highlights: list[str] = []
    current_file = ""
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if current_file in HIGHLIGHT_SKIP_PATHS or current_file.startswith(".bingo/"):
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        text = line[1:].strip()
        if not text or text.startswith(("#", "//", "*")):
            continue
        if "<!-- commit:" in text or text in {
            WORKTREE_START,
            WORKTREE_END,
            BINGO_AUTO_START,
            BINGO_AUTO_END,
        }:
            continue
        if SECRET_LINE_RE.search(text):
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
    status = _worktree_status(repo)
    path = workspace_memory_path(repo, memory_root)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    existing = _without_worktree_snapshot(existing).rstrip()
    if not status:
        if path.exists():
            path.write_text(existing + "\n", encoding="utf-8")
        return path if path.exists() else None

    stat = _git(repo, _worktree_diff_args("--stat"))
    patch = _git(repo, _worktree_diff_args("--unified=0", "--no-ext-diff"))
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


def _bingo_auto_block(source_path: Path, source_content: str, repo: Path) -> str:
    content = _compact_project_memory_source(source_content) or "_No captured workspace memory yet._"
    return (
        f"{BINGO_AUTO_START}\n"
        "## Auto-captured workspace memory\n\n"
        f"- Last synced: {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
        f"- Workspace: `{repo}`\n"
        f"- Source: `{source_path}`\n\n"
        f"{content}\n"
        f"{BINGO_AUTO_END}\n"
    )


def _first_commit_block(content: str) -> str:
    marker = "<!-- commit:"
    start = content.find(marker)
    if start < 0:
        return ""
    candidates = [
        pos for pos in (
            content.find("\n<!-- commit:", start + len(marker)),
            content.find("\n# Workspace Memory", start + len(marker)),
        )
        if pos > start
    ]
    end = min(candidates) if candidates else len(content)
    return content[start:end].strip()


def _compact_project_memory_source(source_content: str) -> str:
    """Keep project memory concise and prevent stale generated history nesting.

    Workspace MEMORY.md can accumulate previous project-memory sync output when
    committed memory files are recorded.  For the tracked `.bingo` mirror, keep
    only the current worktree snapshot and newest commit entry so old deleted
    file names or large prompt payloads do not reappear in future sessions.
    """
    source_content = source_content.strip()
    if not source_content:
        return ""

    sections: list[str] = []
    worktree_match = re.search(
        rf"{re.escape(WORKTREE_START)}.*?{re.escape(WORKTREE_END)}",
        source_content,
        flags=re.DOTALL,
    )
    if worktree_match:
        sections.append(worktree_match.group(0).strip())

    commit_block = _first_commit_block(source_content)
    if commit_block:
        sections.append(
            "# Workspace Memory\n\n"
            "> Automatically records committed code changes. Newest entries appear first.\n\n"
            + commit_block
        )

    return "\n\n".join(sections) if sections else source_content


def _drop_generated_bingo_tail(tail: str) -> str:
    """Drop stale generated memory accidentally preserved after the auto block."""
    stripped = tail.strip()
    if not stripped:
        return ""
    if (
        stripped.startswith("# Workspace Memory")
        or WORKTREE_START in stripped
        or "<!-- commit:" in stripped
    ):
        return ""
    return tail


def sync_bingo_project_memory(
    cwd: str | Path,
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
) -> Path:
    """Mirror workspace memory into `.bingo/project-memory.md` for future Bingo runs.

    The auto block is replaced on every sync while any manual notes outside the
    block are preserved. AGENTS.md is responsible for making future Bingo
    sessions load this file.
    """
    repo = Path(cwd).resolve()
    source = workspace_memory_path(repo, memory_root)
    source_content = source.read_text(encoding="utf-8", errors="replace") if source.exists() else ""
    path = bingo_project_memory_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)

    header = (
        "# Bingo Project Memory\n\n"
        "> Project-local persistent memory for Bingo sessions launched from this repository.\n"
        "> Keep durable facts, decisions, and verification status here. Do not store secrets.\n\n"
        "## Persistent Notes\n\n"
        "- Next Bingo session must read this file before modifying the project.\n"
        "- Preserve unrelated user changes unless the task explicitly includes them.\n\n"
    )
    auto_block = _bingo_auto_block(source, source_content, repo)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    if not existing.strip():
        content = header + auto_block
    elif BINGO_AUTO_START in existing and BINGO_AUTO_END in existing:
        before, _, rest = existing.partition(BINGO_AUTO_START)
        _, _, after = rest.partition(BINGO_AUTO_END)
        after = _drop_generated_bingo_tail(after)
        content = before.rstrip() + "\n\n" + auto_block
        if after.strip():
            content += "\n" + after.strip() + "\n"
    else:
        content = existing.rstrip() + "\n\n" + auto_block

    encoded = content.encode("utf-8")
    if len(encoded) > MAX_MEMORY_BYTES:
        content = encoded[:MAX_MEMORY_BYTES].decode("utf-8", errors="ignore")
    path.write_text(content.rstrip() + "\n", encoding="utf-8")
    return path


def _worktree_fingerprint(repo: Path) -> str:
    """Hash dirty paths plus mtimes so repeated edits are not missed."""
    porcelain = _git(repo, ["status", "--porcelain=v1"])
    kept_entries = []
    for entry in porcelain.splitlines():
        if len(entry) < 4:
            continue
        item_path = entry[3:]
        if _skip_worktree_path(item_path):
            continue
        kept_entries.append(entry)
    digest = hashlib.sha256("\n".join(kept_entries).encode())
    for entry in kept_entries:
        item_path = entry[3:]
        if " -> " in item_path:
            item_path = item_path.rsplit(" -> ", 1)[-1]
        path = repo / item_path
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


def bootstrap_change_memory(
    cwd: str | Path,
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
    sync_bingo_memory: bool = False,
) -> tuple[Path, Path]:
    """Install automatic recording and backfill the current HEAD immediately."""
    repo = Path(cwd).resolve()
    hook_path = ensure_post_commit_hook(repo)
    memory_path = record_commit(repo, "HEAD", memory_root)
    if sync_bingo_memory:
        sync_bingo_project_memory(repo, memory_root)
    return hook_path, memory_path


def watch_worktree_changes(
    cwd: str | Path,
    poll_interval: float = 2.0,
    memory_root: str | Path = DEFAULT_MEMORY_ROOT,
    sync_bingo_memory: bool = False,
) -> None:
    """Continuously mirror working-tree edits into transient workspace memory."""
    repo = Path(cwd).resolve()
    try:
        bootstrap_change_memory(repo, memory_root, sync_bingo_memory)
    except Exception:
        # Memory recording must continue even if a custom hook cannot be wrapped.
        try:
            record_commit(repo, "HEAD", memory_root)
            if sync_bingo_memory:
                sync_bingo_project_memory(repo, memory_root)
        except Exception:
            pass
    last_fingerprint = ""
    while True:
        try:
            fingerprint = _worktree_fingerprint(repo)
            if fingerprint != last_fingerprint:
                record_worktree_snapshot(repo, memory_root)
                if sync_bingo_memory:
                    sync_bingo_project_memory(repo, memory_root)
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
    parser.add_argument("--snapshot", action="store_true", help="Record current uncommitted worktree")
    parser.add_argument("--watch", action="store_true", help="Continuously record worktree changes")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--sync-bingo-memory", action="store_true")
    args = parser.parse_args(argv)
    if args.watch:
        watch_worktree_changes(
            args.cwd,
            poll_interval=args.poll_interval,
            memory_root=args.memory_root,
            sync_bingo_memory=args.sync_bingo_memory,
        )
        return 0
    if args.install_hook:
        ensure_post_commit_hook(args.cwd)
    if args.snapshot:
        path = record_worktree_snapshot(args.cwd, args.memory_root)
        if path is None:
            path = workspace_memory_path(args.cwd, args.memory_root)
    else:
        path = record_commit(args.cwd, args.commit, args.memory_root)
    if args.sync_bingo_memory:
        path = sync_bingo_project_memory(args.cwd, args.memory_root)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
