"""
bingo File Watcher — 스크립트가 생성/수정한 파일을 실시간으로 감지.

로컬 파일 이벤트 관찰과 동일한 역할:
  - 임시 스크립트 출력 파일 자동 감지
  - 새 발견 사항(.txt/.json/.log) 자동 읽기
  - 콜백으로 터미널에 실시간 알림

사용법:
    watcher = FileWatcher(watch_dirs=["/tmp/bingo_agent"])
    watcher.start(on_new_file=my_callback)
    # ... 작업 ...
    watcher.stop()
"""
from __future__ import annotations
import os, time, threading
from pathlib import Path
from typing import Callable


class FileWatcher:
    """
    주어진 디렉터리를 실시간으로 감시하고 새 파일/변경 파일을 감지.
    watchdog 라이브러리 없이도 동작 (폴링 방식 폴백).
    """

    def __init__(
        self,
        watch_dirs: list[str | Path] | None = None,
        poll_interval: float = 0.5,
    ):
        self.watch_dirs    = [Path(d) for d in (watch_dirs or [])]
        self.poll_interval = poll_interval
        self._known:    dict[Path, float] = {}  # path → mtime
        self._running   = threading.Event()
        self._thread:   threading.Thread | None = None
        self._callbacks: list[Callable[[Path, str], None]] = []

    def add_watch_dir(self, d: str | Path) -> None:
        p = Path(d)
        p.mkdir(parents=True, exist_ok=True)
        if p not in self.watch_dirs:
            self.watch_dirs.append(p)

    def on_change(self, callback: Callable[[Path, str], None]) -> None:
        """파일 변경 시 호출될 콜백 등록. callback(path, event_type)"""
        self._callbacks.append(callback)

    def start(self) -> None:
        """감시 스레드 시작."""
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """감시 스레드 중지."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=2)

    def _poll_loop(self) -> None:
        while self._running.is_set():
            for watch_dir in self.watch_dirs:
                if not watch_dir.exists():
                    continue
                try:
                    for path in watch_dir.rglob("*"):
                        if not path.is_file():
                            continue
                        try:
                            mtime = path.stat().st_mtime
                        except Exception:
                            continue
                        old_mtime = self._known.get(path)
                        if old_mtime is None:
                            self._known[path] = mtime
                            self._fire(path, "created")
                        elif mtime > old_mtime:
                            self._known[path] = mtime
                            self._fire(path, "modified")
                except Exception:
                    pass
            time.sleep(self.poll_interval)

    def _fire(self, path: Path, event: str) -> None:
        for cb in self._callbacks:
            try:
                cb(path, event)
            except Exception:
                pass


class AgentOutputWatcher(FileWatcher):
    """
    bingo 에이전트가 생성한 출력 파일을 실시간 감지하고 콘솔에 표시.

    자동 감지 파일:
      - /tmp/bingo_agent/*.py 실행 결과
      - ~/.bingo/output/*.json / *.txt
      - /tmp/bingo_findings.*
    """

    _WATCH_EXTENSIONS = {".txt", ".json", ".log", ".csv", ".md", ".out"}
    _IGNORE_PATTERNS  = {"__pycache__", ".pyc", ".DS_Store"}

    def __init__(self, console=None):
        import tempfile
        default_dirs = [
            Path(tempfile.gettempdir()) / "bingo_agent",
            Path.home() / ".bingo" / "output",
        ]
        for d in default_dirs:
            d.mkdir(parents=True, exist_ok=True)

        super().__init__(watch_dirs=default_dirs, poll_interval=0.8)
        self.console = console
        self._printed: set[Path] = set()
        self.on_change(self._handle_file_event)

    def _handle_file_event(self, path: Path, event: str) -> None:
        """새 파일 감지 시 내용 읽어서 콘솔에 표시."""
        if path in self._printed:
            return
        if path.suffix not in self._WATCH_EXTENSIONS:
            return
        if any(p in str(path) for p in self._IGNORE_PATTERNS):
            return
        if path.stat().st_size == 0:
            return

        self._printed.add(path)

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            if len(content) < 10:
                return

            if self.console:
                from rich.panel import Panel
                preview = content[:500] + ("..." if len(content) > 500 else "")
                self.console.print(Panel(
                    f"[dim]{preview}[/dim]",
                    title=f"[cyan]📄 {path.name}[/cyan] [dim]({event})[/dim]",
                    border_style="dim cyan",
                    expand=False,
                ))
            else:
                print(f"\n[FILE_WATCH] {path.name}: {content[:200]}")
        except Exception:
            pass

    def save_finding(self, name: str, content: str) -> Path:
        """발견 사항을 파일로 저장 (자동 감지됨)."""
        out_dir = Path.home() / ".bingo" / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time())
        path = out_dir / f"{name}_{ts}.txt"
        path.write_text(content, encoding="utf-8")
        return path
