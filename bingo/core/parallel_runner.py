"""
bingo Parallel Runner — Cursor처럼 여러 작업을 동시에 실행.

사용법:
    from bingo.core.parallel_runner import ParallelRunner, Task

    runner = ParallelRunner()
    results = runner.run([
        Task("recon",   recon_fn,   args=(url,)),
        Task("sqli",    sqli_fn,    args=(url,)),
        Task("webvuln", webvuln_fn, args=(url,)),
    ])
"""
from __future__ import annotations
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import Any, Callable
from enum import Enum


class TaskStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    DONE      = "done"
    ERROR     = "error"


@dataclass
class Task:
    name:    str
    fn:      Callable
    args:    tuple  = field(default_factory=tuple)
    kwargs:  dict   = field(default_factory=dict)
    timeout: float  = 120.0

    # 런타임에 채워짐
    status:     TaskStatus = field(default=TaskStatus.PENDING, init=False)
    result:     Any        = field(default=None, init=False)
    error:      str        = field(default="",   init=False)
    start_time: float      = field(default=0.0,  init=False)
    end_time:   float      = field(default=0.0,  init=False)

    @property
    def elapsed(self) -> float:
        if self.start_time == 0:
            return 0.0
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time


class ParallelRunner:
    """
    Cursor Agent처럼 여러 태스크를 동시에 실행하고 실시간으로 상태를 표시.

    Args:
        max_workers: 동시 실행할 최대 스레드 수 (기본 5)
        on_start:    태스크 시작 시 콜백 fn(task)
        on_done:     태스크 완료 시 콜백 fn(task)
        on_error:    태스크 에러 시 콜백 fn(task)
    """

    def __init__(
        self,
        max_workers: int = 5,
        on_start:  Callable[[Task], None] | None = None,
        on_done:   Callable[[Task], None] | None = None,
        on_error:  Callable[[Task], None] | None = None,
    ):
        self.max_workers = max_workers
        self.on_start = on_start
        self.on_done  = on_done
        self.on_error = on_error
        self._lock = threading.Lock()

    def run(self, tasks: list[Task]) -> dict[str, Any]:
        """
        모든 태스크를 병렬로 실행. 완료되면 {name: result} 딕셔너리 반환.
        """
        results: dict[str, Any] = {}

        def _run_task(task: Task) -> Task:
            task.status     = TaskStatus.RUNNING
            task.start_time = time.time()
            if self.on_start:
                try:
                    self.on_start(task)
                except Exception:
                    pass
            try:
                task.result = task.fn(*task.args, **task.kwargs)
                task.status = TaskStatus.DONE
                task.end_time = time.time()
                if self.on_done:
                    try:
                        self.on_done(task)
                    except Exception:
                        pass
            except Exception as e:
                task.status   = TaskStatus.ERROR
                task.error    = str(e)
                task.end_time = time.time()
                if self.on_error:
                    try:
                        self.on_error(task)
                    except Exception:
                        pass
            return task

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task: dict[Future, Task] = {
                executor.submit(_run_task, task): task
                for task in tasks
            }
            for future in as_completed(future_to_task, timeout=max(t.timeout for t in tasks)):
                task = future_to_task[future]
                try:
                    completed = future.result()
                    results[completed.name] = completed.result
                except Exception as e:
                    task.error  = str(e)
                    task.status = TaskStatus.ERROR
                    results[task.name] = None

        return results

    def run_with_progress(self, tasks: list[Task],
                          console=None) -> dict[str, Any]:
        """
        Rich Live 진행 상황 표시와 함께 병렬 실행.
        Cursor의 툴 실행 카드처럼 각 태스크가 실시간 상태 표시.
        """
        try:
            from rich.console import Console
            from rich.live import Live
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            return self.run(tasks)

        if console is None:
            from rich.console import Console
            console = Console()

        task_map = {t.name: t for t in tasks}

        def make_table() -> Table:
            table = Table(
                show_header=False,
                box=None,
                padding=(0, 1),
                expand=False,
            )
            table.add_column("icon",   width=3)
            table.add_column("name",   style="bold")
            table.add_column("status", width=12)
            table.add_column("detail", style="dim")

            icons = {
                TaskStatus.PENDING: "○",
                TaskStatus.RUNNING: "◌",
                TaskStatus.DONE:    "✓",
                TaskStatus.ERROR:   "✗",
            }
            colors = {
                TaskStatus.PENDING: "dim",
                TaskStatus.RUNNING: "cyan",
                TaskStatus.DONE:    "green",
                TaskStatus.ERROR:   "red",
            }
            for task in tasks:
                icon  = icons[task.status]
                color = colors[task.status]
                if task.status == TaskStatus.RUNNING:
                    detail = f"{task.elapsed:.1f}s..."
                elif task.status == TaskStatus.DONE:
                    result_summary = _summarize_result(task.result)
                    detail = f"{task.elapsed:.1f}s  {result_summary}"
                elif task.status == TaskStatus.ERROR:
                    detail = f"ERROR: {task.error[:50]}"
                else:
                    detail = "waiting..."

                table.add_row(
                    f"[{color}]{icon}[/{color}]",
                    f"[{color}]{task.name}[/{color}]",
                    f"[{color}]{task.status.value}[/{color}]",
                    detail,
                )
            return table

        results: dict[str, Any] = {}

        def _run_task_live(task: Task) -> Task:
            task.status     = TaskStatus.RUNNING
            task.start_time = time.time()
            try:
                task.result = task.fn(*task.args, **task.kwargs)
                task.status = TaskStatus.DONE
            except Exception as e:
                task.status = TaskStatus.ERROR
                task.error  = str(e)
            finally:
                task.end_time = time.time()
            return task

        with Live(make_table(), console=console, refresh_per_second=4,
                  transient=False) as live:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {
                    executor.submit(_run_task_live, task): task
                    for task in tasks
                }
                for future in as_completed(future_to_task,
                                            timeout=max(t.timeout for t in tasks)):
                    task = future_to_task[future]
                    try:
                        completed = future.result()
                        results[completed.name] = completed.result
                    except Exception as e:
                        task.error  = str(e)
                        task.status = TaskStatus.ERROR
                        results[task.name] = None
                    live.update(make_table())

        return results


def _summarize_result(result: Any) -> str:
    """결과를 짧은 요약 문자열로 변환."""
    if result is None:
        return "no result"
    if isinstance(result, list):
        return f"{len(result)} items"
    if isinstance(result, dict):
        keys = [k for k, v in result.items() if v]
        return f"{len(keys)} findings" if keys else "no findings"
    if isinstance(result, str):
        return result[:40]
    return str(result)[:40]
