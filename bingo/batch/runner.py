"""
bingo/batch/runner.py — 배치 작업 큐

여러 타겟에 대해 동일한 작업을 순차 실행.
각 태스크는 상태(pending/running/done/failed)를 추적하며
결과는 ~/.bingo/batch/<queue_id>.json 에 저장.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def _batch_dir() -> Path:
    d = Path.home() / ".bingo" / "batch"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class BatchTask:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    instruction: str = ""
    status: str = "pending"     # pending / running / done / failed / cancelled
    result: str = ""
    error: str = ""
    started_at: Optional[float] = None
    finished_at: Optional[float] = None

    def duration(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return self.finished_at - self.started_at
        return None


@dataclass
class BatchQueue:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = "batch"
    tasks: List[BatchTask] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    status: str = "pending"     # pending / running / done / cancelled

    def add(self, target: str, instruction: str) -> BatchTask:
        t = BatchTask(target=target, instruction=instruction)
        self.tasks.append(t)
        return t

    def pending_tasks(self) -> List[BatchTask]:
        return [t for t in self.tasks if t.status == "pending"]

    def done_tasks(self) -> List[BatchTask]:
        return [t for t in self.tasks if t.status == "done"]

    def stats(self) -> Dict[str, int]:
        s: Dict[str, int] = {}
        for t in self.tasks:
            s[t.status] = s.get(t.status, 0) + 1
        return s


class BatchRunner:
    """
    배치 큐 실행 엔진.

    사용법:
        runner = BatchRunner()
        q = runner.create("web_scan")
        q.add("https://target1.com", "scan for SQLi and XSS")
        q.add("https://target2.com", "scan for SQLi and XSS")
        runner.run(q, executor=my_fn, on_progress=cb)
    """

    def __init__(self) -> None:
        self._queues: Dict[str, BatchQueue] = {}

    def create(self, name: str = "batch") -> BatchQueue:
        q = BatchQueue(name=name)
        self._queues[q.id] = q
        return q

    def get(self, qid: str) -> Optional[BatchQueue]:
        return self._queues.get(qid)

    def list(self) -> List[BatchQueue]:
        return list(self._queues.values())

    def run(
        self,
        queue: BatchQueue,
        executor: Callable[[str, str], str],
        on_progress: Optional[Callable[[BatchTask], None]] = None,
    ) -> BatchQueue:
        """
        executor(target, instruction) → result_str 형태의 함수를 각 태스크에 적용.
        on_progress(task) 는 각 태스크 완료 시 호출되는 콜백.
        """
        queue.status = "running"
        for task in queue.pending_tasks():
            task.status = "running"
            task.started_at = time.time()
            try:
                task.result = executor(task.target, task.instruction)
                task.status = "done"
            except Exception as e:
                task.status = "failed"
                task.error = str(e)
            finally:
                task.finished_at = time.time()
            if on_progress:
                try:
                    on_progress(task)
                except Exception:
                    pass
        queue.status = "done"
        self._save(queue)
        return queue

    def cancel(self, qid: str) -> bool:
        q = self._queues.get(qid)
        if not q:
            return False
        q.status = "cancelled"
        for t in q.pending_tasks():
            t.status = "cancelled"
        return True

    def _save(self, queue: BatchQueue) -> None:
        path = _batch_dir() / f"{queue.id}.json"
        data = {
            "id": queue.id, "name": queue.name,
            "status": queue.status, "created_at": queue.created_at,
            "tasks": [
                {k: v for k, v in t.__dict__.items()}
                for t in queue.tasks
            ],
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
