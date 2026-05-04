"""
Priority-based task queue for the CTF Agent system.
"""

import heapq
import threading
from typing import Dict, List, Optional, Set, Any

from core.task_manager.task import Task, TaskPriority, TaskStatus


class TaskQueue:
    """
    Thread-safe priority queue for Tasks.
    Handles dependencies and blocking status.
    """

    def __init__(self):
        self._tasks: Dict[str, Task] = {}
        self._queue: List[tuple] = []  # Priority queue: (-priority_val, timestamp, task_id)
        self._completed_task_ids: Set[str] = set()
        self._lock = threading.Lock()

    def add_task(self, task: Task) -> None:
        """Add a task to the queue."""
        with self._lock:
            self._tasks[task.id] = task
            if self._is_ready(task):
                # Heapq is a min-heap, so we negate the priority value for a max-priority queue
                heapq.heappush(self._queue, (-task.priority.value, task.created_at.timestamp(), task.id))
            else:
                task.status = TaskStatus.BLOCKED

    def get_next_task(self) -> Optional[Task]:
        """Retrieve the next highest-priority ready task."""
        with self._lock:
            if not self._queue:
                return None
            
            _, _, task_id = heapq.heappop(self._queue)
            task = self._tasks[task_id]
            task.status = TaskStatus.IN_PROGRESS
            return task

    def complete_task(self, task_id: str, result: Optional[Dict[str, Any]] = None) -> None:
        """Mark a task as completed and check for newly unblocked tasks."""
        with self._lock:
            if task_id not in self._tasks:
                return
            
            task = self._tasks[task_id]
            task.status = TaskStatus.COMPLETED
            task.result = result
            self._completed_task_ids.add(task_id)
            
            # Re-check all blocked tasks to see if they can now be queued
            for tid, t in self._tasks.items():
                if t.status == TaskStatus.BLOCKED and self._is_ready(t):
                    t.status = TaskStatus.PENDING
                    heapq.heappush(self._queue, (-t.priority.value, t.created_at.timestamp(), tid))

    def fail_task(self, task_id: str, error: str) -> None:
        """Mark a task as failed."""
        with self._lock:
            if task_id not in self._tasks:
                return
            task = self._tasks[task_id]
            task.status = TaskStatus.FAILED
            task.error = error

    def _is_ready(self, task: Task) -> bool:
        """Check if all dependencies for a task are completed."""
        return all(dep_id in self._completed_task_ids for dep_id in task.dependencies)

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by its ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(self) -> List[Task]:
        """Return a list of all tasks."""
        with self._lock:
            return list(self._tasks.values())
