"""
Unit tests for the Task Manager.
"""

import pytest
from datetime import datetime
from core.task_manager.task import Task, TaskStatus, TaskPriority
from core.task_manager.task_queue import TaskQueue

def test_task_creation():
    task = Task(id="test_1", description="Test task")
    assert task.id == "test_1"
    assert task.status == TaskStatus.PENDING
    assert task.priority == TaskPriority.MEDIUM

def test_task_queue_priority():
    queue = TaskQueue()
    task_low = Task(id="low", description="Low priority", priority=TaskPriority.LOW)
    task_high = Task(id="high", description="High priority", priority=TaskPriority.HIGH)
    
    queue.add_task(task_low)
    queue.add_task(task_high)
    
    next_task = queue.get_next_task()
    assert next_task.id == "high"
    
    next_task = queue.get_next_task()
    assert next_task.id == "low"

def test_task_dependencies():
    queue = TaskQueue()
    task_1 = Task(id="task_1", description="First task")
    task_2 = Task(id="task_2", description="Second task", dependencies=["task_1"])
    
    queue.add_task(task_1)
    queue.add_task(task_2)
    
    # task_2 should be blocked
    assert queue.get_task("task_2").status == TaskStatus.BLOCKED
    
    # Get task_1
    t1 = queue.get_next_task()
    assert t1.id == "task_1"
    
    # task_2 still not ready
    assert queue.get_next_task() is None
    
    # Complete task_1
    queue.complete_task("task_1")
    
    # Now task_2 should be ready
    t2 = queue.get_next_task()
    assert t2.id == "task_2"
    assert t2.status == TaskStatus.IN_PROGRESS
