"""
Async Tool Execution System
Non-blocking tool execution with background processing.
"""

import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from loguru import logger


class TaskStatus(Enum):
    """Status of an async task."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AsyncTask:
    """Represents an async tool execution task."""
    id: str
    tool_name: str
    args: dict
    status: TaskStatus = TaskStatus.PENDING
    result: str = ""
    error: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    callback: Optional[Callable] = None
    
    @property
    def duration(self) -> float:
        """Get task duration in seconds."""
        if self.started_at:
            end = self.completed_at or datetime.now()
            return (end - self.started_at).total_seconds()
        return 0


class AsyncExecutor:
    """
    Manages asynchronous tool execution.
    
    Features:
    - Non-blocking execution
    - Task queue management
    - Progress tracking
    - Callback support
    - Task cancellation
    """
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks: Dict[str, AsyncTask] = {}
        self.futures: Dict[str, Future] = {}
        self._lock = threading.Lock()
        self._callbacks: List[Callable] = []
    
    def submit(self, tool_name: str, args: dict, 
               executor_func: Callable, 
               callback: Callable = None) -> str:
        """
        Submit a tool for async execution.
        
        Args:
            tool_name: Name of the tool
            args: Tool arguments
            executor_func: Function to execute (takes args, returns result)
            callback: Optional callback when complete (receives task)
        
        Returns:
            Task ID
        """
        task_id = str(uuid.uuid4())[:8]
        
        task = AsyncTask(
            id=task_id,
            tool_name=tool_name,
            args=args,
            callback=callback
        )
        
        with self._lock:
            self.tasks[task_id] = task
        
        # Submit to thread pool
        future = self.executor.submit(
            self._execute_task,
            task_id,
            executor_func,
            args
        )
        
        self.futures[task_id] = future
        
        logger.info(f"⚡ Task submitted: {tool_name} (ID: {task_id})")
        return task_id
    
    def _execute_task(self, task_id: str, executor_func: Callable, args: dict):
        """Execute a task in background thread."""
        task = self.tasks.get(task_id)
        if not task:
            return
        
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.now()
        
        try:
            result = executor_func(**args)
            task.result = result
            task.status = TaskStatus.COMPLETED
        except Exception as e:
            task.error = str(e)
            task.status = TaskStatus.FAILED
            logger.error(f"Task {task_id} failed: {e}")
        finally:
            task.completed_at = datetime.now()
            
            # Execute callback if provided
            if task.callback:
                try:
                    task.callback(task)
                except Exception as e:
                    logger.error(f"Callback failed: {e}")
            
            # Notify global callbacks
            for callback in self._callbacks:
                try:
                    callback(task)
                except Exception as e:
                    logger.error(f"Global callback failed: {e}")
    
    def get_task(self, task_id: str) -> Optional[AsyncTask]:
        """Get a task by ID."""
        return self.tasks.get(task_id)
    
    def get_result(self, task_id: str, timeout: float = None) -> Optional[str]:
        """
        Get task result, optionally waiting for completion.
        
        Args:
            task_id: Task ID
            timeout: Seconds to wait (None = don't wait)
        
        Returns:
            Result or None if not available
        """
        task = self.tasks.get(task_id)
        if not task:
            return None
        
        if task.status == TaskStatus.COMPLETED:
            return task.result
        
        if task.status == TaskStatus.FAILED:
            return f"ERROR: {task.error}"
        
        if timeout and task_id in self.futures:
            try:
                self.futures[task_id].result(timeout=timeout)
                return task.result
            except Exception as e:
                return f"ERROR: {e}"
        
        return None
    
    def wait(self, task_id: str, timeout: float = 300) -> AsyncTask:
        """
        Wait for a task to complete.
        
        Args:
            task_id: Task ID
            timeout: Maximum seconds to wait
        
        Returns:
            Task object
        """
        if task_id in self.futures:
            try:
                self.futures[task_id].result(timeout=timeout)
            except Exception as e:
                logger.error(f"Wait failed: {e}")
        
        return self.tasks.get(task_id)
    
    def cancel(self, task_id: str) -> bool:
        """
        Cancel a pending or running task.
        
        Returns:
            True if cancelled successfully
        """
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            return False
        
        if task_id in self.futures:
            cancelled = self.futures[task_id].cancel()
            if cancelled:
                task.status = TaskStatus.CANCELLED
                return True
        
        return False
    
    def list_tasks(self, status: TaskStatus = None) -> List[AsyncTask]:
        """List all tasks, optionally filtered by status."""
        with self._lock:
            if status:
                return [t for t in self.tasks.values() if t.status == status]
            return list(self.tasks.values())
    
    def get_running(self) -> List[AsyncTask]:
        """Get all running tasks."""
        return self.list_tasks(TaskStatus.RUNNING)
    
    def get_pending(self) -> List[AsyncTask]:
        """Get all pending tasks."""
        return self.list_tasks(TaskStatus.PENDING)
    
    def clear_completed(self) -> int:
        """Remove completed tasks from memory."""
        with self._lock:
            to_remove = [
                tid for tid, task in self.tasks.items()
                if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
            ]
            for tid in to_remove:
                del self.tasks[tid]
                if tid in self.futures:
                    del self.futures[tid]
            return len(to_remove)
    
    def on_complete(self, callback: Callable):
        """Register a callback for all task completions."""
        self._callbacks.append(callback)
    
    def shutdown(self, wait: bool = True):
        """Shutdown the executor."""
        self.executor.shutdown(wait=wait)
    
    def get_status(self) -> str:
        """Get formatted status."""
        running = len(self.get_running())
        pending = len(self.get_pending())
        completed = len(self.list_tasks(TaskStatus.COMPLETED))
        failed = len(self.list_tasks(TaskStatus.FAILED))
        
        lines = [
            "╔══════════════════════════════════════════════════════════════",
            "║ ⚡ ASYNC EXECUTOR STATUS",
            "╠══════════════════════════════════════════════════════════════",
            f"║ Workers: {self.max_workers}",
            f"║ Running: {running}",
            f"║ Pending: {pending}",
            f"║ Completed: {completed}",
            f"║ Failed: {failed}",
        ]
        
        # Show running tasks
        if running > 0:
            lines.append("╠══════════════════════════════════════════════════════════════")
            lines.append("║ Running Tasks:")
            for task in self.get_running():
                duration = task.duration
                lines.append(f"║   ▶ {task.tool_name} ({task.id}) - {duration:.1f}s")
        
        lines.append("╚══════════════════════════════════════════════════════════════")
        
        return "\n".join(lines)


# Global instance
_async_executor: Optional[AsyncExecutor] = None


def get_async_executor() -> AsyncExecutor:
    """Get or create the global async executor."""
    global _async_executor
    if _async_executor is None:
        _async_executor = AsyncExecutor()
    return _async_executor


def run_async(tool_name: str, args: dict, executor_func: Callable,
              callback: Callable = None) -> str:
    """
    Quick function to run a tool asynchronously.
    
    Returns:
        Task ID
    """
    return get_async_executor().submit(tool_name, args, executor_func, callback)


def wait_for_task(task_id: str, timeout: float = 300) -> Optional[str]:
    """Wait for a task and return its result."""
    task = get_async_executor().wait(task_id, timeout)
    if task:
        if task.status == TaskStatus.COMPLETED:
            return task.result
        elif task.status == TaskStatus.FAILED:
            return f"ERROR: {task.error}"
    return None


def get_task_status(task_id: str) -> Optional[Dict]:
    """Get task status as a dict."""
    task = get_async_executor().get_task(task_id)
    if task:
        return {
            "id": task.id,
            "tool": task.tool_name,
            "status": task.status.value,
            "duration": task.duration,
            "result": task.result if task.status == TaskStatus.COMPLETED else None,
            "error": task.error if task.status == TaskStatus.FAILED else None
        }
    return None
