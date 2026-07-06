"""
Progress Tracking and Display

Provides progress bars and status indicators for long-running operations.
"""

import time
from typing import Optional, Callable, Any
from dataclasses import dataclass
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TaskProgressColumn, TimeRemainingColumn, TimeElapsedColumn
)
from rich.console import Console
from loguru import logger


console = Console()


@dataclass
class ProgressTask:
    """Represents a progress task."""
    task_id: Any
    description: str
    total: Optional[int]
    completed: int = 0
    
    def percentage(self) -> float:
        """Get completion percentage."""
        if self.total is None or self.total == 0:
            return 0.0
        return (self.completed / self.total) * 100


class ProgressTracker:
    """
    Tracks progress for multiple concurrent operations.
    """
    
    def __init__(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console
        )
        self.tasks: dict[str, ProgressTask] = {}
        self._active = False
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
    
    def start(self):
        """Start the progress display."""
        if not self._active:
            self.progress.start()
            self._active = True
    
    def stop(self):
        """Stop the progress display."""
        if self._active:
            self.progress.stop()
            self._active = False
    
    def add_task(
        self,
        name: str,
        description: str,
        total: Optional[int] = None
    ) -> str:
        """
        Add a new progress task.
        
        Args:
            name: Unique task name
            description: Task description
            total: Total steps (None for indeterminate)
        
        Returns:
            Task name
        """
        task_id = self.progress.add_task(description, total=total)
        self.tasks[name] = ProgressTask(
            task_id=task_id,
            description=description,
            total=total,
            completed=0
        )
        return name
    
    def update(
        self,
        name: str,
        advance: int = 1,
        description: Optional[str] = None,
        completed: Optional[int] = None
    ):
        """
        Update a progress task.
        
        Args:
            name: Task name
            advance: Steps to advance
            description: New description
            completed: Set absolute completed value
        """
        if name not in self.tasks:
            logger.warning(f"Task not found: {name}")
            return
        
        task = self.tasks[name]
        
        if completed is not None:
            task.completed = completed
            self.progress.update(task.task_id, completed=completed)
        else:
            task.completed += advance
            self.progress.update(task.task_id, advance=advance)
        
        if description:
            task.description = description
            self.progress.update(task.task_id, description=description)
    
    def complete(self, name: str):
        """Mark a task as complete."""
        if name not in self.tasks:
            return
        
        task = self.tasks[name]
        if task.total:
            self.progress.update(task.task_id, completed=task.total)
    
    def remove(self, name: str):
        """Remove a task."""
        if name in self.tasks:
            task = self.tasks[name]
            self.progress.remove_task(task.task_id)
            del self.tasks[name]


def with_progress(
    description: str,
    total: Optional[int] = None,
    show_spinner: bool = True
):
    """
    Decorator to show progress for a function.
    
    Args:
        description: Progress description
        total: Total steps (None for indeterminate)
        show_spinner: Show spinner for indeterminate progress
    
    Example:
        @with_progress("Scanning ports", total=100)
        def scan_ports(target, progress_callback=None):
            for i in range(100):
                # Do work
                if progress_callback:
                    progress_callback(i + 1)
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Check if function accepts progress_callback
            import inspect
            sig = inspect.signature(func)
            has_callback = 'progress_callback' in sig.parameters
            
            if has_callback:
                with ProgressTracker() as tracker:
                    tracker.add_task("main", description, total)
                    
                    def callback(completed: int):
                        tracker.update("main", completed=completed)
                    
                    kwargs['progress_callback'] = callback
                    return func(*args, **kwargs)
            else:
                # No callback support, just show indeterminate progress
                if show_spinner:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn(f"[bold blue]{description}..."),
                        console=console
                    ) as progress:
                        progress.add_task("main")
                        return func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
        
        return wrapper
    return decorator


class SimpleProgress:
    """
    Simple progress indicator for quick operations.
    """
    
    def __init__(self, description: str, total: Optional[int] = None):
        self.description = description
        self.total = total
        self.current = 0
        self.start_time = time.time()
    
    def update(self, current: Optional[int] = None):
        """Update progress."""
        if current is not None:
            self.current = current
        else:
            self.current += 1
        
        self._display()
    
    def _display(self):
        """Display progress."""
        elapsed = time.time() - self.start_time
        
        if self.total:
            percentage = (self.current / self.total) * 100
            bar_length = 30
            filled = int(bar_length * self.current / self.total)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            console.print(
                f"\r{self.description}: [{bar}] {percentage:.1f}% "
                f"({self.current}/{self.total}) - {elapsed:.1f}s",
                end=""
            )
        else:
            console.print(
                f"\r{self.description}: {self.current} items - {elapsed:.1f}s",
                end=""
            )
    
    def complete(self):
        """Mark as complete."""
        console.print()  # New line


def show_spinner(description: str, func: Callable, *args, **kwargs) -> Any:
    """
    Show a spinner while executing a function.
    
    Args:
        description: Spinner description
        func: Function to execute
        *args, **kwargs: Function arguments
    
    Returns:
        Function result
    """
    with Progress(
        SpinnerColumn(),
        TextColumn(f"[bold blue]{description}..."),
        console=console
    ) as progress:
        progress.add_task("spinner")
        return func(*args, **kwargs)


# Global progress tracker
_global_tracker: Optional[ProgressTracker] = None


def get_progress_tracker() -> ProgressTracker:
    """Get or create the global progress tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = ProgressTracker()
    return _global_tracker
