"""
Parallel Agent Execution - Run multiple agents simultaneously
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from loguru import logger

from src.sdk.agent import Agent
from src.sdk.runner import Runner, RunResult


@dataclass
class ParallelTask:
    """A task for parallel execution."""
    agent: Agent
    prompt: str
    task_id: str


@dataclass
class ParallelResult:
    """Result from parallel agent execution."""
    task_id: str
    agent_name: str
    result: Optional[RunResult]
    error: Optional[str] = None
    duration_seconds: float = 0.0


class ParallelRunner:
    """
    Run multiple agents in parallel for faster operations using asyncio.
    """

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.semaphore = asyncio.Semaphore(max_workers)

    async def _run_single(self, task: ParallelTask) -> ParallelResult:
        """Run a single agent task using a dedicated Runner instance."""
        start = time.time()
        async with self.semaphore:
            try:
                logger.info(f"[Parallel] Starting {task.agent.name}: {task.task_id}")
                # Each task gets its own Runner instance
                runner = Runner()
                result = await runner.run(task.agent, task.prompt)
                duration = time.time() - start
                logger.info(f"[Parallel] Completed {task.agent.name} in {duration:.2f}s")
                return ParallelResult(
                    task_id=task.task_id,
                    agent_name=task.agent.name,
                    result=result,
                    duration_seconds=duration
                )
            except Exception as e:
                duration = time.time() - start
                logger.error(f"[Parallel] Error in {task.agent.name}: {e}")
                return ParallelResult(
                    task_id=task.task_id,
                    agent_name=task.agent.name,
                    result=None,
                    error=str(e),
                    duration_seconds=duration
                )
    
    async def run_parallel(self, tasks: List[ParallelTask]) -> List[ParallelResult]:
        """Run multiple agent tasks in parallel using asyncio.gather."""
        logger.info(f"[Parallel] Running {len(tasks)} tasks with {self.max_workers} workers")
        
        async_tasks = [self._run_single(task) for task in tasks]
        results = await asyncio.gather(*async_tasks)
        
        total_time = sum(r.duration_seconds for r in results)
        max_time = max(r.duration_seconds for r in results) if results else 0
        
        logger.info(f"[Parallel] All tasks complete. Parallel time: {max_time:.2f}s (vs {total_time:.2f}s sequential)")
        
        return results
    
    def shutdown(self):
        """No-op for compatibility."""
        pass


async def run_recon_and_websec(target: str) -> Dict[str, ParallelResult]:
    """Convenience function to run recon and websec in parallel."""
    from src.agents import create_recon_agent, create_websec_agent
    from src.sdk.key_manager import get_key_manager
    km = get_key_manager()
    model = km.get_model()
    
    runner = ParallelRunner(max_workers=2)
    
    tasks = [
        ParallelTask(
            agent=create_recon_agent(model=model),
            prompt=f"Scan {target} for open ports and subdomains",
            task_id="recon"
        ),
        ParallelTask(
            agent=create_websec_agent(model=model),
            prompt=f"Find directories and check for vulnerabilities on {target}",
            task_id="websec"
        )
    ]
    
    results = await runner.run_parallel(tasks)
    return {r.task_id: r for r in results}


async def run_full_assessment(target: str) -> Dict[str, ParallelResult]:
    """Run a full security assessment with multiple agents in parallel."""
    from src.agents import create_recon_agent, create_websec_agent, create_dfir_agent
    from src.sdk.key_manager import get_key_manager
    km = get_key_manager()
    model = km.get_model()
    
    runner = ParallelRunner(max_workers=3)
    
    tasks = [
        ParallelTask(
            agent=create_recon_agent(model=model),
            prompt=f"Full reconnaissance on {target}: ports, DNS, subdomains, WHOIS",
            task_id="recon"
        ),
        ParallelTask(
            agent=create_websec_agent(model=model),
            prompt=f"Web security scan on {target}: directories, nikto scan",
            task_id="websec"
        ),
        ParallelTask(
            agent=create_dfir_agent(model=model),
            prompt=f"Investigate {target} for any suspicious indicators",
            task_id="dfir"
        )
    ]
    
    results = await runner.run_parallel(tasks)
    return {r.task_id: r for r in results}
