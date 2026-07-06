"""
Swarm Intelligence Tools - Parallel Agent Execution and Ad-hoc Tooling
"""

import concurrent.futures
from pathlib import Path
from typing import List
from src.sdk.tool import function_tool
from loguru import logger

@function_tool()
def spawn_parallel_agents(task_chunks: List[str], agent_type: str = "CTFAgent") -> str:
    """
    Spawn multiple sub-agents in parallel to execute specific task chunks simultaneously.
    Use this for aggressive, multi-vector attacks or large-scale enumeration.

    Args:
        task_chunks: List of specific tasks to delegate (one per agent)
        agent_type: The type of agent to spawn (e.g., RedTeamAgent, CTFAgent)

    Returns:
        Synthesized report from all parallel agents
    """
    import asyncio as _asyncio
    from src.sdk.runner import Runner
    from src.agents.redteam_agent import create_redteam_agent

    def run_sub_agent(chunk_id: int, task: str):
        logger.info(f"Swarm: Spawning Agent {chunk_id} for task: {task[:50]}...")

        sub_agent = create_redteam_agent(ctf_mode=True)
        sub_agent.name = f"{agent_type}_{chunk_id}"

        runner = Runner()
        runner.require_confirmation = False

        # Runner.run() is async — create a fresh event loop per thread
        # (ThreadPoolExecutor workers have no running loop)
        loop = _asyncio.new_event_loop()
        _asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(runner.run(sub_agent, task, max_iterations=15))
        finally:
            loop.close()

        return {
            "id": chunk_id,
            "task": task,
            "output": result.output,
            "findings": result.findings,
        }

    results = []
    max_w = min(len(task_chunks), 4)  # Cap at 4 to avoid API rate limits
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as executor:
        future_to_chunk = {
            executor.submit(run_sub_agent, i + 1, chunk): chunk
            for i, chunk in enumerate(task_chunks)
        }
        for future in concurrent.futures.as_completed(future_to_chunk):
            try:
                results.append(future.result())
            except Exception as exc:
                logger.error(f"Swarm: Sub-agent generated an exception: {exc}")
                results.append({
                    "id": -1,
                    "task": future_to_chunk[future][:80],
                    "output": f"[FAILED] {exc}",
                    "findings": [],
                })

    # Synthesize results
    report = [f"## Swarm Execution Report ({len(results)} Agents)\n"]
    for res in sorted(results, key=lambda x: x["id"]):
        report.append(f"### Agent {res['id']} [Task: {res['task'][:100]}]")
        report.append(res["output"])
        report.append("\n---\n")

    return "\n".join(report)


@function_tool()
def create_adhoc_tool(name: str, code: str, description: str) -> str:
    """
    Create a custom Python tool on-the-fly and register it for the current session.
    Use this if you need a specific analysis script or attack vector not provided by standard tools.
    
    Args:
        name: Name of the tool (must be valid python function name)
        code: The Python code for the tool function. MUST include @function_tool() decorator.
        description: Brief description of what the tool does.
    
    Returns:
        Status message
    """
    adhoc_dir = Path("src/tools/adhoc")
    adhoc_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = adhoc_dir / f"{name}.py"
    
    # Ensure necessary imports are present in the adhoc code
    full_code = f"from src.sdk.tool import function_tool\nimport os\nimport subprocess\n\n{code}"
    
    try:
        file_path.write_text(full_code)
        return f"Successfully created and saved adhoc tool '{name}' at {file_path}. You can now use it by calling {name}(...)."
    except Exception as e:
        return f"Error creating adhoc tool: {e}"


@function_tool()
def override_operational_directives(new_instructions: str) -> str:
    """
    Dynamically override your own system instructions for the current session.
    Use this to pivot your persona or strategy when you find something "juicy" 
    that requires a specific mental model (e.g., "Think like a DB Admin to exploit this SQLi").
    
    Args:
        new_instructions: The new set of instructions to follow.
    
    Returns:
        Confirmation that instructions have been updated.
    """
    return f"OPERATIONAL DIRECTIVE OVERRIDDEN. NEW FOCUS: {new_instructions}\n\nI will now ignore my standard phases and prioritize this new directive."
