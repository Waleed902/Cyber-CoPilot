"""Long-running task controls backed by tmux and the SQLite event log."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from src.sdk.event_log import get_event_log
from src.sdk.tool import function_tool
from src.tools.interactive_shell import get_manager


def _active_target(explicit: str = "") -> str:
    if explicit:
        return explicit
    try:
        from src.sdk.context_hub import get_context_hub

        return get_context_hub().current_target or ""
    except Exception:
        return ""


def _slug(value: str, default: str = "task") -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]+", "_", value or "").strip("_")
    return clean[:40] or default


def _task_id(command: str, session: str) -> str:
    digest = hashlib.sha1(f"{session}:{command}".encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"lt_{_slug(session, 'main')}_{digest}"


def _status_from_screen(screen: str, previous_status: str = "running") -> str:
    if screen.startswith("[IDLE]"):
        return "completed" if previous_status == "running" else previous_status
    if "[ERROR]" in screen:
        return "failed"
    return "running"


def _looks_like_foreground_probe(command: str) -> bool:
    """Return True for short inspection commands that should not be backgrounded."""
    text = (command or "").strip().lower()
    if not text:
        return False

    # These are genuinely long-running/interactive enough to justify tmux.
    long_running_markers = (
        " nmap ",
        " masscan ",
        " gobuster ",
        " feroxbuster ",
        " ffuf ",
        " sqlmap ",
        " hydra ",
        " hashcat ",
        " john ",
        " ghidra",
        " gdb ",
        " radare2 ",
        " r2 ",
        " nc -l",
        " netcat -l",
        "python -m http.server",
        "python3 -m http.server",
        "while true",
        "tail -f",
        "sleep ",
    )
    padded = f" {text} "
    if any(marker in padded for marker in long_running_markers):
        return False

    # Strip common setup prefixes so `cd dir && grep ...` is still recognized.
    simplified = re.sub(r"^(?:cd\s+[^;&|]+(?:&&|;)\s*)+", "", text).strip()
    simplified = re.sub(r"^(?:echo\s+['\"][^'\"]*['\"]\s*(?:&&|;)\s*)+", "", simplified).strip()

    foreground_prefixes = (
        "ls ",
        "find ",
        "file ",
        "strings ",
        "grep ",
        "rg ",
        "sed ",
        "awk ",
        "head ",
        "tail ",
        "cat ",
        "xxd ",
        "hexdump ",
        "readelf ",
        "objdump ",
        "nm ",
        "python ",
        "python3 ",
        "bash -lc ",
    )
    return simplified.startswith(foreground_prefixes) or "python3 <<" in simplified or "python <<" in simplified


@function_tool(name_override="long_task_start")
def long_task_start(command: str, task_id: str = "", session: str = "", target: str = "", wait_seconds: int = 5) -> str:
    """
    Start a long-running shell task in a persistent tmux session and track it.

    Args:
        command: Command to run.
        task_id: Optional stable task id. Auto-generated if empty.
        session: Optional tmux session name. Auto-generated if empty.
        target: Optional target label for the event log.
        wait_seconds: Seconds to wait for initial output before returning.
    """
    if not command.strip():
        return "Command is required."
    if _looks_like_foreground_probe(command):
        return (
            "[FOREGROUND COMMAND REFUSED]\n"
            "This looks like a short inspection command, not a long-running job. "
            "Do not use long_task_start for grep/sed/file/strings/find/cat/head/quick Python probes; "
            "it can hide stdout in tmux and cause evidence-free loops.\n"
            "Use ctf_command(command=..., cwd=...) for CTF/reversing analysis, or artifact_read/artifact_grep "
            "for files already saved in the workspace/session."
        )
    resolved_target = _active_target(target)
    tmux_session = session or f"long_{_slug(resolved_target or 'global')}"
    resolved_task_id = task_id or _task_id(command, tmux_session)
    log = get_event_log(target=resolved_target)
    start_event = log.record(
        "long_task_started",
        target=resolved_target,
        tool="long_task_start",
        correlation_id=resolved_task_id,
        payload={"command": command, "tmux_session": tmux_session},
    )
    log.upsert_long_task(
        task_id=resolved_task_id,
        command=command,
        tmux_session=tmux_session,
        status="running",
        target=resolved_target,
        last_event_id=start_event,
    )

    manager = get_manager(tmux_session)
    output = manager.execute(command, timeout=max(1, min(int(wait_seconds or 5), 60)))
    status = "completed"
    if output.startswith("[TIMEOUT]") or "[AUTO-BACKGROUND]" in output or "interactive prompt detected" in output:
        status = "running"
    if "[ERROR]" in output:
        status = "failed"
    if not (output or "").strip():
        output = (
            "[NO OUTPUT CAPTURED]\n"
            "The command returned without visible stdout/stderr in the tmux screen. "
            "Do not treat this as useful evidence. For short probes, run a foreground "
            "tool that returns output directly. For prompt-driven host:port services, "
            "use tcp_session_open/send/read instead of long_task_start."
        )

    event_id = log.record(
        "long_task_observed",
        target=resolved_target,
        tool="long_task_start",
        correlation_id=resolved_task_id,
        payload={"status": status, "output": output},
    )
    log.update_long_task(resolved_task_id, status=status, last_output=output, last_event_id=event_id)
    return (
        f"Long task: {resolved_task_id}\n"
        f"Status: {status}\n"
        f"tmux session: {tmux_session}\n\n"
        f"{output}"
    )


@function_tool(name_override="long_task_status")
def long_task_status(task_id: str, target: str = "") -> str:
    """
    Read and refresh a tracked long-running task.

    Args:
        task_id: Task id returned by long_task_start.
        target: Optional target label for the event log.
    """
    if not task_id:
        return "Task id is required."
    resolved_target = _active_target(target)
    log = get_event_log(target=resolved_target)
    rows = [row for row in log.list_long_tasks(limit=200) if row.get("task_id") == task_id]
    if not rows:
        return f"Long task not found: {task_id}"
    row: dict[str, Any] = rows[0]
    manager = get_manager(row.get("tmux_session") or "main")
    screen = manager.read_screen()
    status = _status_from_screen(screen, row.get("status", "running"))
    event_id = log.record(
        "long_task_status",
        target=row.get("target") or resolved_target,
        tool="long_task_status",
        correlation_id=task_id,
        payload={"status": status, "screen": screen},
    )
    log.update_long_task(task_id, status=status, last_output=screen, last_event_id=event_id)
    return (
        f"Long task: {task_id}\n"
        f"Status: {status}\n"
        f"tmux session: {row.get('tmux_session')}\n"
        f"Command: {row.get('command')}\n\n"
        f"{screen}"
    )


@function_tool(name_override="long_task_list")
def long_task_list(status: str = "", target: str = "", limit: int = 20) -> str:
    """
    List tracked long-running tasks.

    Args:
        status: Optional status filter such as running, completed, failed.
        target: Optional target label for the event log.
        limit: Maximum rows to return.
    """
    resolved_target = _active_target(target)
    rows = get_event_log(target=resolved_target).list_long_tasks(status=status, limit=limit)
    if not rows:
        return "No long tasks recorded."
    lines = ["Tracked long tasks:"]
    for row in rows:
        lines.append(
            f"- {row.get('task_id')} [{row.get('status')}] "
            f"session={row.get('tmux_session')} updated={row.get('updated_at')} "
            f"cmd={row.get('command')[:140]}"
        )
    return "\n".join(lines)


@function_tool(name_override="long_task_resume")
def long_task_resume(task_id: str = "", target: str = "") -> str:
    """
    Resume context for one or all tracked long tasks after a restart.

    Args:
        task_id: Optional specific task id.
        target: Optional target label for the event log.
    """
    resolved_target = _active_target(target)
    log = get_event_log(target=resolved_target)
    rows = log.list_long_tasks(limit=100)
    if task_id:
        rows = [row for row in rows if row.get("task_id") == task_id]
    if not rows:
        return "No resumable long tasks found."
    lines = ["Long-task resume context:"]
    for row in rows:
        lines.append(
            f"\nTask {row.get('task_id')} [{row.get('status')}]\n"
            f"tmux session: {row.get('tmux_session')}\n"
            f"command: {row.get('command')}\n"
            f"last output:\n{(row.get('last_output') or '')[-2000:]}"
        )
    return "\n".join(lines)
