#!/usr/bin/env python3
"""
Cyber-CoPilot - AI-Powered Cybersecurity Operations
Professional Terminal Interface
"""

import os
import sys
import time
import asyncio
import threading
try:
    import readline
except ImportError:
    pass
import atexit
from dotenv import load_dotenv
from rich.prompt import Prompt
from rich.panel import Panel
from rich import box

# For better multi-line paste support + tab completion
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.keys import Keys
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.filters import Condition
    import glob as _glob
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

from src.sdk.runner import run, clear_memory, Runner

# ── Clipboard image support ────────────────────────────────────────────────────
# Optional: PIL/Pillow is only needed if the user pastes images from clipboard.
# Install with:  pip install Pillow
try:
    from PIL import ImageGrab as _ImageGrab
    import io as _io
    import base64 as _base64
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


def _grab_clipboard_image() -> str | None:
    """Return a base64 PNG data URI from the clipboard image, or None.

    Works on:
    - Windows / macOS: uses Pillow's ImageGrab.grabclipboard()
    - Linux: falls back to xclip/xsel if Pillow is not available or
             ImageGrab returns None (common on Linux X11 sessions).
    """
    # --- PIL path (Windows / macOS, and Linux with xorg via Pillow ≥ 10) ------
    if _PIL_AVAILABLE:
        try:
            img = _ImageGrab.grabclipboard()
            if img is not None:
                buf = _io.BytesIO()
                img.save(buf, format="PNG")
                b64 = _base64.b64encode(buf.getvalue()).decode()
                return f"data:image/png;base64,{b64}"
        except Exception:
            pass

    # --- Linux fallback: xclip -------------------------------------------------
    try:
        import subprocess
        result = subprocess.run(
            ["xclip", "-selection", "clipboard", "-t", "image/png", "-o"],
            capture_output=True, timeout=3,
        )
        if result.returncode == 0 and result.stdout:
            import base64 as _b64
            b64 = _b64.b64encode(result.stdout).decode()
            return f"data:image/png;base64,{b64}"
    except Exception:
        pass

    # --- Linux fallback: xsel --------------------------------------------------
    try:
        import subprocess
        result = subprocess.run(
            ["xsel", "--clipboard", "--output"],
            capture_output=True, timeout=3,
        )
        if result.returncode == 0 and result.stdout:
            # xsel may return raw PNG bytes if the clipboard holds an image
            data = result.stdout
            if data[:4] == b"\x89PNG":
                import base64 as _b64
                b64 = _b64.b64encode(data).decode()
                return f"data:image/png;base64,{b64}"
    except Exception:
        pass

    return None


from src.repl.ui import (
    display_banner, display_quick_guide, display_agents_table,
    display_response, display_target_status, display_session_summary,
    display_error, display_success, display_warning, display_info,
    print_separator, console, display_progress_summary,
    display_supervisor_check,
    # NEW: Enhanced display functions
    display_tool_detailed, display_thinking_detailed, display_thinking_compact, display_failure_recovery, display_findings_summary, display_phase_header, display_real_time_stats,
    start_tool_status, refresh_tool_status, stop_tool_status,
    display_agent_health_preflight, display_hypothesis_board,
    display_coverage_checklist, display_engagement_cockpit,
)
from src.repl.target_manager import get_target_manager
from src.repl.profiles import get_profile_manager
from src.repl.reports import get_report_generator
from src.repl.parallel import run_recon_and_websec, run_full_assessment

class TerminalTitleAnimator:
    """Animates the terminal tab title dynamically."""
    def __init__(self):
        self.running = True
        self.text = "Cyber-CoPilot - Idle"
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def set_text(self, text):
        self.text = text

    def stop(self):
        self.running = False

    def _animate(self):
        # Don't animate if stdout is not a real terminal (e.g. redirected to a file)
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return
            
        idx = 0
        while self.running:
            try:
                # Use raw os.write to file descriptor 1 to bypass rich's stdout capture
                # which strips the \033 escape byte and causes literal ]0; output.
                os.write(1, f"\033]0;{self.frames[idx]} {self.text}\007".encode('utf-8'))
            except Exception:
                pass
            
            idx = (idx + 1) % len(self.frames)
            time.sleep(0.2)

title_animator = TerminalTitleAnimator()

from src.agents import (
    create_recon_agent,
    create_websec_agent,
    create_ctf_agent,
    create_dfir_agent,
    create_redteam_agent,
    create_orchestrator_agent,
    create_blackhat_agent,
    create_reporter_agent,
    create_appsec_agent,
    create_bugbounty_agent
)
# Agent Graph System
from src.sdk.agent_graph import create_killchain_graph, DiscoveryBus
from src.repl.graph import (
    display_agent_graph, display_discovery_bus, display_graph_results,
    display_validated_vulns
)

# Integrations for previously unused modules
from src.sdk.backup_manager import auto_backup_memory, list_memory_backups, restore_memory_backup
from src.sdk.asset_correlation import get_correlator

# New Features
from src.sdk.scope import get_scope_manager
from src.sdk.cache import get_tool_cache
from src.sdk.dashboard import get_dashboard
from src.sdk.evidence import get_evidence_collector
# NEW: Failure Recovery System
from src.sdk.recovery import get_recovery_engine

load_dotenv()

# ── Scan interrupt state ──────────────────────────────────────────────────────
# _in_scan: True while an agent run is executing (used to change Ctrl+C behaviour)
_in_scan: bool = False


def _check_thinking_key() -> str | None:
    """Non-blocking check for + or - keypresses during agent execution.

    Returns '+', '-', or None. Uses the same raw-mode trick as _check_ctrl_e.
    """
    try:
        if sys.platform == "win32":
            import msvcrt
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ('+', '-'):
                    return ch
        else:
            import select
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                if select.select([sys.stdin], [], [], 0)[0]:
                    ch = sys.stdin.read(1)
                    if ch in ('+', '-'):
                        return ch
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        pass
    return None


def _check_ctrl_e() -> bool:
    """Non-blocking check: returns True if Ctrl+E (0x05) was pressed.
    
    Works on both Windows (msvcrt) and Unix (termios/select).
    Safe to call from a tight polling loop; never blocks.
    """
    try:
        if sys.platform == "win32":
            import msvcrt
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                return ch == '\x05'  # Ctrl+E
        else:
            import select
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                if select.select([sys.stdin], [], [], 0)[0]:
                    ch = sys.stdin.read(1)
                    return ch == '\x05'
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        pass
    return False


def _add_host_with_timeout(ip: str, hostname: str, note: str = "HTB", timeout_seconds: float = 2.5) -> dict:
    """
    Add a hosts entry without letting occasional OS-level file stalls block the REPL.
    Returns the same shape as hosts_manager.add_host().
    """
    result_box = {"result": None, "error": None}

    def _worker():
        try:
            from src.repl.hosts_manager import add_host
            result_box["result"] = add_host(ip, hostname, note=note)
        except Exception as exc:
            result_box["error"] = str(exc)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout_seconds)

    if t.is_alive():
        return {
            "success": False,
            "already_existed": False,
            "message": (
                f"hosts update timed out after {timeout_seconds:.1f}s. "
                "Target was set successfully; run 'hosts add <ip> <hostname>' manually."
            ),
        }
    if result_box["error"]:
        return {"success": False, "already_existed": False, "message": f"Hosts update error: {result_box['error']}"}
    return result_box["result"] or {"success": False, "already_existed": False, "message": "Unknown hosts update failure."}

# ─────────────────────────────────────────────────────────────────────────────

# Configure logging - suppress DEBUG on console
from loguru import logger
logger.remove()  # Remove default handler
logger.add(sys.stderr, level="WARNING")  # Only show warnings and errors
logger.add("logs/cyber_copilot.log", rotation="10 MB", level="DEBUG")  # Full debug to file

# Command history file
HISTORY_FILE = os.path.expanduser("~/.cyber_copilot_history")

# Tab completion commands
COMMANDS = [
    "scan", "find subdomains", "whois", "dns enumeration",
    "search exploits", "run sqlmap", "gobuster",
    "analyze", "extract strings", "clear", "switch", "quit", "exit",
    "port scan", "vulnerability scan", "subdomain discovery",
    "pwn", "hack", "exploit", "compromise", "attack", "report",
    "parallel", "full-scan", "target", "history", "logs", "help", "commands",
    "profile", "export", "shell", "revshell", "api", "listen",
    "memory", "remember", "note", "thinking", "confirm", "context", "rate", "poc",
    "supervisor", "supervisor on", "supervisor off", "supervisor 5", "supervisor 10",
    # Model selection
    "model", "model openrouter", "model nvidia",
    # Cyber Kill Chain Assessment Commands
    "graph", "graph recon", "graph weapon", "graph exploit", "graph bounty",
    "graph status", "graph discoveries", "graph validated",
    # New Features
    "scope", "scope add", "scope remove", "scope list",
    "cache", "cache status", "cache clear",
    "dashboard", "dashboard status",
    "evidence", "evidence list", "evidence export",
    # Async Task Commands
    "task", "task status", "task list", "task cancel", "task results",
    # Attack Visualization
    "attack", "attack graph", "attack paths", "attack summary", "attack export",
    # Timeout Configuration
    "timeout", "timeout set", "timeout list",
    # NEW: Enhanced UI Commands
    "detailed", "detailed on", "detailed off",  # Toggle detailed output
    "findings", "findings summary", "findings export",  # View findings
    "live", "live on", "live off",  # Toggle live dashboard
    "recovery", "recovery status", "recovery history",  # Failure recovery
    "stats", "realtime",  # Real-time stats display
    "preflight", "health", "hypotheses", "coverage", "cockpit",
    # Proxy & IP Rotation
    "proxy", "proxy add", "proxy load", "proxy enable", "proxy disable", "proxy status",
    "proxy rotate", "proxy list", "tor", "myip",
    # API Key Management
    "apikey", "apikey status", "apikey reset", "apikey enable",
    "proxy rotate", "proxy list", "tor", "myip",
    # Continue/Resume
    "continue", "resume",
    # Bug Bounty Mode
    "mode", "mode on", "mode off",
    # Hosts File Management (HTB)
    "hosts", "hosts add", "hosts remove", "hosts list",
]

# Track tool execution
_tool_log = []

# Show agent thinking (optional)
_show_thinking = True

# Thinking display mode: "full" = big panel, "compact" = one-liner summary
_thinking_compact = False

# Require confirmation before tool execution (human-in-the-loop)
_require_confirm = False

# Show detailed tool info (enhanced UI)
_show_detailed = True

# Live dashboard instance
_live_dashboard = None

# Session findings tracking
_session_findings = []
_session_tools_used = []

# Continue/Resume state - tracks last execution for recovery
_last_agent = None
_last_input = None
_last_target = None
_last_error = None
_can_continue = False


def _complete_path(partial: str) -> list:
    """Return filesystem completions for a partial path (works on both Linux and Windows)."""
    import glob as _glob_local

    # Strip quotes
    partial = partial.strip("'\"")

    # Expand ~ to home directory
    expanded = os.path.expanduser(partial)

    # If user typed a directory with trailing slash, list its contents
    if os.path.isdir(expanded):
        pattern = os.path.join(expanded, "*")
    else:
        pattern = expanded + "*"

    matches = _glob_local.glob(pattern)

    results = []
    for match in sorted(matches):
        # Re-collapse home prefix back to ~ if the user typed ~ originally
        display = match
        if partial.startswith("~"):
            home = os.path.expanduser("~")
            if display.startswith(home):
                display = "~" + display[len(home):]
        # Append '/' to directories so the user can keep tabbing deeper
        if os.path.isdir(match):
            if not display.endswith(os.sep) and not display.endswith("/"):
                display += "/"
        results.append(display)
    return results


def _is_path_token(text: str) -> bool:
    """Heuristic: does `text` look like a filesystem path the user is typing?"""
    if not text:
        return False
    # Strip potential quotes
    clean = text.strip("'\"")
    if not clean:
        return False
    # If it starts with typical path markers or contains separators
    return (
        clean.startswith("/")
        or clean.startswith("~")
        or clean.startswith(".")
        or "/" in clean
        or "\\" in clean
        or (len(clean) >= 2 and clean[1] == ":" and clean[0].isalpha())  # Windows C:\...
        or os.sep in clean
    )


if PROMPT_TOOLKIT_AVAILABLE:
    class CyberCopilotCompleter(Completer):
        """
        Merged completer for the Cyber-CoPilot REPL:
          - Commands (scan, graph, target, ...) when typing from the start of the line
          - Filesystem paths when a token looks like a path (starts with / ~ . or contains /)
        Behaves like a Linux shell: Tab lists directory contents, keeps completing deeper.
        """

        def get_completions(self, document, complete_event):
            text_before_cursor = document.text_before_cursor
            # Split into tokens to figure out if we're completing a path or a command
            tokens = text_before_cursor.split()
            # The word being typed (for replacement length)
            word = document.get_word_before_cursor(WORD=True)

            # ── Path completion ──────────────────────────────────────────────
            _PATH_COMMANDS = {
                "analyze", "binwalk", "strings", "exiftool", "tshark",
                "ctf", "dfir", "open", "load", "file", "target", "scope", "proxy",
                "steg", "checksec", "ghidra", "pwn", "run", "cat", "ls", "cd"
            }
            
            # If the current word looks like a path, or we are in a command that expects a path
            is_path_context = _is_path_token(word)
            if not is_path_context and len(tokens) >= 1:
                # If we just typed a space after a path-expecting command
                if tokens[0].lower() in _PATH_COMMANDS:
                    is_path_context = True
            
            if is_path_context:
                # Use current word if present, otherwise default to current dir contents
                path_to_complete = word if word else "./"
                for match in _complete_path(path_to_complete):
                    yield Completion(match, start_position=-len(word))
                return

            # ── Command completion ───────────────────────────────────────────
            for cmd in COMMANDS:
                if cmd.lower().startswith(text_before_cursor.lower()):
                    yield Completion(cmd, start_position=-len(text_before_cursor))


def setup_readline():
    """Set up readline for history and tab completion (including filesystem paths)."""
    try:
        if os.path.exists(HISTORY_FILE):
            readline.read_history_file(HISTORY_FILE)
        atexit.register(readline.write_history_file, HISTORY_FILE)
        readline.set_history_length(200)
        
        def completer(text, state):
            line = readline.get_line_buffer()
            begidx = readline.get_begidx()
            
            # Context-aware: is the whole token we're in a path?
            # Find the start of the current token (backwards to space)
            token_start = begidx
            while token_start > 0 and line[token_start-1] not in " \t":
                token_start -= 1
            full_token = line[token_start:readline.get_endidx()]
            
            # Decide: path completion vs command completion
            # If the full token looks like a path, OR the previous char was a separator,
            # OR we are in a command that expects a path (first word in line)
            _PATH_COMMANDS = {"analyze", "binwalk", "strings", "exiftool", "tshark", "ctf", "dfir", "target", "file", "load"}
            first_word = line.split()[0].lower() if line.split() else ""
            
            if _is_path_token(full_token) or (begidx > 0 and line[begidx-1] in "/\\.~") or first_word in _PATH_COMMANDS:
                options = _complete_path(full_token)
                # Readline expects completions for 'text' (the bit after the last delimiter).
                # If we return full paths, readline might double-up if '/' is a delimiter.
                # However, since we set delims to " \t\n;", '/' is NOT a delimiter.
                # So we return the full matches.
            else:
                options = [cmd for cmd in COMMANDS if cmd.lower().startswith(text.lower())]
            
            return options[state] if state < len(options) else None
        
        readline.set_completer(completer)
        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass


# Track current executing tool for cleaner output
_current_tool = None
_execution_start_time = None
_tool_heartbeat_thread = None
_tool_heartbeat_stop = None
_tool_heartbeat_tool = None
_TOOL_HEARTBEAT_INTERVAL = 1  # seconds


def _stop_tool_heartbeat():
    global _tool_heartbeat_thread, _tool_heartbeat_stop, _tool_heartbeat_tool
    if _tool_heartbeat_stop:
        _tool_heartbeat_stop.set()
    if _tool_heartbeat_thread and _tool_heartbeat_thread.is_alive():
        try:
            _tool_heartbeat_thread.join(timeout=0.2)
        except Exception:
            pass
    _tool_heartbeat_thread = None
    _tool_heartbeat_stop = None
    _tool_heartbeat_tool = None
    try:
        stop_tool_status()
    except Exception:
        pass


def _start_tool_heartbeat(tool_name: str, execution_id: str):
    global _tool_heartbeat_thread, _tool_heartbeat_stop, _tool_heartbeat_tool
    _stop_tool_heartbeat()

    _tool_heartbeat_stop = threading.Event()
    _tool_heartbeat_tool = f"{tool_name}#{execution_id}"

    try:
        start_tool_status(tool_name)
    except Exception:
        pass

    def _beat():
        while not _tool_heartbeat_stop.wait(_TOOL_HEARTBEAT_INTERVAL):
            if _current_tool != _tool_heartbeat_tool:
                break
            try:
                refresh_tool_status()
            except Exception:
                pass

    _tool_heartbeat_thread = threading.Thread(target=_beat, daemon=True)
    _tool_heartbeat_thread.start()

def on_tool_start_callback(agent_name: str, tool_name: str, args: dict):
    """Callback when tool execution starts - enhanced with detailed display."""
    global _current_tool, _execution_start_time, _session_tools_used
    import uuid
    execution_id = str(uuid.uuid4())[:8]  # Short unique ID for this execution
    _tool_log.append({"tool": tool_name, "time": time.time(), "id": execution_id, "args": args})
    _current_tool = f"{tool_name}#{execution_id}"  # Track with ID for parallel execution
    _execution_start_time = time.time()
    _session_tools_used.append(tool_name)

    if _show_detailed:
        _start_tool_heartbeat(tool_name, execution_id)
    
    # Update breadcrumb trail dynamically
    try:
        from src.repl.ui import set_breadcrumb
        # Try to find a meaningful endpoint in the args
        endpoint = ""
        if "url" in args:
            endpoint = args["url"]
        elif "target" in args:
            endpoint = args["target"]
        elif "path" in args:
            endpoint = args["path"]
        elif "port" in args:
            endpoint = f"Port {args['port']}"
            
        if endpoint:
            # Strip scheme for cleaner display
            import re
            clean_endpoint = re.sub(r'^https?://', '', str(endpoint))
            set_breadcrumb(clean_endpoint)
    except Exception:
        pass
    
    # Show detailed tool info if enabled
    if _show_detailed:
        # Add visual separator for parallel execution tracking
        print_separator()
        
        # Get tool description from docstring if available
        description = ""
        try:
            from src import tools
            tool_func = getattr(tools, tool_name, None)
            if tool_func and tool_func.__doc__:
                description = tool_func.__doc__.split('\n')[0][:80]
        except Exception:
            pass
        
        # Format command
        runner = Runner()
        command_str = runner._format_command(tool_name, args)
        
        # Show execution ID for parallel tracking
        console.print(f"[dim]Execution ID: {execution_id}[/dim]")

        display_tool_detailed(
            tool_name=tool_name,
            args=args,
            command_str=command_str,
            description=description,
            phase=""
        )
    return execution_id


def on_tool_end_callback(agent_name: str, tool_name: str, success: bool, result: str, execution_id: str | None = None):
    """Callback when tool execution ends - with failure recovery."""
    global _current_tool, _session_findings
    
    # Prefer the explicit execution ID supplied by Runner. Falling back to the
    # global current tool is only for older callback call sites.
    if not execution_id:
        execution_id = _current_tool.split('#')[-1] if _current_tool and '#' in _current_tool else 'N/A'
    
    # Calculate duration
    duration = 0
    for log in reversed(_tool_log):
        if log.get("id") == execution_id or (execution_id == "N/A" and log["tool"] == tool_name):
            duration = time.time() - log["time"]
            break
    
    # Visual separator for tool completion (especially important for parallel execution)
    if success:
        console.print(f"       [green]✓[/green] [dim]completed in {duration:.1f}s[/dim] [dim italic](ID: {execution_id})[/dim italic]")
        
        # Extract and display findings
        runner = Runner()
        findings = runner._extract_findings(tool_name, result or "")
        for finding in findings:
            _session_findings.append({"type": "finding", "value": finding, "source": tool_name})
            if _show_detailed:
                console.print(f"       [green]🔍[/green] {finding}")
        
        # Add visual end marker for parallel execution clarity
        if _show_detailed:
            console.print(f"[dim]{'─' * 80}[/dim]")
    else:
        console.print(f"       [red]✗[/red] [dim]failed after {duration:.1f}s[/dim] [dim italic](ID: {execution_id})[/dim italic]")
        
        # Trigger failure recovery
        recovery_engine = get_recovery_engine()
        context = recovery_engine.record_failure(
            tool_name=tool_name,
            target=_last_target or "",
            error=result[:200] if result else "Unknown error"
        )
        
        # Get and display recovery strategies
        strategies = recovery_engine.get_recovery_strategies(context)
        if strategies and _show_detailed:
            strategy_dicts = [
                {"confidence": s.confidence, "description": s.description}
                for s in strategies[:4]
            ]
            selected = strategy_dicts[0] if strategy_dicts else None
            display_failure_recovery(
                tool_name=tool_name,
                error=result[:100] if result else "Unknown error",
                strategies=strategy_dicts,
                selected_strategy=selected
            )
        
        # Add visual end marker for failed tools too
        if _show_detailed:
            console.print(f"[dim red]{'─' * 80}[/dim red]")
    
    # Save full tool output to session files
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        if tm.session_dir:
            # Retrieve stored args from tool_log
            tool_args = {}
            for log in reversed(_tool_log):
                if log.get("id") == execution_id:
                    tool_args = log.get("args", {})
                    break
            tm.log_tool_call(tool_name, tool_args, result or "")
            tm.save_tool_output(tool_name, tool_args, result or "")
    except Exception:
        pass

    if _current_tool and _current_tool.endswith(f"#{execution_id}"):
        _current_tool = None
        _stop_tool_heartbeat()


def on_command_callback(agent_name: str, tool_name: str, command_str: str):
    """Callback to show the exact command being executed - this is the MAIN display."""
    # Only show if not using detailed mode (to avoid duplication)
    if not _show_detailed:
        console.print(f"  [bold yellow]▶[/bold yellow] [cyan]{command_str}[/cyan]")


def on_thinking_callback(agent_name: str, thinking_content: str, context_usage_pct: int | None = None):
    """Callback for agent thinking - display full reasoning in CLI panel."""
    global _show_thinking, _show_detailed, _thinking_compact

    if not _show_thinking or not thinking_content:
        return

    # Check for real-time + / - keypress and toggle compact mode on the fly
    key = _check_thinking_key()
    if key == '+':
        _thinking_compact = False
    elif key == '-':
        _thinking_compact = True

    if _thinking_compact:
        display_thinking_compact(agent_name, thinking_content, context_usage_pct)
        return

    if _show_detailed:
        # Parse thinking content for structured display
        action = ""
        reasoning = ""

        if "Action:" in thinking_content:
            parts = thinking_content.split("Action:")
            if len(parts) > 1:
                action = parts[1].split("\n")[0].strip()

        if "Reasoning:" in thinking_content or "Because" in thinking_content:
            reasoning = thinking_content

        display_thinking_detailed(
            agent_name=agent_name,
            thought=thinking_content,
            action=action,
            reasoning=reasoning,
            context_usage_pct=context_usage_pct,
        )
    else:
        # Non-detailed mode: show as a neat panel with full untruncated content
        from rich.panel import Panel as _Panel
        from rich import box as _box
        lines = thinking_content.strip().splitlines()
        formatted = "\n".join(f"  {line}" for line in lines if line.strip())
        console.print(_Panel(
            f"[cyan]{formatted}[/cyan]",
            title=f"[bold cyan]💭 {agent_name}[/bold cyan]" + (f" [dim]Context {int(context_usage_pct):02d}%[/dim]" if context_usage_pct is not None else ""),
            border_style="dim cyan",
            box=_box.ROUNDED,
            padding=(0, 1)
        ))


def on_progress_callback(agent_name: str, iteration: int, max_iterations: int, 
                         tools_run: list, findings: list, next_action: str = None):
    """Callback to show meaningful progress every 5 iterations."""
    display_progress_summary(agent_name, iteration, max_iterations, tools_run, findings, next_action)


def on_finding_callback(severity: str, title: str, details: str = "", source: str = ""):
    """Callback when a security finding is discovered."""
    global _session_findings
    
    _session_findings.append({
        "severity": severity,
        "title": title,
        "details": details,
        "source": source
    })
    
    # Show immediate notification for high/critical
    if severity.lower() in ["critical", "high"]:
        icon = "🔴" if severity.lower() == "critical" else "🟠"
        console.print(f"  {icon} [bold {severity.lower()}]FINDING:[/bold {severity.lower()}] {title}")
        try:
            from src.repl.ui import send_desktop_notification
            send_desktop_notification(f"{severity.upper()} Finding Detected", title)
        except Exception:
            pass


def on_supervisor_check_callback(agent_name: str, iteration: int, assessment: dict):
    """Callback fired every supervisor_interval iterations - shows progress evaluation panel."""
    display_supervisor_check(agent_name, iteration, assessment)


def on_phase_change_callback(phase_name: str, phase_number: int = 0, total_phases: int = 0):
    """Callback when execution phase changes."""
    descriptions = {
        "reconnaissance": "Gathering intelligence about the target",
        "weaponization": "Preparing tools and payloads",
        "delivery": "Testing attack vectors",
        "exploitation": "Attempting to exploit vulnerabilities",
        "installation": "Establishing persistence",
        "command_control": "Setting up command & control",
        "actions": "Achieving objectives"
    }
    
    display_phase_header(
        phase_name=phase_name,
        phase_number=phase_number,
        total_phases=total_phases,
        description=descriptions.get(phase_name.lower(), "")
    )


# Register callbacks
Runner.on_tool_start = on_tool_start_callback
Runner.on_tool_end = on_tool_end_callback
Runner.on_command = on_command_callback
Runner.on_progress = on_progress_callback
Runner.on_thinking = on_thinking_callback
Runner.on_supervisor_check = on_supervisor_check_callback
# NEW: Enhanced callbacks
Runner.on_finding = on_finding_callback
Runner.on_phase_change = on_phase_change_callback


# Available agents
AGENTS = {
    "0": ("Orchestrator", create_orchestrator_agent, "🤖 AUTO - Smart delegation"),
    "1": ("ReconAgent", create_recon_agent, "🔍 Reconnaissance & OSINT"),
    "2": ("WebSecAgent", create_websec_agent, "🌐 Web Application Security"),
    "3": ("CTFAgent", create_ctf_agent, "🏁 CTF & Forensics"),
    "4": ("DFIRAgent", create_dfir_agent, "🔬 Digital Forensics"),
    "5": ("RedTeamAgent", create_redteam_agent, "⚠️ Red Team Operations"),
    "6": ("BlackHat", create_blackhat_agent, "💀 Aggressive Exploitation"),
    "7": ("Reporter", create_reporter_agent, "📝 Report Generation"),
    "8": ("AppSecAgent", create_appsec_agent, "🔒 AppSec (XSS, SQLi, SSRF)"),
    "9": ("BugBountyAgent", create_bugbounty_agent, "🎯 Bug Bounty Hunter"),
}

# Cyber Kill Chain Assessment Modes
KILLCHAIN_MODES = {
    "1": ("reconnaissance", "🔍 Reconnaissance", "Subdomain, port scanning, OSINT"),
    "2": ("weaponization", "⚙️ Weaponization", "Recon + Web enumeration"),
    "3": ("exploitation", "💥 Exploitation", "Full vuln scan + exploitation"),
    "4": ("full", "☠️ Full Kill Chain", "All phases: Recon → Post-Exploit"),
    "5": ("bugbounty", "🎯 Bug Bounty", "Optimized for bug bounty programs"),
}

# Global agent graph instance
_agent_graph = None
_discovery_bus = None


async def handle_parallel_command(command: str, target_manager):
    """Handle parallel execution commands."""
    parts = command.split(maxsplit=1)
    if len(parts) < 2:
        display_warning("Usage: parallel <target> OR full-scan <target>")
        return
    
    target = parts[1]
    target_manager.start_session(target, "Parallel")
    target_manager.log_input(command)
    
    display_info(f"Launching parallel agents on [bold]{target}[/bold]...")
    print_separator()
    
    start_time = time.time()
    
    if command.startswith("full-scan"):
        results = await run_full_assessment(target)
    else:
        results = await run_recon_and_websec(target)
    
    total_time = time.time() - start_time
    
    for task_id, result in results.items():
        print_separator("═", "green")
        if result.error:
            display_error(f"{result.agent_name}: {result.error}")
            target_manager.log_output(f"Error: {result.error}", 0)
        elif result.result:
            display_response(
                result.agent_name,
                result.result.output,  # Show full output
                result.result.tool_calls_made,
                result.duration_seconds
            )
            target_manager.log_output(result.result.output, result.result.tool_calls_made)
    
    summary = target_manager.end_session()
    display_success(f"Parallel execution completed in {total_time:.1f}s")
    display_info(f"Logs: {summary.get('session_dir', 'N/A')}")


async def handle_graph_command(command: str, target_manager, current_target: str = None):
    """
    Handle agent graph execution commands based on Cyber Kill Chain.
    
    Commands:
        graph <target>          - Run full kill chain (default)
        graph recon <target>    - Phase 1: Reconnaissance only
        graph weapon <target>   - Phase 2: Recon + Weaponization
        graph exploit <target>  - Phase 3: Up to exploitation
        graph bounty <target>   - Bug bounty optimized assessment
        graph status            - Show graph state
        graph discoveries       - Show discovery bus
        graph validated         - Show validated vulnerabilities
    """
    global _agent_graph, _discovery_bus
    
    parts = command.split(maxsplit=2)
    
    # Handle special subcommands that don't need a target
    if len(parts) > 1:
        subcommand = parts[1].lower()
        
        if subcommand == "status":
            if _agent_graph:
                display_agent_graph(_agent_graph)
            else:
                display_warning("No agent graph initialized. Run an assessment first.")
            return
        
        if subcommand == "discoveries":
            if _discovery_bus:
                display_discovery_bus(_discovery_bus)
            else:
                display_warning("No discoveries yet. Run an assessment first.")
            return
        
        if subcommand == "validated":
            from src.tools.poc_validation import get_validated_vulns
            vulns = get_validated_vulns()
            if vulns:
                display_validated_vulns(vulns)
            else:
                display_warning("No validated vulnerabilities. Run AppSec or PoC validation first.")
            return
        
        if subcommand == "help":
            display_killchain_menu()
            return
    
    # Determine phase and target
    phase = "full"  # Default to full kill chain
    target = None
    
    if len(parts) == 2:
        # Could be: "graph <target>" or "graph help"
        if parts[1].lower() in ["recon", "weapon", "exploit", "bounty", "full", "status", "discoveries", "validated", "help"]:
            phase = parts[1].lower()
            target = current_target
        else:
            # It's a target
            target = parts[1]
            phase = "full"
    elif len(parts) == 3:
        # "graph <phase> <target>"
        phase = parts[1].lower()
        target = parts[2]
    elif len(parts) == 1:
        # Just "graph" - use current target with full
        target = current_target
    
    # Map shorthand to full phase names
    phase_map = {
        "recon": "reconnaissance",
        "weapon": "weaponization",
        "exploit": "exploitation",
        "bounty": "bugbounty",
        "full": "full"
    }
    phase = phase_map.get(phase, phase)
    
    if not target:
        display_warning("Usage: graph <target> OR graph <phase> <target>")
        display_killchain_menu()
        return
    
    # Initialize graph with target for profile persistence
    _discovery_bus = DiscoveryBus(target=target)
    _agent_graph = create_killchain_graph(phase)
    _agent_graph.discovery_bus = _discovery_bus
    
    # Start session
    target_manager.start_session(target, f"KillChain-{phase}")
    target_manager.log_input(command)
    
    start_time = time.time()
    
    # Phase descriptions
    phase_info = {
        "reconnaissance": ("🔍", "RECONNAISSANCE", "Subdomain enumeration, port scanning, OSINT"),
        "weaponization": ("⚙️", "WEAPONIZATION", "Recon + Web enumeration + Directory fuzzing"),
        "exploitation": ("💥", "EXPLOITATION", "Full vulnerability scanning and exploitation"),
        "bugbounty": ("🎯", "BUG BOUNTY", "Comprehensive bug bounty methodology"),
        "full": ("☠️", "FULL KILL CHAIN", "All phases: Reconnaissance → Post-Exploitation"),
    }
    
    emoji, name, desc = phase_info.get(phase, ("🕸️", phase.upper(), ""))
    
    display_info(f"{emoji} Running [bold]{name}[/bold] on [bold cyan]{target}[/bold cyan]")
    display_info(f"[dim]{desc}[/dim]")
    print_separator()
    
    # Set timeout based on phase (None = unlimited)
    timeout_map = {
        "reconnaissance": None,      # unlimited
        "weaponization": None,       # unlimited
        "exploitation": None,        # unlimited
        "bugbounty": None,           # unlimited
        "full": None,                # unlimited
    }
    timeout = timeout_map.get(phase, None)
    
    print_separator()
    display_agent_graph(_agent_graph)
    print_separator()
    
    # Build task description based on phase
    task_descriptions = {
        "reconnaissance": f"Perform thorough reconnaissance on {target}. Find subdomains, open ports, technologies, and potential attack surface.",
        "weaponization": f"Perform reconnaissance and web enumeration on {target}. Map the attack surface with directory fuzzing and technology fingerprinting.",
        "exploitation": f"Perform full security assessment on {target}. Scan for vulnerabilities and attempt exploitation with PoC validation.",
        "bugbounty": f"Hunt for bug bounty vulnerabilities on {target}. Follow bug bounty methodology: recon, scan, validate, report. Focus on high-impact findings.",
        "full": f"Execute full cyber kill chain on {target}. Start with recon, enumerate attack surface, exploit vulnerabilities, and establish persistence.",
    }
    task = task_descriptions.get(phase, f"Security assessment on {target}")
    
    try:
        console.print("[bold yellow]⚡ Executing Kill Chain Assessment...[/bold yellow]\n")
        
        # Run the graph
        results = _agent_graph.run_graph(
            task=task,
            target=target,
            agents=None,  # Run all agents in the graph
            timeout_per_agent=timeout
        )
        
        total_time = time.time() - start_time
        
        # Display results
        display_graph_results(results, _discovery_bus)
        
        # Show validated vulnerabilities
        from src.tools.poc_validation import get_validated_vulns
        vulns = get_validated_vulns()
        if vulns:
            console.print("")
            display_validated_vulns(vulns)
        
        # Log outputs
        for agent_name, result in results.items():
            if result and hasattr(result, 'output'):
                target_manager.log_output(result.output, result.tool_calls_made if hasattr(result, 'tool_calls_made') else 0)  # Log full output
        
        summary = target_manager.end_session()
        print_separator()
        display_success(f"Kill Chain Assessment completed in {total_time:.1f}s")
        display_info(f"Session: {summary.get('session_dir', 'N/A')}")
        
    except Exception as e:
        display_error(f"Graph execution failed: {str(e)}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")


def display_killchain_menu():
    """Display the Cyber Kill Chain assessment menu."""
    from rich.table import Table
    
    table = Table(
        title="[bold cyan]⚔️ CYBER KILL CHAIN ASSESSMENT[/bold cyan]",
        show_header=True,
        header_style="bold white",
        border_style="cyan"
    )
    table.add_column("Phase", style="yellow", min_width=15)
    table.add_column("Command", style="cyan", min_width=25)
    table.add_column("Description", min_width=40)
    
    table.add_row("1. Reconnaissance", "graph recon <target>", "Subdomain enum, port scan, OSINT, tech fingerprinting")
    table.add_row("2. Weaponization", "graph weapon <target>", "Recon + Web enumeration + Directory fuzzing")
    table.add_row("3. Exploitation", "graph exploit <target>", "Full vuln scan + active exploitation + PoC")
    table.add_row("4. Full Kill Chain", "graph <target>", "All phases: Recon → Exploitation → Post-Exploit")
    table.add_row("5. Bug Bounty", "graph bounty <target>", "Bug bounty methodology with report-ready output")
    table.add_row("", "", "")
    table.add_row("[dim]Status[/dim]", "graph status", "Show current graph state")
    table.add_row("[dim]Discoveries[/dim]", "graph discoveries", "Show shared intelligence")
    table.add_row("[dim]Validated[/dim]", "graph validated", "Show confirmed vulnerabilities")
    
    console.print(table)
    console.print("\n[dim]💡 Default: 'graph <target>' runs full kill chain assessment[/dim]")


async def main():
    """Main entry point."""
    global _in_scan, _last_agent, _last_input, _last_target, _last_error, _can_continue

    import sys
    from datetime import datetime
    
    # Check for database reset flag
    if "--reset-db" in sys.argv or "--reset-memory" in sys.argv:
        print("🔄 Resetting ChromaDB database...")
        from pathlib import Path
        import shutil
        
        chroma_dir = Path("./.chroma")
        if chroma_dir.exists():
            backup_dir = Path(f"./.chroma_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            shutil.move(str(chroma_dir), str(backup_dir))
            print(f"📦 Backed up old database to: {backup_dir}")
            print("✅ Database reset complete. Starting fresh...")
        else:
            print("ℹ️  No existing database to reset.")
        
        # Remove flag and continue
        sys.argv = [arg for arg in sys.argv if arg not in ["--reset-db", "--reset-memory"]]
    
    setup_readline()
    
    # Display banner
    display_banner()
    
    # Check API keys
    if not os.getenv("OPENROUTER_API_KEY") and not os.getenv("LONGCAT_API_KEY"):
        display_error("No API key found. Set LONGCAT_API_KEY or OPENROUTER_API_KEY in .env")
        return
    
    
    # Default to Orchestrator agent for fallback (when user types natural language)
    from src.sdk.key_manager import get_key_manager
    km = get_key_manager()
    active_model = km.get_model()
    agent = create_orchestrator_agent(model=active_model)
    
    # Initialize target manager
    target_manager = get_target_manager()
    current_target = None
    title_animator.set_text("Cyber-CoPilot - Idle")
    
    # Initialize prompt_toolkit history and Ctrl+V image-aware key bindings
    pt_history = None
    pt_session = None
    if PROMPT_TOOLKIT_AVAILABLE:
        history_file = os.path.expanduser("~/.cyber-copilot_history")

        # ── Ctrl+V image-aware key binding ─────────────────────────────────
        # Pressing Ctrl+V when an image is in the clipboard inserts "!img "
        # into the input buffer and auto-submits the prompt.
        # If the clipboard holds text (no image), falls back to normal paste.
        _pt_bindings = KeyBindings()

        @_pt_bindings.add("c-v")
        def _ctrl_v_image_paste(event):
            """Ctrl+V: paste image from clipboard, or fall back to text paste."""
            img_uri = _grab_clipboard_image()
            if img_uri:
                # Image is in clipboard — insert the !img trigger and submit
                buf = event.app.current_buffer
                buf.set_document(__import__("prompt_toolkit").document.Document("!img "), bypass_readonly=True)
                buf.validate_and_handle()  # auto-submit the line
            else:
                # No image — do normal text paste from clipboard
                try:
                    import subprocess, sys
                    if sys.platform == "win32":
                        import ctypes
                        # Use Windows clipboard API for text paste
                        ctypes.windll.user32.OpenClipboard(0)
                        handle = ctypes.windll.user32.GetClipboardData(13)  # CF_UNICODETEXT
                        if handle:
                            ctypes.windll.kernel32.GlobalLock.restype = ctypes.c_void_p
                            ptr = ctypes.windll.kernel32.GlobalLock(handle)
                            if ptr:
                                text = ctypes.wstring_at(ptr)
                                ctypes.windll.kernel32.GlobalUnlock(handle)
                                event.app.current_buffer.insert_text(text)
                        ctypes.windll.user32.CloseClipboard()
                    else:
                        result = subprocess.run(
                            ["xclip", "-selection", "clipboard", "-o"],
                            capture_output=True, timeout=2,
                        )
                        if result.returncode == 0:
                            event.app.current_buffer.insert_text(
                                result.stdout.decode("utf-8", errors="replace")
                            )
                except Exception:
                    # Absolute fallback: let prompt_toolkit handle it natively
                    event.app.current_buffer.paste_clipboard_data(
                        event.app.clipboard.get_data()
                    )
        # ───────────────────────────────────────────────────────────────────

        try:
            pt_history = FileHistory(history_file)
            pt_session = PromptSession(history=pt_history, key_bindings=_pt_bindings)
        except Exception:
            pt_session = PromptSession(key_bindings=_pt_bindings)
    
    print_separator()
    console.print(
        "  [bold cyan]target[/bold cyan] [dim]<ip>[/dim]"
        "  [dim red]·[/dim red]  "
        "[bold cyan]switch[/bold cyan]"
        "  [dim red]·[/dim red]  "
        "[bold cyan]ctf[/bold cyan] [dim]<path>[/dim]"
        "  [dim red]·[/dim red]  "
        "[bold cyan]tools check[/bold cyan]"
        "  [dim red]·[/dim red]  "
        "[bold cyan]help[/bold cyan]"
        "  [dim red]·[/dim red]  "
        "[bold cyan]quit[/bold cyan]"
    )
    print_separator()
    
    tool_calls_total = 0
    
    while True:
        user_input = ""
        try:
            # Build prompt string
            if current_target:
                prompt_str = f"🎯 {current_target} ❯ "
            else:
                prompt_str = "❯ "
            
            # Use prompt_toolkit if available (better multi-line paste + tab completion)
            if pt_session:
                try:
                    user_input = await pt_session.prompt_async(
                        prompt_str,
                        auto_suggest=AutoSuggestFromHistory(),
                        completer=CyberCopilotCompleter(),
                        complete_while_typing=False,
                        multiline=False,
                        mouse_support=False,
                        enable_suspend=True,
                    )
                    user_input = user_input.strip()
                except (EOFError, KeyboardInterrupt):
                    raise KeyboardInterrupt
            else:
                # Fallback to basic input
                console.print(f"\n[bold yellow]{prompt_str}[/bold yellow]", end="")
                user_input = input().strip()
            
            if not user_input:
                continue
            
            cmd = user_input.lower()
            
            # === COMMANDS ===
            
            if cmd in ("quit", "exit", "q"):
                if current_target:
                    summary = target_manager.end_session()
                    print_separator()
                    display_session_summary(summary)
                    
                display_info("Creating automatic memory backup...")
                auto_backup_memory()
                display_info("Goodbye! Stay safe. 🔐")
                break

            if cmd in ("stop", "cancel"):
                Runner.cancel_reason = "Scan stopped by user (stop command)."
                Runner.cancel_requested = True
                display_warning("Stop signal sent - the scan will halt at the next checkpoint.")
                continue
            
            if cmd == "help":
                display_quick_guide()
                continue
            
            # === COMMANDS LIST ===
            if cmd == "commands":
                from rich.table import Table
                
                commands_table = Table(
                    title="[bold cyan]📋 Available Commands[/bold cyan]",
                    show_header=True,
                    header_style="bold white",
                    border_style="cyan"
                )
                commands_table.add_column("Command", style="yellow", min_width=20)
                commands_table.add_column("Description", min_width=45)
                
                # General commands
                commands_table.add_row("[bold]General[/bold]", "")
                commands_table.add_row("help", "Show quick start guide")
                commands_table.add_row("commands", "Show this command list")
                commands_table.add_row("clear", "Clear agent memory/context")
                commands_table.add_row("switch", "Switch to a different agent")
                commands_table.add_row("stop / cancel", "Stop current scan without quitting")
                commands_table.add_row("quit / exit / q", "Exit the application")
                commands_table.add_row("!img [text]", "📋 Grab image from clipboard + send to AI")
                commands_table.add_row("paste image [text]", "📋 Alias for !img — paste clipboard image")
                
                # Target management
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Target Management[/bold]", "")
                commands_table.add_row("target <ip>", "Set target; auto-adds IP→hostname to hosts file")
                commands_table.add_row("logs", "Show current session log files")
                commands_table.add_row("history <target>", "Show session history for a target")
                commands_table.add_row("preflight / health", "Check agent construction and key binaries")
                commands_table.add_row("hypotheses", "Show active ranked hypotheses")
                commands_table.add_row("coverage", "Show engagement coverage checklist")
                commands_table.add_row("export", "Export session report (Markdown/HTML)")
                
                # Scope & Safety
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Scope & Safety[/bold]", "")
                commands_table.add_row("scope", "Show current scope status")
                commands_table.add_row("scope <target>", "Quick add target to in-scope")
                commands_table.add_row("scope add <target> [in|out]", "Add target with specific type")
                commands_table.add_row("scope remove <target>", "Remove target from scope")
                commands_table.add_row("cache", "Show tool cache status")

                # API & Model Settings
                commands_table.add_row("", "")
                commands_table.add_row("[bold]API & Model Settings[/bold]", "")
                commands_table.add_row("model", "Show/select AI models")
                commands_table.add_row("model <number>", "Select model by number")
                commands_table.add_row("keys / api", "Show API key status & load balancing")
                commands_table.add_row("api <provider>", "Switch API provider (openrouter/nvidia/modelscope)")
                commands_table.add_row("rate", "Show rate limit status for all providers")

                # Memory & Context
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Memory & Context[/bold]", "")
                commands_table.add_row("memory", "Show vector memory stats")
                commands_table.add_row("memory <query>", "Search agent memory")
                commands_table.add_row("remember <note>", "Store a note in memory")
                commands_table.add_row("context", "Show shared context hub (all agent findings)")
                commands_table.add_row("context full", "Show detailed shared context")
                commands_table.add_row("context clear", "Clear shared context hub")
                commands_table.add_row("ctf <path>", "Start a CTF challenge")
                commands_table.add_row("poc [type]", "Generate Proof of Concept for findings")
                
                # Settings
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Settings[/bold]", "")
                commands_table.add_row("thinking", "Toggle agent thinking display")
                commands_table.add_row("mode", "Toggle bug bounty authorization mode (prevents LLM refusals)")
                commands_table.add_row("confirm", "Toggle tool execution confirmation")
                commands_table.add_row("recovery", "Show failure recovery status & history")
                commands_table.add_row("recovery status", "Show active recovery state")
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Supervisor Feedback Loop[/bold]", "")
                commands_table.add_row("supervisor", "Show supervisor status & current interval")
                commands_table.add_row("supervisor <N>", "Set check interval (e.g. supervisor 5)")
                commands_table.add_row("supervisor on", "Enable supervisor (every 10 iterations)")
                commands_table.add_row("supervisor off", "Disable supervisor checks")
                
                # Tool Installation
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Tool Installation[/bold]", "")
                commands_table.add_row("tools check", "Check ALL installed tools (all categories)")
                commands_table.add_row("tools category <name>", "Check specific tool category")
                commands_table.add_row("tools install-guide", "Get OS-specific installation commands")
                commands_table.add_row("tools install [all|tool1,tool2]", "Install missing recon tools")
                
                # NEW: Task Management
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Async Tasks (NEW)[/bold]", "")
                commands_table.add_row("task list", "List all async tasks")
                commands_table.add_row("task status <id>", "Get task details")
                commands_table.add_row("task results <id>", "Get task output")
                commands_table.add_row("task cancel <id>", "Cancel a running task")
                commands_table.add_row("task wait <id>", "Wait for task to complete")
                
                # NEW: Attack Visualization
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Attack Visualization (NEW)[/bold]", "")
                commands_table.add_row("attack", "Show current attack graph")
                commands_table.add_row("attack-surface", "Show discovered asset map & targets")
                commands_table.add_row("attack graph", "Show Mermaid diagram")
                commands_table.add_row("attack paths", "Find all attack paths")
                commands_table.add_row("attack summary", "Get attack summary")
                commands_table.add_row("attack export", "Export attack graph as JSON")
                
                # Backups
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Backups & State Management[/bold]", "")
                commands_table.add_row("backup", "Create an immediate memory backup")
                commands_table.add_row("restore", "List available memory backups")
                commands_table.add_row("restore <name>", "Restore a specific memory backup")
                
                # NEW: Timeout Configuration
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Timeout Configuration (NEW)[/bold]", "")
                commands_table.add_row("timeout list", "Show all tool timeouts")
                commands_table.add_row("timeout set <tool> <sec>", "Set custom timeout for tool")
                
                # Continue/Resume
                commands_table.add_row("", "")
                commands_table.add_row("[bold]Resume Operations[/bold]", "")
                commands_table.add_row("continue / resume", "Resume last interrupted operation")
                commands_table.add_row("", "[dim]  Works after API exhaustion, rate limits, or errors[/dim]")
                
                console.print(commands_table)
                console.print("\n[dim]💡 Tip: Type any task in natural language and the agent will execute appropriate tools.[/dim]")
                continue
            
            # === SCOPE MANAGEMENT ===
            if cmd == "scope" or cmd.startswith("scope "):
                manager = get_scope_manager()
                parts = user_input.split()
                
                if len(parts) == 1:
                    # Just "scope" - show status
                    console.print(manager.get_status())
                elif len(parts) == 2:
                    # "scope <target>" - add as in-scope (shortcut)
                    target = parts[1]
                    display_success(manager.add_scope(target, "in"))
                    console.print(f"\n[dim]Target added to in-scope. Use 'scope add {target} out' for out-of-scope.[/dim]")
                elif len(parts) >= 3 and parts[1] == "import":
                    # scope import <platform-url> [root-domain]
                    from src.sdk.scope_importer import import_scope_from_url
                    url = parts[2]
                    root_hint = parts[3] if len(parts) > 3 else ""
                    display_info(f"Fetching bug bounty scope from {url}...")
                    result = import_scope_from_url(url, root_hint=root_hint)
                    if result.error:
                        display_error(result.format())
                    else:
                        display_success(result.format())
                elif len(parts) >= 3 and parts[1] == "add":
                    # scope add <target> [in/out]
                    target = parts[2]
                    scope_type = parts[3] if len(parts) > 3 else "in"
                    display_success(manager.add_scope(target, scope_type))
                elif len(parts) >= 3 and parts[1] == "remove":
                    # scope remove <target>
                    display_success(manager.remove_scope(parts[2]))
                elif parts[1] == "list":
                    console.print(manager.get_status())
                elif parts[1] == "strict":
                     # scope strict on/off
                    enabled = parts[2].lower() in ["on", "true", "yes"] if len(parts) > 2 else True
                    display_success(manager.set_strict_mode(enabled))
                else:
                    display_error("""Usage:
  scope                    - Show current scope
  scope <target>           - Add target to in-scope (shortcut)
  scope import <url> [root-domain] - Fetch a bug bounty page and import scope
  scope add <target> [in|out] - Add target with type
  scope remove <target>    - Remove target from scope
  scope list               - Show current scope
  scope strict [on|off]    - Toggle strict mode
  
Examples:
  scope bykea.com          - Quick add to in-scope
  scope import https://bugcrowd.com/engagements/example example.com
  scope add *.bykea.com in - Add wildcard to in-scope
  scope add evil.com out   - Mark as out-of-scope"""
)
                continue

            # === TOOL CACHE ===
            if cmd == "cache" or cmd.startswith("cache "):
                cache = get_tool_cache()
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "status":
                    console.print(cache.get_status())
                elif parts[1] == "clear":
                    count = cache.clear()
                    display_success(f"Cache cleared ({count} entries removed)")
                elif parts[1] == "invalidate":
                     # cache invalidate [tool]
                     tool = parts[2] if len(parts) > 2 else None
                     count = cache.invalidate(tool_name=tool)
                     display_success(f"Invalidated {count} entries")
                continue

            # === DASHBOARD ===
            if cmd == "dashboard":
                dashboard = get_dashboard()
                console.print(dashboard.render())
                continue

            # === EVIDENCE ===
            if cmd == "evidence" or cmd.startswith("evidence "):
                collector = get_evidence_collector()
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "list":
                    console.print(collector.get_status())
                elif parts[1] == "export":
                    # evidence export [target]
                    target = parts[2] if len(parts) > 2 else ""
                    report = collector.export_markdown(target)
                    
                    filename = f"evidence_report_{int(time.time())}.md"
                    with open(filename, "w") as f:
                        f.write(report)
                    display_success(f"Evidence report exported to {filename}")
                continue

            # === ATTACK SURFACE MAP (Asset Correlator) ===
            if cmd == "attack-surface":
                correlator = get_correlator()
                console.print(correlator.get_attack_surface_summary())
                continue
                
            # === BACKUP MANAGEMENT ===
            if cmd == "backup":
                display_info("Creating memory backup...")
                backup_info = auto_backup_memory(force=True)
                if backup_info:
                    display_success(f"Backup created successfully: {backup_info.path.name}")
                else:
                    display_error("Failed to create backup")
                continue
                
            if cmd == "restore" or cmd.startswith("restore "):
                parts = user_input.split()
                if len(parts) == 1:
                    backups = list_memory_backups()
                    if not backups:
                        display_info("No backups found.")
                    else:
                        console.print("[bold cyan]💾 Available Memory Backups:[/bold cyan]")
                        for b in backups:
                            valid_marker = "✅" if b.is_valid else "❌"
                            console.print(f"  {b.path.name} | {b.size_mb():.1f}MB | Age: {b.age_hours():.1f}h | {valid_marker}")
                        console.print("\n[dim]Run 'restore <name>' to restore a specific backup[/dim]")
                else:
                    backup_name = parts[1]
                    display_info(f"Restoring backup {backup_name}...")
                    if restore_memory_backup(backup_name):
                        display_success("Backup restored successfully. Please restart Cyber-Copilot.")
                        break
                    else:
                        display_error("Failed to restore backup.")
                continue

            # === ATTACK VISUALIZATION  ===
            if cmd == "attack" or cmd.startswith("attack "):
                from src.sdk.attack_visualizer import get_attack_visualizer
                
                parts = user_input.split()
                target_for_attack = current_target or "unknown"
                visualizer = get_attack_visualizer(target_for_attack)
                
                if len(parts) == 1 or parts[1] == "status":
                    console.print(visualizer.export_ascii())
                elif parts[1] == "graph":
                    # Show mermaid diagram
                    mermaid = visualizer.export_mermaid()
                    console.print(Panel(mermaid, title="[bold cyan]Attack Graph (Mermaid)[/bold cyan]", border_style="cyan"))
                    console.print("[dim]Copy the mermaid code to https://mermaid.live to visualize[/dim]")
                elif parts[1] == "paths":
                    # Find attack paths
                    paths = visualizer.find_all_paths_to_goal()
                    if paths:
                        console.print("[bold cyan]🎯 Attack Paths Found:[/bold cyan]")
                        for i, path in enumerate(paths, 1):
                            console.print(f"  {i}. {' → '.join(path)}")
                    else:
                        display_info("No complete attack paths found yet")
                elif parts[1] == "summary":
                    console.print(visualizer.get_attack_summary())
                elif parts[1] == "export":
                    # Export to JSON
                    filename = f"attack_graph_{int(time.time())}.json"
                    with open(filename, "w") as f:
                        f.write(visualizer.export_json())
                    display_success(f"Attack graph exported to {filename}")
                else:
                    console.print("""
[bold cyan]🗡️ Attack Path Visualization[/bold cyan]

Commands:
  attack              - Show current attack graph (ASCII)
  attack graph        - Show Mermaid diagram
  attack paths        - Find all attack paths to compromised nodes
  attack summary      - Get text summary of attacks
  attack export       - Export attack graph as JSON
""")
                continue

            # === TIMEOUT CONFIGURATION (NEW) ===
            if cmd == "timeout" or cmd.startswith("timeout "):
                from src.sdk.validation import get_timeout_config
                
                parts = user_input.split()
                config = get_timeout_config()
                
                if len(parts) == 1 or parts[1] == "list":
                    console.print("[bold cyan]⏱️ Tool Timeout Configuration[/bold cyan]\n")
                    console.print(f"Default: {config.default}s\n")
                    console.print("[bold]Custom Timeouts:[/bold]")
                    for tool, timeout in sorted(config.timeouts.items()):
                        console.print(f"  {tool}: {timeout}s")
                elif parts[1] == "set" and len(parts) >= 4:
                    # timeout set <tool> <seconds>
                    tool_name = parts[2]
                    try:
                        timeout_secs = int(parts[3])
                        config.set_timeout(tool_name, timeout_secs)
                        display_success(f"Set timeout for {tool_name} to {timeout_secs}s")
                    except ValueError:
                        display_error("Timeout must be a number in seconds")
                else:
                    display_info("Usage: timeout list | timeout set <tool> <seconds>")
                continue

            # === ASYNC TASK MANAGEMENT ===
            if cmd == "task" or cmd.startswith("task "):
                from src.sdk.async_executor import get_async_executor, TaskStatus
                
                parts = user_input.split()
                executor = get_async_executor()
                
                if len(parts) == 1 or parts[1] == "list":
                    # Show all tasks
                    console.print(executor.get_status())
                    
                    # List recent tasks
                    all_tasks = list(executor.tasks.values())[-10:]  # Last 10
                    if all_tasks:
                        from rich.table import Table
                        table = Table(title="Recent Tasks", show_header=True)
                        table.add_column("ID", style="cyan")
                        table.add_column("Tool", style="green")
                        table.add_column("Status")
                        table.add_column("Duration", justify="right")
                        
                        status_colors = {
                            TaskStatus.PENDING: "yellow",
                            TaskStatus.RUNNING: "blue",
                            TaskStatus.COMPLETED: "green",
                            TaskStatus.FAILED: "red",
                            TaskStatus.CANCELLED: "dim"
                        }
                        
                        for task in all_tasks:
                            status_style = status_colors.get(task.status, "white")
                            table.add_row(
                                task.id,
                                task.tool_name,
                                f"[{status_style}]{task.status.value}[/{status_style}]",
                                f"{task.duration:.1f}s" if task.duration > 0 else "-"
                            )
                        console.print(table)
                        
                elif parts[1] == "status" and len(parts) >= 3:
                    # Get specific task status
                    task_id = parts[2]
                    task = executor.get_task(task_id)
                    if task:
                        status_emoji = {
                            TaskStatus.PENDING: "⏳",
                            TaskStatus.RUNNING: "▶️",
                            TaskStatus.COMPLETED: "✅",
                            TaskStatus.FAILED: "❌",
                            TaskStatus.CANCELLED: "🚫"
                        }
                        console.print(f"""
[bold cyan]📋 Task Details[/bold cyan]

  ID:       {task.id}
  Tool:     {task.tool_name}
  Status:   {status_emoji.get(task.status, "")} {task.status.value}
  Duration: {task.duration:.1f}s
  Args:     {task.args}
""")
                        if task.result:
                            console.print(f"[bold green]Result:[/bold green]\n{task.result}")
                        if task.error:
                            console.print(f"[bold red]Error:[/bold red] {task.error}")
                    else:
                        display_error(f"Task {task_id} not found")
                        
                elif parts[1] == "results" and len(parts) >= 3:
                    # Get task result
                    task_id = parts[2]
                    result = executor.get_result(task_id)
                    if result:
                        console.print(Panel(result, title=f"[cyan]Result: {task_id}[/cyan]"))
                    else:
                        display_info(f"Task {task_id} has no result yet")
                        
                elif parts[1] == "cancel" and len(parts) >= 3:
                    # Cancel a task
                    task_id = parts[2]
                    if executor.cancel(task_id):
                        display_success(f"Cancelled task {task_id}")
                    else:
                        display_error(f"Could not cancel task {task_id}")
                        
                elif parts[1] == "wait" and len(parts) >= 3:
                    # Wait for a task to complete
                    task_id = parts[2]
                    timeout = int(parts[3]) if len(parts) > 3 else 300
                    
                    console.print(f"[dim]Waiting for task {task_id} (timeout: {timeout}s)...[/dim]")
                    task = executor.wait(task_id, timeout)
                    if task and task.status == TaskStatus.COMPLETED:
                        display_success("Task completed!")
                        console.print(task.result if task.result else "No output")
                    elif task:
                        display_error(f"Task ended with status: {task.status.value}")
                    else:
                        display_error(f"Task {task_id} not found")
                else:
                    console.print("""
[bold cyan]⚡ Async Task Management[/bold cyan]

Commands:
  task list                - List all tasks and show status
  task status <id>         - Get detailed task status
  task results <id>        - Get task output/result
  task cancel <id>         - Cancel a pending/running task  
  task wait <id> [timeout] - Wait for task to complete
""")
                continue

            if cmd == "clear":
                clear_memory(agent)
                _tool_log.clear()
                display_success("Memory cleared")
                continue
            
            # === API KEY STATUS ===
            if cmd == "api" or cmd.startswith("api "):
                from src.sdk.key_manager import get_key_manager
                km = get_key_manager()
                
                parts = user_input.split()
                if len(parts) > 1:
                    subcmd = parts[1].lower()
                    
                    if subcmd == "reset":
                        # Reset all keys to healthy state
                        km.reset_keys()
                        display_success("All API keys reset to healthy state")
                        console.print(km.get_status())
                    elif subcmd in ["openrouter", "nvidia", "modelscope"]:
                        # Switch provider: api openrouter, api nvidia, api modelscope
                        if km.switch_provider(subcmd):
                            display_success(f"Switched to [bold]{subcmd}[/bold]")
                        else:
                            display_error(f"Provider '{subcmd}' not available")
                    else:
                        display_error(f"Unknown api command: {subcmd}")
                        console.print("[dim]Usage: api [reset|openrouter|nvidia|modelscope][/dim]")
                else:
                    # Show status
                    console.print(km.get_status())
                continue
            
            # === MODEL SELECTION ===
            if cmd == "model" or cmd.startswith("model "):
                from src.sdk.model_settings import get_model_settings, AVAILABLE_MODELS
                from src.sdk.key_manager import get_key_manager
                from rich.table import Table
                
                model_settings = get_model_settings()
                km = get_key_manager()
                parts = user_input.split()
                
                if len(parts) == 1:
                    # Show current models and list available
                    active_provider = km.keys[km.current_key].provider if km.current_key else "unknown"
                    active_model = km.get_model()
                    
                    console.print(model_settings.get_status())
                    console.print(f"\n[bold green]➜ ACTIVE SELECTION:[/bold green] [bold white]{active_model}[/bold white] (via [cyan]{active_provider}[/cyan])")
                    console.print("[dim]Note: Use 'api <provider>' to switch providers (e.g. 'api nvidia')[/dim]")
                    
                    console.print("\n[bold cyan]Available Models:[/bold cyan]")
                    
                    model_table = Table(show_header=True, header_style="bold white", box=box.ROUNDED)
                    model_table.add_column("#", style="cyan", width=3)
                    model_table.add_column("Provider", style="yellow")
                    model_table.add_column("Model", style="white")
                    model_table.add_column("Free", width=5)
                    model_table.add_column("Description", style="dim")
                    
                    idx = 1
                    for provider, models in AVAILABLE_MODELS.items():
                        for m in models:
                            free_mark = "[green]✓[/green]" if m.is_free else ""
                            model_table.add_row(str(idx), provider, m.name, free_mark, m.description)
                            idx += 1
                    
                    console.print(model_table)
                    console.print("\n[dim]Usage: model <provider> <model_id> OR model <number>[/dim]")
                    console.print("[dim]Example: model nvidia stepfun-ai/step-3.7-flash[/dim]")
                    
                elif len(parts) == 2:
                    # Select by number or show provider models
                    arg = parts[1].lower()
                    
                    # Try as number
                    if arg.isdigit():
                        num = int(arg)
                        idx = 1
                        found = False
                        for provider, models in AVAILABLE_MODELS.items():
                            for m in models:
                                if idx == num:
                                    km.switch_model(provider, m.id)
                                    km.switch_provider(provider)
                                    # Propagate to current agent
                                    if agent:
                                        agent.model = m.id
                                    display_success(f"Model set and provider switched to: [bold]{m.name}[/bold] ({provider})")
                                    found = True
                                    break
                                idx += 1
                            if found:
                                break
                        if not found:
                            display_error(f"Invalid model number: {num}")
                    
                    # Show models for a provider
                    elif arg in AVAILABLE_MODELS:
                        console.print(f"\n[bold cyan]Models for {arg}:[/bold cyan]")
                        for i, m in enumerate(AVAILABLE_MODELS[arg], 1):
                            free_mark = " [green](FREE)[/green]" if m.is_free else ""
                            console.print(f"  {i}. {m.name}{free_mark} - {m.description}")
                            console.print(f"     [dim]{m.id}[/dim]")
                    else:
                        display_error(f"Unknown provider or number: {arg}")
                    
                elif len(parts) >= 3:
                    # Set specific model: model <provider> <model_id>
                    provider = parts[1].lower()
                    model_query = " ".join(parts[2:]).lower()
                    
                    # Find matching model
                    found = False
                    if provider in AVAILABLE_MODELS:
                        for m in AVAILABLE_MODELS[provider]:
                            if model_query in m.id.lower() or model_query in m.name.lower():
                                km.switch_model(provider, m.id)
                                km.switch_provider(provider)
                                # Propagate to current agent
                                if agent:
                                    agent.model = m.id
                                display_success(f"Model set and provider switched to: [bold]{m.name}[/bold] ({provider})")
                                found = True
                                break
                        
                        if not found:
                            # Allow custom model ID
                            km.switch_model(provider, parts[2])
                            # Propagate to current agent
                            if agent:
                                agent.model = parts[2]
                            display_success(f"Model set to: [bold]{parts[2]}[/bold] (custom)")
                    else:
                        display_error(f"Unknown provider: {provider}")
                continue
            
            # === API KEYS STATUS ===
            if cmd == "keys" or cmd == "api":
                from src.sdk.key_manager import get_key_manager
                km = get_key_manager()
                console.print(km.get_status())
                console.print("\n[dim]Tip: Add LONGCAT_API_KEY_2=your_key to .env for load balancing[/dim]")
                continue
            
            # === THINKING TOGGLE ===
            if cmd == "thinking" or cmd.startswith("thinking "):
                global _show_thinking, _thinking_compact
                parts = user_input.split()
                if len(parts) > 1 and parts[1].lower() in ("on", "true", "1", "yes"):
                    _show_thinking = True
                    display_success("Thinking [bold green]ON[/bold green]  (press [bold]+[/bold] to expand  /  [bold]-[/bold] to collapse while agent runs)")
                elif len(parts) > 1 and parts[1].lower() in ("off", "false", "0", "no"):
                    _show_thinking = False
                    display_success("Thinking [bold red]OFF[/bold red]")
                else:
                    _show_thinking = not _show_thinking
                    status = "[bold green]ON[/bold green]  (press [bold]+[/bold] expand / [bold]-[/bold] collapse)" if _show_thinking else "[bold red]OFF[/bold red]"
                    display_success(f"Thinking {status}")
                continue
            
            # === SUPERVISOR FEEDBACK LOOP CONTROL ===
            if cmd == "supervisor" or cmd.startswith("supervisor "):
                from src.sdk.runner import Runner
                parts = user_input.split()
                if len(parts) == 1:
                    iv = Runner.supervisor_interval
                    if iv > 0:
                        display_info(f"Supervisor: [green]ENABLED[/green] - fires every [bold]{iv}[/bold] iterations")
                    else:
                        display_info("Supervisor: [red]DISABLED[/red] - type 'supervisor on' or 'supervisor <N>' to enable")
                else:
                    sub = parts[1].lower()
                    if sub in ("off", "0", "disable"):
                        Runner.supervisor_interval = 0
                        display_success("Supervisor [bold red]disabled[/bold red].")
                    elif sub in ("on", "enable"):
                        Runner.supervisor_interval = 10
                        display_success("Supervisor [bold green]enabled[/bold green] - fires every 10 iterations.")
                    elif sub.isdigit() and int(sub) > 0:
                        Runner.supervisor_interval = int(sub)
                        display_success(f"Supervisor interval set to every [bold]{sub}[/bold] iterations.")
                    else:
                        display_warning("Usage: supervisor [on|off|<number>]  - e.g. 'supervisor 5'")
                continue

            # === CONFIRM TOGGLE (Human-in-the-loop) ===
            if cmd == "confirm" or cmd.startswith("confirm "):
                global _require_confirm
                from src.sdk.runner import Runner
                parts = user_input.split()
                if len(parts) > 1:
                    if parts[1].lower() in ("on", "true", "1", "yes"):
                        _require_confirm = True
                        Runner.require_confirmation = True
                        display_success("Confirmation mode [bold green]ON[/bold green] - Will ask before each tool")
                    else:
                        _require_confirm = False
                        Runner.require_confirmation = False
                        display_success("Confirmation mode [bold red]OFF[/bold red] - Auto-execute tools")
                else:
                    _require_confirm = not _require_confirm
                    Runner.require_confirmation = _require_confirm
                    status = "[bold green]ON[/bold green]" if _require_confirm else "[bold red]OFF[/bold red]"
                    display_success(f"Confirmation mode {status}")
                continue
            
            # === DETAILED OUTPUT TOGGLE ===
            if cmd == "detailed" or cmd.startswith("detailed "):
                global _show_detailed
                parts = user_input.split()
                if len(parts) > 1:
                    if parts[1].lower() in ("on", "true", "1", "yes"):
                        _show_detailed = True
                        display_success("Detailed output [bold green]ON[/bold green] - Showing full tool info")
                    else:
                        _show_detailed = True
                        display_success("Detailed output [bold red]OFF[/bold red] - Minimal output")
                else:
                    _show_detailed = not _show_detailed
                    status = "[bold green]ON[/bold green]" if _show_detailed else "[bold red]OFF[/bold red]"
                    display_success(f"Detailed output {status}")
                continue
            
            # === BUG BOUNTY MODE TOGGLE (Authorization Context) ===
            if cmd == "mode" or cmd.startswith("mode "):
                from src.sdk.agent import enable_bug_bounty_mode, is_bug_bounty_mode, BUG_BOUNTY_AUTHORIZATION_SHORT
                
                parts = user_input.split()
                if len(parts) > 1:
                    if parts[1].lower() in ("on", "true", "1", "yes", "bounty"):
                        enable_bug_bounty_mode(True)
                        display_success("Bug Bounty Mode [bold green]ON[/bold green] - Authorization context enabled")
                        console.print("[dim]Agents will now include bug bounty authorization preamble[/dim]")
                    elif parts[1].lower() == "short":
                        enable_bug_bounty_mode(True, short_preamble=True)
                        display_success("Bug Bounty Mode [bold green]ON (short)[/bold green] - Using compact preamble")
                    else:
                        enable_bug_bounty_mode(False)
                        display_success("Bug Bounty Mode [bold red]OFF[/bold red] - Standard mode")
                        console.print("[dim]⚠️ LLMs may refuse some security testing operations[/dim]")
                else:
                    # Show current status
                    is_enabled = is_bug_bounty_mode()
                    status = "[bold green]ON[/bold green]" if is_enabled else "[bold red]OFF[/bold red]"
                    console.print("\n[bold cyan]🎯 Bug Bounty Authorization Mode[/bold cyan]\n")
                    console.print(f"Status: {status}")
                    console.print("\nThis mode adds an authorization preamble to all agent instructions.")
                    console.print("It helps prevent LLM safety refusals for legitimate penetration testing.\n")
                    console.print("[dim]Commands:[/dim]")
                    console.print("  mode on     - Enable with full preamble")
                    console.print("  mode short  - Enable with compact preamble")
                    console.print("  mode off    - Disable (standard mode)")
                    
                    if is_enabled:
                        console.print("\n[dim]Current preamble (short preview):[/dim]")
                        console.print(f"[dim green]{BUG_BOUNTY_AUTHORIZATION_SHORT[:200]}...[/dim green]")
                continue
            
            # === FINDINGS SUMMARY ===
            if cmd == "findings" or cmd.startswith("findings "):
                global _session_findings
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "summary":
                    if _session_findings:
                        # Count by severity
                        by_severity = {}
                        by_type = {}
                        for f in _session_findings:
                            sev = f.get("severity", "info")
                            ftype = f.get("type", "unknown")
                            by_severity[sev] = by_severity.get(sev, 0) + 1
                            by_type[ftype] = by_type.get(ftype, 0) + 1
                        
                        display_findings_summary(_session_findings, by_severity, by_type)
                    else:
                        display_info("No findings recorded yet. Run some scans first!")
                        
                elif parts[1] == "export":
                    if _session_findings:
                        import json
                        filename = f"findings_{int(time.time())}.json"
                        with open(filename, "w") as f:
                            json.dump(_session_findings, f, indent=2, default=str)
                        display_success(f"Findings exported to {filename}")
                    else:
                        display_warning("No findings to export")
                        
                elif parts[1] == "clear":
                    _session_findings = []
                    display_success("Findings cleared")
                continue
            
            # === STATS (Real-time) ===
            if cmd == "stats" or cmd == "realtime":
                global _session_tools_used
                duration = (time.time() - _execution_start_time) if _execution_start_time else 0
                
                display_real_time_stats(
                    tools_run=len(_session_tools_used),
                    findings=len(_session_findings),
                    duration=duration,
                    current_tool=_current_tool or "",
                    current_agent=agent.name if agent else ""
                )
                continue
            
            # === RECOVERY STATUS (NEW) ===
            if cmd == "recovery" or cmd.startswith("recovery "):
                recovery_engine = get_recovery_engine()
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "status":
                    summary = recovery_engine.get_failure_summary()
                    
                    console.print("[bold cyan]🔄 Failure Recovery Status[/bold cyan]\n")
                    console.print(f"Total Failures: [yellow]{summary['total_failures']}[/yellow]")
                    
                    if summary['by_reason']:
                        console.print("\n[bold]Failures by Reason:[/bold]")
                        for reason, count in summary['by_reason'].items():
                            console.print(f"  • {reason}: {count}")
                    
                    if summary['by_tool']:
                        console.print("\n[bold]Failures by Tool:[/bold]")
                        for tool, count in summary['by_tool'].items():
                            console.print(f"  • {tool}: {count}")
                    
                    if summary['recent_failures']:
                        console.print("\n[bold]Recent Failures:[/bold]")
                        for f in summary['recent_failures']:
                            console.print(f"  [{f['time'][:19]}] {f['tool']}: {f['reason']}")
                            
                elif parts[1] == "history":
                    console.print("[bold cyan]🔄 Full Failure History[/bold cyan]\n")
                    for f in recovery_engine.failure_history[-20:]:
                        console.print(f"  [{f.timestamp.strftime('%H:%M:%S')}] {f.tool_name}")
                        console.print(f"    Reason: {f.reason.value}")
                        console.print(f"    Error: {f.error[:50]}...")
                        console.print()
                        
                elif parts[1] == "clear":
                    recovery_engine.clear_history()
                    display_success("Recovery history cleared")
                continue

            # === ENGAGEMENT COCKPIT ===
            if cmd in ("preflight", "health"):
                display_agent_health_preflight(AGENTS, model=active_model, compact=False)
                continue

            if cmd == "hypotheses" or cmd.startswith("hypotheses "):
                if not current_target:
                    display_warning("Set a target first: target <domain/ip>")
                    continue
                display_hypothesis_board(current_target, compact=False)
                continue

            if cmd == "coverage" or cmd.startswith("coverage "):
                if not current_target:
                    display_warning("Set a target first: target <domain/ip>")
                    continue
                display_coverage_checklist(current_target, compact=False)
                continue

            if cmd == "cockpit":
                if not current_target:
                    display_warning("Set a target first: target <domain/ip>")
                    continue
                display_engagement_cockpit(
                    current_target,
                    str(target_manager.session_dir) if target_manager.session_dir else None,
                    agents=AGENTS,
                    model=active_model,
                    compact=False,
                )
                continue
            
            if cmd == "switch":
                print_separator()
                display_agents_table(AGENTS, agent.name)
                choice = Prompt.ask("Select agent", choices=list(AGENTS.keys()))
                _, agent_factory, _ = AGENTS[choice]
                
                from src.sdk.key_manager import get_key_manager
                current_model = get_key_manager().get_model()
                agent = agent_factory(model=current_model)
                
                display_success(f"Switched to [bold]{agent.name}[/bold] (Model: {agent.model})")
                continue
            
            if cmd.startswith("target "):
                target_start_ts = time.perf_counter()
                target_args = user_input.split()[1:]  # everything after 'target'
                if not target_args:
                    display_warning("Usage: target <domain/ip> [hostname]")
                    continue
                
                new_target = target_args[0]
                if current_target:
                    target_manager.end_session()
                    # ── Reset stale target context before new session ──────────
                    try:
                        from src.agents.orchestrator_agent import reset_current_target
                        reset_current_target()
                    except Exception:
                        pass
                current_target = new_target
                title_animator.set_text(f"Cyber-CoPilot - Target: {current_target}")

                # Add/observe the vhost before session/profile bootstrap so a
                # changed HTB IP can reuse hostname-linked history.
                from src.repl.hosts_manager import get_hosts_file_path, _is_valid_ip
                hosts_result = None
                hosts_elapsed = 0.0
                if len(target_args) >= 2:
                    ip, hostname = target_args[0], target_args[1]
                    hosts_start_ts = time.perf_counter()
                    hosts_result = _add_host_with_timeout(ip, hostname, note="HTB", timeout_seconds=2.5)
                    hosts_elapsed = time.perf_counter() - hosts_start_ts
                    try:
                        get_profile_manager().register_aliases(current_target, {ip, hostname})
                    except Exception as e:
                        logger.debug(f"Failed to register target aliases for {current_target}: {e}")

                session_dir = target_manager.start_session(current_target, agent.name)
                session_elapsed = time.perf_counter() - target_start_ts
                try:
                    from src.agents.orchestrator_agent import set_current_target
                    set_current_target(current_target)
                except Exception:
                    pass
                
                # Update context hub with new target
                context_elapsed = 0.0
                try:
                    context_start_ts = time.perf_counter()
                    from src.sdk.context_hub import get_context_hub
                    hub = get_context_hub()
                    hub.set_target(current_target)
                    context_elapsed = time.perf_counter() - context_start_ts
                except Exception:
                    pass

                # Initialize engagement mode/coverage for the new target if absent.
                try:
                    profile = get_profile_manager().load_profile(current_target)
                    if not getattr(profile, "engagement_mode", ""):
                        profile.engagement_mode = "pentest"
                    if not getattr(profile, "coverage_requirements", []):
                        from src.sdk.hypothesis_engine import get_policy

                        profile.coverage_requirements = [
                            {"requirement": item, "status": "pending"}
                            for item in get_policy(profile.engagement_mode or "pentest").coverage_requirements
                        ]
                    get_profile_manager().save_profile(current_target)
                except Exception:
                    pass
                
                print_separator()
                display_engagement_cockpit(
                    current_target,
                    str(session_dir),
                    agents=AGENTS,
                    model=active_model,
                    compact=True,
                )
                display_success(f"Session started: [bold]{current_target}[/bold]")
                
                # ── Hosts file auto-management ──────────
                if len(target_args) >= 2 and hosts_result is not None:
                    # Format: target <ip> <hostname>
                    ip, hostname = target_args[0], target_args[1]
                    if hosts_result["success"] and not hosts_result["already_existed"]:
                        display_success(f"[bold]Hosts file:[/bold] added  {ip}  {hostname}  → {get_hosts_file_path()}")
                    elif hosts_result["already_existed"]:
                        display_info(f"Hosts file: entry already present ({ip}  {hostname})")
                    else:
                        display_warning(f"Hosts file: {hosts_result['message']}")
                    if hosts_elapsed > 1.0:
                        display_info(f"[dim]Hosts update took {hosts_elapsed:.2f}s[/dim]")
                elif _is_valid_ip(new_target):
                    # Plain IP - remind user they can also pass a hostname
                    display_info("[dim]Tip: to auto-add a hostname run  target <ip> <hostname.htb>[/dim]")

                total_elapsed = time.perf_counter() - target_start_ts
                if total_elapsed > 1.5:
                    display_info(
                        f"[dim]Target setup timing: session={session_elapsed:.2f}s, context={context_elapsed:.2f}s, total={total_elapsed:.2f}s[/dim]"
                    )
                continue

            if cmd.startswith("ctf "):
                # Usage: ctf <path_to_binary>
                parts = user_input.split(maxsplit=1)
                if len(parts) < 2:
                    display_warning("Usage: ctf <path_to_binary>")
                    continue
                
                binary_path = parts[1].strip().strip('"').strip("'")
                binary_name = os.path.basename(binary_path)
                
                # Set target to CTF_challs/<binary_name>
                if current_target:
                    target_manager.end_session()
                
                current_target = f"CTF_challs/{binary_name}"
                title_animator.set_text(f"Cyber-CoPilot - CTF: {binary_name}")
                session_dir = target_manager.start_session(current_target, "CTFAgent")
                
                # Switch to CTF Agent
                from src.agents.ctf_agent import create_ctf_agent
                agent = create_ctf_agent()
                
                # Update context hub
                try:
                    from src.sdk.context_hub import get_context_hub
                    hub = get_context_hub()
                    hub.set_target(current_target)
                    hub.current_phase = "reconnaissance"
                except Exception:
                    pass
                
                display_success(f"CTF Mode Active: [bold]{binary_name}[/bold]")
                display_info(f"Logs organized in: {session_dir}")
                
                # Auto-start with a preparation prompt
                user_input = f"this is a CTF challenge solve this {binary_path}"
                # FALL THROUGH to agent execution
            
            # === HOSTS FILE MANAGEMENT (HTB / Lab machines) ===
            if cmd == "hosts" or cmd.startswith("hosts "):
                from src.repl.hosts_manager import (
                    add_host, remove_host, list_managed_hosts,
                    check_can_write, get_hosts_file_path, _is_valid_ip
                )
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "list":
                    entries = list_managed_hosts()
                    if not entries:
                        display_info(f"No managed hosts entries yet. (file: {get_hosts_file_path()})")
                    else:
                        from rich.table import Table as _Table
                        htable = _Table(
                            title="[bold cyan]🗂️  Managed Hosts Entries[/bold cyan]",
                            show_header=True, header_style="bold white", border_style="cyan"
                        )
                        htable.add_column("IP", style="cyan", min_width=16)
                        htable.add_column("Hostname(s)", style="green", min_width=25)
                        htable.add_column("Note", style="dim", min_width=10)
                        for e in entries:
                            htable.add_row(e["ip"], "  ".join(e["hostnames"]), e["note"])
                        console.print(htable)
                        if not check_can_write():
                            display_warning("Note: hosts file is read-only for current user. Run as admin/sudo to modify.")
                
                elif parts[1] == "add" and len(parts) >= 4:
                    ip, hostname = parts[2], parts[3]
                    note = " ".join(parts[4:]) if len(parts) > 4 else "manual"
                    result = add_host(ip, hostname, note=note)
                    if result["success"] and not result["already_existed"]:
                        display_success(f"Added: {ip}  {hostname}  → {get_hosts_file_path()}")
                    elif result["already_existed"]:
                        display_info(f"Entry already exists: {ip}  {hostname}")
                    else:
                        display_warning(result["message"])
                
                elif parts[1] == "remove" and len(parts) >= 3:
                    hostname = parts[2]
                    result = remove_host(hostname)
                    if result["success"]:
                        display_success(result["message"])
                    else:
                        display_warning(result["message"])
                
                else:
                    console.print("""
[bold cyan]🗂️  Hosts File Management[/bold cyan]

  [yellow]hosts[/yellow]                          - List all managed entries
  [yellow]hosts list[/yellow]                     - List all managed entries  
  [yellow]hosts add <ip> <hostname>[/yellow]      - Add entry to hosts file
  [yellow]hosts remove <hostname>[/yellow]        - Remove managed entry

[dim]Examples:
  target 10.10.11.50 machine.htb   ← auto-adds during target setup
  hosts add 10.10.11.50 machine.htb
  hosts remove machine.htb[/dim]
""")
                continue

            if cmd == "logs":
                if current_target and target_manager.session_dir:
                    display_info(f"Session: {target_manager.session_dir}")
                    console.print("  [dim]├── user_inputs.txt[/dim]")
                    console.print("  [dim]├── agent_outputs.txt[/dim]")
                    console.print("  [dim]├── tool_calls.txt[/dim]")
                    console.print("  [dim]└── summary.txt[/dim]")
                else:
                    display_warning("No active session. Use: target <domain>")
                continue
            
            if cmd.startswith("history"):
                parts = user_input.split(maxsplit=1)
                search_target = parts[1] if len(parts) > 1 else current_target
                if not search_target:
                    display_warning("Usage: history <target>")
                    continue
                history = target_manager.get_target_history(search_target)
                if history:
                    display_info(f"Sessions for {search_target}:")
                    for h in history[:10]:
                        console.print(f"  [cyan]📁[/cyan] {h['name']}")
                else:
                    display_info("No previous sessions found")
                continue
            
            if cmd.startswith(("parallel ", "full-scan ")):
                await handle_parallel_command(user_input, target_manager)
                continue
            
            # === AGENT GRAPH COMMAND ===
            if cmd.startswith("graph"):
                await handle_graph_command(user_input, target_manager, current_target)
                continue
            
            # === PROFILE COMMAND ===
            if cmd == "profile" or cmd.startswith("profile "):
                profile_manager = get_profile_manager()
                parts = user_input.split(maxsplit=1)
                target_to_show = parts[1] if len(parts) > 1 else current_target
                
                if not target_to_show:
                    display_warning("Usage: profile <target> or set target first")
                    continue
                
                summary = profile_manager.get_summary(target_to_show)
                console.print(Panel(summary, title="[bold cyan]Target Profile[/bold cyan]", border_style="cyan"))
                continue
            
            # === EXPORT/REPORT COMMAND ===
            if cmd == "export" or cmd.startswith("export "):
                if not current_target or not target_manager.session_dir:
                    display_warning("No active session. Use: target <domain> first")
                    continue
                
                report_gen = get_report_generator()
                report_path = report_gen.generate_markdown_report(
                    target=current_target,
                    session_dir=str(target_manager.session_dir)
                )
                display_success(f"Report exported: [bold]{report_path}[/bold]")
                
                # Try to generate HTML too
                try:
                    html_path = report_gen.export_to_html(report_path)
                    if html_path:
                        display_success(f"HTML version: [bold]{html_path}[/bold]")
                except Exception:
                    pass
                continue
            
            # === REVERSE SHELL COMMAND ===
            if cmd.startswith("shell ") or cmd.startswith("revshell "):
                parts = user_input.split()
                if len(parts) < 4:
                    console.print("""
[bold cyan]🔓 Reverse Shell Generator[/bold cyan]

Usage: shell <type> <ip> <port>

Examples:
  shell bash 10.10.14.5 4444
  shell python3 192.168.1.5 9001
  shell powershell 10.10.14.5 443

Available types:
  bash, nc, python, python3, php, perl, ruby, powershell, socat, awk, lua

Tip: Use 'shell list' to see all available types
""")
                    continue
                
                shell_type = parts[1]
                
                if shell_type == "list":
                    from src.tools.shells import list_reverse_shells
                    console.print(list_reverse_shells())
                    continue
                
                try:
                    ip = parts[2]
                    port = int(parts[3])
                    from src.tools.shells import generate_reverse_shell
                    result = generate_reverse_shell(shell_type, ip, port)
                    console.print(Panel(result, border_style="yellow"))
                except (IndexError, ValueError):
                    display_error("Usage: shell <type> <ip> <port>")
                continue
            
            # === LISTENER COMMAND ===
            if cmd.startswith("listen "):
                parts = user_input.split()
                if len(parts) < 2:
                    display_warning("Usage: listen <port> [type]")
                    continue
                
                try:
                    port = int(parts[1])
                    listener_type = parts[2] if len(parts) > 2 else "nc"
                    from src.tools.c2_server import start_listener
                    result = await start_listener(port, listener_type)
                    console.print(Panel(result, border_style="green"))
                except ValueError:
                    display_error("Port must be a number")
                continue
            
            # === MEMORY SEARCH COMMAND ===
            if cmd == "memory" or cmd.startswith("memory "):
                from src.sdk.memory import get_memory
                memory = get_memory()
                
                parts = user_input.split(maxsplit=1)
                
                if len(parts) < 2:
                    # Show stats
                    stats = memory.get_stats(current_target)
                    console.print(f"""
[bold cyan]🧠 VECTOR MEMORY[/bold cyan]

Global Entries: {stats.get('global_entries', 0)}
Target Entries: {stats.get('target_entries', 0) if current_target else 'N/A'}
Storage: ./.memory/

[dim]Usage: memory <search query>[/dim]
""")
                    continue
                
                # Search memory
                query = parts[1]
                results = memory.search(query, target=current_target, limit=5)
                
                if results:
                    console.print(f"\n[bold cyan]🔍 Memory Search: '{query}'[/bold cyan]\n")
                    for i, r in enumerate(results, 1):
                        content = r.get('content', '')[:200]
                        meta = r.get('metadata', {})
                        console.print(f"[bold yellow]{i}.[/bold yellow] [{meta.get('category', 'unknown')}]")
                        console.print(f"   [white]{content}[/white]\n")
                else:
                    display_info("No matching memories found")
                continue
            
            # === CONTEXT HUB COMMAND ===
            if cmd == "context" or cmd.startswith("context "):
                from src.sdk.context_hub import get_context_hub
                hub = get_context_hub()
                
                parts = user_input.split()
                
                if len(parts) > 1 and parts[1] == "clear":
                    hub.clear_findings()
                    display_success("Context hub cleared")
                    continue
                
                # Show context hub status
                summary = hub.get_findings_summary()
                
                from rich.table import Table
                
                # Create findings table
                findings_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
                findings_table.add_column("Category", style="yellow")
                findings_table.add_column("Count", style="green", justify="right")
                
                for category, count in summary.items():
                    if count > 0:
                        findings_table.add_row(category.title(), str(count))
                
                console.print(Panel(
                    findings_table,
                    title="[bold white]🎯 SHARED CONTEXT HUB[/bold white]",
                    subtitle=f"[dim]Target: {hub.current_target or 'None'} | Phase: {hub.current_phase}[/dim]",
                    border_style="cyan"
                ))
                
                # Show detailed context if requested
                if len(parts) > 1 and parts[1] == "full":
                    console.print("\n" + hub.get_context_for_agent())
                else:
                    console.print("[dim]Use 'context full' for detailed view, 'context clear' to reset[/dim]")
                continue
            
            # === TOOLS MANAGEMENT ===
            if cmd.startswith("tools"):
                from src.tools.tool_checker import check_all_tools, check_category_tools, get_installation_commands
                from src.tools.recon_active import _install_recon_tools_impl
                
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "check":
                    # Check ALL tools across all categories
                    console.print("\n[bold]Checking all framework tools...[/bold]\n")
                    check_all_tools()
                
                elif parts[1] == "category" and len(parts) > 2:
                    # Check specific category
                    category = parts[2]
                    check_category_tools(category)
                
                elif parts[1] == "install-guide":
                    # Show installation commands
                    get_installation_commands()
                
                elif parts[1] == "install":
                    # Install tools
                    tools_to_install = parts[2] if len(parts) > 2 else "all"
                    
                    console.print("[bold yellow]🔧 Installing reconnaissance tools...[/bold yellow]")
                    console.print("[dim]This may take a few minutes for Go tools.[/dim]\n")
                    
                    result = await _install_recon_tools_impl(tools_to_install)
                    console.print(result)
                    
                    console.print("\n[bold green]✓ Installation process completed![/bold green]")
                    console.print("[dim]Run 'tools check' to verify installations.[/dim]")
                
                else:
                    console.print("""
[bold]Tool Management Commands:[/bold]

  tools check                    - Check ALL installed tools (recon, web, exploit, AD, etc.)
  tools category <name>          - Check specific category (recon/web/exploit/ad/forensics/network/creds/core)
  tools install-guide            - Show installation commands for your OS
  tools install all              - Install all missing reconnaissance tools
  tools install <tool1,tool2>    - Install specific reconnaissance tools

[bold]Stealth & Evasion:[/bold]

  configure stealth mode         - Set to balanced mode (default)
  configure aggressive mode      - Fast scanning (0.1-0.5s delays)
  configure paranoid mode        - Maximum evasion (5-10s delays)
  
  [dim]Prevents WAF blocks, rate limiting, and IP bans[/dim]

[bold]Examples:[/bold]
  tools check                    # Check all framework tools
  tools category web             # Check only web tools
  tools install-guide            # Get OS-specific install commands
  tools install all
  tools install subjack,webanalyze
  configure stealth mode      # For hardened targets

[bold]Available Tools:[/bold]
  • Go Tools: subfinder, httpx, nuclei, subjack, webanalyze, gospider,
              assetfinder, gau, waybackurls, dnsx, naabu, katana, chaos
  • System: nmap, whois, dig, masscan, rustscan, searchsploit,
            netcat, theharvester, dnsrecon, dnsenum, whatweb

[dim]See docs/STEALTH.md for WAF bypass techniques[/dim]
""")
                continue
            
            # === POC COMMAND ===
            if cmd.startswith("poc"):
                from src.sdk.context_hub import get_context_hub
                hub = get_context_hub()
                
                parts = user_input.split()
                finding_type = parts[1] if len(parts) > 1 else "all"
                
                # Validate finding type
                valid_types = ["all", "vulns", "vulnerabilities", "exploits", "access", "creds", "credentials", "ports"]
                if finding_type not in valid_types:
                    display_warning(f"Invalid type. Use: {', '.join(valid_types)}")
                    continue
                
                # Check if there's any data
                has_data = bool(hub.tool_history) or any(hub.findings[k] for k in hub.findings)
                if not has_data:
                    display_warning("No tools executed yet. Run some scans first, then use 'poc' to generate a report.")
                    continue
                
                # Generate POC with loading indicator (calls AI API)
                console.print(f"\n[bold cyan]🔍 Analyzing {len(hub.tool_history)} tool executions...[/bold cyan]")
                console.print("[dim]Generating POC report from actual commands and findings via AI...[/dim]\n")
                
                try:
                    poc_content = hub.generate_poc(finding_type)
                except Exception as e:
                    display_error(f"POC generation failed: {e}")
                    console.print("[dim]Trying fallback report...[/dim]")
                    poc_content = hub._generate_fallback_poc(finding_type)
                
                # Display in panel
                from rich.markdown import Markdown
                
                console.print(Panel(
                    Markdown(poc_content),
                    title="[bold red]🎯 PROOF OF CONCEPT (POC)[/bold red]",
                    subtitle="[dim]Authorized Testing Only[/dim]",
                    border_style="red",
                    expand=True,
                    padding=(1, 2)
                ))
                
                # Ask if user wants to save
                console.print("\n[dim]💾 Save POC? Use: export markdown poc.md[/dim]")
                continue
            
            # === EXPORT FINDINGS COMMAND ===
            if cmd.startswith("export"):
                from src.sdk.runner import get_runner
                
                parts = user_input.split()
                export_format = "markdown"
                output_path = None
                
                # Parse format
                if len(parts) >= 2:
                    export_format = parts[1].lower()
                    if export_format not in ["json", "markdown", "html", "csv"]:
                        display_error("Supported formats: json, markdown, html, csv")
                        continue
                
                # Parse output path
                if len(parts) >= 3:
                    output_path = parts[2]
                else:
                    # Auto-generate filename
                    from datetime import datetime
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    target_name = current_target.replace(".", "_").replace("/", "_") if current_target else "report"
                    ext = {"json": "json", "markdown": "md", "html": "html", "csv": "csv"}[export_format]
                    output_path = f"reports/{target_name}_{timestamp}.{ext}"
                    
                    # Create reports directory
                    os.makedirs("reports", exist_ok=True)
                
                try:
                    result = get_runner().export_findings(export_format, output_path)
                    display_success(result)
                    
                    # Show file size
                    if os.path.exists(output_path):
                        size = os.path.getsize(output_path)
                        console.print(f"[dim]File size: {size:,} bytes[/dim]")
                except Exception as e:
                    display_error(f"Export failed: {e}")
                continue
            
            # === PROXY MANAGEMENT ===
            if cmd.startswith("proxy"):
                from src.tools.web import get_proxy_manager
                pm = get_proxy_manager()
                
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "status":
                    # Show proxy status
                    status = pm.get_status()
                    
                    status_text = f"""[bold]Proxy Manager[/bold]
                    
Enabled: [{'green' if status['enabled'] else 'red'}]{status['enabled']}[/]
Total proxies: [cyan]{status['total']}[/cyan]
Active proxies: [green]{status['active']}[/green]
Failed proxies: [red]{status['failed']}[/red]
Current: [yellow]{status['current'] or 'None'}[/yellow]
Requests: {status['request_count']}/{status['rotate_after']}

[dim]Commands: proxy add|load|enable|disable|rotate|list|reset[/dim]"""
                    
                    console.print(Panel(status_text, border_style="cyan"))
                
                elif parts[1] == "add" and len(parts) >= 3:
                    pm.add_proxy(parts[2])
                    display_success(f"Added proxy: {parts[2]}")
                
                elif parts[1] == "load" and len(parts) >= 3:
                    result = pm.add_proxies_from_file(parts[2])
                    if isinstance(result, int):
                        display_success(f"Loaded {result} proxies from {parts[2]}")
                    else:
                        display_error(result)
                
                elif parts[1] == "enable":
                    if not pm.proxies:
                        display_warning("No proxies configured! Use: proxy add <url>")
                    else:
                        rotate_every = int(parts[2]) if len(parts) >= 3 else 10
                        pm.enabled = True
                        pm.rotate_after = rotate_every
                        display_success(f"Proxy rotation ENABLED (rotating every {rotate_every} requests)")
                
                elif parts[1] == "disable":
                    pm.enabled = False
                    display_success("Proxy rotation DISABLED")
                
                elif parts[1] == "rotate":
                    pm.rotate()
                    current = pm.proxies[pm.current_index]["url"] if pm.proxies else "None"
                    display_success(f"Rotated to: {current}")
                
                elif parts[1] == "list":
                    if not pm.proxies:
                        display_info("No proxies configured")
                    else:
                        from rich.table import Table
                        proxy_table = Table(title="[bold]Configured Proxies[/bold]", box=box.ROUNDED)
                        proxy_table.add_column("#", style="dim")
                        proxy_table.add_column("Proxy URL", style="cyan")
                        proxy_table.add_column("Status", style="green")
                        
                        for i, p in enumerate(pm.proxies):
                            status = "[red]FAILED[/red]" if p["url"] in pm.failed_proxies else "[green]ACTIVE[/green]"
                            current = " [yellow](current)[/yellow]" if i == pm.current_index else ""
                            proxy_table.add_row(str(i+1), p["url"], status + current)
                        
                        console.print(proxy_table)
                
                elif parts[1] == "reset":
                    pm.reset()
                    display_success("Proxy manager reset")
                
                elif parts[1] == "fetch":
                    # Fetch free proxies
                    proxy_type = parts[2] if len(parts) >= 3 else "http"
                    from src.tools.web import fetch_free_proxies
                    result = fetch_free_proxies(proxy_type)
                    console.print(result)
                
                continue
            
            # === TOR COMMAND ===
            if cmd.startswith("tor"):
                from src.tools.web import tor_setup
                
                parts = user_input.split()
                action = parts[1] if len(parts) >= 2 else "help"
                
                result = tor_setup(action)
                console.print(Panel(result, title="[bold]Tor Setup[/bold]", border_style="magenta"))
                continue
            
            # === CHECK MY IP ===
            if cmd == "myip":
                from src.tools.web import check_my_ip, get_proxy_manager
                
                pm = get_proxy_manager()
                result = check_my_ip(use_proxy=pm.enabled)
                console.print(Panel(result, border_style="cyan"))
                continue
            
            # === RATE LIMIT STATUS ===
            if cmd == "rate" or cmd == "ratelimit":
                from src.sdk.key_manager import get_key_manager
                km = get_key_manager()
                
                status = km.get_rate_limit_status()
                
                from rich.table import Table
                rate_table = Table(title="[bold]Rate Limit Status[/bold]", box=box.ROUNDED)
                rate_table.add_column("Provider", style="cyan")
                rate_table.add_column("Tokens", style="green")
                rate_table.add_column("Limit (RPM)", style="yellow")
                rate_table.add_column("Wait", style="red")
                
                for provider, info in status.items():
                    rate_table.add_row(
                        provider,
                        str(info['tokens_available']),
                        str(info['rpm_limit']),
                        f"{info['wait_time']:.1f}s" if info['wait_time'] > 0 else "Ready"
                    )
                
                console.print(rate_table)
                continue
            
            # === API KEY RESET COMMAND ===
            if cmd.startswith("apikey"):
                from src.sdk.key_manager import get_key_manager
                km = get_key_manager()
                
                parts = user_input.split()
                
                if len(parts) == 1 or parts[1] == "status":
                    # Show API key status
                    console.print(km.get_status())
                
                elif parts[1] == "reset":
                    # Reset all keys
                    km.reset_keys()
                    display_success("All API keys reset and re-enabled")
                
                elif parts[1] == "enable" and len(parts) >= 3:
                    # Enable specific key
                    key_name = parts[2]
                    if km.enable_key(key_name):
                        display_success(f"Re-enabled key: {key_name}")
                    else:
                        display_error(f"Key not found: {key_name}")
                
                else:
                    console.print("""[cyan]API Key Management:[/cyan]
  apikey status      - Show all API keys and their status
  apikey reset       - Reset all keys (re-enable disabled ones)
  apikey enable <name> - Re-enable a specific key
""")
                continue
            
            # === REMEMBER/STORE COMMAND ===
            if cmd.startswith("remember ") or cmd.startswith("note "):
                from src.sdk.memory import get_memory
                
                if not current_target:
                    display_warning("Set a target first: target <domain>")
                    continue
                
                parts = user_input.split(maxsplit=1)
                if len(parts) < 2:
                    display_warning("Usage: remember <note text>")
                    continue
                
                memory = get_memory()
                memory.store(current_target, parts[1], category="user_note")
                display_success("Note stored in memory")
                continue
            
            # === RESUME SESSION (cross-session context injection) ===
            # Syntax: "resume session" or "resume session <target>"
            # Loads findings + agent outputs from the most recent previous session
            # for the current (or specified) target and injects them as context.
            if cmd == "resume session" or user_input.lower().startswith("resume session "):
                resume_target = current_target
                parts_rs = user_input.split(None, 2)
                if len(parts_rs) >= 3:
                    resume_target = parts_rs[2].strip()

                if not resume_target:
                    display_warning(
                        "No target set. Use: resume session <target> or set a target first."
                    )
                    continue

                # Find the most recent previous session directory for this target
                import glob as _glob
                import os as _os

                safe_target = resume_target.replace(".", "_").replace("/", "_").replace(":", "_")
                session_dirs = sorted(
                    _glob.glob(f"targets/{resume_target}/session_*")
                    + _glob.glob(f"targets/{safe_target}/session_*"),
                    reverse=True,
                )
                # Skip the current active session (highest timestamp = last)
                prev_sessions = session_dirs[1:] if len(session_dirs) > 1 else session_dirs

                if not prev_sessions:
                    display_warning(
                        f"No previous sessions found for '{resume_target}'. "
                        "Run a session first."
                    )
                    continue

                prev_dir = prev_sessions[0]
                console.print(
                    f"\n[bold green]↩ LOADING PREVIOUS SESSION[/bold green] "
                    f"[dim]{_os.path.basename(prev_dir)}[/dim]"
                )

                # Read last ~80 lines of agent_outputs and tool_calls for context
                context_parts: list[str] = []
                for fname in ("agent_outputs.txt", "tool_calls.txt"):
                    fpath = _os.path.join(prev_dir, fname)
                    if _os.path.exists(fpath):
                        try:
                            with open(fpath, encoding="utf-8", errors="ignore") as _f:
                                lines = _f.readlines()
                            excerpt = "".join(lines[-80:])
                            context_parts.append(
                                f"[{fname}]\n{excerpt}"
                            )
                        except Exception:
                            pass

                # Also pull the profile brief for the target
                try:
                    _pm = get_profile_manager()
                    brief = _pm.get_context_brief(resume_target)
                    if brief:
                        context_parts.insert(0, f"[PROFILE SUMMARY]\n{brief}")
                except Exception:
                    pass

                if not context_parts:
                    display_warning("Previous session files are empty or unreadable.")
                    continue

                MAX_CONTEXT = 6000
                joined = "\n\n".join(context_parts)
                if len(joined) > MAX_CONTEXT:
                    joined = joined[-MAX_CONTEXT:]

                resume_prompt = (
                    f"[RESUMING PREVIOUS SESSION FOR TARGET: {resume_target}]\n\n"
                    f"The following context is from the most recent prior session "
                    f"({_os.path.basename(prev_dir)}). "
                    f"Do NOT repeat completed work. Review the findings, identify what "
                    f"was NOT finished or what needs follow-up, and continue the engagement.\n\n"
                    f"{joined}\n\n"
                    f"---\n"
                    f"What should we focus on next based on the above findings?"
                )

                # Set the target if not already active
                if resume_target != current_target:
                    current_target = resume_target
                    title_animator.set_text(f"Cyber-CoPilot - Target: {current_target}")
                    try:
                        from src.agents.orchestrator_agent import set_current_target
                        set_current_target(current_target)
                    except Exception:
                        pass

                print_separator()
                console.print(
                    f"[bold white]🔄 PROCESSING[/bold white] [dim]via {agent.name}[/dim]"
                )
                print_separator("─", "dim")

                start_time = time.time()
                _tool_log.clear()

                from src.sdk.runner import Runner
                if _show_thinking:
                    Runner.on_thinking = on_thinking_callback
                else:
                    Runner.on_thinking = None

                try:
                    result = await run(agent, resume_prompt)
                    duration = time.time() - start_time
                    tool_calls_total += result.tool_calls_made
                    if current_target:
                        target_manager.log_output(result.output, result.tool_calls_made)
                    _display_result(result, agent, duration)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Interrupted[/yellow]")
                except Exception as exc:
                    display_error(f"Resume failed: {exc}")
                continue

            # === CONTINUE / RESUME COMMAND ===
            if cmd in ("continue", "resume"):
                if not _can_continue or not _last_agent or not _last_input:
                    display_warning("Nothing to continue. No interrupted operation found.")
                    continue
                
                # Reset continue state
                _can_continue = False
                
                # Reset API keys in case they were exhausted
                try:
                    from src.sdk.key_manager import get_key_manager
                    km = get_key_manager()
                    km.reset_keys()
                    display_info("API keys reset for retry")
                except Exception:
                    pass
                
                # Use the saved agent and target
                agent = _last_agent
                if _last_target and _last_target != current_target:
                    current_target = _last_target
                    title_animator.set_text(f"Cyber-CoPilot - Target: {current_target}")
                
                # Build a resume prompt
                resume_input = (
                    f"CONTINUE: Your previous task was interrupted. "
                    f"Last status: {_last_error or 'stopped by user'}. "
                    f"Conversation history is preserved. Do NOT repeat successful tools. "
                    f"Resume with the next logical step of the original task: {_last_input}"
                )
                
                if current_target:
                    prompt_with_context = f"[TARGET: {current_target}] {resume_input}"
                    try:
                        from src.agents.orchestrator_agent import set_current_target
                        set_current_target(current_target)
                    except Exception:
                        pass
                else:
                    prompt_with_context = resume_input
                
                console.print(f"\n[bold green]▶ RESUMING[/bold green] [dim]via {agent.name}[/dim]")
                console.print(f"[dim]Original task: {_last_input[:100]}{'...' if len(_last_input) > 100 else ''}[/dim]")
                print_separator("─", "dim")
                
                start_time = time.time()
                _tool_log.clear()
                
                # Set up callbacks (same as normal execution)
                from src.sdk.runner import Runner
                if _show_thinking:
                    Runner.on_thinking = on_thinking_callback
                else:
                    Runner.on_thinking = None
                
                if _require_confirm:
                    def confirm_tool(agent_name, tool_name, tool_args):
                        args_str = ", ".join(f"{k}={repr(v)[:50]}" for k, v in tool_args.items())
                        console.print("\n[bold yellow]⚠️  CONFIRM TOOL EXECUTION[/bold yellow]")
                        console.print(f"[cyan]Agent:[/cyan] {agent_name}")
                        console.print(f"[cyan]Tool:[/cyan] {tool_name}")
                        console.print(f"[cyan]Args:[/cyan] {args_str}")
                        response = Prompt.ask("[bold]Execute?[/bold]", choices=["y", "n", "all"], default="y")
                        if response == "all":
                            Runner.require_confirmation = False
                            console.print("[dim]Confirmation disabled for remaining tools[/dim]")
                            return True
                        return response.lower() == "y"
                    Runner.on_confirm = confirm_tool
                
                try:
                    result = await run(agent, prompt_with_context)
                    
                    duration = time.time() - start_time
                    tool_calls_total += result.tool_calls_made
                    
                    if current_target:
                        target_manager.log_output(result.output, result.tool_calls_made)
                        try:
                            from src.sdk.memory import get_memory
                            memory = get_memory()
                            memory.store(
                                target=current_target,
                                content=result.output,
                                category="agent_response",
                                metadata={
                                    "agent": agent.name,
                                    "tool_calls": result.tool_calls_made,
                                    "query": f"[RESUMED] {_last_input}"
                                }
                            )
                        except Exception:
                            pass
                    
                    print_separator("─", "dim")
                    display_response(agent.name, result.output, result.tool_calls_made, duration)
                    console.print(f"[dim]📊 Session: {tool_calls_total} total tool calls[/dim]")
                    
                    # Clear saved state on success
                    _last_error = None
                    
                except Exception as e:
                    # Save state again for another continue attempt
                    _last_error = str(e)
                    _can_continue = True
                    display_error(f"Resume failed: {e}")
                    display_info("Type [bold]continue[/bold] to retry again, or [bold]apikey reset[/bold] to reset keys first.")
                
                continue
            
            # ── Clipboard / file image paste ────────────────────────────────
            # Triggers:
            #   !img [optional text]             → grab image from clipboard
            #   !img /path/to/file.png [text]    → load image from file path
            #   paste image [text]               → alias for !img
            _pending_images: list[str] = []
            _lower_input = user_input.lower()

            if _lower_input.startswith("!img") or _lower_input.startswith("paste image"):
                # Parse keyword and tail
                if _lower_input.startswith("!img"):
                    _tail = user_input[4:].strip()
                else:
                    _tail = user_input[11:].strip()

                # --- Check if tail is a file path ----------------------------
                import os as _os
                _file_path = None
                _description = "Analyze this image."
                if _tail:
                    # First token might be a file path
                    _tokens = _tail.split(None, 1)
                    _candidate = _tokens[0]
                    if _os.path.isfile(_candidate):
                        _file_path = _candidate
                        _description = _tokens[1].strip() if len(_tokens) > 1 else "Analyze this image."
                    else:
                        _description = _tail or "Analyze this image."

                if _file_path:
                    # Load image from disk
                    try:
                        import base64 as _b64, mimetypes as _mt
                        _mime = _mt.guess_type(_file_path)[0] or "image/png"
                        with open(_file_path, "rb") as _fh:
                            _img_b64 = _b64.b64encode(_fh.read()).decode()
                        _img_uri = f"data:{_mime};base64,{_img_b64}"
                        _pending_images.append(_img_uri)
                        _kb = len(_img_b64) * 3 // 4 // 1024
                        console.print(f"[bold green]✓ Image loaded from file[/bold green] [dim]{_file_path} ({_kb} KB)[/dim]")
                        user_input = _description
                    except Exception as _e:
                        console.print(f"[bold red]✗ Could not read image file:[/bold red] {_e}")
                        continue
                else:
                    # Grab from clipboard
                    console.print("[dim cyan]📋 Reading image from clipboard...[/dim cyan]")
                    _img_uri = _grab_clipboard_image()
                    if _img_uri:
                        _pending_images.append(_img_uri)
                        _kb = len(_img_uri) * 3 // 4 // 1024
                        console.print(
                            f"[bold green]✓ Image grabbed from clipboard[/bold green] "
                            f"[dim]({_kb} KB)[/dim]"
                        )
                        user_input = _description
                    else:
                        console.print(
                            Panel(
                                "[bold yellow]No image found in clipboard.[/bold yellow]\n\n"
                                "[white]To use clipboard image paste:[/white]\n"
                                "  1. [cyan]Copy an image[/cyan] — screenshot (Print Screen / Snipping Tool),\n"
                                "     or right-click an image → [bold]Copy Image[/bold]\n"
                                "  2. Type [bold green]!img[/bold green] [dim](or [/dim][bold green]paste image[/bold green][dim])[/dim] and press Enter\n\n"
                                "[white]Or paste an image file directly:[/white]\n"
                                "  [bold green]!img /path/to/screenshot.png[/bold green] describe what you see\n\n"
                                "[dim]Linux clipboard note: requires [bold]xclip[/bold] — install with:\n"
                                "  sudo apt install xclip[/dim]",
                                title="[bold red]📋 Clipboard Image[/bold red]",
                                border_style="yellow",
                            )
                        )
                        continue
            # ─────────────────────────────────────────────────────────────────

            # Show execution header
            print_separator()
            console.print(f"[bold white]🔄 PROCESSING[/bold white] [dim]via {agent.name}[/dim]")
            print_separator("─", "dim")

            
            start_time = time.time()
            _tool_log.clear()
            
            # Set up callbacks
            from src.sdk.runner import Runner
            
            # Thinking callback
            if _show_thinking:
                Runner.on_thinking = on_thinking_callback
            else:
                Runner.on_thinking = None
            
            # Human-in-the-loop confirmation callback
            if _require_confirm:
                def confirm_tool(agent_name, tool_name, tool_args):
                    # Format args nicely
                    args_str = ", ".join(f"{k}={repr(v)[:50]}" for k, v in tool_args.items())
                    console.print("\n[bold yellow]⚠️  CONFIRM TOOL EXECUTION[/bold yellow]")
                    console.print(f"[cyan]Agent:[/cyan] {agent_name}")
                    console.print(f"[cyan]Tool:[/cyan] {tool_name}")
                    console.print(f"[cyan]Args:[/cyan] {args_str}")
                    response = Prompt.ask("[bold]Execute?[/bold]", choices=["y", "n", "all"], default="y")
                    if response == "all":
                        # Disable further confirmations for this session
                        Runner.require_confirmation = False
                        console.print("[dim]Confirmation disabled for remaining tools[/dim]")
                        return True
                    return response.lower() == "y"
                Runner.on_confirm = confirm_tool

            # Inject target context into the prompt
            if current_target:
                prompt_with_context = f"[TARGET: {current_target}] {user_input}"
                try:
                    from src.agents.orchestrator_agent import set_current_target
                    set_current_target(current_target)
                except Exception:
                    pass
            else:
                prompt_with_context = user_input
            _in_scan = True
            result = await run(agent, prompt_with_context, images=_pending_images if _pending_images else None)
            _in_scan = False

            duration = time.time() - start_time
            tool_calls_total += result.tool_calls_made

            if current_target:
                target_manager.log_output(result.output, result.tool_calls_made)
                try:
                    from src.sdk.memory import get_memory
                    memory = get_memory()
                    memory.store(
                        target=current_target,
                        content=result.output,
                        category="agent_response",
                        metadata={
                            "agent": agent.name,
                            "tool_calls": result.tool_calls_made,
                            "query": user_input,
                        },
                    )
                except Exception:
                    pass
            # Display response
            print_separator("─", "dim")
            display_response(agent.name, result.output, result.tool_calls_made, duration)
            
            console.print(f"[dim]📊 Session: {tool_calls_total} total tool calls[/dim]")
            
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print()
            if _in_scan:
                # Ctrl+C pressed while scan is running → cancel scan, stay in loop
                Runner.cancel_requested = False
                Runner.cancel_reason = None
                _in_scan = False
                _last_agent = agent
                _last_input = user_input
                _last_target = current_target
                _last_error = "Scan interrupted by user with Ctrl+C"
                _can_continue = True
                stop_tool_status()
                display_info("Type [bold]continue[/bold] to resume the interrupted operation, or enter a new command.")
                continue
                
            # Idle Ctrl+C → exit normally
            if current_target:
                summary = target_manager.end_session()
                print_separator()
                display_session_summary(summary)
            try:
                from src.sdk.async_executor import get_async_executor
                get_async_executor().shutdown(wait=False)
            except Exception: pass
            display_info("Session saved. Goodbye!")
            break
        except EOFError:
            if current_target:
                target_manager.end_session()
            try:
                from src.sdk.async_executor import get_async_executor
                get_async_executor().shutdown(wait=False)
            except Exception: pass
            console.print("\n[dim]Goodbye![/dim]")
            break
        except Exception as e:
            _in_scan = False
            # Save state for continue/resume
            _last_agent = agent
            _last_input = user_input
            _last_target = current_target
            _last_error = str(e)
            _can_continue = True
            
            display_error(str(e))
            display_info("Type [bold]continue[/bold] to resume this operation after the issue is resolved.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
