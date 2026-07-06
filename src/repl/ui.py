"""
Professional REPL UI Components
Rich terminal interface with live status updates

Enhanced with:
- Detailed tool execution info
- Agent thinking visualization
- Parallel processing display
- Failure recovery display
- Real-time summaries
"""

import os
import sys
import socket
import platform
import shutil
import threading
import time
from typing import Dict, List, Optional
from datetime import datetime
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.status import Status
from rich import box
from rich.tree import Tree
from rich.syntax import Syntax

console = Console()

# Live tool status line (single-line spinner with elapsed timer)
_status_handle: Optional[Status] = None
_status_lock = threading.Lock()
_status_tool = ""
_status_phase = ""
_status_detail = ""
_status_started_at = 0.0

_agent_health_cache: Dict[str, tuple[float, dict]] = {}
_AGENT_HEALTH_TTL = 60.0


def _build_status_text() -> Text:
    elapsed = time.time() - _status_started_at if _status_started_at else 0.0
    text = Text()
    if _status_tool:
        text.append(_status_tool, style="bold yellow")
    if _status_phase:
        text.append(f" | {_status_phase}", style="cyan")
    if _status_detail:
        text.append(f" - {_status_detail}", style="dim")
    text.append(f"  {elapsed:.0f}s", style="dim")
    return text


def start_tool_status(tool_name: str, detail: str = "") -> None:
    """Start a live status line for the active tool."""
    global _status_handle, _status_tool, _status_phase, _status_detail, _status_started_at
    with _status_lock:
        _status_tool = tool_name
        _status_phase = ""
        _status_detail = detail
        _status_started_at = time.time()
        if _status_handle:
            try:
                _status_handle.stop()
            except Exception:
                pass
        _status_handle = console.status(_build_status_text(), spinner="dots12")
        _status_handle.start()


def update_tool_status(tool_name: Optional[str] = None, phase: Optional[str] = None, detail: Optional[str] = None) -> None:
    """Update the live status line with new tool/phase/detail information."""
    global _status_tool, _status_phase, _status_detail
    with _status_lock:
        if tool_name is not None:
            _status_tool = tool_name
        if phase is not None:
            _status_phase = phase
        if detail is not None:
            _status_detail = detail
        if _status_handle:
            _status_handle.update(_build_status_text())


def refresh_tool_status() -> None:
    """Refresh the live status line to update the elapsed timer."""
    with _status_lock:
        if _status_handle:
            _status_handle.update(_build_status_text())


def stop_tool_status() -> None:
    """Stop and clear the live status line."""
    global _status_handle, _status_tool, _status_phase, _status_detail, _status_started_at
    with _status_lock:
        if _status_handle:
            try:
                _status_handle.stop()
            except Exception:
                pass
        _status_handle = None
        _status_tool = ""
        _status_phase = ""
        _status_detail = ""
        _status_started_at = 0.0


def _ensure_stdout_blocking() -> None:
    """Reset stdout to blocking mode to prevent BlockingIOError on large outputs (Linux)."""
    try:
        import fcntl
        flags = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
    except Exception:
        pass


# Color scheme
COLORS = {
    "primary": "cyan",
    "secondary": "magenta",
    "success": "green",
    "warning": "yellow",
    "error": "red",
    "muted": "dim white",
    "accent": "bold blue"
}

VERSION = "v1.0.0"

# Logo — red CYBER + yellow COPILOT with ░-textured fill (ansi_shadow font)
_LOGO_LINES = [
    ("bold red",    "  ░██████╗██╗░░░██╗██████╗░███████╗██████╗░"),
    ("bold red",    "  ██╔════╝╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗"),
    ("bold red",    "  ██║░░░░░░╚████╔╝░██████╔╝█████╗░░██████╔╝"),
    ("bold red",    "  ██║░░░░░░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗"),
    ("bold red",    "  ╚██████╗░░░██║░░░██████╔╝███████╗██║░░██║"),
    ("bold red",    "  ░╚═════╝░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝"),
]
_LOGO_LINES2 = [
    ("bold yellow", "  ░██████╗░██████╗░██████╗░██╗██╗░░░░░░██████╗░████████╗"),
    ("bold yellow", "  ██╔════╝██╔═══██╗██╔══██╗██║██║░░░░░██╔═══██╗╚══██╔══╝"),
    ("bold yellow", "  ██║░░░░░██║░░░██║██████╔╝██║██║░░░░░██║░░░██║░░░██║░░░"),
    ("bold yellow", "  ██║░░░░░██║░░░██║██╔═══╝░██║██║░░░░░██║░░░██║░░░██║░░░"),
    ("bold yellow", "  ╚██████╗╚██████╔╝██║░░░░░██║███████╗╚██████╔╝░░░██║░░░"),
    ("bold yellow", "  ░╚═════╝░╚═════╝░╚═╝░░░░░╚═╝╚══════╝░╚═════╝░░░░╚═╝░░░"),
]


def get_system_info() -> dict:
    """Get system information including network interface IPs."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    # Try to get a non-loopback IP (tun0 for VPN, then any active interface)
    vpn_ip = None
    iface_ip = None
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "-4", "addr"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                addr = line.split()[1].split("/")[0]
                if addr.startswith("10.") or addr.startswith("172.") or addr.startswith("192.168."):
                    iface_ip = iface_ip or addr
                if "tun" in result.stdout[max(0, result.stdout.find(addr) - 200):result.stdout.find(addr)]:
                    vpn_ip = addr
    except Exception:
        pass

    api_key_status = "configured"
    try:
        import os as _os
        if not any(
            _os.getenv(env_key)
            for env_key in (
                "OPENROUTER_API_KEY",
                "LONGCAT_API_KEY",
                "NVIDIA_API_KEY",
                "MODELSCOPE_API_KEY",
            )
        ):
            api_key_status = "missing"
    except Exception:
        api_key_status = "unknown"

    return {
        "ip": local_ip,
        "vpn_ip": vpn_ip or iface_ip or local_ip,
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "hostname": platform.node(),
        "user": os.getenv("USER", os.getenv("USERNAME", "unknown")),
        "api_status": api_key_status,
    }


def count_tools() -> int:
    """Count available tools."""
    try:
        from src.tools import __all__ as tools
        return len(tools)
    except Exception:
        return 30


def count_agents() -> int:
    """Count available agents."""
    try:
        from src.agents import __all__ as agents
        return len(agents)
    except Exception:
        return 8


def _get_model_name() -> str:
    """Return the active model short-name, falling back to configured model."""
    # 1. Live model set during an active run
    try:
        from src.sdk.runner import Runner
        m = getattr(Runner, "_current_model", None) or ""
        if m:
            return m.split("/")[-1][:28]
    except Exception:
        pass
    # 2. Configured model from model_settings (whichever provider has an API key)
    try:
        import os as _os
        from src.sdk.key_manager import get_key_manager
        from src.sdk.model_settings import get_model_settings

        km = get_key_manager()
        active_model = km.get_model()
        if active_model:
            return active_model.split("/")[-1][:28]

        settings = get_model_settings()
        for provider, env_key in (
            ("nvidia", "NVIDIA_API_KEY"),
            ("longcat", "LONGCAT_API_KEY"),
            ("openrouter", "OPENROUTER_API_KEY"),
            ("modelscope", "MODELSCOPE_API_KEY"),
        ):
            if _os.getenv(env_key):
                m = settings.get_model(provider)
                if m:
                    return m.split("/")[-1][:28]
    except Exception:
        pass
    return "not set"


def display_banner(show_stats: bool = True):
    """Display the redesigned startup banner."""
    console.clear()

    term_w = shutil.get_terminal_size((120, 40)).columns

    console.print()

    # ── Centered two-part logo ──────────────────────────────────────────────
    for (s1, l1), (s2, l2) in zip(_LOGO_LINES, _LOGO_LINES2):
        combined = l1 + "  " + l2
        pad = max(0, (term_w - len(combined)) // 2)
        console.print(" " * pad + f"[{s1}]{l1}[/{s1}]  [{s2}]{l2}[/{s2}]")

    console.print()

    # ── Divider + tagline ───────────────────────────────────────────────────
    div_width = min(82, term_w - 4)
    dpad = max(0, (term_w - div_width) // 2)
    console.print(" " * dpad + f"[dim red]{'━' * div_width}[/dim red]")

    tagline = f"  AI-Powered Offensive Security Framework By Muhammad Waleed   "
    tpad = max(0, (term_w - len(tagline)) // 2)
    console.print(
        " " * tpad
        + "[dim]  AI-Powered Offensive Security Framework[/dim]"
        + "    "
        + f"[bold yellow]{VERSION}[/bold yellow]  "
        + "\n"
        + " " * max(0, (term_w - len("FYP Project By Muhammad Waleed Supervised by Mr Kaukab Jamal Zuberi")) // 2)
        + "[bold cyan]FYP Project By [/bold cyan]"
        + "[bold green]Muhammad Waleed[/bold green]"
        + "[bold cyan] Supervised by [/bold cyan]"
        + "[bold green]Mr Kaukab Jamal Zuberi[/bold green]"
    )

    console.print(" " * dpad + f"[dim red]{'━' * div_width}[/dim red]")
    console.print()

    if show_stats:
        display_system_stats()


def display_system_stats():
    """Render the modern dashboard shown right after the logo."""
    sys_info = get_system_info()
    tools_n  = count_tools()
    agents_n = count_agents()

    # ── Top stat bar — red/yellow scheme, MODEL replaces OS ─────────────────
    model_name = _get_model_name()

    try:
        sessions_n = len(list((__import__("pathlib").Path("./targets")).glob("*/session_*")))
    except Exception:
        sessions_n = 0

    stat_bar = Table(
        show_header=False,
        box=box.HEAVY_HEAD,
        border_style="dim red",
        padding=(0, 2),
        expand=True,
    )
    for _ in range(7):
        stat_bar.add_column(justify="center")

    stat_bar.add_row(
        f"[bold red]TOOLS[/bold red]\n[bold white]{tools_n}[/bold white]",
        f"[bold yellow]AGENTS[/bold yellow]\n[bold white]{agents_n}[/bold white]",
        f"[bold green]HOST[/bold green]\n[bold white]{sys_info['hostname'][:18]}[/bold white]",
        f"[bold cyan]IP[/bold cyan]\n[bold white]{sys_info['vpn_ip']}[/bold white]",
        f"[bold magenta]MODEL[/bold magenta]\n[bold white]{model_name[:20]}[/bold white]",
        f"[bold white]USER[/bold white]\n[bold white]{sys_info['user'][:14]}[/bold white]",
        f"[bold yellow]SESSIONS[/bold yellow]\n[bold white]{sessions_n}[/bold white]",
    )
    console.print(stat_bar)
    console.print()

    # ── Quick Commands table — red/yellow theme, HEAVY_HEAD box ──────────────
    cmd_rows = [
        ("Target",    "target <ip>",                   "Set target; auto-adds /etc/hosts"),
        ("Agents",    "switch",                         "Pick a specialised single agent"),
        ("Agents",    "ctf <path>",                     "Start a CTF challenge"),
        ("Analysis",  "cockpit",                        "Target status, hypotheses & coverage"),
        ("Analysis",  "preflight",                      "Check agent imports and tool binaries"),
        ("Analysis",  "recovery",                       "Show failure recovery status"),
        ("Analysis",  "context",                        "Show shared agent context"),
        ("Output",    "history [target]",               "Past session history"),
        ("Output",    "export",                         "Generate Markdown / HTML report"),
        ("Tools",     "tools check",                    "Check all installed tools"),
        ("Tools",     "tools install all",              "Install missing recon tools"),
        ("Settings",  "model",                          "Show / select AI model"),
        ("Settings",  "thinking  /  mode",              "Toggle reasoning & auth flags"),
        ("Misc",      "memory <query>",                 "Search past session findings"),
        ("Help",      "help  /  commands",              "Full command reference"),
    ]

    cmd_table = Table(
        title="[bold red]◆ Quick Commands[/bold red]",
        title_justify="left",
        box=box.HEAVY_HEAD,
        border_style="dim red",
        show_header=True,
        header_style="bold yellow",
        padding=(0, 1),
        expand=True,
    )
    cmd_table.add_column("Category",     style="bold cyan",  no_wrap=True, min_width=13, max_width=14)
    cmd_table.add_column("Command",      style="bold white", no_wrap=True, min_width=30, max_width=40)
    cmd_table.add_column("What it does", style="dim",        min_width=30)

    for cat, cmd, desc in cmd_rows:
        cmd_table.add_row(cat, cmd, desc)

    console.print(cmd_table)
    console.print()



def display_quick_guide():
    """Display quick reference guide (called by 'help' command)."""
    guide = Table(
        title="[bold cyan]⌨️  COMMAND REFERENCE[/bold cyan]",
        box=box.MINIMAL_DOUBLE_HEAD,
        border_style="cyan",
        show_header=True,
        header_style="bold dim white",
    )

    guide.add_column("Category",  style="dim cyan",  no_wrap=True, min_width=16)
    guide.add_column("Command",   style="bold white", no_wrap=True, min_width=30)
    guide.add_column("Description", style="dim")

    rows = [
        # Targeting
        ("Target",    "target <ip>",                     "Set target; auto-adds to /etc/hosts"),
        # Agents
        ("Agents",    "switch",                           "Pick a specialised agent"),
        ("Agents",    "ctf <path>",                       "Start a CTF challenge"),
        # Analysis
        ("Analysis",  "preflight",                        "Check agent imports and tool binaries"),
        ("Analysis",  "hypotheses",                       "Show active hypothesis board"),
        ("Analysis",  "coverage",                         "Show pentest coverage checklist"),
        ("Analysis",  "recovery",                         "Show failure recovery status"),
        ("Analysis",  "context",                          "Show shared agent context"),
        # Output
        ("Output",    "history [target]",                 "Past session history"),
        ("Output",    "logs",                             "Show session log paths"),
        ("Output",    "export",                           "Generate Markdown/HTML report"),
        # Tools
        ("Tools",     "tools check",                      "Check all installed tools"),
        ("Tools",     "tools install all",                "Install missing recon tools"),
        # Settings
        ("Settings",  "model",                            "Show / select AI model"),
        ("Settings",  "thinking",                         "Toggle agent reasoning display"),
        ("Settings",  "mode",                             "Toggle bug bounty auth mode"),
        ("Settings",  "confirm",                          "Toggle tool confirmation"),
        ("Settings",  "detailed",                         "Toggle detailed tool output"),
        ("Settings",  "api",                              "Show API key status"),
        # Misc
        ("Misc",      "scope [target]",                   "Manage scope list"),
        ("Misc",      "memory <query>",                   "Search past session findings"),
        ("Misc",      "clear",                            "Reset agent memory"),
        ("Misc",      "continue / resume",                "Resume last interrupted op"),
        ("Misc",      "quit / exit",                      "Exit the framework"),
    ]

    for cat, cmd, desc in rows:
        guide.add_row(cat, cmd, desc)

    console.print(guide)
    console.print()


def display_agents_table(agents: dict, current: str = None):
    """Display agents in a professional table."""
    table = Table(title="[bold cyan]🤖 AVAILABLE AGENTS[/bold cyan]",
                  box=box.DOUBLE_EDGE,
                  border_style="cyan",
                  show_header=True,
                  header_style="bold white")
    
    table.add_column("#", style="bold cyan", width=3, justify="center")
    table.add_column("Agent", style="bold green", width=15)
    table.add_column("Description", style="white")
    table.add_column("Status", width=10, justify="center")
    
    for key, (name, _, desc) in agents.items():
        status = "[green]● ACTIVE[/green]" if name == current else "[dim]○[/dim]"
        table.add_row(key, name, desc, status)
    
    console.print(table)
    console.print()


def display_tool_execution(tool_name: str, args: dict):
    """Display tool execution with live status."""
    args_str = ", ".join(f"{k}={repr(v)[:30]}" for k, v in args.items())
    
    panel = Panel(
        f"[bold yellow]⚡ {tool_name}[/bold yellow]({args_str})",
        title="[bold white]EXECUTING TOOL[/bold white]",
        border_style="yellow",
        box=box.HEAVY
    )
    console.print(panel)


def display_command(agent_name: str, tool_name: str, command_str: str):
    """Display the exact command being executed by the AI."""
    console.print(f"  [bold cyan]▶[/bold cyan] [yellow]{command_str}[/yellow]")


def display_progress_summary(agent_name: str, iteration: int, max_iterations: int, 
                             tools_run: list, findings: list, next_action: str = None):
    """
    Display meaningful progress update showing what was found and what's next.
    Now enhanced with tool success/failure stats and a cleaner planning summary.
    """
    from rich.panel import Panel
    
    # Build progress bar
    progress_pct = (iteration / max_iterations) * 100
    bar_width = 30
    filled = int(bar_width * progress_pct / 100)
    bar = f"[green]{'█' * filled}[/green][dim]{'░' * (bar_width - filled)}[/dim]"
    
    # Build content
    content_lines = []
    
    # 1. Progress Header
    content_lines.append(f"{bar} [bold white]{progress_pct:.0f}%[/bold white] │ Iteration {iteration}/{max_iterations}")
    
    # 2. Activity Summary (Success/Failure)
    if tools_run:
        names = []
        successes = 0
        failures = 0
        for t in tools_run:
            if isinstance(t, tuple):
                name, success = t
                if success: successes += 1
                else: failures += 1
                names.append(name)
            else:
                names.append(str(t))
                successes += 1 # Assume success for strings
        
        unique_names = list(dict.fromkeys(names[-10:]))
        content_lines.append(f"\n[dim]Executed Tools:[/dim] {', '.join(unique_names)}")
        content_lines.append(f"\n[bold white]Activity Summary:[/bold white] [green]✓ {successes}[/green]  [red]✗ {failures}[/red]")
        
        # Show recent tools with icons
        recent_tools = []
        for t in tools_run[-6:]:
            if isinstance(t, tuple):
                icon = "[green]✓[/green]" if t[1] else "[red]✗[/red]"
                recent_tools.append(f"{icon} {t[0]}")
            else:
                recent_tools.append(f"[green]✓[/green] {t}")
        content_lines.append(f"  [dim]Recent:[/dim] {' '.join(recent_tools)}")
    
    # 3. Discoveries section
    if findings:
        content_lines.append("\n[bold green]🎯 Key Discoveries:[/bold green]")
        # Dedup and show last 5
        unique_findings = list(dict.fromkeys(findings))[-5:]
        for finding in unique_findings:
            content_lines.append(f"  [green]•[/green] {finding}")
    
    # 4. Planning / Next Steps
    if next_action:
        # If next_action looks like a full thought, try to summarize or just format it clearly
        next_clean = next_action.strip()
        
        # Heuristic: if it's the SAME as a thought block, make it look distinct
        content_lines.append("\n[bold yellow]📋 Strategic Plan / Next Steps:[/bold yellow]")
        
        # Format the plan lines nicely
        plan_lines = [l.strip() for l in next_clean.splitlines() if l.strip()]
        for line in plan_lines[:8]:  # Show up to 8 lines
            # Strip common "Action:" or "Reasoning:" prefixes if they exist in the summary
            display_line = line
            if display_line.lower().startswith("action:"): display_line = display_line[7:].strip()
            
            if display_line:
                content_lines.append(f"  [yellow]➜ {display_line}[/yellow]")
        
        if len(plan_lines) > 8:
            content_lines.append(f"  [dim italic]... ({len(plan_lines)-8} more lines in full thought)[/dim italic]")
    
    # Display as panel
    panel = Panel(
        "\n".join(content_lines),
        title=f"[bold cyan]📊 {agent_name} PROGRESS CHECK[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2)
    )
    console.print()
    console.print(panel)
    console.print()


def display_supervisor_check(agent_name: str, iteration: int, assessment: dict):
    """
    Display the supervisor feedback loop result in the CLI.

    Shows a gold/amber panel with:
    - Status badge (ON TRACK / AT RISK / STUCK)
    - Efficiency bar
    - Key findings list
    - Assessment paragraph
    - Concrete recommendation
    - Any risk flags
    """
    status = assessment.get("status", "unknown").lower()
    efficiency = assessment.get("efficiency_pct", 0)
    key_findings = assessment.get("key_findings", [])
    assessment_text = assessment.get("assessment", "")
    recommendation = assessment.get("recommendation", "")
    risk_flags = assessment.get("risk_flags", [])
    findings_count = assessment.get("findings_count", 0)

    # Fallback so the panel never shows completely empty content
    if not assessment_text:
        _it = assessment.get("iteration", iteration)
        _dec = assessment.get("decision", "")
        assessment_text = (
            f"Supervisor evaluated iteration {_it}. "
            + (f"Decision: {_dec}." if _dec else "No detailed assessment available.")
        )
    if not recommendation:
        recommendation = assessment.get("decision_reason") or "Vary your approach — avoid repeating the same tool call with identical parameters."

    # Status colour + icon
    STATUS_STYLES = {
        "on_track": ("[bold green]", "✅ ON TRACK"),
        "at_risk":  ("[bold yellow]", "⚠️  AT RISK"),
        "stuck":    ("[bold red]",    "🛑 STUCK"),
        "unknown":  ("[bold dim]",    "❓ UNKNOWN"),
    }
    style, label = STATUS_STYLES.get(status, ("[bold dim]", f"❓ {status.upper()}"))

    # Efficiency bar
    bar_width = 20
    filled = max(0, min(bar_width, int(bar_width * efficiency / 100)))
    if efficiency >= 70:
        bar_color, num_color = "green", "bold green"
    elif efficiency >= 40:
        bar_color, num_color = "yellow", "bold yellow"
    else:
        bar_color, num_color = "red", "bold red"
    eff_bar = (
        f"[{bar_color}]{'█' * filled}[/{bar_color}]"
        f"[dim]{'░' * (bar_width - filled)}[/dim]"
        f" [{num_color}]{efficiency}%[/{num_color}]"
    )

    lines: list[str] = []

    # Header row: status + efficiency + iteration
    lines.append(
        f"{style}{label}[/]  │  Efficiency: {eff_bar}"
        f"  │  Iter {iteration}  │  Findings: [white]{findings_count}[/white]"
    )
    lines.append("")

    # Key findings
    if key_findings:
        lines.append("[bold white]Key Findings:[/bold white]")
        for f in key_findings[:6]:
            lines.append(f"  [green]•[/green] {f}")
        lines.append("")

    # Assessment
    if assessment_text:
        lines.append("[bold white]Assessment:[/bold white]")
        for sentence in assessment_text.split(". "):
            sentence = sentence.strip()
            if sentence:
                lines.append(f"  [white]{sentence}{'.' if not sentence.endswith('.') else ''}[/white]")
        lines.append("")

    # Recommendation
    if recommendation:
        lines.append(f"[bold yellow]▶ Recommendation:[/bold yellow] [yellow]{recommendation}[/yellow]")

    # Risk flags
    if risk_flags:
        lines.append("")
        lines.append("[bold red]Risk Flags:[/bold red]")
        for flag in risk_flags[:4]:
            lines.append(f"  [red]⚑[/red] {flag}")

    border = "green" if status == "on_track" else ("yellow" if status == "at_risk" else "red")
    panel = Panel(
        "\n".join(lines),
        title=f"[bold white on dark_orange] 🔍 SUPERVISOR CHECK — {agent_name} [/bold white on dark_orange]",
        border_style=border,
        box=box.DOUBLE_EDGE,
        padding=(0, 1),
    )
    console.print()
    console.print(panel)
    console.print()


def display_tool_result(tool_name: str, success: bool, duration: float = 0):
    """Display tool completion status."""
    if success:
        status = f"[bold green]✓ {tool_name} completed[/bold green] [dim]({duration:.2f}s)[/dim]"
    else:
        status = f"[bold red]✗ {tool_name} failed[/bold red]"
    
    console.print(f"  {status}")


def display_agent_health_preflight(agents: Optional[dict] = None, model: str = None, compact: bool = False) -> dict:
    """Display agent construction health and key binary availability."""
    agent_rows = _collect_agent_health(agents, model=model)
    binary_rows = _collect_binary_health()

    healthy_agents = sum(1 for row in agent_rows if row["ok"])
    healthy_bins = sum(1 for row in binary_rows if row["ok"])
    failed_agents = [row for row in agent_rows if not row["ok"]]
    missing_bins = [row["name"] for row in binary_rows if not row["ok"]]

    if compact:
        border = "green" if not failed_agents else "red"
        summary = (
            f"[bold]Agents[/bold] {healthy_agents}/{len(agent_rows)} ready"
            f"  |  [bold]Binaries[/bold] {healthy_bins}/{len(binary_rows)} found"
        )
        if failed_agents:
            summary += f"\n[red]Agent blocker:[/red] {failed_agents[0]['name']} - {failed_agents[0]['issue'][:100]}"
        if missing_bins:
            summary += f"\n[yellow]Missing tools:[/yellow] {', '.join(missing_bins[:8])}"
        console.print(Panel(summary, title="[bold]Preflight[/bold]", border_style=border, box=box.ROUNDED))
        return _health_summary(agent_rows, binary_rows)

    agent_table = Table(
        title="[bold cyan]Agent Health Preflight[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    agent_table.add_column("Agent", style="bold white", no_wrap=True)
    agent_table.add_column("Status", width=10, justify="center")
    agent_table.add_column("Tools", width=7, justify="right")
    agent_table.add_column("Issue", style="dim")
    for row in agent_rows:
        status = "[green]READY[/green]" if row["ok"] else "[red]FAILED[/red]"
        agent_table.add_row(row["name"], status, str(row.get("tool_count", "-")), row.get("issue", ""))

    bin_table = Table(
        title="[bold cyan]Toolchain Preflight[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    bin_table.add_column("Binary", style="bold white")
    bin_table.add_column("Status", width=10, justify="center")
    bin_table.add_column("Path", style="dim")
    for row in binary_rows:
        status = "[green]FOUND[/green]" if row["ok"] else ("[red]MISSING[/red]" if row["required"] else "[yellow]OPTIONAL[/yellow]")
        bin_table.add_row(row["name"], status, row.get("path", ""))

    console.print(Group(agent_table, bin_table))
    return _health_summary(agent_rows, binary_rows)


def display_hypothesis_board(target: str, limit: int = 5, compact: bool = False):
    """Display ranked hypotheses from the target profile."""
    profile = _safe_load_profile(target)
    if not profile:
        console.print(Panel("[dim]No target profile loaded.[/dim]", title="[bold]Hypotheses[/bold]", border_style="yellow"))
        return

    mode = getattr(profile, "engagement_mode", "pentest") or "pentest"
    hypotheses = list(getattr(profile, "hypotheses", []) or [])
    active_rows = [h for h in hypotheses if h.get("status", "candidate") not in {"confirmed", "rejected"}]
    rows = active_rows or hypotheses

    table = Table(
        title=f"[bold magenta]Hypothesis Board[/bold magenta] [dim]mode={mode}[/dim]",
        box=box.ROUNDED,
        border_style="magenta",
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    table.add_column("#", width=3, justify="right", style="dim")
    table.add_column("Hypothesis", style="white")
    table.add_column("Status", width=12)
    table.add_column("Score", width=7, justify="right")
    table.add_column("Next Tool", style="cyan")

    if not rows:
        table.add_row("-", "No hypotheses generated yet", "[yellow]PENDING[/yellow]", "-", "generate_hypotheses")
    else:
        for idx, item in enumerate(rows[:limit], 1):
            status = item.get("status", "candidate")
            style = _status_style(status)
            tools = item.get("next_tools", []) or []
            table.add_row(
                str(idx),
                item.get("name", "Unnamed hypothesis"),
                f"[{style}]{status.upper()}[/{style}]",
                str(item.get("score", "-")),
                tools[0] if tools else "-",
            )

    console.print(table)
    if not compact:
        console.print("[dim]Commands: hypotheses | coverage | preflight[/dim]")


def display_coverage_checklist(target: str, compact: bool = False):
    """Display the target's engagement coverage checklist."""
    profile = _safe_load_profile(target)
    if not profile:
        console.print(Panel("[dim]No target profile loaded.[/dim]", title="[bold]Coverage[/bold]", border_style="yellow"))
        return

    mode = getattr(profile, "engagement_mode", "pentest") or "pentest"
    requirements = list(getattr(profile, "coverage_requirements", []) or [])
    if not requirements:
        try:
            from src.sdk.hypothesis_engine import get_policy

            requirements = [{"requirement": item, "status": "pending"} for item in get_policy(mode).coverage_requirements]
        except Exception:
            requirements = []

    total = len(requirements)
    done = sum(1 for item in requirements if item.get("status") == "done")
    pending = [item.get("requirement", "") for item in requirements if item.get("status", "pending") != "done"]
    border = "green" if total and done == total else "yellow"

    if compact:
        text = f"[bold]Coverage[/bold] {done}/{total} complete  |  mode={mode}"
        if pending:
            text += f"\n[dim]Next:[/dim] {pending[0][:120]}"
        console.print(Panel(text, title="[bold]Coverage[/bold]", border_style=border, box=box.ROUNDED))
        return

    table = Table(
        title=f"[bold yellow]Coverage Checklist[/bold yellow] [dim]mode={mode}[/dim]",
        box=box.ROUNDED,
        border_style=border,
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    table.add_column("#", width=3, justify="right", style="dim")
    table.add_column("Status", width=10)
    table.add_column("Requirement", style="white")
    if not requirements:
        table.add_row("-", "[dim]N/A[/dim]", "No mandatory coverage configured for this mode.")
    else:
        for idx, item in enumerate(requirements, 1):
            status = item.get("status", "pending")
            style = "green" if status == "done" else "yellow" if status == "pending" else "cyan"
            table.add_row(str(idx), f"[{style}]{status.upper()}[/{style}]", item.get("requirement", ""))
    console.print(table)


def display_engagement_cockpit(target: str, session_dir: str = None, agents: Optional[dict] = None, model: str = None, compact: bool = False):
    """Display the clean session-start cockpit."""
    display_target_status(target, session_dir)


def _safe_load_profile(target: str):
    if not target:
        return None
    try:
        from src.repl.profiles import get_profile_manager

        return get_profile_manager().load_profile(target)
    except Exception:
        return None


def _status_style(status: str) -> str:
    value = (status or "").lower()
    if value in {"confirmed", "done", "success"}:
        return "green"
    if value in {"rejected", "failed"}:
        return "red"
    if value in {"blocked", "inconclusive"}:
        return "yellow"
    return "cyan"


def _collect_agent_health(agents: Optional[dict] = None, model: str = None) -> List[dict]:
    if agents is None:
        try:
            from src.agents import (
                create_orchestrator_agent,
                create_recon_agent,
                create_websec_agent,
                create_ctf_agent,
                create_dfir_agent,
                create_redteam_agent,
                create_blackhat_agent,
                create_reporter_agent,
                create_appsec_agent,
                create_bugbounty_agent,
            )

            agents = {
                "0": ("Orchestrator", create_orchestrator_agent, ""),
                "1": ("ReconAgent", create_recon_agent, ""),
                "2": ("WebSecAgent", create_websec_agent, ""),
                "3": ("CTFAgent", create_ctf_agent, ""),
                "4": ("DFIRAgent", create_dfir_agent, ""),
                "5": ("RedTeamAgent", create_redteam_agent, ""),
                "6": ("BlackHat", create_blackhat_agent, ""),
                "7": ("Reporter", create_reporter_agent, ""),
                "8": ("AppSecAgent", create_appsec_agent, ""),
                "9": ("BugBountyAgent", create_bugbounty_agent, ""),
            }
        except Exception as exc:
            return [{"name": "agent registry", "ok": False, "tool_count": 0, "issue": str(exc)}]

    rows: List[dict] = []
    now = time.time()
    for _, entry in sorted(agents.items(), key=lambda kv: str(kv[0])):
        name, factory = entry[0], entry[1]
        cache_key = f"{name}:{model or ''}"
        cached = _agent_health_cache.get(cache_key)
        if cached and now - cached[0] < _AGENT_HEALTH_TTL:
            rows.append(dict(cached[1]))
            continue
        try:
            try:
                agent = factory(model=model) if model else factory()
            except TypeError as exc:
                if "model" not in str(exc):
                    raise
                agent = factory()
            row = {
                "name": getattr(agent, "name", name),
                "ok": True,
                "tool_count": len(getattr(agent, "tools", []) or []),
                "issue": "",
            }
        except Exception as exc:
            row = {"name": name, "ok": False, "tool_count": 0, "issue": str(exc)}
        _agent_health_cache[cache_key] = (now, row)
        rows.append(dict(row))
    return rows


def _collect_binary_health() -> List[dict]:
    checks = [
        ("nmap", True),
        ("curl", True),
        ("python", True),
        ("ffuf", False),
        ("feroxbuster", False),
        ("gobuster", False),
        ("nuclei", False),
        ("wpscan", False),
        ("whatweb", False),
    ]
    rows = []
    for name, required in checks:
        path = shutil.which(name)
        rows.append({"name": name, "required": required, "ok": bool(path), "path": path or ""})
    return rows


def _health_summary(agent_rows: List[dict], binary_rows: List[dict]) -> dict:
    return {
        "agents_ok": sum(1 for row in agent_rows if row["ok"]),
        "agents_total": len(agent_rows),
        "binaries_ok": sum(1 for row in binary_rows if row["ok"]),
        "binaries_total": len(binary_rows),
        "agent_failures": [row for row in agent_rows if not row["ok"]],
        "missing_binaries": [row for row in binary_rows if not row["ok"]],
    }


def display_thinking():
    """Display thinking indicator."""
    return Progress(
        SpinnerColumn(spinner_name="dots12", style="cyan"),
        TextColumn("[bold cyan]Processing...[/bold cyan]"),
        transient=True
    )


def display_response(agent_name: str, response: str, tool_calls: int, duration: float = 0):
    """Display agent response in a professional panel."""
    _ensure_stdout_blocking()
    # Header with stats
    header = f"[bold green]{agent_name}[/bold green]  │  " \
             f"[cyan]🔧 {tool_calls} tools[/cyan]  │  " \
             f"[yellow]⏱️  {duration:.1f}s[/yellow]"

    from rich.markdown import Markdown
    # Use native Markdown rendering instead of dumping plain text
    formatted_response = Markdown(response) if response.strip() else response

    panel = Panel(
        formatted_response,
        title=header,
        title_align="left",
        border_style="green",
        box=box.DOUBLE,
        padding=(1, 2)
    )
    try:
        console.print(panel)
        console.print()
    except BlockingIOError:
        # stdout buffer was full; reset to blocking and retry, then fall back to plain text
        _ensure_stdout_blocking()
        try:
            console.print(panel)
            console.print()
        except BlockingIOError:
            print(f"\n[{agent_name}] ({tool_calls} tools, {duration:.1f}s)\n{response}\n", flush=True)


def display_target_status(target: str, session_dir: str = None):
    """Display current target status bar."""
    parts = [
        f"[bold yellow]🎯 TARGET:[/bold yellow] [white]{target}[/white]"
    ]
    
    if session_dir:
        parts.append(f"[dim]📁 {session_dir}[/dim]")
    
    parts.append(f"[dim]⏰ {datetime.now().strftime('%H:%M:%S')}[/dim]")
    
    status_bar = " │ ".join(parts)
    console.print(Panel(status_bar, box=box.SIMPLE, style="on grey23"))


def display_target_status(target: str, session_dir: str = None):
    """Display a compact current target status bar."""
    profile = _safe_load_profile(target)
    mode = getattr(profile, "engagement_mode", "pentest") if profile else "pentest"

    parts = [
        f"[bold yellow]TARGET:[/bold yellow] [white]{target}[/white]",
        f"[bold cyan]MODE:[/bold cyan] [white]{mode}[/white]",
    ]
    if session_dir:
        parts.append(f"[dim]{session_dir}[/dim]")
    parts.append(f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim]")

    console.print(Panel(" | ".join(parts), box=box.SIMPLE, style="on grey23"))


def display_session_summary(summary: dict):
    """Display session summary on exit."""
    table = Table(title="[bold cyan]📊 SESSION SUMMARY[/bold cyan]",
                  box=box.DOUBLE_EDGE, border_style="cyan")
    
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Target", str(summary.get("target", "N/A")))
    table.add_row("Duration", f"{summary.get('duration_seconds', 0):.1f} seconds")
    table.add_row("User Inputs", str(summary.get("total_inputs", 0)))
    table.add_row("Agent Outputs", str(summary.get("total_outputs", 0)))
    table.add_row("Tool Calls", str(summary.get("total_tool_calls", 0)))
    table.add_row("Log Location", str(summary.get("session_dir", "N/A")))
    
    console.print(table)


def display_error(message: str):
    """Display error message."""
    _ensure_stdout_blocking()
    try:
        console.print(Panel(
            f"[bold red]ERROR:[/bold red] {message}",
            border_style="red",
            box=box.HEAVY
        ))
    except BlockingIOError:
        print(f"\nERROR: {message}\n", file=sys.stderr, flush=True)


def display_success(message: str):
    """Display success message."""
    console.print(f"[bold green]✓[/bold green] {message}")


def display_warning(message: str):
    """Display warning message."""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")


def display_info(message: str):
    """Display info message."""
    console.print(f"[bold cyan]ℹ[/bold cyan] {message}")


def send_desktop_notification(title: str, message: str):
    """Send an OS-level desktop notification and terminal bell."""
    import platform
    import subprocess
    import os

    def _notify():
        try:
            if platform.system() == "Windows":
                # PowerShell Native Windows Toast
                ps_script = f'''
[xml]$toast = @"
<toast>
  <visual>
    <binding template="ToastText02">
      <text id="1">{title}</text>
      <text id="2">{message}</text>
    </binding>
  </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($toast.OuterXml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Cyber-CoPilot").Show($xml)
'''
                subprocess.run(["powershell", "-WindowStyle", "Hidden", "-Command", ps_script], creationflags=0x08000000)
            elif platform.system() == "Darwin":
                os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
            else:
                os.system(f'notify-send "{title}" "{message}"')
        except Exception:
            pass

    # Terminal Bell
    print('\a', end='', flush=True)
    # Background thread to prevent locking REPL
    threading.Thread(target=_notify, daemon=True).start()


_current_breadcrumb = ""

def set_breadcrumb(path: str):
    """Set the dynamic breadcrumb trail (e.g., active endpoint)."""
    global _current_breadcrumb
    _current_breadcrumb = path

def get_prompt(target: str = None, agent_name: str = "CoPilot") -> str:
    """Get the input prompt string."""
    breadcrumb_line = f"\n[dim yellow]⛓️  Trail: {target} ➔ {_current_breadcrumb}[/dim yellow]" if _current_breadcrumb and target else ""
    if target:
        return f"{breadcrumb_line}\n[bold magenta]🤖 {agent_name}[/bold magenta] [bold yellow]🎯 {target}[/bold yellow] [bold cyan]❯[/bold cyan] "
    return f"\n[bold magenta]🤖 {agent_name}[/bold magenta] [bold cyan]❯[/bold cyan] "


def print_separator(char: str = "─", style: str = "dim cyan"):
    """Print a separator line."""
    width = shutil.get_terminal_size().columns
    console.print(f"[{style}]{char * width}[/{style}]")


# ============================================================================
# ENHANCED TOOL EXECUTION DISPLAY
# ============================================================================

def display_tool_detailed(
    tool_name: str,
    args: Dict,
    command_str: str = "",
    description: str = "",
    expected_duration: str = "",
    phase: str = ""
):
    """
    Display detailed information about a tool being executed.

    Shows:
    - Tool name and purpose
    - Full command being run
    - Arguments with explanations
    - Expected duration
    - Current phase in the attack chain
    """
    content = Table.grid(expand=True)
    content.add_column()
    content.add_column(ratio=3)

    # Tool name with icon
    tool_icons = {
        "nmap": "🔍",
        "subfinder": "🌐",
        "sublist3r": "🌐",
        "ffuf": "📂",
        "feroxbuster": "📂",
        "nuclei": "⚡",
        "sqlmap": "💉",
        "katana": "🕷️",
        "gau": "📜",
        "httpx": "🌍",
        "default": "🔧"
    }

    icon = tool_icons.get(tool_name.split('_')[0], tool_icons["default"])

    content.add_row("[bold]Tool:[/bold]", f"[bold yellow]{icon} {tool_name}[/bold yellow]")

    if description:
        content.add_row("[dim]Purpose:[/dim]", f"[white]{description[:80]}[/white]")

    if phase:
        content.add_row("[dim]Phase:[/dim]", f"[cyan]{phase}[/cyan]")

    content.add_row("", "")  # Spacer

    # Command - SHOW FULL COMMAND (do not truncate; callers may need full payloads)
    if command_str:
        content.add_row("[bold]Command:[/bold]", "")
        content.add_row("", Syntax(command_str, "bash", theme="monokai", word_wrap=True, background_color="default"))

    # Arguments - SHOW TRUNCATED CONTEXT (150 chars)
    if args:
        content.add_row("", "")
        content.add_row("[bold]Arguments:[/bold]", "")
        import json
        for key, value in args.items():
            if isinstance(value, (dict, list)):
                val_str = json.dumps(value, indent=2)
                content.add_row(f"  [cyan]{key}:[/cyan]", Syntax(val_str, "json", theme="monokai", background_color="default"))
            else:
                val_str = str(value)
                content.add_row(f"  [cyan]{key}:[/cyan]", f"[white]{val_str}[/white]")

    if expected_duration:
        content.add_row("", "")
        content.add_row("[dim]Est. Duration:[/dim]", f"[yellow]{expected_duration}[/yellow]")

    panel = Panel(
        content,
        title="[bold white on blue] ⚡ EXECUTING TOOL [/bold white on blue]",
        border_style="blue",
        box=box.HEAVY
    )
    console.print(panel)


def display_thinking_compact(
    agent_name: str,
    thought: str,
    context_usage_pct: int | None = None,
):
    """Single-line collapsed thinking indicator. Expand with 'thinking +'."""
    import re as _re
    clean = _re.sub(r"<tool_call>.*?</(?:tool_call|function)>", "", thought, flags=_re.DOTALL).strip()
    clean = _re.sub(r"</?(?:tool_call|function|parameter)[^>]*>", "", clean).strip()

    first_line = next((l.strip() for l in clean.splitlines() if l.strip()), "")
    if len(first_line) > 100:
        first_line = first_line[:97] + "…"

    total_lines = len([l for l in clean.splitlines() if l.strip()])
    ctx = f" [dim]| ctx {int(context_usage_pct):02d}%[/dim]" if context_usage_pct is not None else ""
    more = f" [dim]+{total_lines - 1} lines[/dim]" if total_lines > 1 else ""

    console.print(
        f"  [dim cyan]🧠 {agent_name}[/dim cyan]{ctx}  [dim]{first_line}[/dim]{more}"
        "  [dim italic][bold]+[/bold] expand[/dim italic]"
    )


def display_thinking_detailed(
    agent_name: str,
    thought: str,
    action: str = "",
    reasoning: str = "",
    plan: List[str] = None,
    iteration: int = 0,
    context_usage_pct: int | None = None,
):
    """
    Display detailed agent thinking process.
    
    Shows:
    - Current thought/analysis
    - Planned action
    - Reasoning behind decisions
    - Next steps in plan
    """
    import re as _re
    # Strip raw <tool_call>...</tool_call> blocks the model sometimes leaks into thinking
    thought = _re.sub(r"<tool_call>.*?</(?:tool_call|function)>", "", thought, flags=_re.DOTALL).strip()
    # Also strip any trailing lone XML-like tags
    thought = _re.sub(r"</?(?:tool_call|function|parameter)[^>]*>", "", thought).strip()

    content = []

    # Current thought - SHOW FULL CONTENT with proper line wrapping
    thought_text = Text()
    context_label = f" | Context {int(context_usage_pct):02d}%" if context_usage_pct is not None else ""
    thought_text.append(f"💭 Current Analysis:{context_label}\n", style="bold cyan")
    thought_lines = thought.split('\n')
    for line in thought_lines:
        thought_text.append(f"   {line}\n", style="white")
    content.append(thought_text)
    
    if reasoning:
        reason_text = Text()
        reason_text.append("\n🧠 Reasoning:\n", style="bold yellow")
        # Show full reasoning with line breaks preserved
        reasoning_lines = reasoning.split('\n')
        for line in reasoning_lines[:20]:  # Limit to 20 lines to avoid overwhelming output
            reason_text.append(f"   {line}\n", style="dim white")
        if len(reasoning_lines) > 20:
            reason_text.append(f"   ... ({len(reasoning_lines) - 20} more lines)\n", style="dim italic")
        content.append(reason_text)
    
    if action:
        action_text = Text()
        action_text.append("\n⚡ Next Action:\n", style="bold green")
        action_text.append(f"   {action[:100]}", style="white")
        content.append(action_text)
    
    if plan:
        plan_text = Text()
        plan_text.append("\n📋 Execution Plan:\n", style="bold magenta")
        for i, step in enumerate(plan[:5], 1):
            plan_text.append(f"   {i}. {step[:60]}\n", style="dim white")
        content.append(plan_text)
    
    panel = Panel(
        Group(*content),
        title=f"[bold cyan]🧠 {agent_name} THINKING[/bold cyan]"
              + (f" [dim]#{iteration}[/dim]" if iteration else "")
              + "  [dim italic][bold]-[/bold] collapse[/dim italic]",
        border_style="cyan",
        box=box.ROUNDED
    )
    console.print(panel)


def display_parallel_status(
    tasks: Dict[str, Dict],
    total_progress: int = 0
):
    """
    Display status of parallel agent execution.
    
    Args:
        tasks: Dict of task_id -> {agent_name, status, progress, tools_run, findings}
        total_progress: Overall progress percentage
    """
    # Overall progress bar
    Progress(
        TextColumn("[bold cyan]Overall Progress[/bold cyan]"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
        transient=True
    )
    
    table = Table(box=box.ROUNDED, border_style="magenta", expand=True)
    table.add_column("Agent", style="cyan", width=18)
    table.add_column("Status", width=12)
    table.add_column("Progress", width=25)
    table.add_column("Tools", width=6, justify="center")
    table.add_column("Findings", width=8, justify="center")
    
    status_styles = {
        "running": "[bold yellow]● Running[/bold yellow]",
        "completed": "[bold green]✓ Done[/bold green]",
        "failed": "[bold red]✗ Failed[/bold red]",
        "queued": "[dim]◯ Queued[/dim]",
        "retrying": "[orange1]↻ Retry[/orange1]"
    }
    
    for task_id, task in tasks.items():
        agent_name = task.get("agent_name", task_id)
        status = status_styles.get(task.get("status", "queued"), task.get("status", ""))
        progress = task.get("progress", 0)
        tools = task.get("tools_run", 0)
        findings = task.get("findings", 0)
        
        # Progress bar
        filled = progress // 5
        bar = f"[green]{'█' * filled}[/green][dim]{'░' * (20 - filled)}[/dim] {progress}%"
        
        # Highlight findings
        findings_str = f"[bold green]{findings}[/bold green]" if findings > 0 else str(findings)
        
        table.add_row(agent_name, status, bar, str(tools), findings_str)
    
    # Overall progress bar
    overall_filled = total_progress // 5
    overall_bar = f"[bold cyan]{'█' * overall_filled}[/bold cyan][dim]{'░' * (20 - overall_filled)}[/dim] {total_progress}%"
    
    content = Table.grid(expand=True)
    content.add_row(f"[bold]Total Progress:[/bold] {overall_bar}")
    content.add_row("")
    content.add_row(table)
    
    panel = Panel(
        content,
        title="[bold magenta]🔀 PARALLEL EXECUTION STATUS[/bold magenta]",
        border_style="magenta",
        box=box.HEAVY
    )
    console.print(panel)


def display_failure_recovery(
    tool_name: str,
    error: str,
    strategies: List[Dict],
    selected_strategy: Dict = None
):
    """
    Display failure and recovery strategies.
    
    Args:
        tool_name: The failed tool
        error: Error message
        strategies: List of recovery strategy dicts
        selected_strategy: The chosen strategy
    """
    content = []
    
    # Error info
    error_text = Text()
    error_text.append(f"❌ {tool_name} failed\n", style="bold red")
    error_text.append(f"   Error: {error[:100]}\n", style="dim red")
    content.append(error_text)
    
    # Recovery strategies
    if strategies:
        strategies_text = Text()
        strategies_text.append("\n🔄 Recovery Strategies:\n", style="bold yellow")
        
        for i, strategy in enumerate(strategies[:4], 1):
            confidence = strategy.get("confidence", 0) * 100
            desc = strategy.get("description", "Unknown strategy")
            
            if selected_strategy and strategy == selected_strategy:
                strategies_text.append(f"   [{i}] [bold green]→ {desc}[/bold green] [dim]({confidence:.0f}% confidence)[/dim]\n")
            else:
                strategies_text.append(f"   [{i}] {desc} [dim]({confidence:.0f}% confidence)[/dim]\n")
        
        content.append(strategies_text)
    
    if selected_strategy:
        action_text = Text()
        action_text.append("\n⚡ Taking Action: ", style="bold cyan")
        action_text.append(selected_strategy.get("description", ""), style="white")
        content.append(action_text)
    
    panel = Panel(
        Group(*content),
        title="[bold red]⚠️ FAILURE RECOVERY[/bold red]",
        border_style="red",
        box=box.ROUNDED
    )
    console.print(panel)


def display_findings_summary(
    findings: List[Dict],
    by_severity: Dict[str, int] = None,
    by_type: Dict[str, int] = None
):
    """
    Display a summary of all findings.
    
    Args:
        findings: List of finding dicts
        by_severity: Count by severity level
        by_type: Count by finding type
    """
    # Severity bar
    severity_colors = {
        "critical": ("🔴", "bold red"),
        "high": ("🟠", "bold orange1"),
        "medium": ("🟡", "bold yellow"),
        "low": ("🔵", "bold blue"),
        "info": ("⚪", "dim white")
    }
    
    if not by_severity:
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in by_severity:
                by_severity[sev] += 1
    
    # Build severity summary
    severity_line = Text()
    for sev, (icon, style) in severity_colors.items():
        count = by_severity.get(sev, 0)
        if count > 0:
            severity_line.append(f" {icon} ", style=style)
            severity_line.append(f"{count} ", style=style)
    
    # Type breakdown
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE, expand=True)
    table.add_column("Type", style="cyan", width=20)
    table.add_column("Count", width=8, justify="center")
    table.add_column("Samples", style="dim")
    
    if by_type:
        for ftype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:10]:
            # Get samples
            samples = [f.get("value", "")[:30] for f in findings if f.get("type") == ftype][:2]
            samples_str = ", ".join(samples) if samples else ""
            table.add_row(ftype, str(count), samples_str)
    
    # Recent findings
    recent_table = Table(show_header=True, header_style="bold", box=box.SIMPLE, expand=True)
    recent_table.add_column("Severity", width=10)
    recent_table.add_column("Finding", style="white")
    recent_table.add_column("Source", style="dim", width=15)
    
    for finding in findings[-10:]:
        sev = finding.get("severity", "info")
        icon, style = severity_colors.get(sev, ("•", "white"))
        recent_table.add_row(
            f"[{style.split()[1] if ' ' in style else style}]{icon} {sev.upper()}[/]",
            finding.get("title", finding.get("value", ""))[:50],
            finding.get("source", "")[:15]
        )
    
    content = Table.grid(expand=True)
    content.add_row(severity_line)
    content.add_row("")
    content.add_row(f"[bold]Total Findings: {len(findings)}[/bold]")
    content.add_row("")
    content.add_row(recent_table)
    
    panel = Panel(
        content,
        title="[bold red]🎯 SECURITY FINDINGS[/bold red]",
        border_style="red",
        box=box.HEAVY
    )
    console.print(panel)


def display_execution_timeline(
    events: List[Dict],
    current_time: datetime = None
):
    """
    Display a timeline of execution events.
    
    Args:
        events: List of event dicts {time, type, description, status}
        current_time: Current timestamp
    """
    tree = Tree("[bold cyan]📊 Execution Timeline[/bold cyan]")
    
    event_icons = {
        "tool_start": "▶️",
        "tool_end": "✓",
        "tool_error": "❌",
        "finding": "🔍",
        "agent_start": "🤖",
        "agent_end": "✅",
        "handoff": "↗️",
        "retry": "🔄"
    }
    
    for event in events[-15:]:
        event_type = event.get("type", "unknown")
        icon = event_icons.get(event_type, "•")
        
        time_str = event.get("time", "")
        if isinstance(time_str, datetime):
            time_str = time_str.strftime("%H:%M:%S")
        
        desc = event.get("description", "")[:60]
        status = event.get("status", "")
        
        style = "green" if status == "success" else "red" if status == "error" else "white"
        
        tree.add(f"[dim]{time_str}[/dim] {icon} [{style}]{desc}[/{style}]")
    
    console.print(tree)


def display_tool_progress_live(
    tool_name: str,
    progress: int,
    output_preview: str = "",
    elapsed: float = 0
):
    """
    Display live tool progress update.
    
    Args:
        tool_name: Name of the running tool
        progress: Progress percentage (0-100)
        output_preview: Preview of recent output
        elapsed: Elapsed time in seconds
    """
    filled = progress // 4
    bar = f"[green]{'█' * filled}[/green][dim]{'░' * (25 - filled)}[/dim]"
    
    output_line = f"[dim]{output_preview[:60]}...[/dim]" if output_preview else ""
    
    console.print(
        f"  [yellow]⚡ {tool_name}[/yellow] {bar} {progress}% [dim]({elapsed:.1f}s)[/dim]"
    )
    if output_line:
        console.print(f"     {output_line}")


def display_phase_header(
    phase_name: str,
    phase_number: int = 0,
    total_phases: int = 0,
    description: str = ""
):
    """
    Display a prominent phase header for kill chain phases.
    
    Args:
        phase_name: Name of the current phase
        phase_number: Current phase number
        total_phases: Total number of phases
        description: Phase description
    """
    phase_icons = {
        "reconnaissance": "🔍",
        "weaponization": "⚔️",
        "delivery": "📦",
        "exploitation": "💥",
        "installation": "📲",
        "command_control": "🎮",
        "actions": "🎯",
        "bug_bounty": "🐛"
    }
    
    icon = phase_icons.get(phase_name.lower().replace(" ", "_"), "📍")
    
    progress_str = f"[{phase_number}/{total_phases}]" if total_phases else ""
    
    header = Text()
    header.append(f"\n{icon} ", style="bold")
    header.append(f"PHASE: {phase_name.upper()}", style="bold white on blue")
    header.append(f" {progress_str}", style="dim")
    
    console.print(header)
    
    if description:
        console.print(f"   [dim italic]{description}[/dim italic]")
    
    console.print()


def display_agent_handoff(
    from_agent: str,
    to_agent: str,
    reason: str = "",
    data_passed: List[str] = None
):
    """
    Display agent handoff information.
    
    Args:
        from_agent: Source agent
        to_agent: Target agent
        reason: Reason for handoff
        data_passed: Key data being passed
    """
    content = Text()
    content.append(f"🤖 {from_agent}", style="cyan")
    content.append(" → ", style="bold yellow")
    content.append(f"🤖 {to_agent}", style="green")
    
    if reason:
        content.append(f"\n   [dim]{reason}[/dim]")
    
    if data_passed:
        content.append("\n   [bold]Data Passed:[/bold]")
        for item in data_passed[:5]:
            content.append(f"\n   • {item[:50]}")
    
    panel = Panel(
        content,
        title="[bold yellow]↗️ AGENT HANDOFF[/bold yellow]",
        border_style="yellow",
        box=box.ROUNDED
    )
    console.print(panel)


def display_real_time_stats(
    tools_run: int,
    findings: int,
    duration: float,
    current_tool: str = "",
    current_agent: str = ""
):
    """
    Display a compact real-time stats bar.
    """
    stats = []
    
    if current_agent:
        stats.append(f"[cyan]🤖 {current_agent}[/cyan]")
    
    if current_tool:
        stats.append(f"[yellow]⚡ {current_tool}[/yellow]")
    
    stats.append(f"[green]🔧 {tools_run} tools[/green]")
    stats.append(f"[red]🎯 {findings} findings[/red]")
    
    # Format duration
    if duration >= 3600:
        dur_str = f"{duration/3600:.1f}h"
    elif duration >= 60:
        dur_str = f"{duration/60:.1f}m"
    else:
        dur_str = f"{duration:.0f}s"
    
    stats.append(f"[dim]⏱️ {dur_str}[/dim]")
    
    console.print(" │ ".join(stats))

