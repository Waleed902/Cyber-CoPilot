"""
Real-time Dashboard System
Provides live visibility into agent operations and findings.
"""

import threading
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box


@dataclass
class AgentStatus:
    """Status of an agent in the dashboard."""
    name: str
    status: str = "idle"  # idle, running, completed, error
    progress: int = 0
    current_tool: str = ""
    tools_run: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass  
class Finding:
    """A security finding for the dashboard."""
    severity: str  # critical, high, medium, low, info
    title: str
    target: str
    source: str
    confidence: str = "unknown"  # high, medium, low, unknown
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ToolExecution:
    """A tool execution record."""
    name: str
    target: str
    status: str  # running, completed, failed, cached
    started_at: datetime
    duration: float = 0
    cached: bool = False


class Dashboard:
    """
    Real-time dashboard for agent operations.
    
    Features:
    - Live agent status
    - Finding counters by severity
    - Tool execution timeline
    - Session statistics
    """
    
    def __init__(self, target: str = ""):
        self.target = target
        self.session_start = datetime.now()
        self.agents: Dict[str, AgentStatus] = {}
        self.findings: List[Finding] = []
        self.tool_history: deque = deque(maxlen=50)
        self.current_tools: Dict[str, ToolExecution] = {}
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._running = False
        self.console = Console()
    
    def set_target(self, target: str):
        """Set the current target."""
        self.target = target
    
    def register_agent(self, name: str):
        """Register an agent in the dashboard."""
        with self._lock:
            if name not in self.agents:
                self.agents[name] = AgentStatus(name=name)
    
    def update_agent(self, name: str, status: str = None, progress: int = None,
                     current_tool: str = None):
        """Update agent status."""
        with self._lock:
            if name not in self.agents:
                self.agents[name] = AgentStatus(name=name)
            
            agent = self.agents[name]
            if status:
                agent.status = status
                if status == "running" and not agent.started_at:
                    agent.started_at = datetime.now()
                elif status == "completed":
                    agent.completed_at = datetime.now()
            if progress is not None:
                agent.progress = progress
            if current_tool:
                agent.current_tool = current_tool
    
    def add_finding(self, severity: str, title: str, target: str = "", source: str = ""):
        """Add a finding to the dashboard."""
        with self._lock:
            finding = Finding(
                severity=severity.lower(),
                title=title[:60],
                target=target or self.target,
                source=source
            )
            self.findings.append(finding)
    
    def tool_started(self, tool_name: str, target: str = ""):
        """Record tool start."""
        with self._lock:
            exec_record = ToolExecution(
                name=tool_name,
                target=target or self.target,
                status="running",
                started_at=datetime.now()
            )
            self.current_tools[tool_name] = exec_record
    
    def tool_completed(self, tool_name: str, success: bool = True, cached: bool = False):
        """Record tool completion."""
        with self._lock:
            if tool_name in self.current_tools:
                exec_record = self.current_tools.pop(tool_name)
                exec_record.status = "completed" if success else "failed"
                exec_record.cached = cached
                exec_record.duration = (datetime.now() - exec_record.started_at).total_seconds()
                self.tool_history.append(exec_record)
                
                # Update agent tools_run count
                for agent in self.agents.values():
                    if agent.status == "running":
                        agent.tools_run += 1
    
    def get_finding_counts(self) -> Dict[str, int]:
        """Get finding counts by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts
    
    def get_session_duration(self) -> str:
        """Get formatted session duration."""
        delta = datetime.now() - self.session_start
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def _build_header(self) -> Panel:
        """Build the header panel."""
        target_text = f"🎯 [bold white]{self.target}[/bold white]" if self.target else "[dim]No target set[/dim]"
        duration = self.get_session_duration()
        
        header = Table.grid(expand=True)
        header.add_column(ratio=2)
        header.add_column(ratio=1, justify="right")
        header.add_row(
            target_text,
            f"🕐 [cyan]{duration}[/cyan]"
        )
        
        return Panel(header, box=box.ROUNDED, style="cyan")
    
    def _build_agents_panel(self) -> Panel:
        """Build the agents status panel."""
        table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
        table.add_column("Agent", style="cyan")
        table.add_column("Status", width=12)
        table.add_column("Progress", width=20)
        table.add_column("Current", style="dim")
        
        for agent in self.agents.values():
            status_colors = {
                "idle": "[dim]○ Idle[/dim]",
                "running": "[yellow]● Running[/yellow]",
                "completed": "[green]✓ Done[/green]",
                "error": "[red]✗ Error[/red]"
            }
            status = status_colors.get(agent.status, agent.status)
            
            # Progress bar
            if agent.status == "running":
                filled = agent.progress // 5
                bar = f"[green]{'█' * filled}[/green][dim]{'░' * (20 - filled)}[/dim] {agent.progress}%"
            else:
                bar = ""
            
            current = agent.current_tool if agent.status == "running" else ""
            
            table.add_row(agent.name, status, bar, current)
        
        return Panel(table, title="[bold]Agents[/bold]", box=box.ROUNDED)
    
    def _build_findings_panel(self) -> Panel:
        """Build the findings summary panel."""
        counts = self.get_finding_counts()
        
        findings_text = Text()
        findings_text.append("🔴 ", style="red")
        findings_text.append(f"{counts['critical']} ", style="bold red")
        findings_text.append("🟠 ", style="red")
        findings_text.append(f"{counts['high']} ", style="bold")
        findings_text.append("🟡 ", style="yellow")
        findings_text.append(f"{counts['medium']} ", style="bold yellow")
        findings_text.append("🔵 ", style="blue")
        findings_text.append(f"{counts['low']} ", style="bold blue")
        findings_text.append("⚪ ", style="dim")
        findings_text.append(f"{counts['info']}", style="dim")
        
        total = sum(counts.values())
        
        content = Table.grid()
        content.add_row(findings_text)
        content.add_row(Text(f"Total: {total} findings", style="dim"))
        
        # Recent findings
        if self.findings:
            content.add_row(Text(""))
            content.add_row(Text("Recent:", style="bold"))
            for finding in self.findings[-3:]:
                severity_icons = {
                    "critical": "🔴",
                    "high": "🟠", 
                    "medium": "🟡",
                    "low": "🔵",
                    "info": "⚪"
                }
                icon = severity_icons.get(finding.severity, "•")
                content.add_row(Text(f"  {icon} {finding.title[:40]}", style="dim"))
        
        return Panel(content, title="[bold]Findings[/bold]", box=box.ROUNDED)
    
    def _build_tools_panel(self) -> Panel:
        """Build the current tools panel."""
        content = Table.grid(expand=True)
        
        # Running tools
        if self.current_tools:
            for tool in self.current_tools.values():
                elapsed = (datetime.now() - tool.started_at).total_seconds()
                content.add_row(
                    Text(f"▶ {tool.name}", style="yellow"),
                    Text(f"{elapsed:.1f}s", style="dim", justify="right")
                )
        else:
            content.add_row(Text("No tools running", style="dim"))
        
        # Recent completions
        if self.tool_history:
            content.add_row(Text(""))
            recent = list(self.tool_history)[-5:]
            for tool in reversed(recent):
                status_icon = "✓" if tool.status == "completed" else "✗"
                cached_tag = " [cached]" if tool.cached else ""
                color = "green" if tool.status == "completed" else "red"
                content.add_row(
                    Text(f"{status_icon} {tool.name}{cached_tag}", style=color),
                    Text(f"{tool.duration:.1f}s", style="dim", justify="right")
                )
        
        return Panel(content, title="[bold]Tools[/bold]", box=box.ROUNDED)
    
    def render(self) -> Layout:
        """Render the full dashboard."""
        layout = Layout()
        
        layout.split(
            Layout(self._build_header(), name="header", size=3),
            Layout(name="body")
        )
        
        layout["body"].split_row(
            Layout(self._build_agents_panel(), name="agents", ratio=2),
            Layout(name="right")
        )
        
        layout["right"].split(
            Layout(self._build_findings_panel(), name="findings"),
            Layout(self._build_tools_panel(), name="tools")
        )
        
        return layout
    
    def render_compact(self) -> str:
        """Render a compact single-line status."""
        counts = self.get_finding_counts()
        duration = self.get_session_duration()
        
        running = [a.name for a in self.agents.values() if a.status == "running"]
        running_text = f"▶ {', '.join(running)}" if running else "idle"
        
        total_findings = sum(counts.values())
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        
        findings_text = f"🔴{critical} 🟠{high}" if (critical or high) else f"{total_findings} findings"
        
        return f"[{duration}] {running_text} | {findings_text}"
    
    def print_status(self):
        """Print current dashboard status."""
        self.console.print(self.render())
    
    def print_compact(self):
        """Print compact status line."""
        self.console.print(self.render_compact())


# Global instance
_dashboard: Optional[Dashboard] = None


def get_dashboard() -> Dashboard:
    """Get or create the global dashboard."""
    global _dashboard
    if _dashboard is None:
        _dashboard = Dashboard()
    return _dashboard


def reset_dashboard(target: str = ""):
    """Reset the dashboard for a new session."""
    global _dashboard
    _dashboard = Dashboard(target=target)
    return _dashboard
