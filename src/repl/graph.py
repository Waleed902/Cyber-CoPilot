"""
Attack Path Visualization
BloodHound-style graph showing compromise chains:
    Subdomain → Open Port → SQLi → DB Creds → Admin Panel → RCE → Root

Visual representation of attack paths and kill chains using Rich.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from rich.console import Console
from rich.tree import Tree
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class NodeType(Enum):
    """Types of nodes in the attack graph."""
    ENTRY_POINT = "entry_point"      # Initial target/subdomain
    PORT = "port"                     # Open port/service
    TECHNOLOGY = "technology"         # Web technology/CMS
    VULNERABILITY = "vulnerability"   # Discovered vulnerability
    CREDENTIAL = "credential"        # Captured credentials
    ACCESS = "access"                # Access level gained
    PRIVILEGE = "privilege"          # Privilege escalation
    DATA = "data"                    # Sensitive data obtained
    LATERAL = "lateral"             # Lateral movement


@dataclass
class AttackNode:
    """A node in the attack path graph."""
    id: str
    label: str
    node_type: NodeType
    severity: str = "info"  # critical, high, medium, low, info
    source_tool: str = ""
    timestamp: str = ""
    metadata: Dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%H:%M:%S")


@dataclass
class AttackEdge:
    """An edge connecting two nodes in the attack path."""
    source_id: str
    target_id: str
    label: str = ""  # Describes the technique used
    tool_used: str = ""


class AttackPathGraph:
    """
    Tracks and visualizes attack paths as a directed graph.
    
    Nodes represent discoveries (subdomains, ports, vulns, creds, access levels).
    Edges represent attack techniques connecting them.
    """
    
    def __init__(self, target: str = ""):
        self.target = target
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self._adjacency: Dict[str, List[str]] = {}  # node_id -> [child_ids]
        self.kill_chains: List[List[str]] = []  # Complete attack paths
    
    # ─── Node Management ─────────────────────────────────────────
    
    def add_node(self, node_id: str, label: str, node_type: NodeType,
                 severity: str = "info", source_tool: str = "",
                 metadata: Dict = None) -> AttackNode:
        """Add or update a node."""
        if node_id in self.nodes:
            existing = self.nodes[node_id]
            if source_tool and source_tool != existing.source_tool:
                existing.metadata.setdefault("confirmed_by", []).append(source_tool)
            return existing
        
        node = AttackNode(
            id=node_id,
            label=label,
            node_type=node_type,
            severity=severity,
            source_tool=source_tool,
            metadata=metadata or {}
        )
        self.nodes[node_id] = node
        self._adjacency.setdefault(node_id, [])
        return node
    
    def add_edge(self, source_id: str, target_id: str, 
                 label: str = "", tool_used: str = ""):
        """Add a directed edge between nodes."""
        # Prevent duplicates
        for e in self.edges:
            if e.source_id == source_id and e.target_id == target_id:
                return
        
        edge = AttackEdge(
            source_id=source_id,
            target_id=target_id,
            label=label,
            tool_used=tool_used
        )
        self.edges.append(edge)
        self._adjacency.setdefault(source_id, []).append(target_id)
    
    # ─── Convenience Methods (auto-create + link) ────────────────
    
    def add_subdomain(self, subdomain: str, source_tool: str = ""):
        """Add a subdomain as an entry point node."""
        node_id = f"sub:{subdomain}"
        self.add_node(node_id, subdomain, NodeType.ENTRY_POINT, 
                      source_tool=source_tool)
        # Link to root target
        root_id = f"target:{self.target}"
        if root_id not in self.nodes:
            self.add_node(root_id, self.target, NodeType.ENTRY_POINT)
        self.add_edge(root_id, node_id, "subdomain")
        return node_id
    
    def add_port(self, host: str, port: int, service: str, 
                 source_tool: str = ""):
        """Add an open port linked to its host."""
        node_id = f"port:{host}:{port}"
        self.add_node(node_id, f"{port}/{service}", NodeType.PORT,
                      severity="info", source_tool=source_tool,
                      metadata={"port": port, "service": service})
        # Link to host
        host_id = f"sub:{host}" if f"sub:{host}" in self.nodes else f"target:{host}"
        if host_id not in self.nodes:
            host_id = f"target:{host}"
            self.add_node(host_id, host, NodeType.ENTRY_POINT)
        self.add_edge(host_id, node_id, "port scan")
        return node_id
    
    def add_vulnerability(self, name: str, severity: str, host: str = "",
                          port: int = 0, url: str = "", source_tool: str = ""):
        """Add a vulnerability linked to its service/port."""
        node_id = f"vuln:{name}:{host}:{port}"
        self.add_node(node_id, name, NodeType.VULNERABILITY,
                      severity=severity, source_tool=source_tool,
                      metadata={"url": url})
        
        # Link to port or host
        if port:
            port_id = f"port:{host}:{port}"
            if port_id in self.nodes:
                self.add_edge(port_id, node_id, "vulnerability scan")
            else:
                host_id = f"target:{host}"
                if host_id not in self.nodes:
                    self.add_node(host_id, host, NodeType.ENTRY_POINT)
                self.add_edge(host_id, node_id, "vulnerability scan")
        elif host:
            host_id = f"sub:{host}" if f"sub:{host}" in self.nodes else f"target:{host}"
            if host_id not in self.nodes:
                host_id = f"target:{host}"
                self.add_node(host_id, host, NodeType.ENTRY_POINT)
            self.add_edge(host_id, node_id, "vulnerability scan")
        
        return node_id
    
    def add_credential(self, username: str, cred_type: str = "password",
                       from_vuln: str = "", source_tool: str = ""):
        """Add captured credentials linked to the vulnerability that revealed them."""
        node_id = f"cred:{username}"
        self.add_node(node_id, f"🔑 {username}", NodeType.CREDENTIAL,
                      severity="high", source_tool=source_tool,
                      metadata={"cred_type": cred_type})
        
        # Link to vulnerability if provided
        if from_vuln:
            for nid, node in self.nodes.items():
                if node.node_type == NodeType.VULNERABILITY and from_vuln.lower() in node.label.lower():
                    self.add_edge(nid, node_id, "credential extraction")
                    break
        return node_id
    
    def add_access(self, access_level: str, host: str = "",
                   from_cred: str = "", source_tool: str = ""):
        """Add access level achieved (e.g., 'user shell', 'admin panel')."""
        node_id = f"access:{access_level}:{host}"
        self.add_node(node_id, f"🔓 {access_level}", NodeType.ACCESS,
                      severity="critical", source_tool=source_tool)
        
        # Link to credential
        if from_cred:
            cred_id = f"cred:{from_cred}"
            if cred_id in self.nodes:
                self.add_edge(cred_id, node_id, "authentication")
        return node_id
    
    def add_privilege_escalation(self, priv_level: str, from_access: str = "",
                                  technique: str = "", source_tool: str = ""):
        """Add privilege escalation."""
        node_id = f"priv:{priv_level}"
        self.add_node(node_id, f"👑 {priv_level}", NodeType.PRIVILEGE,
                      severity="critical", source_tool=source_tool,
                      metadata={"technique": technique})
        
        # Link to previous access
        if from_access:
            for nid in self.nodes:
                if nid.startswith("access:") and from_access.lower() in nid.lower():
                    self.add_edge(nid, node_id, technique or "privilege escalation")
                    break
        return node_id
    
    # ─── Auto-build from Dedup Findings ──────────────────────────
    
    def build_from_dedup(self):
        """Auto-build the attack graph from the deduplication engine."""
        try:
            from src.sdk.analysis import get_deduplicator
            dedup = get_deduplicator()
        except ImportError:
            return
        
        # Entry point
        root_id = f"target:{self.target}"
        self.add_node(root_id, self.target, NodeType.ENTRY_POINT)
        
        # Subdomains
        for f in dedup.get_by_category("subdomain"):
            self.add_subdomain(f.data.get("subdomain", f.title), f.sources[0] if f.sources else "")
        
        # Ports
        for f in dedup.get_by_category("port"):
            host = f.data.get("target", self.target)
            self.add_port(host, f.data.get("port", 0), f.data.get("service", ""), 
                         f.sources[0] if f.sources else "")
        
        # Vulnerabilities
        for f in dedup.get_by_category("vulnerability"):
            host = f.data.get("target", self.target)
            self.add_vulnerability(f.title, f.severity, host=host,
                                   url=f.data.get("url", ""),
                                   source_tool=f.sources[0] if f.sources else "")
        
        # Credentials
        for f in dedup.get_by_category("credential"):
            self.add_credential(f.data.get("username", "unknown"),
                              source_tool=f.sources[0] if f.sources else "")
        
        # Auto-detect kill chains
        self._detect_kill_chains()
    
    def _detect_kill_chains(self):
        """Detect complete attack paths from entry to privilege."""
        self.kill_chains = []
        
        # Find all root nodes (entry points with no incoming edges)
        incoming = set()
        for edge in self.edges:
            incoming.add(edge.target_id)
        
        roots = [nid for nid, node in self.nodes.items() 
                 if node.node_type == NodeType.ENTRY_POINT and nid not in incoming]
        
        if not roots:
            roots = [nid for nid, node in self.nodes.items() 
                     if node.node_type == NodeType.ENTRY_POINT]
        
        # DFS to find all paths to high-value targets
        high_value_types = {NodeType.CREDENTIAL, NodeType.ACCESS, NodeType.PRIVILEGE}
        
        for root in roots:
            self._dfs_paths(root, [], set(), high_value_types)
    
    def _dfs_paths(self, current: str, path: List[str], visited: Set[str],
                   target_types: Set[NodeType]):
        """DFS to find attack paths."""
        if current in visited:
            return
        
        visited.add(current)
        path.append(current)
        
        node = self.nodes.get(current)
        if node and node.node_type in target_types and len(path) > 1:
            self.kill_chains.append(list(path))
        
        for child_id in self._adjacency.get(current, []):
            self._dfs_paths(child_id, path, visited, target_types)
        
        path.pop()
        visited.discard(current)
    
    # ─── Visualization ───────────────────────────────────────────
    
    def render_tree(self) -> Tree:
        """Render the attack graph as a Rich Tree."""
        tree = Tree(
            f"[bold cyan]🎯 Attack Path Graph[/bold cyan] — [white]{self.target}[/white]",
            guide_style="cyan"
        )
        
        if not self.nodes:
            tree.add("[dim]No attack data collected yet. Run scans to populate.[/dim]")
            return tree
        
        # Group nodes by type
        by_type = {}
        for nid, node in self.nodes.items():
            by_type.setdefault(node.node_type, []).append(node)
        
        type_config = {
            NodeType.ENTRY_POINT: ("🌐 Entry Points", "cyan"),
            NodeType.PORT: ("🔌 Open Ports", "blue"),
            NodeType.TECHNOLOGY: ("🛠️  Technologies", "white"),
            NodeType.VULNERABILITY: ("⚠️  Vulnerabilities", "yellow"),
            NodeType.CREDENTIAL: ("🔑 Credentials", "red"),
            NodeType.ACCESS: ("🔓 Access Gained", "bold red"),
            NodeType.PRIVILEGE: ("👑 Privilege Escalation", "bold magenta"),
            NodeType.DATA: ("📦 Sensitive Data", "bold yellow"),
            NodeType.LATERAL: ("🔄 Lateral Movement", "bold blue"),
        }
        
        for ntype, (title, color) in type_config.items():
            nodes = by_type.get(ntype, [])
            if not nodes:
                continue
            
            branch = tree.add(f"[{color}]{title}[/{color}] [dim]({len(nodes)})[/dim]")
            for node in nodes[:15]:  # Limit display
                sev_icon = self._severity_icon(node.severity)
                confirmed = ""
                if node.metadata.get("confirmed_by"):
                    confirmed = f" [green](+{len(node.metadata['confirmed_by'])} tools)[/green]"
                branch.add(f"{sev_icon} [{color}]{node.label}[/{color}]{confirmed} [dim]({node.source_tool})[/dim]")
            
            if len(nodes) > 15:
                branch.add(f"[dim]... and {len(nodes) - 15} more[/dim]")
        
        return tree
    
    def render_kill_chains(self) -> Panel:
        """Render discovered kill chains as visual attack paths."""
        if not self.kill_chains:
            self._detect_kill_chains()
        
        if not self.kill_chains:
            return Panel(
                "[dim]No complete attack paths detected yet.\n"
                "Run more scans to discover connections.[/dim]",
                title="[bold red]⚔️  Kill Chains[/bold red]",
                border_style="red"
            )
        
        lines = []
        
        # Sort chains by length (longest = most interesting)
        sorted_chains = sorted(self.kill_chains, key=len, reverse=True)
        
        for i, chain in enumerate(sorted_chains[:5], 1):
            lines.append(f"[bold yellow]Chain #{i}[/bold yellow] ({len(chain)} steps)")
            
            chain_parts = []
            for j, node_id in enumerate(chain):
                node = self.nodes.get(node_id)
                if not node:
                    continue
                
                icon = self._type_icon(node.node_type)
                sev_color = self._severity_color(node.severity)
                
                chain_parts.append(f"[{sev_color}]{icon} {node.label}[/{sev_color}]")
            
            # Build the visual chain with arrows
            chain_str = " [bold white]→[/bold white] ".join(chain_parts)
            lines.append(f"  {chain_str}")
            lines.append("")
        
        return Panel(
            "\n".join(lines),
            title="[bold red]⚔️  Kill Chains — Compromise Paths[/bold red]",
            border_style="red",
            box=box.DOUBLE
        )
    
    def render_full(self):
        """Render the complete attack path visualization."""
        console.print()
        console.print("[bold cyan]" + "═" * 60 + "[/bold cyan]")
        console.print("[bold white]        🗡️  ATTACK PATH VISUALIZATION[/bold white]")
        console.print("[bold cyan]" + "═" * 60 + "[/bold cyan]")
        console.print()
        
        # Statistics
        stats = self._get_stats()
        stats_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        stats_table.add_column(justify="center")
        
        stats_table.add_row(
            f"[cyan]Nodes[/cyan]\n[bold]{stats['total_nodes']}[/bold]",
            f"[yellow]Vulns[/yellow]\n[bold]{stats['vulns']}[/bold]",
            f"[red]Creds[/red]\n[bold]{stats['creds']}[/bold]",
            f"[magenta]Access[/magenta]\n[bold]{stats['access']}[/bold]",
            f"[bold red]Chains[/bold red]\n[bold]{stats['chains']}[/bold]"
        )
        console.print(stats_table)
        console.print()
        
        # Attack tree
        console.print(self.render_tree())
        console.print()
        
        # Kill chains
        console.print(self.render_kill_chains())
    
    def _get_stats(self) -> Dict:
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "vulns": len([n for n in self.nodes.values() if n.node_type == NodeType.VULNERABILITY]),
            "creds": len([n for n in self.nodes.values() if n.node_type == NodeType.CREDENTIAL]),
            "access": len([n for n in self.nodes.values() if n.node_type in (NodeType.ACCESS, NodeType.PRIVILEGE)]),
            "chains": len(self.kill_chains),
        }
    
    def _severity_icon(self, severity: str) -> str:
        return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(severity, "⚪")
    
    def _severity_color(self, severity: str) -> str:
        return {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "cyan"}.get(severity, "white")
    
    def _type_icon(self, node_type: NodeType) -> str:
        return {
            NodeType.ENTRY_POINT: "🌐", NodeType.PORT: "🔌",
            NodeType.TECHNOLOGY: "🛠️", NodeType.VULNERABILITY: "⚠️",
            NodeType.CREDENTIAL: "🔑", NodeType.ACCESS: "🔓",
            NodeType.PRIVILEGE: "👑", NodeType.DATA: "📦",
            NodeType.LATERAL: "🔄"
        }.get(node_type, "•")


# Global singleton
_attack_graph: Optional[AttackPathGraph] = None


def get_attack_graph(target: str = "") -> AttackPathGraph:
    """Get or create the global attack graph."""
    global _attack_graph
    if _attack_graph is None or (target and _attack_graph.target != target):
        _attack_graph = AttackPathGraph(target=target)
    return _attack_graph


def reset_attack_graph(target: str = ""):
    """Reset the attack graph."""
    global _attack_graph
    _attack_graph = AttackPathGraph(target=target)


# =============================================================================
# AGENT GRAPH UI (merged from graph_ui.py)
# =============================================================================

from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

console = Console()


def display_agent_graph(graph, current_agent: str = None):
    """
    Display the agent graph structure as a visual tree.
    
    Args:
        graph: AgentGraph instance
        current_agent: Currently executing agent (highlighted)
    """
    tree = Tree(
        "[bold cyan]🕸️ AGENT GRAPH[/bold cyan]",
        guide_style="cyan"
    )
    
    # Get execution order
    try:
        batches = graph.get_execution_order()
    except:
        batches = [[n for n in graph.nodes.keys()]]
    
    for batch_num, batch in enumerate(batches, 1):
        batch_node = tree.add(f"[bold yellow]⚡ Phase {batch_num}[/bold yellow] [dim](parallel)[/dim]")
        
        for agent_name in batch:
            if agent_name in graph.nodes:
                node = graph.nodes[agent_name]
                
                # Style based on current agent
                if agent_name == current_agent:
                    style = "[bold green]▶ "
                    suffix = " [green](running)[/green]"
                else:
                    style = "[white]○ "
                    suffix = ""
                
                # Add agent with tools count
                tools_count = len(node.agent.tools) if node.agent else 0
                agent_branch = batch_node.add(
                    f"{style}{agent_name}[/] [dim]({tools_count} tools){suffix}[/dim]"
                )
                
                # Add specializations
                if node.specialization:
                    spec_str = ", ".join(node.specialization[:3])
                    agent_branch.add(f"[dim]📌 {spec_str}[/dim]")
                
                # Add dependencies
                if node.dependencies:
                    deps_str = ", ".join(node.dependencies)
                    agent_branch.add(f"[dim]🔗 depends: {deps_str}[/dim]")
    
    console.print(tree)


def display_execution_progress(agents: List[str], completed: List[str], 
                              current: str = None, results: Dict = None):
    """
    Display a progress view of agent execution.
    
    Args:
        agents: All agents to execute
        completed: Agents that have completed
        current: Currently running agent
        results: Results dict with agent statuses
    """
    table = Table(
        title="[bold cyan]Agent Execution Progress[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white"
    )
    
    table.add_column("Agent", style="cyan", min_width=15)
    table.add_column("Status", min_width=12)
    table.add_column("Tools", justify="right", min_width=8)
    table.add_column("Findings", min_width=20)
    
    for agent_name in agents:
        if agent_name in completed:
            status = "[green]✅ Complete[/green]"
            tools = str(results.get(agent_name, {}).get("tool_calls", 0)) if results else "0"
            findings = results.get(agent_name, {}).get("findings", "-") if results else "-"
        elif agent_name == current:
            status = "[yellow]⚡ Running[/yellow]"
            tools = "[dim]...[/dim]"
            findings = "[dim]...[/dim]"
        else:
            status = "[dim]○ Pending[/dim]"
            tools = "-"
            findings = "-"
        
        table.add_row(agent_name, status, tools, str(findings)[:30])
    
    console.print(table)


def display_discovery_bus(discovery_bus, limit: int = 15):
    """
    Display the contents of the discovery bus.
    
    Args:
        discovery_bus: DiscoveryBus instance
        limit: Maximum discoveries to show
    """
    discoveries = discovery_bus._discoveries[-limit:]
    
    if not discoveries:
        console.print(Panel(
            "[dim]No discoveries yet. Agents will share findings here.[/dim]",
            title="[bold magenta]📡 Discovery Bus[/bold magenta]",
            border_style="magenta"
        ))
        return
    
    table = Table(
        title="[bold magenta]📡 Discovery Bus - Shared Intelligence[/bold magenta]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white"
    )
    
    table.add_column("Type", style="cyan", min_width=12)
    table.add_column("Value", min_width=25)
    table.add_column("Source", style="yellow", min_width=12)
    table.add_column("Severity", min_width=10)
    table.add_column("Validated", min_width=10)
    
    for disc in discoveries:
        # Severity styling
        sev = disc.severity
        if sev == "critical":
            sev_styled = "[bold red]CRITICAL[/bold red]"
        elif sev == "high":
            sev_styled = "[red]HIGH[/red]"
        elif sev == "medium":
            sev_styled = "[yellow]MEDIUM[/yellow]"
        else:
            sev_styled = "[dim]LOW[/dim]"
        
        # Validation status
        validated = "✅ Yes" if disc.validated else "❌ No"
        
        # Discovery type
        disc_type = disc.type.value if hasattr(disc.type, 'value') else str(disc.type)
        
        # Get value from data dict
        value = disc.data.get('name', disc.data.get('url', disc.data.get('port', 'Unknown')))
        table.add_row(
            disc_type,
            str(value)[:35],
            disc.source_agent[:12],
            sev_styled,
            validated
        )
    
    console.print(table)


def display_graph_results(results: Dict, discovery_bus=None):
    """
    Display comprehensive results from an agent graph execution.
    
    Args:
        results: Dict of agent_name -> RunResult
        discovery_bus: Optional DiscoveryBus for showing discoveries
    """
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold white]                    🕸️  AGENT GRAPH RESULTS[/bold white]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    # Summary table
    summary_table = Table(
        title="[bold green]Execution Summary[/bold green]",
        box=box.ROUNDED
    )
    summary_table.add_column("Agent", style="cyan")
    summary_table.add_column("Tools", justify="right")
    summary_table.add_column("Status")
    summary_table.add_column("Key Findings", min_width=30)
    
    total_tools = 0
    
    for agent_name, result in results.items():
        if result and hasattr(result, 'tool_calls_made'):
            tools = result.tool_calls_made
            total_tools += tools
            status = "[green]✅[/green]"
            
            # Extract key findings from output
            output = result.output[:200] if result.output else ""
            if "CRITICAL" in output or "critical" in output.lower():
                findings = "[red]Critical vuln found[/red]"
            elif "HIGH" in output or "vulnerable" in output.lower():
                findings = "[yellow]Vulnerabilities found[/yellow]"
            elif "found" in output.lower() or "discovered" in output.lower():
                findings = "Findings reported"
            else:
                findings = "[dim]No critical findings[/dim]"
        else:
            tools = 0
            status = "[red]❌ Error[/red]"
            findings = "[dim]-[/dim]"
        
        summary_table.add_row(agent_name, str(tools), status, findings)
    
    console.print(summary_table)
    console.print(f"\n[bold]Total Tool Executions: [cyan]{total_tools}[/cyan][/bold]\n")
    
    # Show discovery bus if provided
    if discovery_bus:
        display_discovery_bus(discovery_bus)
    
    # Show detailed outputs
    console.print("\n[bold yellow]───────────── Detailed Agent Outputs ─────────────[/bold yellow]\n")
    
    for agent_name, result in results.items():
        if result and hasattr(result, 'output') and result.output:
            # Truncate long outputs
            output = result.output[:10000]
            if len(result.output) > 10000:
                output += f"\n... [dim](truncated, {len(result.output)} total chars)[/dim]"
            
            console.print(Panel(
                output,
                title=f"[bold cyan]{agent_name}[/bold cyan]",
                border_style="cyan",
                padding=(1, 2)
            ))


def display_validated_vulns(poc_results: List):
    """
    Display validated vulnerabilities with PoC commands.
    
    Args:
        poc_results: List of ValidationResult from poc_validation
    """
    confirmed = [r for r in poc_results if r.validated]
    unconfirmed = [r for r in poc_results if not r.validated]
    
    if not poc_results:
        console.print("[dim]No vulnerability validations performed yet.[/dim]")
        return
    
    table = Table(
        title="[bold red]🎯 Validated Vulnerabilities[/bold red]",
        box=box.ROUNDED,
        show_header=True
    )
    
    table.add_column("Vulnerability", style="cyan", min_width=15)
    table.add_column("Confirmed", min_width=10)
    table.add_column("Confidence", min_width=10)
    table.add_column("PoC Available", min_width=12)
    
    for result in confirmed:
        table.add_row(
            result.vulnerability.replace("_", " ").title(),
            "[green]✅ Yes[/green]",
            f"[bold]{result.confidence}[/bold]",
            "✅" if result.poc_command else "❌"
        )
    
    for result in unconfirmed:
        table.add_row(
            result.vulnerability.replace("_", " ").title(),
            "[red]❌ No[/red]",
            f"[dim]{result.confidence}[/dim]",
            "❌"
        )
    
    console.print(table)
    
    # Show PoC commands for confirmed vulns
    if confirmed:
        console.print("\n[bold yellow]📝 PoC Commands:[/bold yellow]\n")
        for result in confirmed:
            if result.poc_command:
                console.print(f"[cyan]{result.vulnerability}:[/cyan]")
                console.print(f"  [dim]{result.poc_command[:100]}[/dim]\n")


def create_live_progress_display(agents: List[str]):
    """
    Create a live-updating progress display for agent execution.
    
    Args:
        agents: List of agent names to track
    
    Returns:
        Progress instance for updating
    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )
    
    # Add tasks for each agent
    tasks = {}
    for agent in agents:
        task_id = progress.add_task(f"[cyan]{agent}[/cyan]", total=100)
        tasks[agent] = task_id
    
    return progress, tasks


def display_graph_menu():
    """Display menu for graph-based operations."""
    menu = """
[bold cyan]>>  AGENT GRAPH OPERATIONS[/bold cyan]

[yellow]Run Commands:[/yellow]
  [cyan]graph run[/cyan] <target>     - Full assessment (4 agents, 15 min timeout)
  [cyan]graph quick[/cyan] <target>   - Quick assessment (2 agents, 5 min timeout) ⚡
  [cyan]graph appsec[/cyan] <url>     - AppSec-focused (XSS, SQLi, SSRF)
  [cyan]graph recon[/cyan] <target>   - Reconnaissance only

[yellow]Status Commands:[/yellow]
  [cyan]graph status[/cyan]           - Show current graph state
  [cyan]graph discoveries[/cyan]      - Show shared intelligence from agents
  [cyan]graph validated[/cyan]        - Show validated vulnerabilities with PoC

[yellow]Examples:[/yellow]
  graph run example.com
  graph quick 192.168.1.1
  graph appsec https://example.com/app
"""
    console.print(Panel(menu, border_style="cyan"))

# ─── EdgeType (alias for compatibility with attack_visualizer users) ──────────
from enum import Enum as _Enum

class EdgeType(_Enum):
    """Edge type for attack path connections (compatibility alias)."""
    EXPLOITS         = "exploits"
    LEADS_TO         = "leads_to"
    REQUIRES         = "requires"
    BYPASSES         = "bypasses"
    LATERAL_MOVE     = "lateral_move"
    ESCALATES        = "escalates"


# ─── Compatibility aliases (were in sdk/attack_visualizer.py) ─────────────────
AttackPathVisualizer  = AttackPathGraph
get_attack_visualizer = get_attack_graph
reset_attack_visualizer = reset_attack_graph

# ─── EdgeType (alias for compatibility with attack_visualizer users) ──────────
from enum import Enum as _Enum

class EdgeType(_Enum):
    """Edge type for attack path connections (compatibility alias)."""
    EXPLOITS         = "exploits"
    LEADS_TO         = "leads_to"
    REQUIRES         = "requires"
    BYPASSES         = "bypasses"
    LATERAL_MOVE     = "lateral_move"
    ESCALATES        = "escalates"


# ─── Compatibility aliases (were in sdk/attack_visualizer.py) ─────────────────
AttackPathVisualizer  = AttackPathGraph
get_attack_visualizer = get_attack_graph
reset_attack_visualizer = reset_attack_graph

