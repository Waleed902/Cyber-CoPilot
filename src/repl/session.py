"""
Cyber-CoPilot REPL Session State Tracker
Holds the current state between interactive prompts.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from src.sdk.runner import Runner
from src.sdk.agent_graph import AgentGraph, DiscoveryBus
from src.intelligence.engine import IntelligenceBus
from src.intelligence.graph import AttackGraph
from src.sdk.finding_bridge import install_bridge

@dataclass
class REPLSession:
    """Holds all state for the current active terminal session."""
    active_agent: str = "orchestrator"
    agent_history: List[str] = field(default_factory=list)
    
    # Active execution context
    runner: Optional[Runner] = None
    graph: Optional[AgentGraph] = None
    
    # Intelligence Core components
    intelligence_bus: IntelligenceBus = field(default_factory=IntelligenceBus)
    attack_graph: AttackGraph = field(default_factory=AttackGraph)
    # Top-level DiscoveryBus shared with AgentGraph nodes — bridged with the
    # IntelligenceBus so a finding registered on either side is visible on both.
    discovery_bus: DiscoveryBus = field(default_factory=DiscoveryBus)
    
    # Target configurations
    target_ip: Optional[str] = None
    target_hostname: Optional[str] = None
    workspace: Optional[str] = None
    
    # Interaction flags
    is_interactive: bool = True
    in_scan: bool = False
    
    # Tool Cache state
    cache_enabled: bool = True
    cache_ttl: int = 3600
    
    env_overrides: Dict[str, str] = field(default_factory=dict)
    
    def switch_agent(self, agent_name: str):
        """Switches the active agent and records history."""
        if self.active_agent:
            self.agent_history.append(self.active_agent)
        self.active_agent = agent_name

# Global session instance singleton
global_session = REPLSession()

# Install Discovery↔Finding bridge once the global session exists.
install_bridge()
