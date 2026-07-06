"""
Cyber-CoPilot SDK - Custom Agent Framework
"""

from .agent import Agent
from .tool import FunctionTool, function_tool
from .runner import Runner, run, clear_memory
from .agent_graph import (
    AgentGraph, AgentNode, DiscoveryBus, Discovery, DiscoveryType,
    create_default_graph
)

# New features
from .scope import ScopeManager, get_scope_manager, check_scope
from .cache import ToolCache, get_tool_cache, cached_tool_execution
from .dashboard import Dashboard, get_dashboard, reset_dashboard
from .evidence import EvidenceCollector, get_evidence_collector, capture_evidence
from .async_executor import AsyncExecutor, get_async_executor, run_async, wait_for_task

__all__ = [
    "Agent", "FunctionTool", "function_tool", "Runner", "run", "clear_memory",
    # Agent Graph System
    "AgentGraph", "AgentNode", "DiscoveryBus", "Discovery", "DiscoveryType",
    "create_default_graph",
    # Scope Management
    "ScopeManager", "get_scope_manager", "check_scope",
    # Tool Caching
    "ToolCache", "get_tool_cache", "cached_tool_execution",
    # Dashboard
    "Dashboard", "get_dashboard", "reset_dashboard",
    # Evidence Collection
    "EvidenceCollector", "get_evidence_collector", "capture_evidence",
    # Async Execution
    "AsyncExecutor", "get_async_executor", "run_async", "wait_for_task"
]

