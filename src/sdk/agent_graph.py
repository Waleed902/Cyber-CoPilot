"""
Agent Graph System - Dynamic Multi-Agent Collaboration

Implements a graph-based agent orchestration system where specialized agents
collaborate dynamically, share discoveries, and work together on complex tasks.

Inspired by Strix's Graph of Agents architecture.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, Future
from loguru import logger
import json
import threading

from .agent import Agent
from .runner import get_runner, RunResult

# Import profile manager for persistence
try:
    from src.repl.profiles import get_profile_manager
except ImportError:
    get_profile_manager = None


class DiscoveryType(Enum):
    """Types of discoveries that can be shared between agents."""
    VULNERABILITY = "vulnerability"
    SERVICE = "service"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    SUBDOMAIN = "subdomain"
    FILE = "file"
    CONFIGURATION = "configuration"
    EXPLOIT_SUCCESS = "exploit_success"
    ATTACK_PATH = "attack_path"


@dataclass
class Discovery:
    """A discovery that can be shared between agents."""
    type: DiscoveryType
    source_agent: str
    target: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "info"  # critical, high, medium, low, info
    validated: bool = False
    poc_available: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "source": self.source_agent,
            "target": self.target,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "validated": self.validated,
            "poc_available": self.poc_available
        }
    
    def to_summary(self) -> str:
        """Get a brief summary for agent context."""
        return f"[{self.type.value.upper()}] {self.data.get('name', 'Unknown')} ({self.severity}) from {self.source_agent}"


@dataclass
class AgentNode:
    """A node in the agent graph representing an agent and its connections."""
    agent: Agent
    specialization: List[str]  # What this agent specializes in
    dependencies: List[str] = field(default_factory=list)  # Agents it depends on
    provides: List[DiscoveryType] = field(default_factory=list)  # What discoveries it can provide
    consumes: List[DiscoveryType] = field(default_factory=list)  # What discoveries it needs
    priority: int = 5  # Execution priority (1 = highest)
    
    @property
    def name(self) -> str:
        return self.agent.name


class DiscoveryBus:
    """
    Central bus for sharing discoveries between agents.
    All agents publish their discoveries here and subscribe to relevant types.
    Now also syncs discoveries to TargetProfileManager for persistence.
    """
    
    def __init__(self, target: str = None):
        self._discoveries: List[Discovery] = []
        self._subscribers: Dict[DiscoveryType, List[Callable]] = {}
        self._lock = threading.Lock()
        self._target = target  # Target for profile persistence
        self._profile_manager = None
        
        # Try to get profile manager for persistence
        if get_profile_manager is not None:
            try:
                self._profile_manager = get_profile_manager()
            except Exception as e:
                logger.warning(f"[DiscoveryBus] Could not get profile manager: {e}")
    
    def set_target(self, target: str):
        """Set the target for profile persistence."""
        self._target = target
    
    def publish(self, discovery: Discovery):
        """Publish a discovery to the bus and persist to profile."""
        with self._lock:
            self._discoveries.append(discovery)
            logger.info(f"[DiscoveryBus] New discovery: {discovery.to_summary()}")
            
            # Persist to TargetProfile
            self._sync_to_profile(discovery)
            
            # Notify subscribers
            if discovery.type in self._subscribers:
                for callback in self._subscribers[discovery.type]:
                    try:
                        callback(discovery)
                    except Exception as e:
                        logger.error(f"[DiscoveryBus] Subscriber error: {e}")
    
    def _sync_to_profile(self, discovery: Discovery):
        """Sync a discovery to the TargetProfileManager for persistence."""
        if not self._profile_manager or not self._target:
            return
        
        try:
            target = discovery.target or self._target
            
            if discovery.type == DiscoveryType.VULNERABILITY:
                self._profile_manager.add_vulnerability(
                    target=target,
                    name=discovery.data.get('name', 'Unknown'),
                    severity=discovery.severity,
                    cve=discovery.data.get('cve', ''),
                    description=discovery.data.get('context', '')[:500]
                )
                logger.debug(f"[DiscoveryBus] Synced vulnerability to profile: {discovery.data.get('name')}")
            
            elif discovery.type == DiscoveryType.SERVICE:
                # Handle port discoveries
                port = discovery.data.get('port')
                if port:
                    self._profile_manager.add_port(
                        target=target,
                        port=int(port),
                        service=discovery.data.get('service', ''),
                        version=discovery.data.get('version', '')
                    )
                    logger.debug(f"[DiscoveryBus] Synced port to profile: {port}")
                
                # Handle IP address discoveries
                ip = discovery.data.get('ip')
                if ip:
                    self._profile_manager.add_ip_address(target=target, ip=ip)
                    logger.debug(f"[DiscoveryBus] Synced IP to profile: {ip}")
            
            elif discovery.type == DiscoveryType.SUBDOMAIN:
                subdomain = discovery.data.get('subdomain') or discovery.data.get('name')
                if subdomain:
                    self._profile_manager.add_subdomain(target=target, subdomain=subdomain)
                    logger.debug(f"[DiscoveryBus] Synced subdomain to profile: {subdomain}")
            
            elif discovery.type == DiscoveryType.CREDENTIAL:
                self._profile_manager.add_credential(
                    target=target,
                    username=discovery.data.get('username', ''),
                    password=discovery.data.get('password', ''),
                    hash=discovery.data.get('hash', ''),
                    source=discovery.source_agent
                )
                logger.debug("[DiscoveryBus] Synced credential to profile")
            
            elif discovery.type == DiscoveryType.ENDPOINT:
                # Store as a note since endpoints aren't a separate profile field
                url = discovery.data.get('url', '')
                if url and len(url) > 5:
                    self._profile_manager.add_note(
                        target=target,
                        note=f"Endpoint discovered: {url}",
                        category="endpoint"
                    )
        except Exception as e:
            logger.warning(f"[DiscoveryBus] Failed to sync to profile: {e}")
    
    def subscribe(self, discovery_type: DiscoveryType, callback: Callable):
        """Subscribe to a specific type of discovery."""
        with self._lock:
            if discovery_type not in self._subscribers:
                self._subscribers[discovery_type] = []
            self._subscribers[discovery_type].append(callback)
    
    def get_discoveries(self, 
                       discovery_type: Optional[DiscoveryType] = None,
                       source_agent: Optional[str] = None,
                       severity: Optional[str] = None,
                       validated_only: bool = False) -> List[Discovery]:
        """Get discoveries matching the filter criteria."""
        with self._lock:
            results = self._discoveries.copy()
        
        if discovery_type:
            results = [d for d in results if d.type == discovery_type]
        if source_agent:
            results = [d for d in results if d.source_agent == source_agent]
        if severity:
            results = [d for d in results if d.severity == severity]
        if validated_only:
            results = [d for d in results if d.validated]
        
        return results
    
    def get_context_for_agent(self, agent_name: str, max_items: int = 20) -> str:
        """Get relevant discoveries as context for an agent."""
        with self._lock:
            # Get discoveries not from this agent (i.e., from other agents)
            relevant = [d for d in self._discoveries if d.source_agent != agent_name]
            
        # Sort by severity and recency
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        relevant.sort(key=lambda d: (severity_order.get(d.severity, 5), -d.timestamp.timestamp()))
        
        # Take top N
        relevant = relevant[:max_items]
        
        if not relevant:
            return ""
        
        lines = ["## Discoveries from Other Agents:"]
        for d in relevant:
            lines.append(f"- {d.to_summary()}")
            if d.data.get("details"):
                lines.append(f"  Details: {d.data['details'][:100]}")
        
        return "\n".join(lines)
    
    def clear(self):
        """Clear all discoveries."""
        with self._lock:
            self._discoveries.clear()
    
    def get_summary(self) -> str:
        """Get a summary of all discoveries."""
        with self._lock:
            total = len(self._discoveries)
            by_type = {}
            by_severity = {}
            
            for d in self._discoveries:
                by_type[d.type.value] = by_type.get(d.type.value, 0) + 1
                by_severity[d.severity] = by_severity.get(d.severity, 0) + 1
        
        lines = [
            "## Discovery Summary",
            f"Total: {total} discoveries",
            "",
            "By Type:"
        ]
        for t, count in by_type.items():
            lines.append(f"  - {t}: {count}")
        
        lines.append("")
        lines.append("By Severity:")
        for s, count in by_severity.items():
            lines.append(f"  - {s}: {count}")
        
        return "\n".join(lines)


class AgentGraph:
    """
    Graph-based multi-agent orchestration system.
    
    Features:
    - Dynamic agent collaboration
    - Automatic discovery sharing
    - Parallel execution based on dependencies
    - Intelligent task routing
    - Aggregated results
    """
    
    def __init__(self, max_parallel: int = 4):
        self.nodes: Dict[str, AgentNode] = {}
        self.discovery_bus = DiscoveryBus()
        self.executor = ThreadPoolExecutor(max_workers=max_parallel)
        self.max_parallel = max_parallel
        self._running = False
        self._results: Dict[str, RunResult] = {}
    
    def add_agent(self, node: AgentNode):
        """Add an agent node to the graph."""
        self.nodes[node.name] = node
        logger.debug(f"[AgentGraph] Added agent: {node.name}")
    
    def remove_agent(self, name: str):
        """Remove an agent from the graph."""
        if name in self.nodes:
            del self.nodes[name]
    
    def get_execution_order(self) -> List[List[str]]:
        """
        Get the execution order based on dependencies.
        Returns a list of batches that can be executed in parallel.
        """
        # Build dependency graph
        remaining = set(self.nodes.keys())
        completed = set()
        batches = []
        
        while remaining:
            # Find agents whose dependencies are satisfied
            batch = []
            for name in remaining:
                node = self.nodes[name]
                deps_satisfied = all(d in completed for d in node.dependencies if d in self.nodes)
                if deps_satisfied:
                    batch.append(name)
            
            if not batch:
                # Circular dependency or missing dependency - just add remaining
                logger.warning("[AgentGraph] Circular or missing dependency detected")
                batch = list(remaining)
            
            # Sort by priority within batch
            batch.sort(key=lambda n: self.nodes[n].priority)
            batches.append(batch)
            
            for name in batch:
                remaining.discard(name)
                completed.add(name)
        
        return batches
    
    def _run_agent_with_context(self, node: AgentNode, task: str, target: str) -> RunResult:
        """Run an agent with shared discovery context."""
        # Get discoveries from other agents
        context = self.discovery_bus.get_context_for_agent(node.name)
        
        # Build enhanced prompt
        enhanced_prompt = f"[TARGET: {target}]\n"
        if context:
            enhanced_prompt += f"\n{context}\n\n"
        enhanced_prompt += f"Task: {task}"
        
        # Run the agent
        runner = get_runner()
        result = asyncio.run(runner.run(node.agent, enhanced_prompt))
        
        # Parse and publish any discoveries from the result
        self._extract_and_publish_discoveries(node.name, target, result.output)
        
        return result
    
    def _extract_and_publish_discoveries(self, agent_name: str, target: str, output: str):
        """Extract discoveries from agent output via LLM structured parsing with regex fallback."""
        if not output or len(output) < 50:
            return
        try:
            from src.sdk.key_manager import get_key_manager
            km = get_key_manager()
            client = km.get_client()
            settings = type('obj', (object,), {'model': km.get_model()})()
            prompt = (
                f"Extract all security discoveries from this agent output for target: {target}\n"
                f"Output:\n{output[:3500]}\n\n"
                "Return ONLY a JSON object with these keys:\n"
                '{"vulnerabilities": [{"name": "", "severity": "critical|high|medium|low", '
                '"cve": "", "description": ""}], '
                '"services": [{"port": 0, "protocol": "tcp", "service": "", "version": ""}], '
                '"subdomains": ["sub.example.com"], '
                '"endpoints": ["https://..."], '
                '"credentials": [{"username": "", "password": "", "hash": ""}], '
                '"ips": ["1.2.3.4"]}'
            )
            resp = client.chat.completions.create(
                model=settings.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=1500,
                response_format={"type": "json_object"},
            )
            raw = resp.choices[0].message.content or "{}"
            data = json.loads(raw)

            # Publish vulnerabilities
            for v in data.get("vulnerabilities", []):
                name = v.get("name", "").strip()
                severity = v.get("severity", "medium").lower()
                if name:
                    self.discovery_bus.publish(Discovery(
                        type=DiscoveryType.VULNERABILITY,
                        source_agent=agent_name, target=target,
                        data={"name": name, "cve": v.get("cve", ""),
                              "description": v.get("description", "")[:300]},
                        severity=severity
                    ))

            # Publish services/ports
            for s in data.get("services", []):
                port = s.get("port", 0)
                if port:
                    self.discovery_bus.publish(Discovery(
                        type=DiscoveryType.SERVICE,
                        source_agent=agent_name, target=target,
                        data={"port": int(port), "protocol": s.get("protocol", "tcp"),
                              "service": s.get("service", ""), "version": s.get("version", "")},
                        severity="info"
                    ))

            # Publish subdomains
            for sub in data.get("subdomains", []):
                if sub:
                    self.discovery_bus.publish(Discovery(
                        type=DiscoveryType.SUBDOMAIN,
                        source_agent=agent_name, target=target,
                        data={"subdomain": str(sub).lower()},
                        severity="info"
                    ))

            # Publish endpoints
            for url in data.get("endpoints", []):
                if url and len(str(url)) > 3:
                    self.discovery_bus.publish(Discovery(
                        type=DiscoveryType.ENDPOINT,
                        source_agent=agent_name, target=target,
                        data={"url": str(url)},
                        severity="info"
                    ))

            # Publish credentials as high-severity vulns
            for cred in data.get("credentials", []):
                user = cred.get("username", "")
                if user:
                    self.discovery_bus.publish(Discovery(
                        type=DiscoveryType.VULNERABILITY,
                        source_agent=agent_name, target=target,
                        data={"name": "exposed_credential",
                              "username": user,
                              "password": cred.get("password", ""),
                              "hash": cred.get("hash", "")},
                        severity="critical"
                    ))

            # Publish extra IPs as SERVICE discoveries
            for ip in data.get("ips", []):
                if ip and not str(ip).startswith(("127.", "0.", "255.")):
                    self.discovery_bus.publish(Discovery(
                        type=DiscoveryType.SERVICE,
                        source_agent=agent_name, target=target,
                        data={"ip": str(ip)},
                        severity="info"
                    ))

            logger.debug(f"LLM extracted discoveries for {agent_name} on {target}")

        except Exception as e:
            logger.warning(f"LLM discovery extraction failed ({e}), falling back to regex")
            self._extract_and_publish_discoveries_regex(agent_name, target, output)

    def _extract_and_publish_discoveries_regex(self, agent_name: str, target: str, output: str):
        """Extract discoveries from agent output and publish them."""
        output_lower = output.lower()
        
        # Detect vulnerability mentions
        vuln_keywords = {
            "sql injection": ("sql_injection", "high"),
            "sqli": ("sql_injection", "high"),
            "xss": ("xss", "medium"),
            "cross-site scripting": ("xss", "medium"),
            "ssrf": ("ssrf", "high"),
            "command injection": ("command_injection", "critical"),
            "rce": ("rce", "critical"),
            "remote code execution": ("rce", "critical"),
            "lfi": ("lfi", "high"),
            "local file inclusion": ("lfi", "high"),
            "rfi": ("rfi", "high"),
            "path traversal": ("path_traversal", "high"),
            "open redirect": ("open_redirect", "low"),
            "csrf": ("csrf", "medium"),
            "xxe": ("xxe", "high"),
            "idor": ("idor", "medium"),
            "authentication bypass": ("auth_bypass", "critical"),
            "broken auth": ("auth_bypass", "high"),
        }
        
        for keyword, (vuln_name, severity) in vuln_keywords.items():
            if keyword in output_lower:
                discovery = Discovery(
                    type=DiscoveryType.VULNERABILITY,
                    source_agent=agent_name,
                    target=target,
                    data={
                        "name": vuln_name,
                        "detected_keyword": keyword,
                        "context": output[:500]
                    },
                    severity=severity
                )
                self.discovery_bus.publish(discovery)
        
        # Detect service mentions (ports)
        import re
        service_patterns = ["port", "service", "running", "listening"]
        if any(p in output_lower for p in service_patterns):
            port_matches = re.findall(r'(\d{1,5})/(?:tcp|udp)', output)
            seen_ports = set()
            for port in port_matches:
                if port not in seen_ports:
                    seen_ports.add(port)
                    discovery = Discovery(
                        type=DiscoveryType.SERVICE,
                        source_agent=agent_name,
                        target=target,
                        data={"port": int(port)},
                        severity="info"
                    )
                    self.discovery_bus.publish(discovery)
        
        # Detect subdomains (extract domain parts that match the target)
        # Match patterns like: subdomain.example.com, www.target.com
        base_domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*{re.escape(base_domain)}'
        subdomain_matches = re.findall(rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(base_domain)})', output)
        seen_subdomains = set()
        for subdomain in subdomain_matches[:20]:  # Limit to avoid spam
            subdomain = subdomain.lower()
            if subdomain not in seen_subdomains and subdomain != base_domain:
                seen_subdomains.add(subdomain)
                discovery = Discovery(
                    type=DiscoveryType.SUBDOMAIN,
                    source_agent=agent_name,
                    target=target,
                    data={"subdomain": subdomain},
                    severity="info"
                )
                self.discovery_bus.publish(discovery)
        
        # Detect IP addresses  
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ip_matches = re.findall(ip_pattern, output)
        seen_ips = set()
        for ip in ip_matches[:10]:  # Limit
            # Filter out common non-target IPs
            if ip not in seen_ips and not ip.startswith(('127.', '0.', '255.')):
                seen_ips.add(ip)
                # Store as a service discovery with IP info
                discovery = Discovery(
                    type=DiscoveryType.SERVICE,
                    source_agent=agent_name,  
                    target=target,
                    data={"ip": ip},
                    severity="info"
                )
                self.discovery_bus.publish(discovery)
        
        # Detect endpoints
        url_matches = re.findall(r'(https?://[^\s<>"\']+|/[a-zA-Z0-9_\-./]+)', output)
        for url in url_matches[:10]:  # Limit to avoid spam
            if len(url) > 3:
                discovery = Discovery(
                    type=DiscoveryType.ENDPOINT,
                    source_agent=agent_name,
                    target=target,
                    data={"url": url},
                    severity="info"
                )
                self.discovery_bus.publish(discovery)
    
    def run_graph(self, task: str, target: str, 
                  agents: Optional[List[str]] = None,
                  timeout_per_agent: Optional[int] = None) -> Dict[str, RunResult]:
        """
        Run the agent graph on a task.
        
        Args:
            task: The main task to accomplish
            target: The target system/URL
            agents: Optional list of specific agents to run (default: all)
            timeout_per_agent: Timeout per agent in seconds (default: None = unlimited)
        
        Returns:
            Dict mapping agent names to their results
        """
        self._running = True
        self._results = {}
        
        # Filter agents if specified
        if agents:
            nodes_to_run = {k: v for k, v in self.nodes.items() if k in agents}
        else:
            nodes_to_run = self.nodes
        
        # Get execution order
        batches = self.get_execution_order()
        
        logger.info(f"[AgentGraph] Running {len(nodes_to_run)} agents in {len(batches)} batches")
        
        for batch_idx, batch in enumerate(batches):
            batch_agents = [name for name in batch if name in nodes_to_run]
            if not batch_agents:
                continue
            
            logger.info(f"[AgentGraph] Batch {batch_idx + 1}: {batch_agents}")
            
            # Run batch in parallel
            futures: Dict[str, Future] = {}
            for agent_name in batch_agents:
                node = self.nodes[agent_name]
                future = self.executor.submit(
                    self._run_agent_with_context, 
                    node, task, target
                )
                futures[agent_name] = future
            
            # Wait for batch to complete
            for agent_name, future in futures.items():
                try:
                    result = future.result(timeout=timeout_per_agent)  # None = wait forever
                    self._results[agent_name] = result
                    logger.info(f"[AgentGraph] {agent_name} completed")
                except TimeoutError:
                    error_msg = f"Agent timed out after {timeout_per_agent}s - consider increasing timeout or running fewer tools"
                    logger.error(f"[AgentGraph] {agent_name} timed out: {error_msg}")
                    self._results[agent_name] = RunResult(
                        output=f"⚠️ Timeout: {error_msg}",
                        messages=[],
                        tool_calls_made=0
                    )
                except Exception as e:
                    error_msg = str(e) if str(e) else "Unknown error occurred"
                    logger.error(f"[AgentGraph] {agent_name} failed: {error_msg}")
                    self._results[agent_name] = RunResult(
                        output=f"❌ Error: {error_msg}",
                        messages=[],
                        tool_calls_made=0
                    )
        
        self._running = False

        # ── Post-graph: VulnChainer attack-path analysis ────────────────────
        try:
            vuln_discoveries = self.discovery_bus.get_discoveries(DiscoveryType.VULNERABILITY)
            if len(vuln_discoveries) >= 2:
                logger.info(
                    f"[AgentGraph] Running VulnChainer on {len(vuln_discoveries)} findings"
                )
                findings = [
                    {
                        "id": str(i),
                        "name": d.data.get("name", "Unknown"),
                        "severity": d.severity,
                        "cve": d.data.get("cve", ""),
                        "description": d.data.get("context", d.data.get("description", "")),
                        "affected_resource": d.target,
                        "exploitable": d.poc_available,
                    }
                    for i, d in enumerate(vuln_discoveries)
                ]
                from src.sdk.key_manager import get_key_manager
                km = get_key_manager()
                client = km.get_client()
                settings = type('obj', (object,), {'model': km.get_model()})()
                from src.sdk.vuln_chainer import VulnChainer
                chainer = VulnChainer(client=client, model=settings.model)
                chains = chainer.chain(findings, context=target)

                if chains:
                    for chain in chains:
                        chain_data = chain.to_dict() if hasattr(chain, "to_dict") else vars(chain)
                        self.discovery_bus.publish(Discovery(
                            type=DiscoveryType.ATTACK_PATH,
                            source_agent="VulnChainer",
                            target=target,
                            data=chain_data,
                            severity=chain_data.get("severity", "high"),
                        ))
                    logger.info(
                        f"[AgentGraph] VulnChainer produced {len(chains)} attack chain(s)"
                    )
                    # Inject attack chains into a dedicated result entry
                    chain_summary = "\n\n".join(
                        f"## Attack Chain {i+1}: {c.to_dict().get('name','')}\n"
                        f"Severity : {c.to_dict().get('severity','')}\n"
                        f"Steps    : {' → '.join(c.to_dict().get('steps', []))}\n"
                        f"Impact   : {c.to_dict().get('impact','')}\n"
                        f"Exploits : {', '.join(c.to_dict().get('exploits', []))}"
                        if hasattr(c, "to_dict") else str(c)
                        for i, c in enumerate(chains)
                    )
                    self._results["__vuln_chains__"] = RunResult(
                        output=f"# Chained Attack Paths\n\n{chain_summary}",
                        messages=[],
                        tool_calls_made=0,
                    )
        except Exception as _vc_err:
            logger.warning(f"[AgentGraph] VulnChainer post-analysis failed: {_vc_err}")

        return self._results
    
    async def run_graph_async(self, task: str, target: str,
                              agents: Optional[List[str]] = None) -> Dict[str, RunResult]:
        """Async version of run_graph."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, 
            lambda: self.run_graph(task, target, agents)
        )
    
    def get_aggregated_results(self) -> str:
        """Get aggregated results from all agents."""
        if not self._results:
            return "No results available. Run the graph first."
        
        lines = ["# Agent Graph Results\n"]
        
        for agent_name, result in self._results.items():
            lines.append(f"## {agent_name}")
            lines.append(f"Tool calls: {result.tool_calls_made}")
            lines.append("")
            lines.append(result.output[:2000])  # Truncate long outputs
            lines.append("\n---\n")
        
        lines.append("## Discovery Summary")
        lines.append(self.discovery_bus.get_summary())
        
        return "\n".join(lines)
    
    def shutdown(self):
        """Shutdown the executor."""
        self.executor.shutdown(wait=True)


# Global instance
_agent_graph: Optional[AgentGraph] = None


def get_agent_graph() -> AgentGraph:
    """Get or create the global agent graph instance."""
    global _agent_graph
    if _agent_graph is None:
        _agent_graph = AgentGraph()
    return _agent_graph


def reset_agent_graph():
    """Reset the agent graph."""
    global _agent_graph
    if _agent_graph:
        _agent_graph.shutdown()
    _agent_graph = AgentGraph()


def create_default_graph() -> AgentGraph:
    """
    Create a default agent graph with all agents configured.
    
    Graph structure:
    - ReconAgent (no dependencies, runs first)
    - WebSecAgent (depends on ReconAgent for endpoints)
    - AppSecAgent (depends on WebSecAgent)
    - RedTeamAgent (depends on AppSecAgent for vulns)
    - BlackHatAgent (depends on all for final exploitation)
    """
    from src.agents import (
        create_recon_agent,
        create_websec_agent,
        create_redteam_agent,
        create_blackhat_agent
    )
    
    graph = AgentGraph()
    
    # Recon Agent - runs first, discovers services and endpoints
    graph.add_agent(AgentNode(
        agent=create_recon_agent(),
        specialization=["reconnaissance", "port_scanning", "dns", "subdomain"],
        dependencies=[],
        provides=[DiscoveryType.SERVICE, DiscoveryType.SUBDOMAIN, DiscoveryType.ENDPOINT],
        consumes=[],
        priority=1
    ))
    
    # WebSec Agent - depends on recon for targets
    graph.add_agent(AgentNode(
        agent=create_websec_agent(),
        specialization=["web_security", "directory_enum", "http"],
        dependencies=["ReconAgent"],
        provides=[DiscoveryType.ENDPOINT, DiscoveryType.FILE],
        consumes=[DiscoveryType.SERVICE, DiscoveryType.ENDPOINT],
        priority=2
    ))
    
    # RedTeam Agent - depends on websec for attack surface
    graph.add_agent(AgentNode(
        agent=create_redteam_agent(),
        specialization=["exploitation", "sqli", "brute_force"],
        dependencies=["WebSecAgent"],
        provides=[DiscoveryType.VULNERABILITY, DiscoveryType.CREDENTIAL, DiscoveryType.EXPLOIT_SUCCESS],
        consumes=[DiscoveryType.ENDPOINT, DiscoveryType.VULNERABILITY],
        priority=3
    ))
    
    # BlackHat Agent - final stage, uses all discoveries
    graph.add_agent(AgentNode(
        agent=create_blackhat_agent(),
        specialization=["advanced_exploitation", "attack_chains", "post_exploit"],
        dependencies=["RedTeamAgent"],
        provides=[DiscoveryType.EXPLOIT_SUCCESS, DiscoveryType.ATTACK_PATH],
        consumes=[DiscoveryType.VULNERABILITY, DiscoveryType.CREDENTIAL, DiscoveryType.SERVICE],
        priority=4
    ))
    
    return graph


def create_killchain_graph(phase: str = "full") -> AgentGraph:
    """
    Create an agent graph tailored to a specific kill-chain phase.

    Phases:
      - reconnaissance  : ReconAgent only
      - weaponization   : ReconAgent + WebSecAgent
      - exploitation    : ReconAgent + WebSecAgent + RedTeamAgent
      - bugbounty       : ReconAgent + WebSecAgent + BugBountyAgent
      - full (default)  : All agents (same as create_default_graph)

    Args:
        phase: Kill-chain phase name (case-insensitive)

    Returns:
        Configured AgentGraph for the requested phase
    """
    from src.agents import (
        create_recon_agent,
        create_websec_agent,
        create_redteam_agent,
        create_blackhat_agent,
        create_bugbounty_agent,
    )

    phase = phase.lower().strip()
    graph = AgentGraph()

    # --- Recon (always present) ---
    graph.add_agent(AgentNode(
        agent=create_recon_agent(),
        specialization=["reconnaissance", "port_scanning", "dns", "subdomain"],
        dependencies=[],
        provides=[DiscoveryType.SERVICE, DiscoveryType.SUBDOMAIN, DiscoveryType.ENDPOINT],
        consumes=[],
        priority=1
    ))

    if phase == "reconnaissance":
        return graph

    # --- WebSec ---
    graph.add_agent(AgentNode(
        agent=create_websec_agent(),
        specialization=["web_security", "directory_enum", "http"],
        dependencies=["ReconAgent"],
        provides=[DiscoveryType.ENDPOINT, DiscoveryType.FILE],
        consumes=[DiscoveryType.SERVICE, DiscoveryType.ENDPOINT],
        priority=2
    ))

    if phase == "weaponization":
        return graph

    if phase == "bugbounty":
        graph.add_agent(AgentNode(
            agent=create_bugbounty_agent(),
            specialization=["bug_bounty", "sqli", "xss", "ssrf", "recon"],
            dependencies=["WebSecAgent"],
            provides=[DiscoveryType.VULNERABILITY, DiscoveryType.EXPLOIT_SUCCESS],
            consumes=[DiscoveryType.ENDPOINT, DiscoveryType.SERVICE],
            priority=3
        ))
        return graph

    # exploitation / full
    graph.add_agent(AgentNode(
        agent=create_redteam_agent(),
        specialization=["exploitation", "sqli", "brute_force"],
        dependencies=["WebSecAgent"],
        provides=[DiscoveryType.VULNERABILITY, DiscoveryType.CREDENTIAL, DiscoveryType.EXPLOIT_SUCCESS],
        consumes=[DiscoveryType.ENDPOINT, DiscoveryType.VULNERABILITY],
        priority=3
    ))

    if phase == "exploitation":
        return graph

    # full
    graph.add_agent(AgentNode(
        agent=create_blackhat_agent(),
        specialization=["advanced_exploitation", "attack_chains", "post_exploit"],
        dependencies=["RedTeamAgent"],
        provides=[DiscoveryType.EXPLOIT_SUCCESS, DiscoveryType.ATTACK_PATH],
        consumes=[DiscoveryType.VULNERABILITY, DiscoveryType.CREDENTIAL, DiscoveryType.SERVICE],
        priority=4
    ))

    return graph
