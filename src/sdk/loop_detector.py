"""
Smart Loop Detection with Context Awareness

Detects infinite loops and unproductive patterns in agent execution.
Provides early termination conditions when no progress is made.
"""

import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from loguru import logger
from urllib.parse import urlparse


@dataclass
class ToolCall:
    """Represents a single tool call with context."""
    tool_name: str
    args: Dict
    timestamp: float
    result_hash: Optional[str] = None  # Hash of result for comparison
    success: bool = True
    result_snippet: str = ""  # First ~200 chars of result for pattern detection
    
    def signature(self) -> str:
        """Generate a unique signature for this tool call."""
        args_str = json.dumps(self.args, sort_keys=True)
        return f"{self.tool_name}:{args_str}"
    
    def is_similar_to(self, other: 'ToolCall', time_window: float = 60.0) -> bool:
        """Check if this call is similar to another within a time window."""
        if self.tool_name != other.tool_name:
            return False
        
        # Check if within time window
        if abs(self.timestamp - other.timestamp) > time_window:
            return False
        
        # Check if args are identical
        return self.signature() == other.signature()


@dataclass
class LoopPattern:
    """Detected loop pattern."""
    pattern_type: str  # 'exact_repeat', 'alternating', 'no_progress', 'error_loop'
    tool_names: List[str]
    repeat_count: int
    confidence: float  # 0.0 to 1.0
    suggestion: str
    first_seen: float
    last_seen: float


class SmartLoopDetector:
    """
    Intelligent loop detection with context awareness.
    
    Detects:
    - Exact repeated tool calls (same tool, same args)
    - Alternating patterns (A -> B -> A -> B)
    - No-progress loops (tools running but no new findings)
    - Error loops (same tool failing repeatedly)
    - Delegation loops (agent A -> agent B -> agent A)
    """
    
    # Tools that are expected to be called multiple times with different args
    # These tools should only trigger loop detection if called with IDENTICAL args
    EXPLORATORY_TOOLS = {
        'curl_request',
        'http_request',
        'browser_visit',
        'browser_extract_forms',
        'http_fuzz',
        'sqli_scanner',
        'xss_scanner',
        'directory_scan',
        'parameter_discovery',
        'endpoint_probe',
        'api_test',
        'fuzzing',
        'manual_test',
        'custom_request',
        'web_probe',
        'url_test',
        # Scan / enumeration tools that may be re-run with tweaked args
        'full_appsec_scan',
        'dirsearch_scan',
        'gobuster_scan',
        'nuclei_scan',
        'wpscan',
        'nikto_scan',
        'ffuf_fuzz',
        'nmap_scan',
        'subfinder_enum',
        # Shell/CTF tools — called many times per session with different commands
        'ctf_command',
        'interactive_bash',
    }
    
    def __init__(
        self,
        max_exact_repeats: int = 3,
        max_alternating_cycles: int = 4,
        no_progress_threshold: int = 80,
        time_window: float = 300.0  # 5 minutes
    ):
        self.max_exact_repeats = max_exact_repeats
        self.max_alternating_cycles = max_alternating_cycles
        self.no_progress_threshold = no_progress_threshold
        self.time_window = time_window
        
        # Track all tool calls
        self.call_history: List[ToolCall] = []
        
        # Track findings to detect progress
        self.findings_count = 0
        self.last_progress_iteration = 0
        
        # Track errors
        self.error_counts: Dict[str, int] = defaultdict(int)
        
        # Detected patterns
        self.detected_patterns: List[LoopPattern] = []
    
    # Indicators that a tool result means "connection dropped / no response"
    CONNECTION_DROP_INDICATORS = [
        "no response received",
        "timed out",
        "connection timed out",
        "connection refused",
        "connection reset",
        "no route to host",
        "network is unreachable",
        "name or service not known",
        "operation now in progress",  # nc timeout message
    ]

    def record_call(
        self,
        tool_name: str,
        args: Dict,
        success: bool = True,
        result_hash: Optional[str] = None,
        result_snippet: str = "",
    ) -> Optional[LoopPattern]:
        """
        Record a tool call and check for loop patterns.
        
        Args:
            result_snippet: First ~200 chars of the tool result, used for
                            connection-drop / IP-ban detection.
        
        Returns:
            LoopPattern if a loop is detected, None otherwise
        """
        call = ToolCall(
            tool_name=tool_name,
            args=args,
            timestamp=time.time(),
            result_hash=result_hash,
            success=success,
            result_snippet=result_snippet[:300] if result_snippet else "",
        )
        
        self.call_history.append(call)
        
        # Track errors
        if not success:
            self.error_counts[tool_name] += 1
        
        # Check for various loop patterns
        pattern = self._detect_patterns(call)
        
        if pattern:
            self.detected_patterns.append(pattern)
            logger.warning(
                f"Loop detected: {pattern.pattern_type} - {pattern.tool_names} "
                f"(confidence: {pattern.confidence:.2f})"
            )
        
        return pattern
    
    def record_finding(self, iteration: int):
        """Record that a new finding was discovered."""
        self.findings_count += 1
        self.last_progress_iteration = iteration
    
    def check_progress(self, current_iteration: int) -> Optional[LoopPattern]:
        """
        Check if progress is being made.
        
        Returns:
            LoopPattern if no progress detected, None otherwise
        """
        iterations_since_progress = current_iteration - self.last_progress_iteration
        
        if iterations_since_progress >= self.no_progress_threshold:
            # Check if tools are running but producing no results
            recent_calls = self._get_recent_calls(window=60.0)
            
            if len(recent_calls) >= 10:  # Increased from 3 to 10
                return LoopPattern(
                    pattern_type='no_progress',
                    tool_names=[c.tool_name for c in recent_calls[-3:]],
                    repeat_count=iterations_since_progress,
                    confidence=0.8,
                    suggestion=(
                        f"No new findings in {iterations_since_progress} iterations. "
                        "Consider changing approach or target."
                    ),
                    first_seen=recent_calls[0].timestamp,
                    last_seen=recent_calls[-1].timestamp
                )
        
        return None
    
    def _detect_patterns(self, current_call: ToolCall) -> Optional[LoopPattern]:
        """Detect various loop patterns."""
        
        # 0. Connection-drop / IP-ban detection (highest priority)
        ban_pattern = self._detect_connection_drop(current_call)
        if ban_pattern:
            return ban_pattern
        
        # 1. Exact repeat detection
        exact_pattern = self._detect_exact_repeats(current_call)
        if exact_pattern:
            return exact_pattern
        
        # 2. Alternating pattern detection
        alternating_pattern = self._detect_alternating(current_call)
        if alternating_pattern:
            return alternating_pattern
        
        # 3. Error loop detection
        error_pattern = self._detect_error_loop(current_call)
        if error_pattern:
            return error_pattern
        
        # 4. Delegation loop detection
        delegation_pattern = self._detect_delegation_loop(current_call)
        if delegation_pattern:
            return delegation_pattern
        
        return None
    
    def _detect_exact_repeats(self, current_call: ToolCall) -> Optional[LoopPattern]:
        """Detect exact repeated tool calls."""
        recent_calls = self._get_recent_calls(window=self.time_window)
        
        # Determine threshold based on tool type
        is_exploratory = current_call.tool_name in self.EXPLORATORY_TOOLS
        threshold = 10 if is_exploratory else self.max_exact_repeats
        
        # Count how many times this exact call appears
        signature = current_call.signature()
        repeat_count = sum(1 for c in recent_calls if c.signature() == signature)
        
        # For exploratory tools, only flag if IDENTICAL args repeated many times
        # For other tools, flag after fewer repeats
        if repeat_count >= threshold:
            confidence = 0.7 if is_exploratory else 1.0
            tool_type = "exploratory tool" if is_exploratory else "tool"
            
            return LoopPattern(
                pattern_type='exact_repeat',
                tool_names=[current_call.tool_name],
                repeat_count=repeat_count,
                confidence=confidence,
                suggestion=(
                    f"{tool_type.capitalize()} '{current_call.tool_name}' called {repeat_count} times with "
                    "identical arguments. Try different parameters or a different tool."
                ),
                first_seen=recent_calls[0].timestamp,
                last_seen=current_call.timestamp
            )
        
        return None
    
    def _detect_alternating(self, current_call: ToolCall) -> Optional[LoopPattern]:
        """Detect alternating patterns (A -> B -> A -> B)."""
        if len(self.call_history) < 4:
            return None
        
        recent = self.call_history[-4:]
        
        # Check for A-B-A-B pattern
        if (recent[0].tool_name == recent[2].tool_name and
            recent[1].tool_name == recent[3].tool_name and
            recent[0].tool_name != recent[1].tool_name):
            
            # Count how many times this pattern repeats
            pattern_tools = [recent[0].tool_name, recent[1].tool_name]
            cycle_count = self._count_alternating_cycles(pattern_tools)
            
            # Check if any of the tools are exploratory
            has_exploratory = any(tool in self.EXPLORATORY_TOOLS for tool in pattern_tools)
            
            # Be more lenient with exploratory tools - they may alternate naturally
            threshold = 5 if has_exploratory else self.max_alternating_cycles
            confidence = 0.6 if has_exploratory else 0.9
            
            if cycle_count >= threshold:
                return LoopPattern(
                    pattern_type='alternating',
                    tool_names=pattern_tools,
                    repeat_count=cycle_count,
                    confidence=confidence,
                    suggestion=(
                        f"Alternating between {pattern_tools[0]} and {pattern_tools[1]} "
                        f"{cycle_count} times. This suggests a dependency issue or "
                        "incorrect tool selection."
                    ),
                    first_seen=recent[0].timestamp,
                    last_seen=current_call.timestamp
                )
        
        return None
    
    def _detect_error_loop(self, current_call: ToolCall) -> Optional[LoopPattern]:
        """Detect repeated failures of the same tool."""
        if current_call.success:
            return None
        
        error_count = self.error_counts[current_call.tool_name]
        
        if error_count >= 3:
            return LoopPattern(
                pattern_type='error_loop',
                tool_names=[current_call.tool_name],
                repeat_count=error_count,
                confidence=0.95,
                suggestion=(
                    f"Tool '{current_call.tool_name}' has failed {error_count} times. "
                    "The tool may not be installed, configured incorrectly, or "
                    "incompatible with the target. Try an alternative tool."
                ),
                first_seen=self.call_history[0].timestamp,
                last_seen=current_call.timestamp
            )
        
        return None
    
    def _detect_connection_drop(self, current_call: ToolCall) -> Optional[LoopPattern]:
        """
        Detect consecutive connection drops / timeouts that indicate an IP ban.
        
        If the last N tool calls all returned "No response received" or similar
        timeout/drop indicators, the target has likely banned our IP via WAF/IPS.
        This prevents the agent from mindlessly running 30+ tools into the void.
        """
        # Only check network-facing tools, not planning/delegation tools
        _NETWORK_TOOLS = {
            'curl_request', 'http_request', 'wget_download',
            'whatweb_scan', 'nuclei_scan', 'feroxbuster_scan',
            'gobuster_scan', 'dirsearch_scan', 'nc_connect', 'nc_scan',
            'nmap_scan', 'nmap_service_scan', 'nmap_discover',
            'sslscan_check', 'wafw00f_detect', 'hydra_bruteforce',
            'arjun_scan', 'browser_visit', 'naabu_port_scan',
        }
        if current_call.tool_name not in _NETWORK_TOOLS:
            return None
        
        # Check if the current call's result indicates a connection drop
        snippet_lower = current_call.result_snippet.lower()
        is_drop = any(ind in snippet_lower for ind in self.CONNECTION_DROP_INDICATORS)
        if not is_drop:
            return None

        current_endpoint = self._network_endpoint(current_call)
        if current_endpoint:
            had_prior_success = any(
                self._network_endpoint(call) == current_endpoint
                and not any(ind in call.result_snippet.lower() for ind in self.CONNECTION_DROP_INDICATORS)
                for call in self.call_history[:-1]
                if call.tool_name in _NETWORK_TOOLS
            )
            if not had_prior_success:
                return None

        # Count consecutive connection drops from the tail of call_history
        # (only counting network tools, skipping non-network tools like register_service)
        consecutive_drops = 0
        drop_calls: List[ToolCall] = []
        for call in reversed(self.call_history):
            if call.tool_name not in _NETWORK_TOOLS:
                continue  # skip non-network tools
            if current_endpoint and self._network_endpoint(call) != current_endpoint:
                continue
            call_snippet = call.result_snippet.lower()
            if any(ind in call_snippet for ind in self.CONNECTION_DROP_INDICATORS):
                consecutive_drops += 1
                drop_calls.append(call)
            else:
                break  # found a successful network call, stop counting
        
        # Trigger after 3 consecutive network-tool drops
        if consecutive_drops >= 3:
            return LoopPattern(
                pattern_type='connection_drop_ip_ban',
                tool_names=[current_call.tool_name],
                repeat_count=consecutive_drops,
                confidence=0.95,
                suggestion=(
                    f"⚠️ PROBABLE IP BAN: {consecutive_drops} consecutive network tools "
                    f"returned 'No response' / timeout. The target's WAF/IPS has likely "
                    f"blocked our IP. STOP all loud scanning immediately. Options:\n"
                    f"  1. Wait 10-15 minutes for the ban to expire\n"
                    f"  2. Switch to a different source IP / VPN\n"
                    f"  3. Use stealthier techniques (slower rate, different User-Agent)\n"
                    f"  4. Report current findings and move on"
                ),
                first_seen=drop_calls[-1].timestamp if drop_calls else current_call.timestamp,
                last_seen=current_call.timestamp,
            )
        
        return None

    def _network_endpoint(self, call: ToolCall) -> Optional[str]:
        """Return a stable host:port-ish endpoint key for network calls."""
        args = call.args or {}

        url = args.get("url") or args.get("base_url") or args.get("target_url")
        if isinstance(url, str) and url:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            if parsed.hostname:
                port = parsed.port
                if port is None:
                    port = 443 if parsed.scheme == "https" else 80
                return f"{parsed.hostname.lower()}:{port}"

        host = args.get("host") or args.get("target") or args.get("ip")
        port = args.get("port")
        if isinstance(host, str) and host:
            host = host.split("://", 1)[-1].split("/", 1)[0].lower()
            if port:
                return f"{host}:{port}"
            return host

        return None
    
    def _detect_delegation_loop(self, current_call: ToolCall) -> Optional[LoopPattern]:
        """Detect delegation loops (agent A delegates to B, B delegates back to A)."""
        if not current_call.tool_name.startswith('delegate_to_'):
            return None
        
        recent_delegations = [
            c for c in self.call_history[-10:]
            if c.tool_name.startswith('delegate_to_')
        ]
        
        if len(recent_delegations) < 3:
            return None
        
        # Check for A -> B -> A pattern
        if len(recent_delegations) >= 3:
            last_three = recent_delegations[-3:]
            if (last_three[0].tool_name == last_three[2].tool_name and
                last_three[0].tool_name != last_three[1].tool_name):
                
                return LoopPattern(
                    pattern_type='delegation_loop',
                    tool_names=[c.tool_name for c in last_three],
                    repeat_count=3,
                    confidence=0.85,
                    suggestion=(
                        "Delegation loop detected. Agents are passing tasks back and forth. "
                        "The orchestrator should handle this task directly or provide "
                        "more specific instructions."
                    ),
                    first_seen=last_three[0].timestamp,
                    last_seen=current_call.timestamp
                )
        
        return None
    
    def _count_alternating_cycles(self, pattern_tools: List[str]) -> int:
        """Count how many times an alternating pattern repeats."""
        if len(self.call_history) < 4:
            return 0
        
        count = 0
        i = len(self.call_history) - 1
        
        while i >= 1:
            if (self.call_history[i].tool_name == pattern_tools[1] and
                self.call_history[i-1].tool_name == pattern_tools[0]):
                count += 1
                i -= 2
            else:
                break
        
        return count
    
    def _get_recent_calls(self, window: float) -> List[ToolCall]:
        """Get tool calls within the time window."""
        cutoff = time.time() - window
        return [c for c in self.call_history if c.timestamp >= cutoff]
    
    def _get_unique_arg_sets(self, tool_name: str, window: float = None) -> int:
        """
        Count unique argument sets for a specific tool.
        Useful for understanding if exploratory tools are actually exploring.
        """
        calls = self.call_history if window is None else self._get_recent_calls(window)
        tool_calls = [c for c in calls if c.tool_name == tool_name]
        
        # Get unique signatures (tool_name:args)
        unique_signatures = set(c.signature() for c in tool_calls)
        return len(unique_signatures)
    
    def should_terminate(self, current_iteration: int, max_iterations: int) -> Tuple[bool, str]:
        """
        Determine if execution should terminate early.
        
        Returns:
            (should_terminate, reason)
        """
        # Check for critical loop patterns
        if self.detected_patterns:
            latest_pattern = self.detected_patterns[-1]
            
            # Only terminate on delegation loops, error loops, IP bans, or no progress
            # (structural problems). exact_repeat and alternating patterns are handled
            # per-call in the runner (the call is skipped, but the session continues).
            if latest_pattern.confidence >= 0.9 and latest_pattern.pattern_type in (
                'delegation_loop', 'error_loop', 'no_progress',
                'connection_drop_ip_ban',
            ):
                return True, latest_pattern.suggestion
        
        # Check for no progress — but only if we've had truly zero activity
        no_progress = self.check_progress(current_iteration)
        if no_progress:
            return True, no_progress.suggestion
        
        # Removed the aggressive "50% iterations with < 2 findings" check.
        # Reconnaissance phases naturally produce few extractable findings
        # (tool results are informational, not vulnerability-specific).
        
        return False, ""
    
    def get_summary(self) -> Dict:
        """Get a summary of detected patterns."""
        # Get exploratory tool stats
        exploratory_stats = {}
        for tool in self.EXPLORATORY_TOOLS:
            tool_calls = [c for c in self.call_history if c.tool_name == tool]
            if tool_calls:
                unique_args = self._get_unique_arg_sets(tool)
                exploratory_stats[tool] = {
                    'total_calls': len(tool_calls),
                    'unique_arg_sets': unique_args,
                    'exploration_ratio': unique_args / len(tool_calls) if tool_calls else 0
                }
        
        return {
            'total_calls': len(self.call_history),
            'unique_tools': len(set(c.tool_name for c in self.call_history)),
            'findings_count': self.findings_count,
            'patterns_detected': len(self.detected_patterns),
            'exploratory_tool_stats': exploratory_stats,
            'patterns': [
                {
                    'type': p.pattern_type,
                    'tools': p.tool_names,
                    'repeats': p.repeat_count,
                    'confidence': p.confidence,
                    'suggestion': p.suggestion
                }
                for p in self.detected_patterns
            ],
            'error_counts': dict(self.error_counts)
        }
    
    def reset(self):
        """Reset the detector state."""
        self.call_history.clear()
        self.findings_count = 0
        self.last_progress_iteration = 0
        self.error_counts.clear()
        self.detected_patterns.clear()


# Global instance
_loop_detector: Optional[SmartLoopDetector] = None


def get_loop_detector() -> SmartLoopDetector:
    """Get or create the global loop detector instance."""
    global _loop_detector
    if _loop_detector is None:
        _loop_detector = SmartLoopDetector()
    return _loop_detector


def reset_loop_detector():
    """Reset the global loop detector."""
    global _loop_detector
    if _loop_detector:
        _loop_detector.reset()
