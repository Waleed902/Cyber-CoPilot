"""
Smart Retry and Failure Recovery System

Provides intelligent retry strategies when tools fail:
- Alternative tool suggestions
- Parameter adjustment
- Fallback strategies
- Learning from failures
"""

import asyncio
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum
from loguru import logger


class FailureReason(Enum):
    """Categorized failure reasons."""
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    TOOL_NOT_FOUND = "tool_not_found"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMITED = "rate_limited"
    INVALID_TARGET = "invalid_target"
    NO_RESULTS = "no_results"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass
class FailureContext:
    """Context about a tool failure."""
    tool_name: str
    target: str
    error: str
    reason: FailureReason
    args: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    retry_count: int = 0


@dataclass
class RecoveryStrategy:
    """A strategy to recover from failure."""
    strategy_type: str  # alternative_tool, adjust_params, fallback, manual
    description: str
    confidence: float  # 0.0 to 1.0
    tool_name: Optional[str] = None
    new_args: Optional[Dict] = None
    wait_time: int = 0  # seconds to wait before retry
    reason: str = ""


# Tool alternatives mapping
TOOL_ALTERNATIVES = {
    # Subdomain enumeration alternatives
    "subfinder_enum": ["sublist3r_enum", "amass_enum", "dnsrecon_enum"],
    "sublist3r_enum": ["subfinder_enum", "amass_enum", "dnsrecon_enum"],
    "amass_enum": ["subfinder_enum", "sublist3r_enum", "dnsrecon_enum"],
    
    # Port scanning alternatives
    "nmap_scan": ["masscan_scan", "rustscan"],
    
    # Directory bruteforce alternatives
    "ffuf_fuzz": ["feroxbuster_scan", "gobuster_scan", "dirsearch_scan"],
    "feroxbuster_scan": ["ffuf_fuzz", "gobuster_scan", "dirsearch_scan"],
    
    # Web crawling alternatives
    "katana_crawl": ["hakrawler", "gospider", "gau_urls"],
    "hakrawler": ["katana_crawl", "gospider", "gau_urls"],
    
    # JavaScript analysis alternatives
    "linkfinder_js": ["jsparser_analyze", "secretfinder_js"],
    "jsparser_analyze": ["linkfinder_js", "secretfinder_js"],
    
    # Parameter discovery alternatives
    "arjun_params": ["paramspider", "param_miner"],
    "paramspider": ["arjun_params", "param_miner"],
    
    # URL discovery alternatives
    "gau_urls": ["waybackurls", "katana_crawl"],
    "waybackurls": ["gau_urls", "katana_crawl"],
    
    # Technology detection alternatives
    "httpx_tech_detect": ["wappalyzer_scan", "whatweb_scan"],
    "wappalyzer_scan": ["httpx_tech_detect", "whatweb_scan"],
    
    # DNS tools alternatives
    "dig_lookup": ["host_lookup", "nslookup_query"],
    "dnsrecon_enum": ["dig_lookup", "dnsenum"],
    
    # SQL injection alternatives
    "sqlmap_scan": ["sqli_manual", "nosql_injection_check"],
    
    # XSS alternatives
    "xss_scan": ["dalfox_xss", "kxss", "xsstrike"],
}

# Parameter adjustments for common failures
PARAMETER_ADJUSTMENTS = {
    FailureReason.TIMEOUT: {
        "timeout": lambda x: x * 2,  # Double timeout
        "threads": lambda x: max(1, x // 2),  # Halve threads
        "rate_limit": lambda x: max(1, x // 2),  # Reduce rate
    },
    FailureReason.RATE_LIMITED: {
        "delay": lambda x: (x or 0) + 2,  # Add delay
        "threads": lambda x: max(1, x // 4),  # Reduce threads significantly
        "rate_limit": lambda x: max(1, (x or 100) // 4),
    },
    FailureReason.BLOCKED: {
        "use_proxy": lambda x: True,
        "user_agent": lambda x: "random",
        "delay": lambda x: (x or 0) + 5,
    },
    FailureReason.CONNECTION_ERROR: {
        "timeout": lambda x: (x or 30) + 15,
        "retries": lambda x: (x or 1) + 2,
        "verify_ssl": lambda x: False,
    },
}


class FailureRecoveryEngine:
    """
    Engine for intelligent failure recovery.
    
    Features:
    - Categorizes failures
    - Suggests alternative tools
    - Adjusts parameters
    - Learns from patterns
    - Tracks success rates
    """
    
    def __init__(self):
        self.failure_history: List[FailureContext] = []
        self.success_rates: Dict[str, Dict] = defaultdict(lambda: {"success": 0, "failure": 0})
        self.recovery_results: Dict[str, List[bool]] = defaultdict(list)
        self.callbacks: List[Callable] = []
    
    def categorize_failure(self, error: str) -> FailureReason:
        """Categorize the failure based on error message."""
        error_lower = error.lower()
        
        if any(x in error_lower for x in ["timeout", "timed out"]):
            return FailureReason.TIMEOUT
        
        if any(x in error_lower for x in ["connection refused", "connection error", "network unreachable", "no route"]):
            return FailureReason.CONNECTION_ERROR
        
        if any(x in error_lower for x in ["not found", "not installed", "command not found", "no such file"]):
            return FailureReason.TOOL_NOT_FOUND
        
        if any(x in error_lower for x in ["permission denied", "access denied", "forbidden"]):
            return FailureReason.PERMISSION_DENIED
        
        if any(x in error_lower for x in ["rate limit", "too many requests", "429"]):
            return FailureReason.RATE_LIMITED
        
        if any(x in error_lower for x in ["invalid", "malformed", "bad request"]):
            return FailureReason.INVALID_TARGET
        
        if any(x in error_lower for x in ["no results", "empty", "not found"]):
            return FailureReason.NO_RESULTS
        
        if any(x in error_lower for x in ["blocked", "waf", "firewall", "captcha"]):
            return FailureReason.BLOCKED
        
        return FailureReason.UNKNOWN
    
    def record_failure(self, tool_name: str, target: str, error: str, 
                       args: Dict = None, retry_count: int = 0) -> FailureContext:
        """Record a tool failure."""
        reason = self.categorize_failure(error)
        
        context = FailureContext(
            tool_name=tool_name,
            target=target,
            error=error,
            reason=reason,
            args=args or {},
            retry_count=retry_count
        )
        
        self.failure_history.append(context)
        self.success_rates[tool_name]["failure"] += 1
        
        # Notify callbacks
        for callback in self.callbacks:
            try:
                callback("failure", context)
            except:
                pass
        
        return context
    
    def record_success(self, tool_name: str):
        """Record a tool success."""
        self.success_rates[tool_name]["success"] += 1
    
    def get_recovery_strategies(self, context: FailureContext, 
                                 max_strategies: int = 5) -> List[RecoveryStrategy]:
        """
        Generate recovery strategies for a failure.
        
        Args:
            context: The failure context
            max_strategies: Maximum strategies to return
        
        Returns:
            List of recovery strategies ordered by confidence
        """
        strategies = []
        
        # Strategy 1: Alternative tools
        if context.tool_name in TOOL_ALTERNATIVES:
            for alt_tool in TOOL_ALTERNATIVES[context.tool_name]:
                # Check success rate of alternative
                alt_stats = self.success_rates[alt_tool]
                total = alt_stats["success"] + alt_stats["failure"]
                
                if total > 0:
                    success_rate = alt_stats["success"] / total
                else:
                    success_rate = 0.5  # Unknown, assume average
                
                strategies.append(RecoveryStrategy(
                    strategy_type="alternative_tool",
                    description=f"Use {alt_tool} instead of {context.tool_name}",
                    confidence=success_rate,
                    tool_name=alt_tool,
                    reason=f"Alternative tool for {context.reason.value}"
                ))
        
        # Strategy 2: Parameter adjustments
        if context.reason in PARAMETER_ADJUSTMENTS:
            adjustments = PARAMETER_ADJUSTMENTS[context.reason]
            new_args = context.args.copy()
            
            for param, adjuster in adjustments.items():
                if param in new_args:
                    new_args[param] = adjuster(new_args[param])
                else:
                    # Add the parameter with default adjusted
                    new_args[param] = adjuster(None) if param in ["delay", "use_proxy", "verify_ssl"] else adjuster(30)
            
            strategies.append(RecoveryStrategy(
                strategy_type="adjust_params",
                description=f"Retry {context.tool_name} with adjusted parameters",
                confidence=0.6 if context.retry_count < 2 else 0.3,
                tool_name=context.tool_name,
                new_args=new_args,
                wait_time=5 if context.reason == FailureReason.RATE_LIMITED else 2,
                reason=f"Adjusted for {context.reason.value}"
            ))
        
        # Strategy 3: Wait and retry for rate limiting
        if context.reason == FailureReason.RATE_LIMITED:
            wait_time = min(60, 10 * (context.retry_count + 1))
            strategies.append(RecoveryStrategy(
                strategy_type="wait_retry",
                description=f"Wait {wait_time}s and retry {context.tool_name}",
                confidence=0.7 if context.retry_count < 3 else 0.4,
                tool_name=context.tool_name,
                new_args=context.args,
                wait_time=wait_time,
                reason="Rate limit cooldown"
            ))
        
        # Strategy 4: Tool not found - suggest installation
        if context.reason == FailureReason.TOOL_NOT_FOUND:
            strategies.append(RecoveryStrategy(
                strategy_type="install_tool",
                description=f"Install {context.tool_name} and retry",
                confidence=0.8,
                tool_name=context.tool_name,
                reason="Tool needs to be installed"
            ))
            
            # Add alternative that might be installed
            if context.tool_name in TOOL_ALTERNATIVES:
                strategies.append(RecoveryStrategy(
                    strategy_type="alternative_tool",
                    description="Use alternative tool that may be installed",
                    confidence=0.5,
                    tool_name=TOOL_ALTERNATIVES[context.tool_name][0],
                    reason="Original tool not installed"
                ))
        
        # Strategy 5: Blocked - use evasion
        if context.reason == FailureReason.BLOCKED:
            strategies.append(RecoveryStrategy(
                strategy_type="evasion",
                description=f"Retry {context.tool_name} with evasion techniques",
                confidence=0.5,
                tool_name=context.tool_name,
                new_args={
                    **context.args,
                    "use_proxy": True,
                    "random_agent": True,
                    "delay": 3
                },
                wait_time=10,
                reason="Apply evasion for WAF/firewall"
            ))
        
        # Strategy 6: No results - try broader search
        if context.reason == FailureReason.NO_RESULTS:
            strategies.append(RecoveryStrategy(
                strategy_type="broaden_search",
                description=f"Retry {context.tool_name} with broader scope",
                confidence=0.5,
                tool_name=context.tool_name,
                new_args={
                    **context.args,
                    "depth": context.args.get("depth", 1) + 1,
                    "aggressive": True
                },
                reason="Expand search scope"
            ))
        
        # Strategy 7: Manual intervention suggestion
        if context.retry_count >= 3:
            strategies.append(RecoveryStrategy(
                strategy_type="manual",
                description="Consider manual investigation",
                confidence=0.3,
                reason="Multiple automated attempts failed"
            ))
        
        # Sort by confidence
        strategies.sort(key=lambda x: x.confidence, reverse=True)
        
        return strategies[:max_strategies]
    
    def record_recovery_result(self, strategy: RecoveryStrategy, success: bool):
        """Record whether a recovery strategy worked."""
        key = f"{strategy.strategy_type}:{strategy.tool_name or 'none'}"
        self.recovery_results[key].append(success)
    
    def get_recommended_strategy(self, context: FailureContext) -> Optional[RecoveryStrategy]:
        """Get the single best recovery strategy."""
        strategies = self.get_recovery_strategies(context, max_strategies=1)
        return strategies[0] if strategies else None
    
    def should_retry(self, context: FailureContext, max_retries: int = 3) -> bool:
        """Determine if we should retry the tool."""
        if context.retry_count >= max_retries:
            return False
        
        # Don't retry if tool not found and no alternatives
        if context.reason == FailureReason.TOOL_NOT_FOUND:
            return context.tool_name in TOOL_ALTERNATIVES
        
        # Always retry at least once for transient errors
        if context.reason in [FailureReason.TIMEOUT, FailureReason.CONNECTION_ERROR, 
                              FailureReason.RATE_LIMITED]:
            return True
        
        return context.retry_count < 2
    
    def get_failure_summary(self) -> Dict:
        """Get a summary of all failures."""
        by_reason = defaultdict(int)
        by_tool = defaultdict(int)
        
        for failure in self.failure_history:
            by_reason[failure.reason.value] += 1
            by_tool[failure.tool_name] += 1
        
        return {
            "total_failures": len(self.failure_history),
            "by_reason": dict(by_reason),
            "by_tool": dict(by_tool),
            "recent_failures": [
                {
                    "tool": f.tool_name,
                    "reason": f.reason.value,
                    "time": f.timestamp.isoformat()
                }
                for f in self.failure_history[-5:]
            ]
        }
    
    def get_tool_reliability(self, tool_name: str) -> float:
        """Get the reliability (success rate) of a tool."""
        stats = self.success_rates[tool_name]
        total = stats["success"] + stats["failure"]
        
        if total == 0:
            return 1.0  # Unknown, assume reliable
        
        return stats["success"] / total
    
    def clear_history(self):
        """Clear failure history."""
        self.failure_history.clear()
    
    def add_callback(self, callback: Callable):
        """Add a callback for failure events."""
        self.callbacks.append(callback)


# Global instance
_recovery_engine: Optional[FailureRecoveryEngine] = None


def get_recovery_engine() -> FailureRecoveryEngine:
    """Get or create the global failure recovery engine."""
    global _recovery_engine
    if _recovery_engine is None:
        _recovery_engine = FailureRecoveryEngine()
    return _recovery_engine


async def execute_with_recovery(
    tool_func: Callable,
    tool_name: str,
    target: str,
    args: Dict,
    max_retries: int = 3,
    on_strategy: Callable = None
) -> Tuple[Any, List[RecoveryStrategy]]:
    """
    Execute a tool with automatic failure recovery.
    
    Args:
        tool_func: The tool function to execute
        tool_name: Name of the tool
        target: Target being scanned
        args: Tool arguments
        max_retries: Maximum retry attempts
        on_strategy: Callback when a recovery strategy is used
    
    Returns:
        Tuple of (result, strategies_used)
    """
    engine = get_recovery_engine()
    strategies_used = []
    current_args = args.copy()
    current_tool = tool_func
    current_name = tool_name
    retry_count = 0
    
    while retry_count <= max_retries:
        try:
            # Execute the tool
            result = await current_tool(**current_args)
            
            # Check if it was successful
            if hasattr(result, 'success') and result.success:
                engine.record_success(current_name)
                return result, strategies_used
            
            # Handle tool-level failure (success=False)
            error = getattr(result, 'error', 'Unknown error')
            
        except Exception as e:
            error = str(e)
        
        # Record failure
        context = engine.record_failure(
            tool_name=current_name,
            target=target,
            error=error,
            args=current_args,
            retry_count=retry_count
        )
        
        # Check if we should retry
        if not engine.should_retry(context, max_retries):
            break
        
        # Get recovery strategy
        strategy = engine.get_recommended_strategy(context)
        
        if strategy is None:
            break
        
        strategies_used.append(strategy)
        
        if on_strategy:
            on_strategy(strategy)
        
        # Apply strategy
        if strategy.strategy_type == "alternative_tool":
            # Try to get alternative tool function
            # This would need to be integrated with the tool registry
            logger.info(f"Recovery: Switching to {strategy.tool_name}")
            current_name = strategy.tool_name
            # Note: actual tool lookup would happen here
        
        elif strategy.strategy_type in ["adjust_params", "wait_retry", "evasion", "broaden_search"]:
            if strategy.new_args:
                current_args = strategy.new_args
            
            if strategy.wait_time > 0:
                logger.info(f"Recovery: Waiting {strategy.wait_time}s before retry")
                await asyncio.sleep(strategy.wait_time)
        
        elif strategy.strategy_type == "manual":
            # Stop automated retries
            break
        
        retry_count += 1
    
    # All retries exhausted
    return None, strategies_used
