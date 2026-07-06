"""
Scope Management System
Prevents testing of out-of-scope targets and enforces boundaries.
"""

import json
import ipaddress
from pathlib import Path
from typing import List, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse
from loguru import logger


def extract_domain_from_target(target: str) -> str:
    """
    Extract domain/IP from various target formats.
    Handles: URLs, domains, IPs, ports
    
    Examples:
        https://example.com:443 → example.com
        http://192.168.1.1:8080 → 192.168.1.1
        example.com:443 → example.com
        sub.example.com → sub.example.com
    """
    target = target.strip().lower()
    
    # Handle URLs with protocol
    if target.startswith(('http://', 'https://', 'ftp://', 'ssh://')):
        parsed = urlparse(target)
        # Get hostname (removes port automatically)
        domain = parsed.hostname or parsed.netloc.split(':')[0]
        return domain.lower()
    
    # Handle domain:port or IP:port
    if ':' in target and not target.startswith('['):
        # Not IPv6, likely port notation
        domain = target.split(':')[0]
        return domain.lower()
    
    # Handle IPv6 with brackets
    if target.startswith('[') and ']' in target:
        # Extract IPv6 from brackets
        return target.split(']')[0] + ']'
    
    # Already clean domain or IP
    return target


@dataclass
class ScopeEntry:
    """A scope entry (domain, IP, or CIDR)."""
    target: str
    scope_type: str  # "in" or "out"
    added_at: str = ""
    notes: str = ""
    program_url: str = ""
    platform: str = ""
    allowed_testing: str = ""
    excluded_tests: str = ""
    rate_limits: str = ""
    last_verified: str = ""
    
    def __post_init__(self):
        if not self.added_at:
            self.added_at = datetime.now().isoformat()


@dataclass 
class ScopeConfig:
    """Scope configuration for a session."""
    in_scope: List[ScopeEntry] = field(default_factory=list)
    out_of_scope: List[ScopeEntry] = field(default_factory=list)
    strict_mode: bool = False  # Allow all targets by default for pentesting
    prompt_unknown: bool = False  # Don't prompt for unknown targets


class ScopeManager:
    """
    Manages testing scope to prevent unauthorized access.
    
    Features:
    - Domain/subdomain matching
    - IP and CIDR range support
    - Strict mode enforcement
    - Interactive prompts for unknown targets
    """
    
    def __init__(self, config_path: str = "./.scope.json"):
        self.config_path = Path(config_path)
        self.config = ScopeConfig()
        self._cache: Set[str] = set()  # Cache of approved targets
        self._denied: Set[str] = set()  # Cache of denied targets
        self._load_config()
    
    def _load_config(self):
        """Load scope config from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    data = json.load(f)
                    self.config = ScopeConfig(
                        in_scope=[ScopeEntry(**e) for e in data.get("in_scope", [])],
                        out_of_scope=[ScopeEntry(**e) for e in data.get("out_of_scope", [])],
                        strict_mode=data.get("strict_mode", False),  # Default to permissive for pentesting
                        prompt_unknown=data.get("prompt_unknown", False)  # Don't prompt by default
                    )
            except Exception as e:
                logger.warning(f"Failed to load scope config: {e}")
    
    def _save_config(self):
        """Save scope config to file."""
        try:
            data = {
                "in_scope": [asdict(e) for e in self.config.in_scope],
                "out_of_scope": [asdict(e) for e in self.config.out_of_scope],
                "strict_mode": self.config.strict_mode,
                "prompt_unknown": self.config.prompt_unknown
            }
            with open(self.config_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save scope config: {e}")
    
    def add_scope(self, target: str, scope_type: str = "in", notes: str = "",
                  program_url: str = "", platform: str = "",
                  allowed_testing: str = "", excluded_tests: str = "",
                  rate_limits: str = "", last_verified: str = "") -> str:
        """
        Add a target to scope.
        
        Args:
            target: Domain, IP, or CIDR (can include protocol like http://example.com)
            scope_type: "in" or "out"
            notes: Optional notes
        
        Returns:
            Confirmation message
        """
        # CRITICAL FIX: Normalize target to extract domain before storing
        # This ensures "http://example.com" and "example.com" are treated the same
        normalized_target = extract_domain_from_target(target).lower()
        entry = ScopeEntry(
            target=normalized_target,
            scope_type=scope_type,
            notes=notes,
            program_url=program_url,
            platform=platform,
            allowed_testing=allowed_testing,
            excluded_tests=excluded_tests,
            rate_limits=rate_limits,
            last_verified=last_verified or datetime.now().isoformat(),
        )
        
        if scope_type == "in":
            # Remove from out-of-scope if present
            self.config.out_of_scope = [e for e in self.config.out_of_scope if e.target != normalized_target]
            # Add to in-scope
            existing = next((e for e in self.config.in_scope if e.target == normalized_target), None)
            if existing:
                existing.notes = notes or existing.notes
                existing.program_url = program_url or existing.program_url
                existing.platform = platform or existing.platform
                existing.allowed_testing = allowed_testing or existing.allowed_testing
                existing.excluded_tests = excluded_tests or existing.excluded_tests
                existing.rate_limits = rate_limits or existing.rate_limits
                existing.last_verified = last_verified or existing.last_verified
            else:
                self.config.in_scope.append(entry)
        else:
            # Remove from in-scope if present
            self.config.in_scope = [e for e in self.config.in_scope if e.target != normalized_target]
            # Add to out-of-scope
            existing = next((e for e in self.config.out_of_scope if e.target == normalized_target), None)
            if existing:
                existing.notes = notes or existing.notes
                existing.program_url = program_url or existing.program_url
                existing.platform = platform or existing.platform
                existing.excluded_tests = excluded_tests or existing.excluded_tests
                existing.last_verified = last_verified or existing.last_verified
            else:
                self.config.out_of_scope.append(entry)
        
        self._save_config()
        self._cache.clear()  # Clear cache on scope change
        self._denied.clear()
        
        return f"✅ Added '{normalized_target}' to {'IN-SCOPE' if scope_type == 'in' else 'OUT-OF-SCOPE'}"
    
    def remove_scope(self, target: str) -> str:
        """Remove a target from all scope lists."""
        # Normalize target for consistent matching
        normalized_target = extract_domain_from_target(target).lower()
        initial_in = len(self.config.in_scope)
        initial_out = len(self.config.out_of_scope)
        
        self.config.in_scope = [e for e in self.config.in_scope if e.target != normalized_target]
        self.config.out_of_scope = [e for e in self.config.out_of_scope if e.target != normalized_target]
        
        if len(self.config.in_scope) < initial_in or len(self.config.out_of_scope) < initial_out:
            self._save_config()
            return f"✅ Removed '{normalized_target}' from scope"
        return f"⚠️ '{normalized_target}' was not in scope"
    
    def clear_scope(self) -> str:
        """Clear all scope entries."""
        self.config.in_scope = []
        self.config.out_of_scope = []
        self._cache.clear()
        self._denied.clear()
        self._save_config()
        return "✅ Scope cleared"
    
    def _matches_entry(self, target: str, entry: ScopeEntry) -> bool:
        """Check if a target matches a scope entry."""
        target = target.lower()
        scope_target = entry.target.lower()
        
        # Exact match
        if target == scope_target:
            return True
        
        # Wildcard domain (*.example.com matches sub.example.com)
        if scope_target.startswith("*."):
            domain = scope_target[2:]
            if target.endswith(domain) or target == domain.lstrip("."):
                return True
        
        # Subdomain match (example.com matches *.example.com)
        if target.endswith("." + scope_target):
            return True
        
        # IP/CIDR matching (IPv4 and IPv6)
        try:
            # Check if target is an IP (v4 or v6)
            target_ip = ipaddress.ip_address(target)
            
            # Check if entry is CIDR
            if "/" in scope_target:
                network = ipaddress.ip_network(scope_target, strict=False)
                if target_ip in network:
                    return True
            else:
                # Direct IP comparison
                scope_ip = ipaddress.ip_address(scope_target)
                if target_ip == scope_ip:
                    return True
        except ValueError:
            pass  # Not an IP address
        
        # IPv6 bracket notation handling (e.g., [::1] or [2001:db8::1])
        if target.startswith('[') and target.endswith(']'):
            try:
                ipv6 = target[1:-1]  # Remove brackets
                target_ip = ipaddress.ip_address(ipv6)
                
                if "/" in scope_target:
                    network = ipaddress.ip_network(scope_target.strip('[]'), strict=False)
                    if target_ip in network:
                        return True
                else:
                    scope_clean = scope_target.strip('[]')
                    scope_ip = ipaddress.ip_address(scope_clean)
                    if target_ip == scope_ip:
                        return True
            except ValueError:
                pass
        
        return False
    
    def is_in_scope(self, target: str) -> bool:
        """Check if a target is in scope."""
        # Normalize target (extract domain from URL if needed)
        target = extract_domain_from_target(target)
        
        # Check cache
        if target in self._cache:
            return True
        if target in self._denied:
            return False
        
        # Check out-of-scope first (takes priority)
        for entry in self.config.out_of_scope:
            if self._matches_entry(target, entry):
                self._denied.add(target)
                return False
        
        # Check in-scope
        for entry in self.config.in_scope:
            if self._matches_entry(target, entry):
                self._cache.add(target)
                return True
        
        # If no scope defined, consider in-scope (first target sets scope)
        if not self.config.in_scope and not self.config.out_of_scope:
            return True
        
        # Unknown target - depends on strict mode
        return not self.config.strict_mode
    
    def check_and_prompt(self, target: str) -> tuple[bool, str]:
        """
        Check if target is in scope, prompt if unknown.
        
        Returns:
            (allowed, message)
        """
        # Normalize target (extract domain from URL if needed)
        target = extract_domain_from_target(target)
        target = target.lower()
        
        # Check out-of-scope
        for entry in self.config.out_of_scope:
            if self._matches_entry(target, entry):
                return False, f"🚫 BLOCKED: '{target}' is OUT OF SCOPE"
        
        # Check in-scope
        for entry in self.config.in_scope:
            if self._matches_entry(target, entry):
                return True, f"✅ '{target}' is in scope"
        
        # No scope defined - auto-add first target
        if not self.config.in_scope and not self.config.out_of_scope:
            self.add_scope(target, "in")
            return True, f"✅ Auto-added '{target}' to scope (first target)"
        
        # Unknown target
        if self.config.strict_mode:
            return False, f"⚠️ '{target}' is not in defined scope. Use 'scope add {target} in' to add."
        else:
            return True, f"⚠️ '{target}' not explicitly scoped (non-strict mode)"
    
    def get_status(self) -> str:
        """Get formatted scope status."""
        lines = [
            "╔══════════════════════════════════════════════════════════════",
            "║ 🎯 SCOPE CONFIGURATION",
            "╠══════════════════════════════════════════════════════════════"
        ]
        
        # Settings
        mode = "STRICT" if self.config.strict_mode else "PERMISSIVE"
        lines.append(f"║ Mode: {mode}")
        
        # In-scope
        lines.append("╠══════════════════════════════════════════════════════════════")
        lines.append("║ ✅ IN-SCOPE:")
        if self.config.in_scope:
            for entry in self.config.in_scope:
                lines.append(f"║   • {entry.target}")
        else:
            lines.append("║   (none defined)")
        
        # Out-of-scope
        lines.append("╠══════════════════════════════════════════════════════════════")
        lines.append("║ 🚫 OUT-OF-SCOPE:")
        if self.config.out_of_scope:
            for entry in self.config.out_of_scope:
                lines.append(f"║   • {entry.target}")
        else:
            lines.append("║   (none defined)")
        
        lines.append("╚══════════════════════════════════════════════════════════════")
        
        return "\n".join(lines)
    
    def set_strict_mode(self, enabled: bool) -> str:
        """Enable or disable strict mode."""
        self.config.strict_mode = enabled
        self._save_config()
        mode = "STRICT" if enabled else "PERMISSIVE"
        return f"✅ Scope mode set to {mode}"


# Global instance
_scope_manager: Optional[ScopeManager] = None


def get_scope_manager() -> ScopeManager:
    """Get or create the global scope manager."""
    global _scope_manager
    if _scope_manager is None:
        _scope_manager = ScopeManager()
    return _scope_manager


def check_scope(target: str) -> tuple[bool, str]:
    """Quick check if target is in scope."""
    return get_scope_manager().check_and_prompt(target)
