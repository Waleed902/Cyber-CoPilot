"""
Type Hints & Validation System
Pydantic-based validation for tool arguments to prevent injection and ensure correctness.
"""

import re
import ipaddress
from typing import Optional, Dict, Union, Callable
from dataclasses import dataclass
from functools import wraps
from loguru import logger

try:
    from pydantic import BaseModel, Field, validator, root_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    logger.warning("Pydantic not installed. Install with: pip install pydantic")


# ============= VALIDATION MODELS =============

if PYDANTIC_AVAILABLE:
    
    class TargetValidator(BaseModel):
        """Base validator for target arguments."""
        target: str = Field(..., min_length=1, max_length=500)
        
        @validator('target')
        def validate_target(cls, v):
            """Prevent command injection in target."""
            dangerous_chars = [';', '|', '&', '$', '`', '>', '<', '\\', '\n', '\r']
            for char in dangerous_chars:
                if char in v:
                    raise ValueError(f"Invalid character '{char}' in target - possible injection attempt")
            return v.strip()
    
    
    class NmapArgs(TargetValidator):
        """Validation for nmap_scan arguments."""
        scan_type: str = Field(default="-sV", max_length=200)
        timeout: int = Field(default=600, ge=10, le=3600)
        
        @validator('scan_type')
        def validate_scan_type(cls, v):
            """Validate nmap flags."""
            # Allow common nmap flags
            allowed_patterns = [
                r'^-[sStTAOPpnvVdDrFoigehbGZ0-9]+$',  # Single flags
                r'^--[a-zA-Z\-]+',  # Long options
                r'^\d+[\-,\d]*$',  # Port numbers
                r'^[a-zA-Z0-9\-_./]+$',  # Script names, paths
            ]
            
            parts = v.split()
            for part in parts:
                if not any(re.match(p, part) for p in allowed_patterns):
                    # Check if it looks like a dangerous injection
                    if any(c in part for c in [';', '|', '&', '$', '`']):
                        raise ValueError(f"Invalid nmap option: {part}")
            return v
    
    
    class UrlValidator(BaseModel):
        """Validation for URL arguments."""
        url: str = Field(..., min_length=1, max_length=2000)
        
        @validator('url')
        def validate_url(cls, v):
            """Validate URL format."""
            v = v.strip()
            if not v.startswith(('http://', 'https://', '/')):
                # Allow relative paths and bare domains
                if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]+[a-zA-Z0-9]', v):
                    raise ValueError("Invalid URL format")
            # Check for injection
            dangerous = [';', '|', '&', '$', '`', '\n', '\r']
            for char in dangerous:
                if char in v:
                    raise ValueError(f"Invalid character in URL: {char}")
            return v
    
    
    class GobusterArgs(UrlValidator):
        """Validation for gobuster_scan arguments."""
        wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt")
        extensions: str = Field(default="")
        threads: int = Field(default=20, ge=1, le=100)
        
        @validator('wordlist')
        def validate_wordlist(cls, v):
            """Validate wordlist path."""
            if any(c in v for c in [';', '|', '&', '$', '`']):
                raise ValueError("Invalid wordlist path")
            return v
        
        @validator('extensions')
        def validate_extensions(cls, v):
            """Validate extensions format."""
            if v and not re.match(r'^[a-zA-Z0-9,]+$', v):
                raise ValueError("Extensions must be comma-separated alphanumeric values")
            return v
    
    
    class SqlmapArgs(UrlValidator):
        """Validation for sqlmap_attack arguments."""
        options: str = Field(default="--batch --dbs")
        
        @validator('options')
        def validate_options(cls, v):
            """Validate sqlmap options - all options allowed for full pentesting."""
            return v
    
    
    class HydraArgs(TargetValidator):
        """Validation for hydra_bruteforce arguments."""
        service: str = Field(...)
        userlist: str = Field(default="/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt")
        passlist: str = Field(default="/usr/share/wordlists/rockyou.txt")
        
        @validator('service')
        def validate_service(cls, v):
            """Validate service name."""
            allowed = ['ssh', 'ftp', 'http-post-form', 'http-get', 'rdp', 'smb', 
                      'mysql', 'postgres', 'mssql', 'telnet', 'vnc', 'pop3', 'imap']
            if v.lower().split()[0] not in allowed:
                raise ValueError(f"Unknown service: {v}")
            return v
    
    
    class IpAddressValidator(BaseModel):
        """Validation for IP address arguments."""
        ip: str
        
        @validator('ip')
        def validate_ip(cls, v):
            """Validate IP address (IPv4 or IPv6)."""
            v = v.strip()
            try:
                # Try parsing as IP
                ipaddress.ip_address(v)
                return v
            except ValueError:
                # Try parsing as network
                try:
                    ipaddress.ip_network(v, strict=False)
                    return v
                except ValueError:
                    # Check if it's a hostname
                    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]+[a-zA-Z0-9]$', v):
                        return v
                    raise ValueError(f"Invalid IP/hostname: {v}")


# ============= VALIDATION DECORATOR =============

def validated_tool(validator_class=None):
    """
    Decorator to add Pydantic validation to tool functions.
    
    Usage:
        @validated_tool(NmapArgs)
        @function_tool()
        def nmap_scan(target: str, scan_type: str = "-sV") -> str:
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(**kwargs):
            if PYDANTIC_AVAILABLE and validator_class:
                try:
                    # Validate arguments
                    validated = validator_class(**kwargs)
                    kwargs = validated.dict()
                except Exception as e:
                    return f"❌ Validation Error: {str(e)}"
            return func(**kwargs)
        return wrapper
    return decorator


# ============= INPUT SANITIZERS =============

def sanitize_target(target: str) -> str:
    """Sanitize a target string."""
    if not target:
        return target
    
    # Remove dangerous characters
    dangerous = [';', '|', '&', '$', '`', '>', '<', '\n', '\r']
    for char in dangerous:
        target = target.replace(char, '')
    
    return target.strip()


def sanitize_command_arg(arg: str) -> str:
    """Sanitize a command argument."""
    if not arg:
        return arg
    
    # Quote if contains spaces
    if ' ' in arg and not (arg.startswith('"') and arg.endswith('"')):
        # Escape any existing quotes
        arg = arg.replace('"', '\\"')
        arg = f'"{arg}"'
    
    return arg


def validate_port(port: Union[str, int]) -> Optional[int]:
    """Validate and return a port number."""
    try:
        port_int = int(port)
        if 1 <= port_int <= 65535:
            return port_int
    except (ValueError, TypeError):
        pass
    return None


def validate_ip_or_hostname(value: str) -> bool:
    """Check if value is a valid IP or hostname."""
    value = value.strip()
    
    # Try as IP
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    
    # Try as hostname
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]+[a-zA-Z0-9]$', value):
        return True
    
    return False


# ============= TOOL TIMEOUT CONFIGURATION =============

@dataclass
class ToolTimeoutConfig:
    """Configuration for per-tool timeouts."""
    default: int = 1200  # 20 minutes default
    
    # Tool-specific timeouts (in seconds)
    timeouts: Dict[str, int] = None
    
    def __post_init__(self):
        if self.timeouts is None:
            self.timeouts = {
                # Fast tools
                "whois_lookup": 60,
                "dig_lookup": 60,
                "curl_request": 120,
                "http_request": 120,
                
                # Medium tools
                "gobuster_scan": 1200,   # 20 minutes (was 900)
                "dirsearch_scan": 1800,  # 30 minutes (was 1200)
                "nikto_scan": 1200,      # 20 minutes (was 900)
                "nuclei_scan": 1200,     # 20 minutes (was 900)
                "subfinder_enum": 600,   # 10 minutes (was 300)
                "amass_enum": 1200,      # 20 minutes
                "arjun_scan": 1200,      # 20 minutes (parameter fuzzing)
                "feroxbuster_scan": 1200,
                "ffuf_content_fuzz": 1200,
                "paramspider": 600,
                "gospider_crawl": 600,
                "katana_crawl": 600,
                "hakrawler": 600,
                
                # Slow tools
                "nmap_scan": 1200,       # 20 minutes
                "sqlmap_attack": 1800,   # 30 minutes (was 900)
                "hydra_bruteforce": 1800, # 30 minutes (was 900)
                "wpscan": 1200,          # 20 minutes (was 900)
                "ffuf_fuzz": 1200,       # 20 minutes (was 900)
                "xsstrike": 600,
                "dalfox_scan": 600,
                "commix": 900,
                "tplmap_scan": 600,
                "nosqlmap_attack": 600,
                
                # Very slow tools
                "full_nmap_scan": 3600,  # 60 minutes (was 2400)
                "masscan": 1800,
                "crackmapexec": 900,
                "patator_bruteforce": 1800,
            }
    
    def get_timeout(self, tool_name: str) -> int:
        """Get timeout for a specific tool."""
        return self.timeouts.get(tool_name, self.default)
    
    def set_timeout(self, tool_name: str, timeout: int):
        """Set custom timeout for a tool."""
        self.timeouts[tool_name] = timeout


# Global timeout config
_timeout_config: Optional[ToolTimeoutConfig] = None


def get_timeout_config() -> ToolTimeoutConfig:
    """Get the global timeout configuration."""
    global _timeout_config
    if _timeout_config is None:
        _timeout_config = ToolTimeoutConfig()
    return _timeout_config


def get_tool_timeout(tool_name: str) -> int:
    """Get timeout for a specific tool."""
    return get_timeout_config().get_timeout(tool_name)
