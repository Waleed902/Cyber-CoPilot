"""
Anonsurf Manager Tool

This tool allows agents to control the Kali Linux `anonsurf` utility
to route traffic through the Tor network, providing an additional layer
of operational security and IP rotation capability.
"""

import subprocess
from src.sdk.tool import function_tool

@function_tool()
def manage_anonsurf(action: str) -> str:
    """
    Control the anonsurf anonymization layer to route traffic through Tor.
    Use this to rotate the external IP address or hide traffic origins.

    Args:
        action: The action to perform. Valid options: 'start', 'stop', 'change' (changes Tor identity/IP), 'status', 'myip'

    Returns:
        The output of the anonsurf command.
    """
    valid_actions = ["start", "stop", "change", "status", "myip"]
    action = action.lower().strip()

    if action not in valid_actions:
        return f"Error: Invalid action '{action}'. Valid actions are: {', '.join(valid_actions)}"

    # anonsurf requires sudo for most actions
    cmd = []
    if action in ["start", "stop", "change"]:
        cmd = ["sudo", "anonsurf", action]
    else:
        cmd = ["anonsurf", action]

    try:
        # Run command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout.strip()
        error = result.stderr.strip()
        
        if result.returncode != 0:
            return f"Error executing anonsurf {action} (Exit code {result.returncode}):\n{error}\n{output}"
            
        if not output and error:
            output = error
            
        header = f"=== Anonsurf {action.upper()} ==="
        return f"{header}\n{output}"

    except subprocess.TimeoutExpired:
        return f"Error: anonsurf {action} command timed out after 30 seconds."
    except FileNotFoundError:
        return "Error: 'anonsurf' command not found. Is it installed on this Kali Linux system?"
    except Exception as e:
        return f"Error running anonsurf: {str(e)}"
