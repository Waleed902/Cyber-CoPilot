"""
Metasploit RPC Integration
Allows the framework to interact with a local Metasploit RPC daemon (msfrpcd)
to execute exploits, configure payloads, and manage sessions programmatically.
"""

from src.sdk.tool import function_tool
import re
import subprocess
import time
import json


_MSF_MODULE_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
_MSF_OPTION_KEY_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _clean_msf_value(value: object, max_len: int = 500) -> str:
    """Remove msfconsole command separators from a single argument value."""
    cleaned = str(value).replace(";", " ").replace("\r", " ").replace("\n", " ").strip()
    return " ".join(cleaned.split())[:max_len]


def _valid_msf_module_path(value: str) -> bool:
    return bool(value and _MSF_MODULE_RE.match(value))


def _run_msfconsole_search_fallback(query: str, reason: str) -> str:
    clean_query = _clean_msf_value(query, max_len=200)
    if not clean_query:
        return "Error: query cannot be empty."

    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-x", f"search {clean_query}; exit"],
            capture_output=True,
            text=True,
            timeout=180,
        )
        output = (result.stdout or result.stderr or "").strip()
        if not output:
            output = f"No modules found matching '{clean_query}'"
        return (
            "[Metasploit RPC unavailable; used msfconsole CLI fallback]\n"
            f"RPC reason: {reason}\n\n"
            f"{output[:4000]}"
        )
    except FileNotFoundError:
        return (
            f"{reason}\n"
            "Error: msfconsole binary was not found on PATH. Install Metasploit Framework."
        )
    except subprocess.TimeoutExpired:
        return "Error: msfconsole search timed out after 180 seconds."
    except Exception as e:
        return f"Error running msfconsole search fallback: {e}"


def _run_msfconsole_module_fallback(module_name: str, options: str, payload: str, reason: str) -> str:
    if not _valid_msf_module_path(module_name):
        return (
            "Error: invalid Metasploit module path. Use a path like "
            "'auxiliary/scanner/http/http_version' or 'exploit/multi/handler'."
        )

    try:
        opts = json.loads(options or "{}")
    except json.JSONDecodeError:
        return "Error: options must be a valid JSON string."

    if not isinstance(opts, dict):
        return "Error: options must be a JSON object."

    commands = [f"use {module_name}"]
    clean_payload = _clean_msf_value(payload, max_len=200)
    if clean_payload:
        if not _valid_msf_module_path(clean_payload):
            return "Error: invalid Metasploit payload path."
        commands.append(f"set PAYLOAD {clean_payload}")

    for key, value in opts.items():
        clean_key = str(key).strip()
        if not _MSF_OPTION_KEY_RE.match(clean_key):
            return f"Error: invalid Metasploit option name '{key}'."
        commands.append(f"set {clean_key} {_clean_msf_value(value)}")

    commands.extend(["run", "exit"])
    rc_cmd = "; ".join(commands)

    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-x", rc_cmd],
            capture_output=True,
            text=True,
            timeout=600,
        )
        output = (result.stdout or result.stderr or "No output").strip()
        return (
            "[Metasploit RPC unavailable; used msfconsole CLI fallback]\n"
            f"RPC reason: {reason}\n\n"
            f"{output[:6000]}"
        )
    except FileNotFoundError:
        return (
            f"{reason}\n"
            "Error: msfconsole binary was not found on PATH. Install Metasploit Framework."
        )
    except subprocess.TimeoutExpired:
        return "Error: msfconsole module execution timed out after 10 minutes."
    except Exception as e:
        return f"Error running msfconsole module fallback: {e}"

def _get_msf_client():
    """Attempt to connect to the local Metasploit RPC daemon, starting it if necessary."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        import subprocess
        import time
        import socket
        
        # Check if port 55553 is open locally
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 55553))
        sock.close()
        
        if result != 0:
            # Port is closed, try to start msfrpcd automatically
            print("Metasploit RPC not running on 55553. Starting msfrpcd automatically...")
            # We use shell=True to allow it to run in the background
            subprocess.Popen(
                "msfrpcd -P msf -n -S", 
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # Wait for it to boot up
            time.sleep(8)
            
        # Default credentials for msfrpcd when started with `-P msf -n -S`
        return MsfRpcClient('msf', port=55553) # Default port is 55553
    except ImportError:
        return "Error: pymetasploit3 library is not installed. Run `pip install pymetasploit3`."
    except Exception as e:
        return f"Error connecting to Metasploit RPC daemon: {str(e)}\nMake sure Metasploit is installed and accessible."

@function_tool()
def msf_search_module(query: str) -> str:
    """
    Search Metasploit for exploit, auxiliary, or payload modules.
    
    Args:
        query: The search term (e.g., 'eternalblue', 'cve-2021-41773', 'wordpress')
        
    Returns:
        List of matching modules and their descriptions.
    """
    client = _get_msf_client()
    if isinstance(client, str):
        return _run_msfconsole_search_fallback(query, client)
        
    try:
        # We use the console to run the search command because the API's search 
        # functionality can be limited depending on the MSF version.
        cid = client.consoles.console().cid
        client.consoles.console(cid).write(f"search {query}")
        
        # Wait for the search to complete
        time.sleep(2)
        output = client.consoles.console(cid).read()
        
        # Clean up console
        client.consoles.console(cid).destroy()
        
        if not output['data']:
            return f"No modules found matching '{query}'"
            
        return output['data'][:4000] # Limit output to avoid context overflow
    except Exception as e:
        return f"Error searching Metasploit: {str(e)}"

@function_tool()
def msf_execute_module(module_name: str, options: str, payload: str = "") -> str:
    """
    Execute a Metasploit exploit or auxiliary module.
    
    Args:
        module_name: The full module path (e.g., 'exploit/windows/smb/ms17_010_psexec')
        options: A JSON string of module options (e.g., '{"RHOSTS": "10.10.10.10", "LPORT": "4444"}')
        payload: Optional payload to use (e.g., 'windows/x64/meterpreter/reverse_tcp')
        
    Returns:
        The execution results, console output, and any sessions created.
    """
    try:
        opts = json.loads(options or "{}")
    except json.JSONDecodeError:
        return "Error: options must be a valid JSON string."
    if not isinstance(opts, dict):
        return "Error: options must be a JSON object."

    client = _get_msf_client()
    if isinstance(client, str):
        return _run_msfconsole_module_fallback(module_name, options, payload, client)
        
    try:
        # Determine module type based on path
        mod_type = module_name.split('/')[0]
        if mod_type not in ['exploit', 'auxiliary', 'post', 'payload', 'encoder', 'nop']:
            return f"Error: Invalid module type '{mod_type}'. Must be exploit, auxiliary, etc."
            
        module = client.modules.use(mod_type, module_name)
        
        # Set options
        for key, value in opts.items():
            if key in module.options:
                module[key] = value
            else:
                # Add it anyway, some options are hidden or advanced
                module[key] = value
                
        # Execute the module
        if mod_type == 'exploit':
            # Run exploit and capture output
            result = module.execute(payload=payload if payload else None)
        else:
            # Run auxiliary module
            result = module.execute()
            
        # Check if a job or session was created
        job_id = result.get('job_id')
        uuid = result.get('uuid')
        
        output = f"Module execution started. Result: {result}\n"
        
        if job_id:
            output += f"Running as background job {job_id}.\n"
            
        # Give it a moment to run
        time.sleep(3)
        
        # Check sessions
        sessions = client.sessions.list
        if sessions:
            output += f"\nActive Sessions:\n{json.dumps(sessions, indent=2)}\n"
            output += "You can interact with sessions using the msfconsole manually."
        else:
            output += "\nNo sessions created yet (or exploit failed)."
            
        return output
        
    except Exception as e:
        return f"Error executing Metasploit module: {str(e)}"
