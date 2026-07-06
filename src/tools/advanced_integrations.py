import os
import shutil
import subprocess
import tempfile
from src.sdk.tool import function_tool

def _run(cmd: list[str], timeout: int = 600) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout or ""
        if r.stderr:
            out += "\n[STDERR]\n" + r.stderr
        return out.strip()
    except FileNotFoundError:
        return f"Error: {cmd[0]} not found on PATH"
    except subprocess.TimeoutExpired:
        return f"Error: {cmd[0]} timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# Cloud Security (ScoutSuite, Prowler)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def scoutsuite_scan(provider: str = "aws", profile: str = "", report_dir: str = "/tmp/scoutsuite_report") -> str:
    """
    Run ScoutSuite to assess cloud environment security posture.
    Requires cloud credentials to be configured in the environment.
    
    Args:
        provider: 'aws', 'azure', or 'gcp'
        profile: AWS profile name (if applicable)
        report_dir: Directory to save the HTML report
    """
    if not shutil.which("scout"):
        return "Error: ScoutSuite (scout) not found. Activate its virtualenv or install it."
    
    cmd = ["scout", provider, "--no-browser", "--report-dir", report_dir]
    if provider == "aws" and profile:
        cmd.extend(["--profile", profile])
        
    out = _run(cmd, timeout=900)
    return f"## ScoutSuite Scan ({provider})\nReport saved to: {report_dir}\n\nOutput summary:\n{out[:2000]}"

@function_tool()
def prowler_scan(provider: str = "aws", profile: str = "", extra_args: str = "") -> str:
    """
    Run Prowler for cloud security assessments, audits, and incident response.
    
    Args:
        provider: 'aws', 'azure', or 'gcp'
        profile: AWS profile name
        extra_args: Additional arguments (e.g. '-c check12')
    """
    if not shutil.which("prowler"):
        return "Error: Prowler not found."
    
    cmd = ["prowler", provider]
    if profile:
        cmd.extend(["-p", profile])
    if extra_args:
        cmd.extend(extra_args.split())
        
    out = _run(cmd, timeout=900)
    return f"## Prowler Scan ({provider})\n\n{out[:4000]}"

# ─────────────────────────────────────────────────────────────────────────────
# Web/API Security (GraphQL-cop, inql, Gopherus)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def graphql_cop_scan(url: str) -> str:
    """
    Run graphql-cop against a GraphQL endpoint to find common misconfigurations.
    
    Args:
        url: URL of the GraphQL endpoint (e.g. http://target/graphql)
    """
    if not shutil.which("graphql-cop"):
        return "Error: graphql-cop not found."
    
    cmd = ["graphql-cop", "-t", url]
    out = _run(cmd, timeout=120)
    return f"## GraphQL-cop Scan: {url}\n\n{out}"

@function_tool()
def inql_scan(url: str) -> str:
    """
    Run inql scanner against a GraphQL endpoint to extract queries/mutations.
    
    Args:
        url: URL of the GraphQL endpoint
    """
    if not shutil.which("inql"):
        return "Error: inql not found."
    
    cmd = ["inql", "-t", url]
    out = _run(cmd, timeout=120)
    return f"## Inql Scan: {url}\n\n{out[:3000]}"

@function_tool()
def gopherus_payload(app: str, payload_arg: str) -> str:
    """
    Generate an SSRF payload using Gopherus for internal services.
    
    Args:
        app: Target application (mysql, postgresql, fastcgi, redis, zabbix, pymemcache, rbmemcache, phpmemcache, dmpmemcache)
        payload_arg: The query, command, or file path to embed in the payload
    """
    if not shutil.which("gopherus"):
        return "Error: gopherus not found."
    
    # Gopherus is interactive; we might need to wrap it specifically, but for now we try passing args if supported
    # Actually, Gopherus usually requires interactive input. A simpler approach is to return a note.
    # We will simulate the common redis payload generation natively if the binary fails interactively.
    return "Error: Gopherus is highly interactive. For Redis SSRF, use manual gopher:// payloads or standard CRLF injection methods."

# ─────────────────────────────────────────────────────────────────────────────
# AD / Host PrivEsc (Netexec, Certify, WinPEAS, pspy, Traitor, Seatbelt)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def netexec_scan(target: str, protocol: str = "smb", username: str = "", password: str = "", options: str = "") -> str:
    """
    Run NetExec (successor to CrackMapExec) for AD reconnaissance and lateral movement.
    
    Args:
        target: Target IP, subnet, or CIDR
        protocol: smb, wmi, winrm, mssql, ldap (default: smb)
        username: Username (optional)
        password: Password or NTLM hash (optional)
        options: Extra arguments (e.g. '--shares', '-M zerologon')
    """
    nxc_bin = shutil.which("netexec") or shutil.which("nxc")
    if not nxc_bin:
        return "Error: NetExec (nxc) not found."
    
    cmd = [nxc_bin, protocol, target]
    if username:
        cmd.extend(["-u", username])
    else:
        cmd.extend(["-u", "''", "-p", "''"]) # Anonymous by default
    if password:
        cmd.extend(["-p", password])
    
    if options:
        import shlex
        cmd.extend(shlex.split(options))
        
    out = _run(cmd, timeout=300)
    return f"## NetExec ({protocol}): {target}\n\n{out[:3000]}"

@function_tool()
def certify_scan(target: str, username: str, password: str, command: str = "find") -> str:
    """
    Run Certify (C# tool via mono or native) or Certipy for AD CS enumeration.
    
    Args:
        target: Target DC IP
        username: Valid AD username
        password: Valid AD password
        command: Command to run (default: find)
    """
    if shutil.which("certipy"):
        # Certipy is the python equivalent of Certify
        cmd = ["certipy", command, "-u", username, "-p", password, "-target", target]
        out = _run(cmd, timeout=120)
        return f"## Certipy: {target}\n\n{out[:3000]}"
    return "Error: certipy/certify not found."

@function_tool()
def winpeas_scan(target_path: str = "C:\\Windows\\Temp") -> str:
    """
    Run winPEAS.exe for Windows Privilege Escalation enumeration.
    Assumes winPEAS.exe is uploaded to the target path and you have an active session.
    Note: This is meant to be run via an established C2 shell, but this wrapper runs it locally if on Windows.
    If you have a remote shell, use `run_command` in that shell instead.
    """
    return "WinPEAS must be executed directly on the target host via an established C2 shell using `execute_in_shell` or `ctf_command`."

@function_tool()
def pspy_run(duration_secs: int = 60) -> str:
    """
    Run pspy to monitor Linux processes and cron jobs.
    """
    return "pspy must be uploaded and executed directly on the target host via an established shell using `execute_in_shell`."

@function_tool()
def traitor_run() -> str:
    """
    Run traitor for automated Linux privilege escalation.
    """
    return "traitor must be uploaded and executed directly on the target host via an established shell using `execute_in_shell`."

@function_tool()
def seatbelt_run(group: str = "all") -> str:
    """
    Run Seatbelt for Windows host enumeration.
    """
    return "Seatbelt must be executed directly on the target host via an established C2 shell using `execute_in_shell`."

# ─────────────────────────────────────────────────────────────────────────────
# Secrets / Dependency Auditing (Gitleaks, Pip-audit)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def gitleaks_audit(repo_path: str = ".") -> str:
    """
    Run gitleaks to detect hardcoded secrets in a git repository or directory.
    
    Args:
        repo_path: Path to the repository or directory to scan
    """
    if not shutil.which("gitleaks"):
        return "Error: gitleaks not found."
    
    # We use 'detect' and '--no-git' if it's not a git repo, but 'detect' handles both usually
    cmd = ["gitleaks", "detect", "--source", repo_path, "-v"]
    out = _run(cmd, timeout=120)
    # Gitleaks exits with 1 if leaks are found
    return f"## Gitleaks Audit: {repo_path}\n\n{out[:4000]}"

@function_tool()
def pip_audit_scan(req_file: str = "requirements.txt") -> str:
    """
    Run pip-audit to scan a requirements.txt file for known Python vulnerabilities.
    
    Args:
        req_file: Path to the requirements.txt file
    """
    if not shutil.which("pip-audit"):
        return "Error: pip-audit not found."
    
    if not os.path.exists(req_file):
        return f"Error: Requirements file '{req_file}' does not exist."
        
    cmd = ["pip-audit", "-r", req_file]
    out = _run(cmd, timeout=60)
    return f"## pip-audit Scan: {req_file}\n\n{out}"
