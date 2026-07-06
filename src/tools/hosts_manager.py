"""
Hosts file manager tool

Provides tools to manage virtual-host (vhost) entries in the OS hosts file,
solving the #1 methodology failure: hosts-only domains being unreachable.
"""

from __future__ import annotations

import os
import re
import subprocess
import platform

from src.sdk.tool import function_tool


try:
    from src.repl.hosts_manager import get_hosts_file_path

    _HOSTS_FILE = get_hosts_file_path()
except Exception:
    _HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/hosts"


def _read_hosts() -> str:
    """Read current hosts file content."""
    try:
        with open(_HOSTS_FILE, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error reading {_HOSTS_FILE}: {e}"


def _has_entry(ip: str, hostname: str) -> bool:
    """Return True if an entry for this hostname already exists."""
    content = _read_hosts()
    pattern = rf"^\s*{re.escape(ip)}\s+.*\b{re.escape(hostname)}\b"
    return bool(re.search(pattern, content, re.MULTILINE))


def _hostname_resolves(hostname: str) -> bool:
    """Return True if hostname already resolves (DNS or hosts file)."""
    import socket
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False


def _success_msg(ip: str, hostname: str) -> str:
    return (
        f"✅ Added to hosts file: {ip}\t{hostname}\n\n"
        f"All tools can now resolve http://{hostname}/ correctly.\n"
        f"Recommended next steps:\n"
        f"  1. Run: feroxbuster_scan('http://{hostname}')\n"
        f"  2. Run: gobuster_scan('http://{hostname}')\n"
        f"  3. Run: curl_request('http://{hostname}/')"
    )


def _permission_hint(ip: str, hostname: str) -> str:
    if platform.system() == "Windows":
        return (
            f"Re-run the terminal as Administrator, then add this line to {_HOSTS_FILE}:\n\n"
            f"   {ip}\t{hostname}\n"
        )
    return (
        f"Run this ONE command in your Kali terminal right now:\n\n"
        f"   echo '{ip}\\t{hostname}' | sudo tee -a /etc/hosts\n"
    )


def _register_in_context_hub(ip: str, hostname: str) -> None:
    """Register vhost mapping in context hub so resolve_vhost() can use it."""
    try:
        from src.sdk.context_hub import get_context_hub
        chub = get_context_hub()
        subdomains = chub.findings.setdefault("subdomains", [])
        for sd in subdomains:
            if sd.get("subdomain") == hostname:
                sd["ip"] = ip
                return
        subdomains.append({"subdomain": hostname, "ip": ip, "source": "hosts_manager"})
    except Exception:
        pass


@function_tool()
def add_hosts_entry(ip: str, hostname: str) -> str:
    """
    Add a virtual-host entry to the OS hosts file so that hostname-only domains
    (like facts.htb) are reachable from tools like curl, gobuster, feroxbuster,
    arjun, gau, gospider, and any other tool that uses system DNS.

    CRITICAL: Call this tool immediately when:
    1. You discover that an IP redirects to a hostname (e.g. via curl or whatweb)
    2. The hostname ends in .htb, .local, .internal, .corp, .lab, or similar
    3. Any tool fails with "Could not resolve host" or "Name or service not known"

    Args:
        ip: Target IP address (e.g., "10.129.244.96")
        hostname: Hostname to map (e.g., "facts.htb")

    Returns:
        Confirmation that the entry was added (or already exists)
    """
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip.strip()):
        return f"Error: '{ip}' does not look like a valid IPv4 address."

    hostname = hostname.strip().lower()
    if not hostname:
        return "Error: hostname cannot be empty."

    if _has_entry(ip, hostname):
        _register_in_context_hub(ip, hostname)
        return (
            f"✅ Entry already exists: {ip} {hostname}\n"
            f"You can now use http://{hostname}/ directly in all tools."
        )

    entry = f"\n{ip}\t{hostname}\t# added by cyber-copilot\n"

    # ── Strategy 1: shared cross-platform hosts manager ──────────────────────
    try:
        from src.repl.hosts_manager import add_host

        result = add_host(ip, hostname, note="tools.add_hosts_entry")
        if result.get("success"):
            _register_in_context_hub(ip, hostname)
            return _success_msg(ip, hostname)
    except Exception:
        pass

    # ── Strategy 2: Direct write ──────────────────────────────────────────────
    # Works when the tool is run as root (sudo python3 main.py) or the
    # user already owns /etc/hosts (some lab setups).
    if os.access(_HOSTS_FILE, os.W_OK):
        try:
            with open(_HOSTS_FILE, "a") as f:
                f.write(entry)
            _register_in_context_hub(ip, hostname)
            return _success_msg(ip, hostname)
        except Exception:
            pass  # fall through

    # ── Strategy 3: sudo -n tee (non-interactive) ─────────────────────────────
    # -n means "never prompt for a password" – fails immediately with rc=1
    # if credentials aren't cached, instead of hanging on a TTY prompt.
    try:
        result = subprocess.run(
            ["sudo", "-n", "tee", "-a", _HOSTS_FILE],
            input=entry,
            capture_output=True,
            text=True,
            timeout=8,
        )
        if result.returncode == 0:
            _register_in_context_hub(ip, hostname)
            return _success_msg(ip, hostname)
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass  # sudo not found

    # ── Strategy 4: sudo -n sh -c "echo >> /etc/hosts" ───────────────────────
    try:
        line = f"{ip}\\t{hostname}\\t# added by cyber-copilot"
        result = subprocess.run(
            ["sudo", "-n", "sh", "-c", f"printf '{line}\\n' >> /etc/hosts"],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode == 0:
            _register_in_context_hub(ip, hostname)
            return _success_msg(ip, hostname)
    except Exception:
        pass

    # ── All strategies failed ── register in context hub anyway ──────────────
    # This means http_request and curl_request can still reach the vhost
    # via Host: header injection (resolve_vhost() uses the context hub).
    _register_in_context_hub(ip, hostname)
    return (
        f"⚠️ Could not write hosts file automatically: {_HOSTS_FILE}\n\n"
        f"▶  {_permission_hint(ip, hostname)}\n"
        f"✅ IMPORTANT: '{hostname}' has been registered in the context hub.\n"
        f"   • http_request and curl_request will still reach {hostname}\n"
        f"     automatically via Host: header.\n"
        f"   • feroxbuster, gobuster, arjun, gau need the hosts entry."
    )


@function_tool()
def remove_hosts_entry(hostname: str) -> str:
    """
    Remove a virtual-host entry from the OS hosts file (cleanup after engagement).

    Args:
        hostname: Hostname to remove (e.g., "facts.htb")

    Returns:
        Confirmation of removal
    """
    hostname = hostname.strip().lower()
    try:
        try:
            from src.repl.hosts_manager import remove_host

            result = remove_host(hostname)
            if result.get("success") and result.get("removed_count", 0) > 0:
                return f"✅ Removed '{hostname}' from hosts file."
        except Exception:
            pass

        content = _read_hosts()
        lines = content.splitlines(keepends=True)
        filtered = [
            l for l in lines
            if not re.search(rf"\b{re.escape(hostname)}\b", l)
        ]
        if len(filtered) == len(lines):
            return f"No entry for '{hostname}' found in hosts file."
        new_content = "".join(filtered)

        # Try direct write first
        if os.access(_HOSTS_FILE, os.W_OK):
            with open(_HOSTS_FILE, "w") as f:
                f.write(new_content)
            return f"✅ Removed '{hostname}' from hosts file."

        # Try sudo -n tee
        result = subprocess.run(
            ["sudo", "-n", "tee", _HOSTS_FILE],
            input=new_content,
            capture_output=True,
            text=True,
            timeout=8,
        )
        if result.returncode == 0:
            return f"✅ Removed '{hostname}' from hosts file."
        return (
            f"⚠️ Could not write hosts file (sudo needs password): {_HOSTS_FILE}\n"
            f"Manual fix: sudo sed -i '/{re.escape(hostname)}/d' /etc/hosts"
        )
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def list_hosts_entries() -> str:
    """
    Show all custom entries in the OS hosts file (non-default lines).
    Useful to verify that virtual-host mappings are in place before running tools.

    Returns:
        Custom hosts file entries
    """
    content = _read_hosts()
    _DEFAULT_PATTERNS = re.compile(
        r"^\s*(#|127\.|::1|fe80:|ff0[02]:|$)", re.IGNORECASE
    )
    custom = [
        l.rstrip()
        for l in content.splitlines()
        if not _DEFAULT_PATTERNS.match(l)
    ]
    if not custom:
        return "No custom hosts file entries found."
    return "## Custom hosts file entries:\n" + "\n".join(custom)


@function_tool()
def check_vhost_resolution(hostname: str) -> str:
    """
    Check whether a hostname resolves correctly (via DNS or hosts file).
    Use this after discovering a redirect to confirm the hostname is reachable
    before running enumeration tools.

    Args:
        hostname: Hostname to check (e.g., "facts.htb")

    Returns:
        Resolution status and the resolved IP address
    """
    import socket
    hostname = hostname.strip()
    try:
        ip = socket.gethostbyname(hostname)
        return (
            f"✅ '{hostname}' resolves to {ip}\n"
            f"All tools can reach http://{hostname}/ directly."
        )
    except socket.gaierror:
        try:
            from src.sdk.context_hub import get_context_hub
            chub = get_context_hub()
            for sd in chub.findings.get("subdomains", []):
                if sd.get("subdomain") == hostname and sd.get("ip"):
                    return (
                        f"⚠️ '{hostname}' does NOT resolve via DNS.\n"
                        f"However, context hub has IP: {sd['ip']}\n"
                        f"Run: add_hosts_entry('{sd['ip']}', '{hostname}') to fix this."
                    )
            ip_target = chub.current_target or ""
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_target):
                return (
                    f"❌ '{hostname}' does NOT resolve via DNS!\n"
                    f"Current target IP: {ip_target}\n"
                    f"FIX: add_hosts_entry('{ip_target}', '{hostname}')\n"
                    f"This is likely the correct mapping based on the redirect."
                )
        except Exception:
            pass
        return (
            f"❌ '{hostname}' does NOT resolve via DNS or hosts file!\n"
            f"FIX: add_hosts_entry('<target_ip>', '{hostname}')\n"
            f"Example: add_hosts_entry('10.129.244.96', '{hostname}')"
        )
