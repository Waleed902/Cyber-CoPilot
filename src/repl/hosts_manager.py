"""
Hosts File Manager - Auto-manage /etc/hosts for HTB & lab machines.

Supports Windows, Linux, and macOS.
Entries are tagged so they can be listed/removed cleanly.
"""

import os
import re
import platform
import ipaddress
from pathlib import Path
from loguru import logger


# The tag used to mark entries written by this tool
_MARKER = "# cyber-copilot"

# Hosts file path per OS
if platform.system() == "Windows":
    HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")
else:
    HOSTS_FILE = Path("/etc/hosts")


def _is_valid_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _read_hosts() -> list[str]:
    """Read and return the hosts file lines (or [] on failure)."""
    try:
        return HOSTS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning(f"Cannot read hosts file: {exc}")
        return []


def _write_hosts(lines: list[str]) -> bool:
    """Write *lines* back to the hosts file. Returns True on success."""
    content = "\n".join(lines) + "\n"
    try:
        HOSTS_FILE.write_text(content, encoding="utf-8")
        return True
    except PermissionError:
        return False


def _entry_exists(ip: str, hostname: str, lines: list[str]) -> bool:
    """Return True if an identical ip→hostname mapping already exists."""
    pattern = re.compile(
        r"^\s*" + re.escape(ip) + r"\s+" + re.escape(hostname) + r"(\s|$)",
        re.IGNORECASE,
    )
    return any(pattern.search(line) for line in lines)


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def add_host(ip: str, hostname: str, note: str = "") -> dict:
    """
    Add  ``<ip>  <hostname>``  to the hosts file.

    Returns a dict with keys:
        success (bool), message (str), already_existed (bool)
    """
    if not _is_valid_ip(ip):
        return {"success": False, "message": f"'{ip}' is not a valid IP address.", "already_existed": False}

    lines = _read_hosts()

    if _entry_exists(ip, hostname, lines):
        return {
            "success": True,
            "message": f"Entry already exists: {ip}  {hostname}",
            "already_existed": True,
        }

    tag = f"{_MARKER} {note}".strip() if note else _MARKER
    new_line = f"{ip}\t{hostname}\t{tag}"
    lines.append(new_line)

    if _write_hosts(lines):
        return {"success": True, "message": f"Added: {ip}  {hostname}", "already_existed": False}
    else:
        # Elevation hint
        if platform.system() == "Windows":
            hint = "Re-run the terminal as Administrator."
        else:
            hint = f"Try: sudo python main.py  OR  sudo sh -c 'echo \"{ip}\\t{hostname}\" >> /etc/hosts'"
        return {
            "success": False,
            "message": f"Permission denied writing to {HOSTS_FILE}.\n  {hint}",
            "already_existed": False,
        }


def remove_host(hostname: str) -> dict:
    """
    Remove all cyber-copilot-tagged lines that contain *hostname*.

    Returns a dict with keys:
        success (bool), message (str), removed_count (int)
    """
    lines = _read_hosts()
    new_lines = []
    removed = 0

    for line in lines:
        # Only remove lines we own (tagged with _MARKER)
        if _MARKER in line and re.search(r"\b" + re.escape(hostname) + r"\b", line, re.IGNORECASE):
            removed += 1
        else:
            new_lines.append(line)

    if removed == 0:
        return {"success": True, "message": f"No managed entries found for '{hostname}'.", "removed_count": 0}

    if _write_hosts(new_lines):
        return {"success": True, "message": f"Removed {removed} entry(s) for '{hostname}'.", "removed_count": removed}
    else:
        if platform.system() == "Windows":
            hint = "Re-run the terminal as Administrator."
        else:
            hint = "Try running with sudo."
        return {"success": False, "message": f"Permission denied writing to {HOSTS_FILE}.\n  {hint}", "removed_count": 0}


def list_managed_hosts() -> list[dict]:
    """
    Return a list of dicts for every line this tool has added.

    Each dict has keys: ip, hostnames (list[str]), note (str)
    """
    lines = _read_hosts()
    entries = []
    for line in lines:
        if _MARKER not in line:
            continue
        # Strip the comment part
        code = line.split("#")[0].strip()
        if not code:
            continue
        parts = code.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        hostnames = parts[1:]
        # Extract note (everything after the marker)
        note_match = re.search(re.escape(_MARKER) + r"\s*(.*)", line)
        note = note_match.group(1).strip() if note_match else ""
        entries.append({"ip": ip, "hostnames": hostnames, "note": note})
    return entries


def check_can_write() -> bool:
    """Return True if we can write to the hosts file without sudo."""
    return os.access(HOSTS_FILE, os.W_OK)


def get_hosts_file_path() -> str:
    return str(HOSTS_FILE)
