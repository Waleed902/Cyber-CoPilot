"""
Proxy Manager — IP Rotation & Anti-Ban Engine

Integrates TorNet, Anonsurf, and ProxyChains4 into Cyber-CoPilot for
automated IP rotation to avoid bans during active scanning/testing.

Supports three backends:
  1. TorNet   — automatic timed rotation via Tor (pip install tornet)
  2. Anonsurf — system-wide Tor routing (pre-installed on Parrot/Kali)
  3. ProxyChains4 — per-tool proxy chaining (/etc/proxychains4.conf)

The module also provides:
  - Ban detection: auto-rotate on repeated 429/403/503 responses
  - Status dashboard: see active backend, current IP, rotation stats
  - Integration hooks: other tools can call get_proxy() to inject proxy settings
"""

import subprocess
import shutil
import time
import threading
import os
from typing import Optional, Dict, Literal
from dataclasses import dataclass, field

from src.sdk.tool import function_tool

# ─────────────────────────────────────────────────────────────────────────────
# Proxy State
# ─────────────────────────────────────────────────────────────────────────────

BackendType = Literal["tornet", "anonsurf", "proxychains", "none"]


@dataclass
class ProxyState:
    """Tracks the active proxy/rotation configuration."""
    backend: BackendType = "none"
    is_active: bool = False
    rotation_interval: int = 60        # seconds between rotations
    total_rotations: int = 0
    ban_detections: int = 0
    last_rotation: float = 0.0
    last_ip: str = ""
    tornet_pid: Optional[int] = None   # PID of background TorNet process
    _auto_rotate_thread: Optional[threading.Thread] = None
    consecutive_bans: int = 0
    auto_rotate_on_ban: bool = True


_state = ProxyState()


def get_state() -> ProxyState:
    """Get the global proxy state."""
    return _state


# ─────────────────────────────────────────────────────────────────────────────
# Helper: check if a tool is installed
# ─────────────────────────────────────────────────────────────────────────────

def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _get_current_ip(via_tor: bool = False) -> str:
    """Fetch the current public IP address."""
    check_urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in check_urls:
        try:
            if via_tor:
                cmd = ["curl", "-s", "--max-time", "10",
                       "--socks5-hostname", "127.0.0.1:9050", url]
            else:
                cmd = ["curl", "-s", "--max-time", "10", url]
            rc, out, _ = _run(cmd, timeout=15)
            if rc == 0 and out and len(out) < 50:
                return out.strip()
        except Exception:
            continue
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# TorNet Backend
# ─────────────────────────────────────────────────────────────────────────────

def _check_tor_running() -> bool:
    """Check if the Tor service is running."""
    rc, out, _ = _run(["systemctl", "is-active", "tor"], timeout=5)
    if rc == 0 and "active" in out:
        return True
    # Fallback: check if SOCKS port is open
    rc2, _, _ = _run(["curl", "-s", "--max-time", "3",
                       "--socks5-hostname", "127.0.0.1:9050",
                       "https://check.torproject.org/api/ip"], timeout=8)
    return rc2 == 0


def _tornet_rotate() -> str:
    """Request a single IP rotation via Tor's NEWNYM signal."""
    # Try using stem (Python Tor controller library)
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=9051) as ctrl:
            ctrl.authenticate()
            ctrl.signal(Signal.NEWNYM)
            _state.total_rotations += 1
            _state.last_rotation = time.time()
            time.sleep(2)  # Wait for new circuit
            new_ip = _get_current_ip(via_tor=True)
            _state.last_ip = new_ip
            return f"✅ Tor circuit rotated (stem). New IP: {new_ip}"
    except Exception:
        pass

    # Fallback: restart Tor service
    rc, _, err = _run(["sudo", "systemctl", "restart", "tor"], timeout=15)
    if rc == 0:
        _state.total_rotations += 1
        _state.last_rotation = time.time()
        time.sleep(3)
        new_ip = _get_current_ip(via_tor=True)
        _state.last_ip = new_ip
        return f"✅ Tor service restarted. New IP: {new_ip}"
    return f"❌ Failed to rotate Tor circuit: {err}"


# ─────────────────────────────────────────────────────────────────────────────
# Anonsurf Backend
# ─────────────────────────────────────────────────────────────────────────────

def _anonsurf_status() -> str:
    rc, out, err = _run(["anonsurf", "status"], timeout=10)
    return out or err or "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Function Tools — exposed to the LLM agent
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def proxy_status() -> str:
    """
    Show the current proxy/IP rotation status including active backend,
    current IP, rotation stats, and available backends.

    Returns:
        Formatted status dashboard
    """
    results = ["## 🔄 Proxy & IP Rotation Status\n"]

    # Check available backends
    backends = {
        "tornet": _tool_exists("tornet"),
        "anonsurf": _tool_exists("anonsurf"),
        "proxychains4": _tool_exists("proxychains4") or _tool_exists("proxychains"),
        "tor": _tool_exists("tor") or _check_tor_running(),
        "stem": False,
    }
    try:
        import stem  # noqa: F401
        backends["stem"] = True
    except ImportError:
        pass

    results.append("### Available Backends")
    for name, available in backends.items():
        icon = "✅" if available else "❌"
        results.append(f"  {icon} {name}")

    results.append(f"\n### Active Configuration")
    results.append(f"  Backend:          {_state.backend}")
    results.append(f"  Active:           {'🟢 Yes' if _state.is_active else '🔴 No'}")
    results.append(f"  Rotation interval: {_state.rotation_interval}s")
    results.append(f"  Total rotations:  {_state.total_rotations}")
    results.append(f"  Ban detections:   {_state.ban_detections}")
    results.append(f"  Auto-rotate on ban: {'Yes' if _state.auto_rotate_on_ban else 'No'}")

    if _state.last_ip:
        results.append(f"  Last known IP:    {_state.last_ip}")

    # Get current IP
    if _state.backend in ("tornet", "anonsurf") and _state.is_active:
        current = _get_current_ip(via_tor=True)
        results.append(f"  Current Tor IP:   {current}")
    else:
        current = _get_current_ip(via_tor=False)
        results.append(f"  Current real IP:  {current}")

    # ProxyChains config check
    if backends["proxychains4"]:
        conf_path = "/etc/proxychains4.conf"
        if os.path.exists(conf_path):
            results.append(f"\n### ProxyChains4 Config: {conf_path}")
            try:
                with open(conf_path, "r") as f:
                    lines = f.readlines()
                # Show chain type and proxy list
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if any(kw in line for kw in [
                            "dynamic_chain", "strict_chain", "random_chain",
                            "proxy_dns", "socks", "http"
                        ]):
                            results.append(f"  {line}")
            except Exception:
                results.append("  (could not read config)")

    return "\n".join(results)


@function_tool()
def proxy_start_tornet(interval: int = 60) -> str:
    """
    Start TorNet-based IP rotation. Rotates your Tor exit IP automatically
    every N seconds. Requires: tor service running + tornet installed.

    Args:
        interval: Seconds between IP rotations (default 60, min 10)

    Returns:
        Status of TorNet activation
    """
    if interval < 10:
        interval = 10

    if not _tool_exists("tornet"):
        return (
            "❌ TorNet not found. Install with:\n"
            "  pip install tornet\n"
            "  sudo apt install tor -y\n"
            "  sudo systemctl start tor"
        )

    if not _check_tor_running():
        # Try to start Tor
        rc, _, err = _run(["sudo", "systemctl", "start", "tor"], timeout=15)
        if rc != 0:
            return f"❌ Tor service is not running. Start it first:\n  sudo systemctl start tor\n  Error: {err}"

    # Start TorNet in background
    try:
        proc = subprocess.Popen(
            ["tornet", "--interval", str(interval), "--count", "0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _state.backend = "tornet"
        _state.is_active = True
        _state.rotation_interval = interval
        _state.tornet_pid = proc.pid
        _state.last_rotation = time.time()

        # Wait a moment and check IP
        time.sleep(3)
        ip = _get_current_ip(via_tor=True)
        _state.last_ip = ip

        # Set environment variable so other tools can pick up the proxy
        os.environ["HTTPS_PROXY"] = "socks5://127.0.0.1:9050"
        os.environ["HTTP_PROXY"] = "socks5://127.0.0.1:9050"

        # Also set it on the REPL session
        try:
            from src.repl.session import global_session
            global_session.env_overrides["HTTP_PROXY"] = "socks5://127.0.0.1:9050"
            global_session.env_overrides["HTTPS_PROXY"] = "socks5://127.0.0.1:9050"
            global_session.env_overrides["PROXY"] = "socks5://127.0.0.1:9050"
        except Exception:
            pass

        return "\n".join([
            "## ✅ TorNet Started",
            f"  Rotation interval: every {interval} seconds",
            f"  Current Tor IP:    {ip}",
            f"  TorNet PID:        {proc.pid}",
            f"  SOCKS5 proxy:      socks5://127.0.0.1:9050",
            "",
            "All HTTP tools will now route through Tor automatically.",
            "Use `proxy_rotate_ip` to force an immediate rotation.",
            "Use `proxy_stop` to stop rotation and restore direct connection.",
        ])
    except Exception as e:
        return f"❌ Failed to start TorNet: {e}"


@function_tool()
def proxy_start_anonsurf() -> str:
    """
    Start Anonsurf to route ALL system traffic through Tor.
    This is system-wide — every connection goes through Tor.

    Returns:
        Status of Anonsurf activation
    """
    if not _tool_exists("anonsurf"):
        return (
            "❌ Anonsurf not found. Install with:\n"
            "  sudo apt install anonsurf -y\n"
            "  # OR: git clone https://github.com/Und3rf10w/kali-anonsurf\n"
            "  # cd kali-anonsurf && sudo ./installer.sh"
        )

    # Start anonsurf in the background so it doesn't block
    try:
        import subprocess
        proc = subprocess.Popen(
            ["sudo", "anonsurf", "start"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        # Give it a few seconds to initialize
        time.sleep(5)
    except Exception as e:
        return f"❌ Anonsurf failed to start: {str(e)}"

    _state.backend = "anonsurf"
    _state.is_active = True
    _state.last_rotation = time.time()

    # Wait and check IP
    time.sleep(3)
    ip = _get_current_ip(via_tor=True)
    _state.last_ip = ip

    return "\n".join([
        "## ✅ Anonsurf Started",
        f"  Current Tor IP: {ip}",
        "  Mode: System-wide (ALL traffic goes through Tor)",
        "",
        "Use `proxy_rotate_ip` to request a new identity.",
        "Use `proxy_stop` to stop Anonsurf and restore direct connection.",
        "",
        "⚠️ Note: System-wide mode may slow down all network operations.",
    ])


@function_tool()
def proxy_setup_proxychains() -> str:
    """
    Configure ProxyChains4 to route through Tor. This sets up the
    /etc/proxychains4.conf file to use dynamic_chain mode with Tor's
    SOCKS5 proxy and proxy_dns to prevent DNS leaks.

    ProxyChains is free — it uses your local Tor service as the proxy.
    No paid proxies needed.

    Returns:
        Setup status and usage instructions
    """
    # Check if proxychains is installed
    pc_cmd = "proxychains4" if _tool_exists("proxychains4") else "proxychains"
    if not _tool_exists(pc_cmd):
        return (
            "❌ ProxyChains4 not found. Install with:\n"
            "  sudo apt install proxychains4 -y\n"
            "  sudo apt install tor -y\n"
            "  sudo systemctl start tor"
        )

    if not _check_tor_running():
        rc, _, err = _run(["sudo", "systemctl", "start", "tor"], timeout=15)
        if rc != 0:
            return f"❌ Tor not running. Start it:\n  sudo systemctl start tor\n  Error: {err}"

    conf_path = "/etc/proxychains4.conf"

    # Generate optimized config
    config_content = """# ProxyChains4 Configuration — Optimized for Cyber-CoPilot
# Generated by proxy_manager

# Use dynamic_chain: skips dead proxies, continues through the chain
dynamic_chain

# Quiet mode (less noise in tool output)
quiet_mode

# Proxy DNS requests through the chain (CRITICAL: prevents DNS leaks)
proxy_dns

# Timeouts
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Proxy List
# Route through local Tor SOCKS5 proxy
[ProxyList]
socks5  127.0.0.1 9050

# To add more proxies (free SOCKS5 sources):
# socks5  proxy_ip  proxy_port
# You can find free proxies at:
#   https://spys.one/en/socks-proxy-list/
#   https://www.proxy-list.download/SOCKS5
#   https://hidemy.life/proxy-list
"""

    # Write config (requires sudo)
    try:
        # Write to temp file then move with sudo
        tmp_path = "/tmp/proxychains4.conf.cybercopilot"
        with open(tmp_path, "w") as f:
            f.write(config_content)
        rc, _, err = _run(
            ["sudo", "cp", tmp_path, conf_path], timeout=10
        )
        if rc != 0:
            return (
                f"❌ Could not write config (need sudo):\n  {err}\n\n"
                f"Manual fix — paste this into {conf_path}:\n"
                f"```\n{config_content}```"
            )
    except Exception as e:
        return (
            f"❌ Config write failed: {e}\n\n"
            f"Manual fix — edit {conf_path} with:\n"
            f"```\n{config_content}```"
        )

    _state.backend = "proxychains"

    return "\n".join([
        "## ✅ ProxyChains4 Configured",
        f"  Config: {conf_path}",
        "  Chain type: dynamic_chain",
        "  DNS leak protection: enabled (proxy_dns)",
        "  Proxy: Tor SOCKS5 (127.0.0.1:9050)",
        "",
        "### Usage — prefix any tool with proxychains4:",
        "```bash",
        "proxychains4 nmap -sT -Pn target.com",
        "proxychains4 sqlmap -u 'http://target.com/?id=1'",
        "proxychains4 gobuster dir -u http://target.com -w wordlist.txt",
        "proxychains4 curl http://target.com",
        "proxychains4 nikto -h target.com",
        "proxychains4 ffuf -u http://target.com/FUZZ -w wordlist.txt",
        "```",
        "",
        "### ⚠️ Limitations:",
        "  - Only TCP connections work (no UDP, no ICMP ping)",
        "  - nmap: use -sT (TCP connect) scans only, not -sS (SYN)",
        "  - Add -Pn to nmap (skip host discovery, ICMP won't work)",
        "  - Speed will be reduced (~2-5s latency per request via Tor)",
        "",
        "### 📋 Free Proxy Sources (to add more proxies):",
        "  - https://spys.one/en/socks-proxy-list/",
        "  - https://www.proxy-list.download/SOCKS5",
        "  - https://hidemy.life/proxy-list",
        f"  Add them to {conf_path} under [ProxyList]",
    ])


@function_tool()
def proxy_rotate_ip() -> str:
    """
    Force an immediate IP rotation. Works with any active backend
    (TorNet, Anonsurf, or manual Tor).

    Returns:
        Old IP, new IP, and rotation confirmation
    """
    old_ip = _state.last_ip or _get_current_ip(
        via_tor=_state.backend in ("tornet", "anonsurf")
    )

    if _state.backend == "anonsurf":
        rc, out, err = _run(["sudo", "anonsurf", "change"], timeout=20)
        if rc != 0:
            return f"❌ Anonsurf identity change failed: {err}"
        time.sleep(3)
        new_ip = _get_current_ip(via_tor=True)
        _state.last_ip = new_ip
        _state.total_rotations += 1
        _state.last_rotation = time.time()
        _state.consecutive_bans = 0
        return f"✅ Anonsurf identity changed\n  Old IP: {old_ip}\n  New IP: {new_ip}"

    elif _state.backend == "tornet":
        result = _tornet_rotate()
        _state.consecutive_bans = 0
        return f"{result}\n  Old IP: {old_ip}"

    elif _state.backend in ("proxychains", "none"):
        # Try Tor NEWNYM directly
        if _check_tor_running():
            result = _tornet_rotate()
            _state.consecutive_bans = 0
            return f"{result}\n  Old IP: {old_ip}"
        return (
            "❌ No active rotation backend. Start one first:\n"
            "  - proxy_start_tornet(interval=60)\n"
            "  - proxy_start_anonsurf()\n"
            "  - proxy_setup_proxychains()"
        )

    return "❌ Unknown backend state"


@function_tool()
def proxy_stop() -> str:
    """
    Stop the active proxy/rotation backend and restore direct connection.

    Returns:
        Confirmation of proxy shutdown
    """
    results = []

    if _state.backend == "tornet" and _state.tornet_pid:
        try:
            os.kill(_state.tornet_pid, 15)  # SIGTERM
            results.append(f"✅ TorNet process (PID {_state.tornet_pid}) terminated")
        except Exception as e:
            # Try pkill
            _run(["pkill", "-f", "tornet"])
            results.append(f"✅ TorNet stopped (pkill fallback)")

    elif _state.backend == "anonsurf":
        rc, out, err = _run(["sudo", "anonsurf", "stop"], timeout=20)
        results.append(f"✅ Anonsurf stopped")

    # Clear environment variables
    for var in ["HTTP_PROXY", "HTTPS_PROXY"]:
        os.environ.pop(var, None)

    try:
        from src.repl.session import global_session
        global_session.env_overrides.pop("HTTP_PROXY", None)
        global_session.env_overrides.pop("HTTPS_PROXY", None)
        global_session.env_overrides.pop("PROXY", None)
    except Exception:
        pass

    _state.backend = "none"
    _state.is_active = False
    _state.tornet_pid = None
    _state.consecutive_bans = 0

    # Get real IP
    real_ip = _get_current_ip(via_tor=False)
    results.append(f"  Real IP restored: {real_ip}")
    results.append(f"  Total rotations this session: {_state.total_rotations}")

    if not results:
        results.append("⚠️ No active proxy was running")

    return "\n".join(results)


@function_tool()
def proxy_check_ip() -> str:
    """
    Check your current public IP address, both direct and through Tor
    (if active). Useful to verify proxy is working.

    Returns:
        Current IP addresses
    """
    results = ["## 🌍 IP Address Check\n"]

    # Direct IP
    direct_ip = _get_current_ip(via_tor=False)
    results.append(f"  Direct IP:  {direct_ip}")

    # Tor IP (if Tor is available)
    if _check_tor_running():
        tor_ip = _get_current_ip(via_tor=True)
        results.append(f"  Tor IP:     {tor_ip}")
        if direct_ip != tor_ip and tor_ip != "unknown":
            results.append("  ✅ Tor is working — IPs are different")
        elif tor_ip == "unknown":
            results.append("  ⚠️ Could not reach Tor check service")
        else:
            results.append("  ❌ WARNING: IPs match — Tor may not be routing correctly!")
    else:
        results.append("  Tor:        not running")

    results.append(f"\n  Active backend: {_state.backend}")
    if _state.is_active:
        results.append(f"  Rotations:  {_state.total_rotations}")
        results.append(f"  Bans caught: {_state.ban_detections}")

    return "\n".join(results)


# ─────────────────────────────────────────────────────────────────────────────
# Ban Detection Hook — called by other tools to auto-rotate on ban
# ─────────────────────────────────────────────────────────────────────────────

def on_ban_detected(status_code: int, url: str = "") -> str:
    """
    Called by other tools (http_request, etc.) when a potential ban is detected.
    Auto-rotates IP if enabled and a rotation backend is active.

    Args:
        status_code: HTTP status code (429, 403, 503 indicate bans)
        url: URL that triggered the ban

    Returns:
        Action taken (or empty string if no action)
    """
    if status_code not in (429, 403, 503):
        _state.consecutive_bans = 0
        return ""

    _state.ban_detections += 1
    _state.consecutive_bans += 1

    if not _state.auto_rotate_on_ban or not _state.is_active:
        return ""

    # Only rotate after 2+ consecutive bans (avoid false positives from legit 403s)
    if _state.consecutive_bans >= 2:
        result = proxy_rotate_ip.invoke()
        return f"🔄 Auto-rotated IP after {_state.consecutive_bans} consecutive bans (status {status_code})\n{result}"

    return ""


def get_proxy_url() -> str:
    """
    Get the current proxy URL for injection into tool commands.
    Used by http_request, evasion session, etc.

    Returns:
        Proxy URL string (e.g. 'socks5://127.0.0.1:9050') or empty string
    """
    if _state.is_active and _state.backend in ("tornet", "anonsurf"):
        return "socks5://127.0.0.1:9050"
    return ""


def get_proxychains_prefix() -> list[str]:
    """
    Get the proxychains command prefix for wrapping CLI tools.

    Returns:
        ['proxychains4'] if proxychains is active, [] otherwise
    """
    if _state.backend == "proxychains":
        cmd = "proxychains4" if _tool_exists("proxychains4") else "proxychains"
        return [cmd]
    return []
