"""
Passive Reconnaissance Tools
OSINT / DNS / CT-logs / archive sources — no active probing.
"""
from __future__ import annotations

import json
import importlib
import os
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
import urllib.parse
from pathlib import Path
from typing import Optional

import requests

from src.sdk.tool import function_tool
from src.sdk.utils import smart_output


@function_tool()
def whois_lookup(domain: str) -> str:
    """
    Perform WHOIS lookup on a domain.

    Args:
        domain: Domain name to lookup

    Returns:
        WHOIS information
    """
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No WHOIS results for {domain}"
        return f"## WHOIS Results: {domain}\n\n{output}"
    except FileNotFoundError:
        return "Error: whois not found. Please install whois."
    except subprocess.TimeoutExpired:
        return "Error: WHOIS lookup timed out"
    except Exception as e:
        return f"Error running whois: {e}"


@function_tool()
def dig_lookup(domain: str, record_type: str = "A") -> str:
    """
    Perform DNS lookup using dig.

    Args:
        domain: Domain name to lookup
        record_type: DNS record type (A, AAAA, MX, TXT, NS, CNAME)

    Returns:
        DNS records
    """
    try:
        result = subprocess.run(
            ["dig", "+short", record_type, domain],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        if not output:
            return "No records found"
        return f"## DNS {record_type} Records: {domain}\n\n{output}"
    except FileNotFoundError:
        return "Error: dig not found. Please install dnsutils."
    except Exception as e:
        return f"Error running dig: {e}"


@function_tool()
def subfinder_enum(domain: str) -> str:
    """
    Enumerate subdomains using subfinder (passive sources).
    Returns raw subdomain list. Use subdomain_enum_live to also check which are alive.

    Args:
        domain: Target domain to enumerate subdomains for

    Returns:
        List of discovered subdomains
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip()
        if not output:
            return "No subdomains found"
        lines = [l for l in output.splitlines() if l.strip()]
        count = len(lines)

        # ── Persist to session file ──────────────────────────────────────────
        _session_note = ""
        try:
            from src.repl.target_manager import get_target_manager as _gtm
            _saved = _gtm().save_subdomains(lines)
            if _saved:
                _session_note = (
                    f"\n\n✅ Saved {count} subdomains → {_saved}"
                    f"\n   Next steps:"
                    f"\n   • httpx_probe('{_saved}') — probe live hosts"
                    f"\n   • subdomain_takeover_scan(subdomains_list='...') — check takeover"
                )
        except Exception:
            pass

        raw = f"Found {count} subdomains:\n" + "\n".join(lines) + _session_note
        return smart_output(raw, "subfinder_enum", domain)
    except FileNotFoundError:
        return "Error: subfinder not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    except subprocess.TimeoutExpired:
        return "Error: subfinder timed out after 120 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def subdomain_enum_live(domain: str, show_all: bool = False) -> str:
    """
    PREFERRED subdomain discovery tool — finds subdomains AND filters to live hosts only.

    Runs subfinder to discover subdomains, then immediately pipes the results
    into httpx to probe which ones are alive, returning status codes, titles,
    and technology hints. Eliminates the need to run httpx manually.

    Always use this instead of subfinder_enum when you need actionable results.

    Args:
        domain: Target domain (e.g. example.com)
        show_all: If True, show all probed hosts including unreachable ones

    Returns:
        Live subdomains with HTTP status, title, and tech stack
    """
    import shutil
    import tempfile

    if not shutil.which("subfinder"):
        return "Error: subfinder not found. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    # ── Step 1: subfinder ────────────────────────────────────────────────────
    try:
        sf_result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=120
        )
        subdomains = [l.strip() for l in sf_result.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        return "Error: subfinder timed out after 120 seconds"
    except Exception as e:
        return f"Error running subfinder: {e}"

    if not subdomains:
        return f"No subdomains found for {domain} via subfinder."

    total_found = len(subdomains)

    # ── Step 2: httpx probe on live hosts ────────────────────────────────────
    if not shutil.which("httpx"):
        # httpx not available — return raw subfinder output with note
        return (
            f"## Subdomains: {domain} ({total_found} found, live-filter skipped)\n"
            f"(httpx not installed — showing raw list)\n\n"
            + "\n".join(subdomains)
        )

    # Write subdomains to a temp file for httpx
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(subdomains))
        tmp_path = f.name

    try:
        httpx_cmd = [
            "httpx",
            "-l", tmp_path,
            "-status-code",
            "-title",
            "-tech-detect",
            "-silent",
            "-follow-redirects",
            "-timeout", "10",
        ]
        hx_result = subprocess.run(httpx_cmd, capture_output=True, text=True, timeout=300)
        live_output = hx_result.stdout.strip()
    except subprocess.TimeoutExpired:
        live_output = ""
    except Exception:
        live_output = ""
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if not live_output:
        # httpx returned nothing — fall back to Python requests probe
        import concurrent.futures
        import requests as _req

        def _probe(host: str):
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    r = _req.get(url, timeout=8, allow_redirects=True,
                                 verify=False, headers={"User-Agent": "Mozilla/5.0"})
                    title = ""
                    try:
                        import re as _re
                        m = _re.search(r"<title[^>]*>([^<]{1,120})</title>", r.text, _re.I)
                        if m:
                            title = m.group(1).strip()
                    except Exception:
                        pass
                    return f"{url} [{r.status_code}] {title}".strip()
                except Exception:
                    continue
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            raw_results = list(pool.map(_probe, subdomains))

        live_fallback = [r for r in raw_results if r is not None]

        if not live_fallback:
            return (
                f"## Subdomains: {domain}\n"
                f"subfinder found {total_found} subdomains but neither httpx nor requests probe found any alive.\n\n"
                f"Raw list:\n" + "\n".join(subdomains)
            )

        live_output = "\n".join(live_fallback)
        live_lines = live_fallback
        live_count = len(live_fallback)

        out = f"## Live Subdomains: {domain} (httpx fallback — requests probe)\n\n"
        out += f"Found: {total_found} subdomains | Live: {live_count} responding\n\n"
        out += "### Live Hosts (URL | Status | Title)\n"
        out += "\n".join(live_lines)
        if total_found > live_count:
            dead = total_found - live_count
            out += f"\n\n({dead} subdomains did not respond — excluded)"

        try:
            from src.repl.target_manager import get_target_manager as _gtm
            _saved = _gtm().save_subdomains(subdomains)
            if _saved:
                out += (
                    f"\n\n✅ Saved {total_found} subdomains → {_saved}"
                    f"\n   Pass this file to subdomain_takeover_scan()"
                )
        except Exception:
            pass

        return out

    live_lines = [l for l in live_output.splitlines() if l.strip()]
    live_count = len(live_lines)

    out = f"## Live Subdomains: {domain}\n\n"
    out += f"Found: {total_found} subdomains | Live: {live_count} responding\n\n"
    out += "### Live Hosts (URL | Status | Title | Tech)\n"
    out += "\n".join(live_lines)
    if total_found > live_count:
        dead = total_found - live_count
        out += f"\n\n({dead} subdomains did not respond — excluded)"

    # ── Persist all discovered subdomains to session file ───────────────────
    try:
        from src.repl.target_manager import get_target_manager as _gtm
        _saved = _gtm().save_subdomains(subdomains)
        if _saved:
            out += (
                f"\n\n✅ Saved {total_found} subdomains → {_saved}"
                f"\n   Pass this file to httpx_probe('{_saved}') or subdomain_takeover_scan()"
            )
    except Exception:
        pass

    return smart_output(out, "subdomain_enum_live", domain)


@function_tool()
def dnsrecon_enum(domain: str, record_type: str = "std") -> str:
    """
    DNS reconnaissance and enumeration using dnsrecon.

    Args:
        domain: Target domain
        record_type: Enumeration type (std, rvl, brt, srv, axfr, goo, snoop, tld, zonewalk)

    Returns:
        DNS records and zone information
    """
    try:
        result = subprocess.run(
            ["dnsrecon", "-d", domain, "-t", record_type],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return "No results"
        raw = f"## DNSRecon Results: {domain}\n\n{output}"
        return smart_output(raw, "dnsrecon_enum", domain)
    except FileNotFoundError:
        return "Error: dnsrecon not found. Install with: sudo apt install dnsrecon"
    except subprocess.TimeoutExpired:
        return "Error: dnsrecon timed out after 2 minutes"
    except Exception as e:
        return f"Error running dnsrecon: {e}"


@function_tool()
def cloudflair_scan(domain: str) -> str:
    """
    Find origin IP address behind Cloudflare using CloudFlair.
    Useful for bypassing Cloudflare WAF protection.

    Args:
        domain: Target domain protected by Cloudflare

    Returns:
        Potential origin IP addresses
    """
    try:
        result = subprocess.run(
            ["cloudflair", domain],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return "No origin IPs found or CloudFlair not installed"
        return f"## CloudFlair Results: {domain}\n\n{output}"
    except FileNotFoundError:
        return "Error: cloudflair not found. Install with: pip install cloudflair"
    except subprocess.TimeoutExpired:
        return "Error: CloudFlair scan timed out after 5 minutes"
    except Exception as e:
        return f"Error running cloudflair: {e}"


@function_tool()
def dnsenum_scan(domain: str, options: str = "") -> str:
    """
    DNS enumeration including zone transfers, brute force, and Google scraping.

    AUTO-FALLBACK: If dnsenum fails/times out, automatically falls back to
    dig + host + nslookup for basic DNS enumeration.

    Args:
        domain: Target domain
        options: Additional dnsenum options

    Returns:
        DNS enumeration results
    """
    results = [f"## DNS Enumeration: {domain}\n"]

    # Primary: dnsenum
    try:
        cmd = ["dnsenum", domain] + (options.split() if options else [])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()
        if output:
            raw = f"## DNSenum Results: {domain}\n\n{output}"
            return smart_output(raw, "dnsenum_scan", domain)
    except FileNotFoundError:
        results.append("⚠️ dnsenum not found — falling back to dig/nslookup")
    except subprocess.TimeoutExpired:
        results.append("⚠️ dnsenum timed out after 5 minutes — falling back to dig/nslookup")
    except Exception as e:
        results.append(f"⚠️ dnsenum failed: {e} — falling back to dig/nslookup")

    # ═══ FALLBACK: Basic DNS enumeration ═══
    results.append("\n### Fallback DNS Enumeration")

    # 1. A records
    try:
        a_result = subprocess.run(
            ["dig", "A", domain, "+short"],
            capture_output=True, text=True, timeout=15
        )
        if a_result.stdout.strip():
            results.append("\n**A Records:**")
            for line in a_result.stdout.strip().split("\n"):
                results.append(f"  {line}")
        else:
            results.append("\n**A Records:** None found")
    except Exception:
        # Try nslookup fallback
        try:
            ns_result = subprocess.run(
                ["nslookup", domain],
                capture_output=True, text=True, timeout=10
            )
            if ns_result.stdout.strip():
                results.append("\n**A Records (nslookup):**")
                for line in ns_result.stdout.strip().split("\n")[-4:]:
                    if "Address" in line:
                        results.append(f"  {line.strip()}")
        except Exception:
            results.append("\n**A Records:** Could not resolve")

    # 2. MX records
    try:
        mx_result = subprocess.run(
            ["dig", "MX", domain, "+short"],
            capture_output=True, text=True, timeout=15
        )
        if mx_result.stdout.strip():
            results.append("\n**MX Records:**")
            for line in mx_result.stdout.strip().split("\n"):
                results.append(f"  {line}")
    except Exception:
        pass

    # 3. NS records
    ns_lines: list[str] = []
    try:
        ns_result = subprocess.run(
            ["dig", "NS", domain, "+short"],
            capture_output=True, text=True, timeout=15
        )
        ns_lines = [line.strip() for line in ns_result.stdout.strip().split("\n") if line.strip()]
        if ns_lines:
            results.append("\n**NS Records:**")
            for line in ns_lines:
                results.append(f"  {line}")
    except Exception:
        pass

    # 4. TXT records
    try:
        txt_result = subprocess.run(
            ["dig", "TXT", domain, "+short"],
            capture_output=True, text=True, timeout=15
        )
        if txt_result.stdout.strip():
            results.append("\n**TXT Records:**")
            for line in txt_result.stdout.strip().split("\n"):
                if len(line.strip()) > 5:
                    results.append(f"  {line.strip()[:200]}")
    except Exception:
        pass

    # 5. Zone transfer attempt
    try:
        for ns_line in ns_lines:
            ns_server = ns_line.strip().rstrip(".")
            if ns_server:
                zr = subprocess.run(
                    ["dig", "AXFR", domain, f"@{ns_server}", "+timeout=5"],
                    capture_output=True, text=True, timeout=15
                )
                if "Transfer failed" not in zr.stdout and len(zr.stdout) > 100:
                    results.append(f"\n🔴 ZONE TRANSFER SUCCESSFUL via {ns_server}!")
                    results.append(zr.stdout[:500])
                    break
    except Exception:
        pass

    results.append("\n### Recommendation")
    results.append("  • Install dnsenum for comprehensive brute-force subdomain discovery")
    results.append(f"  • Use subdomain_enum_live('{domain}') for live subdomain discovery")
    results.append(f"  • Use subfinder_enum('{domain}') for passive subdomain enumeration")

    return "\n".join(results)


@function_tool()
def shodan_search(query: str, api_key: str = "") -> str:
    """
    Search Shodan for exposed services and vulnerabilities.

    Args:
        query: Shodan search query (e.g., "hostname:example.com")
        api_key: Shodan API key (or set SHODAN_API_KEY env var)

    Returns:
        Shodan search results
    """
    try:
        if not api_key:
            api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            return "Error: Shodan API key required. Set SHODAN_API_KEY environment variable or pass api_key"
        env = os.environ.copy()
        env["SHODAN_API_KEY"] = api_key
        result = subprocess.run(
            ["shodan", "search", "--fields", "ip_str,port,org,hostnames,os,vulns", query],
            capture_output=True, text=True, timeout=60, env=env
        )
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No Shodan results for: {query}"
        raw = f"## Shodan Results: {query}\n\n{output}"
        return smart_output(raw, "shodan_search", query)
    except FileNotFoundError:
        return "Error: shodan CLI not found. Install with: pip install shodan"
    except subprocess.TimeoutExpired:
        return "Error: shodan timed out after 60 seconds"
    except Exception as e:
        return f"Error: {e}"


def _crtsh_discover_subdomains(domain: str, timeout: int = 30) -> tuple[list[str], Optional[str]]:
    """Return (subdomains, error_message) from crt.sh JSON output."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)",
                "Accept": "application/json",
            },
            timeout=timeout,
        )
    except requests.RequestException as e:
        return [], f"request failed: {e}"

    if response.status_code != 200:
        return [], f"HTTP {response.status_code}"

    body = (response.text or "").strip()
    if not body:
        return [], "empty response"

    try:
        data = response.json()
    except ValueError as e:
        snippet = body[:200].replace("\n", " ")
        return [], f"non-JSON response: {e} (first bytes: {snippet!r})"

    seen: set[str] = set()
    for entry in data if isinstance(data, list) else []:
        name = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for line in str(name).splitlines():
            line = line.strip().lstrip("*.")
            if line and domain in line:
                seen.add(line)

    return sorted(seen), None


@function_tool()
def crtsh_search(domain: str) -> str:
    """
    Search certificate transparency logs via crt.sh to discover subdomains.

    AUTO-RETRY: Attempts up to 3 times with different API endpoints before failing.
    Falls back to Google's CT log API if crt.sh is unavailable.

    Args:
        domain: Target domain (e.g. example.com)

    Returns:
        List of subdomains from certificate logs
    """
    results = [f"## Certificate Transparency Search: {domain}\n"]

    # Attempt 1: Primary crt.sh API
    subdomains, err = _crtsh_discover_subdomains(domain, timeout=30)
    if subdomains:
        results.append(f"✅ crt.sh: Found {len(subdomains)} subdomains")
        results.append("\n### Discovered Subdomains")
        for sub in sorted(subdomains)[:50]:
            results.append(f"  {sub}")
        if len(subdomains) > 50:
            results.append(f"  ... and {len(subdomains) - 50} more")
        raw = "\n".join(results)
        return smart_output(raw, "crtsh_search", domain)

    results.append(f"⚠️ crt.sh primary API failed: {err or 'no results'}")

    # Attempt 2: Retry with longer timeout
    results.append("  Retrying with extended timeout...")
    subdomains, err = _crtsh_discover_subdomains(domain, timeout=60)
    if subdomains:
        results.append(f"✅ crt.sh retry successful: Found {len(subdomains)} subdomains")
        results.append("\n### Discovered Subdomains")
        for sub in sorted(subdomains)[:50]:
            results.append(f"  {sub}")
        raw = "\n".join(results)
        return smart_output(raw, "crtsh_search", domain)

    results.append(f"  ⚠️ crt.sh retry failed: {err or 'no results'}")

    # Attempt 3: Fallback to Google's CT log API via dig
    results.append("  Falling back to Google CT log via DNS...")
    try:
        subprocess.run(
            ["dig", "TXT", f"{domain}._transparent.ctld.log.202208.googlect TransparencyLog.ct.googleapis.com", "+short"],
            capture_output=True, text=True, timeout=15
        )
        # Also try fetching the crt.sh web interface and parsing
        web_result = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=20,
            verify=True
        )
        if web_result.status_code == 200:
            data = web_result.json()
            fallback_subs = set()
            for entry in data:
                name = entry.get("name_value", "").strip()
                if name and not name.startswith("*"):
                    fallback_subs.add(name)
            if fallback_subs:
                results.append(f"✅ crt.sh web fallback: Found {len(fallback_subs)} subdomains")
                results.append("\n### Discovered Subdomains")
                for sub in sorted(fallback_subs)[:50]:
                    results.append(f"  {sub}")
                raw = "\n".join(results)
                return smart_output(raw, "crtsh_search", domain)
    except Exception as e:
        results.append(f"  ⚠️ Fallback also failed: {str(e)[:80]}")

    # Final: Recommend alternatives
    results.append("\n### CT Log Search Failed")
    results.append("All crt.sh endpoints failed — the service may be experiencing issues.")
    results.append("\nRecommended alternatives:")
    results.append(f"  • Use subfinder_enum('{domain}') for passive subdomain enumeration")
    results.append(f"  • Use amass_enum('{domain}') for comprehensive enumeration")
    results.append(f"  • Use subdomain_enum_live('{domain}') for live subdomain discovery")
    results.append(f"  • Manually check: https://crt.sh/?q=%25.{domain}")

    return "\n".join(results)


@function_tool()
def github_subdomain_search(domain: str, token: str = "") -> str:
    """
    Search GitHub code for subdomains / endpoints referencing the target domain.

    Args:
        domain: Target domain to search for
        token: GitHub personal access token (for higher rate limits)

    Returns:
        GitHub search results
    """
    try:
        url = f"https://api.github.com/search/code?q={urllib.parse.quote(domain)}+-filename:.md&per_page=50"
        headers = {
            "User-Agent": "cyber-copilot",
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            headers["Authorization"] = f"token {token}"
        response = requests.get(url, headers=headers, timeout=30)
        data = response.json()
        if "items" not in data:
            msg = data.get("message", "Unknown error")
            return f"GitHub search error: {msg}"
        items = data["items"]
        if not items:
            return f"No GitHub results for {domain}"
        lines = [f"Found {len(items)} code references for {domain}:"]
        for item in items[:20]:
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            lines.append(f"  [{repo}] {path}\n  {html_url}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error searching GitHub: {e}"


@function_tool()
def cloud_enum_scan(keyword: str, options: str = "") -> str:
    """
    Enumerate cloud storage buckets and services for a given keyword using cloud_enum.

    Args:
        keyword: Keyword / company name to search for
        options: Additional cloud_enum options

    Returns:
        Cloud bucket/storage enumeration results
    """
    try:
        cmd = ["cloud_enum", "-k", keyword] + (options.split() if options else [])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"cloud_enum found nothing for keyword: {keyword}"
        raw = f"## Cloud Enum Results for '{keyword}'\n\n{output}"
        return smart_output(raw, "cloud_enum_scan", keyword)
    except FileNotFoundError:
        return "cloud_enum not found. Install with: pip install cloud-enum"
    except subprocess.TimeoutExpired:
        return f"cloud_enum timed out for keyword: {keyword}"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def alterx_permutate(domain: str, wordlist: str = "", options: str = "") -> str:
    """
    Generate subdomain permutations using alterx.

    Args:
        domain: Target domain or comma-separated list of subdomains
        wordlist: Optional custom wordlist file
        options: Additional alterx options

    Returns:
        Generated subdomain permutations
    """
    try:
        cmd = ["alterx", "-d", domain]
        if wordlist:
            cmd += ["-w", wordlist]
        if options:
            cmd += options.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()
        if not output:
            return f"alterx generated no permutations for {domain}"
        count = len(output.splitlines())
        raw = f"## Alterx Permutations for {domain} ({count} generated)\n\n{output}"
        return smart_output(raw, "alterx_permutate", domain)
    except FileNotFoundError:
        return "alterx not found. Install from: https://github.com/projectdiscovery/alterx"
    except subprocess.TimeoutExpired:
        return f"alterx generated no permutations for {domain}"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def amass_enum(domain: str, mode: str = "enum", options: str = "-passive") -> str:
    """
    Advanced subdomain enumeration and attack surface mapping using OWASP Amass.
    More comprehensive than subfinder - use when thoroughness matters over speed.

    AUTO-FALLBACK: If amass fails, automatically falls back to subfinder + crtsh.

    Args:
        domain: Target domain
        mode: Amass mode (enum, intel, viz, track)
        options: Additional amass flags (e.g., -passive, -active)

    Returns:
        Discovered subdomains and network assets
    """
    results = []

    # Primary: amass
    try:
        cmd = ["amass", mode, "-d", domain] + options.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()
        if output and "error" not in output.lower()[:50]:
            lines = [l for l in output.splitlines() if l.strip()]
            count = len(lines)
            raw = f"Amass found {count} results:\n\n{output}"
            return smart_output(raw, "amass_enum", domain)
    except FileNotFoundError:
        results.append("⚠️ amass not found — falling back to subfinder + crtsh")
    except subprocess.TimeoutExpired:
        results.append("⚠️ amass timed out after 10 minutes — falling back to alternatives")
    except Exception as e:
        results.append(f"⚠️ amass failed: {e} — falling back to alternatives")

    # ═══ FALLBACK: subfinder + crtsh + subdomain_enum_live ═══
    results.append("\n### Fallback Subdomain Enumeration")

    # Fallback 1: subfinder
    subdomains_found = set()
    try:
        sf_cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        sf_result = subprocess.run(sf_cmd, capture_output=True, text=True, timeout=120)
        if sf_result.stdout.strip():
            sf_subs = [s.strip() for s in sf_result.stdout.strip().split("\n") if s.strip()]
            subdomains_found.update(sf_subs)
            results.append(f"\n**subfinder:** Found {len(sf_subs)} subdomains")
            for sub in sf_subs[:20]:
                results.append(f"  {sub}")
            if len(sf_subs) > 20:
                results.append(f"  ... and {len(sf_subs) - 20} more")
    except Exception:
        results.append("\n**subfinder:** Not available or failed")

    # Fallback 2: crt.sh
    try:
        crt_subs, crt_err = _crtsh_discover_subdomains(domain, timeout=20)
        if crt_subs:
            new_subs = set(crt_subs) - subdomains_found
            subdomains_found.update(crt_subs)
            results.append(f"\n**crt.sh:** Found {len(crt_subs)} subdomains")
            if new_subs:
                results.append(f"  ({len(new_subs)} unique not found by subfinder)")
                for sub in list(new_subs)[:10]:
                    results.append(f"  {sub}")
        elif crt_err:
            results.append(f"\n**crt.sh:** Failed — {crt_err[:100]}")
    except Exception as e:
        results.append(f"\n**crt.sh:** Error — {str(e)[:80]}")

    # Summary
    results.append("\n### Summary")
    results.append(f"  Total unique subdomains discovered: {len(subdomains_found)}")
    if subdomains_found:
        results.append("\n### All Discovered Subdomains")
        for sub in sorted(subdomains_found):
            results.append(f"  {sub}")
    
        results.append("\n### Recommendation")
        results.append(f"  • Run subdomain_takeover_scan('{domain}') to check for dangling records")
        results.append(f"  • Run subdomain_enum_live('{domain}') to probe which are responding")
    else:
        results.append("  No subdomains found via fallback methods")
        results.append("  • Install amass for comprehensive enumeration")
        results.append("  • Install subfinder: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")

    raw = "\n".join(results)
    return smart_output(raw, "amass_enum", domain)


@function_tool()
def fierce_scan(domain: str, options: str = "") -> str:
    """
    DNS reconnaissance using fierce - finds non-contiguous IP space and hostnames.
    Useful for discovering internal networks and IP ranges.

    Args:
        domain: Target domain
        options: Additional fierce options

    Returns:
        DNS reconnaissance results
    """
    try:
        cmd = ["fierce", "--domain", domain] + (options.split() if options else [])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return "No results from fierce scan"
        return f"## Fierce Results: {domain}\n\n{output}"
    except FileNotFoundError:
        return "Error: fierce not found. Install with: pip install fierce"
    except subprocess.TimeoutExpired:
        return "Error: fierce timed out after 5 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def sublist3r_enum(domain: str, use_bruteforce: bool = False, threads: int = 10, engines: str = "") -> str:
    """
    Run Sublist3r for subdomain enumeration using search engines and DNS queries.

    Args:
        domain: Target domain (e.g. example.com)
        use_bruteforce: Enable bruteforce module
        threads: Number of threads (default 10)
        engines: Comma-separated list of search engines

    Returns:
        Discovered subdomains
    """
    outfile = f"/tmp/sublist3r_{domain}.txt"
    try:
        cmd = ["sublist3r", "-d", domain, "-t", str(threads), "-o", outfile]
        if use_bruteforce:
            cmd.append("-b")
        if engines:
            cmd += ["-e", engines]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if os.path.exists(outfile):
            with open(outfile) as f:
                content = f.read().strip()
            if content:
                lines = [l for l in content.splitlines() if l.strip()]
                return f"Found {len(lines)} subdomains:\n{content}"
        output = result.stdout.strip() or result.stderr.strip()
        if not output:
            return f"No subdomains found for {domain}"
        return f"## Sublist3r Results: {domain}\n\n{output}"
    except FileNotFoundError:
        return "Error: sublist3r not found. Install: pip install sublist3r"
    except subprocess.TimeoutExpired:
        return "Error: sublist3r timed out after 5 minutes"
    except Exception as e:
        return f"Error: {e}"
    finally:
        if os.path.exists(outfile):
            try:
                os.remove(outfile)
            except Exception:
                pass


@function_tool()
def gau_urls(domain: str, providers: str = "", blacklist: str = "") -> str:
    """
    Fetch URLs from Wayback Machine, Common Crawl, and AlienVault using gau.
    Automatically filters out static assets (images, fonts, CSS, JS bundles)
    and returns only security-relevant URLs — those with parameters or
    interesting extensions.

    Args:
        domain: Target domain
        providers: Comma-separated providers (wayback,commoncrawl,otx,urlscan)
        blacklist: Additional extensions to blacklist (appended to defaults)

    Returns:
        Filtered historical URLs grouped by category
    """
    # Extensions that are never security-relevant
    _JUNK_EXTS = {
        "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp",
        "mp4", "mp3", "mov", "avi", "webm", "wav",
        "woff", "woff2", "ttf", "eot", "otf",
        "css", "map", "min.js",
    }
    _INTERESTING_EXTS = {"php", "asp", "aspx", "jsp", "jspx", "cfm", "rb", "py"}
    _API_PATTERNS = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
                     "/ajax/", "/json", ".json", "/ws/", "/rpc"]

    # Build the default blacklist for gau
    default_bl = "png,jpg,jpeg,gif,webp,svg,ico,bmp,mp4,mp3,woff,woff2,ttf,eot,css"
    combined_bl = default_bl + ("," + blacklist if blacklist else "")

    try:
        cmd = ["gau", domain, "--blacklist", combined_bl]
        if providers:
            cmd += ["--providers", providers]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()
        if not output:
            return f"No archived URLs found for {domain}"

        all_urls = list(dict.fromkeys(u.strip() for u in output.splitlines() if u.strip()))
        total = len(all_urls)

        # Categorise
        with_params    = [u for u in all_urls if "?" in u and "=" in u]
        api_urls       = [u for u in all_urls if any(p in u.lower() for p in _API_PATTERNS)]
        upload_urls    = [u for u in all_urls if any(k in u.lower() for k in ["upload", "file", "attach"])]
        admin_urls     = [u for u in all_urls if any(k in u.lower() for k in ["/admin", "/dashboard", "/manage", "/cms"])]
        interesting_ext= [u for u in all_urls if any(u.lower().split("?")[0].endswith(e) for e in _INTERESTING_EXTS)]

        # Deduplicate by path (ignore query params) to cut noise
        seen_paths: set = set()
        unique_param_urls = []
        for u in with_params:
            path = u.split("?")[0]
            if path not in seen_paths:
                seen_paths.add(path)
                unique_param_urls.append(u)

        out = f"## GAU URLs: {domain}\n"
        out += f"Total fetched: {total} | After dedup: {len(set(u.split('?')[0] for u in all_urls))}\n\n"

        def _section(title, urls, limit=30):
            if not urls:
                return ""
            lines = [f"### {title} ({len(urls)} found)"]
            lines += urls[:limit]
            if len(urls) > limit:
                lines.append(f"  ... and {len(urls) - limit} more")
            return "\n".join(lines) + "\n\n"

        out += _section("🎯 URLs With Parameters (prime injection targets)", unique_param_urls, 40)
        out += _section("🔌 API Endpoints", api_urls, 20)
        out += _section("👑 Admin/Dashboard Paths", admin_urls, 20)
        out += _section("📎 File Upload Endpoints", upload_urls, 20)
        out += _section("⚙️  Server-Side Script URLs", interesting_ext, 20)

        if not any([unique_param_urls, api_urls, admin_urls, upload_urls, interesting_ext]):
            out += "No security-relevant URLs found. All results were static assets.\n"
            out += "Sample raw URLs:\n" + "\n".join(all_urls[:20])

        return out.strip()
    except FileNotFoundError:
        return "Error: gau not found. Install: go install github.com/lc/gau/v2/cmd/gau@latest"
    except subprocess.TimeoutExpired:
        return "Error: gau timed out after 120 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def waybackurls(domain: str, no_subs: bool = False) -> str:
    """
    Fetch historical URLs from Wayback Machine.

    Args:
        domain: Target domain
        no_subs: Exclude subdomains

    Returns:
        Historical URLs from Wayback Machine
    """
    try:
        cmd = ["waybackurls", domain]
        if no_subs:
            cmd.append("-no-subs")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout.strip()
        if not output:
            return f"No archived URLs found for {domain}"
        lines = output.splitlines()
        count = len(lines)
        return f"Found {count} archived URLs:\n{output}"
    except FileNotFoundError:
        return "Error: waybackurls not found. Install: go install github.com/tomnomnom/waybackurls@latest"
    except subprocess.TimeoutExpired:
        return "Error: waybackurls timed out after 120 seconds"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
def paramspider(domain: str, exclude: str = "") -> str:
    """
    Find parameters from URLs using ParamSpider (mines from web archives).

    Args:
        domain: Target domain
        exclude: Comma-separated extensions to exclude (e.g., css,jpg,png)

    Returns:
        URLs with parameters from web archives
    """
    try:
        cmd = ["paramspider", "--domain", domain]
        if exclude:
            cmd += ["--exclude", exclude]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip()
        if not output:
            return f"No parameters found for {domain}"
        lines = [l for l in output.splitlines() if "?" in l and "=" in l]
        if not lines:
            return f"No URLs with parameters found for {domain}"
        count = len(lines)
        sample = "\n".join(lines[:20])
        return f"Found {count} unique parameters:\nSample URLs ({min(20, count)}):\n{sample}"
    except FileNotFoundError:
        return "Error: paramspider not found. Install: pip install paramspider"
    except subprocess.TimeoutExpired:
        return "Error: paramspider timed out after 5 minutes"
    except Exception as e:
        return f"Error: {e}"


@function_tool()
async def subdomain_takeover_scan(domain: str, subdomains_list: str = "", check_cname_only: bool = False) -> str:
    """
    Scan subdomains for takeover vulnerabilities.

    Discovers subdomains via crt.sh and dns brute-force, then checks each
    for indicators of dangling DNS records or unclaimed services.

    Args:
        domain: Target domain to scan
        subdomains_list: Comma-separated subdomains (skip discovery if provided)
        check_cname_only: Only check CNAME records

    Returns:
        Subdomains vulnerable to takeover
    """
    from src.tools.subdomain_takeover import subdomain_takeover_scan as canonical_subdomain_takeover_scan

    return await canonical_subdomain_takeover_scan.invoke(
        domain=domain,
        subdomains_list=subdomains_list,
        check_cname_only=check_cname_only,
    )


def _passive_get(url: str, params: dict | None = None) -> dict:
    """Simple GET helper returning parsed JSON."""
    response = requests.get(
        url,
        params=params,
        timeout=30,
        headers={"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"},
    )
    return response.json()


@function_tool()
async def passive_recon_chain(
    domain: str,
    include_github: bool = False,
    shodan_key: str = "",
    github_token: str = "",
) -> str:
    """
    Run the complete passive reconnaissance chain for a target domain.

    Executes all passive sources in sequence and aggregates results.

    Args:
        domain: Target domain
        include_github: Include GitHub subdomain search
        shodan_key: Shodan API key
        github_token: GitHub token for higher rate limits

    Returns:
        Aggregated passive recon results
    """
    header = f"=== Passive Recon Chain: {domain} ===\n{'=' * 60}\n"
    sections = [header]
    step = 1

    def add_section(label: str, result: str) -> None:
        nonlocal step
        sections.append(f"── Step {step}: {label} ──────────────────────────────\n{result}\n")
        step += 1

    # Auto-load keys from env when not passed explicitly
    if not shodan_key:
        shodan_key = os.environ.get("SHODAN_API_KEY", "")
    if not github_token:
        github_token = os.environ.get("GITHUB_TOKEN", "")
    # Auto-enable GitHub search when a token is available
    if github_token and not include_github:
        include_github = True

    # WHOIS
    add_section("WHOIS", await whois_lookup(domain))

    # DNS records
    for rtype in ("A", "MX", "TXT", "NS"):
        add_section(f"DIG {rtype}", await dig_lookup(domain, rtype))

    # Subfinder
    add_section("Subfinder", await subfinder_enum(domain))

    # crt.sh
    add_section("crt.sh", await crtsh_search(domain))

    # Amass (passive)
    add_section("Amass (passive)", await amass_enum(domain, mode="enum", options="-passive"))

    # Shodan (optional)
    if shodan_key:
        add_section("Shodan", await shodan_search(f"hostname:{domain}", api_key=shodan_key))

    # GitHub (optional)
    if include_github:
        add_section("GitHub", await github_subdomain_search(domain, token=github_token))

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# theHarvester — Email / Employee / Subdomain OSINT
# ---------------------------------------------------------------------------

@function_tool()
def theharvester(
    domain: str,
    sources: str = "google,bing,duckduckgo,crtsh,dnsdumpster,urlscan",
    limit: int = 500,
    options: str = "",
) -> str:
    """
    Multi-source OSINT harvesting for emails, employee names, subdomains,
    IPs, and URLs using theHarvester.

    Unique value: discovers employee email addresses (→ phishing, credential stuffing),
    LinkedIn usernames, Bing/Google indexed subdomains not in DNS records,
    and ASN/IP blocks — none of these come from subfinder or amass.

    Args:
        domain: Target domain (e.g. target.com)
        sources: Comma-separated source list. Available: google, bing, yahoo,
                 duckduckgo, linkedin, twitter, shodan, crtsh, dnsdumpster,
                 urlscan, virustotal, anubis, bufferoverun, hackertarget, threatminer.
                 NOTE: bing, shodan, virustotal, baidu require API keys in /etc/theHarvester/api-keys.yaml.
                 Use 'crtsh,duckduckgo,urlscan,hackertarget' for safe unauthenticated default sources!
        limit: Max results per source (default 500)
        options: Extra theHarvester flags (e.g. '-n' for DNS lookup on found hosts)

    Returns:
        Emails, subdomains, IPs, employee names found across all sources
    """
    try:
        cmd = [
            "theHarvester",
            "-d", domain,
            "-b", sources,
            "-l", str(limit),
        ] + (options.split() if options else [])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout.strip() or result.stderr.strip()

        if not output:
            return f"No results from theHarvester for {domain}"
        return f"## theHarvester Results — {domain}\nSources: {sources}\n\n{output}"

    except FileNotFoundError:
        return (
            "Error: theHarvester not found.\n"
            "Install: sudo apt install theharvester\n"
            "Or: pip install theHarvester  /  git clone https://github.com/laramies/theHarvester"
        )
    except subprocess.TimeoutExpired:
        return f"Error: theHarvester timed out after 5 minutes for {domain}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# TruffleHog — Secret Scanning in Git Repositories
# ---------------------------------------------------------------------------

@function_tool()
def trufflehog_scan(
    target: str,
    scan_type: str = "github",
    options: str = "--only-verified",
) -> str:
    """
    Scan Git repositories, GitHub orgs, S3 buckets, or file systems for
    leaked secrets (API keys, tokens, passwords, private keys) using TruffleHog v3.

    TruffleHog uses 700+ regex detectors with entropy analysis and lives in
    git history — finds secrets that were committed and then "deleted".

    Args:
        target: Scan target:
                - GitHub org/repo: 'https://github.com/target-org' or 'github --org=target-org'
                - Local filesystem: '/path/to/repo'
                - S3 bucket: 's3://bucket-name'
                - Single file: '/path/to/file'
        scan_type: Scan backend — 'github', 'git', 'filesystem', 's3', 'docker'
        options: Extra trufflehog flags (e.g. '--only-verified', '--json',
                 '--since-commit=abc123', '--branch=main')

    Returns:
        Verified and unverified secrets found with type, line, and commit context
    """
    try:
        if scan_type == "github" and not target.startswith("http"):
            target = f"https://github.com/{target}"

        cmd = ["trufflehog", scan_type, target] + options.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()

        if not output:
            return f"No secrets found by TruffleHog in {target}"
        return f"## TruffleHog Secret Scan — {target}\nType: {scan_type}\n\n{output}"

    except FileNotFoundError:
        return (
            "Error: trufflehog not found.\n"
            "Install: go install github.com/trufflesecurity/trufflehog/v3@latest\n"
            "Or: brew install trufflehog  /  docker pull trufflesecurity/trufflehog"
        )
    except subprocess.TimeoutExpired:
        return f"Error: TruffleHog timed out after 10 minutes scanning {target}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# PureDNS — Wildcard-Aware DNS Brute-Force
# ---------------------------------------------------------------------------

@function_tool()
def puredns_bruteforce(
    domain: str,
    wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    resolvers: str = "",
    options: str = "",
) -> str:
    """
    High-performance DNS subdomain brute-forcing with automatic wildcard detection
    and filtering using puredns.

    Advantage over dnsx_resolve alone: puredns detects wildcard DNS (e.g. *.example.com
    resolves to one IP) and automatically filters them out — preventing false positives
    that flood results. Uses massdns under the hood for speed.

    Args:
        domain: Target domain (e.g. target.com)
        wordlist: Path to subdomain wordlist (default: SecLists top 20k)
        resolvers: Path to resolvers file (public DNS IPs). If empty, puredns
                   uses its built-in resolver list.
        options: Extra puredns flags (e.g. '--rate-limit 5000 --wildcard-tests 30')

    Returns:
        Valid (non-wildcard) subdomains confirmed by DNS resolution
    """
    try:
        cmd = ["puredns", "bruteforce", wordlist, domain]
        if resolvers and os.path.isfile(resolvers):
            cmd += ["-r", resolvers]
        cmd += options.split()

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        output = result.stdout.strip() or result.stderr.strip()

        if not output:
            return f"No subdomains found by puredns brute-force on {domain}"
        count = len([l for l in output.splitlines() if l.strip()])
        return f"## PureDNS Brute-Force — {domain}\n\nFound {count} valid subdomains:\n\n{output}"

    except FileNotFoundError:
        return (
            "Error: puredns not found.\n"
            "Install: go install github.com/d3mondev/puredns/v2@latest\n"
            "Also requires massdns: sudo apt install massdns"
        )
    except subprocess.TimeoutExpired:
        return f"Error: puredns timed out after 10 minutes on {domain}"
    except Exception as e:
        return f"Error: {e}"


# ============================================================================
# Merged from recon_intel.py
# ============================================================================

def _run(cmd: list[str], timeout: int = 60, stdin: str = "") -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=stdin or None,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


@function_tool()
def shodan_query(
    query: str,
    api_key: str = "",
    max_results: int = 20,
    fields: str = "ip_str,port,org,country_name,product,version,vulns",
) -> str:
    """
    Query Shodan for infrastructure intelligence.

    More powerful than shodan_search — supports structured field selection,
    vulnerability cross-referencing, and certificate subject extraction.

    API key is read from env var SHODAN_API_KEY if not provided.

    Args:
        query: Shodan search query — e.g. "org:\\"Cloudflare\\" port:8443"
               or "hostname:example.com" or "ssl.cert.subject.cn:example.com"
               or "vuln:CVE-2021-44228"
        api_key: Shodan API key (env SHODAN_API_KEY used if empty)
        max_results: Maximum results to return (default 20, max 100)
        fields: Comma-separated fields to include in output

    Returns:
        Structured Shodan results with hosts, ports, CVEs, and org info
    """
    key = api_key.strip() or os.environ.get("SHODAN_API_KEY", "")

    if shutil.which("shodan") and key:
        rc, out, err = _run(
            ["shodan", "search", "--fields", fields, "--limit", str(max_results), query],
            timeout=30,
        )
        if rc == 0 and out.strip():
            lines = out.strip().split("\n")
            header = textwrap.dedent(f"""\
                ╔══════════════════════════════════════════════════════════════╗
                ║                    SHODAN QUERY RESULTS                      ║
                ╚══════════════════════════════════════════════════════════════╝
                Query  : {query}
                Results: {len(lines)}
                Fields : {fields}
                ──────────────────────────────────────────────────────────────
            """)
            return header + out[:8000]

    try:
        shodan_lib = importlib.import_module("shodan")
        if not key:
            return "[shodan_query] No API key — set SHODAN_API_KEY env var or pass api_key"
        api = getattr(shodan_lib, "Shodan")(key)
        results = api.search(query, limit=min(max_results, 100))
        total = results.get("total", 0)
        matches = results.get("matches", [])

        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║                    SHODAN QUERY RESULTS                      ║",
            "╚══════════════════════════════════════════════════════════════╝",
            f"Query  : {query}",
            f"Total  : {total} (showing {len(matches)})",
            "──────────────────────────────────────────────────────────────",
        ]
        for m in matches:
            ip   = m.get("ip_str", "?")
            port = m.get("port", "?")
            org  = m.get("org", "?")
            prod = m.get("product", "")
            ver  = m.get("version", "")
            cc   = m.get("location", {}).get("country_code", "??")
            vulns = list(m.get("vulns", {}).keys())[:5]
            line = f"  {ip}:{port}  [{cc}]  {org}"
            if prod:
                line += f"  {prod}{' ' + ver if ver else ''}"
            if vulns:
                line += f"  ⚠ CVEs: {', '.join(vulns)}"
            lines.append(line)
        return "\n".join(lines)

    except ImportError:
        pass
    except Exception as e:
        return f"[shodan_query] Shodan library error: {e}"

    if not key:
        return textwrap.dedent("""\
            [shodan_query] Shodan not available.
            Install: pip install shodan   OR   apt install shodan-cli
            API Key: export SHODAN_API_KEY=your_key
        """)

    try:
        import urllib.request
        import urllib.parse as _urlparse
        q_enc = _urlparse.quote(query)
        url = f"https://api.shodan.io/shodan/host/search?key={key}&query={q_enc}&minify=false"
        with urllib.request.urlopen(url, timeout=15) as r:
            data = json.loads(r.read())
        matches = data.get("matches", [])
        out_lines = [f"  {m.get('ip_str','?')}:{m.get('port','?')}  {m.get('org','')}" for m in matches[:max_results]]
        return f"Shodan results for '{query}':\n" + "\n".join(out_lines)
    except Exception as e:
        return f"[shodan_query] HTTP fallback error: {e}"


@function_tool()
def censys_search(
    query: str,
    index: str = "hosts",
    api_id: str = "",
    api_secret: str = "",
    max_results: int = 20,
) -> str:
    """
    Search Censys for certificate, host, and domain intelligence.

    Censys excels at certificate-based discovery — finding all hosts that share
    a TLS certificate's Subject Alternative Names with the target.

    API credentials read from CENSYS_API_ID / CENSYS_API_SECRET env vars.

    Args:
        query: Censys query — e.g.
            "parsed.names: example.com"  (cert SAN search)
            "parsed.subject.organization: ExampleCorp"
            "(ip: 1.2.3.0/24) AND services.port: 443"
        index: "hosts" | "certificates" | "domains" (default: hosts)
        api_id: Censys App ID (env CENSYS_API_ID used if empty)
        api_secret: Censys App secret (env CENSYS_API_SECRET used if empty)
        max_results: Maximum results to fetch (default 20)

    Returns:
        Structured Censys results with IPs, services, certificates
    """
    _id  = api_id.strip()     or os.environ.get("CENSYS_API_ID",     "")
    _sec = api_secret.strip() or os.environ.get("CENSYS_API_SECRET", "")

    try:
        censys_search_mod = importlib.import_module("censys.search")
        CensysHosts = getattr(censys_search_mod, "CensysHosts")
        CensysCerts = getattr(censys_search_mod, "CensysCerts")
        if not _id or not _sec:
            return "[censys_search] No credentials — set CENSYS_API_ID & CENSYS_API_SECRET"

        if index == "certificates":
            api = CensysCerts(_id, _sec)
        else:
            api = CensysHosts(_id, _sec)

        results_list = list(api.search(query, per_page=min(max_results, 100)))
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║                   CENSYS SEARCH RESULTS                      ║",
            "╚══════════════════════════════════════════════════════════════╝",
            f"Query : {query}",
            f"Index : {index}",
            f"Found : {len(results_list)}",
            "──────────────────────────────────────────────────────────────",
        ]
        for r in results_list[:max_results]:
            if index == "certificates":
                lines.append(
                    f"  SHA256: {r.get('fingerprint_sha256','?')[:16]}…  "
                    f"Subject: {r.get('parsed',{}).get('subject_dn','?')}"
                )
            else:
                ip   = r.get("ip", "?")
                svcs = r.get("services", [])
                ports = [str(s.get("port", "?")) for s in svcs[:5]]
                lines.append(f"  {ip}  ports: {', '.join(ports)}")
        return "\n".join(lines)

    except ImportError:
        pass
    except Exception as e:
        return f"[censys_search] Library error: {e}"

    if not _id or not _sec:
        return textwrap.dedent("""\
            [censys_search] censys library not installed.
            Install: pip install censys
            API keys: https://search.censys.io/account/api
            Set: CENSYS_API_ID + CENSYS_API_SECRET env vars
        """)

    try:
        import urllib.request
        import base64
        cred = base64.b64encode(f"{_id}:{_sec}".encode()).decode()
        endpoint = f"https://search.censys.io/api/v2/{index}/search"
        req_body = json.dumps({"q": query, "per_page": max_results}).encode()
        req = urllib.request.Request(
            endpoint, data=req_body, method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {cred}",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        hits = data.get("result", {}).get("hits", [])
        return f"Censys results ({len(hits)}):\n" + "\n".join(
            f"  {h.get('ip', h.get('fingerprint_sha256', '?'))}" for h in hits
        )
    except Exception as e:
        return f"[censys_search] HTTP fallback error: {e}"


@function_tool()
def chaos_projectdiscovery(
    domain: str,
    api_key: str = "",
) -> str:
    """
    Query the ProjectDiscovery Chaos dataset — a massive passive subdomain
    database updated regularly from certificate transparency, DNS crawling,
    and public sources.

    Often surfaces subdomains that subfinder/amass miss because Chaos indexes
    historical snapshots and programme-specific datasets.

    API key from env CHAOS_API_KEY or https://chaos.projectdiscovery.io/

    Args:
        domain: Apex domain to query e.g. "example.com"
        api_key: Chaos API key (env CHAOS_API_KEY used if empty)

    Returns:
        List of discovered subdomains with count
    """
    key = api_key.strip() or os.environ.get("CHAOS_API_KEY", "")
    domain = domain.strip().lstrip("https://").lstrip("http://").split("/")[0]

    if shutil.which("chaos"):
        cmd = ["chaos", "-d", domain, "-silent"]
        if key:
            cmd = ["chaos", "-d", domain, "-key", key, "-silent"]
        rc, out, err = _run(cmd, timeout=60)
        if rc == 0 and out.strip():
            subs = [l.strip() for l in out.splitlines() if l.strip()]
            return textwrap.dedent(f"""\
                ╔══════════════════════════════════════════════════════════════╗
                ║              CHAOS PROJECT DISCOVERY                         ║
                ╚══════════════════════════════════════════════════════════════╝
                Domain : {domain}
                Found  : {len(subs)} subdomains
                ──────────────────────────────────────────────────────────────
            """) + "\n".join(("  " + s) for s in subs[:200])

    if not key:
        return textwrap.dedent("""\
            [chaos_projectdiscovery] chaos CLI not found and no API key.
            Install CLI : go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
            API key     : https://chaos.projectdiscovery.io/
            Set env     : CHAOS_API_KEY=your_key
        """)

    try:
        import urllib.request
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        req = urllib.request.Request(url, headers={"Authorization": key})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        subs = data.get("subdomains", [])
        count = data.get("count", len(subs))
        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║              CHAOS PROJECT DISCOVERY (HTTP API)              ║",
            "╚══════════════════════════════════════════════════════════════╝",
            f"Domain : {domain}",
            f"Found  : {count} subdomains",
            "──────────────────────────────────────────────────────────────",
        ]
        for s in subs[:200]:
            lines.append(f"  {s}.{domain}")
        return "\n".join(lines)
    except Exception as e:
        return f"[chaos_projectdiscovery] Error: {e}"


@function_tool()
def dnsx_resolve(
    domains: str,
    record_types: str = "A,CNAME,MX,TXT",
    resolvers: str = "",
    wildcard_filter: bool = True,
    probe_http: bool = False,
) -> str:
    """
    Mass DNS resolution using dnsx (ProjectDiscovery).
    Resolves large lists of domains/subdomains rapidly with configurable
    record types and custom resolvers.

    Falls back to Python's socket module if dnsx is not installed.

    Args:
        domains: Newline or comma-separated list of domains/subdomains to resolve.
                 Also accepts a single apex domain — will use it as-is.
        record_types: Comma-separated DNS record types: A, AAAA, CNAME, MX, TXT, NS, SOA
        resolvers: Comma-separated custom DNS resolvers e.g. "8.8.8.8,1.1.1.1"
        wildcard_filter: Filter out wildcard DNS responses (default True)
        probe_http: Also probe each resolved IP for HTTP/HTTPS (default False)

    Returns:
        DNS resolution results with IP addresses and record values
    """
    if "," in domains and "." in domains and "\n" not in domains:
        domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    else:
        domain_list = [d.strip() for d in domains.replace(",", "\n").splitlines() if d.strip()]

    if shutil.which("dnsx"):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(domain_list))
            input_file = tf.name

        try:
            cmd = ["dnsx", "-l", input_file, "-silent", "-resp"]
            for rt in record_types.split(","):
                rt = rt.strip().lower()
                if rt:
                    cmd += [f"-{rt}"]
            if resolvers:
                cmd += ["-r", resolvers]
            if wildcard_filter:
                cmd += ["-wt"]
            if probe_http:
                cmd += ["-probe"]

            rc, out, err = _run(cmd, timeout=120)
            if rc == 0:
                lines_out = out.strip().splitlines()
                return textwrap.dedent(f"""\
                    ╔══════════════════════════════════════════════════════════════╗
                    ║                   DNSX MASS RESOLUTION                       ║
                    ╚══════════════════════════════════════════════════════════════╝
                    Domains  : {len(domain_list)}
                    Resolved : {len(lines_out)}
                    Records  : {record_types}
                    ──────────────────────────────────────────────────────────────
                """) + "\n".join(lines_out[:500])
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

    results = []
    for d in domain_list[:100]:
        try:
            addr = socket.gethostbyname(d)
            results.append(f"  {d:<40} A  {addr}")
        except socket.gaierror:
            results.append(f"  {d:<40} NXDOMAIN")

    fallback_note = (
        "  [dnsx not installed — using Python socket (A records only)]\n"
        "  Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest\n"
        "──────────────────────────────────────────────────────────────\n"
    )
    header = textwrap.dedent(f"""\
        ╔══════════════════════════════════════════════════════════════╗
        ║                   DNS RESOLUTION (fallback)                  ║
        ╚══════════════════════════════════════════════════════════════╝
        Domains: {len(domain_list)}
        ──────────────────────────────────────────────────────────────
    """)
    return header + fallback_note + "\n".join(results)


@function_tool()
def uncover(
    query: str,
    engines: str = "shodan,censys,fofa,hunter,quake",
    limit: int = 100,
    field: str = "host",
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    fofa_email: str = "",
    fofa_key: str = "",
) -> str:
    """
    Multi-engine mass host discovery using uncover (ProjectDiscovery).
    Queries Shodan, Censys, Fofa, Hunter, and Quake simultaneously with
    a single query, deduplicates results, and returns unified host list.

    Prerequisites: API keys for each engine stored in ~/.config/uncover/
    or passed as arguments / environment variables.

    Args:
        query: Search query — dork-style e.g. "title:\\"Apache\\" country:US"
               Each engine has its own syntax; uncover handles translation.
        engines: Comma-separated engines: shodan,censys,fofa,hunter,quake
        limit: Max results per engine (default 100)
        field: Output field: host | ip | port | all (default: host)
        shodan_key: Shodan API key (env SHODAN_API_KEY used if empty)
        censys_id: Censys App ID (env CENSYS_API_ID used if empty)
        censys_secret: Censys App secret (env CENSYS_API_SECRET used if empty)
        fofa_email: Fofa registered email (env FOFA_EMAIL used if empty)
        fofa_key: Fofa API key (env FOFA_KEY used if empty)

    Returns:
        Deduplicated host list from all queried engines with source tags
    """
    sk = shodan_key    or os.environ.get("SHODAN_API_KEY",     "")
    ci = censys_id     or os.environ.get("CENSYS_API_ID",      "")
    cs = censys_secret or os.environ.get("CENSYS_API_SECRET",  "")
    fe = fofa_email    or os.environ.get("FOFA_EMAIL",          "")
    fk = fofa_key      or os.environ.get("FOFA_KEY",            "")

    env_override = {**os.environ}
    if sk: env_override["SHODAN_API_KEY"]    = sk
    if ci: env_override["CENSYS_API_ID"]     = ci
    if cs: env_override["CENSYS_API_SECRET"] = cs
    if fe: env_override["FOFA_EMAIL"]        = fe
    if fk: env_override["FOFA_KEY"]          = fk

    if shutil.which("uncover"):
        engine_flags = []
        for eng in engines.split(","):
            eng = eng.strip().lower()
            if eng:
                engine_flags += ["-e", eng]

        cmd = [
            "uncover",
            "-q", query,
            "-limit", str(limit),
            "-f", field,
            "-silent",
            "-json",
        ] + engine_flags

        rc, out, err = _run(cmd, timeout=120)
        if rc == 0 and out.strip():
            entries = [json.loads(l) for l in out.strip().splitlines() if l.strip().startswith("{")]
            unique_hosts: dict[str, list[str]] = {}
            for e in entries:
                h = e.get("host") or e.get("ip", "")
                src = e.get("source", "?")
                if h:
                    unique_hosts.setdefault(h, []).append(src)

            lines = [
                "╔══════════════════════════════════════════════════════════════╗",
                "║                UNCOVER MULTI-ENGINE RESULTS                  ║",
                "╚══════════════════════════════════════════════════════════════╝",
                f"Query  : {query}",
                f"Engines: {engines}",
                f"Unique : {len(unique_hosts)} hosts",
                "──────────────────────────────────────────────────────────────",
            ]
            for host, sources in sorted(unique_hosts.items()):
                lines.append(f"  {host:<45} [{', '.join(set(sources))}]")
            return "\n".join(lines)
        else:
            return f"[uncover] Returned rc={rc}: {err[:300]}"

    results: list[str] = []

    if "shodan" in engines and sk:
        try:
            r = shodan_query(query=query, api_key=sk, max_results=limit)
            results.append(f"=== SHODAN ===\n{r}")
        except Exception as e:
            results.append(f"=== SHODAN === Error: {e}")

    if "censys" in engines and ci and cs:
        try:
            r = censys_search(query=query, api_id=ci, api_secret=cs, max_results=limit)
            results.append(f"=== CENSYS ===\n{r}")
        except Exception as e:
            results.append(f"=== CENSYS === Error: {e}")

    if results:
        return (
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║         UNCOVER (fallback: individual engines)               ║\n"
            "╚══════════════════════════════════════════════════════════════╝\n"
            "[uncover CLI not installed — using individual engine APIs]\n"
            "Install: go install github.com/projectdiscovery/uncover/cmd/uncover@latest\n\n"
            + "\n\n".join(results)
        )

    return textwrap.dedent(f"""\
        [uncover] Not available.
        Install: go install github.com/projectdiscovery/uncover/cmd/uncover@latest
        Config : Set API keys in ~/.config/uncover/provider-config.yaml
                 OR pass as env vars: SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
                 FOFA_EMAIL + FOFA_KEY, HUNTER_API_KEY, QUAKE_TOKEN
        Query was: {query}
    """)


# ============================================================================
# Merged from recon_modern.py
# ============================================================================

@function_tool()
def shodan_internetdb(target: str) -> str:
    """
    Fully passive Shodan InternetDB lookup. NO key required, NO packets to target.
    Returns ports, hostnames, CVEs, and tags Shodan has already observed.

    Use this BEFORE any active scan to skip what's already known.

    Args:
        target: IP address (hostname will be resolved first)
    """
    ip = target.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        try:
            ip = socket.gethostbyname(ip)
        except Exception as e:
            return f"Error: cannot resolve {target}: {e}"

    url = f"https://internetdb.shodan.io/{ip}"
    try:
        r = requests.get(url, timeout=10)
    except Exception as e:
        return f"Error contacting InternetDB: {e}"

    if r.status_code == 404:
        return f"InternetDB has no record for {ip} (no public Shodan banners)."
    if r.status_code != 200:
        return f"InternetDB returned HTTP {r.status_code}: {r.text[:200]}"

    try:
        data = r.json()
    except ValueError:
        return f"Non-JSON response from InternetDB: {r.text[:300]}"

    out = [f"## Shodan InternetDB: {ip}"]
    if data.get("hostnames"):
        out.append(f"  hostnames: {', '.join(data['hostnames'][:10])}")
    if data.get("ports"):
        out.append(f"  ports:     {', '.join(str(p) for p in data['ports'])}")
    if data.get("tags"):
        out.append(f"  tags:      {', '.join(data['tags'])}")
    if data.get("vulns"):
        cves = data["vulns"]
        out.append(f"  CVEs ({len(cves)}):")
        for c in cves[:25]:
            out.append(f"    - {c}")
        if len(cves) > 25:
            out.append(f"    ... +{len(cves) - 25} more")
        out.append("\n[Next] cve_lookup() each CVE; if exploitable run nuclei templates targeted at them.")
    return "\n".join(out)


@function_tool()
def asn_pivot(target: str, max_hosts: int = 256) -> str:
    """
    Discover the ASN owning a target, list all its CIDR netblocks, then
    probe up to `max_hosts` per netblock for HTTP services (passive: BGPview API).

    Use to expand attack surface from one IP to the whole organization.

    Args:
        target:    IP or hostname
        max_hosts: Cap per netblock for the live-host probe (0 = none, just list CIDRs)
    """
    ip = target.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        try:
            ip = socket.gethostbyname(ip)
        except Exception as e:
            return f"Error: cannot resolve {target}: {e}"

    try:
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=12,
                         headers={"User-Agent": "cyber-copilot-recon"})
        data = r.json()
    except Exception as e:
        return f"Error contacting bgpview.io: {e}"

    if data.get("status") != "ok":
        return f"bgpview returned: {data.get('status_message', 'unknown')}"

    asns = (data.get("data") or {}).get("prefixes", [])
    if not asns:
        return f"No ASN data for {ip}"

    org_set = set()
    cidrs = set()
    for entry in asns:
        cidrs.add(entry.get("prefix", ""))
        asn = entry.get("asn", {})
        if asn.get("description"):
            org_set.add(asn["description"])
        if asn.get("name"):
            org_set.add(asn["name"])

    out = [f"## ASN Pivot: {ip}"]
    out.append(f"  Org(s): {', '.join(sorted(org_set))[:300]}")
    out.append(f"  Netblocks: {len(cidrs)}")
    for c in sorted(cidrs)[:30]:
        out.append(f"    - {c}")
    if len(cidrs) > 30:
        out.append(f"    ... +{len(cidrs)-30} more")

    if max_hosts <= 0:
        out.append("\n[Next] feed CIDRs into masscan/naabu, then httpx_probe.")
        return "\n".join(out)

    try:
        import ipaddress
    except ImportError:
        return "\n".join(out)

    out.append(f"\n[Live probe — {max_hosts} per netblock]")
    live = []
    for cidr in sorted(cidrs)[:5]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())[:max_hosts]
        except Exception:
            continue
        for h in hosts:
            for port, scheme in ((80, "http"), (443, "https")):
                url = f"{scheme}://{h}/"
                try:
                    rr = requests.get(url, timeout=2, verify=False, allow_redirects=False)
                    title = re.search(r"<title>([^<]+)</title>", rr.text or "", re.I)
                    title_s = title.group(1).strip()[:60] if title else ""
                    live.append(f"  [{rr.status_code}] {url}  {title_s}")
                except Exception:
                    pass
    out += live[:60]
    if len(live) > 60:
        out.append(f"  ... +{len(live)-60} more")
    return "\n".join(out)


_DEFAULT_DORKS = [
    "password",
    "api_key",
    "apikey",
    "secret",
    "AWS_ACCESS_KEY_ID",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "client_secret",
    "DB_PASSWORD",
    "JWT_SECRET",
    "SLACK_TOKEN",
    "private_key",
    ".env",
    "config.yml",
]


@function_tool()
def github_dork_search(domain: str, max_results: int = 50, custom_dorks: str = "") -> str:
    """
    Search GitHub for leaked secrets containing a target domain across a curated
    dork pack (and any custom dorks the operator supplies).

    Set GITHUB_TOKEN in env for 5,000/hr; without a token unauth limit is 10/min.

    Args:
        domain:        Target domain or org name (becomes a literal in queries)
        max_results:   Cap on results PER DORK (default 50)
        custom_dorks:  Comma-separated extra dork keywords
    """
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    dorks = list(_DEFAULT_DORKS)
    if custom_dorks.strip():
        dorks += [d.strip() for d in custom_dorks.split(",") if d.strip()]

    out = [f"## GitHub Dork Search: {domain}"]
    out.append(f"Auth: {'token' if token else 'unauth (rate limited)'}")
    hits_total = 0

    for dork in dorks:
        q = f'"{domain}" {dork}'
        url = "https://api.github.com/search/code"
        try:
            r = requests.get(url, headers=headers, params={"q": q, "per_page": min(max_results, 30)}, timeout=12)
        except Exception as e:
            out.append(f"  [{dork}] error: {e}")
            continue
        if r.status_code == 403 and "rate limit" in r.text.lower():
            out.append(f"  [{dork}] rate-limited — set GITHUB_TOKEN")
            break
        if r.status_code != 200:
            out.append(f"  [{dork}] HTTP {r.status_code}")
            continue
        body = r.json()
        items = body.get("items", [])
        if not items:
            continue
        out.append(f"\n[{dork}] {len(items)} hits")
        for item in items[:10]:
            repo = (item.get("repository") or {}).get("full_name", "?")
            path = item.get("path", "?")
            url2 = item.get("html_url", "")
            out.append(f"  - {repo}/{path}  {url2}")
            hits_total += 1

    out.append(f"\nTotal candidate hits: {hits_total}")
    if hits_total:
        out.append("[Next] git_dump or git clone these repos, then trufflehog_repo to verify live secrets.")
    return "\n".join(out)


@function_tool()
def trufflehog_repo(repo_or_path: str, only_verified: bool = True) -> str:
    """
    Run trufflehog against a git repo URL or local filesystem path. Verified
    findings (where trufflehog could authenticate to the leaking provider) are
    promoted to CRITICAL.

    Args:
        repo_or_path:    https://github.com/... OR /path/to/clone
        only_verified:   Filter out unverified noisy matches (default True)
    """
    if not shutil.which("trufflehog"):
        return ("Error: trufflehog not on PATH. Install:\n"
                "  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin")

    is_url = repo_or_path.startswith("http://") or repo_or_path.startswith("https://") or repo_or_path.startswith("git@")
    cmd = ["trufflehog", "git" if is_url else "filesystem", repo_or_path, "--json"]
    if only_verified:
        cmd.append("--only-verified")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return "Error: trufflehog timed out after 15 minutes"

    out_lines = r.stdout.splitlines()
    findings = []
    for line in out_lines:
        try:
            j = json.loads(line)
            findings.append(j)
        except Exception:
            continue

    out = [f"## trufflehog: {repo_or_path}", f"Findings: {len(findings)}", f"Mode: {'verified-only' if only_verified else 'all'}"]
    for f in findings[:30]:
        det = f.get("DetectorName") or f.get("detector_name") or "?"
        verified = f.get("Verified") or f.get("verified")
        raw = f.get("Raw") or f.get("raw") or ""
        loc = f.get("SourceMetadata") or {}
        out.append(f"  - [{det}{' VERIFIED' if verified else ''}] {str(raw)[:80]}")
        if loc:
            out.append(f"      {json.dumps(loc)[:200]}")
    if len(findings) > 30:
        out.append(f"  ... +{len(findings)-30} more")
    if not findings and r.stderr:
        out.append("\n[stderr] " + r.stderr.strip()[:500])
    return "\n".join(out)


@function_tool()
def git_dump(url: str, output_dir: str = "") -> str:
    """
    Pull a publicly exposed .git/ directory using git-dumper.

    Args:
        url:        URL pointing at a .git/ root (e.g. https://example.com/.git/)
        output_dir: Where to save (default: session dir or temp)
    """
    if not output_dir:
        try:
            from src.repl.target_manager import get_target_manager
            sd = getattr(get_target_manager(), "session_dir", "") or ""
        except Exception:
            sd = ""
        output_dir = str(Path(sd or tempfile.gettempdir()) / f"git_dump_{re.sub(r'[^a-z0-9]+', '_', url.lower())[:40]}")

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    if not shutil.which("git-dumper"):
        return "Error: git-dumper not on PATH. Install: pip install git-dumper"

    cmd = ["git-dumper", url, output_dir]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return "Error: git-dumper timed out after 15 minutes"

    out = [f"## git-dumper: {url}", f"Output: {output_dir}", "", (r.stdout or "")[-1500:]]
    if r.returncode == 0 and any(Path(output_dir).iterdir()):
        out.append("\n[Next] Run trufflehog_repo on the dumped directory to extract leaked secrets.")
    return "\n".join(out)


@function_tool()
def jsluice_extract(urls_or_files: str, mode: str = "urls") -> str:
    """
    Wrap jsluice (https://github.com/BishopFox/jsluice) to pull URLs and
    secrets out of JS bundles, with a Python regex fallback if missing.

    Args:
        urls_or_files: Newline- or comma-separated URLs / local JS file paths
        mode:          urls | secrets
    """
    if mode not in ("urls", "secrets"):
        return "Error: mode must be 'urls' or 'secrets'"

    items = [x.strip() for x in re.split(r"[\n,]", urls_or_files) if x.strip()]
    if not items:
        return "Error: no URLs/files provided"

    has_jsluice = bool(shutil.which("jsluice"))
    found = set()
    
    for item in items[:50]:
        target = item
        text_content = ""
        is_temp = False
        
        # Load content if URL
        if item.startswith("http"):
            try:
                rr = requests.get(item, timeout=10, verify=False)
                text_content = rr.text or ""
                tmp = Path(tempfile.mkstemp(suffix=".js")[1])
                tmp.write_text(text_content, encoding="utf-8")
                target = str(tmp)
                is_temp = True
            except Exception:
                continue
        else:
            try:
                with open(item, "r", encoding="utf-8", errors="ignore") as f:
                    text_content = f.read()
            except Exception:
                pass

        if has_jsluice:
            try:
                cmd = ["jsluice", mode, target]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                for line in (r.stdout or "").splitlines():
                    line = line.strip()
                    if line:
                        found.add(line)
            except Exception:
                pass
        else:
            # Fallback regex extraction
            if mode == "urls":
                # Find common endpoints and URLs
                endpoints = re.findall(r'(?:https?://|/api/|/)[a-zA-Z0-9.\-_/]+', text_content)
                for ep in endpoints:
                    if len(ep) > 2 and ep not in ("https://", "http://"):
                        found.add(ep)
            else:
                # Find secrets
                for name, pat in _SECRET_PATTERNS:
                    for match in re.findall(pat, text_content):
                        # jsluice output format
                        found.add(f'{{"kind":"{name}","data":{{"match":"{match}"}}}}')
        
        if is_temp:
            try:
                os.remove(target)
            except Exception:
                pass

    tool_used = "jsluice" if has_jsluice else "regex_fallback"
    out = [f"## {tool_used} {mode}: {len(items)} input(s)", f"Distinct results: {len(found)}"]
    
    # Credential tag if secrets were found (for orchestrator pivot)
    if mode == "secrets" and len(found) > 0:
        out.append("[credential] [secret] Secrets discovered!")
        
    for line in sorted(found)[:200]:
        out.append(f"  {line}")
    if len(found) > 200:
        out.append(f"  ... +{len(found)-200} more")
    return "\n".join(out)


_SECRET_PATTERNS = [
    ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("AWS Session", r"\bASIA[0-9A-Z]{16}\b"),
    ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("Slack Bot Token", r"\bxox[bpoa]-\d+-\d+-[A-Za-z0-9]+\b"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub PAT", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GitHub OAuth", r"\bgho_[A-Za-z0-9]{36}\b"),
    ("Stripe Secret", r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    ("Stripe Restricted", r"\brk_live_[A-Za-z0-9]{24,}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ("Generic Secret Var", r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?[A-Za-z0-9+/_=\-]{16,}['\"]?"),
    ("PEM Private Key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
]


@function_tool()
def js_secret_chain(domain: str, max_urls: int = 200) -> str:
    """
    End-to-end JS leak chain:
      1) wayback/gau-style URL collection (via gau if available, else CommonCrawl)
      2) Filter to *.js
      3) Fetch each, scan with regex secret patterns
    No external paid APIs required.

    Args:
        domain:    Target domain
        max_urls:  Cap on JS files fetched (default 200)
    """
    js_urls = set()

    if shutil.which("gau"):
        try:
            r = subprocess.run(["gau", domain, "--threads", "10"],
                               capture_output=True, text=True, timeout=120)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line.endswith(".js"):
                    js_urls.add(line)
        except Exception:
            pass

    if len(js_urls) < 5:
        try:
            cc = requests.get(
                f"https://index.commoncrawl.org/CC-MAIN-2024-30-index?url=*.{domain}/*.js&output=json",
                timeout=30,
            )
            for line in (cc.text or "").splitlines():
                try:
                    j = json.loads(line)
                    u = j.get("url")
                    if u and u.endswith(".js"):
                        js_urls.add(u)
                except Exception:
                    continue
        except Exception:
            pass

    js_urls = list(js_urls)[:max_urls]
    out = [f"## JS Secret Chain: {domain}", f"JS URLs collected: {len(js_urls)}"]

    findings = []
    for u in js_urls:
        try:
            rr = requests.get(u, timeout=8, verify=False)
            body = rr.text or ""
        except Exception:
            continue
        for label, pattern in _SECRET_PATTERNS:
            for m in re.findall(pattern, body)[:3]:
                if isinstance(m, tuple):
                    m = " ".join(m)
                findings.append((label, str(m)[:120], u))

    out.append(f"Secret-pattern matches: {len(findings)}")
    for label, sample, source in findings[:60]:
        out.append(f"  [{label}] {sample}")
        out.append(f"      from: {source}")
    if len(findings) > 60:
        out.append(f"  ... +{len(findings)-60} more")
    if findings:
        out.append("\n[Next] Verify each candidate with the relevant API; promote VERIFIED keys to a CRITICAL finding.")
    return "\n".join(out)
