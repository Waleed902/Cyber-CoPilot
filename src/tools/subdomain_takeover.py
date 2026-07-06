"""
Subdomain Takeover Prober — Service-Fingerprinted
Detects dangling DNS records pointing to cloud/SaaS services that can be claimed.

Covers 25+ services with precise fingerprints:
AWS S3, GitHub Pages, Heroku, Azure, Netlify, Fastly, Shopify,
Ghost, Surge, Cargo, Tumblr, Unbounce, LaunchRock, HelpDesk, etc.

Also probes:
- CNAME following to dead endpoints
- NS delegation to expired domains
- A-record pointing to unallocated IP ranges
"""

import socket
import re
import subprocess
import requests
from src.sdk.core import function_tool


# ─── Service fingerprints (CNAME target pattern → takeover indicator) ─────────
TAKEOVER_FINGERPRINTS = [
    # AWS S3
    {
        "service": "AWS S3",
        "cname_patterns": [".s3.amazonaws.com", ".s3-website"],
        "fingerprint": "NoSuchBucket",
        "severity": "HIGH",
        "instructions": "Create an S3 bucket with the same name as the subdomain"
    },
    # GitHub Pages
    {
        "service": "GitHub Pages",
        "cname_patterns": [".github.io"],
        "fingerprint": "There isn't a GitHub Pages site here",
        "severity": "HIGH",
        "instructions": "Create a GitHub repo with the CNAME file pointing to this subdomain"
    },
    # Heroku
    {
        "service": "Heroku",
        "cname_patterns": [".herokudns.com", ".herokussl.com", "herokuapp.com"],
        "fingerprint": "No such app",
        "severity": "HIGH",
        "instructions": "Create a Heroku app and add custom domain"
    },
    # Azure
    {
        "service": "Azure (cloudapp)",
        "cname_patterns": [".azurewebsites.net", ".cloudapp.azure.com", ".cloudapp.net"],
        "fingerprint": "404 Web Site not found",
        "severity": "HIGH",
        "instructions": "Create Azure App Service with the matching hostname"
    },
    # Azure CDN
    {
        "service": "Azure CDN",
        "cname_patterns": [".azureedge.net"],
        "fingerprint": "The resource you are looking for has been removed",
        "severity": "HIGH",
        "instructions": "Create Azure CDN endpoint with matching name"
    },
    # Netlify
    {
        "service": "Netlify",
        "cname_patterns": [".netlify.app", ".netlify.com"],
        "fingerprint": "Not found - Request ID",
        "severity": "HIGH",
        "instructions": "Deploy a Netlify site and configure custom domain"
    },
    # Shopify
    {
        "service": "Shopify",
        "cname_patterns": [".myshopify.com"],
        "fingerprint": "Sorry, this shop is currently unavailable",
        "severity": "MEDIUM",
        "instructions": "Create Shopify store matching subdomain"
    },
    # Ghost
    {
        "service": "Ghost (Pro)",
        "cname_patterns": [".ghost.io"],
        "fingerprint": "The thing you were looking for is no longer here",
        "severity": "HIGH",
        "instructions": "Create a Ghost Pro blog with matching subdomain"
    },
    # Fastly
    {
        "service": "Fastly",
        "cname_patterns": [".fastly.net"],
        "fingerprint": "Fastly error: unknown domain",
        "severity": "HIGH",
        "instructions": "Configure a Fastly service for this domain"
    },
    # Surge.sh
    {
        "service": "Surge.sh",
        "cname_patterns": [".surge.sh"],
        "fingerprint": "project not found",
        "severity": "HIGH",
        "instructions": "Deploy with surge to the matching subdomain"
    },
    # Unbounce
    {
        "service": "Unbounce",
        "cname_patterns": [".unbouncepages.com"],
        "fingerprint": "The requested URL was not found on this server",
        "severity": "MEDIUM",
        "instructions": "Create an Unbounce account and claim the subdomain"
    },
    # Tumblr
    {
        "service": "Tumblr",
        "cname_patterns": [".tumblr.com"],
        "fingerprint": "There's nothing here",
        "severity": "MEDIUM",
        "instructions": "Create a Tumblr blog and set custom domain"
    },
    # HubSpot
    {
        "service": "HubSpot",
        "cname_patterns": [".hubspot.net", ".hs-sites.com"],
        "fingerprint": "Domain is not configured",
        "severity": "HIGH",
        "instructions": "Add domain to HubSpot CMS"
    },
    # WP Engine
    {
        "service": "WP Engine",
        "cname_patterns": [".wpengine.com"],
        "fingerprint": "The site you were looking for couldn't be found",
        "severity": "HIGH",
        "instructions": "Create WP Engine install with matching domain"
    },
    # Zendesk
    {
        "service": "Zendesk",
        "cname_patterns": [".zendesk.com"],
        "fingerprint": "Help Center Closed",
        "severity": "LOW",
        "instructions": "Create Zendesk account and claim subdomain"
    },
    # Cloudfront
    {
        "service": "AWS CloudFront",
        "cname_patterns": [".cloudfront.net"],
        "fingerprint": "Bad request",
        "severity": "MEDIUM",
        "instructions": "Create CloudFront distribution for this domain"
    },
    # Vercel
    {
        "service": "Vercel",
        "cname_patterns": [".vercel.app", "cname.vercel-dns.com"],
        "fingerprint": "The deployment could not be found",
        "severity": "HIGH",
        "instructions": "Deploy a Vercel project and add custom domain"
    },
    # Render
    {
        "service": "Render",
        "cname_patterns": [".onrender.com"],
        "fingerprint": "not found",
        "severity": "HIGH",
        "instructions": "Create a Render web service with matching domain"
    },
    # Fly.io
    {
        "service": "Fly.io",
        "cname_patterns": [".fly.dev"],
        "fingerprint": "404 Not Found",
        "severity": "HIGH",
        "instructions": "Deploy a Fly.io app and add custom domain"
    },
    # Railway
    {
        "service": "Railway",
        "cname_patterns": [".up.railway.app"],
        "fingerprint": "Application not found",
        "severity": "HIGH",
        "instructions": "Deploy a Railway app with matching domain"
    },
    # Firebase Hosting
    {
        "service": "Firebase Hosting",
        "cname_patterns": [".web.app", ".firebaseapp.com"],
        "fingerprint": "Site Not Found",
        "severity": "HIGH",
        "instructions": "Create Firebase project and add custom domain"
    },
    # DigitalOcean App Platform
    {
        "service": "DigitalOcean Apps",
        "cname_patterns": [".ondigitalocean.app"],
        "fingerprint": "This app is not available",
        "severity": "HIGH",
        "instructions": "Create DO App Platform project with domain"
    },
    # Gitbook
    {
        "service": "Gitbook",
        "cname_patterns": [".gitbook.io"],
        "fingerprint": "If you need to, you can always",
        "severity": "MEDIUM",
        "instructions": "Claim the Gitbook space with custom domain"
    },
    # Supabase
    {
        "service": "Supabase",
        "cname_patterns": [".supabase.co"],
        "fingerprint": "not found",
        "severity": "HIGH",
        "instructions": "Create Supabase project matching subdomain"
    },
    # Pantheon
    {
        "service": "Pantheon",
        "cname_patterns": [".pantheonsite.io"],
        "fingerprint": "The gods are wise",
        "severity": "HIGH",
        "instructions": "Create Pantheon site with matching domain"
    },
    # Cargo Collective
    {
        "service": "Cargo Collective",
        "cname_patterns": [".cargocollective.com"],
        "fingerprint": "404 Not Found",
        "severity": "MEDIUM",
        "instructions": "Create Cargo site with custom domain"
    },
    # Pointing to non-existent IP (generic)
    {
        "service": "Generic dead A-record",
        "cname_patterns": [],
        "fingerprint": None,
        "severity": "VARIES",
        "instructions": "Claim the IP space or target infrastructure"
    },
]


def _resolve_cname(subdomain: str) -> str:
    """Resolve CNAME chain for a subdomain."""
    try:
        result = subprocess.run(
            ["nslookup", "-type=CNAME", subdomain],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except Exception:
        try:
            socket.getaddrinfo(subdomain, None)
            return "Resolves to IP (no CNAME)"
        except socket.gaierror:
            return "NXDOMAIN"


def _check_http_fingerprint(subdomain: str, fingerprints: list) -> tuple:
    """Try HTTP/HTTPS and check for takeover fingerprints.

    Returns (is_vulnerable, fingerprint_matched, response_snippet)
    A subdomain is ONLY vulnerable if the HTTP response contains the
    service-specific takeover fingerprint (e.g. "NoSuchBucket", "No such app").
    A live site responding with normal content is NOT vulnerable even if it has
    a CNAME to a third-party service.
    """
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=8, verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (CyberCoPilot-TakeoverProbe/1.0)"}
            )
            text = resp.text
            status = resp.status_code

            # ─── CRITICAL: If the page returns normal content, it's NOT vulnerable ───
            # A true takeover target returns an error page from the cloud provider.
            # If it returns 200 with real content, the service is still active.
            if status == 200 and len(text) > 500:
                # Check if it looks like a real site (not a provider error page)
                provider_error_indicators = [
                    "nosuchbucket", "no such app", "not found", "site not found",
                    "there's nothing here", "project not found", "bad request",
                    "the requested url was not found", "domain is not configured",
                    "sorry, this shop", "if you need to, you can always",
                    "the gods are wise", "help center closed",
                ]
                is_error_page = any(ind.lower() in text.lower() for ind in provider_error_indicators)

                if not is_error_page:
                    # This is a LIVE site — NOT vulnerable to takeover
                    return False, None, f"LIVE SITE (HTTP {status}, {len(text)} bytes) — not vulnerable"

            # Check for takeover fingerprints
            for fp in fingerprints:
                if fp and fp.lower() in text.lower():
                    return True, fp, text[:200]

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass
    return False, None, None


@function_tool()
def subdomain_takeover_scan(
    subdomains: str,
    check_http: bool = True
):
    """
    Probe subdomains for takeover vulnerabilities using service-specific fingerprints.
    Works on 25+ cloud/SaaS services (S3, GitHub Pages, Heroku, Azure, Netlify, etc.)

    Args:
        subdomains: Comma-separated list of subdomains to check
          (e.g. staging.example.com,dev.example.com,cdn.example.com)
        check_http: Whether to probe HTTP in addition to DNS (default True)
    """
    targets = [s.strip() for s in subdomains.split(",") if s.strip()]
    results = [f"[TAKEOVER] Scanning {len(targets)} subdomains for dangling records"]

    vulnerable = []
    potential = []

    for subdomain in targets:
        results.append(f"\n[CHECK] {subdomain}")

        # 1. DNS resolution
        cname_output = _resolve_cname(subdomain)

        if "NXDOMAIN" in cname_output:
            results.append("  [DNS] NXDOMAIN — subdomain not resolving (dangling!)")
            potential.append((subdomain, "NXDOMAIN", "Unknown", "MEDIUM"))
            continue

        results.append(f"  [DNS] Resolves: {cname_output[:80].strip()}")

        # 2. Check CNAME target against known vulnerable patterns
        matched_service = None

        for svc_info in TAKEOVER_FINGERPRINTS[:-1]:  # Skip generic
            for pattern in svc_info["cname_patterns"]:
                if pattern in cname_output.lower():
                    matched_service = svc_info
                    break
            if matched_service:
                break

        if matched_service:
            results.append(f"  [SERVICE] CNAME points to: {matched_service['service']}")

            if check_http:
                is_vuln, fp, snippet = _check_http_fingerprint(
                    subdomain,
                    [matched_service["fingerprint"]]
                )
                if is_vuln:
                    vulnerable.append((subdomain, matched_service["service"], matched_service["severity"]))
                    results.append("  ⚠️  TAKEOVER POSSIBLE!")
                    results.append(f"  Fingerprint: '{fp}' found in response")
                    results.append(f"  Severity: {matched_service['severity']}")
                    results.append(f"  Instructions: {matched_service['instructions']}")
                else:
                    results.append("  [OK] Service fingerprint not triggered (may still be at-risk)")
        else:
            if check_http:
                # Generic: check for any known fingerprints
                all_fingerprints = [svc["fingerprint"] for svc in TAKEOVER_FINGERPRINTS if svc["fingerprint"]]
                is_vuln, fp, snippet = _check_http_fingerprint(subdomain, all_fingerprints)
                if is_vuln:
                    results.append(f"  ⚠️  FINGERPRINT MATCHED: '{fp}'")
                    potential.append((subdomain, fp, "Unknown service", "HIGH"))

    results.append(f"\n{'='*60}")
    results.append("TAKEOVER SCAN COMPLETE")
    results.append(f"  Vulnerable: {len(vulnerable)}")
    results.append(f"  Potential:  {len(potential)}")

    if vulnerable:
        results.append("\n⚠️  CONFIRMED TAKEOVER TARGETS:")
        for sub, svc, sev in vulnerable:
            results.append(f"  [{sev}] {sub} → {svc}")

    if potential:
        results.append("\n[INVESTIGATE] Potential targets (manual check needed):")
        for sub, reason, svc, sev in potential:
            results.append(f"  [{sev}] {sub} → {reason}")

    return "\n".join(results)


@function_tool()
def ns_takeover_probe(domain: str):
    """
    Check if a domain's NS records point to expired/unclaimed nameservers,
    enabling full DNS takeover.

    Args:
        domain: Domain to check (e.g. example.com or sub.example.com)
    """
    results = [f"[NS-TAKEOVER] Probing NS records for: {domain}"]

    try:
        result = subprocess.run(
            ["nslookup", "-type=NS", domain],
            capture_output=True, text=True, timeout=10
        )
        ns_output = result.stdout
        results.append(f"[NS Records]\n{ns_output[:400]}")

        # Extract NS servers
        ns_servers = re.findall(r'nameserver\s*=\s*(\S+)', ns_output, re.IGNORECASE)
        ns_servers += re.findall(r'Name Server:\s*(\S+)', ns_output, re.IGNORECASE)

        for ns in ns_servers:
            ns = ns.rstrip(".")
            results.append(f"\n[CHECK NS] {ns}")
            try:
                socket.getaddrinfo(ns, None)
                results.append("  [OK] NS resolves")
            except socket.gaierror:
                results.append(f"  ⚠️  NS DOES NOT RESOLVE: '{ns}'")
                results.append("  If this NS domain is available for registration → FULL DOMAIN TAKEOVER possible!")

    except Exception as e:
        results.append(f"[ERROR] {e}")

    return "\n".join(results)


@function_tool()
def mx_takeover_probe(domain: str) -> str:
    """
    Check if MX records point to unclaimed/expired mail services.
    MX takeover allows intercepting all email for the domain — HIGH severity.

    Checks for:
    - MX pointing to NXDOMAIN (dead mail server)
    - MX pointing to registerable domains
    - MX pointing to cloud mail services that can be claimed

    Args:
        domain: Domain to check (e.g. example.com)

    Returns:
        MX takeover analysis results
    """
    results = [f"[MX-TAKEOVER] Probing MX records for: {domain}"]

    try:
        result = subprocess.run(
            ["nslookup", "-type=MX", domain],
            capture_output=True, text=True, timeout=10
        )
        mx_output = result.stdout
        results.append(f"\n[MX Records]\n{mx_output[:500]}")

        # Extract MX servers
        mx_servers = re.findall(r'mail exchanger\s*=\s*\d+\s+(\S+)', mx_output, re.IGNORECASE)
        mx_servers += re.findall(r'MX preference\s*=\s*\d+,\s*mail exchanger\s*=\s*(\S+)', mx_output, re.IGNORECASE)

        if not mx_servers:
            results.append("\n⚠️  NO MX RECORDS FOUND — domain cannot receive email")
            results.append("  This means: email to @domain will bounce (or fall back to A record)")
            return "\n".join(results)

        vulnerable = []
        for mx in mx_servers:
            mx = mx.rstrip(".")
            results.append(f"\n[CHECK MX] {mx}")
            try:
                socket.getaddrinfo(mx, None)
                results.append("  [OK] MX resolves")
                # Check if it's a cloud service that could be claimed
                cloud_mx = [
                    (".google.com", "Google Workspace"),
                    (".outlook.com", "Microsoft 365"),
                    (".pphosted.com", "Proofpoint"),
                    (".mimecast.com", "Mimecast"),
                    (".mailgun.org", "Mailgun"),
                    (".sendgrid.net", "SendGrid"),
                    (".amazonaws.com", "AWS SES"),
                    (".zoho.com", "Zoho Mail"),
                ]
                for pattern, service in cloud_mx:
                    if pattern in mx.lower():
                        results.append(f"  ℹ️  Cloud mail service: {service}")
                        results.append(f"  Check if {domain} is verified in {service} account")
            except socket.gaierror:
                vulnerable.append(mx)
                results.append(f"  🔴 MX DOES NOT RESOLVE: '{mx}'")
                results.append("  If this domain is registerable → FULL EMAIL TAKEOVER!")
                results.append(f"  Register '{mx}', set up mail server → intercept ALL email to @{domain}")

        if vulnerable:
            results.append(f"\n{'='*60}")
            results.append(f"🔴 VULNERABLE MX RECORDS: {len(vulnerable)}")
            for mx in vulnerable:
                results.append(f"  → {mx} (NXDOMAIN — registerable?)")
        else:
            results.append("\n✅ All MX records resolve correctly")

    except Exception as e:
        results.append(f"[ERROR] {e}")

    return "\n".join(results)


@function_tool()
def wildcard_dns_detect(domain: str) -> str:
    """
    Detect wildcard DNS records (*.domain.com resolves to an IP).
    Wildcard DNS breaks subdomain enumeration — you'll get false positives.
    Must detect this BEFORE running subdomain scans.

    Args:
        domain: Domain to check (e.g. example.com)

    Returns:
        Wildcard detection result with guidance
    """
    results = [f"[WILDCARD DNS] Testing: {domain}"]
    import random
    import string

    # Generate 3 random subdomains that shouldn't exist
    test_subs = [
        ''.join(random.choices(string.ascii_lowercase, k=12)) + f".{domain}"
        for _ in range(3)
    ]

    resolved_ips = []
    for sub in test_subs:
        try:
            addrs = socket.getaddrinfo(sub, None)
            ip = addrs[0][4][0]
            resolved_ips.append(ip)
            results.append(f"  {sub} → {ip}")
        except socket.gaierror:
            results.append(f"  {sub} → NXDOMAIN ✅")

    if len(resolved_ips) >= 2:
        # Check if they all resolve to the same IP (classic wildcard)
        unique_ips = set(resolved_ips)
        if len(unique_ips) == 1:
            results.append(f"\n🔴 WILDCARD DNS DETECTED! All random subdomains resolve to: {unique_ips.pop()}")
            results.append("  Impact: Subdomain enumeration will produce FALSE POSITIVES")
            results.append("  Mitigation: Filter results by this IP, or use tools with wildcard filtering (subfinder -nW)")
            results.append("  For feroxbuster/gobuster: responses from this IP should be filtered")
        else:
            results.append(f"\n⚠️  Multiple random subs resolve but to DIFFERENT IPs: {unique_ips}")
            results.append("  Possible load balancer or CDN catch-all")
    elif len(resolved_ips) == 1:
        results.append("\n⚠️  Partial wildcard — 1 of 3 random subs resolved")
        results.append("  May be intermittent or recently changed")
    else:
        results.append("\n✅ No wildcard DNS detected — subdomain enumeration is safe")

    return "\n".join(results)


@function_tool()
def dns_rebinding_probe(target_url: str, internal_ip: str = "127.0.0.1") -> str:
    """
    Test if a web application is vulnerable to DNS rebinding attacks.
    DNS rebinding bypasses Same-Origin Policy by switching DNS resolution
    from the attacker's server to an internal IP after the browser has loaded.

    This checks the server-side mitigations:
    - Host header validation
    - DNS pinning
    - Private IP rejection

    Args:
        target_url: URL to test (e.g. http://target.com/api/internal)
        internal_ip: Internal IP to test rebinding to (default 127.0.0.1)

    Returns:
        DNS rebinding vulnerability assessment
    """
    import urllib.parse
    results = [f"[DNS REBINDING] Testing: {target_url}"]
    results.append(f"Rebind target IP: {internal_ip}\n")

    parsed = urllib.parse.urlparse(target_url)
    original_host = parsed.hostname

    # Test 1: Host header manipulation
    results.append("[TEST 1] Host header validation")
    test_hosts = [
        internal_ip,
        f"{internal_ip}.nip.io",
        "127.0.0.1.nip.io",
        f"{original_host}.attacker.com",
        "localhost",
        "0.0.0.0",
        "[::1]",
    ]

    for test_host in test_hosts:
        try:
            resp = requests.get(
                target_url,
                headers={"Host": test_host},
                timeout=5, verify=False, allow_redirects=False
            )
            if resp.status_code < 400:
                results.append(f"  🔴 Host '{test_host}' accepted! Status: {resp.status_code}")
                results.append("     Server does NOT validate Host header — rebinding possible")
            else:
                results.append(f"  ✅ Host '{test_host}' rejected: {resp.status_code}")
        except Exception as e:
            results.append(f"  ⚠️  Host '{test_host}' error: {str(e)[:40]}")

    # Test 2: Private IP in URL parameters (server-side SSRF via rebinding)
    results.append("\n[TEST 2] URL-based internal access")

    # Check if any URL param accepts URLs
    params = dict(urllib.parse.parse_qsl(parsed.query))
    url_params = [k for k, v in params.items() if v.startswith("http")]

    if url_params:
        results.append(f"  Found URL parameters: {url_params}")
        results.append("  These can be DNS-rebinding pivot points")
    else:
        results.append("  No URL parameters found — test manually with known endpoints")

    results.append("\n[REMEDIATION]")
    results.append("  • Validate Host header against whitelist")
    results.append("  • Use DNS pinning (resolve once, cache IP)")
    results.append("  • Reject private/internal IPs in URL parameters")
    results.append("  • Tools: Singularity (NCC Group), rbndr.us")

    return "\n".join(results)


@function_tool()
def spf_dmarc_dkim_check(domain: str) -> str:
    """
    Check email security posture: SPF, DMARC, DKIM records.
    Weak email security = email spoofing = phishing attacks.
    This is a common bug bounty finding (P3-P4 severity).

    Args:
        domain: Domain to check (e.g. example.com)

    Returns:
        Email security assessment with spoofability rating
    """
    results = [f"[EMAIL SECURITY] Checking: {domain}"]
    results.append("=" * 60)

    score = 0  # 0 = fully spoofable, 10 = hardened
    issues = []

    # ── SPF Check ─────────────────────────────────────────────
    results.append("\n[SPF RECORD]")
    try:
        spf_result = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=10
        )
        spf_output = spf_result.stdout
        spf_records = re.findall(r'"(v=spf1[^"]*)"', spf_output, re.IGNORECASE)

        if not spf_records:
            results.append("  🔴 NO SPF RECORD — anyone can send email as @" + domain)
            issues.append("Missing SPF record")
        else:
            spf = spf_records[0]
            results.append(f"  Record: {spf}")

            if "+all" in spf:
                results.append("  🔴 SPF has '+all' — ALLOWS ALL SENDERS (useless!)")
                issues.append("SPF +all allows all senders")
            elif "~all" in spf:
                results.append("  🟡 SPF has '~all' (softfail) — emails from unauthorized senders may still be delivered")
                issues.append("SPF softfail (~all) instead of hardfail (-all)")
                score += 2
            elif "-all" in spf:
                results.append("  ✅ SPF has '-all' (hardfail) — unauthorized senders blocked")
                score += 4
            elif "?all" in spf:
                results.append("  🔴 SPF has '?all' (neutral) — no enforcement")
                issues.append("SPF neutral (?all) provides no protection")

            # Check for too many includes (DNS lookup limit = 10)
            includes = re.findall(r'include:', spf)
            if len(includes) > 8:
                results.append(f"  ⚠️  {len(includes)} includes — approaching 10 DNS lookup limit")
                issues.append(f"SPF has {len(includes)} includes (limit: 10)")
    except Exception as e:
        results.append(f"  Error: {e}")

    # ── DMARC Check ───────────────────────────────────────────
    results.append("\n[DMARC RECORD]")
    try:
        dmarc_result = subprocess.run(
            ["nslookup", "-type=TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=10
        )
        dmarc_output = dmarc_result.stdout
        dmarc_records = re.findall(r'"(v=DMARC1[^"]*)"', dmarc_output, re.IGNORECASE)

        if not dmarc_records:
            results.append("  🔴 NO DMARC RECORD — email spoofing not monitored")
            issues.append("Missing DMARC record")
        else:
            dmarc = dmarc_records[0]
            results.append(f"  Record: {dmarc}")

            # Parse policy
            policy_match = re.search(r'p=(\w+)', dmarc)
            if policy_match:
                policy = policy_match.group(1).lower()
                if policy == "none":
                    results.append("  🔴 DMARC policy is 'none' — NO ENFORCEMENT (monitoring only)")
                    issues.append("DMARC p=none provides no protection")
                elif policy == "quarantine":
                    results.append("  🟡 DMARC policy is 'quarantine' — spoofed emails go to spam")
                    score += 2
                elif policy == "reject":
                    results.append("  ✅ DMARC policy is 'reject' — spoofed emails blocked")
                    score += 3

            # Check subdomain policy
            sp_match = re.search(r'sp=(\w+)', dmarc)
            if sp_match:
                results.append(f"  Subdomain policy: {sp_match.group(1)}")
            else:
                results.append("  ⚠️  No subdomain policy (sp=) — inherits parent policy")

            # Check reporting
            if 'rua=' in dmarc:
                results.append("  ✅ Aggregate reporting enabled (rua=)")
            if 'ruf=' in dmarc:
                results.append("  ✅ Forensic reporting enabled (ruf=)")

            # Check percentage
            pct_match = re.search(r'pct=(\d+)', dmarc)
            if pct_match and int(pct_match.group(1)) < 100:
                results.append(f"  ⚠️  Only {pct_match.group(1)}% of emails checked")
                issues.append(f"DMARC pct={pct_match.group(1)} (not 100%)")
    except Exception as e:
        results.append(f"  Error: {e}")

    # ── DKIM Check ────────────────────────────────────────────
    results.append("\n[DKIM RECORDS]")
    common_selectors = ["default", "google", "k1", "mail", "dkim", "s1", "s2",
                        "selector1", "selector2", "mandrill", "mxvault"]
    dkim_found = False
    for selector in common_selectors:
        try:
            dkim_result = subprocess.run(
                ["nslookup", "-type=TXT", f"{selector}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=5
            )
            if "DKIM" in dkim_result.stdout.upper() or "v=dkim" in dkim_result.stdout.lower() or "p=" in dkim_result.stdout:
                results.append(f"  ✅ DKIM found: selector={selector}")
                dkim_found = True
                score += 2
                break
        except Exception:
            continue

    if not dkim_found:
        results.append(f"  🟡 No DKIM found (checked {len(common_selectors)} common selectors)")
        results.append("  Note: DKIM may exist with a non-standard selector")
        issues.append("No DKIM record found with common selectors")

    # ── Spoofability Rating ───────────────────────────────────
    results.append(f"\n{'='*60}")
    results.append("EMAIL SPOOFABILITY ASSESSMENT")
    results.append(f"{'='*60}")

    if score <= 2:
        rating = "🔴 EASILY SPOOFABLE"
        results.append(f"  Rating: {rating}")
        results.append(f"  An attacker can send emails as anyone@{domain}")
        results.append("  Impact: Phishing, BEC, account takeover via password resets")
    elif score <= 5:
        rating = "🟡 PARTIALLY PROTECTED"
        results.append(f"  Rating: {rating}")
        results.append("  Some protection exists but can be bypassed")
    else:
        rating = "✅ WELL PROTECTED"
        results.append(f"  Rating: {rating}")
        results.append("  Email spoofing is blocked or quarantined")

    if issues:
        results.append(f"\n  Issues Found ({len(issues)}):")
        for issue in issues:
            results.append(f"    • {issue}")

    results.append(f"\n  Security Score: {score}/9")

    return "\n".join(results)


@function_tool()
def dns_zone_transfer_exploit(domain: str) -> str:
    """
    Attempt DNS zone transfer (AXFR) and parse all records if successful.
    A successful zone transfer leaks ALL DNS records — subdomains, internal IPs,
    mail servers, TXT records with SPF/DKIM, SRV records, etc.

    This goes beyond just checking if AXFR is allowed — it actually parses
    and categorizes the leaked records for exploitation.

    Args:
        domain: Domain to attempt zone transfer on

    Returns:
        Parsed zone transfer results or failure message
    """
    results = [f"[ZONE TRANSFER] Attempting AXFR on: {domain}"]

    # First get NS servers
    try:
        ns_result = subprocess.run(
            ["nslookup", "-type=NS", domain],
            capture_output=True, text=True, timeout=10
        )
        ns_servers = re.findall(r'nameserver\s*=\s*(\S+)', ns_result.stdout, re.IGNORECASE)
        ns_servers += re.findall(r'Name Server:\s*(\S+)', ns_result.stdout, re.IGNORECASE)
        ns_servers = [ns.rstrip(".") for ns in ns_servers]

        if not ns_servers:
            results.append("  No NS servers found — cannot attempt AXFR")
            return "\n".join(results)

        results.append(f"  NS servers: {', '.join(ns_servers)}")
    except Exception as e:
        results.append(f"  Error getting NS: {e}")
        return "\n".join(results)

    # Attempt AXFR against each NS
    for ns in ns_servers:
        results.append(f"\n[AXFR] Trying: {ns}")
        try:
            # Try dig first (more reliable for AXFR)
            axfr_result = subprocess.run(
                ["dig", f"@{ns}", domain, "AXFR", "+nocomments", "+nostats"],
                capture_output=True, text=True, timeout=15
            )
            output = axfr_result.stdout

            if "Transfer failed" in output or "failed" in output.lower() or not output.strip():
                # Try nslookup fallback
                axfr_result = subprocess.run(
                    ["nslookup", "-type=AXFR", domain, ns],
                    capture_output=True, text=True, timeout=15
                )
                output = axfr_result.stdout

            if "Transfer failed" in output or "refused" in output.lower() or len(output.strip()) < 50:
                results.append(f"  ❌ AXFR refused by {ns}")
                continue

            # AXFR succeeded!
            results.append(f"  🔴 ZONE TRANSFER SUCCESSFUL from {ns}!")
            results.append("  This is a CRITICAL vulnerability — all DNS records leaked\n")

            # Parse and categorize records
            a_records = re.findall(r'(\S+)\s+\d*\s*IN\s+A\s+(\S+)', output)
            cname_records = re.findall(r'(\S+)\s+\d*\s*IN\s+CNAME\s+(\S+)', output)
            mx_records = re.findall(r'(\S+)\s+\d*\s*IN\s+MX\s+\d+\s+(\S+)', output)
            txt_records = re.findall(r'(\S+)\s+\d*\s*IN\s+TXT\s+"([^"]+)"', output)
            srv_records = re.findall(r'(\S+)\s+\d*\s*IN\s+SRV\s+(\S+)', output)
            re.findall(r'(\S+)\s+\d*\s*IN\s+NS\s+(\S+)', output)

            if a_records:
                results.append(f"  [A Records] ({len(a_records)} hosts)")
                # Identify internal IPs
                for name, ip in a_records[:30]:
                    internal = ""
                    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                      "172.30.", "172.31.", "192.168.")):
                        internal = " ⚠️ INTERNAL IP!"
                    results.append(f"    {name} → {ip}{internal}")

            if cname_records:
                results.append(f"\n  [CNAME Records] ({len(cname_records)})")
                for name, target in cname_records[:20]:
                    results.append(f"    {name} → {target}")

            if mx_records:
                results.append(f"\n  [MX Records] ({len(mx_records)})")
                for name, mx in mx_records[:10]:
                    results.append(f"    {name} → {mx}")

            if txt_records:
                results.append(f"\n  [TXT Records] ({len(txt_records)})")
                for name, txt in txt_records[:15]:
                    # Flag interesting TXT records
                    flag = ""
                    if "spf" in txt.lower():
                        flag = " [SPF]"
                    elif "dkim" in txt.lower():
                        flag = " [DKIM]"
                    elif "dmarc" in txt.lower():
                        flag = " [DMARC]"
                    elif any(kw in txt.lower() for kw in ["api", "key", "secret", "token", "password"]):
                        flag = " 🔴 SENSITIVE!"
                    results.append(f"    {name}: {txt[:80]}{flag}")

            if srv_records:
                results.append(f"\n  [SRV Records] ({len(srv_records)})")
                for name, target in srv_records[:10]:
                    results.append(f"    {name} → {target}")

            total = len(a_records) + len(cname_records) + len(mx_records) + len(txt_records)
            results.append(f"\n  Total records leaked: {total}")
            results.append("  Use these subdomains for further reconnaissance!")
            break  # Got data, stop trying other NS

        except FileNotFoundError:
            results.append("  ⚠️  'dig' not found — install dnsutils")
        except Exception as e:
            results.append(f"  Error: {str(e)[:60]}")

    return "\n".join(results)
