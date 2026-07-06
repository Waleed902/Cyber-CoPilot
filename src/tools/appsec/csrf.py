import subprocess
import re
import requests
from src.sdk.tool import function_tool
from .common import register_appsec_vulnerability

# Session-level deduplication for CSRF analysis
_csrf_analyzed_urls: set[str] = set()


@function_tool()
async def csrf_analyzer(url: str, method: str = "POST", cookies: str = "") -> str:
    """
    Analyze a form/endpoint for CSRF vulnerabilities.
    Checks for anti-CSRF tokens, SameSite cookie settings, and actually
    tests if the endpoint accepts state-changing requests without tokens.

    Args:
        url: Target URL to analyze
        method: HTTP method (typically POST for CSRF)
        cookies: Session cookies to use

    Returns:
        CSRF analysis results with recommendations
    """
    # Session-level dedup
    if url in _csrf_analyzed_urls:
        return f"[SKIPPED] CSRF analysis already performed on {url} this session. Use the existing results."
    _csrf_analyzed_urls.add(url)

    results = []
    results.append(f"## CSRF Analysis for {url}\n")

    issues = []
    confirmations = []

    # Resolve vhost -> IP if hostname is not in DNS
    try:
        from src.tools.http_proxy import resolve_vhost as _resolve_vhost
        _resolved_url, _vhost = _resolve_vhost(url)
    except Exception:
        _resolved_url, _vhost = url, ""

    # Fetch the page
    cmd = ["curl", "-s", "-i", "-c", "-", "-L", "--max-time", "15"]
    if cookies:
        cmd.extend(["-H", f"Cookie: {cookies}"])
    if _vhost:
        cmd.extend(["-H", f"Host: {_vhost}"])
    cmd.append(_resolved_url)

    response = ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        response = result.stdout

        if not response.strip():
            return (
                f"## CSRF Analysis for {url}\n\n"
                f"\u26a0\ufe0f Empty response \u2014 host may be unreachable.\n"
                f"CSRF status: UNKNOWN"
            )

        # Parse headers and body
        header_body_split = response.split("\r\n\r\n", 1)
        if len(header_body_split) == 2:
            headers_text, body = header_body_split
        else:
            headers_text = ""
            body = header_body_split[0] if header_body_split else ""

        # Check for CSRF tokens in response body
        csrf_patterns = [
            (r'(?i)name=["\']csrf[_-]?token["\']', "CSRF token meta tag"),
            (r'(?i)name=["\']authenticity_token["\']', "Rails authenticity token"),
            (r'(?i)name=["\']_token["\']', "Generic _token"),
            (r'(?i)name=["\']__requestverificationtoken["\']', "ASP.NET verification token"),
            (r'(?i)name=["\']anti[_-]?csrf["\']', "Anti-CSRF token"),
            (r'(?i)content=["\'][^"\']{8,}["\'][^>]*name=["\']csrf-token["\']', "Meta CSRF content"),
        ]

        has_csrf_token = False
        for pattern, token_name in csrf_patterns:
            if re.search(pattern, body):
                has_csrf_token = True
                results.append(f"\u2705 CSRF token found: {token_name}")
                break

        # Also check for CSRF token in cookies
        csrf_cookie_patterns = [r'(?i)csrf[_-]?token', r'(?i)xsrf[_-]?token', r'(?i)_csrf']
        has_csrf_cookie = False
        for cookie_pattern in csrf_cookie_patterns:
            if re.search(cookie_pattern, response):
                has_csrf_cookie = True
                results.append("\u2705 CSRF token cookie found")
                break

        if not has_csrf_token and not has_csrf_cookie:
            results.append("\u26a0\ufe0f No CSRF token detected in response or cookies")
        else:
            confirmations.append("CSRF protection mechanism detected")

        # Check cookie SameSite attributes
        set_cookie_headers = re.findall(r'(?i)Set-Cookie:\s*([^\r\n]+)', headers_text)

        for cookie in set_cookie_headers:
            cookie_lower = cookie.lower()
            if "samesite=strict" in cookie_lower:
                results.append("  \u2705 Cookie: SameSite=Strict (strong CSRF protection)")
                confirmations.append("SameSite=Strict cookie protection")
            elif "samesite=lax" in cookie_lower:
                results.append("  \u26a0\ufe0f Cookie: SameSite=Lax (partial CSRF protection)")
            elif "samesite" not in cookie_lower:
                results.append("  \u274c Cookie missing SameSite attribute")
                issues.append("Cookie missing SameSite attribute")

        # Check security headers properly - parse from HEADERS only
        headers_text.lower()

        # X-Frame-Options: check headers specifically
        if re.search(r'(?i)^X-Frame-Options:', headers_text, re.MULTILINE):
            xfo_value = re.search(r'(?i)^X-Frame-Options:\s*(.+)', headers_text, re.MULTILINE)
            if xfo_value:
                results.append(f"  \u2705 X-Frame-Options: {xfo_value.group(1).strip()}")
                confirmations.append("X-Frame-Options present")
        else:
            # Also check in CSP header
            csp_frame = re.search(r'(?i)frame-ancestors\s+([^;]+)', headers_text)
            if csp_frame:
                results.append(f"  \u2705 Content-Security-Policy frame-ancestors: {csp_frame.group(1).strip()}")
                confirmations.append("CSP frame-ancestors present")
            else:
                issues.append("Missing X-Frame-Options header")
                results.append("  \u274c Missing X-Frame-Options")

        # Content-Security-Policy
        if re.search(r'(?i)^Content-Security-Policy:', headers_text, re.MULTILINE):
            csp_match = re.search(r'(?i)^Content-Security-Policy:\s*(.+)', headers_text, re.MULTILINE)
            if csp_match:
                results.append("  \u2705 Content-Security-Policy present")
                confirmations.append("Content-Security-Policy present")
        else:
            results.append("  \u26a0\ufe0f Missing Content-Security-Policy header")

        # \u2500\u2500\u2500 ACTUAL CSRF EXPLOITATION TEST \u2500\u2500\u2500
        # Don't just look for tokens - actually test if the endpoint accepts requests without them
        results.append("\n### Active CSRF Exploitation Test")

        # Build a minimal POST request without CSRF tokens
        test_headers = {
            "User-Agent": "Mozilla/5.0 (CyberCoPilot CSRF Tester)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://evil.com",  # Cross-origin
            "Referer": "https://evil.com/",
        }
        if cookies:
            test_headers["Cookie"] = cookies

        try:
            test_resp = requests.post(
                _resolved_url,
                data={"csrf_test": "true"},
                headers=test_headers,
                timeout=10,
                allow_redirects=False,
                verify=False
            )

            status = test_resp.status_code

            # Check if the request was accepted without CSRF token
            if status in (200, 201, 204):
                # Success without token = potential CSRF
                body_text = test_resp.text.lower()
                # Check if response indicates successful action
                if "error" not in body_text and "invalid" not in body_text and "forbidden" not in body_text:
                    issues.append(f"Endpoint accepts {method} requests without CSRF token (HTTP {status})")
                    results.append(f"  \ud83d\udd34 ENDPOINT ACCEPTS POST WITHOUT CSRF TOKEN (HTTP {status})")
                else:
                    results.append(f"  \u2705 Endpoint rejected tokenless request (HTTP {status})")
                    confirmations.append("Endpoint requires CSRF validation")
            elif status == 403:
                results.append("  \u2705 Request rejected with 403 Forbidden")
                confirmations.append("Endpoint has CSRF or origin validation")
            elif status == 401:
                results.append("  \u26a0\ufe0f Request rejected with 401 Unauthorized (auth required)")
            elif status == 422:
                results.append("  \u2705 Request rejected with 422 Unprocessable Entity")
                confirmations.append("Endpoint validates requests")
            else:
                results.append(f"  \u26a0\ufe0f Response: HTTP {status}")

        except requests.exceptions.Timeout:
            results.append("  \u26a0\ufe0f Exploitation test timed out")
        except requests.exceptions.ConnectionError:
            results.append("  \u26a0\ufe0f Could not connect to endpoint for exploitation test")
        except Exception as e:
            results.append(f"  \u26a0\ufe0f Exploitation test failed: {str(e)[:60]}")

    except subprocess.TimeoutExpired:
        return (
            f"## CSRF Analysis for {url}\n\n"
            f"\u26a0\ufe0f Request timed out. Host may be unreachable.\n"
            f"CSRF status: UNKNOWN"
        )
    except Exception as e:
        return f"Error analyzing CSRF: {str(e)}"

    # Summary
    results.append("\n## Vulnerability Summary")
    if issues:
        results.append(f"🔴 Found {len(issues)} CSRF-related issues:")
        for issue in issues:
            results.append(f"  - {issue}")
            await register_appsec_vulnerability(
                target_url=url, vuln_type="CSRF", severity="HIGH",
                parameter=method, payload="", evidence=issue
            )
        results.append("\n### Exploitation Tips:")
        results.append("1. Create an HTML form targeting the vulnerable endpoint")
        results.append("2. Host it on attacker-controlled domain")
        results.append("3. Trick victim into visiting while authenticated")
        results.append("4. Use fetch() or XMLHttpRequest for tokenless requests")
    elif confirmations:
        results.append(f"\u2705 CSRF protections verified ({len(confirmations)} confirmations):")
        for c in confirmations:
            results.append(f"  - {c}")
    else:
        results.append("\u26a0\ufe0f Inconclusive results - manual review recommended")

    return "\n".join(results)
