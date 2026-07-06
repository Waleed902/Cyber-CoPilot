"""
HTTP Proxy Tools - Request/Response Manipulation

Provides full HTTP proxy capabilities for:
- Request interception and modification
- Response analysis
- Header manipulation
- Cookie management
- Session handling
"""

import subprocess
import re
import json
import urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from src.sdk.tool import function_tool

# ── DNS resolution cache ─────────────────────────────────────────────────────
# Caches whether a hostname is resolvable for 60 seconds to avoid blocking
# gethostbyname() calls on every tool invocation.
import time as _time
_dns_cache: dict = {}   # hostname → (resolvable: bool, expires_at: float)
_DNS_CACHE_TTL = 60.0   # seconds


def _dns_resolves(hostname: str) -> bool:
    """Return True if hostname resolves via DNS. Results cached for 60 s."""
    import socket as _sock
    now = _time.monotonic()
    entry = _dns_cache.get(hostname)
    if entry is not None:
        resolvable, expires_at = entry
        if now < expires_at:
            return resolvable
    try:
        _sock.gethostbyname(hostname)
        resolvable = True
    except _sock.gaierror:
        resolvable = False
    _dns_cache[hostname] = (resolvable, now + _DNS_CACHE_TTL)
    return resolvable


# Session-level consecutive-timeout guard:
# If the same host times out N times in a row without a successful response,
# further calls block immediately with an instructive error rather than wasting
# 30 seconds each iteration.
_HTTP_TIMEOUT_MAX = 3          # hard stop after this many consecutive timeouts
_http_timeout_counts: dict = {}  # host → consecutive timeout count


@dataclass
class HTTPRequest:
    """Represents an HTTP request."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    
    def to_curl(self) -> str:
        """Convert to curl command."""
        cmd_parts = ["curl", "-X", self.method]
        
        for key, value in self.headers.items():
            cmd_parts.extend(["-H", f"{key}: {value}"])
        
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            cmd_parts.extend(["-H", f"Cookie: {cookie_str}"])
        
        if self.body:
            cmd_parts.extend(["-d", self.body])
        
        cmd_parts.append(self.url)
        return " ".join(cmd_parts)


@dataclass
class HTTPResponse:
    """Represents an HTTP response."""
    status_code: int
    status_text: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_time: float = 0.0
    
    def get_header(self, name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


class HTTPSession:
    """Manages HTTP session state with cookie persistence."""
    
    def __init__(self):
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.history: List[Tuple[HTTPRequest, HTTPResponse]] = []
    
    def set_cookie(self, name: str, value: str):
        self.cookies[name] = value
    
    def set_header(self, name: str, value: str):
        self.headers[name] = value
    
    def clear_cookies(self):
        self.cookies.clear()


# Global session
_session = HTTPSession()


def get_session() -> HTTPSession:
    return _session


def resolve_vhost(url: str) -> tuple[str, str]:
    """
    Resolve an unresolvable vhost hostname to its IP using the context hub.

    If the URL hostname cannot be resolved by DNS, looks up the IP from the
    context hub (registered services / current target) and returns a rewritten
    URL that uses the IP + the original hostname as a Host header value.

    Also handles the reverse case: if the URL is already an IP address, checks
    whether a vhost hostname is registered for that IP in the context hub and
    returns it as the Host header — ensuring tools like ssti_scanner that are
    called with a raw IP still inject the correct Host: header.

    Returns:
        (resolved_url, host_header)  — host_header is "" when no rewrite needed.
    """
    import socket as _sock
    import re as _re
    from urllib.parse import urlparse as _up

    parsed = _up(url)
    hostname = parsed.hostname or ""

    # ── Case A: URL already uses an IP ────────────────────────────────────────
    # Check if the context hub has a vhost registered for this IP and inject
    # the Host header so web apps that require a virtualhost still work.
    if hostname and _re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        try:
            from src.sdk.context_hub import get_context_hub
            chub = get_context_hub()
            for sd in chub.findings.get("subdomains", []):
                if sd.get("ip") == hostname and sd.get("subdomain"):
                    # Return the URL unchanged but with correct Host header
                    return url, sd["subdomain"]
        except Exception:
            pass
        return url, ""  # IP with no known vhost

    # ── Case B: URL uses a hostname ── try DNS first ──────────────────────────
    if _dns_resolves(hostname):
        return url, ""  # DNS works fine (result cached)

    # ── Case C: Hostname doesn't resolve ── look up IP in context hub ─────────
    try:
        from src.sdk.context_hub import get_context_hub
        chub = get_context_hub()
        ip = ""
        for sd in chub.findings.get("subdomains", []):
            if sd.get("subdomain") == hostname and sd.get("ip"):
                ip = sd["ip"]
                break
        if not ip:
            ct = chub.current_target or ""
            if _re.match(r'^\d+\.\d+\.\d+\.\d+$', ct):
                ip = ct
        if ip:
            new_url = url.replace(f"{parsed.scheme}://{hostname}", f"{parsed.scheme}://{ip}")
            return new_url, hostname
    except Exception:
        pass

    return url, ""


@function_tool()
def http_request(url: str, method: str = "GET", headers: str = "",
                 data: str = "", json_data: str = "",
                 cookies: str = "", follow_redirects: bool = True,
                 timeout: int = 30, proxy: str = "", session_name: str = "", **kwargs) -> str:
    """
    Make a fully customizable HTTP request with detailed response analysis.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
        headers: Custom headers as "Key1: Value1, Key2: Value2"
        data: Form data or raw body
        json_data: JSON data (sets Content-Type automatically)
        cookies: Cookies as "name1=value1; name2=value2"
        follow_redirects: Whether to follow 3xx redirects
        timeout: Request timeout in seconds
        proxy: Proxy URL (e.g., http://127.0.0.1:8080)
        session_name: Active authentication session name to automatically inject cookies and tokens.

    Returns:
        Detailed response with headers, body, and analysis
    """
    if session_name:
        from src.tools.auth_context import _SESSION_STORE
        sess = _SESSION_STORE.get(session_name)
        if not sess:
            return f"⛔ ERROR: Authentication session '{session_name}' not found."
        
        req_kwargs = sess.as_requests_kwargs()
        
        # Inject cookies
        if req_kwargs.get("cookies"):
            sess_cookies = "; ".join(f"{k}={v}" for k, v in req_kwargs["cookies"].items())
            cookies = f"{sess_cookies}; {cookies}" if cookies else sess_cookies
            
        # Inject headers (like Authorization)
        if req_kwargs.get("headers"):
            for hk, hv in req_kwargs["headers"].items():
                if hk.lower() == "authorization":
                    token_hdr = f"{hk}: {hv}"
                    headers = f"{headers}, {token_hdr}" if headers else token_hdr

    # ── GET with body guard: map data/json_data into query string ─────────
    method_upper = method.upper()
    if method_upper == "GET" and (data or json_data):
        import json as _json
        import urllib.parse as _ulp

        url_for_parse = url if "://" in url else f"http://{url}"
        parsed = _ulp.urlparse(url_for_parse)
        query_pairs = list(_ulp.parse_qsl(parsed.query, keep_blank_values=True))

        if json_data:
            try:
                payload = _json.loads(json_data)
                if isinstance(payload, dict):
                    for k, v in payload.items():
                        query_pairs.append((str(k), str(v)))
                else:
                    query_pairs.append(("json", json_data))
            except Exception:
                query_pairs.append(("json", json_data))

        if data:
            query_pairs.extend(_ulp.parse_qsl(data, keep_blank_values=True))

        new_query = _ulp.urlencode(query_pairs, doseq=True)
        url = _ulp.urlunparse(parsed._replace(query=new_query))
        data = ""
        json_data = ""

    # ── Consecutive-timeout guard ─────────────────────────────────────────────
    try:
        import urllib.parse as _ulp_to
        _host_to = _ulp_to.urlparse(url if "://" in url else f"http://{url}").hostname or url
        _tc = _http_timeout_counts.get(_host_to, 0)
        if _tc >= _HTTP_TIMEOUT_MAX:
            return (
                f"⛔ TIMEOUT LOOP DETECTED: {_host_to} has timed out {_tc} consecutive times.\n"
                f"Continuing to send HTTP requests to this host is pointless.\n"
                f"Possible causes:\n"
                f"  • Host is firewalled / only accessible via specific network path\n"
                f"  • Hostname resolves to an IP that does not serve HTTP\n"
                f"  • The service requires a VPN or specific source IP\n"
                f"Action: Stop HTTP requests to {_host_to} and report findings so far."
            )
    except Exception:
        pass
    # ── Protocol guard: reject non-HTTP ports before curl even runs ───────────
    _NON_HTTP_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 110: "POP3", 143: "IMAP",
        161: "SNMP", 389: "LDAP", 445: "SMB",
        465: "SMTPS/SMTP", 587: "SMTP Submission",
        636: "LDAPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 27017: "MongoDB",
    }
    try:
        import urllib.parse as _ulp_guard
        _url_check = url if "://" in url else f"http://{url}"
        _parsed_check = _ulp_guard.urlparse(_url_check)
        _port_check = _parsed_check.port
        _svc_name = _NON_HTTP_PORTS.get(_port_check, "") if _port_check else ""
        if _svc_name:
            _tips = {
                21:  "  ftp <target>  or  nmap_service_scan for enumeration",
                22:  "  ssh_exec() or netcat_shell() for SSH interaction",
                25:  f"  Raw socket:  nc -C {_parsed_check.hostname} 25  (speak SMTP)",
                110: f"  Raw socket:  nc {_parsed_check.hostname} 110  (speak POP3)",
                143: f"  Raw socket:  nc {_parsed_check.hostname} 143  (speak IMAP)",
                465: f"  swaks --server {_parsed_check.hostname}:465 --tls",
                587: (
                    f"  swaks: swaks --to user@domain --server {_parsed_check.hostname}:587 --tls\n"
                    f"  Python: python3 -c \"import smtplib; s=smtplib.SMTP('{_parsed_check.hostname}', 587); "
                    f"s.ehlo(); s.starttls(); print(s.ehlo())\""
                ),
                993: f"  openssl s_client -connect {_parsed_check.hostname}:993",
                995: f"  openssl s_client -connect {_parsed_check.hostname}:995",
            }
            _tip = _tips.get(_port_check, f"  Use a protocol-specific tool for {_svc_name} on port {_port_check}")
            return (
                f"\u26d4 PROTOCOL MISMATCH: http_request cannot communicate with a "
                f"{_svc_name} service on port {_port_check}.\n"
                f"URL passed: {url}\n\n"
                f"Correct approach:\n{_tip}"
            )
    except Exception:
        pass  # guard is non-fatal — proceed if URL parsing fails
    import time
    
    cmd = ["curl", "-s", "-i", "-w", "\n%{time_total}", "--globoff", "-X", method.upper()]

    # Timeout
    cmd.extend(["--max-time", str(timeout)])
    
    # Redirects
    if follow_redirects:
        cmd.append("-L")
    
    # Proxy — use explicit proxy, or auto-inject from proxy_manager if active
    if not proxy:
        try:
            from src.tools.proxy_manager import get_proxy_url
            proxy = get_proxy_url()
        except Exception:
            pass
    if proxy:
        cmd.extend(["-x", proxy])
    
    # Add session headers
    session = get_session()
    for key, value in session.headers.items():
        cmd.extend(["-H", f"{key}: {value}"])
    
    # Custom headers
    if headers:
        for header in headers.split(","):
            header = header.strip()
            if header:
                cmd.extend(["-H", header])
    
    # JSON data
    if json_data:
        cmd.extend(["-H", "Content-Type: application/json"])
        cmd.extend(["-d", json_data])
    elif data:
        cmd.extend(["-d", data])
    
    # Cookies (merge session + custom)
    all_cookies = session.cookies.copy()
    if cookies:
        for cookie in cookies.split(";"):
            if "=" in cookie:
                name, value = cookie.strip().split("=", 1)
                all_cookies[name] = value
    
    if all_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in all_cookies.items())
        cmd.extend(["-H", f"Cookie: {cookie_str}"])

    # ── Virtual host awareness ─────────────────────────────────────────────
    # If the URL hostname is unresolvable (e.g. facts.htb) but we have an IP
    # mapping in context, rewrite to use the IP + inject Host header so curl
    # can actually reach the target.  Only applies when the caller hasn't
    # already provided a Host header.
    _has_host_header = any("host:" in h.lower() for h in headers.split(",")) if headers else False
    if not _has_host_header:
        import socket as _socket
        import re as _re2
        from urllib.parse import urlparse as _urlparse2
        _p = _urlparse2(url)
        _h = _p.hostname or ""
        if _h and not _re2.match(r'^\d+\.\d+\.\d+\.\d+$', _h):
            if not _dns_resolves(_h):
                try:
                    from src.sdk.context_hub import get_context_hub
                    _chub = get_context_hub()
                    _ip2 = ""
                    for _sd in _chub.findings.get("subdomains", []):
                        if _sd.get("subdomain") == _h and _sd.get("ip"):
                            _ip2 = _sd["ip"]
                            break
                    if not _ip2:
                        _ct2 = _chub.current_target or ""
                        if _re2.match(r'^\d+\.\d+\.\d+\.\d+$', _ct2):
                            _ip2 = _ct2
                    if _ip2:
                        url = url.replace(f"{_p.scheme}://{_h}", f"{_p.scheme}://{_ip2}")
                        cmd.extend(["-H", f"Host: {_h}"])
                except Exception:
                    pass

    cmd.append(url)

    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=timeout + 5)
        elapsed = time.time() - start_time
        
        output = result.stdout
        lines = output.split("\n")
        
        # Parse response
        header_section = True
        body_lines = []
        status_line = ""
        headers_dict = {}
        
        for line in lines:
            if header_section:
                if line.startswith("HTTP/"):
                    status_line = line
                elif ": " in line:
                    key, value = line.split(": ", 1)
                    headers_dict[key.strip()] = value.strip()
                    
                    # Update session cookies
                    if key.lower() == "set-cookie":
                        cookie_parts = value.split(";")[0]
                        if "=" in cookie_parts:
                            c_name, c_value = cookie_parts.split("=", 1)
                            session.set_cookie(c_name.strip(), c_value.strip())
                
                elif line.strip() == "":
                    header_section = False
            else:
                body_lines.append(line)
        
        body = "\n".join(body_lines).strip()

        # Skip body for binary content types — avoids binary decode noise
        _ct = headers_dict.get('Content-Type', headers_dict.get('content-type', ''))
        _binary_types = ('image/', 'video/', 'audio/', 'application/octet-stream',
                         'application/zip', 'application/x-', 'font/')
        if any(_ct.startswith(bt) for bt in _binary_types):
            body = f'[Binary content ({_ct}) — {headers_dict.get("Content-Length", "?") } bytes, body skipped]'
        
        # Extract timing from curl output
        if body_lines and body_lines[-1].replace(".", "").isdigit():
            elapsed = float(body_lines[-1])
            body = "\n".join(body_lines[:-1]).strip()

        # Successful response — reset consecutive timeout counter for this host
        try:
            import urllib.parse as _ulp_ok
            _host_ok = _ulp_ok.urlparse(url if "://" in url else f"http://{url}").hostname or url
            _http_timeout_counts.pop(_host_ok, None)
        except Exception:
            pass

        # Ban detection — notify proxy_manager for auto-rotation
        try:
            _status_code_match = re.search(r'HTTP/\S+\s+(\d+)', status_line)
            if _status_code_match:
                _sc = int(_status_code_match.group(1))
                if _sc in (429, 403, 503):
                    from src.tools.proxy_manager import on_ban_detected
                    _ban_msg = on_ban_detected(_sc, url)
                    if _ban_msg:
                        # Prepend ban-rotation notice to output
                        pass  # logged silently; the agent sees the status code
        except Exception:
            pass

        # Build response
        results = [
            "## HTTP Response",
            f"**Status:** {status_line}",
            f"**Time:** {elapsed:.3f}s",
            "",
            "### Headers",
        ]
        
        for key, value in headers_dict.items():
            results.append(f"  {key}: {value}")
        
        results.append("")
        results.append("### Body")
        
        # Truncate large bodies
        if len(body) > 5000:
            results.append(f"```\n{body[:5000]}\n...[truncated, {len(body)} bytes total]\n```")
        else:
            results.append(f"```\n{body}\n```")
        
        # Security analysis — only meaningful when a real HTTP response was received.
        # An empty status_line means the connection failed (timeout/refused/DNS error);
        # reporting missing headers in that case produces false findings.
        results.append("")
        results.append("### Security Analysis")
        if not status_line:
            results.append("  ⚠️ No HTTP response received — security header analysis skipped")
        else:
            security_headers = {
                "X-Frame-Options": headers_dict.get("X-Frame-Options", "❌ Missing"),
                "X-Content-Type-Options": headers_dict.get("X-Content-Type-Options", "❌ Missing"),
                "X-XSS-Protection": headers_dict.get("X-XSS-Protection", "❌ Missing"),
                "Strict-Transport-Security": headers_dict.get("Strict-Transport-Security", "❌ Missing"),
                "Content-Security-Policy": headers_dict.get("Content-Security-Policy", "❌ Missing")[:50] if headers_dict.get("Content-Security-Policy") else "❌ Missing",
            }

            for header, value in security_headers.items():
                if value.startswith("❌"):
                    results.append(f"  ⚠️ {header}: {value}")
                else:
                    results.append(f"  ✅ {header}: {value[:50]}")
        
        return "\n".join(results)
    
    except subprocess.TimeoutExpired:
        # Track consecutive timeouts per host
        try:
            import urllib.parse as _ulp_te
            _host_te = _ulp_te.urlparse(url if "://" in url else f"http://{url}").hostname or url
            _http_timeout_counts[_host_te] = _http_timeout_counts.get(_host_te, 0) + 1
        except Exception:
            pass
        return f"Error: Request timed out after {timeout} seconds"
    except Exception as e:
        return f"Error: {str(e)}"


@function_tool()
def http_intercept_modify(original_request: str, modifications: str) -> str:
    """
    Take an HTTP request and modify it (simulating proxy intercept).
    
    Args:
        original_request: Raw HTTP request or curl command
        modifications: JSON with modifications: {"headers": {"X-New": "value"}, "body": "new body", "params": {"id": "2"}}
    
    Returns:
        Modified request and execution result
    """
    if not modifications:
        return "Error: modifications parameter is required (JSON string like {\"headers\": {}, \"body\": \"\"})"
    try:
        mods = json.loads(modifications)
    except (json.JSONDecodeError, TypeError):
        return "Error: modifications must be valid JSON"
    
    # Parse original request
    # If it's a curl command, extract parts
    if original_request.startswith("curl"):
        # Extract URL
        url_match = re.search(r'(https?://[^\s"]+)', original_request)
        url = url_match.group(1) if url_match else ""
        
        # Extract method
        method_match = re.search(r'-X\s+(\w+)', original_request)
        method = method_match.group(1) if method_match else "GET"
        
        # Extract existing headers
        headers = {}
        for match in re.finditer(r"-H\s+['\"]([^'\"]+)['\"]", original_request):
            if ": " in match.group(1):
                key, value = match.group(1).split(": ", 1)
                headers[key] = value
        
        # Extract body
        body_match = re.search(r"-d\s+['\"]([^'\"]+)['\"]", original_request)
        body = body_match.group(1) if body_match else ""
    else:
        return "Error: Please provide a curl command or use http_request directly"
    
    # Apply modifications
    if "url" in mods:
        url = mods["url"]
    
    if "method" in mods:
        method = mods["method"]
    
    if "headers" in mods:
        headers.update(mods["headers"])
    
    if "body" in mods:
        body = mods["body"]
    
    if "params" in mods:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params.update(mods["params"])
        new_query = urllib.parse.urlencode(params)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    # Build modified request
    header_str = ", ".join(f"{k}: {v}" for k, v in headers.items())
    
    result = [
        "## Modified Request",
        f"Method: {method}",
        f"URL: {url}",
        f"Headers: {header_str}",
        f"Body: {body[:200]}..." if len(body) > 200 else f"Body: {body}",
        "",
        "## Executing modified request...",
        ""
    ]
    
    # Execute
    response = http_request.invoke(
        url=url,
        method=method,
        headers=header_str,
        data=body
    )
    
    result.append(response)
    
    return "\n".join(result)


@function_tool()
def http_compare(url1: str, url2: str, method: str = "GET") -> str:
    """
    Compare responses from two URLs or same URL with different parameters.
    Useful for detecting behavioral differences (e.g., auth bypass, IDOR).
    
    Args:
        url1: First URL/request
        url2: Second URL/request  
        method: HTTP method
    
    Returns:
        Comparison of both responses highlighting differences
    """
    results = ["## HTTP Response Comparison\n"]
    
    # Make first request
    cmd1 = ["curl", "-s", "-i", "-X", method, "--max-time", "15", url1]
    cmd2 = ["curl", "-s", "-i", "-X", method, "--max-time", "15", url2]
    
    try:
        result1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=20)
        result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=20)
        
        resp1 = result1.stdout
        resp2 = result2.stdout
        
        # Extract status codes
        status1 = re.search(r'HTTP/\S+\s+(\d+)', resp1)
        status2 = re.search(r'HTTP/\S+\s+(\d+)', resp2)
        
        code1 = status1.group(1) if status1 else "Unknown"
        code2 = status2.group(1) if status2 else "Unknown"
        
        results.append(f"### Request 1: {url1[:60]}...")
        results.append(f"Status: {code1}")
        results.append(f"Response Length: {len(resp1)} bytes")
        
        results.append(f"\n### Request 2: {url2[:60]}...")
        results.append(f"Status: {code2}")
        results.append(f"Response Length: {len(resp2)} bytes")
        
        results.append("\n### Analysis")
        
        # Compare
        if code1 != code2:
            results.append(f"⚠️ Different status codes: {code1} vs {code2}")
        else:
            results.append(f"✅ Same status codes: {code1}")
        
        len_diff = abs(len(resp1) - len(resp2))
        if len_diff > 100:
            results.append(f"⚠️ Response size difference: {len_diff} bytes")
        else:
            results.append(f"✅ Similar response sizes (diff: {len_diff} bytes)")
        
        # Content comparison
        body1 = resp1.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp1 else resp1
        body2 = resp2.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in resp2 else resp2
        
        if body1 == body2:
            results.append("✅ Identical response bodies")
        else:
            results.append("⚠️ Different response bodies")
            
            # Find specific differences
            lines1 = set(body1.split("\n"))
            lines2 = set(body2.split("\n"))
            
            only_in_1 = lines1 - lines2
            only_in_2 = lines2 - lines1
            
            if only_in_1:
                results.append(f"\nOnly in Response 1 ({len(only_in_1)} unique lines):")
                for line in list(only_in_1)[:5]:
                    if line.strip():
                        results.append(f"  - {line[:80]}")
            
            if only_in_2:
                results.append(f"\nOnly in Response 2 ({len(only_in_2)} unique lines):")
                for line in list(only_in_2)[:5]:
                    if line.strip():
                        results.append(f"  + {line[:80]}")
        
        # Security implications
        results.append("\n### Security Implications")
        
        if code1 == "200" and code2 in ["401", "403"]:
            results.append("🔴 Potential Authorization Bypass: Request 1 bypassed auth!")
        elif code1 in ["401", "403"] and code2 == "200":
            results.append("🔴 Potential Authorization Bypass: Request 2 bypassed auth!")
        elif code1 == code2 == "200" and len_diff > 500:
            results.append("⚠️ Same status but different content - possible IDOR")
        
    except Exception as e:
        results.append(f"Error: {str(e)}")
    
    return "\n".join(results)


@function_tool()
def http_fuzz(url: str, parameter: str = "", wordlist_type: str = "numbers",
              custom_values: str = "", method: str = "GET") -> str:
    """
    Fuzz an HTTP parameter with different values.
    
    Args:
        url: Target URL with the parameter
        parameter: Parameter name to fuzz. If omitted, the first URL query
            parameter is used.
        wordlist_type: Type of fuzzing (numbers, common_ids, usernames, paths)
        custom_values: Custom values to test (comma-separated)
        method: HTTP method
    
    Returns:
        Fuzzing results showing different responses
    """
    results = ["## HTTP Parameter Fuzzing\n"]
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if not parameter:
        if params:
            parameter = next(iter(params))
            results.append(f"Inferred parameter: {parameter}")
        else:
            return (
                "Error: http_fuzz needs a parameter to fuzz. "
                "Pass parameter='id' or include a query string such as "
                "https://target/path?id=1."
            )
    
    # Build wordlist
    if custom_values:
        values = [v.strip() for v in custom_values.split(",")]
    elif wordlist_type == "numbers":
        values = [str(i) for i in range(1, 21)]
    elif wordlist_type == "common_ids":
        values = ["1", "2", "0", "-1", "admin", "test", "999999", "null", "undefined"]
    elif wordlist_type == "usernames":
        values = ["admin", "administrator", "root", "test", "user", "guest", "demo"]
    elif wordlist_type == "paths":
        values = ["../", "..\\", "/etc/passwd", "....//", "%00", "."]
    else:
        values = [str(i) for i in range(1, 11)]
    
    results.append(f"Parameter: {parameter}")
    results.append(f"Values to test: {len(values)}")
    results.append(f"Method: {method}\n")
    
    findings = []
    baseline_len = None
    
    for value in values[:30]:  # Limit to 30 tests
        test_params = params.copy()
        test_params[parameter] = value
        test_query = urllib.parse.urlencode(test_params)

        # Build test URL, then apply vhost resolution
        _base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        try:
            from src.tools.http_proxy import resolve_vhost as _rv
            _base_resolved, _fuzz_vhost = _rv(_base)
        except Exception:
            _base_resolved, _fuzz_vhost = _base, ""
        test_url = f"{_base_resolved}?{test_query}"
        
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code},%{size_download}", 
               "-X", method, "--max-time", "10"]
        if _fuzz_vhost:
            cmd.extend(["-H", f"Host: {_fuzz_vhost}"])
        cmd.append(test_url)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            output = result.stdout.strip()
            
            if "," in output:
                status, size = output.split(",")
                size = int(size)
                
                if baseline_len is None:
                    baseline_len = size
                
                # Flag interesting responses
                interesting = False
                notes = []
                
                if status not in ["200", "404"]:
                    interesting = True
                    notes.append(f"Status: {status}")
                
                if abs(size - baseline_len) > 100:
                    interesting = True
                    notes.append(f"Size diff: {size - baseline_len:+d}")
                
                if interesting:
                    findings.append({
                        "value": value,
                        "status": status,
                        "size": size,
                        "notes": notes
                    })
                
                results.append(f"  {value}: Status={status}, Size={size}")
        
        except Exception as e:
            results.append(f"  {value}: Error - {str(e)[:30]}")
    
    # Summary
    results.append("\n### Interesting Findings")
    
    if findings:
        for f in findings:
            results.append(f"  ⚠️ Value '{f['value']}': {', '.join(f['notes'])}")
    else:
        results.append("  No anomalies detected")
    
    return "\n".join(results)


@function_tool()
def session_status() -> str:
    """
    Get the current HTTP session status including cookies and headers.
    
    Returns:
        Current session state
    """
    session = get_session()
    
    results = [
        "## HTTP Session Status",
        "",
        "### Stored Cookies"
    ]
    
    if session.cookies:
        for name, value in session.cookies.items():
            results.append(f"  {name}: {value[:50]}...")
    else:
        results.append("  No cookies stored")
    
    results.append("")
    results.append("### Default Headers")
    
    for name, value in session.headers.items():
        results.append(f"  {name}: {value[:50]}")
    
    results.append("")
    results.append(f"### Request History: {len(session.history)} requests")
    
    return "\n".join(results)


@function_tool()
def session_set_cookie(name: str, value: str) -> str:
    """
    Set a cookie in the current session.
    
    Args:
        name: Cookie name
        value: Cookie value
    
    Returns:
        Confirmation
    """
    session = get_session()
    session.set_cookie(name, value)
    return f"✅ Cookie set: {name}={value[:30]}..."


@function_tool()
def session_set_header(name: str, value: str) -> str:
    """
    Set a default header for all requests in this session.
    
    Args:
        name: Header name
        value: Header value
    
    Returns:
        Confirmation
    """
    session = get_session()
    session.set_header(name, value)
    return f"✅ Header set: {name}: {value[:50]}"


@function_tool()
def session_clear() -> str:
    """
    Clear all session cookies and reset headers.
    
    Returns:
        Confirmation
    """
    global _session
    _session = HTTPSession()
    return "✅ Session cleared"
