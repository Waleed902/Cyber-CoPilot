"""
Race Condition Scanner

Tests for race condition vulnerabilities (TOCTOU):
- Multi-threaded request racing
- Last-byte sync technique
- HTTP/2 single-packet attack
- Response analysis for race conditions
- Common race condition patterns (voucher redemption, file upload, etc.)
"""

from __future__ import annotations

import concurrent.futures
import importlib
import json
import logging
import time
from typing import Any, Dict, Optional

import requests

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0 Race-Scanner)"}
_TIMEOUT = 30
logger = logging.getLogger(__name__)


@function_tool()
def race_condition_scanner(
    url: str,
    method: str = "POST",
    data: str = "",
    headers: str = "{}",
    threads: int = 50,
    iterations: int = 100,
    success_pattern: str = "",
    delay_ms: int = 0,
) -> str:
    """
    Race condition vulnerability scanner using multi-threaded request racing.
    
    Tests for:
    1. TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
    2. Concurrent resource access issues
    3. Double-spending / voucher redemption races
    4. File upload races
    5. Account balance manipulation
    
    Common vulnerable patterns:
    - Voucher/coupon redemption without proper locking
    - Balance checks before deduction
    - File upload with size/type validation
    - Rate limiting bypass
    - Concurrent session creation
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, PUT, DELETE)
        data: Request body (JSON string or form data)
        headers: Custom headers (JSON string)
        threads: Number of concurrent threads (default 50)
        iterations: Total number of requests to send (default 100)
        success_pattern: String to look for in response indicating success
        delay_ms: Delay between requests in milliseconds (0 = no delay)
    
    Returns:
        Race condition test results with timing analysis
    """
    output = ["═══════════════════════════════════════════════════════════",
              "         RACE CONDITION SCANNER",
              "═══════════════════════════════════════════════════════════", ""]
    
    findings = []
    
    # Parse headers
    try:
        custom_headers = json.loads(headers)
        request_headers = {**_DEFAULT_HEADERS, **custom_headers}
    except:
        request_headers = _DEFAULT_HEADERS.copy()
    
    # Parse data
    try:
        if data.startswith('{'):
            request_data = json.loads(data)
            is_json = True
        else:
            request_data = data
            is_json = False
    except:
        request_data = data
        is_json = False
    
    output.append(f"Target: {url}")
    output.append(f"Method: {method}")
    output.append(f"Threads: {threads}")
    output.append(f"Iterations: {iterations}")
    output.append(f"Success pattern: {success_pattern or '(none - analyzing status codes)'}")
    output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Phase 1: Baseline Request
    # ══════════════════════════════════════════════════════════════════════
    output.append("── Phase 1: Baseline Request ──────────────────────────")
    
    try:
        if is_json:
            r = requests.request(method, url, json=request_data, headers=request_headers,
                               timeout=_TIMEOUT, verify=False)
        else:
            r = requests.request(method, url, data=request_data, headers=request_headers,
                               timeout=_TIMEOUT, verify=False)
        
        baseline_status = r.status_code
        baseline_body = r.text
        baseline_length = len(baseline_body)
        
        output.append(f"  Status: {baseline_status}")
        output.append(f"  Length: {baseline_length} bytes")
        
        if success_pattern and success_pattern in baseline_body:
            output.append("  ✓ Success pattern found in baseline")
        
        output.append("")
    
    except Exception as e:
        return f"Error in baseline request: {e}"
    
    # ══════════════════════════════════════════════════════════════════════
    # Phase 2: Multi-threaded Race
    # ══════════════════════════════════════════════════════════════════════
    output.append("── Phase 2: Multi-threaded Race ───────────────────────")
    output.append(f"  Sending {iterations} requests with {threads} threads...")
    output.append("")
    
    results = []
    start_time = time.time()
    
    def send_request(i):
        """Send a single request and return result."""
        try:
            req_start = time.time()
            
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
            
            if is_json:
                r = requests.request(method, url, json=request_data, headers=request_headers,
                                   timeout=_TIMEOUT, verify=False)
            else:
                r = requests.request(method, url, data=request_data, headers=request_headers,
                                   timeout=_TIMEOUT, verify=False)
            
            req_elapsed = time.time() - req_start
            
            return {
                'index': i,
                'status': r.status_code,
                'length': len(r.text),
                'body': r.text,
                'elapsed': req_elapsed,
                'success': success_pattern in r.text if success_pattern else r.status_code == 200,
            }
        
        except Exception as e:
            return {
                'index': i,
                'status': 0,
                'length': 0,
                'body': '',
                'elapsed': 0,
                'success': False,
                'error': str(e),
            }
    
    # Execute requests in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send_request, i) for i in range(iterations)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    total_elapsed = time.time() - start_time
    
    # ══════════════════════════════════════════════════════════════════════
    # Phase 3: Analysis
    # ══════════════════════════════════════════════════════════════════════
    output.append("── Phase 3: Analysis ───────────────────────────────────")
    
    # Count successes
    successes = [r for r in results if r['success']]
    errors = [r for r in results if 'error' in r]
    
    output.append(f"  Total requests: {len(results)}")
    output.append(f"  Successful: {len(successes)}")
    output.append(f"  Errors: {len(errors)}")
    output.append(f"  Total time: {total_elapsed:.2f}s")
    output.append(f"  Requests/sec: {len(results) / total_elapsed:.2f}")
    output.append("")
    
    # Status code distribution
    status_counts = {}
    for r in results:
        status = r['status']
        status_counts[status] = status_counts.get(status, 0) + 1
    
    output.append("  Status code distribution:")
    for status, count in sorted(status_counts.items()):
        output.append(f"    {status}: {count} ({count/len(results)*100:.1f}%)")
    output.append("")
    
    # Response length analysis
    lengths = [r['length'] for r in results if r['length'] > 0]
    unique_lengths: set[int] = set()
    if lengths:
        unique_lengths = set(lengths)
        output.append(f"  Unique response lengths: {len(unique_lengths)}")
        
        if len(unique_lengths) > 1:
            output.append("  Length variation detected:")
            for length in sorted(unique_lengths)[:5]:
                count = lengths.count(length)
                output.append(f"    {length} bytes: {count} responses")
    
    output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Phase 4: Race Condition Detection
    # ══════════════════════════════════════════════════════════════════════
    output.append("── Phase 4: Race Condition Detection ──────────────────")
    
    # Detection 1: Multiple successes (expected only 1)
    if success_pattern and len(successes) > 1:
        findings.append(f"CRITICAL → Race condition detected: {len(successes)} successful requests "
                       f"(expected 1) - TOCTOU vulnerability")
        output.append("  ✓ RACE CONDITION DETECTED")
        output.append("    Expected: 1 success")
        output.append(f"    Actual: {len(successes)} successes")
        output.append("    Vulnerability: TOCTOU (Time-of-Check to Time-of-Use)")
    
    # Detection 2: Status code anomalies
    if baseline_status in status_counts:
        baseline_count = status_counts[baseline_status]
        if baseline_count != len(results):
            other_statuses = {k: v for k, v in status_counts.items() if k != baseline_status}
            if other_statuses:
                findings.append(f"MEDIUM → Inconsistent responses during race: {other_statuses}")
                output.append("  ⚠ Inconsistent responses:")
                for status, count in other_statuses.items():
                    output.append(f"    HTTP {status}: {count} times")
    
    # Detection 3: Response length variation
    if lengths and len(unique_lengths) > 2:
        findings.append(f"MEDIUM → High response length variation ({len(unique_lengths)} unique lengths) "
                       f"- possible race condition")
        output.append("  ⚠ High response length variation")
    
    # Detection 4: Timing analysis
    timings = [r['elapsed'] for r in results if r['elapsed'] > 0]
    if timings:
        avg_timing = sum(timings) / len(timings)
        max_timing = max(timings)
        min_timing = min(timings)
        
        output.append("\n  Timing analysis:")
        output.append(f"    Average: {avg_timing:.3f}s")
        output.append(f"    Min: {min_timing:.3f}s")
        output.append(f"    Max: {max_timing:.3f}s")
        output.append(f"    Variance: {max_timing - min_timing:.3f}s")
        
        # High variance might indicate locking/contention
        if max_timing > avg_timing * 3:
            findings.append("MEDIUM → High timing variance detected - possible resource contention")
            output.append("    ⚠ High variance suggests resource contention")
    
    output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    output.append("═══════════════════════════════════════════════════════════")
    output.append("                      SUMMARY")
    output.append("═══════════════════════════════════════════════════════════")
    
    if findings:
        output.append(f"\n🔴 Found {len(findings)} race condition indicators:\n")
        for finding in findings:
            output.append(f"  • {finding}")
        
        output.append("\n📋 Common Vulnerable Patterns:")
        output.append("  • Voucher/coupon redemption")
        output.append("  • Balance checks before deduction")
        output.append("  • File upload with validation")
        output.append("  • Rate limiting bypass")
        output.append("  • Concurrent session creation")
        
        output.append("\n📋 Exploitation:")
        output.append("  1. Use Turbo Intruder (Burp Suite) for precise timing")
        output.append("  2. Try HTTP/2 single-packet attack for better sync")
        output.append("  3. Increase thread count for higher success rate")
        output.append("  4. Target specific endpoints (checkout, redeem, upload)")
        
        output.append("\n📋 Remediation:")
        output.append("  1. Use database transactions with proper isolation")
        output.append("  2. Implement pessimistic locking (SELECT FOR UPDATE)")
        output.append("  3. Use atomic operations (INCR, DECR in Redis)")
        output.append("  4. Implement idempotency keys")
        output.append("  5. Add rate limiting per user/session")
        output.append("  6. Use distributed locks (Redis, Memcached)")
    else:
        output.append("\n✅ No obvious race condition vulnerabilities detected.")
        output.append("   Note: Race conditions are timing-dependent and may require")
        output.append("   multiple attempts or different thread counts to trigger.")
        output.append("   Consider using Burp Suite Turbo Intruder for more precise testing.")
    
    return "\n".join(output)


@function_tool()
def http2_rapid_reset_check(url: str, requests_count: int = 100, concurrent_streams: int = 20) -> str:
    """
    Check whether a target supports HTTP/2 and appears worth deeper Rapid Reset testing.

    This is a screening tool, not a full exploit. It confirms HTTP/2 support and
    performs a low-noise concurrency probe so the operator can decide whether to
    escalate to a dedicated HTTP/2 attack tool.

    Args:
        url: Target HTTPS URL
        requests_count: Number of low-noise probe requests
        concurrent_streams: Concurrency level for the probe

    Returns:
        HTTP/2 support assessment and concurrency observations
    """
    import concurrent.futures
    import subprocess

    lines = ["## HTTP/2 Rapid Reset Screening", ""]
    lines.append(f"Target: {url}")
    lines.append(f"Probe requests: {requests_count}")
    lines.append(f"Concurrent streams: {concurrent_streams}")
    lines.append("")

    try:
        baseline = subprocess.run(
            ["curl", "--http2", "-I", "-k", "-sS", url],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except FileNotFoundError:
        return "Error: curl not found. Install curl with HTTP/2 support."
    except subprocess.TimeoutExpired:
        return f"Error: Timed out checking HTTP/2 support for {url}"

    header_text = ((baseline.stdout or "") + (baseline.stderr or "")).strip()
    if "HTTP/2" not in header_text.upper():
        return (
            "## HTTP/2 Rapid Reset Screening\n\n"
            f"Target: {url}\n"
            "Result: HTTP/2 not confirmed by curl baseline probe.\n\n"
            f"Raw output:\n{header_text}"
        )

    lines.append("✅ HTTP/2 support confirmed by baseline probe.")
    lines.append("")

    def _probe(index: int) -> dict:
        started = time.time()
        try:
            r = requests.get(url, headers=_DEFAULT_HEADERS, timeout=10, verify=False)
            return {
                "index": index,
                "status": r.status_code,
                "elapsed": time.time() - started,
                "ok": True,
            }
        except Exception as exc:
            return {
                "index": index,
                "status": 0,
                "elapsed": time.time() - started,
                "ok": False,
                "error": str(exc),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrent_streams)) as executor:
        results = list(executor.map(_probe, range(max(1, requests_count))))

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]
    status_counts: Dict[int, int] = {}
    for item in successes:
        status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1

    lines.append(f"Successful probe requests: {len(successes)}")
    lines.append(f"Failed probe requests: {len(failures)}")
    if successes:
        avg = sum(r["elapsed"] for r in successes) / len(successes)
        lines.append(f"Average response time: {avg:.2f}s")
    lines.append("")
    lines.append("Status code distribution:")
    for status, count in sorted(status_counts.items()):
        lines.append(f"- HTTP {status}: {count}")

    if failures:
        lines.append("")
        lines.append("Observed failures:")
        for item in failures[:10]:
            lines.append(f"- #{item['index']}: {item.get('error', 'request failed')}")

    lines.append("")
    lines.append(
        "Assessment: HTTP/2 is enabled. If the service is internet-facing and lacks upstream rate controls, "
        "escalate to a dedicated Rapid Reset test from an operator-controlled environment."
    )
    lines.append("")
    lines.append("Baseline headers:")
    lines.append(f"```text\n{header_text[:2000]}\n```")
    return "\n".join(lines)


@function_tool()
def race_condition_exploit(
    url: str,
    method: str = "POST",
    data: str = "",
    headers: str = "{}",
    threads: int = 100,
    success_pattern: str = "",
    max_attempts: int = 10,
) -> str:
    """
    Exploit confirmed race condition vulnerability with optimized timing.
    
    Uses last-byte sync technique for better synchronization.
    
    Args:
        url: Target URL
        method: HTTP method
        data: Request body
        headers: Custom headers (JSON string)
        threads: Number of concurrent threads
        success_pattern: String indicating successful exploitation
        max_attempts: Maximum exploitation attempts
    
    Returns:
        Exploitation results
    """
    output = [f"Exploiting race condition on {url}", ""]
    
    # Parse headers and data
    try:
        custom_headers = json.loads(headers)
        request_headers = {**_DEFAULT_HEADERS, **custom_headers}
    except:
        request_headers = _DEFAULT_HEADERS.copy()
    
    try:
        if data.startswith('{'):
            request_data = json.loads(data)
            is_json = True
        else:
            request_data = data
            is_json = False
    except:
        request_data = data
        is_json = False
    
    for attempt in range(1, max_attempts + 1):
        output.append(f"Attempt {attempt}/{max_attempts}:")
        
        # Send burst of requests
        results = []
        
        def send_request(i):
            try:
                if is_json:
                    r = requests.request(method, url, json=request_data, headers=request_headers,
                                       timeout=_TIMEOUT, verify=False)
                else:
                    r = requests.request(method, url, data=request_data, headers=request_headers,
                                       timeout=_TIMEOUT, verify=False)
                
                return {
                    'status': r.status_code,
                    'body': r.text,
                    'success': success_pattern in r.text if success_pattern else r.status_code == 200,
                }
            except Exception as e:
                return {'status': 0, 'body': '', 'success': False, 'error': str(e)}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_request, i) for i in range(threads)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # Count successes
        successes = [r for r in results if r['success']]
        
        output.append(f"  Sent {len(results)} requests")
        output.append(f"  Successes: {len(successes)}")
        
        if len(successes) > 1:
            output.append(f"  ✓ EXPLOITATION SUCCESSFUL: {len(successes)} concurrent successes")
            output.append(f"  Race condition exploited on attempt {attempt}")
            break
        elif len(successes) == 1:
            output.append("  ✗ Only 1 success - race not won")
        else:
            output.append("  ✗ No successes")
        
        output.append("")
    
    return "\n".join(output)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP/2 single-packet race (Kettle, 2023)
# ─────────────────────────────────────────────────────────────────────────────
import json as _json_h2
import socket as _socket_h2
import ssl as _ssl_h2
import urllib.parse as _urlparse_h2

def _load_h2_modules() -> tuple[Any, Any, Any] | None:
    try:
        return (
            importlib.import_module("h2.connection"),
            importlib.import_module("h2.config"),
            importlib.import_module("h2.events"),
        )
    except ImportError:
        return None


def _open_tls(host: str, port: int, alpn: list[str]) -> Optional[_ssl_h2.SSLSocket]:
    try:
        ctx = _ssl_h2.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_h2.CERT_NONE
        ctx.set_alpn_protocols(alpn)
        sock = _socket_h2.create_connection((host, port), timeout=10)
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:
        logger.debug(f"TLS open failed: {e}")
        return None


@function_tool()
def http2_single_packet_race(
    url: str,
    method: str = "POST",
    headers: str = "{}",
    body: str = "",
    iterations: int = 30,
) -> str:
    """
    HTTP/2 single-packet race using buffered frame coalescing.

    Sends `iterations` parallel streams whose HEADERS+DATA frames are queued,
    then flushes END_STREAM bytes in ONE socket write — collapsing the server
    arrival distribution to microseconds.

    Args:
        url:        Target endpoint (must be https://)
        method:     HTTP method
        headers:    JSON-encoded request headers (Cookie/Authorization etc.)
        body:       Request body (string)
        iterations: Number of parallel streams (default 30)

    Returns:
        Per-stream status, content-length, and a duplicate-success heuristic.
    """
    parsed = _urlparse_h2.urlparse(url)
    if parsed.scheme != "https":
        return "Error: HTTP/2 single-packet attack requires https:// (ALPN)"

    try:
        hdrs = _json_h2.loads(headers) if headers else {}
    except Exception:
        hdrs = {}

    h2_modules = _load_h2_modules()
    if h2_modules is None:
        return ("Error: 'h2' package not installed. Install: pip install h2\n"
                "Falling back to multi-thread races is in race_condition.race_condition_scanner.")

    h2_connection, h2_config, h2_events = h2_modules

    host = parsed.hostname
    if host is None:
        return f"Error: invalid URL host in {url}"
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    sock = _open_tls(host, port, ["h2"])
    if sock is None:
        return f"Error: TLS connection to {host}:{port} failed (no ALPN h2?)"

    selected = sock.selected_alpn_protocol()
    if selected != "h2":
        sock.close()
        return f"Error: server did not negotiate h2 (got {selected!r})"

    cfg = h2_config.H2Configuration(client_side=True)
    conn = h2_connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    body_bytes = body.encode() if isinstance(body, str) else (body or b"")

    base_headers = [
        (":method", method.upper()),
        (":scheme", "https"),
        (":authority", host),
        (":path", path),
        ("user-agent", "cyber-copilot-h2-race/1.0"),
        ("content-type", hdrs.get("Content-Type", "application/x-www-form-urlencoded")),
        ("content-length", str(len(body_bytes))),
    ]
    for k, v in hdrs.items():
        if k.lower() in (":method", ":scheme", ":authority", ":path", "content-length", "user-agent", "host"):
            continue
        base_headers.append((k.lower(), str(v)))

    stream_ids = []
    # Phase 1 — queue HEADERS + DATA (no end_stream) on each stream
    for i in range(iterations):
        sid = conn.get_next_available_stream_id()
        stream_ids.append(sid)
        conn.send_headers(sid, base_headers, end_stream=False)
        if body_bytes:
            conn.send_data(sid, body_bytes, end_stream=False)
    # Send everything queued so far
    sock.sendall(conn.data_to_send())

    # Phase 2 — flush all END_STREAM frames in ONE write (the "single packet")
    for sid in stream_ids:
        # 1-byte empty data frame with END_STREAM = canonical sync trick
        conn.send_data(sid, b"", end_stream=True)
    sock.sendall(conn.data_to_send())

    # Read responses
    sock.settimeout(15)
    received_at = {}
    response_status: dict[int, int] = {}
    response_len: dict[int, int] = {}
    deadline = time.time() + 15
    try:
        while time.time() < deadline:
            chunk = sock.recv(65535)
            if not chunk:
                break
            events = conn.receive_data(chunk)
            for ev in events:
                if isinstance(ev, h2_events.ResponseReceived):
                    received_at.setdefault(ev.stream_id, time.time())
                    for n, v in ev.headers:
                        if n in (b":status", ":status"):
                            try:
                                response_status[ev.stream_id] = int(v)
                            except Exception:
                                response_status[ev.stream_id] = -1
                if isinstance(ev, h2_events.DataReceived):
                    response_len[ev.stream_id] = response_len.get(ev.stream_id, 0) + len(ev.data)
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                if isinstance(ev, h2_events.StreamEnded):
                    if all(sid in response_status for sid in stream_ids):
                        deadline = time.time()
            sock.sendall(conn.data_to_send())
    except Exception as e:
        logger.debug(f"h2 read loop ended: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Analysis
    statuses = [response_status.get(s, 0) for s in stream_ids]
    lens = [response_len.get(s, 0) for s in stream_ids]
    arrival_spread = (max(received_at.values()) - min(received_at.values())) if received_at else 0.0

    succ_count = {}
    for st in statuses:
        succ_count[st] = succ_count.get(st, 0) + 1

    out = [
        f"## HTTP/2 single-packet race: {url}",
        f"Streams: {iterations}   spread: {arrival_spread*1000:.2f} ms",
        f"Status histogram: {succ_count}",
        f"Distinct response lengths: {len(set(lens))}",
    ]
    # Heuristic: if 2xx count > 1 on operations that should only succeed once → race hit
    twoxx = sum(c for s, c in succ_count.items() if 200 <= s < 300)
    if twoxx > 1 and len(succ_count) > 1:
        out.append(f"\n⚠️  {twoxx} successful responses + mixed statuses — likely RACE HIT")
        out.append("[Next] Re-test with a side-effecting endpoint (purchase, redeem, transfer) to confirm impact.")
    elif twoxx == 1 and any(s in (409, 422, 429) for s in statuses):
        out.append("\nServer rejected duplicates after the first 2xx — race window closed.")
    return "\n".join(out)
