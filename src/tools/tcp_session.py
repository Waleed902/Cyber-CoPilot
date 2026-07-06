"""Persistent TCP line-session tools for interactive challenge services."""

from __future__ import annotations

import select
import socket
import time
from dataclasses import dataclass

from src.sdk.tool import function_tool


MAX_READ_BYTES = 200_000


@dataclass
class TCPSession:
    host: str
    port: int
    sock: socket.socket


_SESSIONS: dict[str, TCPSession] = {}


def _read_available(sock: socket.socket, timeout: float, max_bytes: int = MAX_READ_BYTES) -> str:
    chunks: list[bytes] = []
    deadline = time.time() + max(timeout, 0.05)
    total = 0
    while time.time() < deadline and total < max_bytes:
        wait = max(0.01, min(0.2, deadline - time.time()))
        readable, _, _ = select.select([sock], [], [], wait)
        if not readable:
            continue
        try:
            data = sock.recv(min(8192, max_bytes - total))
        except socket.timeout:
            continue
        if not data:
            break
        chunks.append(data)
        total += len(data)
        deadline = time.time() + min(max(timeout, 0.05), 0.25)
    text = b"".join(chunks).decode("utf-8", errors="replace")
    if total >= max_bytes:
        text += "\n...[tcp-session-read-truncated]"
    return text


def _get_session(session: str) -> TCPSession | None:
    return _SESSIONS.get((session or "default").strip() or "default")


@function_tool(name_override="tcp_session_open")
def tcp_session_open(host: str, port: int, session: str = "default", timeout: int = 5) -> str:
    """
    Open a persistent TCP connection to a line-oriented service and read its banner.

    Use this for CTF netcat-style services, restricted shells, and prompts where
    server-side state must survive across multiple payloads.

    Args:
        host: Hostname or IP address.
        port: TCP port.
        session: Local session name to reuse in tcp_session_send/read/close.
        timeout: Connection and initial read timeout in seconds.
    """
    name = (session or "default").strip() or "default"
    old = _SESSIONS.pop(name, None)
    if old:
        try:
            old.sock.close()
        except OSError:
            pass
    try:
        sock = socket.create_connection((host, int(port)), timeout=max(1, int(timeout or 5)))
        sock.setblocking(False)
    except OSError as exc:
        return f"[tcp_session_open] failed to connect to {host}:{port}: {exc}"
    _SESSIONS[name] = TCPSession(host=host, port=int(port), sock=sock)
    banner = _read_available(sock, timeout=min(max(float(timeout or 5), 0.2), 3.0))
    return (
        f"[tcp-session:{name}] connected to {host}:{port}\n"
        f"--- banner ---\n{banner if banner else '(no banner yet)'}"
    )


@function_tool(name_override="tcp_session_send")
def tcp_session_send(
    data: str,
    session: str = "default",
    append_newline: bool = True,
    read_timeout: float = 0.5,
) -> str:
    """
    Send text to a persistent TCP session and read the immediate response.

    Args:
        data: Text to send.
        session: Session name from tcp_session_open.
        append_newline: Append a newline after data, useful for shell prompts.
        read_timeout: Seconds to wait for response bytes after sending.
    """
    name = (session or "default").strip() or "default"
    state = _get_session(name)
    if not state:
        return f"[tcp_session_send] no active session named {name!r}. Run tcp_session_open first."
    payload = (data or "") + ("\n" if append_newline else "")
    try:
        state.sock.sendall(payload.encode("utf-8", errors="replace"))
    except OSError as exc:
        return f"[tcp-session:{name}] send failed: {exc}"
    response = _read_available(state.sock, timeout=max(float(read_timeout or 0.5), 0.05))
    return f"[tcp-session:{name}] sent {len(payload)} bytes\n--- response ---\n{response if response else '(no immediate response)'}"


@function_tool(name_override="tcp_session_send_binary")
def tcp_session_send_binary(
    hex_data: str,
    session: str = "default",
    append_newline: bool = True,
    read_timeout: float = 2.0,
) -> str:
    """
    Send raw binary bytes (encoded as a hex string) to a persistent TCP session.

    Use this instead of tcp_session_send when the payload contains non-printable
    bytes or binary data that must not be mangled by UTF-8 encoding.
    Typical use: crypto oracle challenges where the plaintext block contains
    arbitrary byte values (0x00–0xff).

    IMPORTANT — safe plaintext rules for crypto oracles:
    - Avoid bytes 0x00–0x1f and 0x7f–0xff if the server reads input with Python
      input() or readline() — those will cause UnicodeDecodeError or truncation.
    - Avoid 0x0a (\\n) and 0x0d (\\r) embedded in the payload; they terminate
      the server's input() call early, desyncing the session.
    - Safe range for input()-based servers: 0x20–0x7e (printable ASCII only).
    - When the server reads raw bytes (e.g. sys.stdin.buffer.read(16)), any
      byte value is safe but you must set append_newline=False.

    Args:
        hex_data:       Hex-encoded bytes to send, e.g. \"41424344\" for b\"ABCD\".
                        Must be an even-length string of hex digits (no spaces or 0x prefix).
        session:        Session name from tcp_session_open.
        append_newline: Append a 0x0a newline byte after the payload (default True).
                        Set False for servers that read a fixed number of bytes.
        read_timeout:   Seconds to wait for response bytes after sending.
    """
    name = (session or "default").strip() or "default"
    state = _get_session(name)
    if not state:
        return f"[tcp_session_send_binary] no active session named {name!r}. Run tcp_session_open first."
    # Validate and decode hex
    hex_clean = (hex_data or "").strip().replace(" ", "").lower()
    if not hex_clean:
        return f"[tcp-session:{name}] send_binary failed: hex_data is empty."
    if len(hex_clean) % 2 != 0:
        return f"[tcp-session:{name}] send_binary failed: hex_data has odd length ({len(hex_clean)} chars). Ensure it is a valid hex string."
    try:
        payload = bytes.fromhex(hex_clean)
    except ValueError as exc:
        return f"[tcp-session:{name}] send_binary failed: invalid hex_data — {exc}"
    if append_newline:
        payload += b"\n"
    try:
        state.sock.sendall(payload)
    except OSError as exc:
        return f"[tcp-session:{name}] send_binary failed: {exc}"
    response = _read_available(state.sock, timeout=max(float(read_timeout or 2.0), 0.05))
    return (
        f"[tcp-session:{name}] sent {len(payload)} bytes (binary)\n"
        f"--- response ---\n{response if response else '(no immediate response)'}"
    )


@function_tool(name_override="tcp_session_read")
def tcp_session_read(session: str = "default", read_timeout: float = 0.5) -> str:
    """
    Read currently available bytes from a persistent TCP session without sending.

    Args:
        session: Session name from tcp_session_open.
        read_timeout: Seconds to wait for response bytes.
    """
    name = (session or "default").strip() or "default"
    state = _get_session(name)
    if not state:
        return f"[tcp_session_read] no active session named {name!r}. Run tcp_session_open first."
    response = _read_available(state.sock, timeout=max(float(read_timeout or 0.5), 0.05))
    return f"[tcp-session:{name}] read\n--- response ---\n{response if response else '(no data available)'}"


@function_tool(name_override="tcp_session_close")
def tcp_session_close(session: str = "default") -> str:
    """
    Close a persistent TCP session.

    Args:
        session: Session name from tcp_session_open.
    """
    name = (session or "default").strip() or "default"
    state = _SESSIONS.pop(name, None)
    if not state:
        return f"[tcp_session_close] no active session named {name!r}."
    try:
        state.sock.close()
    except OSError:
        pass
    return f"[tcp-session:{name}] closed {state.host}:{state.port}"
