import asyncio
import socket
import threading

from src.tools.tcp_session import (
    tcp_session_close,
    tcp_session_open,
    tcp_session_send,
)


def _run(tool, **kwargs):
    return asyncio.run(tool.invoke(**kwargs))


def _start_stateful_server():
    ready = threading.Event()
    state = {"count": 0}

    def server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            state["port"] = srv.getsockname()[1]
            srv.listen(1)
            ready.set()
            conn, _addr = srv.accept()
            with conn:
                conn.sendall(b"banner> ")
                buffer = b""
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    buffer += data
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line == b"quit":
                            conn.sendall(b"bye\n")
                            return
                        state["count"] += 1
                        conn.sendall(f"#{state['count']}:{line.decode(errors='replace')}\n> ".encode())

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(2)
    return state["port"]


def test_tcp_session_preserves_server_state_across_sends():
    port = _start_stateful_server()

    opened = _run(tcp_session_open, host="127.0.0.1", port=port, session="unit", timeout=2)
    assert "connected" in opened
    assert "banner>" in opened

    first = _run(tcp_session_send, data="alpha", session="unit", read_timeout=0.5)
    second = _run(tcp_session_send, data="beta", session="unit", read_timeout=0.5)
    closed = _run(tcp_session_close, session="unit")

    assert "#1:alpha" in first
    assert "#2:beta" in second
    assert "closed" in closed
