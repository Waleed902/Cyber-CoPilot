import pytest

from src.sdk.tmux_session import TmuxSessionManager


class FakeTmuxSession(TmuxSessionManager):
    def __init__(self, session: str = "main", capture: str = "[DCPTN:0:/tmp] "):
        super().__init__(session=session)
        self.calls: list[list[str]] = []
        self.capture = capture

    def _tmux(self, args: list[str], timeout: int = 10) -> str:
        self.calls.append(args)
        if args[0] == "has-session":
            raise RuntimeError("session not found")
        if args[0] == "capture-pane":
            return self.capture
        return ""


def test_send_preserves_multiline_commands_line_by_line():
    manager = FakeTmuxSession()

    manager._send("python3 << 'PY'\nprint('ok')\nPY")

    assert manager.calls == [
        ["send-keys", "-t", "main", "-l", "python3 << 'PY'"],
        ["send-keys", "-t", "main", "Enter"],
        ["send-keys", "-t", "main", "-l", "print('ok')"],
        ["send-keys", "-t", "main", "Enter"],
        ["send-keys", "-t", "main", "-l", "PY"],
        ["send-keys", "-t", "main", "Enter"],
    ]


def test_initialize_starts_new_sessions_in_bash(monkeypatch):
    monkeypatch.setattr("src.sdk.tmux_session.time.sleep", lambda _seconds: None)
    TmuxSessionManager._initialized.clear()
    manager = FakeTmuxSession()

    manager.initialize()

    assert ["new-session", "-d", "-s", "main", "bash --noprofile --norc"] in manager.calls

