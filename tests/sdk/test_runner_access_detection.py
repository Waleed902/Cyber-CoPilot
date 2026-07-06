from src.sdk.runner import Runner


def test_access_detection_rejects_missing_shell_session():
    runner = object.__new__(Runner)

    assert runner._is_confirmed_access_result(
        "execute_in_shell",
        "Session not found: shell_1",
        True,
    ) is False


def test_access_detection_accepts_jupyter_terminal_handshake():
    runner = object.__new__(Runner)

    assert runner._is_confirmed_access_result(
        "jupyter_terminal_command",
        "Terminal: 1\nHandshake: HTTP/1.1 101 Switching Protocols\nuid=1000(analyst)",
        True,
    ) is True

