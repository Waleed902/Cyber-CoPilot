import asyncio
from types import SimpleNamespace


def test_msf_search_module_uses_cli_fallback_when_rpc_unavailable(monkeypatch):
    from src.sdk.cache import get_tool_cache
    import src.tools.metasploit_rpc as metasploit_rpc

    get_tool_cache().invalidate(tool_name="msf_search_module")
    monkeypatch.setattr(
        metasploit_rpc,
        "_get_msf_client",
        lambda: "Error: pymetasploit3 library is not installed.",
    )

    calls = []

    def fake_run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        return SimpleNamespace(stdout="Matching Modules\nauxiliary/scanner/http/http_version", stderr="")

    monkeypatch.setattr(metasploit_rpc.subprocess, "run", fake_run)

    result = asyncio.run(
        metasploit_rpc.msf_search_module.invoke(query="http version; sessions")
    )

    assert "used msfconsole CLI fallback" in result
    assert "auxiliary/scanner/http/http_version" in result
    assert calls == [
        ["msfconsole", "-q", "-x", "search http version sessions; exit"]
    ]


def test_blackhat_agent_has_raw_shell_fallback_tools():
    from src.agents.blackhat_agent import create_blackhat_agent

    agent = create_blackhat_agent(model="test-model")
    tool_names = {tool.name for tool in agent.tools}

    assert "interactive_bash" in tool_names
    assert "read_shell_screen" in tool_names
    assert "terminal_screenshot" in tool_names
