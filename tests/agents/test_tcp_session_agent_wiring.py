from pathlib import Path


AGENT_FILES = [
    "src/agents/orchestrator_agent.py",
    "src/agents/ctf_agent.py",
    "src/agents/specialty_agents.py",
    "src/agents/recon_agent.py",
    "src/agents/redteam_agent.py",
    "src/agents/blackhat_agent.py",
    "src/agents/verifier_agent.py",
]


def test_stateful_tcp_tools_are_available_to_operational_agents():
    for rel_path in AGENT_FILES:
        text = Path(rel_path).read_text(encoding="utf-8", errors="replace")
        assert "tcp_session_open" in text, rel_path
        assert "tcp_session_send" in text, rel_path
        assert "tcp_session_read" in text, rel_path
        assert "tcp_session_close" in text, rel_path


def test_shared_prompt_teaches_persistent_service_state():
    text = Path("src/sdk/system_prompts.py").read_text(encoding="utf-8", errors="replace")
    assert "PERSISTENT SERVICE STATE" in text
    assert "RAW TCP SESSION FALLBACK" in text
    assert "LONG TASK DISCIPLINE" in text


def test_orchestrator_has_foreground_ctf_tools_for_local_analysis():
    text = Path("src/agents/orchestrator_agent.py").read_text(encoding="utf-8", errors="replace")
    assert "ctf_command" in text
    assert "read_tool_output" in text
    assert "LOCAL CTF / REVERSING FILE FAST PATH" in text
    assert "Do NOT use `long_task_start` for quick local inspection commands" in text
