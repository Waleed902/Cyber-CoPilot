from pathlib import Path


def test_execute_bash_tool_exists_and_is_attached_to_all_agents():
    from src.sdk.agent import Agent
    from src.sdk.cache import ToolCache
    from src.tools.forensics import execute_bash

    agent = Agent(name="SmokeAgent", tools=[])
    tool_names = {getattr(tool, "name", getattr(tool, "__name__", "")) for tool in agent.tools}

    assert execute_bash.name == "execute_bash"
    assert "execute_bash" in tool_names
    assert "kwargs" not in execute_bash.params_json_schema["properties"]
    assert ToolCache.DEFAULT_TTLS["execute_bash"] == 0
    assert ToolCache.DEFAULT_TTLS["ctf_command"] == 0


def test_ctf_prompt_teaches_execute_bash_and_stall_breakers():
    text = Path("src/prompts/ctf.md").read_text(encoding="utf-8", errors="replace")

    assert "Use `execute_bash` or `ctf_command` as the shell" in text
    assert "First-action matrix" in text
    assert "Stall breakers" in text
