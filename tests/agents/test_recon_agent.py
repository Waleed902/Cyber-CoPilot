from src.agents.recon_agent import create_recon_agent


def test_recon_agent_constructs_with_wordpress_tools():
    agent = create_recon_agent(model="test-model")
    tool_names = {tool.name for tool in agent.tools}

    assert agent.name == "ReconAgent"
    assert "wpscan" in tool_names
    assert "cmseek_scan" in tool_names
    assert "wpseku_scan" in tool_names
    assert "wpprobe_scan" in tool_names
