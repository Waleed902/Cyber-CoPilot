import asyncio

from src.tools import hypothesis_tools


def test_hypothesis_tools_persist_mode_queue_and_results(tmp_path, monkeypatch):
    profile_dir = tmp_path / "targets"

    import src.repl.profiles as profiles

    profiles._profile_manager = profiles.TargetProfileManager(base_dir=str(profile_dir))
    monkeypatch.setattr(hypothesis_tools, "_active_target", lambda explicit_target="": explicit_target or "10.129.103.125")

    mode_result = asyncio.run(hypothesis_tools.set_engagement_mode.invoke(mode="pentest"))
    assert "Coverage required before final conclusion: yes" in mode_result

    context = "MCP Inspector on port 6274 exposes /api/mcp/connect and Jupyter localhost:8888"
    result = asyncio.run(hypothesis_tools.generate_hypotheses.invoke(context=context))
    assert "Exposed MCP/Jupyter control-plane pivot" in result
    assert "mcp_inspector_audit" in result

    profile = profiles.get_profile_manager().load_profile("10.129.103.125")
    assert profile.engagement_mode == "pentest"
    assert profile.hypotheses
    assert profile.coverage_requirements

    hypothesis_id = profile.hypotheses[0]["id"]
    selected = asyncio.run(hypothesis_tools.select_hypothesis_tools.invoke(hypothesis_id=hypothesis_id))
    assert "jupyter_terminal_command" in selected

    updated = asyncio.run(
        hypothesis_tools.record_hypothesis_result.invoke(
            hypothesis_id=hypothesis_id,
            outcome="rejected",
            evidence="MCP endpoint required authentication",
        )
    )
    assert "REJECTED" in updated or "[rejected]" in updated
    assert "Checklist:" in updated

    profile = profiles.get_profile_manager().load_profile("10.129.103.125")
    assert profile.hypotheses[0]["status"] == "rejected"
