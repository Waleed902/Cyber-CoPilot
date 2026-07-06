import asyncio

from src.tools import devtools_pivot


def test_mcp_inspector_audit_extracts_endpoints_and_persists_profile(tmp_path, monkeypatch):
    profile_dir = tmp_path / "targets"

    def fake_active_target(explicit_target=""):
        return explicit_target or "10.129.103.125"

    def fake_http_request(url, method="GET", body=None, headers=None, timeout=10):
        if url.endswith("/"):
            return (
                200,
                {},
                '<title>MCPJam Inspector</title><script type="module" src="/assets/index.js"></script>',
            )
        if url.endswith("/api/mcp/servers"):
            return 200, {}, '{"success":true,"servers":[]}'
        if url.endswith("/assets/index.js"):
            return (
                200,
                {},
                'fetch("/api/mcp/connect"); fetch("/api/mcp/servers"); const x="127.0.0.1:8888"; // Jupyter',
            )
        return 404, {}, "missing"

    monkeypatch.setattr(devtools_pivot, "_active_target", fake_active_target)
    monkeypatch.setattr(devtools_pivot, "_http_request", fake_http_request)

    import src.repl.profiles as profiles

    profiles._profile_manager = profiles.TargetProfileManager(base_dir=str(profile_dir))

    result = asyncio.run(devtools_pivot.mcp_inspector_audit.invoke(base_url="http://devhub.htb:6274"))

    assert "Exposed MCP Inspector-style control plane detected" in result
    assert "/api/mcp/connect" in result
    assert "127.0.0.1:8888" in result

    profile = profiles.get_profile_manager().load_profile("10.129.103.125")
    assert any(d["name"].startswith("MCP Inspector") for d in profile.devtools)
    assert any(e["url"] == "/api/mcp/connect" for e in profile.api_endpoints)
    assert any("MCP Inspector to Jupyter" in p["name"] for p in profile.attack_paths)

