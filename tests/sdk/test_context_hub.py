import sqlite3

from src.sdk.context_hub import ContextHub, _context_hub_var


def test_record_tool_persists_output_with_lone_surrogates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    token = _context_hub_var.set(None)
    try:
        hub = ContextHub()
        hub.set_target("hsaco.in")

        bad_output = "csrf_analyzer output \udce2\udca1 complete"
        hub.record_tool(
            "csrf_analyzer",
            "web_agent",
            {"url": "https://hsaco.in/\udcff", "sample": bad_output},
            bad_output,
            True,
        )

        assert hub.tool_history[-1]["result_summary"] == (
            "csrf_analyzer output \\udce2\\udca1 complete"
        )

        with sqlite3.connect(tmp_path / ".context.db") as conn:
            row = conn.execute(
                "SELECT args, result FROM tool_history WHERE tool = ?",
                ("csrf_analyzer",),
            ).fetchone()

        assert row is not None
        assert "\\udcff" in row[0]
        assert "\\udce2\\udca1" in row[1]
    finally:
        _context_hub_var.reset(token)
