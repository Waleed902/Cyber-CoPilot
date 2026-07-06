import subprocess
from types import SimpleNamespace

import pytest

from src.tools.http_proxy import http_fuzz


@pytest.mark.asyncio
async def test_http_fuzz_infers_first_query_parameter(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout="200,100", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = await http_fuzz.invoke(
        url="https://example.test/item?id=123&view=full",
        custom_values="999",
    )

    assert "Inferred parameter: id" in result
    assert "Parameter: id" in result
    assert "id=999" in captured["cmd"][-1]
    assert "view=full" in captured["cmd"][-1]


@pytest.mark.asyncio
async def test_http_fuzz_reports_missing_parameter_without_query():
    result = await http_fuzz.invoke(url="https://example.test/item")

    assert "needs a parameter" in result
