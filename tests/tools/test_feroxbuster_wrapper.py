import subprocess
from types import SimpleNamespace

import pytest

from src.tools import recon_active
from src.tools.recon_active import feroxbuster_scan


@pytest.mark.asyncio
async def test_feroxbuster_accepts_rate_limit_and_filter_status(monkeypatch):
    recon_active._ferox_scanned_urls.clear()
    captured = {}

    monkeypatch.setattr(recon_active.requests, "get", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("skip probe")))

    try:
        import src.tools.http_proxy as http_proxy

        monkeypatch.setattr(http_proxy, "resolve_vhost", lambda url: (url, ""))
    except Exception:
        pass

    def fake_run(cmd, capture_output, text, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return SimpleNamespace(stdout="no findings", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = await feroxbuster_scan.invoke(
        url="https://example.test/app/",
        threads=10,
        depth=2,
        rate_limit="5",
        filter_status="429",
        timeout="45",
    )

    cmd = captured["cmd"]
    assert "--rate-limit" in cmd
    assert cmd[cmd.index("--rate-limit") + 1] == "5"
    assert "--filter-status" in cmd
    assert cmd[cmd.index("--filter-status") + 1] == "429"
    assert captured["timeout"] == 45
    assert "feroxbuster Results" in result
