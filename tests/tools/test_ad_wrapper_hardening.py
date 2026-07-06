import asyncio
import subprocess

import pytest

from src.sdk.cache import get_tool_cache
from src.tools.argv import safe_split_options
from src.tools.ad_attacks import bloodhound_collector, ldapsearch_query
from src.tools.exploitation import crackmapexec


@pytest.fixture(autouse=True)
def disable_tool_cache_for_wrappers():
    cache = get_tool_cache()
    for tool_name in ("crackmapexec", "ldapsearch_query", "bloodhound_collector"):
        cache.set_ttl(tool_name, 0)


def run_tool(tool, **kwargs):
    return asyncio.run(tool.invoke(**kwargs))


def test_safe_split_rejects_shell_pipe():
    args, error = safe_split_options("--shares | tee out.txt")

    assert args == []
    assert "shell control token" in error


def test_crackmapexec_rejects_shell_fragment_before_running(monkeypatch):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(args[0], 0, stdout="ok", stderr="")

    monkeypatch.setattr("src.tools.exploitation.shutil.which", lambda name: "nxc" if name == "nxc" else None)
    monkeypatch.setattr("src.tools.exploitation.subprocess.run", fake_run)

    output = run_tool(
        crackmapexec,
        target="10.129.245.56",
        protocol="smb",
        options="--shares | tee ad_enumeration.txt",
    )

    assert "shell control token" in output
    assert called is False


def test_crackmapexec_prefers_netexec_and_preserves_quoted_options(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr("src.tools.exploitation.shutil.which", lambda name: "nxc" if name == "nxc" else None)
    monkeypatch.setattr("src.tools.exploitation.subprocess.run", fake_run)

    output = run_tool(
        crackmapexec,
        target="10.129.245.56",
        protocol="smb",
        options='-u administrator -d ping.htb --shares --local-auth --shares-filter "C$"',
    )

    assert output == "ok"
    assert captured["cmd"][:3] == ["nxc", "smb", "10.129.245.56"]
    assert captured["cmd"][-1] == "C$"


def test_ldapsearch_drops_bad_deref_and_normalizes_ldif_wrap(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="ldap-ok", stderr="")

    monkeypatch.setattr("src.tools.ad_attacks.subprocess.run", fake_run)

    output = run_tool(
        ldapsearch_query,
        target="10.129.245.56",
        base_dn="DC=ping,DC=htb",
        query="(&(objectClass=user)(servicePrincipalName=*))",
        options="-x -s sub -a -L -o ldif-wrap=no",
    )

    assert "Dropped ldapsearch '-a'" in output
    assert "-a" not in captured["cmd"]
    assert "ldif_wrap=no" in captured["cmd"]
    assert captured["cmd"][-3:-1] == ["-b", "DC=ping,DC=htb"]
    assert captured["cmd"][-1] == "(&(objectClass=user)(servicePrincipalName=*))"


def test_bloodhound_ip_target_uses_dc_hostname_and_nameserver(monkeypatch, tmp_path):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(cmd, 0, stdout="bh-ok", stderr="")

    monkeypatch.setattr("src.tools.ad_attacks.shutil.which", lambda name: "bloodhound-python")
    monkeypatch.setattr("src.tools.ad_attacks.subprocess.run", fake_run)

    output = run_tool(
        bloodhound_collector,
        target="10.129.245.56",
        username="administrator",
        password="",
        domain="ping.htb",
        output_dir=str(tmp_path),
    )

    assert "BloodHound Collection Complete" in output
    assert "-dc" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("-dc") + 1] == "dc1.ping.htb"
    assert captured["cmd"][captured["cmd"].index("-ns") + 1] == "10.129.245.56"
    assert captured["cwd"] == str(tmp_path)
