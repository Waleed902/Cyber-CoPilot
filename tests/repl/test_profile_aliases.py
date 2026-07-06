import json

import src.repl.profiles as profiles
import src.repl.hosts_manager as hosts_manager


def test_changed_htb_ip_reuses_hostname_profile_evidence(tmp_path, monkeypatch):
    targets_dir = tmp_path / "targets"
    old_dir = targets_dir / "10.129.81.1"
    new_dir = targets_dir / "10.129.212.66"
    old_dir.mkdir(parents=True)
    new_dir.mkdir(parents=True)

    (old_dir / "profile.json").write_text(
        json.dumps(
            {
                "target": "10.129.81.1",
                "target_type": "domain",
                "web_technologies": ["RedirectLocation[http://connected.htb/]"],
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "version": "Apache",
                        "state": "open",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (new_dir / "profile.json").write_text(
        json.dumps(
            {
                "target": "10.129.212.66",
                "target_type": "domain",
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "service": "ssh",
                        "version": "OpenSSH",
                        "state": "open",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    hosts_file = tmp_path / "hosts"
    hosts_file.write_text("10.129.212.66 connected.htb\n", encoding="utf-8")
    monkeypatch.setattr(hosts_manager, "HOSTS_FILE", hosts_file)

    pm = profiles.TargetProfileManager(base_dir=str(targets_dir))
    profile = pm.load_profile("10.129.212.66")

    assert profile.target == "10.129.212.66"
    assert "10.129.81.1" in profile.aliases
    assert "connected.htb" in profile.aliases
    assert "RedirectLocation[http://connected.htb/]" in profile.web_technologies
    assert {(p["port"], p["service"]) for p in profile.ports} == {(22, "ssh"), (80, "http")}
    assert pm.targets_equivalent("10.129.212.66", "10.129.81.1")
    assert pm.targets_equivalent("10.129.212.66", "connected.htb")


def test_register_aliases_merges_history_without_hosts_file(tmp_path):
    targets_dir = tmp_path / "targets"
    old_dir = targets_dir / "10.129.81.1"
    old_dir.mkdir(parents=True)

    (old_dir / "profile.json").write_text(
        json.dumps(
            {
                "target": "10.129.81.1",
                "target_type": "domain",
                "web_technologies": ["RedirectLocation[http://connected.htb/]"],
                "vulnerabilities": [
                    {
                        "name": "Confirmed command execution",
                        "severity": "critical",
                        "verified": True,
                    }
                ],
                "credentials": [
                    {
                        "username": "freepbxuser",
                        "password": "mZzDpAGKTmPJ",
                        "source": "/etc/freepbx.conf",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    pm = profiles.TargetProfileManager(base_dir=str(targets_dir))
    profile = pm.register_aliases("10.129.86.80", {"connected.htb"})

    assert "10.129.81.1" in profile.aliases
    assert "connected.htb" in profile.aliases
    assert profile.vulnerabilities[0]["name"] == "Confirmed command execution"
    assert profile.credentials[0]["username"] == "freepbxuser"
