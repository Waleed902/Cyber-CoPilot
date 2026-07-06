from src.tools.exploitation import (
    _has_nuclei_templates,
    _nuclei_template_candidate_dirs,
    _resolve_templates,
    _sanitize_nuclei_options,
)


def test_nuclei_cves_alias_uses_http_cves_path():
    assert _resolve_templates("cves") == ["http/cves"]


def test_nuclei_web_alias_uses_current_http_template_root():
    assert _resolve_templates("web") == ["http"]
    assert _resolve_templates("http") == ["http"]


def test_nuclei_web_path_is_normalized_to_current_http_root():
    assert _resolve_templates("/usr/share/nuclei-templates/web") == ["http"]
    assert _resolve_templates("web,http/cves") == ["http", "http/cves"]


def test_nuclei_template_candidates_include_common_kali_and_v3_paths(monkeypatch):
    monkeypatch.setenv("HOME", "/home/kali")
    monkeypatch.setenv("NUCLEI_TEMPLATES", "/custom/nuclei-templates")

    candidates = _nuclei_template_candidate_dirs()

    assert "/custom/nuclei-templates" in candidates
    assert "/home/kali/nuclei-templates" in candidates
    assert "/home/kali/.local/nuclei-templates" in candidates
    assert "/home/kali/.local/nuclei/templates" in candidates
    assert "/usr/share/nuclei-templates" in candidates


def test_has_nuclei_templates_detects_yaml_files(tmp_path):
    template_dir = tmp_path / "http" / "exposures"
    template_dir.mkdir(parents=True)
    (template_dir / "example.yaml").write_text("id: example\ninfo:\n  name: example\n", encoding="utf-8")

    assert _has_nuclei_templates(str(tmp_path))


def test_nuclei_options_drop_unsupported_and_managed_flags():
    accepted, dropped = _sanitize_nuclei_options("--no-interactive -timeout 8 -severity low -rl 5")

    assert accepted == ["-timeout", "8"]
    assert "--no-interactive" in dropped
    assert "-severity" in dropped
    assert "low" in dropped
    assert "-rl" in dropped
    assert "5" in dropped
