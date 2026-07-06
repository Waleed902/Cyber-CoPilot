from src.sdk.hypothesis_engine import (
    generate_hypotheses_from_context,
    get_policy,
    render_hypotheses,
)


def test_mcp_jupyter_hypothesis_ranks_before_generic_coverage():
    context = """
    nmap found ports 22, 80, 6274.
    Landing page says MCPJam Inspector and JS references /api/mcp/connect.
    Bundle mentions Jupyter at 127.0.0.1:8888.
    """

    hypotheses = generate_hypotheses_from_context(context, mode="pentest")

    assert hypotheses
    assert hypotheses[0].id.startswith("exposed_mcp_jupyter_pivot")
    assert "mcp_inspector_audit" in hypotheses[0].next_tools
    assert "jupyter_terminal_command" in hypotheses[0].next_tools


def test_pentest_policy_requires_coverage_after_hypothesis():
    policy = get_policy("pentest")
    rendered = render_hypotheses([], mode="pentest")

    assert policy.coverage_required is True
    assert "Coverage checklist" in rendered
    assert "High-confidence hypotheses tested" in rendered


def test_fast_policy_does_not_require_full_coverage():
    policy = get_policy("fast")

    assert policy.coverage_required is False
    assert policy.hypothesis_budget < get_policy("pentest").hypothesis_budget


def test_service_foothold_hypothesis_generation():
    context = "Nmap scan results: Port 22/tcp is open (ssh), Port 445/tcp is open (microsoft-ds)."
    hypotheses = generate_hypotheses_from_context(context, mode="pentest")
    
    # We should have the service foothold hypothesis
    foothold_hyps = [h for h in hypotheses if h.id.startswith("service_foothold_weak_creds")]
    assert foothold_hyps
    assert "hydra_bruteforce" in foothold_hyps[0].next_tools


def test_local_privesc_hypothesis_generation():
    context = """
    Successfully established a reverse shell.
    Session ID: shell_4444
    whoami: www-data
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    """
    hypotheses = generate_hypotheses_from_context(context, mode="pentest")
    
    # We should have all local privesc hypotheses
    ids = {h.id for h in hypotheses}
    assert any(i.startswith("local_privesc_sudo") for i in ids)
    assert any(i.startswith("local_privesc_suid") for i in ids)
    assert any(i.startswith("local_privesc_linpeas") for i in ids)
    assert any(i.startswith("local_privesc_writable") for i in ids)
    assert any(i.startswith("ctf_flag_extraction") for i in ids)

