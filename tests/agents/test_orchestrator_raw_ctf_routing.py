from src.agents.orchestrator_agent import _force_tcp_session_first, _is_raw_hostport_ctf_task


def test_raw_hostport_ctf_task_forces_tcp_session_first():
    task = (
        "Host target pulsing dot 154.57.164.65:31009. "
        "Challenge Scenario: restricted shell regex filter. Submit challenge Flag HTB{s0me_t3xt}."
    )

    assert _is_raw_hostport_ctf_task(task)
    routed = _force_tcp_session_first(task)

    assert "MANDATORY RAW TCP FIRST STEP" in routed
    assert "tcp_session_open(host='154.57.164.65', port=31009, session='ctf')" in routed
    assert "Do not write, save, or run a Python/socket probe script" in routed


def test_plain_web_task_does_not_force_tcp_session():
    task = "run nuclei on https://example.com"

    assert not _is_raw_hostport_ctf_task(task)
    assert _force_tcp_session_first(task) == task
