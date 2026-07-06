from src.tools.long_tasks import _looks_like_foreground_probe, long_task_start


def _run_tool(tool, **kwargs):
    import asyncio

    return asyncio.run(tool.invoke(**kwargs))


def test_long_task_rejects_quick_foreground_probe():
    result = _run_tool(
        long_task_start,
        command="cd /tmp && grep -n -i htb strings.txt | head -20",
        task_id="quick_probe",
        wait_seconds=5,
    )

    assert "[FOREGROUND COMMAND REFUSED]" in result
    assert "ctf_command" in result


def test_foreground_probe_detector_allows_real_background_jobs():
    assert _looks_like_foreground_probe("cd /tmp && grep -n htb strings.txt")
    assert not _looks_like_foreground_probe("nmap -sV 10.10.10.10")
    assert not _looks_like_foreground_probe("python3 -m http.server 8000")
