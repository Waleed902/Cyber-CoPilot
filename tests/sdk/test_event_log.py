from src.sdk.event_log import EventLog


def test_event_log_persists_payload_and_task_output_with_lone_surrogates(tmp_path):
    log = EventLog(
        tmp_path / "events.sqlite",
        target="hsaco.in\udcff",
        session_id="session\udce2",
    )
    bad_output = "terminal output \udce2\udca1"

    log.record(
        "tool_result",
        agent="web\udcff",
        tool="csrf_analyzer",
        payload={"bad\udcff": bad_output},
    )
    event = log.recent_events(limit=1)[0]

    assert event["target"] == "hsaco.in\\udcff"
    assert "bad\\udcff" in event["payload"]
    assert event["payload"]["bad\\udcff"] == "terminal output \\udce2\\udca1"

    log.upsert_long_task(
        task_id="csrf\udcff",
        command=bad_output,
        tmux_session="scan",
        status="running",
        last_output=bad_output,
    )
    task = log.list_long_tasks(limit=1)[0]

    assert task["task_id"] == "csrf\\udcff"
    assert task["command"] == "terminal output \\udce2\\udca1"
    assert task["last_output"] == "terminal output \\udce2\\udca1"
