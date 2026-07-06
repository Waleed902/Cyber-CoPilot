from src.sdk.loop_detector import SmartLoopDetector


def test_connection_drop_detector_ignores_different_unproven_ports():
    detector = SmartLoopDetector()

    detector.record_call(
        "curl_request",
        {"url": "http://devhub.htb:6274/"},
        result_snippet="HTTP/1.1 200 OK",
    )

    for port in (8888, 3000, 5000):
        pattern = detector.record_call(
            "curl_request",
            {"url": f"http://10.129.103.125:{port}/"},
            result_snippet="No response received",
        )
        assert pattern is None

    should_stop, reason = detector.should_terminate(9, 120)
    assert should_stop is False
    assert "PROBABLE IP BAN" not in reason


def test_connection_drop_detector_flags_same_previously_working_endpoint():
    detector = SmartLoopDetector()

    detector.record_call(
        "curl_request",
        {"url": "http://devhub.htb:6274/"},
        result_snippet="HTTP/1.1 200 OK",
    )

    pattern = None
    for _ in range(3):
        pattern = detector.record_call(
            "curl_request",
            {"url": "http://devhub.htb:6274/"},
            result_snippet="No response received",
        )

    assert pattern is not None
    assert pattern.pattern_type == "connection_drop_ip_ban"

