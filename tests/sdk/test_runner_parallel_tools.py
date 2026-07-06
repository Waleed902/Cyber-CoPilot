import asyncio
import time
from types import SimpleNamespace

import pytest

from src.sdk.core import Agent, FunctionTool
from src.sdk.runner import Runner


class _FakeCompletions:
    def __init__(self):
        self.calls = 0

    async def create(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            msg = SimpleNamespace(
                content=None,
                reasoning_content=None,
                tool_calls=[
                    SimpleNamespace(
                        id="call_a",
                        function=SimpleNamespace(name="slow_a", arguments="{}"),
                    ),
                    SimpleNamespace(
                        id="call_b",
                        function=SimpleNamespace(name="slow_b", arguments="{}"),
                    ),
                ],
                role="assistant",
            )
        else:
            msg = SimpleNamespace(
                content="done",
                reasoning_content=None,
                tool_calls=None,
                role="assistant",
            )
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


class _FakeKeyManager:
    def __init__(self):
        completions = _FakeCompletions()
        self._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))

    def get_async_client(self):
        return self._client

    def get_client(self):
        return self._client

    def get_model(self):
        return "fake-model"

    def get_current_provider(self):
        return "nvidia"

    async def wait_for_rate_limit_async(self, timeout=60.0):
        return True

    def record_success(self, tokens_used=0):
        return None


@pytest.mark.asyncio
async def test_runner_executes_multiple_tool_calls_concurrently(monkeypatch):
    marks = {}
    events = []

    class _FakeEventLog:
        def record(self, event_type, **kwargs):
            events.append((event_type, kwargs))
            return len(events)

    monkeypatch.setattr("src.sdk.event_log.get_event_log", lambda target="": _FakeEventLog())

    async def slow_a():
        marks["a_start"] = time.perf_counter()
        await asyncio.sleep(0.2)
        marks["a_end"] = time.perf_counter()
        return "a"

    async def slow_b():
        marks["b_start"] = time.perf_counter()
        await asyncio.sleep(0.2)
        marks["b_end"] = time.perf_counter()
        return "b"

    monkeypatch.setattr(Runner, "_save_conversations", lambda self: None)

    class _NoFindingExtractor:
        def extract_findings(self, tool_name, tool_output, context=None):
            return []

    monkeypatch.setattr("src.intelligence.evaluator.FindingExtractor", _NoFindingExtractor)
    monkeypatch.setattr(
        "src.sdk.context_hub.get_context_hub",
        lambda: SimpleNamespace(current_target=""),
    )

    runner = Runner.__new__(Runner)
    runner.key_manager = _FakeKeyManager()
    runner.conversations = {}
    runner._loaded_messages = {}

    agent = Agent(
        name="ParallelTest",
        instructions="Use tools.",
        tools=[
            FunctionTool("slow_a", "slow a", {"type": "object", "properties": {}, "required": []}, slow_a),
            FunctionTool("slow_b", "slow b", {"type": "object", "properties": {}, "required": []}, slow_b),
        ],
    )

    result = await runner.run(agent, "run both", max_iterations=3)

    assert result.output == "done"
    assert result.tool_calls_made == 2
    assert abs(marks["a_start"] - marks["b_start"]) < 0.05
    assert marks["b_start"] < marks["a_end"]
    assert marks["a_start"] < marks["b_end"]
    event_types = [event_type for event_type, _ in events]
    assert "user_message" in event_types
    assert "assistant_tool_calls" in event_types
    assert event_types.count("tool_started") == 2
    assert event_types.count("tool_finished") == 2
    assert "assistant_final" in event_types


@pytest.mark.asyncio
async def test_runner_keeps_ctf_command_batches_serial(monkeypatch):
    starts = []
    ends = []

    class _CtfCompletions:
        def __init__(self):
            self.calls = 0

        async def create(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                msg = SimpleNamespace(
                    content=None,
                    reasoning_content=None,
                    tool_calls=[
                        SimpleNamespace(
                            id="call_1",
                            function=SimpleNamespace(
                                name="ctf_command",
                                arguments='{"command": "first"}',
                            ),
                        ),
                        SimpleNamespace(
                            id="call_2",
                            function=SimpleNamespace(
                                name="ctf_command",
                                arguments='{"command": "second"}',
                            ),
                        ),
                    ],
                    role="assistant",
                )
            else:
                msg = SimpleNamespace(
                    content="done",
                    reasoning_content=None,
                    tool_calls=None,
                    role="assistant",
                )
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    class _CtfKeyManager(_FakeKeyManager):
        def __init__(self):
            completions = _CtfCompletions()
            self._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))

    class _FakeEventLog:
        def record(self, event_type, **kwargs):
            return 1

    monkeypatch.setattr("src.sdk.event_log.get_event_log", lambda target="": _FakeEventLog())
    monkeypatch.setattr(Runner, "_save_conversations", lambda self: None)

    class _NoFindingExtractor:
        def extract_findings(self, tool_name, tool_output, context=None):
            return []

    monkeypatch.setattr("src.intelligence.evaluator.FindingExtractor", _NoFindingExtractor)
    monkeypatch.setattr(
        "src.sdk.context_hub.get_context_hub",
        lambda: SimpleNamespace(current_target=""),
    )

    async def fake_ctf_command(command):
        starts.append((command, time.perf_counter()))
        await asyncio.sleep(0.12)
        ends.append((command, time.perf_counter()))
        return command

    runner = Runner.__new__(Runner)
    runner.key_manager = _CtfKeyManager()
    runner.conversations = {}
    runner._loaded_messages = {}

    agent = Agent(
        name="SerialShellTest",
        instructions="Use tools.",
        tools=[
            FunctionTool(
                "ctf_command",
                "shell",
                {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
                fake_ctf_command,
            ),
        ],
    )

    result = await runner.run(agent, "run both", max_iterations=3)

    assert result.output == "done"
    assert result.tool_calls_made == 2
    assert [name for name, _ in starts] == ["first", "second"]
    assert starts[1][1] >= ends[0][1]
