import pytest
from src.sdk.core import FunctionTool, function_tool


@pytest.mark.anyio
async def test_function_tool_argument_sanitization():
    # Define a simple function that expects 'url'
    def my_dummy_tool(url: str, max_chars: int = 1000):
        return f"Fetched {url} with limit {max_chars}"

    tool = FunctionTool(
        name="my_dummy_tool",
        description="A dummy tool",
        params_json_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "max_chars": {"type": "integer"}
            },
            "required": ["url"]
        },
        invoke=my_dummy_tool
    )

    # 1. Test trimming of keys and filtering of unexpected parameters (like ' verbatim')
    res = await tool.invoke(**{"url": "http://example.com", " verbatim": True, "max_chars": 500})
    assert res == "Fetched http://example.com with limit 500"

    # 2. Test trimming of parameter keys
    res2 = await tool.invoke(**{" url ": "http://example.com"})
    assert res2 == "Fetched http://example.com with limit 1000"


@pytest.mark.anyio
async def test_function_tool_decorator_filters_arguments():
    @function_tool()
    def decorated_fetch(url: str, max_chars: int = 1000):
        return f"Fetched {url} with limit {max_chars}"

    result = await decorated_fetch.invoke(
        **{" url ": "http://example.com", " verbatim": True, "max_chars": 500}
    )

    assert result == "Fetched http://example.com with limit 500"


@pytest.mark.anyio
async def test_reasoning_effort_injection_and_fallback(monkeypatch):
    from src.sdk.key_manager import APIKeyManager, APIKeyConfig
    from unittest.mock import MagicMock, AsyncMock

    # Create dummy config
    config = APIKeyConfig(
        name="test_nvidia",
        provider="nvidia",
        api_key="nv-test-key",
        base_url="https://integrate.api.nvidia.com/v1",
        model="stepfun-ai/step-3.5-flash",
        priority=0
    )

    manager = APIKeyManager()
    manager.keys["test_nvidia"] = config

    # Mock OpenAI client classes
    mock_client = MagicMock()
    mock_async_client = MagicMock()
    
    # Mock completions create
    mock_sync_create = MagicMock(return_value="sync_success")
    mock_async_create = AsyncMock(return_value="async_success")
    
    mock_client.chat.completions.create = mock_sync_create
    mock_async_client.chat.completions.create = mock_async_create

    # Wrap the mocked clients
    manager._wrap_completions_with_reasoning_effort(mock_client, is_async=False)
    manager._wrap_completions_with_reasoning_effort(mock_async_client, is_async=True)

    # Test 1: Sync creation with stepfun-ai model injection (default to high)
    res_sync = mock_client.chat.completions.create(model="stepfun-ai/step-3.5-flash", messages=[])
    assert res_sync == "sync_success"
    mock_sync_create.assert_called_once()
    assert mock_sync_create.call_args[1]["reasoning_effort"] == "high"

    # Test 2: Async creation with stepfun-ai reasoning model injection (xhigh)
    res_async = await mock_async_client.chat.completions.create(model="stepfun-ai/step-3.7-flash", messages=[])
    assert res_async == "async_success"
    mock_async_create.assert_called_once()
    assert mock_async_create.call_args[1]["reasoning_effort"] == "xhigh"

    # Reset mocks to test fallback logic
    mock_sync_create.reset_mock()
    mock_async_create.reset_mock()

    # Mock a failure on the first call (when reasoning_effort is present), then success
    call_count = {"sync": 0, "async": 0}
    
    def failing_sync_create(*args, **kwargs):
        call_count["sync"] += 1
        if "reasoning_effort" in kwargs:
            raise ValueError("reasoning_effort not supported")
        return "fallback_sync_success"
        
    async def failing_async_create(*args, **kwargs):
        call_count["async"] += 1
        if "reasoning_effort" in kwargs:
            raise ValueError("reasoning_effort not supported")
        return "fallback_async_success"

    # Re-apply wrapper with failing mock function implementations
    mock_client.chat.completions.create = failing_sync_create
    mock_async_client.chat.completions.create = failing_async_create
    manager._wrap_completions_with_reasoning_effort(mock_client, is_async=False)
    manager._wrap_completions_with_reasoning_effort(mock_async_client, is_async=True)

    # Execute sync call and assert it falls back
    res_sync_fallback = mock_client.chat.completions.create(model="stepfun-ai/step-3.5-flash", messages=[])
    assert res_sync_fallback == "fallback_sync_success"
    assert call_count["sync"] == 2  # First with reasoning_effort (fails), second without it (succeeds)

    # Execute async call and assert it falls back
    res_async_fallback = await mock_async_client.chat.completions.create(model="stepfun-ai/step-3.7-flash", messages=[])
    assert res_async_fallback == "fallback_async_success"
    assert call_count["async"] == 2  # First with reasoning_effort (fails), second without it (succeeds)
