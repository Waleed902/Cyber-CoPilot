from src.sdk.compaction import compact_messages, context_usage_pct


def test_compaction_preserves_recent_tail_and_adds_ledger():
    messages = [{"role": "system", "content": "system prompt"}]
    for idx in range(40):
        messages.append({"role": "user", "content": f"goal {idx} " + ("x" * 1000)})
        messages.append(
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"call_{idx}",
                        "type": "function",
                        "function": {"name": "curl_request", "arguments": "{}"},
                    }
                ],
            }
        )
        messages.append({"role": "tool", "tool_call_id": f"call_{idx}", "content": f"result {idx} " + ("y" * 1000)})

    compacted, meta = compact_messages(messages, context_limit=8000, preserve_tail=6)

    assert meta["changed"] is True
    assert any("[SESSION COMPACTION LEDGER]" in (m.get("content") or "") for m in compacted)
    assert compacted[-1]["content"].startswith("result 39")
    assert len(compacted) < len(messages)


def test_context_usage_pct_increases_with_messages():
    low = context_usage_pct([{"role": "user", "content": "small"}], context_limit=12000)
    high = context_usage_pct([{"role": "user", "content": "x" * 20000}], context_limit=12000)

    assert high > low
