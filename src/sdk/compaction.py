"""Context estimation and structured session compaction."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any


DEFAULT_CONTEXT_LIMIT_TOKENS = 120_000
DEFAULT_OUTPUT_RESERVE_TOKENS = 16_384
DEFAULT_SAFETY_BUFFER_TOKENS = 4_096


def estimate_tokens(value: Any) -> int:
    """Fast approximate token estimator used before LLM calls."""
    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        text = str(value)
    return max(1, len(text) // 4)


def context_budget(
    context_limit: int = DEFAULT_CONTEXT_LIMIT_TOKENS,
    output_reserve: int = DEFAULT_OUTPUT_RESERVE_TOKENS,
    safety_buffer: int = DEFAULT_SAFETY_BUFFER_TOKENS,
) -> int:
    return max(8_000, int(context_limit) - int(output_reserve) - int(safety_buffer))


def context_usage_pct(
    messages: list[dict],
    tools_schema: list | None = None,
    context_limit: int = DEFAULT_CONTEXT_LIMIT_TOKENS,
    output_reserve: int = DEFAULT_OUTPUT_RESERVE_TOKENS,
    safety_buffer: int = DEFAULT_SAFETY_BUFFER_TOKENS,
) -> int:
    budget = context_budget(context_limit, output_reserve, safety_buffer)
    used = estimate_tokens(messages) + estimate_tokens(tools_schema or [])
    return min(999, max(0, round((used / budget) * 100)))


def should_compact(
    messages: list[dict],
    tools_schema: list | None = None,
    context_limit: int = DEFAULT_CONTEXT_LIMIT_TOKENS,
    output_reserve: int = DEFAULT_OUTPUT_RESERVE_TOKENS,
    safety_buffer: int = DEFAULT_SAFETY_BUFFER_TOKENS,
) -> bool:
    budget = context_budget(context_limit, output_reserve, safety_buffer)
    used = estimate_tokens(messages) + estimate_tokens(tools_schema or [])
    return used > budget


def compact_messages(
    messages: list[dict],
    tools_schema: list | None = None,
    context_limit: int = DEFAULT_CONTEXT_LIMIT_TOKENS,
    output_reserve: int = DEFAULT_OUTPUT_RESERVE_TOKENS,
    safety_buffer: int = DEFAULT_SAFETY_BUFFER_TOKENS,
    preserve_tail: int = 18,
) -> tuple[list[dict], dict[str, Any]]:
    """
    Compact old history into a structured Markdown ledger.

    Recent messages remain intact. Older tool chatter is compressed into durable
    state: goal, decisions, progress, blocked items, tools used, and critical
    snippets. Existing compaction ledgers are folded forward.
    """
    if not messages:
        return messages, {"changed": False, "reason": "empty"}

    budget = context_budget(context_limit, output_reserve, safety_buffer)
    before_tokens = estimate_tokens(messages) + estimate_tokens(tools_schema or [])
    if before_tokens <= budget:
        return messages, {"changed": False, "before_tokens": before_tokens, "budget": budget}

    leading_system: list[dict] = []
    rest = list(messages)
    while rest and rest[0].get("role") == "system":
        leading_system.append(rest.pop(0))

    if len(rest) <= preserve_tail + 2:
        # Fall back to truncating large tool outputs if there is not enough head
        # history to summarize away.
        compacted = leading_system + [_truncate_message(m) for m in rest]
        return compacted, {
            "changed": True,
            "strategy": "truncate_only",
            "before_tokens": before_tokens,
            "after_tokens": estimate_tokens(compacted) + estimate_tokens(tools_schema or []),
            "budget": budget,
        }

    tail = rest[-preserve_tail:]
    head = rest[:-preserve_tail]
    ledger = _build_ledger(head)
    ledger_msg = {"role": "system", "content": ledger}
    compacted = leading_system + [ledger_msg] + tail

    after_tokens = estimate_tokens(compacted) + estimate_tokens(tools_schema or [])
    if after_tokens > budget:
        # Keep the freshest context intact but shrink oversized tail payloads.
        compacted = leading_system + [ledger_msg] + [_truncate_message(m) for m in tail]
        after_tokens = estimate_tokens(compacted) + estimate_tokens(tools_schema or [])

    return compacted, {
        "changed": True,
        "strategy": "ledger",
        "before_tokens": before_tokens,
        "after_tokens": after_tokens,
        "budget": budget,
        "head_messages": len(head),
        "tail_messages": len(tail),
    }


def _truncate_message(msg: dict) -> dict:
    content = msg.get("content")
    if isinstance(content, str) and len(content) > 4_000:
        return {**msg, "content": content[:4_000] + "\n...[compaction-tail-truncated]"}
    return msg


def _build_ledger(messages: list[dict]) -> str:
    prior_ledgers: list[str] = []
    user_goals: list[str] = []
    assistant_notes: list[str] = []
    tool_counts: Counter[str] = Counter()
    tool_results: list[str] = []
    blocked: list[str] = []
    confirmed_findings: list[str] = []   # structured security findings extracted from tool outputs

    for msg in messages:
        role = msg.get("role", "")
        content = (msg.get("content") or "").strip()
        if "[SESSION COMPACTION LEDGER]" in content:
            prior_ledgers.append(content[:8_000])
            continue
        if role == "user" and content:
            user_goals.append(_one_line(content, 260))
        elif role == "assistant":
            for tc in msg.get("tool_calls", []) or []:
                name = ((tc.get("function") or {}).get("name") or "").strip()
                if name:
                    tool_counts[name] += 1
            if content:
                assistant_notes.append(_one_line(content, 240))
        elif role == "tool" and content:
            lower = content.lower()
            if any(marker in lower for marker in ("blocked", "scope error", "permission", "not found", "timeout", "error:")):
                blocked.append(_one_line(content, 240))
            else:
                tool_results.append(_one_line(content, 240))
            # Extract structured finding lines from tool output
            for finding in _extract_findings_from_output(content):
                if finding not in confirmed_findings:
                    confirmed_findings.append(finding)

    lines = [
        "[SESSION COMPACTION LEDGER]",
        f"Compacted at: {datetime.now().isoformat()}",
        "",
        "## Goal",
        f"- {user_goals[-1] if user_goals else 'Continue the active security assessment.'}",
        "",
        "## Constraints",
        "- Preserve the active target/scope from current system context.",
        "- Treat recent un-compacted messages below this ledger as authoritative.",
        "- Use persisted target profile, event log, and artifacts for exact historical details.",
        "",
    ]

    # Confirmed findings block — highest priority carry-forward
    lines.append("## Confirmed Findings (carry-forward — do NOT re-test these)")
    if confirmed_findings:
        for f in confirmed_findings[:20]:
            lines.append(f"- {f}")
    else:
        lines.append("- None confirmed in compacted history.")

    lines.extend(["", "## Progress"])
    for item in tool_results[-8:]:
        lines.append(f"- {item}")
    if not tool_results:
        lines.append("- No compacted tool results with durable signal.")

    lines.extend(["", "## Key Decisions / Assistant Notes"])
    for item in assistant_notes[-6:]:
        lines.append(f"- {item}")
    if not assistant_notes:
        lines.append("- No compacted assistant decisions.")

    lines.extend(["", "## Tools Used"])
    if tool_counts:
        for name, count in tool_counts.most_common(12):
            lines.append(f"- {name}: {count}")
    else:
        lines.append("- No compacted tool calls.")

    lines.extend(["", "## Blocked / Errors"])
    for item in blocked[-6:]:
        lines.append(f"- {item}")
    if not blocked:
        lines.append("- No compacted blockers.")

    if prior_ledgers:
        lines.extend(["", "## Previous Ledger Carry-Forward"])
        for ledger in prior_ledgers[-2:]:
            lines.append("```")
            lines.append(ledger[:3_000])
            lines.append("```")

    return "\n".join(lines)


def _one_line(text: str, limit: int) -> str:
    clean = " ".join(text.replace("\r", "\n").split())
    return clean[:limit] + ("..." if len(clean) > limit else "")


# Patterns that signal a confirmed or high-confidence security finding.
_FINDING_PATTERNS: list[tuple[str, str]] = [
    # (signal keyword, severity label)
    ("sql injection", "SQLi"),
    ("time-based blind", "SQLi/time-based"),
    ("error-based", "SQLi/error-based"),
    ("union-based", "SQLi/union"),
    ("xss", "XSS"),
    ("cross-site scripting", "XSS"),
    ("remote code execution", "RCE"),
    ("command injection", "Command Injection"),
    ("ssrf", "SSRF"),
    ("server-side request forgery", "SSRF"),
    ("local file inclusion", "LFI"),
    ("path traversal", "Path Traversal"),
    ("open redirect", "Open Redirect"),
    ("csrf", "CSRF"),
    ("idor", "IDOR"),
    ("insecure direct object", "IDOR"),
    ("privilege escalation", "PrivEsc"),
    ("authentication bypass", "Auth Bypass"),
    ("default credentials", "Default Creds"),
    ("hardcoded", "Hardcoded Secret"),
    ("exposed .git", "Git Exposure"),
    ("directory listing", "Dir Listing"),
    ("cve-", "CVE"),
    ("flag{", "FLAG"),
    ("htb{", "FLAG"),
    ("thm{", "FLAG"),
    ("picoctf{", "FLAG"),
    ("password:", "Credential"),
    ("hash:", "Credential"),
]

def _extract_findings_from_output(text: str) -> list[str]:
    """Extract concise confirmed-finding lines from a raw tool output string.

    Returns a list of short one-line summaries suitable for the ledger's
    "Confirmed Findings" section.  Each line is at most 200 characters.
    """
    findings: list[str] = []
    seen: set[str] = set()
    lines = text.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or len(stripped) < 10:
            continue
        lower = stripped.lower()

        for keyword, label in _FINDING_PATTERNS:
            if keyword in lower:
                # Build a concise summary
                summary = _one_line(stripped, 180)
                key = summary[:60].lower()
                if key not in seen:
                    seen.add(key)
                    findings.append(f"[{label}] {summary}")
                break  # one label per line

    return findings
