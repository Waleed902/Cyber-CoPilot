"""First-class scheduling helpers for persisted target hypotheses."""

from __future__ import annotations

from typing import Any, Dict, List


DONE_STATUSES = {"confirmed", "rejected", "invalid"}
BLOCKED_STATUSES = {"blocked"}


def _score(item: Dict[str, Any]) -> tuple[float, float, int]:
    try:
        score = float(item.get("score") or 0)
    except Exception:
        score = 0.0
    try:
        confidence = float(item.get("confidence") or 0)
    except Exception:
        confidence = 0.0
    try:
        cost = int(item.get("cost") or 1)
    except Exception:
        cost = 1
    return score, confidence, -cost


def select_next_hypothesis(hypotheses: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Select the highest-ranked active hypothesis."""
    active = [
        dict(item)
        for item in hypotheses or []
        if str(item.get("status", "candidate")).lower() not in DONE_STATUSES | BLOCKED_STATUSES
    ]
    if not active:
        active = [
            dict(item)
            for item in hypotheses or []
            if str(item.get("status", "candidate")).lower() not in DONE_STATUSES
        ]
    if not active:
        return {}
    return sorted(active, key=_score, reverse=True)[0]


def render_scheduler_context(target: str = "", limit_tools: int = 6) -> str:
    """
    Render the current scheduler decision as an agent-readable context block.

    This does not execute anything. It tells the agent which persisted lead should
    be tested first and how to decide whether it succeeded or failed.
    """
    if not target:
        try:
            from src.sdk.context_hub import get_context_hub

            target = get_context_hub().current_target or ""
        except Exception:
            target = ""
    if not target:
        return ""
    try:
        from src.repl.profiles import get_profile_manager

        profile = get_profile_manager().load_profile(target)
    except Exception:
        return ""
    hypothesis = select_next_hypothesis(getattr(profile, "hypotheses", []) or [])
    if not hypothesis:
        return ""
    tools = ", ".join((hypothesis.get("next_tools") or [])[:limit_tools])
    success = "; ".join((hypothesis.get("success_criteria") or [])[:4])
    failure = "; ".join((hypothesis.get("failure_criteria") or [])[:4])
    evidence = "; ".join((hypothesis.get("evidence") or [])[:4])
    return (
        "[HYPOTHESIS SCHEDULER]\n"
        f"Target: {target}\n"
        f"Next hypothesis: {hypothesis.get('name')}\n"
        f"ID: {hypothesis.get('id')}\n"
        f"Status: {hypothesis.get('status', 'candidate')}\n"
        f"Score: {hypothesis.get('score')} confidence={hypothesis.get('confidence')} cost={hypothesis.get('cost')}\n"
        f"Evidence: {evidence}\n"
        f"Try first: {tools}\n"
        f"Success criteria: {success}\n"
        f"Failure criteria: {failure}\n"
        "After testing this lead, call record_hypothesis_result with confirmed, rejected, blocked, or inconclusive."
    )
