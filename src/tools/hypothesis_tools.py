"""
Tools for hypothesis-driven pentest execution.

These tools let agents pursue high-signal leads without losing the coverage
discipline expected in professional pentests.
"""

from __future__ import annotations

from src.sdk.hypothesis_engine import (
    MODE_POLICIES,
    generate_hypotheses_from_context,
    get_policy,
    merge_hypotheses,
    normalize_mode,
    render_hypotheses,
    render_selected_hypothesis,
    update_hypothesis_result,
)
from src.sdk.hypothesis_scheduler import render_scheduler_context, select_next_hypothesis
from src.sdk.tool import function_tool


def _active_target(explicit_target: str = "") -> str:
    if explicit_target:
        return explicit_target
    try:
        from src.agents.orchestrator_agent import get_current_target

        current = get_current_target()
        if current:
            return current
    except Exception:
        pass
    try:
        from src.repl.target_manager import get_target_manager

        tm = get_target_manager()
        if getattr(tm, "current_target", None):
            return tm.current_target
    except Exception:
        pass
    return explicit_target or "default"


def _profile(target: str):
    from src.repl.profiles import get_profile_manager

    pm = get_profile_manager()
    return pm, pm.load_profile(target)


@function_tool()
def set_engagement_mode(mode: str = "pentest", target: str = "") -> str:
    """
    Set the assessment mode for the active target.

    Args:
        mode: One of fast, ctf, pentest, audit, stealth, or report
        target: Optional target override

    Returns:
        Mode policy and coverage expectations.
    """
    selected = normalize_mode(mode)
    active = _active_target(target)
    pm, profile = _profile(active)
    profile.engagement_mode = selected
    profile.coverage_requirements = [
        {"requirement": item, "status": "pending"}
        for item in get_policy(selected).coverage_requirements
    ]
    pm.save_profile(active)
    return _render_coverage(profile, selected)


@function_tool()
def generate_hypotheses(context: str = "", target: str = "", mode: str = "") -> str:
    """
    Generate and persist ranked attack-path hypotheses from current observations.

    Args:
        context: Recon observations, tool output excerpts, page text, banners, or analyst notes
        target: Optional target override
        mode: Optional mode override; defaults to the profile mode or pentest

    Returns:
        Ranked hypotheses with next tools, proof budgets, and coverage rules.
    """
    active = _active_target(target)
    pm, profile = _profile(active)
    selected = normalize_mode(mode or getattr(profile, "engagement_mode", "pentest"))
    profile.engagement_mode = selected
    generated = generate_hypotheses_from_context(context=context, mode=selected, profile=profile)
    profile.hypotheses = merge_hypotheses(getattr(profile, "hypotheses", []), generated)
    if not getattr(profile, "coverage_requirements", []):
        profile.coverage_requirements = [
            {"requirement": item, "status": "pending"}
            for item in get_policy(selected).coverage_requirements
        ]
    for hyp in generated[:5]:
        pm.add_attack_path(
            active,
            hyp.name,
            [f"Evidence: {', '.join(hyp.evidence[:3])}", f"Test with: {', '.join(hyp.next_tools[:4])}"],
            confidence=_confidence_label(hyp.confidence),
            status=hyp.status,
        )
    pm.save_profile(active)
    return render_hypotheses(profile.hypotheses, mode=selected)


@function_tool()
def show_active_hypotheses(target: str = "", status: str = "") -> str:
    """
    Show persisted hypotheses for the active target.

    Args:
        target: Optional target override
        status: Optional status filter such as candidate, confirmed, rejected, or blocked

    Returns:
        Current hypothesis queue and pentest coverage reminder.
    """
    active = _active_target(target)
    _, profile = _profile(active)
    mode = normalize_mode(getattr(profile, "engagement_mode", "pentest"))
    rows = list(getattr(profile, "hypotheses", []) or [])
    if status:
        wanted = status.strip().lower()
        rows = [row for row in rows if row.get("status", "").lower() == wanted]
    return render_hypotheses(rows, mode=mode)


@function_tool()
def schedule_next_hypothesis(target: str = "") -> str:
    """
    Select the highest-ranked active hypothesis and return its focused test plan.

    Args:
        target: Optional target override. Defaults to the active target.

    Returns:
        Scheduler-selected hypothesis, preferred tools, and success/failure criteria.
    """
    active = _active_target(target)
    _, profile = _profile(active)
    selected = select_next_hypothesis(getattr(profile, "hypotheses", []) or [])
    if not selected:
        return "No active hypotheses are scheduled. Run generate_hypotheses first or complete baseline coverage."
    return render_scheduler_context(active)


@function_tool()
def select_hypothesis_tools(hypothesis_id: str = "", target: str = "") -> str:
    """
    Select the focused tool set and proof criteria for one hypothesis.

    Args:
        hypothesis_id: Hypothesis id from generate_hypotheses/show_active_hypotheses
        target: Optional target override

    Returns:
        Tool sequence, success criteria, failure criteria, and coverage reminder.
    """
    active = _active_target(target)
    _, profile = _profile(active)
    mode = normalize_mode(getattr(profile, "engagement_mode", "pentest"))
    rows = list(getattr(profile, "hypotheses", []) or [])
    selected = None
    if hypothesis_id:
        selected = next((row for row in rows if row.get("id") == hypothesis_id), None)
    if selected is None and rows:
        selected = rows[0]
    return render_selected_hypothesis(selected or {}, mode=mode)


@function_tool()
def record_hypothesis_result(
    hypothesis_id: str,
    outcome: str,
    evidence: str = "",
    target: str = "",
) -> str:
    """
    Record whether a hypothesis was confirmed, rejected, blocked, or inconclusive.

    Args:
        hypothesis_id: Hypothesis id from generate_hypotheses/show_active_hypotheses
        outcome: confirmed, rejected, blocked, inconclusive, or tested
        evidence: Short proof or reason for rejection
        target: Optional target override

    Returns:
        Updated queue plus the remaining coverage requirements for the engagement mode.
    """
    active = _active_target(target)
    pm, profile = _profile(active)
    profile.hypotheses = update_hypothesis_result(
        getattr(profile, "hypotheses", []),
        hypothesis_id=hypothesis_id,
        outcome=outcome,
        evidence=evidence,
    )
    pm.save_profile(active)
    mode = normalize_mode(getattr(profile, "engagement_mode", "pentest"))
    queue = render_hypotheses(profile.hypotheses, mode=mode, limit=5)
    coverage = _render_coverage(profile, mode)
    return f"{queue}\n\n{coverage}"


@function_tool()
def show_coverage_requirements(target: str = "", mode: str = "") -> str:
    """
    Show the coverage checklist for an engagement mode.

    Args:
        target: Optional target override
        mode: Optional mode override

    Returns:
        Mode description and required coverage checklist.
    """
    active = _active_target(target)
    pm, profile = _profile(active)
    selected = normalize_mode(mode or getattr(profile, "engagement_mode", "pentest"))
    profile.engagement_mode = selected
    if not getattr(profile, "coverage_requirements", []):
        profile.coverage_requirements = [
            {"requirement": item, "status": "pending"}
            for item in get_policy(selected).coverage_requirements
        ]
        pm.save_profile(active)
    return _render_coverage(profile, selected)


def _render_coverage(profile, mode: str) -> str:
    policy = get_policy(mode)
    lines = [
        f"## Coverage Policy: {policy.name}",
        policy.description,
        f"Coverage required before final conclusion: {'yes' if policy.coverage_required else 'no'}",
        "",
        "Checklist:",
    ]
    rows = getattr(profile, "coverage_requirements", []) or [
        {"requirement": item, "status": "pending"} for item in policy.coverage_requirements
    ]
    if not rows:
        lines.append("- No mandatory coverage in this mode.")
    for row in rows:
        lines.append(f"- {row.get('status', 'pending').upper()}: {row.get('requirement')}")
    if policy.notes:
        lines.append("")
        lines.append("Mode notes:")
        lines.extend(f"- {note}" for note in policy.notes)
    lines.append("")
    lines.append(f"Available modes: {', '.join(MODE_POLICIES)}")
    return "\n".join(lines)


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.65:
        return "medium"
    return "low"
