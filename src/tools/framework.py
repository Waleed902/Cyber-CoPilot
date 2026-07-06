"""
Offensive workflow tools.

These are glue tools for bug bounty maturity: they help agents map the app,
avoid noisy duplicate findings, promote only validated evidence, and reason
about chains.
"""

from __future__ import annotations

import json
from typing import Optional

from src.sdk.finding_lifecycle import get_finding_lifecycle
from src.sdk.http_knowledge import get_http_knowledge
from src.sdk.tool import function_tool


@function_tool()
def record_http_observation(
    target: str,
    url: str,
    method: str = "GET",
    status_code: int = 0,
    params: str = "",
    body: str = "",
    auth_required: str = "",
    content_type: str = "",
    response_length: int = 0,
    response_excerpt: str = "",
    source_tool: str = "",
    notes: str = "",
) -> str:
    """
    Record an observed HTTP endpoint into the target knowledge graph.

    Args:
        target: Root target/domain for this engagement
        url: Full endpoint URL
        method: HTTP method
        status_code: Observed HTTP status code
        params: Comma-separated parameter names if known
        body: Optional request body used to infer JSON/form parameters
        auth_required: "true", "false", or blank to infer from status/body
        content_type: Response content type
        response_length: Response body length if known
        response_excerpt: Short response sample for auth/status inference
        source_tool: Tool that produced this observation
        notes: Analyst notes

    Returns:
        Confirmation plus adaptive next-test suggestions.
    """
    parsed_params = [p.strip() for p in params.split(",") if p.strip()] if params else None
    auth_value: Optional[bool]
    if auth_required.lower() in {"true", "yes", "1"}:
        auth_value = True
    elif auth_required.lower() in {"false", "no", "0"}:
        auth_value = False
    else:
        auth_value = None

    kb = get_http_knowledge()
    obs = kb.record(
        target=target,
        url=url,
        method=method,
        status_code=status_code,
        params=parsed_params,
        body=body,
        auth_required=auth_value,
        content_type=content_type,
        response_length=response_length,
        response_excerpt=response_excerpt,
        source_tool=source_tool,
        notes=notes,
    )
    suggestions = kb.suggest_tests(target)[:5]
    lines = [
        f"Recorded HTTP observation: {obs.fingerprint}",
        f"Parameters: {', '.join(obs.params) if obs.params else '(none)'}",
        f"Auth required: {obs.auth_required}",
        "",
        "Next adaptive tests:",
    ]
    if suggestions:
        for item in suggestions:
            lines.append(f"- {item['kind']}: {item['url']} via {item['tool']} ({item['reason']})")
    else:
        lines.append("- No targeted tests inferred yet; continue app mapping.")
    return "\n".join(lines)


@function_tool()
def suggest_adaptive_tests(target: str = "") -> str:
    """
    Suggest next offensive tests from the accumulated HTTP knowledge graph.

    Args:
        target: Optional target filter

    Returns:
        Prioritized test suggestions and knowledge summary.
    """
    kb = get_http_knowledge()
    summary = kb.summary(target)
    suggestions = kb.suggest_tests(target)
    lines = [
        "## Target Knowledge Summary",
        json.dumps(summary, indent=2),
        "",
        "## Adaptive Test Queue",
    ]
    if not suggestions:
        lines.append("No adaptive tests yet. Record endpoints with record_http_observation first.")
        return "\n".join(lines)
    for i, item in enumerate(suggestions, 1):
        lines.append(f"{i}. {item['kind']} on {item['url']}")
        lines.append(f"   Tool: {item['tool']}")
        lines.append(f"   Why: {item['reason']}")
    return "\n".join(lines)


@function_tool()
def register_finding_candidate(
    title: str,
    target: str,
    severity: str,
    endpoint: str = "",
    parameter: str = "",
    category: str = "",
    evidence: str = "",
    scope_source: str = "",
) -> str:
    """
    Register a suspected vulnerability as an unconfirmed candidate.

    Args:
        title: Finding title
        target: In-scope target
        severity: info, low, medium, high, or critical
        endpoint: Affected URL/path
        parameter: Affected parameter if any
        category: Vulnerability family, e.g. idor, xss, ssrf
        evidence: Initial signal or tool output
        scope_source: Bug bounty program/scope source

    Returns:
        Candidate fingerprint and validation guidance.
    """
    lifecycle = get_finding_lifecycle()
    finding = lifecycle.add_candidate(
        title=title,
        target=target,
        severity=severity,
        endpoint=endpoint,
        parameter=parameter,
        category=category,
        evidence=evidence,
        scope_source=scope_source,
    )
    return (
        f"Candidate registered: {finding.fingerprint}\n"
        f"Status: {finding.status}\n"
        f"Confidence: {finding.confidence}/100\n\n"
        "Before reporting, promote it with validation evidence that includes proof, an observable result, "
        "and a negative control or response diff."
    )


@function_tool()
def promote_finding_with_evidence(
    fingerprint: str,
    evidence: str,
    validation_notes: str = "",
    impact: str = "",
    remediation: str = "",
    cwe: str = "",
    cvss: str = "",
) -> str:
    """
    Promote a candidate to confirmed only when evidence is report-quality.

    Args:
        fingerprint: Candidate fingerprint from register_finding_candidate
        evidence: Concrete proof, ideally raw HTTP/PoC output plus negative control
        validation_notes: How validation was performed
        impact: Realistic impact statement
        remediation: Remediation guidance
        cwe: CWE identifier
        cvss: CVSS vector or score

    Returns:
        Promotion result and reportability status.
    """
    ok, message, finding = get_finding_lifecycle().promote(
        fingerprint=fingerprint,
        evidence=evidence,
        validation_notes=validation_notes,
        impact=impact,
        remediation=remediation,
        cwe=cwe,
        cvss=cvss,
    )
    if not finding:
        return message
    return (
        f"{message}\n"
        f"Status: {finding.status}\n"
        f"Reportable: {finding.reportable}\n"
        f"Confidence: {finding.confidence}/100"
    )


@function_tool()
def build_attack_chains(target: str = "") -> str:
    """
    Build attack-chain opportunities from confirmed and candidate findings.

    Args:
        target: Optional target filter

    Returns:
        Chain opportunities and concrete validation next steps.
    """
    chains = get_finding_lifecycle().chain_opportunities(target)
    if not chains:
        return (
            "No chain opportunities detected yet. Add confirmed findings from different classes "
            "(for example open redirect + OAuth, SSRF + cloud metadata, IDOR + mass assignment)."
        )
    lines = ["## Attack Chain Opportunities"]
    for i, chain in enumerate(chains, 1):
        lines.append(f"{i}. {chain['chain']}")
        lines.append(f"   Rationale: {chain['rationale']}")
        lines.append(f"   Next step: {chain['next_step']}")
    return "\n".join(lines)


@function_tool()
def generate_evidence_report(target: str = "") -> str:
    """
    Generate a report-ready Markdown summary from confirmed findings only.

    Args:
        target: Optional target filter

    Returns:
        Markdown report containing only reportable findings.
    """
    return get_finding_lifecycle().markdown_report(target)


@function_tool()
def framework_maturity_status(target: str = "") -> str:
    """
    Show maturity status for the current bug bounty workflow.

    Args:
        target: Optional target filter

    Returns:
        Coverage gaps and next actions.
    """
    kb = get_http_knowledge()
    lifecycle = get_finding_lifecycle()
    summary = kb.summary(target)
    reportable = lifecycle.reportable(target)
    candidates = lifecycle.findings
    if target:
        t = target.lower()
        candidates = [f for f in candidates if f.target.lower() == t or f.target.lower().endswith(f".{t}")]

    checks = [
        ("App mapped", summary["endpoints"] >= 5, f"{summary['endpoints']} endpoint(s) recorded"),
        ("Parameters inventoried", bool(summary["parameters"]), f"{len(summary['parameters'])} parameter(s) recorded"),
        ("Auth surface identified", summary["auth_required_endpoints"] > 0, f"{summary['auth_required_endpoints']} auth endpoint(s)"),
        ("Candidates tracked", bool(candidates), f"{len(candidates)} candidate/confirmed finding(s)"),
        ("Reportable proof", bool(reportable), f"{len(reportable)} reportable finding(s)"),
        ("Chain reasoning", bool(lifecycle.chain_opportunities(target)), "chain opportunities checked"),
    ]

    lines = ["## Offensive Framework Maturity"]
    for name, ok, detail in checks:
        lines.append(f"- {'PASS' if ok else 'GAP'} {name}: {detail}")
    lines.append("")
    lines.append("Next best action:")
    suggestions = kb.suggest_tests(target)
    if suggestions:
        first = suggestions[0]
        lines.append(f"- Run {first['tool']} against {first['url']} because {first['reason']}.")
    elif not candidates:
        lines.append("- Map endpoints and register candidates before scanning deeper.")
    elif not reportable:
        lines.append("- Promote candidates with proof plus negative controls.")
    else:
        lines.append("- Generate evidence report and review chain opportunities.")
    return "\n".join(lines)
