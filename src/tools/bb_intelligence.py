"""
Bug Bounty Intelligence Tools — Agent-Callable Wrappers

Exposes three elite hunting engines as tool functions the BugBountyAgent can call:

1. amplify_finding()      — Post-finding escalation recipes (what to do AFTER a finding)
2. model_attack_surface() — Target recon signals → EV-ranked attack queue
3. format_bb_report()     — H1/Bugcrowd submission-ready report generation
4. calculate_cvss()       — Precise CVSS 3.1 score from vector components
5. chain_all_findings()   — Cross-finding chain analysis (what combos create Critical)
"""

from __future__ import annotations

import json
from typing import Optional
from loguru import logger


def amplify_finding(
    finding_title: str,
    severity: str = "medium",
    endpoint: str = "",
    evidence: str = "",
    category: str = "",
    top_n: int = 5,
) -> str:
    """
    After confirming a finding, call this to get ranked escalation steps.

    This answers: "I just confirmed X — what do I do NEXT to maximize impact?"
    Returns specific tests, tools, expected severity upgrades, and typical bounty ranges.

    Args:
        finding_title: Title of the confirmed finding (e.g., "Reflected XSS on /search")
        severity: Current severity (critical/high/medium/low)
        endpoint: The vulnerable endpoint URL
        evidence: Brief description of evidence / what was confirmed
        category: Optional finding category (xss/ssrf/idor/etc.)
        top_n: How many escalation steps to return (default: 5)

    Returns:
        Formatted escalation guidance as text
    """
    try:
        from src.sdk.impact_amplifier import get_amplifier
        amplifier = get_amplifier()
        result = amplifier.amplify(
            finding_title=finding_title,
            severity=severity,
            endpoint=endpoint,
            evidence=evidence,
            category=category,
            top_n=top_n,
        )
        return amplifier.format_amplification(result)
    except Exception as e:
        logger.error(f"amplify_finding error: {e}")
        return f"[amplify_finding error]: {e}\n\nManual escalation path: Prove data extraction or privilege escalation. Programs pay for impact, not finding type."


def model_attack_surface(
    tech_stack: str = "",
    auth_type: str = "unknown",
    endpoints: str = "",
    roles: str = "",
    cloud_indicators: str = "",
    notes: str = "",
    top_n: int = 6,
) -> str:
    """
    Build an EV-ranked attack queue from target recon signals.

    Call this BEFORE running any scanner — it tells you exactly what to test first
    based on what will most likely pay. Replaces guesswork with expected-value math.

    Args:
        tech_stack: Comma-separated technologies detected (e.g., "React, Django, PostgreSQL, nginx")
        auth_type: Authentication mechanism (jwt/session/oauth/saml/api_key/basic/none)
        endpoints: Comma-separated discovered endpoints (e.g., "/api/v1/users, /admin, /checkout")
        roles: Comma-separated user roles seen (e.g., "user, admin, viewer, owner")
        cloud_indicators: Cloud signals (e.g., "AWS headers, S3 URLs in responses, EC2 instance")
        notes: Free-text notes from recon (app description, platform type, etc.)
        top_n: How many attack classes to show in the queue (default: 6)

    Returns:
        Prioritized attack queue with starting actions for each class
    """
    try:
        from src.sdk.surface_modeler import get_surface_modeler
        modeler = get_surface_modeler()

        tech_list = [t.strip() for t in tech_stack.split(",") if t.strip()]
        endpoint_list = [e.strip() for e in endpoints.split(",") if e.strip()]
        role_list = [r.strip() for r in roles.split(",") if r.strip()]
        cloud_list = [c.strip() for c in cloud_indicators.split(",") if c.strip()]

        model = modeler.build_attack_queue(
            tech_stack=tech_list,
            auth_type=auth_type,
            endpoints=endpoint_list,
            roles=role_list,
            cloud_indicators=cloud_list,
            notes=notes,
        )
        return modeler.format_queue(model, top_n=top_n)
    except Exception as e:
        logger.error(f"model_attack_surface error: {e}")
        return f"[model_attack_surface error]: {e}\n\nDefault priority: IDOR > SSRF > JWT > Mass Assignment > Business Logic > XSS"


def format_bb_report(
    title: str,
    vulnerability_type: str,
    severity: str,
    endpoint: str,
    parameter: str = "",
    steps_to_reproduce: str = "",
    expected_result: str = "",
    actual_result: str = "",
    poc_request: str = "",
    impact: str = "",
    remediation: str = "",
    evidence: str = "",
    platform: str = "hackerone",
    chain_description: str = "",
) -> str:
    """
    Generate a HackerOne or Bugcrowd submission-ready report for a confirmed finding.

    Produces professional-grade output that can be copy-pasted directly into a bug bounty
    submission form. Includes CVSS 3.1 vector string, impact narrative, and remediation steps.

    Args:
        title: Finding title (e.g., "SSRF to AWS Cloud Metadata via image_url parameter")
        vulnerability_type: Vuln class (ssrf/idor/xss/sqli/jwt/cors/race_condition/ssti/etc.)
        severity: critical/high/medium/low
        endpoint: Full vulnerable endpoint URL
        parameter: Vulnerable parameter name
        steps_to_reproduce: Numbered steps separated by newlines (or pipe | separator)
        expected_result: What the secure behavior should be
        actual_result: What actually happens (the vulnerability)
        poc_request: Self-contained curl command or raw HTTP request proving the issue
        impact: Business impact description (auto-generated if empty)
        remediation: Fix recommendation (auto-generated if empty)
        evidence: Raw HTTP response, tool output, or screenshot description as proof
        platform: "hackerone" or "bugcrowd" (default: hackerone)
        chain_description: If this is part of an attack chain, describe the chain here

    Returns:
        Complete submission-ready report as formatted markdown
    """
    try:
        from src.sdk.bb_report_formatter import get_formatter

        formatter = get_formatter()

        # Parse steps — support newline or pipe separator
        if steps_to_reproduce:
            if "|" in steps_to_reproduce:
                steps = [s.strip() for s in steps_to_reproduce.split("|") if s.strip()]
            else:
                steps = [s.strip() for s in steps_to_reproduce.split("\n") if s.strip()]
        else:
            steps = []

        result = formatter.format_finding(
            title=title,
            vulnerability_type=vulnerability_type,
            severity=severity,
            endpoint=endpoint,
            parameter=parameter,
            steps_to_reproduce=steps,
            expected_result=expected_result,
            actual_result=actual_result,
            poc_request=poc_request,
            impact=impact,
            remediation=remediation,
            evidence=evidence,
            platform=platform,
            chain_description=chain_description,
        )

        header = (
            f"━━━ {platform.upper()} SUBMISSION REPORT ━━━\n"
            f"CVSS: {result.cvss_score} {result.severity} — {result.cvss_vector}\n"
            f"{'━' * 50}\n\n"
        )
        return header + result.body

    except Exception as e:
        logger.error(f"format_bb_report error: {e}")
        return f"[format_bb_report error]: {e}"


def calculate_cvss(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "N",
) -> str:
    """
    Calculate a precise CVSS 3.1 Base Score from individual metric components.

    Use this when you need an accurate CVSS score for a confirmed finding.
    The score will be used in bug bounty reports and severity justifications.

    CVSS 3.1 Metrics:
        AV (Attack Vector):        N=Network, A=Adjacent, L=Local, P=Physical
        AC (Attack Complexity):    L=Low, H=High
        PR (Privileges Required):  N=None, L=Low, H=High
        UI (User Interaction):     N=None, R=Required
        S  (Scope):                U=Unchanged, C=Changed
        C  (Confidentiality):      N=None, L=Low, H=High
        I  (Integrity):            N=None, L=Low, H=High
        A  (Availability):         N=None, L=Low, H=High

    Common examples:
        Remote unauthenticated RCE:  AV=N AC=L PR=N UI=N S=U C=H I=H A=H → 9.8 Critical
        Stored XSS (admin-visible):  AV=N AC=L PR=L UI=N S=C C=H I=H A=N → 9.0 Critical
        Reflected XSS:               AV=N AC=L PR=N UI=R S=C C=L I=L A=N → 6.1 Medium
        IDOR read:                   AV=N AC=L PR=L UI=N S=U C=H I=N A=N → 6.5 Medium
        SSRF to cloud metadata:      AV=N AC=L PR=N UI=N S=C C=H I=H A=N → 10.0 Critical

    Returns:
        CVSS score, severity label, and vector string
    """
    try:
        from src.sdk.bb_report_formatter import get_formatter
        formatter = get_formatter()
        result = formatter.calculate_cvss(av=av, ac=ac, pr=pr, ui=ui, s=s, c=c, i=i, a=a)
        return (
            f"CVSS 3.1 Score: {result['score']} — {result['severity']}\n"
            f"Vector: {result['vector']}\n\n"
            f"Metrics:\n"
            f"  AV={av} (Attack Vector: {'Network' if av=='N' else 'Adjacent' if av=='A' else 'Local' if av=='L' else 'Physical'})\n"
            f"  AC={ac} (Attack Complexity: {'Low' if ac=='L' else 'High'})\n"
            f"  PR={pr} (Privileges Required: {'None' if pr=='N' else 'Low' if pr=='L' else 'High'})\n"
            f"  UI={ui} (User Interaction: {'None' if ui=='N' else 'Required'})\n"
            f"  S={s}  (Scope: {'Unchanged' if s=='U' else 'Changed'})\n"
            f"  C={c}  (Confidentiality Impact: {'None' if c=='N' else 'Low' if c=='L' else 'High'})\n"
            f"  I={i}  (Integrity Impact: {'None' if i=='N' else 'Low' if i=='L' else 'High'})\n"
            f"  A={a}  (Availability Impact: {'None' if a=='N' else 'Low' if a=='L' else 'High'})\n"
        )
    except Exception as e:
        logger.error(f"calculate_cvss error: {e}")
        return f"[calculate_cvss error]: {e}"


def chain_all_findings(
    findings_json: str = "",
    target: str = "",
) -> str:
    """
    Analyze all confirmed and candidate findings to identify attack chain opportunities.

    Identifies which finding combinations create Critical-severity chains worth
    significantly more than individual findings. Use this before final reporting
    to ensure you haven't missed a chain that upgrades Medium findings to Critical.

    Args:
        findings_json: JSON list of findings. Each finding should have:
                       {title: str, severity: str, category: str, endpoint: str}
                       (or pass empty string to analyze current session findings)
        target: Target hostname to filter findings from session (optional)

    Returns:
        Analysis of fully-chainable and partially-chainable attack chains
    """
    try:
        from src.sdk.impact_amplifier import get_amplifier

        amplifier = get_amplifier()
        findings = []

        # Try to parse provided JSON
        if findings_json:
            try:
                findings = json.loads(findings_json)
            except json.JSONDecodeError:
                pass

        # Fall back to current session findings if no JSON provided
        if not findings:
            try:
                from src.sdk.finding_lifecycle import get_finding_lifecycle
                lc = get_finding_lifecycle()
                all_findings = lc.findings
                if target:
                    all_findings = [f for f in all_findings
                                    if target.lower() in (f.target or "").lower()]
                findings = [{"title": f.title, "category": f.category or "", "severity": f.severity}
                            for f in all_findings]
            except Exception:
                pass

        if not findings:
            return (
                "No findings provided and no findings in current session. "
                "Confirm findings first with promote_finding_with_evidence, then call chain_all_findings."
            )

        chains = amplifier.chain_from_findings(findings)

        if not chains:
            return (
                f"No chain opportunities detected across {len(findings)} finding(s). "
                "This could mean findings are isolated, or the finding types don't have known combination attacks."
            )

        lines = [
            f"═══ ATTACK CHAIN ANALYSIS — {len(findings)} Findings ═══",
            "",
        ]

        fully_chainable = [c for c in chains if "FULLY" in c["status"]]
        partial = [c for c in chains if "PARTIAL" in c["status"]]

        if fully_chainable:
            lines += [f"🔴 FULLY CHAINABLE ({len(fully_chainable)}) — All prerequisites confirmed:", ""]
            for ch in fully_chainable:
                lines += [
                    f"  ⚡ {ch['title']}",
                    f"     Combined Severity : {ch['combined_severity']}",
                    f"     Typical Bounty    : {ch['bounty_range']}",
                    f"     {ch['description']}",
                    "",
                ]

        if partial:
            lines += [f"🟡 PARTIAL CHAINS ({len(partial)}) — Close to Critical:", ""]
            for ch in partial:
                lines += [
                    f"  🔍 {ch['title']}",
                    f"     Status         : {ch['status']}",
                    f"     Combined Severity: {ch['combined_severity']}",
                    f"     {ch['description']}",
                    "",
                ]

        lines += [
            "─── NEXT STEP ───",
            "For FULLY CHAINABLE chains: document the chain in your report and upgrade severity.",
            "For PARTIAL chains: the 'requires_also' component is your highest-priority next test.",
        ]

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"chain_all_findings error: {e}")
        return f"[chain_all_findings error]: {e}"


def suggest_next_escalation(
    confirmed_findings_summary: str,
    current_severity: str = "medium",
) -> str:
    """
    Given a summary of what's been confirmed so far, suggest the single most
    valuable next escalation test to run.

    Use this when you're not sure what to do next after finding something.
    It analyzes all confirmed findings holistically and suggests the ONE test
    most likely to upgrade severity or create a chain.

    Args:
        confirmed_findings_summary: Brief text describing what's been confirmed
                                    e.g., "Reflected XSS on /search, CORS on /api/profile"
        current_severity: The highest severity found so far (critical/high/medium/low)

    Returns:
        Single highest-value next step with rationale
    """
    try:
        from src.sdk.impact_amplifier import get_amplifier, _ESCALATION_RECIPES, _CHAIN_MATRIX

        summary_lower = confirmed_findings_summary.lower()
        amplifier = get_amplifier()

        # Detect all finding types mentioned
        detected: list[str] = []
        for alias, key in amplifier._alias_map.items():
            if alias in summary_lower:
                if key not in detected:
                    detected.append(key)

        if not detected:
            return (
                "Could not detect specific finding types in the summary. "
                "Please describe what you've confirmed: e.g., 'Reflected XSS on /search, CORS on /api/profile'. "
                "Fallback recommendation: Run chain_all_findings with your actual finding objects."
            )

        # Check for complete chains first
        detected_set = set(detected)
        for chain in _CHAIN_MATRIX:
            if set(chain["requires"]).issubset(detected_set):
                return (
                    f"✅ CHAIN ALREADY COMPLETABLE: {chain['title']}\n"
                    f"Combined Severity: {chain['combined_severity']} — {chain['bounty_range']}\n"
                    f"Action: Document this chain in your report and upgrade severity to {chain['combined_severity']}.\n"
                    f"Description: {chain['description']}"
                )

        # Find best partial chain completion
        best_chain = None
        best_overlap = 0
        for chain in _CHAIN_MATRIX:
            overlap = len(set(chain["requires"]) & detected_set)
            if overlap > best_overlap:
                best_overlap = overlap
                best_chain = chain

        if best_chain and best_overlap >= 1:
            missing = set(best_chain["requires"]) - detected_set
            return (
                f"🎯 HIGHEST-VALUE NEXT TEST:\n"
                f"You are {best_overlap}/{len(best_chain['requires'])} of the way to: {best_chain['title']}\n"
                f"Combined Severity would be: {best_chain['combined_severity']} ({best_chain['bounty_range']})\n\n"
                f"Missing: Confirm {', '.join(missing)} to complete this chain.\n\n"
                f"Chain description: {best_chain['description']}"
            )

        # Fall back to top escalation for the first detected type
        result = amplifier.amplify(detected[0], current_severity, top_n=1)
        if result.escalation_steps:
            step = result.escalation_steps[0]
            return (
                f"🎯 TOP ESCALATION FOR {detected[0].upper()}:\n"
                f"{step.title}\n"
                f"Expected Severity : {step.expected_severity}\n"
                f"Typical Bounty    : {step.bounty_range}\n"
                f"Test              : {step.test}\n"
                f"Tool              : {step.tool or 'manual HTTP test'}\n"
                f"Rationale         : {step.rationale}"
            )

        return "No specific escalation identified. Focus on proving data extraction or privilege escalation impact."

    except Exception as e:
        logger.error(f"suggest_next_escalation error: {e}")
        return f"[suggest_next_escalation error]: {e}"
