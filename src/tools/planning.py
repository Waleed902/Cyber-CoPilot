"""
Attack Planning Tools for Agents
Provides tools for attack planning and vulnerability chaining
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import urllib
import urllib.parse

from src.sdk.tool import function_tool
from src.sdk.attack_planner import (
    get_attack_planner, 
    suggest_attack_plan, 
    suggest_next_action,
    get_exploit_chain_for,
    Vulnerability,
    # Phase 4 — Exploit Chain Engine
    get_chain_engine,
)

# ---------------------------------------------------------------------------
# Vulnerability Knowledge Base loader
# ---------------------------------------------------------------------------

_KB_PATH = Path(__file__).resolve().parents[2] / "data" / "vuln_knowledge_base.json"
_KB_CACHE: Optional[Dict] = None


def _load_kb() -> Dict:
    """Load (and cache) the vulnerability knowledge base from disk."""
    global _KB_CACHE
    if _KB_CACHE is not None:
        return _KB_CACHE
    try:
        with open(_KB_PATH, "r", encoding="utf-8") as fh:
            _KB_CACHE = json.load(fh)
    except FileNotFoundError:
        _KB_CACHE = {"vulnerabilities": []}
    assert _KB_CACHE is not None
    return _KB_CACHE


def _get_vuln_entry(vuln_id: str) -> Optional[Dict]:
    """Return a single vuln entry by ID (exact or case-insensitive partial match)."""
    kb = _load_kb()
    vuln_id_norm = vuln_id.lower().replace(" ", "_").replace("-", "_")
    # Exact match first
    for v in kb.get("vulnerabilities", []):
        if v["id"] == vuln_id_norm:
            return v
    # Partial match
    for v in kb.get("vulnerabilities", []):
        if vuln_id_norm in v["id"] or vuln_id_norm in v["name"].lower().replace(" ", "_"):
            return v
    return None


@function_tool()
def plan_attack(target_type: str = "") -> str:
    """
    Generate an attack plan based on target type.
    Use this to get a structured attack methodology.
    
    Args:
        target_type: Type of target (web_application, windows_domain, linux_server, network_internal)
                    Leave empty to auto-detect based on discovered services.
    
    Returns:
        Structured attack plan with phases and recommended tools
    """
    # If caller omitted target_type, make a best-effort guess from current target.
    # This prevents early-session misclassification when no services are registered yet.
    inferred: str | None = None
    try:
        import ipaddress
        from src.sdk.context_hub import get_context_hub

        _t = (get_context_hub().current_target or "").strip()
        if _t:
            try:
                ip = ipaddress.ip_address(_t)
                if ip.is_private:
                    inferred = "network_internal"
            except ValueError:
                # Not a raw IP — leave to service-based auto-detection
                pass
    except Exception:
        inferred = None

    chosen = target_type.strip() if target_type and target_type.strip() else inferred

    # Guardrail: public IP + network_internal is almost always a mistaken plan selection.
    try:
        import ipaddress
        from src.sdk.context_hub import get_context_hub

        _t = (get_context_hub().current_target or "").strip()
        if chosen == "network_internal" and _t:
            try:
                ip = ipaddress.ip_address(_t)
                if not ip.is_private:
                    # Return a warning + a recommended web_application plan.
                    return (
                        "⚠️ Methodology mismatch: target looks like a public IP, but 'network_internal' was requested.\n"
                        "Defaulting to a web/internet-facing methodology unless you explicitly confirm this is an internal scope.\n\n"
                        + suggest_attack_plan("web_application")
                    )
            except ValueError:
                pass
    except Exception:
        pass

    return suggest_attack_plan(chosen or "")


@function_tool()
def get_next_action() -> str:
    """
    Get suggested next actions based on current attack state.
    Use this when unsure what to do next.
    
    Returns:
        Prioritized list of suggested actions with tools
    """
    return suggest_next_action()


@function_tool()
def chain_exploits(vulnerability: str) -> str:
    """
    Get an exploit chain starting from a vulnerability.
    Shows how to chain multiple exploits for maximum impact.
    
    Args:
        vulnerability: Starting vulnerability (e.g., sql_injection, zerologon, command_injection)
    
    Returns:
        Step-by-step exploit chain with tools and actions
    """
    return get_exploit_chain_for(vulnerability)


# Unvalidated vulnerability candidates waiting for PoC confirmation
_candidate_vulns: list = []
# Evidence registry: vuln_name -> list of evidence items (request/response, PoC output, screenshots)
_evidence_registry: dict = {}


@function_tool()
def register_vulnerability(name: str, severity: str, service: str = "",
                           port: int = 0, cve: str = "", validated: bool = False,
                           evidence: str = "") -> str:
    """
    Register a discovered vulnerability for attack planning.

    IMPORTANT — set validated=True ONLY when you have concrete evidence:
      • auto_validate() or multi_validate() returned a confirmed positive, OR
      • A manually executed PoC produced observable proof of exploitability, OR
      • A version-exact CVE match with a public, reliable PoC

    Calling without validated=True (the default) places the finding in a
    *candidate* (unconfirmed) list only.  It will NOT appear as a confirmed
    vulnerability and will NOT influence attack suggestions until re-registered
    as validated.

    REQUIRES evidence: When validated=True, you MUST provide an evidence
    string describing the concrete proof (PoC output, HTTP response, etc.).

    Args:
        name: Vulnerability name (e.g., sql_injection, xss, zerologon)
        severity: Severity level (critical, high, medium, low)
        service: Affected service name
        port: Affected port number
        cve: CVE identifier if known
        validated: Set True only after active PoC confirmation (default: False)
        evidence: Concrete proof description — PoC output, HTTP response, or validation result

    Returns:
        Confirmation and updated suggestions, or candidate-bucket notice
    """
    if not validated:
        _candidate_vulns.append({
            "name": name, "severity": severity, "service": service,
            "port": port, "cve": cve,
        })
        return (
            f"\U0001f4cb CANDIDATE (unvalidated): {name} ({severity}) added to pending list.\n\n"
            f"\u26a0\ufe0f  This has NOT been registered as a confirmed vulnerability.\n"
            f"Validate exploitability first, then re-register:\n"
            f"  1. Run auto_validate() or multi_validate() for this finding, OR\n"
            f"  2. Execute a PoC that produces concrete observable evidence\n\n"
            f"Then call: register_vulnerability(name='{name}', severity='{severity}', "
            f"service='{service}', port={port}, cve='{cve}', validated=True, "
            f"evidence='<your PoC output or validation result>')"
        )

    # ── Enforce evidence requirement for validated=True ──
    if not evidence or not evidence.strip():
        return (
            f"\u274c REJECTED: {name} ({severity})\n\n"
            f"\u26a0\ufe0f  validated=True REQUIRES concrete evidence.\n"
            f"You must provide an evidence string describing the proof.\n\n"
            f"Examples of acceptable evidence:\n"
            f"  - Output from auto_validate() showing CONFIRMED status\n"
            f"  - HTTP response body demonstrating exploitability\n"
            f"  - PoC command output showing successful exploitation\n"
            f"  - Screenshot or observable impact description\n\n"
            f"Re-call with: register_vulnerability(name='{name}', ..., "
            f"validated=True, evidence='<concrete proof>')"
        )

    # ── Cross-check with PoC validation results ──
    poc_confirmed = False
    try:
        from src.tools.poc_validation import get_validated_vulns
        for v in get_validated_vulns():
            if v.validated and v.vulnerability.lower() in name.lower():
                poc_confirmed = True
                break
    except Exception:
        pass

    # ── Check against candidate vulns (should have been candidate first) ──
    was_candidate = any(
        c["name"].lower() == name.lower() for c in _candidate_vulns
    )

    if not poc_confirmed and not was_candidate:
        return (
            f"\u274c REJECTED: {name} ({severity})\n\n"
            f"This finding was not previously registered as a candidate and no PoC "
            f"validation result was detected. Register it as a candidate first, then "
            f"validate with auto_validate(), multi_validate(), or a concrete PoC before "
            f"marking it confirmed."
        )
    else:
        warning = ""

    # ── Store evidence ──
    _evidence_registry.setdefault(name.lower(), []).append({
        "evidence": evidence,
        "timestamp": datetime.now().isoformat(),
        "service": service,
        "port": port,
    })

    planner = get_attack_planner()

    vuln = Vulnerability(
        name=name,
        severity=severity,
        service=service if service else None,
        port=port if port else None,
        cve=cve if cve else None,
        exploitable=True
    )

    planner.add_vulnerability(vuln)

    # ── Update Profile Manager so it persists for reports ──
    try:
        from src.repl.profiles import get_profile_manager
        from src.agents.orchestrator_agent import get_current_target
        pm = get_profile_manager()
        t = get_current_target()
        if t:
            pm.add_vulnerability(
                t,
                name=name,
                severity=severity,
                cve=cve,
                description=evidence[:500],
                verified=True,
            )
    except Exception:
        pass

    # ── Capture evidence in Evidence Collector ──
    try:
        from src.sdk.evidence import get_evidence_collector
        collector = get_evidence_collector()
        try:
            from src.agents.orchestrator_agent import get_current_target
            target = get_current_target() or "unknown"
        except Exception:
            target = "unknown"
        collector.capture_command_output(
            finding_type=name.lower(),
            title=f"Validated: {name}",
            command=f"register_vulnerability({name})",
            output=evidence,
            target=target,
            severity=severity.lower()
        )
    except Exception:
        pass

    # Get updated suggestions
    suggestions = planner.suggest_next_actions()

    lines = [
        f"\u2705 Registered: {name} ({severity})",
        f"\U0001f4ce Evidence recorded ({len(evidence)} chars)",
        ""
    ]
    if warning:
        lines.append(warning)
    lines.append("Updated attack suggestions:")

    for sugg in suggestions[:3]:
        lines.append(f"\u2022 {sugg['action']} - Tools: {', '.join(sugg['tools'])}")

    return "\n".join(lines)


@function_tool()
def register_service(port: int, service: str, version: str = "") -> str:
    """
    Register a discovered service for attack planning.
    Call this when nmap or other recon finds services.
    
    Args:
        port: Port number
        service: Service name (e.g., ssh, http, smb, ldap)
        version: Version string if known
    
    Returns:
        Confirmation and target profile update
    """
    planner = get_attack_planner()
    planner.add_service(port, service, version)
    
    profile = planner.detect_target_profile()
    
    return f"✅ Registered: {service} on port {port}\n📊 Target profile: {profile}"


@function_tool()
def attack_summary() -> str:
    """
    Get a summary of the current attack state.
    Shows discovered vulnerabilities, services, and profile.
    
    Returns:
        Attack state summary
    """
    planner = get_attack_planner()
    summary = planner.get_summary()
    
    # Add next suggestions
    suggestions = planner.suggest_next_actions()
    
    if suggestions:
        summary += "\n\n💡 Top Suggestions:\n"
        for sugg in suggestions[:3]:
            summary += f"• {sugg['action']}\n"
    
    return summary


@function_tool()
def generate_attack_plan() -> str:
    """
    Generate a comprehensive attack plan based on recon findings.
    Creates a detailed, step-by-step plan for presentation to the user.
    Call this after reconnaissance phase to plan the attack strategy.
    
    Returns:
        Detailed attack plan formatted for user review
    """
    planner = get_attack_planner()
    plan = planner.generate_detailed_plan()
    
    if not plan:
        return "⚠️ Insufficient reconnaissance data. Complete recon phase first."
    
    lines = [
        "╔═══════════════════════════════════════════════════════════════╗",
        "║              🎯 ATTACK PLAN - USER APPROVAL REQUIRED          ║",
        "╚═══════════════════════════════════════════════════════════════╝",
        "",
        f"📊 **Target Profile**: {plan['target_profile'].upper().replace('_', ' ')}",
        f"🔍 **Vulnerabilities Found**: {plan['vulns_found']}",
        f"🎖️ **Priority Level**: {plan['priority_level'].upper()}",
        "",
        "═══════════════════════════════════════════════════════════════",
        "## 📋 EXECUTIVE SUMMARY",
        "═══════════════════════════════════════════════════════════════",
        "",
        plan['summary'],
        "",
        "═══════════════════════════════════════════════════════════════",
        "## 🗺️ ATTACK PHASES",
        "═══════════════════════════════════════════════════════════════",
        ""
    ]
    
    for i, phase in enumerate(plan['phases'], 1):
        lines.append(f"### Phase {i}: {phase['name']}")
        lines.append(f"**Objective**: {phase['objective']}")
        lines.append(f"**Tools**: {', '.join(phase['tools'])}")
        lines.append(f"**Expected Outcome**: {phase['outcome']}")
        lines.append(f"**Risk Level**: {phase['risk']}")
        
        if phase.get('steps'):
            lines.append("\n**Steps**:")
            for j, step in enumerate(phase['steps'], 1):
                lines.append(f"  {j}. {step}")
        
        lines.append("")
    
    if plan.get('high_value_targets'):
        lines.append("═══════════════════════════════════════════════════════════════")
        lines.append("## 🎯 HIGH-VALUE TARGETS")
        lines.append("═══════════════════════════════════════════════════════════════")
        lines.append("")
        
        for target in plan['high_value_targets']:
            lines.append(f"• **{target['name']}** [{target['severity']}]")
            lines.append(f"  → Attack Vector: {target['vector']}")
            lines.append(f"  → Success Probability: {target['probability']}")
            lines.append("")
    
    if plan.get('risks'):
        lines.append("═══════════════════════════════════════════════════════════════")
        lines.append("## ⚠️ RISKS & CONSIDERATIONS")
        lines.append("═══════════════════════════════════════════════════════════════")
        lines.append("")
        for risk in plan['risks']:
            lines.append(f"⚠️ {risk}")
        lines.append("")
    
    lines.extend([
        "═══════════════════════════════════════════════════════════════",
        "## ✅ NEXT STEPS",
        "═══════════════════════════════════════════════════════════════",
        "",
        "This plan requires user approval before execution.",
        "",
        "To approve and execute: Type 'approve plan' or 'execute plan'",
        "To modify the plan: Provide specific changes",
        "To cancel: Type 'cancel plan' or 'reject plan'",
        "",
        "═══════════════════════════════════════════════════════════════",
    ])
    
    # Store the plan for execution
    planner.save_pending_plan(plan)
    
    return "\n".join(lines)


@function_tool()
def modify_attack_plan(phase: str, changes: str) -> str:
    """
    Modify a specific phase of the attack plan based on user feedback.
    
    Args:
        phase: Phase name or number to modify
        changes: Description of requested changes
    
    Returns:
        Updated plan section
    """
    planner = get_attack_planner()
    result = planner.modify_plan(phase, changes)
    
    if result:
        return f"✅ Plan modified: {changes}\n\nUpdated plan available. Review with 'show plan'"
    else:
        return "Error: No active plan to modify. Generate a plan first."


@function_tool()
def show_current_plan() -> str:
    """
    Display the current attack plan (pending or in-progress).
    
    Returns:
        Current attack plan details
    """
    planner = get_attack_planner()
    plan = planner.get_current_plan()
    
    if not plan:
        return "No active attack plan. Run 'generate_attack_plan()' first."
    
    status = plan.get('status', 'pending')
    
    lines = [
        f"📋 **Current Plan Status**: {status.upper()}",
        f"🎯 **Target**: {plan.get('target_profile', 'Unknown')}",
        "",
        "**Phases**:"
    ]
    
    for i, phase in enumerate(plan.get('phases', []), 1):
        phase_status = phase.get('status', 'pending')
        icon = "✅" if phase_status == "completed" else "🔄" if phase_status == "in-progress" else "⏸️"
        lines.append(f"{icon} Phase {i}: {phase['name']} - {phase_status}")
    
    return "\n".join(lines)


# ===========================================================================
# VULNERABILITY KNOWLEDGE BASE TOOLS
# Phase 2 — unified payload registry backed by data/vuln_knowledge_base.json
# ===========================================================================


@function_tool()
def list_vuln_types(category: str = "") -> str:
    """
    List all vulnerability types in the knowledge base, optionally filtered by category.

    Categories: Injection, Inspection, Authorization, Authentication, File_Access,
                Request_Forgery, Client_Side, Infrastructure, Business_Logic

    Args:
        category: Filter by category name (leave empty for all)

    Returns:
        Table of vuln IDs, names, severities and linked tools.
    """
    kb = _load_kb()
    vulns = kb.get("vulnerabilities", [])

    if category:
        cat_norm = category.lower().replace(" ", "_")
        vulns = [v for v in vulns if v["category"].lower().replace(" ", "_") == cat_norm]

    if not vulns:
        return "No vulnerability types found" + (f" in category '{category}'" if category else "") + "."

    # Group by category
    groups: Dict[str, List[Dict]] = {}
    for v in vulns:
        groups.setdefault(v["category"], []).append(v)

    lines = [f"## Vulnerability Knowledge Base ({len(vulns)} entries)\n"]
    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

    for cat, entries in groups.items():
        lines.append(f"### {cat.replace('_', ' ')} ({len(entries)})")
        for e in entries:
            icon = severity_icon.get(e["severity"], "⚪")
            tools_str = ", ".join(e.get("tools", [])[:3])
            lines.append(f"  {icon} `{e['id']}` — {e['name']} | CWE: {e['cwe']} | Tools: {tools_str}")
        lines.append("")

    return "\n".join(lines)


@function_tool()
def get_payloads(vuln_type: str, limit: int = 0) -> str:
    """
    Retrieve payloads for a specific vulnerability type from the knowledge base.

    Args:
        vuln_type: Vuln ID or name (e.g. 'sqli_error_based', 'xss_reflected', 'ssrf')
        limit:     Max number of payloads to return (0 = all)

    Returns:
        Payload list with WAF bypass techniques and the linked validation tool.
    """
    entry = _get_vuln_entry(vuln_type)
    if not entry:
        # Try to find similar
        kb = _load_kb()
        all_ids = [v["id"] for v in kb.get("vulnerabilities", [])]
        suggestions = [i for i in all_ids if vuln_type.lower() in i]
        hint = f"\nDid you mean: {', '.join(suggestions[:5])}" if suggestions else ""
        return f"❌ Unknown vuln type: '{vuln_type}'.{hint}\nUse list_vuln_types() to see all IDs."

    payloads = entry.get("payloads", [])
    if limit and limit > 0:
        payloads = payloads[:limit]

    bypass = entry.get("waf_bypass", [])
    tools  = entry.get("tools", [])
    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    icon = severity_icon.get(entry["severity"], "⚪")

    lines = [
        f"## Payloads: {entry['name']}",
        f"{icon} Severity: {entry['severity'].upper()} | CWE: {entry['cwe']} | Category: {entry['category']}",
        f"Proof method: `{entry['proof_method']}` | Tools: {', '.join(tools)}",
        "",
        "### Payloads",
    ]

    if payloads:
        for i, p in enumerate(payloads, 1):
            lines.append(f"  {i:2d}. {p}")
    else:
        lines.append("  (No static payloads — this type uses tool-generated probes)")

    if bypass:
        lines.append("")
        lines.append("### WAF Bypass Techniques")
        lines.append(f"  {', '.join(bypass)}")

    lines.append("")
    lines.append("### AI Guidance")
    lines.append(f"  {entry['ai_prompt']}")

    return "\n".join(lines)


@function_tool()
def get_vuln_info(vuln_id: str) -> str:
    """
    Get full knowledge base entry for a vulnerability type: description, CWE,
    severity, payloads, proof method, AI prompt, WAF bypass, and linked tools.

    Args:
        vuln_id: Vulnerability ID (e.g. 'ssrf', 'ssti', 'jwt_attack')

    Returns:
        Complete structured entry from the knowledge base.
    """
    entry = _get_vuln_entry(vuln_id)
    if not entry:
        return f"❌ Not found: '{vuln_id}'. Use list_vuln_types() to discover IDs."

    lines = [
        f"# {entry['name']}",
        f"**ID**: `{entry['id']}` | **CWE**: {entry['cwe']} | **Category**: {entry['category']}",
        f"**Severity**: {entry['severity'].upper()} | **Proof method**: `{entry['proof_method']}`",
        "",
        "## Payloads",
    ]
    payloads = entry.get("payloads", [])
    if payloads:
        for p in payloads:
            lines.append(f"  - {p}")
    else:
        lines.append("  (none — use linked tools)")

    lines += [
        "",
        "## WAF Bypass Techniques",
        f"  {', '.join(entry.get('waf_bypass', ['none']))}",
        "",
        "## Linked Tools",
        f"  {', '.join(entry.get('tools', ['none']))}",
        "",
        "## AI Validation Prompt",
        f"  {entry['ai_prompt']}",
    ]
    return "\n".join(lines)


@function_tool()
def search_vulns(query: str) -> str:
    """
    Search the vulnerability knowledge base by keyword.
    Searches ID, name, category, CWE, and AI prompt fields.

    Args:
        query: Search term (e.g. 'injection', 'authentication', 'CWE-79', 'csrf')

    Returns:
        Matching vulnerability entries.
    """
    kb = _load_kb()
    query_norm = query.lower()
    matched = []

    for v in kb.get("vulnerabilities", []):
        searchable = " ".join([
            v["id"], v["name"], v["category"],
            v["cwe"], v["ai_prompt"],
            " ".join(v.get("tools", []))
        ]).lower()
        if query_norm in searchable:
            matched.append(v)

    if not matched:
        return f"No results for '{query}'."

    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    lines = [f"## Search Results for '{query}' ({len(matched)} matches)\n"]
    for v in matched:
        icon = severity_icon.get(v["severity"], "⚪")
        lines.append(f"{icon} `{v['id']}` — **{v['name']}** ({v['severity'].upper()}) [{v['category']}]")
        lines.append(f"   CWE: {v['cwe']} | Proof: `{v['proof_method']}` | Tools: {', '.join(v.get('tools', [])[:3])}")
        lines.append("")
    return "\n".join(lines)


# ===========================================================================
# EXPLOIT CHAIN ENGINE TOOLS
# Phase 4 — multi-vuln chaining, MITRE ATT&CK tagging, risk scoring
# ===========================================================================


@function_tool()
def build_exploit_chain(vuln_ids: str) -> str:
    """
    Build exploit chains from a set of confirmed vulnerability IDs.

    Takes a comma-separated list of confirmed vulnerability IDs (from the
    vulnerability knowledge base) and computes all applicable multi-step exploit
    chains, ordered by severity and CVSS estimate. Each chain includes:
      - Ordered exploit steps with MITRE ATT&CK tactic/technique tags
      - Primary tool recommendations per step
      - Impact description and confidence score
      - Remediation recommendations

    Use this after confirming multiple vulnerabilities to understand how an
    attacker could chain them together for maximum impact.

    Args:
        vuln_ids: Comma-separated confirmed vulnerability IDs from the KB.
                  Examples: "ssrf,cloud_metadata" or "lfi,info_disclosure" or
                  "xss_stored,csrf,cors_misconfiguration"

    Returns:
        Full markdown report of all applicable exploit chains.
    """
    ids = [v.strip() for v in vuln_ids.split(",") if v.strip()]
    if not ids:
        return "No vulnerability IDs provided. Pass a comma-separated list (e.g. 'ssrf,cloud_metadata')."
    engine = get_chain_engine()
    chains = engine.compute_chains(ids)
    return engine.format_all(chains)


@function_tool()
def list_chain_templates() -> str:
    """
    List all known exploit chain templates in the Phase 4 Chain Engine.

    Returns a catalogue table showing every defined chain's ID, title,
    severity, and the vulnerability IDs that trigger it. Use this to
    understand what chains to look for during an engagement, or to plan
    which vulnerabilities to prioritise confirming.

    Returns:
        Markdown table of all chain templates with triggers.
    """
    return get_chain_engine().list_all_chain_templates()


@function_tool()
def score_attack_surface(vuln_ids: str) -> str:
    """
    Score the overall attack surface risk given a list of confirmed vulnerability IDs.

    Computes a chain-aware risk score by:
      1. Identifying all applicable exploit chains
      2. Weighting each chain by its CVSS estimate and confidence
      3. Classifying overall risk as CRITICAL / HIGH / MEDIUM-HIGH / MEDIUM / LOW
      4. Listing the top 5 priority chains to address first

    Use this to produce a concise executive-level risk summary after confirming
    multiple findings.

    Args:
        vuln_ids: Comma-separated confirmed vulnerability IDs from the KB.
                  Example: "sqli_union_based,file_upload,info_disclosure"

    Returns:
        Risk score summary with priority chain list.
    """
    ids = [v.strip() for v in vuln_ids.split(",") if v.strip()]
    if not ids:
        return "No vulnerability IDs provided."
    return get_chain_engine().score_attack_surface(ids)


# =============================================================================
# Phase 5 — Cross-Scan Learning tools
# =============================================================================

from src.sdk.context_hub import get_scan_memory


@function_tool()
def record_scan_findings(
    target: str,
    tech_stack: str,
    scan_type: str,
    vulns_json: str,
    tools_used: str,
    waf_detected: str = "",
    chains_triggered: str = "",
    notes: str = "",
) -> str:
    """
    Persist the findings of a completed scan to the cross-scan learning history.

    Call this tool at the end of every engagement so future scans against similar
    targets can benefit from historical data. Data is saved to
    data/execution_history.json and queried by `get_tool_recommendations`,
    `what_worked_before`, and `scan_history_stats`.

    Args:
        target:           Target hostname or IP (e.g. "target.com" or "10.10.10.5")
        tech_stack:       Comma-separated detected technologies
                          (e.g. "PHP,MySQL,WordPress,Apache")
        scan_type:        One of: web_application, linux_server, windows_domain,
                          api, network, iot, mobile
        vulns_json:       JSON array of finding dicts. Each dict should contain:
                          vuln_id, severity, tool, payload (optional),
                          validated (bool), validation_score (0-100), endpoint
                          Example: '[{"vuln_id":"sqli_error_based","severity":"critical",
                          "tool":"sqlmap_attack","payload":"'"'"' OR 1=1--",
                          "validated":true,"validation_score":90,"endpoint":"/login"}]'
        tools_used:       Comma-separated list of every tool executed
                          (e.g. "nmap_scan,sqlmap_attack,dalfox_scan")
        waf_detected:     WAF vendor name if detected; leave empty if none
        chains_triggered: Comma-separated chain IDs that fired (from build_exploit_chain)
        notes:            Optional free-text notes about the engagement

    Returns:
        Confirmation message with the assigned scan_id.
    """
    import json as _json
    try:
        vulns = _json.loads(vulns_json) if vulns_json.strip() else []
    except Exception as e:
        return f"vulns_json parse error: {e}. Provide a valid JSON array."

    techs = [t.strip() for t in tech_stack.split(",") if t.strip()]
    tools = [t.strip() for t in tools_used.split(",") if t.strip()]
    chains = [c.strip() for c in chains_triggered.split(",") if c.strip()]

    scan_id = get_scan_memory().record_scan(
        target=target,
        tech_stack=techs,
        scan_type=scan_type,
        vulns_found=vulns,
        tools_executed=tools,
        waf_detected=waf_detected,
        chains_triggered=chains,
        notes=notes,
    )
    return (
        f"Scan recorded successfully.\n"
        f"  scan_id   : {scan_id}\n"
        f"  target    : {target}\n"
        f"  tech_stack: {', '.join(techs) or 'none'}\n"
        f"  vulns     : {len(vulns)} ({sum(1 for v in vulns if v.get('validated'))} validated)\n"
        f"  tools     : {len(tools)}\n"
        f"  chains    : {len(chains)}\n\n"
        f"Use `scan_history_stats` to review aggregate metrics across all scans."
    )


@function_tool()
def get_tool_recommendations(tech_stack: str, scan_type: str = "") -> str:
    """
    Recommend the most effective tools for a target based on cross-scan learning history.

    Queries execution_history.json to find which tools have historically produced
    *validated* vulnerability findings against similar technology stacks and/or
    scan types. Returns a ranked list with hit counts.

    Use this at the START of a new engagement, after recon reveals the tech stack,
    to prioritise which offensive tools to run first.

    Args:
        tech_stack:  Technology stack tokens to match against history.
                     Can be a comma-separated list or plain text.
                     Examples: "PHP,MySQL", "WordPress", "IIS .NET MSSQL"
        scan_type:   (Optional) Filter by scan type: web_application, linux_server,
                     windows_domain, api, network.  Leave empty to search all types.

    Returns:
        Ranked tool recommendation table with confirmed hit counts and vuln types.
    """
    return get_scan_memory().recommend_tools(tech_stack, scan_type)


@function_tool()
def what_worked_before(vuln_type: str) -> str:
    """
    Retrieve the payloads and tools that have historically confirmed a specific
    vulnerability type in past engagements.

    Searches execution_history.json for all validated findings matching
    `vuln_type` and returns the best tools, most successful payloads, tech stacks
    where the vuln was found, and recent occurrence details.

    Use this before attacking a suspected vulnerability to avoid rediscovering
    working techniques from scratch.

    Args:
        vuln_type: Vulnerability type ID to search for. Use IDs from the KB
                   (list_vuln_types / get_vuln_info) or natural substrings such as:
                   "sqli", "sqli_error_based", "xss", "xss_reflected",
                   "rce", "lfi", "ssrf", "open_redirect", "idor", "ssti"

    Returns:
        Historical win report: best tools, working payloads, affected tech stacks,
        and recent occurrences.
    """
    return get_scan_memory().what_worked_before(vuln_type)


@function_tool()
def scan_history_stats() -> str:
    """
    Display aggregate statistics across all recorded engagements in
    execution_history.json.

    Provides a comprehensive overview including:
     - Total scans, vulns found, validated vuln count, tool call volume
     - Top vulnerability types by frequency
     - Most-executed tools
     - Technology stacks encountered most often
     - WAFs detected and their frequency
     - Exploit chains that fired
     - Scan type distribution
     - Severity breakdown

    Use this to review the knowledge base, identify coverage gaps, or brief a
    team on intelligence gathered across all past engagements.

    Returns:
        Full markdown statistics report.
    """
    return get_scan_memory().scan_history_stats()

# =============================================================================
# Phase 6 — Graph Topology APIs
# =============================================================================

@function_tool()
def query_attack_paths(start_node: str, target_node: str) -> str:
    """
    Query the Intelligence Attack Graph for known exploit paths between two nodes.
    
    The graph correlates fragmented discoveries (e.g., SSRF on Web, Open AWS Metadata)
    into contiguous exploit chains. Use this to determine if a path exists from your
    current foothold to the target objective.
    
    Args:
        start_node: The boundary you control (e.g., "Internet", "Web Server", "10.10.10.5")
        target_node: The objective boundary (e.g., "AWS Account", "Internal DB")

    Returns:
        Formatted chain of findings required to traverse the path, or a notice if no path exists.
    """
    from src.repl.session import global_session

    paths = global_session.attack_graph.get_attack_paths(start_node, target_node)

    if not paths:
        return f"No known attack paths discovered yet from '{start_node}' to '{target_node}'."

    lines = [f"## Attack Paths: {start_node} ➔ {target_node}\n"]

    for i, path in enumerate(paths, 1):
        lines.append(f"### Path {i} ({len(path)} steps)")
        for j, finding in enumerate(path, 1):
            severity = finding.severity.name if hasattr(finding.severity, "name") else str(finding.severity)
            lines.append(f"  {j}. [{severity}] {finding.description} (via {finding.tool})")
            if finding.evidence:
                lines.append(f"     Evidence: {finding.evidence[:80]}")
        lines.append("")

    return "\n".join(lines)


# ===========================================================================
# WORKFLOW ORCHESTRATION TOOLS
# Auto-triage, auto-bypass, and auto-fallback — closes the gaps from sessions
# ===========================================================================


@function_tool()
async def nuclei_scan_and_triage(target: str, severity: str = "critical,high,medium") -> str:
    """
    Run a nuclei vulnerability scan AND automatically triage the results.
    This is the RECOMMENDED nuclei workflow — never run nuclei_scan alone.

    Combines:
      1. nuclei_scan(target, severity=...) — vulnerability scanning
      2. nuclei_triage(output) — automated categorization and prioritization

    Args:
        target: Target URL or IP (e.g. https://example.com)
        severity: Severity filter (default: critical,high,medium)

    Returns:
        Combined scan output + triage report with prioritized findings
    """
    results = [f"## Nuclei Scan + Triage: {target}\n"]
    results.append("=" * 60)

    # Step 1: Run nuclei scan
    results.append("\n### Phase 1: Vulnerability Scan")
    try:
        from src.tools.exploitation import nuclei_scan
        scan_output = await nuclei_scan.invoke(target=target, severity=severity)
        results.append(scan_output)
    except Exception as e:
        return f"Error running nuclei_scan: {e}"

    # Check if there were no findings
    if "no findings" in scan_output.lower() or "nuclei scan complete: no findings" in scan_output.lower():
        results.append("\n### Phase 2: Triage")
        results.append("\u2705 No findings to triage — target appears clean at this severity level")
        results.append("\nRecommendations:")
        results.append(f"  • Try lower severity: nuclei_scan_and_triage('{target}', 'low,info')")
        results.append("  • Try authenticated scan if you have credentials")
        results.append("  • Move to manual testing of specific endpoints")
        return "\n".join(results)

    # Step 2: Auto-triage
    results.append("\n\n### Phase 2: Automated Triage")
    try:
        from src.tools.exploitation import nuclei_triage
        triage_output = await nuclei_triage.invoke(nuclei_output=scan_output, min_severity="medium")
        results.append(triage_output)
    except Exception as e:
        results.append(f"\n\u26a0\ufe0f Triage failed: {e}")
        results.append("Review scan output manually above")

    return "\n".join(results)


@function_tool()
async def dir_enum_with_bypass(url: str, threads: int = 10, depth: int = 2) -> str:
    """
    Directory/endpoint enumeration WITH automatic follow-up on 403/429 responses.

    Workflow:
      1. feroxbuster_scan — standard directory brute-force
      2. If 403 responses found → auto-trigger http_fuzz with WAF bypass headers
      3. If 429 responses found → auto-trigger waf_bypass_payloads
      4. Consolidated report of real findings

    This prevents the common mistake of ignoring 403 results that may be
    accessible with proper headers or authentication.

    Args:
        url: Target URL (e.g. https://target.com)
        threads: Number of feroxbuster threads (default 10)
        depth: Recursion depth (default 2)

    Returns:
        Consolidated directory enumeration results with bypass attempts
    """
    results = [f"## Directory Enumeration + Bypass: {url}\n"]
    results.append("=" * 60)

    # Step 1: Run feroxbuster
    results.append("\n### Phase 1: Directory Enumeration (feroxbuster)")
    try:
        from src.tools.recon_active import feroxbuster_scan
        ferox_output = await feroxbuster_scan.invoke(url=url, threads=threads, depth=depth)
        results.append(ferox_output)
    except Exception as e:
        return f"Error running feroxbuster: {e}"

    # Parse feroxbuster output for 403/429 responses
    paths_403 = re.findall(r'\[403\]\s+(https?://\S+)', ferox_output)
    paths_429 = re.findall(r'\[429\]\s+(https?://\S+)', ferox_output)
    paths_200 = re.findall(r'\[200\]\s+(https?://\S+)', ferox_output)

    # Check for wildcard detection
    has_wildcard = "WILDCARD" in ferox_output.upper() or "CATCHALL" in ferox_output.upper()
    if has_wildcard:
        results.append("\n\u26a0\ufe0f Wildcard/catchall detected — 403/429 results may be unreliable")

    # Step 2: Auto-follow-up on 403 responses
    if paths_403:
        results.append(f"\n\n### Phase 2: Bypass Testing on {len(paths_403)} Forbidden Paths")
        results.append("Attempting to access 403-protected endpoints with bypass techniques\n")

        bypass_results = []
        for path_403 in paths_403[:10]:  # Limit to first 10 to avoid excessive requests
            try:
                import urllib.error
                import urllib.request

                bypass_headers = {
                    "User-Agent": "Mozilla/5.0",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Custom-IP-Authorization": "127.0.0.1",
                }
                req = urllib.request.Request(path_403, headers=bypass_headers, method="GET")
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        body = resp.read(500).decode("utf-8", errors="replace")
                        fuzz_output = f"HTTP {resp.status}\n{body}"
                except urllib.error.HTTPError as http_err:
                    body = http_err.read(500).decode("utf-8", errors="replace")
                    fuzz_output = f"HTTP {http_err.code}\n{body}"
                bypass_results.append((path_403, fuzz_output))
            except Exception as e:
                bypass_results.append((path_403, f"Error: {e}"))

        # Summarize bypass attempts
        results.append("#### Bypass Results Summary")
        for path_403, bypass_output in bypass_results:
            if "HTTP 200" in bypass_output and "Error" not in bypass_output[:50]:
                results.append(f"  \ud83d\udd13 BYPASSED: {path_403} â€” accessible with bypass headers!")
                results.append(f"    {bypass_output[:200]}")
            elif "HTTP 403" in bypass_output:
                results.append(f"  \u274c Still forbidden: {path_403}")
            else:
                results.append(f"  \u26a0\ufe0f  {path_403} â€” {bypass_output[:100]}")

        if len(paths_403) > 10:
            results.append(f"\n  ... and {len(paths_403) - 10} more 403 paths not tested")
    else:
        results.append("\n### Phase 2: No 403 Responses to Bypass")

    # Step 3: Auto-follow-up on 429 responses (rate limiting)
    if paths_429:
        results.append(f"\n\n### Phase 3: Rate Limit Testing ({len(paths_429)} rate-limited paths)")
        results.append("Testing if 429 responses are genuine rate limits or WAF blocks\n")

        try:
            from src.tools.http_evasion import waf_bypass_payloads
            waf_output = await waf_bypass_payloads.invoke(vuln_type="rate_limit", waf_name="generic")
            results.append(waf_output)
        except Exception as e:
            results.append(f"WAF bypass check failed: {e}")
    elif "429" in ferox_output:
        # 429 detected but not as a path â€” might be global rate limiting
        results.append("\n### Phase 3: Rate Limiting Detected")
        results.append("\u26a0\ufe0f  Target returned 429 (Too Many Requests) during enumeration")
        results.append("Recommendation: Reduce request rate, add delays, or use proxy rotation")

    # Summary
    results.append("\n\n### Final Summary")
    results.append(f"  Paths with 200 OK: {len(paths_200)}")
    results.append(f"  Paths with 403 Forbidden: {len(paths_403)}")
    results.append(f"  Paths with 429 Rate Limited: {len(paths_429)}")
    results.append(f"  Bypass attempts: {len(paths_403[:10])}")

    return "\n".join(results)


@function_tool()
async def auto_param_scan(url: str, scan_types: str = "sqli,xss,ssrf,path_traversal") -> str:
    """
    Automated parameter discovery + vulnerability scanning workflow.

    Solves the problem of calling injection tools on URLs without parameters.

    Workflow:
      1. arjun_scan — discover hidden GET/POST parameters
      2. If URL already has params, use those
      3. Run requested vulnerability scanners against discovered params
      4. Consolidated report with actionable findings

    Args:
        url: Target URL (e.g. https://target.com/page or https://api.target.com/v1/data)
        scan_types: Comma-separated scan types: sqli, xss, ssrf, path_traversal,
                    command_injection, open_redirect, cors (default: sqli,xss,ssrf,path_traversal)

    Returns:
        Combined parameter discovery + vulnerability scan results
    """
    results = [f"## Auto Parameter Scan: {url}\n"]
    results.append("=" * 60)

    parsed = urllib.parse.urlparse(url)
    url_params = dict(urllib.parse.parse_qsl(parsed.query))

    # Step 1: Discover parameters
    results.append("\n### Phase 1: Parameter Discovery")

    discovered_params = list(url_params.keys())

    if not discovered_params:
        results.append("  No URL query parameters found — running arjun_scan...")
        try:
            from src.tools.web import arjun_scan
            arjun_output = await arjun_scan.invoke(url=url)
            # Extract parameters from arjun output
            arjun_params = re.findall(r'(?:Parameter|Param)\s*[:\s]+(\w+)', arjun_output)
            if arjun_params:
                discovered_params = arjun_params
                results.append(f"  ✅ Discovered parameters: {', '.join(discovered_params)}")
            else:
                results.append("  \u26a0\ufe0f arjun found no parameters")
        except Exception as e:
            results.append(f"  \u26a0\ufe0f arjun_scan failed: {str(e)[:80]}")
    else:
        results.append(f"  Found {len(discovered_params)} URL parameters: {', '.join(discovered_params)}")

    if not discovered_params:
        results.append("\n\u274c No parameters discovered. Cannot proceed with injection testing.")
        results.append("Recommendations:")
        results.append("  • Use feroxbuster_scan to find endpoints with parameters")
        results.append("  • Use js_endpoint_extractor to find API endpoints from JavaScript")
        results.append("  • Test POST endpoints with browser_extract_forms first")
        return "\n".join(results)

    # Step 2: Run requested scanners
    scan_list = [s.strip().lower() for s in scan_types.split(",")]
    results.append(f"\n### Phase 2: Vulnerability Scanning ({len(scan_list)} types)")

    for scan_type in scan_list:
        results.append(f"\n{'─' * 40}")
        results.append(f"#### {scan_type.upper()}")

        try:
            if scan_type in ("sqli", "sql"):
                from src.tools.appsec.sqli import sqli_scanner
                # sqli_scanner auto-tests all params if parameter=""
                scan_output = await sqli_scanner.invoke(url=url, parameter="")
                results.append(scan_output[:1000])  # Truncate to avoid overflow

            elif scan_type in ("xss", "cross-site-scripting"):
                from src.tools.appsec.xss import xss_scanner
                scan_output = await xss_scanner.invoke(url=url, parameter="")
                results.append(scan_output[:1000])

            elif scan_type == "ssrf":
                from src.tools.appsec.ssrf import ssrf_scanner
                # SSRF needs a specific parameter - test first discovered param
                test_param = discovered_params[0] if discovered_params else ""
                if test_param:
                    scan_output = await ssrf_scanner.invoke(url=url, parameter=test_param)
                    results.append(f"  Testing parameter: {test_param}")
                    results.append(scan_output[:1000])
                else:
                    results.append("  \u26a0\ufe0f No parameters to test for SSRF")

            elif scan_type in ("path_traversal", "lfi", "path"):
                from src.tools.appsec.path_traversal import path_traversal_scanner
                # Test first file-like parameter
                file_keywords = ['file', 'path', 'doc', 'page', 'include', 'load', 'src', 'read']
                file_param = None
                for kw in file_keywords:
                    for p in discovered_params:
                        if kw in p.lower():
                            file_param = p
                            break
                    if file_param:
                        break

                if file_param:
                    scan_output = await path_traversal_scanner.invoke(url=url, parameter=file_param)
                    results.append(f"  Testing parameter: {file_param}")
                    results.append(scan_output[:1000])
                else:
                    results.append(f"  \u26a0\ufe0f No file-related parameters found in: {', '.join(discovered_params)}")
                    results.append(f"  Testing first parameter anyway: {discovered_params[0]}")
                    scan_output = await path_traversal_scanner.invoke(url=url, parameter=discovered_params[0])
                    results.append(scan_output[:1000])

            elif scan_type == "command_injection":
                from src.tools.appsec.cmd_injection import command_injection_scanner
                test_param = discovered_params[0] if discovered_params else ""
                if test_param:
                    scan_output = await command_injection_scanner.invoke(url=url, parameter=test_param)
                    results.append(scan_output[:1000])
                else:
                    results.append("  \u26a0\ufe0f No parameters to test")

            elif scan_type in ("open_redirect", "redirect"):
                from src.tools.appsec.open_redirect import open_redirect_scan
                scan_output = await open_redirect_scan.invoke(url=url)
                results.append(scan_output[:1000])

            elif scan_type in ("cors",):
                from src.tools.web import cors_scan
                scan_output = await cors_scan.invoke(url=url)
                results.append(scan_output[:1000])

            else:
                results.append(f"  \u26a0\ufe0f Unknown scan type: {scan_type}")
                results.append("  Supported: sqli, xss, ssrf, path_traversal, command_injection, open_redirect, cors")

        except Exception as e:
            results.append(f"  \u274c {scan_type.upper()} scan error: {str(e)[:200]}")

    # Summary
    results.append("\n\n### Final Summary")
    results.append(f"  Parameters discovered: {len(discovered_params)} — {', '.join(discovered_params)}")
    results.append(f"  Scan types attempted: {len(scan_list)} — {', '.join(scan_list)}")
    results.append("\n  Review findings above for any confirmed vulnerabilities.")
    results.append("  For confirmed findings, call: register_vulnerability(name='...', validated=True, evidence='...')")

    return "\n".join(results)


@function_tool()
def record_ctf_solution(
    challenge_name: str,
    category: str,
    techniques: str,
    working_commands: str,
    notes: str = "",
    files_involved: str = ""
) -> str:
    """
    Record a successful CTF challenge solution to the cross-challenge knowledge base.
    
    This helps in future challenges of a similar type by storing the techniques,
    commands, and tips that actually worked.
    
    Args:
        challenge_name: Name of the challenge (e.g. "warmup", "pwn101")
        category:       Category (pwn, rev, web, crypto, forensics, steg, misc)
        techniques:     Comma-separated list of techniques used (e.g. "ret2libc, bof")
        working_commands: Comma-separated list of actual commands/payloads that worked
        notes:          Tips or tricky parts to remember for next time
        files_involved: Comma-separated list of file names/hashes
        
    Returns:
        Confirmation with assigned challenge_id.
    """
    from src.sdk.context_hub import get_ctf_history
    
    techs = [t.strip() for t in techniques.split(",") if t.strip()]
    cmds = [c.strip() for c in working_commands.split(",") if c.strip()]
    files = [f.strip() for f in files_involved.split(",") if f.strip()]
    
    challenge_id = get_ctf_history().record_solution(
        challenge_name=challenge_name,
        category=category,
        techniques=techs,
        working_commands=cmds,
        notes=notes,
        files_involved=files
    )
    
    return (
        f"✅ CTF Solution recorded successfully!\n"
        f"  Challenge ID: {challenge_id}\n"
        f"  Name: {challenge_name}\n"
        f"  Category: {category}\n"
        f"  Techniques: {', '.join(techs)}\n\n"
        f"This knowledge will be available for future challenges via `get_ctf_tips`."
    )


@function_tool()
def get_ctf_tips(category: str = "", keywords: str = "") -> str:
    """
    Query the historical CTF knowledge base for tips and techniques that worked before.

    Args:
        category: Filter by category (e.g. "pwn", "steg")
        keywords: Search terms (e.g. "buffer overflow", "zsteg", "blind")

    Returns:
        Markdown report of matching historical tips and working commands.
    """
    from src.sdk.context_hub import get_ctf_history
    return get_ctf_history().query_tips(category=category, keywords=keywords)


@function_tool()
def recall_ctf_similar(challenge_description: str, category: str = "") -> str:
    """
    Recall semantically similar past CTF solutions from vector memory.

    Call this at the START of any challenge — before running any analysis tool —
    to check whether the framework has already solved a similar challenge.
    If it has, the techniques and solve commands are returned immediately so you
    can try the same approach first instead of re-discovering it from scratch.

    Uses ChromaDB semantic similarity (not keyword matching) so it finds
    "XOR cipher with rolling key" even if you describe it as "repeating key encryption."
    Falls back to keyword search if vector memory is unavailable.

    Args:
        challenge_description: Free-text description of the current challenge.
                               Include observable properties: file type, observed
                               output, flag format, algorithm hints, error messages.
                               Example: "ELF64 binary checks 32-char input byte by byte
                                         with XOR and compares against hardcoded array"
        category:              CTF category hint: "rev", "pwn", "crypto", "web",
                               "forensics", "steg", "misc", or "" to search all.

    Returns:
        Structured recall of the most similar past solutions, or a message
        indicating no history exists yet.
    """
    from src.sdk.context_hub import get_ctf_history
    history = get_ctf_history()

    lines: list[str] = []

    # 1. Semantic search via ChromaDB (preferred)
    semantic_results = history.semantic_search(challenge_description, category=category, limit=5)
    if semantic_results:
        lines.append(f"[RECALL] Found {len(semantic_results)} semantically similar past solution(s):")
        lines.append("")
        for i, r in enumerate(semantic_results, 1):
            content = r.get("content", "")
            meta = r.get("metadata", {}) or {}
            dist = r.get("distance", 1.0)
            similarity = max(0, round((1.0 - dist) * 100))
            name = meta.get("challenge_name", "unknown")
            cat = meta.get("ctf_category", "?")
            techs_raw = meta.get("techniques", "[]")
            try:
                import json as _json
                techs = ", ".join(_json.loads(techs_raw)) or "—"
            except Exception:
                techs = techs_raw or "—"
            lines.append(f"  ── Match #{i} (similarity ~{similarity}%) [{cat.upper()}] {name} ──")
            lines.append(f"    Techniques: {techs}")
            # Extract commands and notes from stored content
            for ln in content.splitlines():
                if ln.startswith("Notes:") or ln.startswith("Commands:"):
                    lines.append(f"    {ln}")
            lines.append("")

        lines.append("Suggested approach: try the techniques from Match #1 first.")
        lines.append("If they fail, fall back to standard analysis (binary_triage → strings → decompile).")
        return "\n".join(lines)

    # 2. Fallback: keyword search
    kw_result = history.query_tips(category=category, keywords=challenge_description[:120])
    if "No historical matches" not in kw_result and "No CTF history" not in kw_result:
        return "[RECALL — keyword fallback]\n" + kw_result

    return (
        "[RECALL] No similar past solutions found.\n"
        "This is a new challenge type — proceed with standard analysis.\n"
        "After solving, call record_ctf_solution() so future challenges benefit from this run."
    )


@function_tool()
def save_target_credential(username: str, password: str = "", cookie: str = "", source: str = "") -> str:
    """
    Save discovered credentials or session cookies to the target profile.
    This ensures credentials persist across sessions.
    
    Args:
        username: Username or email (or 'session_cookie')
        password: Password (or token/cookie value)
        cookie: Session cookie (optional)
        source: Where it was found or provided
        
    Returns:
        Confirmation message
    """
    from src.sdk.context_hub import get_context_hub
    from src.repl.profiles import get_profile_manager
    target = get_context_hub().current_target
    if not target:
        return "Failed: No active target set."
    
    pm = get_profile_manager()
    # Handle cookie vs password
    if cookie and not password:
        password = cookie
    pm.add_credential(target, username=username, password=password, source=source)
    return f"✅ Successfully saved credential for '{username}' to {target} profile."

@function_tool()
def save_target_scope(scope_details: str) -> str:
    """
    Save Bugcrowd, HackerOne, or custom scope definitions to the target profile.
    
    Args:
        scope_details: Full text of the scope definition
        
    Returns:
        Confirmation message
    """
    from src.sdk.context_hub import get_context_hub
    from src.repl.profiles import get_profile_manager
    target = get_context_hub().current_target
    if not target:
        return "Failed: No active target set."
    
    pm = get_profile_manager()
    pm.add_note(target, note=f"SCOPE DEFINITION:\n{scope_details}", category="scope")
    return f"✅ Successfully saved scope definition to {target} profile notes."
