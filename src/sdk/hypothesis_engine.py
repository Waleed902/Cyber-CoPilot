"""
Hypothesis-driven engagement planning.

This module keeps the framework pentest-oriented: strong leads are tested early,
but pentest/audit modes still require a coverage pass before conclusions.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List


@dataclass(frozen=True)
class EngagementPolicy:
    """Execution policy for an assessment mode."""

    name: str
    description: str
    hypothesis_budget: int
    coverage_required: bool
    coverage_requirements: List[str]
    notes: List[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    """A testable attack-path hypothesis."""

    id: str
    name: str
    category: str
    evidence: List[str]
    confidence: float
    impact: int
    cost: int
    next_tools: List[str]
    success_criteria: List[str]
    failure_criteria: List[str]
    budget: int
    status: str = "candidate"
    mode: str = "pentest"
    score: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_result: str = ""
    result_evidence: str = ""


MODE_POLICIES: Dict[str, EngagementPolicy] = {
    "fast": EngagementPolicy(
        name="fast",
        description="Exploit-path triage for labs or time-boxed checks.",
        hypothesis_budget=3,
        coverage_required=False,
        coverage_requirements=[
            "Record untested services and endpoints as residual risk.",
            "Validate only the highest-signal attack path before stopping.",
        ],
        notes=["Use when the user explicitly wants speed over assurance."],
    ),
    "ctf": EngagementPolicy(
        name="ctf",
        description="Challenge-solving mode optimized for the shortest viable path.",
        hypothesis_budget=3,
        coverage_required=False,
        coverage_requirements=[
            "Track tried paths to avoid loops.",
            "Stop after objective proof is obtained.",
        ],
    ),
    "pentest": EngagementPolicy(
        name="pentest",
        description="Professional pentest mode: hypothesis-led, then coverage-complete.",
        hypothesis_budget=5,
        coverage_required=True,
        coverage_requirements=[
            "Initial service and web fingerprinting completed.",
            "High-confidence hypotheses tested or explicitly rejected.",
            "All exposed services receive at least one protocol-appropriate quick-win check.",
            "HTTP robots/sitemap/.well-known and sensitive files checked.",
            "Auth, upload, API, admin, and numeric-ID surfaces tested when present.",
            "Versioned software mapped to CVE/exploitability checks.",
            "Confirmed findings include reproducible evidence and a negative control where practical.",
            "Untested surfaces are listed as residual risk before final reporting.",
        ],
        notes=[
            "Speed means shorter decision latency, not reduced coverage.",
            "After a promising path is tested, return to the coverage checklist.",
        ],
    ),
    "audit": EngagementPolicy(
        name="audit",
        description="Coverage-heavy assessment mode.",
        hypothesis_budget=4,
        coverage_required=True,
        coverage_requirements=[
            "Complete pentest-mode checklist.",
            "Subdomains and alternate vhosts receive baseline fingerprinting.",
            "TLS, headers, CORS, auth, API, and dependency surfaces checked.",
            "Low and informational findings are retained for hardening guidance.",
            "Evidence is collected even for non-exploitable misconfigurations.",
        ],
    ),
    "stealth": EngagementPolicy(
        name="stealth",
        description="Low-noise mode for rate-limited or monitored targets.",
        hypothesis_budget=3,
        coverage_required=True,
        coverage_requirements=[
            "Prefer passive recon and single-request probes.",
            "Use low-rate checks for required coverage.",
            "Document coverage deferred due to noise constraints.",
        ],
        notes=["Avoid broad brute forcing unless explicitly approved."],
    ),
    "report": EngagementPolicy(
        name="report",
        description="Reporting mode. No new exploitation unless explicitly requested.",
        hypothesis_budget=0,
        coverage_required=False,
        coverage_requirements=[
            "Summarize confirmed findings only.",
            "List hypotheses and untested coverage as limitations.",
        ],
    ),
}


def normalize_mode(mode: str = "") -> str:
    """Return a supported engagement mode, defaulting to pentest."""
    selected = (mode or "pentest").strip().lower()
    return selected if selected in MODE_POLICIES else "pentest"


def get_policy(mode: str = "") -> EngagementPolicy:
    """Return the policy for an engagement mode."""
    return MODE_POLICIES[normalize_mode(mode)]


def profile_to_context(profile: Any) -> str:
    """Render a TargetProfile-like object into compact rule input."""
    if not profile:
        return ""

    chunks: List[str] = []
    for p in getattr(profile, "ports", []) or []:
        chunks.append(f"port {p.get('port')} {p.get('service', '')} {p.get('version', '')}")
    chunks.extend(getattr(profile, "web_technologies", []) or [])
    chunks.extend(getattr(profile, "web_directories", []) or [])
    for item in getattr(profile, "api_endpoints", []) or []:
        chunks.append(f"{item.get('method', '')} {item.get('url', '')} {item.get('notes', '')}")
    for item in getattr(profile, "devtools", []) or []:
        chunks.append(f"{item.get('name', '')} {item.get('url', '')} {item.get('evidence', '')}")
    for item in getattr(profile, "attack_paths", []) or []:
        chunks.append(f"{item.get('name', '')} {' '.join(item.get('steps', []))}")
    return "\n".join(str(c) for c in chunks if c)


def generate_hypotheses_from_context(
    context: str = "",
    mode: str = "pentest",
    profile: Any = None,
) -> List[Hypothesis]:
    """Generate ranked hypotheses from observed target facts."""
    selected_mode = normalize_mode(mode)
    policy = get_policy(selected_mode)
    text = "\n".join([context or "", profile_to_context(profile)]).lower()
    hypotheses: List[Hypothesis] = []

    def add(
        key: str,
        name: str,
        category: str,
        evidence: Iterable[str],
        confidence: float,
        impact: int,
        cost: int,
        next_tools: List[str],
        success_criteria: List[str],
        failure_criteria: List[str],
    ) -> None:
        evidence_list = _unique([e for e in evidence if e])
        if not evidence_list:
            return
        ident = _hypothesis_id(key, evidence_list)
        budget = max(1, min(policy.hypothesis_budget or 1, 6))
        score = round((confidence * impact) / max(cost, 1), 3)
        hypotheses.append(
            Hypothesis(
                id=ident,
                name=name,
                category=category,
                evidence=evidence_list,
                confidence=confidence,
                impact=impact,
                cost=cost,
                next_tools=next_tools,
                success_criteria=success_criteria,
                failure_criteria=failure_criteria,
                budget=budget,
                mode=selected_mode,
                score=score,
            )
        )

    if _has_any(text, ["mcp inspector", "mcpjam", "/api/mcp", "jupyter", "localhost:8888", "127.0.0.1:8888", "6274"]):
        add(
            "exposed_mcp_jupyter_pivot",
            "Exposed MCP/Jupyter control-plane pivot",
            "devtool_exposure",
            _evidence_matches(text, ["mcp inspector", "mcpjam", "/api/mcp", "jupyter", "localhost:8888", "127.0.0.1:8888", "6274"]),
            0.92,
            5,
            1,
            ["mcp_inspector_audit", "mcp_inspector_connect_stdio", "jupyter_terminal_command"],
            ["MCP API returns server/connect metadata", "Jupyter token or terminal execution is confirmed"],
            ["MCP endpoints absent or require auth", "No reachable Jupyter path or token after budget"],
        )

    if _has_any(text, [".git/head", ".git/config", ".env", "source map", "sourcemap", ".map"]):
        add(
            "source_disclosure_secrets",
            "Source/config disclosure may expose credentials or implementation flaws",
            "information_disclosure",
            _evidence_matches(text, [".git/head", ".git/config", ".env", "source map", "sourcemap", ".map"]),
            0.82,
            4,
            1,
            ["curl_request", "wget_download", "secretfinder_js", "git_dump", "js_secret_chain"],
            ["Readable source/config artifact contains secrets, routes, or credentials"],
            ["Artifact is not readable or contains no actionable sensitive data"],
        )

    if _has_any(text, ["login", "password", "signin", "sign in", "auth", "jwt", "session"]):
        add(
            "auth_surface_abuse",
            "Authentication surface may expose bypass, injection, weak credentials, or session flaws",
            "authentication",
            _evidence_matches(text, ["login", "password", "signin", "sign in", "auth", "jwt", "session"]),
            0.72,
            4,
            2,
            ["browser_extract_forms", "sqli_scanner", "http_compare", "jwt_analysis", "password_reset_tester"],
            ["Different response proves auth bypass, injection, weak reset, or token flaw"],
            ["Baseline and attack responses match safe controls across tested inputs"],
        )

    if _has_any(text, ["upload", "multipart/form-data", "avatar", "import", "attachment"]):
        add(
            "file_upload_execution_or_xss",
            "File upload surface may allow stored XSS, parser abuse, or execution",
            "file_upload",
            _evidence_matches(text, ["upload", "multipart/form-data", "avatar", "import", "attachment"]),
            0.74,
            4,
            2,
            ["browser_extract_forms", "browser_upload_file", "validate_xss", "command_injection_scanner"],
            ["Uploaded benign proof executes, reflects, or is retrievable from a dangerous context"],
            ["Upload rejects dangerous content and serves accepted files safely"],
        )

    if _has_any(text, ["graphql", "/graphql", "graphiql"]):
        add(
            "graphql_schema_and_authz",
            "GraphQL endpoint may expose schema, injection, or authorization gaps",
            "api_security",
            _evidence_matches(text, ["graphql", "/graphql", "graphiql"]),
            0.78,
            4,
            1,
            ["graphql_introspection", "graphql_schema_inventory", "graphql_authz_replay_probe", "graphql_injection_test"],
            ["Schema is exposed or object access differs across users/ids"],
            ["Introspection disabled and authz checks hold for sampled objects"],
        )

    if _has_any(text, ["wordpress", "wp-content", "wp-login", "xmlrpc.php"]):
        add(
            "wordpress_known_surface",
            "WordPress surface may expose plugin, theme, XML-RPC, or credential issues",
            "cms",
            _evidence_matches(text, ["wordpress", "wp-content", "wp-login", "xmlrpc.php"]),
            0.76,
            3,
            1,
            ["wpscan", "wordpress_xmlrpc_audit", "wpprobe_scan", "wpseku_scan"],
            ["Versioned vulnerable plugin/theme, XML-RPC abuse, or credential issue is confirmed"],
            ["WPScan/XML-RPC checks return no exploitable issue in budget"],
        )

    if _has_any(text, ["minio", "s3", "bucket", "amazonaws.com"]):
        add(
            "object_storage_exposure",
            "Object storage may allow anonymous listing, overwrite, or secret disclosure",
            "cloud_storage",
            _evidence_matches(text, ["minio", "s3", "bucket", "amazonaws.com"]),
            0.75,
            4,
            1,
            ["s3_bucket_explorer", "s3_bucket_enum", "cloud_asset_enum"],
            ["Bucket/listing/write/read exposure is confirmed with scoped proof"],
            ["Bucket inaccessible or permissions deny sampled read/list/write checks"],
        )

    if _has_any(text, ["jenkins", "grafana", "kibana", "prometheus", "phpmyadmin", "admin", "8080", "8443", "3000", "5000"]):
        add(
            "admin_panel_default_or_cve",
            "Exposed admin/developer panel may have default creds, version CVEs, or unsafe APIs",
            "admin_panel",
            _evidence_matches(text, ["jenkins", "grafana", "kibana", "prometheus", "phpmyadmin", "admin", "8080", "8443", "3000", "5000"]),
            0.68,
            4,
            2,
            ["curl_request", "browser_visit", "suggest_exploits_for_technology", "hydra_bruteforce"],
            ["Version/default credential/API exposure is proven"],
            ["Panel requires auth and sampled default/version checks fail"],
        )

    if re.search(r"/(?:users?|orders?|data|scan|profile|account)/\d+\b", text):
        add(
            "numeric_id_idor",
            "Numeric object identifiers may allow IDOR/BOLA",
            "access_control",
            re.findall(r"/(?:users?|orders?|data|scan|profile|account)/\d+\b", text)[:5],
            0.8,
            4,
            1,
            ["idor_probe", "two_account_authz_engine", "http_compare"],
            ["Changing object id returns another user's data or action result"],
            ["Authorization blocks or responses are equivalent for sampled ids"],
        )

    if _has_versioned_service(text):
        add(
            "versioned_service_cve",
            "Versioned services should be checked for known CVEs before blind fuzzing",
            "known_cve",
            _versioned_service_evidence(text),
            0.66,
            3,
            1,
            ["suggest_exploits_for_service", "suggest_exploits_for_technology", "searchsploit"],
            ["Known applicable CVE has a safe verification path or exploitability proof"],
            ["No applicable CVE or target configuration is not vulnerable"],
        )

    # ── Initial Service Footholds ──
    service_ev = _evidence_matches(text, ["21/tcp", "21/open", "ftp ", "22/tcp", "22/open", "ssh ", "445/tcp", "139/tcp", "smb ", "microsoft-ds", "3389/tcp", "rdp ", "3306/tcp", "1433/tcp", "mysql", "mssql"])
    if service_ev:
        add(
            "service_foothold_weak_creds",
            "Initial service foothold via default credentials or weak credential spray",
            "credential_access",
            service_ev,
            0.60,
            8,
            2,
            ["hydra_bruteforce", "smbclient_access", "patator_bruteforce"],
            ["Valid credentials found", "Guest/anonymous access allowed"],
            ["All credential attempts fail or target locks accounts"],
        )

    # ── Local Privilege Escalation & Looting (Triggers when a shell is active) ──
    has_active_shell = _has_any(text, ["whoami", "session_id", "uid=", "gid=", "active shell", "shell_", "established shell", "reverse shell", "listener"])
    if has_active_shell:
        shell_ev = _evidence_matches(text, ["whoami", "session_id", "uid=", "gid=", "active shell", "shell_", "established shell", "reverse shell", "listener"])
        
        add(
            "local_privesc_sudo",
            "Local privilege escalation via sudo rules",
            "privilege_escalation",
            shell_ev + ["Shell capability verified"],
            0.85,
            10,
            1,
            ["sudo_check", "gtfobins_check"],
            ["Sudo -l returns exploitable rules", "Escalated shell session established"],
            ["Sudo requires password we do not have", "No sudo rules or rules are secure"],
        )
        
        add(
            "local_privesc_suid",
            "Local privilege escalation via SUID/SGID binaries or capabilities",
            "privilege_escalation",
            shell_ev + ["Shell capability verified"],
            0.80,
            10,
            1,
            ["sudo_check", "gtfobins_check"],
            ["SUID binary matches known GTFOBins exploit", "Capabilities allow write/read execution"],
            ["No SUID binaries found or all are standard/safe"],
        )
        
        add(
            "local_privesc_linpeas",
            "Local privilege escalation search via LinPEAS execution",
            "privilege_escalation",
            shell_ev + ["Shell capability verified"],
            0.90,
            10,
            2,
            ["linpeas_scan"],
            ["LinPEAS flags high-confidence vector in red/yellow", "Vulnerable local script/service discovered"],
            ["LinPEAS runs and returns no actionable vector"],
        )

        add(
            "local_privesc_writable",
            "Local privilege escalation via world-writable files, cron jobs, or active processes",
            "privilege_escalation",
            shell_ev + ["Shell capability verified"],
            0.75,
            10,
            2,
            ["find_writable_dirs", "pspy_monitor"],
            ["Writable script executed by root is hijacked", "Cron job executes malicious payload"],
            ["No writable system paths or root-owned cron jobs"],
        )

    # ── Active Directory Domain Domination ──
    ad_ev = _evidence_matches(text, ["active directory", "domain controller", "domain admins", "kerberos", "ldap", "88/tcp", "389/tcp", "445/tcp"])
    if ad_ev:
        add(
            "local_privesc_ad",
            "Active Directory Domain Privilege Escalation to Domain Admin",
            "active_directory",
            ad_ev,
            0.70,
            10,
            2,
            ["bloodhound_collector", "bloodhound_query", "impacket_kerberoast", "impacket_asreproast"],
            ["BloodHound path reveals path to DA", "Kerberoasted/AS-REP roasted account has high privileges"],
            ["AD controls are strict and no path to Domain Admin exists"],
        )

    # ── CTF Flag Extraction / Looting ──
    if has_active_shell or selected_mode == "ctf":
        add(
            "ctf_flag_extraction",
            "Capture target CTF flags (user.txt, root.txt, flag.txt)",
            "loot",
            ["Target file system accessibility"],
            0.95,
            9,
            1,
            ["execute_in_shell", "interactive_bash"],
            ["Flag output printed and matched regex format", "record_ctf_solution called"],
            ["Flag file not found or permission denied"],
        )

    if not hypotheses and text.strip():
        add(
            "baseline_coverage_first",
            "No strong exploit hypothesis yet; complete baseline coverage",
            "coverage",
            ["No high-confidence rule matched current observations"],
            0.5,
            2,
            2,
            ["nmap_service_scan", "curl_request", "whatweb_scan", "mcp_inspector_audit"],
            ["New service, endpoint, technology, or high-signal exposure is discovered"],
            ["Baseline checks produce no new actionable observations"],
        )

    hypotheses.sort(key=lambda h: (h.score, h.confidence, -h.cost), reverse=True)
    return hypotheses


def merge_hypotheses(existing: List[Dict[str, Any]], generated: List[Hypothesis]) -> List[Dict[str, Any]]:
    """Merge generated hypotheses into persisted dictionaries by id."""
    merged: Dict[str, Dict[str, Any]] = {}
    for item in existing or []:
        if item.get("id"):
            merged[item["id"]] = dict(item)
    for hyp in generated:
        payload = asdict(hyp)
        if hyp.id in merged:
            preserved = {
                key: merged[hyp.id].get(key)
                for key in ("status", "created_at", "last_result", "result_evidence")
                if merged[hyp.id].get(key)
            }
            payload.update(preserved)
            payload["updated_at"] = datetime.now().isoformat()
        merged[hyp.id] = payload
    return sorted(merged.values(), key=lambda h: h.get("score", 0), reverse=True)


def update_hypothesis_result(
    hypotheses: List[Dict[str, Any]],
    hypothesis_id: str,
    outcome: str,
    evidence: str = "",
) -> List[Dict[str, Any]]:
    """Update one persisted hypothesis with a result."""
    wanted = (hypothesis_id or "").strip()
    normalized_outcome = _normalize_outcome(outcome)
    now = datetime.now().isoformat()
    updated: List[Dict[str, Any]] = []
    for item in hypotheses or []:
        row = dict(item)
        if row.get("id") == wanted:
            row["status"] = normalized_outcome
            row["last_result"] = normalized_outcome
            row["result_evidence"] = evidence[:1000]
            row["updated_at"] = now
        updated.append(row)
    return updated


def render_hypotheses(hypotheses: List[Dict[str, Any]], mode: str = "pentest", limit: int = 8) -> str:
    """Render hypotheses and mode policy for an agent/user."""
    policy = get_policy(mode)
    lines = [
        f"Engagement mode: {policy.name}",
        policy.description,
        f"Hypothesis proof budget: {policy.hypothesis_budget} focused tool calls per lead",
        f"Coverage required before final conclusion: {'yes' if policy.coverage_required else 'no'}",
        "",
        "Ranked hypotheses:",
    ]
    if not hypotheses:
        lines.append("- None generated yet. Add recon observations or run baseline coverage.")
    for idx, item in enumerate(hypotheses[:limit], 1):
        tools = ", ".join(item.get("next_tools", [])[:5])
        evidence = "; ".join(item.get("evidence", [])[:3])
        lines.append(
            f"{idx}. {item.get('name')} [{item.get('status', 'candidate')}] "
            f"score={item.get('score')} confidence={item.get('confidence')} id={item.get('id')}"
        )
        lines.append(f"   Evidence: {evidence}")
        lines.append(f"   Next tools: {tools}")
    if policy.coverage_required:
        lines.append("")
        lines.append("Coverage checklist to return to after high-signal hypotheses:")
        lines.extend(f"- {req}" for req in policy.coverage_requirements)
    return "\n".join(lines)


def render_selected_hypothesis(item: Dict[str, Any], mode: str = "pentest") -> str:
    """Render a single hypothesis as a tool-selection plan."""
    if not item:
        return "Hypothesis not found."
    policy = get_policy(mode)
    lines = [
        f"Hypothesis: {item.get('name')}",
        f"ID: {item.get('id')}",
        f"Status: {item.get('status', 'candidate')}",
        f"Budget: {item.get('budget', policy.hypothesis_budget)} focused tool calls",
        "",
        "Use these tools first:",
    ]
    lines.extend(f"- {tool}" for tool in item.get("next_tools", []))
    lines.append("")
    lines.append("Success criteria:")
    lines.extend(f"- {criterion}" for criterion in item.get("success_criteria", []))
    lines.append("Failure criteria:")
    lines.extend(f"- {criterion}" for criterion in item.get("failure_criteria", []))
    if policy.coverage_required:
        lines.append("")
        lines.append("After this hypothesis is confirmed or rejected, resume pentest coverage.")
    return "\n".join(lines)


def _hypothesis_id(key: str, evidence: List[str]) -> str:
    seed = "|".join([key] + evidence[:4]).encode("utf-8", errors="ignore")
    return f"{key}:{hashlib.sha1(seed).hexdigest()[:10]}"


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        clean = str(value).strip()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


def _has_any(text: str, needles: Iterable[str]) -> bool:
    return any(needle.lower() in text for needle in needles)


def _evidence_matches(text: str, needles: Iterable[str]) -> List[str]:
    return [needle for needle in needles if needle.lower() in text]


def _has_versioned_service(text: str) -> bool:
    return bool(re.search(r"\b(?:apache|nginx|openssh|wordpress|php|tomcat|iis|grafana|jenkins|exim|bind|mysql|mariadb|postgresql)[^\n]{0,40}\b\d+(?:\.\d+)+", text))


def _versioned_service_evidence(text: str) -> List[str]:
    pattern = re.compile(
        r"\b(?:apache|nginx|openssh|wordpress|php|tomcat|iis|grafana|jenkins|exim|bind|mysql|mariadb|postgresql)[^\n]{0,40}\b\d+(?:\.\d+)+",
        re.IGNORECASE,
    )
    return _unique(match.group(0)[:120] for match in pattern.finditer(text))[:5]


def _normalize_outcome(outcome: str) -> str:
    value = (outcome or "").strip().lower()
    aliases = {
        "success": "confirmed",
        "confirmed": "confirmed",
        "proved": "confirmed",
        "valid": "confirmed",
        "fail": "rejected",
        "failed": "rejected",
        "rejected": "rejected",
        "invalid": "rejected",
        "blocked": "blocked",
        "inconclusive": "inconclusive",
        "tested": "tested",
    }
    return aliases.get(value, value or "tested")


# ─────────────────────────────────────────────────────────────────────────────
# Pivot / Escalation Tables
# When a hypothesis fails → generate pivot alternatives
# When it succeeds → generate escalation next-steps
# ─────────────────────────────────────────────────────────────────────────────

_PIVOT_TABLE: Dict[str, List[Dict[str, Any]]] = {
    # SQLi failed → try these alternatives
    "authentication": [
        {"name": "Try OAuth/SSO flow vulnerabilities", "category": "oauth",
         "next_tools": ["oauth_flow_test", "browser_visit"],
         "success_criteria": ["redirect_uri bypass confirmed", "state CSRF confirmed"],
         "failure_criteria": ["OAuth flow completes securely 3 times"],
         "confidence": 40.0, "impact": 8, "cost": 2},
        {"name": "Test JWT algorithm confusion (if JWT auth)", "category": "jwt",
         "next_tools": ["jwt_analysis", "jwt_forge", "jwt_embedded_jwk"],
         "success_criteria": ["alg:none accepted", "RS256→HS256 confusion works"],
         "failure_criteria": ["alg:none rejected", "JWT validation is strict"],
         "confidence": 45.0, "impact": 9, "cost": 2},
        {"name": "Brute-force / credential spray as last resort", "category": "auth",
         "next_tools": ["hydra_bruteforce", "kerbrute_spray"],
         "success_criteria": ["valid credential found"],
         "failure_criteria": ["all attempts fail or rate-limited"],
         "confidence": 25.0, "impact": 7, "cost": 3},
    ],
    "sql_injection": [
        {"name": "Try ORDER BY injection (WAF bypass)", "category": "sql_injection",
         "next_tools": ["http_request", "http_fuzz"],
         "success_criteria": ["sort order changes with injection", "error on high column number"],
         "failure_criteria": ["ORDER BY injection produces same response 3 times"],
         "confidence": 50.0, "impact": 9, "cost": 1},
        {"name": "Try NoSQL injection (if MongoDB/Redis stack)", "category": "nosql",
         "next_tools": ["http_request", "http_fuzz"],
         "success_criteria": ["[$ne] operator bypasses auth", "[$gt] returns unexpected data"],
         "failure_criteria": ["NoSQL operators rejected or cause errors"],
         "confidence": 35.0, "impact": 8, "cost": 1},
        {"name": "Try second-order SQLi via stored field", "category": "sql_injection",
         "next_tools": ["browser_auth_test", "http_request"],
         "success_criteria": ["SQL error on field retrieval", "data manipulation via stored value"],
         "failure_criteria": ["Stored value properly escaped in all contexts"],
         "confidence": 30.0, "impact": 9, "cost": 3},
        {"name": "Try SSTI if template engine detected", "category": "ssti",
         "next_tools": ["http_request", "http_fuzz"],
         "success_criteria": ["{{7*7}} evaluates to 49", "RCE command output returned"],
         "failure_criteria": ["Template syntax treated as literal text"],
         "confidence": 40.0, "impact": 10, "cost": 2},
    ],
    "access_control": [
        {"name": "Test BFLA via HTTP method tampering on 403 endpoints", "category": "bfla",
         "next_tools": ["http_request", "rest_api_fuzzing"],
         "success_criteria": ["PUT/DELETE/PATCH succeeds where GET returned 403"],
         "failure_criteria": ["All methods return 403 consistently"],
         "confidence": 45.0, "impact": 8, "cost": 2},
        {"name": "Test mass assignment on update endpoint", "category": "mass_assignment",
         "next_tools": ["rest_api_fuzzing", "http_request"],
         "success_criteria": ["role/admin/premium field accepted and persisted"],
         "failure_criteria": ["Extra fields ignored or rejected"],
         "confidence": 40.0, "impact": 9, "cost": 1},
        {"name": "Try cross-tenant IDOR (if multi-tenant app)", "category": "idor",
         "next_tools": ["two_account_authz_engine", "http_compare"],
         "success_criteria": ["Org A data accessible with Org B credentials"],
         "failure_criteria": ["Cross-tenant access properly denied"],
         "confidence": 55.0, "impact": 9, "cost": 2},
    ],
    "api_security": [
        {"name": "Test GraphQL BOLA — access other users' objects via mutations", "category": "bola",
         "next_tools": ["graphql_authz_replay_probe", "http_request"],
         "success_criteria": ["Mutation succeeds on another user's object ID"],
         "failure_criteria": ["GraphQL authorization is enforced at field level"],
         "confidence": 55.0, "impact": 8, "cost": 2},
        {"name": "Test API version downgrade — try v1 instead of v2", "category": "api_version",
         "next_tools": ["api_version_enumeration", "http_request"],
         "success_criteria": ["Old API version responds with less security controls"],
         "failure_criteria": ["All API versions have identical security posture"],
         "confidence": 40.0, "impact": 7, "cost": 1},
        {"name": "Test rate limit bypass via header manipulation", "category": "rate_limit",
         "next_tools": ["api_rate_limit_bypass", "http_fuzz"],
         "success_criteria": ["X-Forwarded-For bypass confirmed", "rate limit reset via header"],
         "failure_criteria": ["Rate limiting enforced regardless of headers"],
         "confidence": 45.0, "impact": 6, "cost": 1},
    ],
    "file_upload": [
        {"name": "Try SVG upload for stored XSS", "category": "xss",
         "next_tools": ["http_request", "browser_visit"],
         "success_criteria": ["SVG onload fires in browser context"],
         "failure_criteria": ["SVG content-type rejected or sanitized"],
         "confidence": 50.0, "impact": 7, "cost": 1},
        {"name": "Try path traversal in filename", "category": "path_traversal",
         "next_tools": ["http_request"],
         "success_criteria": ["File written outside upload directory"],
         "failure_criteria": ["Filename sanitized before storage"],
         "confidence": 30.0, "impact": 9, "cost": 1},
        {"name": "Try double extension bypass (file.php.jpg)", "category": "rce",
         "next_tools": ["http_request", "browser_visit"],
         "success_criteria": ["PHP code executed when accessing uploaded file"],
         "failure_criteria": ["Double extension rejected or not executed"],
         "confidence": 35.0, "impact": 10, "cost": 1},
    ],
    "ssrf": [
        {"name": "Try DNS rebinding to bypass IP allowlist", "category": "ssrf",
         "next_tools": ["http_request", "managed_oast_ssrf_validation"],
         "success_criteria": ["SSRF reaches internal target after DNS rebinding"],
         "failure_criteria": ["DNS rebinding blocked by TTL or IP validation"],
         "confidence": 30.0, "impact": 9, "cost": 3},
        {"name": "Try open redirect chain to bypass SSRF allowlist", "category": "ssrf",
         "next_tools": ["ssrf_scanner", "http_request"],
         "success_criteria": ["SSRF follows redirect from allowed domain to internal"],
         "failure_criteria": ["Redirect not followed or blocked"],
         "confidence": 35.0, "impact": 9, "cost": 2},
        {"name": "Try gopher:// protocol for Redis/MySQL attack", "category": "ssrf_rce",
         "next_tools": ["http_request"],
         "success_criteria": ["Redis command executed via gopher SSRF"],
         "failure_criteria": ["gopher:// protocol blocked"],
         "confidence": 25.0, "impact": 10, "cost": 2},
    ],
    "information_disclosure": [
        {"name": "Dump .git repo and search commit history for secrets", "category": "secrets",
         "next_tools": ["git_dump", "trufflehog_repo"],
         "success_criteria": ["API keys or credentials found in git history"],
         "failure_criteria": ["Git dump fails or history contains no secrets"],
         "confidence": 60.0, "impact": 9, "cost": 2},
        {"name": "Search JS bundles for hardcoded API keys", "category": "secrets",
         "next_tools": ["jsluice_extract", "js_secret_chain"],
         "success_criteria": ["Active API key or credential found in JS"],
         "failure_criteria": ["No secrets found in client-side JS"],
         "confidence": 50.0, "impact": 8, "cost": 1},
        {"name": "Test Swagger/OpenAPI for undocumented admin endpoints", "category": "api",
         "next_tools": ["rest_api_fuzzing", "http_request"],
         "success_criteria": ["Admin endpoint accessible without authorization"],
         "failure_criteria": ["All API endpoints require proper authorization"],
         "confidence": 55.0, "impact": 8, "cost": 2},
    ],
    "cms": [
        {"name": "Run CVE check for specific CMS version", "category": "cve",
         "next_tools": ["searchsploit", "nuclei_scan"],
         "success_criteria": ["CVE exploit succeeds on target version"],
         "failure_criteria": ["No applicable CVEs or patched version"],
         "confidence": 60.0, "impact": 9, "cost": 1},
        {"name": "Enumerate and test plugins/themes for vulnerabilities", "category": "cms",
         "next_tools": ["wpscan", "wpseku_scan", "wpprobe_scan"],
         "success_criteria": ["Vulnerable plugin found and exploited"],
         "failure_criteria": ["All plugins up to date or not vulnerable"],
         "confidence": 50.0, "impact": 8, "cost": 2},
    ],
}

_ESCALATION_NEXT_STEPS: Dict[str, List[Dict[str, Any]]] = {
    "sql_injection": [
        {"name": "Extract full database — users table, credentials", "category": "exploitation",
         "next_tools": ["sqlmap_attack", "sqli_extract_blind"],
         "success_criteria": ["User table extracted with password hashes"],
         "failure_criteria": ["Extraction fails or returns no data"],
         "confidence": 75.0, "impact": 10, "cost": 2},
        {"name": "Check for FILE privilege → webshell via INTO OUTFILE", "category": "rce",
         "next_tools": ["sqlmap_attack", "http_request"],
         "success_criteria": ["Webshell written and accessible"],
         "failure_criteria": ["FILE privilege absent or directory not writable"],
         "confidence": 55.0, "impact": 10, "cost": 2},
    ],
    "ssrf": [
        {"name": "Probe cloud metadata for IAM credentials", "category": "cloud",
         "next_tools": ["ssrf_cloud_metadata", "ssrf_imdsv2_chain"],
         "success_criteria": ["IAM credentials returned from IMDS"],
         "failure_criteria": ["IMDS not reachable or returns 404"],
         "confidence": 70.0, "impact": 10, "cost": 1},
        {"name": "Run pacu to assess IAM permissions after credential theft", "category": "cloud",
         "next_tools": ["pacu_run"],
         "success_criteria": ["IAM role has meaningful permissions"],
         "failure_criteria": ["Role has no significant permissions"],
         "confidence": 65.0, "impact": 10, "cost": 2},
    ],
    "access_control": [
        {"name": "Enumerate ALL user IDs to prove mass data exfiltration scope", "category": "idor",
         "next_tools": ["idor_enumerate", "http_fuzz"],
         "success_criteria": ["500+ user records accessible"],
         "failure_criteria": ["Enumeration limited or access denied after N requests"],
         "confidence": 70.0, "impact": 10, "cost": 2},
        {"name": "Try IDOR on financial/billing endpoints for maximum impact", "category": "idor",
         "next_tools": ["rest_api_fuzzing", "http_request"],
         "success_criteria": ["Payment or billing data of other users accessible"],
         "failure_criteria": ["Financial endpoints properly authorized"],
         "confidence": 60.0, "impact": 10, "cost": 2},
    ],
    "authentication": [
        {"name": "Forge admin token and access admin panel", "category": "privilege_escalation",
         "next_tools": ["jwt_forge", "browser_auth_test"],
         "success_criteria": ["Admin panel accessible with forged token"],
         "failure_criteria": ["Forged token rejected or admin panel inaccessible"],
         "confidence": 70.0, "impact": 10, "cost": 1},
    ],
    "information_disclosure": [
        {"name": "Test each found credential against live services", "category": "credential_use",
         "next_tools": ["http_request", "curl_request"],
         "success_criteria": ["Credential grants access to backend service"],
         "failure_criteria": ["Credential invalid or rotated"],
         "confidence": 80.0, "impact": 10, "cost": 1},
    ],
}


def record_hypothesis_outcome(
    hypotheses: List[Dict[str, Any]],
    hypothesis_id: str,
    outcome: str,
    evidence: str = "",
    observed_behavior: str = "",
    mode: str = "pentest",
) -> Dict[str, Any]:
    """
    Record the outcome of a hypothesis and generate pivot or escalation hypotheses.

    When a hypothesis FAILS:
      → Returns 2-3 pivot hypotheses that approach the same objective differently.
      → Updates the original hypothesis status to 'rejected'.

    When a hypothesis SUCCEEDS (confirmed):
      → Returns escalation hypotheses that push the confirmed finding to higher impact.
      → Updates the original hypothesis status to 'confirmed'.

    This creates a self-updating attack tree instead of a static checklist.

    Args:
        hypotheses:          Current list of hypothesis dicts (from runner state)
        hypothesis_id:       ID of the hypothesis that was just tested
        outcome:             Result: "confirmed" / "success" / "rejected" / "failed" / "blocked"
        evidence:            Evidence text from the test
        observed_behavior:   What the server actually returned (helps pivot generation)
        mode:                Engagement mode

    Returns:
        Dict with keys:
          - updated_hypotheses: Updated hypothesis list
          - new_hypotheses: List of new pivot or escalation hypotheses to add
          - action_message: Human-readable summary of what happened and what's next
    """
    normalized = _normalize_outcome(outcome)
    updated = update_hypothesis_result(hypotheses, hypothesis_id, normalized, evidence)

    # Find the original hypothesis
    original = next((h for h in updated if h.get("id") == hypothesis_id), None)
    category = (original or {}).get("category", "")

    new_hyps: List[Dict[str, Any]] = []
    action_message = ""

    if normalized in ("rejected", "blocked", "inconclusive"):
        # Generate pivot hypotheses
        pivot_candidates = _PIVOT_TABLE.get(category, [])
        if not pivot_candidates:
            # Generic pivot: try a different attack class entirely
            pivot_candidates = _PIVOT_TABLE.get("access_control", [])

        # Avoid re-generating hypotheses that already exist
        existing_names = {h.get("name", "").lower() for h in updated}
        new_pivots: List[Dict[str, Any]] = []
        for pivot in pivot_candidates[:3]:
            if pivot["name"].lower() not in existing_names:
                h_id = _hypothesis_id(pivot["name"], [evidence[:50]])
                new_pivots.append({
                    **pivot,
                    "id": h_id,
                    "status": "candidate",
                    "score": pivot["confidence"] * pivot["impact"] / max(pivot["cost"], 1),
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat(),
                    "last_result": "",
                    "result_evidence": "",
                    "budget": get_policy(mode).hypothesis_budget,
                    "mode": mode,
                    "evidence": [f"Pivoted from rejected hypothesis: {hypothesis_id}"],
                })
        new_hyps = new_pivots
        action_message = (
            f"Hypothesis {hypothesis_id} → {normalized}. "
            f"Generated {len(new_hyps)} pivot hypotheses: "
            + ", ".join(h["name"] for h in new_hyps)
            + ". Resume coverage checklist after testing these."
        )

    elif normalized == "confirmed":
        # Generate escalation hypotheses
        escalation_candidates = _ESCALATION_NEXT_STEPS.get(category, [])
        existing_names = {h.get("name", "").lower() for h in updated}
        new_escalations: List[Dict[str, Any]] = []
        for esc in escalation_candidates[:2]:
            if esc["name"].lower() not in existing_names:
                h_id = _hypothesis_id(esc["name"], [evidence[:50]])
                new_escalations.append({
                    **esc,
                    "id": h_id,
                    "status": "candidate",
                    "score": esc["confidence"] * esc["impact"] / max(esc["cost"], 1),
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat(),
                    "last_result": "",
                    "result_evidence": "",
                    "budget": get_policy(mode).hypothesis_budget,
                    "mode": mode,
                    "evidence": [f"Escalation from confirmed hypothesis: {hypothesis_id}", evidence[:200]],
                })
        new_hyps = new_escalations

        # Also check for chain opportunities
        chain_note = ""
        try:
            from src.sdk.impact_amplifier import get_amplifier
            amplifier = get_amplifier()
            # Use the category as a proxy finding
            proxy = [{"title": category, "category": category}]
            chains = amplifier.chain_from_findings(proxy)
            if chains:
                top_chain = chains[0]
                chain_note = (
                    f" Chain opportunity: {top_chain['title']} "
                    f"({top_chain['combined_severity']}, {top_chain.get('bounty_range', '')}). "
                    f"Status: {top_chain.get('status', '')}"
                )
        except Exception:
            pass

        action_message = (
            f"Hypothesis {hypothesis_id} → CONFIRMED. "
            f"Generated {len(new_hyps)} escalation hypotheses: "
            + ", ".join(h["name"] for h in new_hyps)
            + "."
            + chain_note
        )
    else:
        action_message = f"Hypothesis {hypothesis_id} updated to '{normalized}'."

    return {
        "updated_hypotheses": updated,
        "new_hypotheses": new_hyps,
        "action_message": action_message,
    }

