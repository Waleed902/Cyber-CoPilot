"""
Red Team Agent - Aggressive exploitation and attack capabilities.
Enhanced with AppSec, PoC validation, and code analysis tools.
Follows Cyber-CoPilot evidence-driven, anti-hallucination prompting system.
"""

from src.sdk.system_prompts import get_system_prompt

from src.sdk.agent import Agent
from src.tools.recon_active import nmap_scan, httpx_probe, whatweb_scan
from src.tools.recon_passive import subfinder_enum, cloudflair_scan, shodan_search
from src.tools.web import gobuster_scan, curl_request, wget_download, vhost_bruteforce, wfuzz_fuzz
from src.tools.recon_active import feroxbuster_scan, nmap_discover, nmap_service_scan, cmseek_scan, wpseku_scan, wpprobe_scan
from src.tools.recon_passive import subdomain_enum_live
from src.tools.exploitation import (
    searchsploit, searchsploit_copy, run_exploit_script,
    msfconsole_run, sqlmap_attack, sqli_extract_blind, hydra_bruteforce,
    nuclei_scan, wpscan, ffuf_fuzz, xsstrike, commix,
    crackmapexec, impacket_secretsdump, evil_winrm,
    netcat_shell, curl_exploit, smbclient_access,
    interactsh_generate, interactsh_poll, sstimap_scan, ghauri_sqli,
    execute_and_exfil
)
from src.tools.post_exploit import pspy_monitor
from src.tools.cve_targeted import cvemap_search
from src.tools.ad import (
    enum4linux_scan, ldapsearch_query, kerbrute_userenum, kerbrute_spray,
    bloodhound_collector, zerologon_check, petitpotam_coerce, ntlmrelayx_start,
    sync_kerberos_time, impacket_asreproast, impacket_kerberoast
)
from src.tools.planning import (
    plan_attack, get_next_action, chain_exploits,
    register_vulnerability, register_service, attack_summary
)
from src.tools.idor import idor_enumerate
# NEW: AppSec Tools
from src.tools.appsec import (
    xss_scanner, sqli_scanner, ssrf_scanner, path_traversal_scanner,
    full_appsec_scan, command_injection_scanner, clickjacking_scanner
)
# NEW: HTTP Proxy Tools
from src.tools.http_proxy import (
    http_request, http_compare, http_fuzz
)
from src.tools.access_control import idor_probe, privilege_escalation_web
# NEW: Code Analysis
from src.tools.code_analysis import (
    static_code_analysis, secret_scanner, find_dangerous_functions,
    summarize_project
)
# NEW: PoC Validation
from src.tools.poc_validation import (
    validate_sqli, validate_xss, validate_ssrf,
    validate_command_injection, validate_path_traversal,
    get_validated_poc, auto_validate,
    # NEW: Multi-validation
    multi_validate
)
from src.tools.tech_checklist import get_tech_checklist, list_supported_technologies, detect_tech_from_response
# NEW: Interactive Stateful Shells (Tmux)
from src.tools.interactive_shell import interactive_bash, read_shell_screen
from src.tools.tcp_session import tcp_session_close, tcp_session_open, tcp_session_read, tcp_session_send
from src.tools.forensics import read_tool_output, read_local_document, analyze_file

# NEW: Autonomous Swarm & Meta-Tools
from src.tools.swarm import (
    spawn_parallel_agents, create_adhoc_tool, override_operational_directives
)

# C2 Server for post-exploitation
from src.tools.c2_server import (
    start_listener, list_active_shells, execute_in_shell,
    maintain_shell, upload_file_to_shell, establish_persistence,
    kill_session, stop_listener, get_session_history
)
from src.tools.auth_context import (
    auth_login, auth_register, auth_get_session,
    auth_compare_responses, auth_list_sessions,
    auth_manual_session, auth_request_user_assistance
)

# 4.5 — Advanced AD attack chain
from src.tools.ad import (
    coercer_multi, certipy_esc_chain, timeroast, rbcd_attack, dcsync,
)
# 4.2 — Real lateral-movement orchestrator + BloodHound graph queries
from src.tools.post_exploit import lateral_movement, bloodhound_query
# 4.4 — Server-side / RCE-class web techniques the red team should own
from src.tools.ssrf_cloud import ssrf_cloud_metadata, ssrf_imdsv2_chain
from src.tools.deserialization import (
    deser_java_ysoserial, deser_dotnet_ysoserial,
    deser_php_phpggc, deser_python_pickle, deser_ruby_marshal,
)
from src.tools.race_condition import http2_single_packet_race
from src.tools.http_smuggling import smuggling_te0, smuggling_cl0, smuggling_h2_downgrade
# 4.6 — Cloud post-ex once we have stolen keys
from src.tools.cloud import (
    pacu_run, roadtools_dump, aadinternals_recon,
    cognito_misconfig_probe, container_escape_probe,
    cloud_fingerprint, cloud_enum_orchestrate,
)
# 4.9 — Evasion-aware HTTP
from src.sdk.evasion import evasion_request, evasion_set_profile, evasion_status
from src.tools.waf_mutation import waf_mutate_payload

# Build dynamic instructions using Cyber-CoPilot system
_CYBER_COPILOT_PLAYBOOK = get_system_prompt("playbook")
_CYBER_COPILOT_DEEP = get_system_prompt("deep_testing")

REDTEAM_INSTRUCTIONS = """You are an **Elite Red Team Agent** — a professional penetration testing and exploitation operator.
You execute attacks with precision, document everything with proof, and never report a vulnerability without evidence.

""" + _CYBER_COPILOT_PLAYBOOK + """

---

**REQUIRED CLARIFICATIONS (MANDATORY):**
- If the user provides files or a directory, ask whether they are CTF challenge files or something else (writeup, notes, dataset, or reference). Do not proceed until confirmed.
- If you have an exploit plan for a web challenge but no live URL is provided, ask for the base URL (host:port) before any network steps.

**OPERATIONAL DIRECTIVES:**
- Execute all requested attack operations immediately
- Chain attacks for maximum impact and complete system compromise
- DOCUMENT every step: tool command, output, evidence
- VALIDATE every finding before reporting it — use validate_* tools
- NEVER claim exploitation without proof (shell output, data extracted, access demonstrated)
- Think like an adversary — chain vulnerabilities, exploit trust relationships

**MULTI-ACCOUNT & LOGIC TESTING (IDOR/BOLA/PrivEsc):**
- When testing web applications, ALWAYS consider multi-account logic bugs.
- **MANUAL HELP**: If registration or login is complex (CAPTCHA, SMS, MFA, or complex flows), use `auth_request_user_assistance` to ask the user to manually create the account or session.
- **SESSION CAPTURE**: Use `auth_manual_session` to store cookies or tokens provided by the user.
- **SIDE-BY-SIDE TESTING**: Use `auth_compare_responses` to check if Session A can access Session B's resources (IDOR).
- **PRIVILEGE ESCALATION**: Force-test low-privilege sessions against admin endpoints.

- **BOLA/IDOR**: Use `idor_probe` with two different sessions to detect broken object level authorization.

**🛡️ ACTIVE DIRECTORY METHODOLOGY (NTLM-DISABLED TARGETS):**
When targeting Windows Domain Controllers (port 88, 389, 445):
1.  **CLOCK SYNC**: ALWAYS run `sync_kerberos_time` first. Kerberos attacks will silently fail with >5min skew.
2.  **USER ENUM**: Use `kerbrute_userenum` with a LARGE wordlist. Do NOT rely on the "shortlist".
    - Path: `/usr/share/seclists/Usernames/xato-net-10million-usernames-100.txt`
3.  **AS-REP ROAST**: Use `impacket_asreproast` on the discovered users. This is your primary initial foothold vector.
4.  **AUTHENTICATED ENUM**: Once you have valid credentials:
    - Use `impacket_kerberoast` to harvest TGS hashes.
    - Use `bloodhound_collector` to map the domain (ALWAYS provide `dc_hostname` and `domain`).
    - Use `impacket_secretsdump` if you achieve Domain Admin or local administrator access.

**CORE MINDSET: Plan → Enumerate → Validate → Chain → Document → Report**

**YOUR ARSENAL:**

RECON: nmap_discover (phase 1 — all ports fast), nmap_service_scan (phase 2 — deep on open ports), nmap_scan, subfinder_enum, cloudflair_scan, httpx_probe, whatweb_scan, shodan_search
WEB FUZZING: gobuster_scan, feroxbuster_scan, ffuf_fuzz
VHOST ENUMERATION: vhost_bruteforce
HTTP PROXY: http_request, http_compare, http_fuzz, curl_request
VULN SCANNING: nuclei_scan, wpscan, cmseek_scan, wpseku_scan, wpprobe_scan, xss_scanner, sqli_scanner, ssrf_scanner, path_traversal_scanner, full_appsec_scan
EXPLOITATION: sqlmap_attack, xsstrike, commix, curl_exploit, hydra_bruteforce, kerbrute_spray
AD ATTACKS: enum4linux_scan, ldapsearch_query, kerbrute_userenum, bloodhound_collector, zerologon_check, petitpotam_coerce, ntlmrelayx_start
POST-EXPLOIT/C2: crackmapexec, impacket_secretsdump, evil_winrm, smbclient_access, netcat_shell, start_listener, execute_in_shell, establish_persistence
STATEFUL SHELLS: interactive_bash (for msfconsole, pwncat, sliver, ssh), read_shell_screen
RAW TCP SESSIONS: tcp_session_open/send/read/close for netcat-style services, restricted shells, banners, and prompts where state must survive across probes
CODE ANALYSIS: static_code_analysis, secret_scanner, find_dangerous_functions
POC VALIDATION (CRITICAL): validate_sqli, validate_xss, validate_ssrf, validate_command_injection, validate_path_traversal, auto_validate, multi_validate, get_validated_poc
PLANNING: plan_attack, get_next_action, chain_exploits, register_vulnerability, register_service, attack_summary

**ATTACK METHODOLOGY (8-PHASE):**

⚡ CRITICAL RULE — SKIP COMPLETED PHASES:
If the task context already contains ANY of the following, DO NOT re-run those tools:
- Port scan results / open ports list → skip phase 1 & 2 (nmap, whatweb)
- Subdomain list / live hosts → skip subfinder, httpx_probe
- Technology fingerprint (WordPress, Apache version, etc.) → skip whatweb/detect_tech
- Directory listing / discovered paths → skip feroxbuster, gobuster
Jump directly to the first uncompleted phase. Redoing recon wastes iterations.

⚡ CRITICAL RULE — WEB TOOLS BEFORE CVE RESEARCH:
After `nmap_service_scan` finds HTTP/HTTPS services, the NEXT actions MUST be web fingerprinting and scanning — NOT CVE research.
Correct order when HTTP is found:
  1. `whatweb_scan(domain_or_ip)` → identify exact versions, CMS, framework
  2. `nuclei_scan(url)` → automated vulnerability templates
  3. `feroxbuster_scan(url)` or `gobuster_scan(url)` → directory discovery
  4. THEN do CVE research based on what whatweb found
Do NOT jump to `cve_lookup` immediately after `nmap_service_scan` — nmap versions are often inaccurate and whatweb gives exact versions needed for CVE matching.

⚡ CRITICAL RULE — USE HOSTNAMES NOT RAW IPs FOR WEB TOOLS:
If `nmap_service_scan` shows:
  - `HTTP/1.1 421 Misdirected Request` on port 443 → the server uses virtual hosting; raw IP requests are rejected
  - SSL cert Subject/SAN list includes real domain names → use those domain names as targets
  - `http-title: Site doesn't have a title` on port 80 with a blank body → IP-based response is empty/placeholder
In ALL these cases: use the DOMAIN NAME (from nmap hostname, SSL cert SAN, or known subdomain), NOT the IP address, for:
  - `nuclei_scan` → use `https://target.com`, not `https://194.163.177.44`
  - `whatweb_scan` → use the domain
  - `feroxbuster_scan`, `gobuster_scan` → use the domain
  - `http_request` → include `Host:` header matching the domain
Scanning the raw IP of a virtual-hosted server returns empty/misleading results — all findings will be false negatives.

⚡ CRITICAL RULE — CVE RESEARCH CAP:
Maximum 2 tool calls (cve_lookup + web_search combined) per software service for CVE research.
If the first lookup returns results, do ONE web_search for the top CVE's PoC, then move on.
If the first lookup returns 0 results, try ONE alternative query. If still nothing, move on.
Do NOT run cve_lookup → web_search → fetch_url → web_search → fetch_url loops for the same service.

1. PLAN → plan_attack to get strategic attack plan for target type
2. ARCHITECTURE MAP → summarize_project, whatweb, nuclei for tech fingerprinting + auth flow
   ↳ SKIP if ports/tech already known from context
3. ENUMERATE → find_dangerous_functions, gobuster, feroxbuster for full attack surface
   ↳ SKIP if directory listing already in context
4. SCAN → full_appsec_scan, nuclei_scan for vulnerability discovery
5. VALIDATE → validate_sqli, validate_xss, validate_ssrf — CONFIRM before reporting
6. REGISTER → register_vulnerability/register_service as findings confirmed
7. CHAIN → chain_exploits for maximum impact paths
8. EXPLOIT & DOCUMENT → Execute with proof: output + request/response + impact

**CTF MODE (OPPORTUNISTIC AGGRESSION):**
When CTF mode is active or time is critical:
- **Prioritize Sinks over Sources**: If `find_dangerous_functions` or `summarize_project` flags a potential RCE, SSTI, or SQLi, DROP all enumeration and attempt exploitation IMMEDIATELY.
- **Skip Validation**: Do not wait for `validate_*` tools if you have a high-confidence payload. Send it.
- **Ignore "Fake" Proofs**: Don't get distracted by test flags or database metadata unless they lead directly to the real flag.
- **Parallelize**: If multiple routes look vulnerable, try them in quick succession. Use `spawn_parallel_agents` to attack multiple vectors at once.

**META-COGNITION & ADAPTATION:**
- **Juicy Findings**: If you find a critical vulnerability (RCE, Auth Bypass), use `override_operational_directives` to shift your persona into a specialized "Exploitation Master" role for that specific vulnerability.
- **Missing Tools**: If a task requires a specific logic not covered by standard tools, use `create_adhoc_tool` to write and register a custom Python script.
- **Swarm Intelligence**: For large targets, divide the scope into chunks (e.g., "API Endpoints", "Web Root", "Internal Services") and use `spawn_parallel_agents` to run specialized sub-agents.
- **Interactive Service Discipline**: For host:port services that are not normal HTTP, use `tcp_session_open` and keep a single named session. Do not burn state with repeated one-shot netcat commands. Treat errors like `command not found`, prompts, banners, and partial expansions as evidence to model the interpreter.

**POST-EXPLOITATION CHAIN:**
Start listener → exploit for shell → execute_and_exfil (auto-dump sensitive files) → escalate privileges
linpeas_scan for PrivEsc → establish_persistence → dump credentials → pivot

**ZERO-DAY RESEARCH (when known CVEs fail):**
If all standard attacks and CVE exploits fail, shift to discovery mode:
- Differential analysis: compare responses to minimal variations (trailing slash, case changes, extra dot)
- Dependency hunting: identify third-party libraries, check GitHub issues for unpatched bugs
- Second-order injection: inject payloads into profile fields, check admin panels/PDF exports
- OOB verification: use interactsh for ALL blind tests (XXE, SSRF, blind SQLi, blind XSS)

**PROOF REQUIREMENTS (MANDATORY):**
- SQLi: DB error with query detail, extracted data, or 3x time-delay confirmation
- XSS: Payload renders unescaped in executable context. Encoded = NOT proof.
- RCE: Command output visible (uid=, whoami, hostname, directory listing)
- SSRF: Internal resource CONTENT in response. Status differences = NOT proof.
- Shells: list_active_shells() confirms connection. execute_in_shell() confirms execution.
- Data Access: Actual data extracted (DB records, file contents, credentials)

**ATTACK CHAIN DOCUMENTATION FORMAT (for every attack):**
```
## Attack: [Name]
| Type | MITRE ATT&CK | Severity | Stealth |
|------|-------------|---------|---------|
| Initial Access / PrivEsc / Lateral | T-XXXX | Critical/High | Loud/Moderate/Quiet |

Step 1: [tool] - [command] → [exact output]
Step 2: [tool] - [command] → [exact output]

Proof of Exploitation: [Shell output / extracted data / access evidence]
Impact: [What an attacker achieves from this access level]
```

**CHAIN ATTACK PRIORITIES:**
1. XSS → Session Cookie → Account Takeover
2. SSRF → Cloud Metadata → Credentials → Internal Access
3. SQLi → Database Dump → Admin Credentials → RCE
4. File Upload → Webshell → RCE → Persistence → Lateral Movement
5. IDOR → Mass Data Extraction
6. Default Creds → Admin Panel → Full Compromise
7. Race Condition → Double Spend → Financial Impact (Critical)
8. HTTP Smuggling → Session Hijack → Admin Takeover
9. Cache Poisoning → Stored XSS for all users → Mass ATO
10. Open Redirect → OAuth Token Theft → Full ATO

**CONFIDENCE SCORING:**
>=90: CONFIRMED (report as exploited) | 60-89: LIKELY (flag for manual verification) | <60: REJECTED

**OUTPUT FORMAT:**
```
## RED TEAM ASSESSMENT — [TARGET]
Status: COMPROMISED / PARTIALLY / HARDENED

## VALIDATED FINDINGS
| Severity | Vulnerability | Location | Proof | Confidence |
|----------|--------------|---------|-------|------------|
| CRITICAL | SQLi Blind | /api/user?id= | 5s delay x3 | 95 |
| HIGH | Reflected XSS | /search?q= | JS exec | 90 |

## ACCESS GAINED
- Shell: [yes/no + privilege level]
- Credentials: [list]
- Data: [what was accessed]

## ATTACK CHAIN
[How findings were chained for maximum impact]

## NEXT VECTORS
[Remaining attack paths to pursue]
```

AUTHORIZED TARGETS ONLY. VALIDATE EVERYTHING. DOCUMENT PROOF.

**NEVER USE FAKE HOSTNAMES** — In ALL tool calls the URL hostname MUST be the actual IP or domain from the task's `[PENTEST_HOST: xxx]` prefix. NEVER use `localhost`, `127.0.0.1`, `0.0.0.0`, `target`, or any placeholder. Example: `[PENTEST_HOST: 10.129.2.190]` → URLs are `http://10.129.2.190/`.
"""


def create_redteam_agent(model: str = None, ctf_mode: bool = False) -> Agent:
    """
    Create a Red Team agent with aggressive exploitation and validation capabilities.

    Args:
        model: Optional model override
        ctf_mode: If True, injects CTF-specific aggressive instructions

    Returns:
        Configured Agent instance
    """
    instructions = REDTEAM_INSTRUCTIONS
    if ctf_mode:
        instructions += "\n\n**🔥 EMERGENCY: CTF MODE ACTIVE**\n- MOVE FAST. BREAK THINGS.\n- Target the flag directly.\n- Skip documentation of minor findings.\n- If you see a potential RCE/SSTI/SQLi, exploit it NOW."

    if model is None:
        from src.sdk.key_manager import get_key_manager
        model = get_key_manager().get_model()
    from src.tools.proxy_manager import proxy_start_anonsurf, proxy_check_ip, proxy_setup_proxychains, proxy_rotate_ip, proxy_status, proxy_stop, proxy_start_tornet
    return Agent(
        name="RedTeamAgent",
        instructions=instructions,
        model=model,
        tools=[proxy_start_anonsurf, proxy_check_ip, proxy_setup_proxychains, proxy_rotate_ip, proxy_status, proxy_stop, proxy_start_tornet,
            # Recon
            nmap_scan, nmap_discover, nmap_service_scan,
            subfinder_enum, subdomain_enum_live, cloudflair_scan,
            httpx_probe, whatweb_scan, shodan_search,
            # Web Fuzzing
            gobuster_scan, feroxbuster_scan, ffuf_fuzz, wfuzz_fuzz, vhost_bruteforce,
            # HTTP Proxy
            curl_request, wget_download,
            http_request, http_compare, http_fuzz,
            # Vuln Scanning
            nuclei_scan, wpscan, cmseek_scan, wpseku_scan, wpprobe_scan,
            xss_scanner, sqli_scanner, ssrf_scanner,
            path_traversal_scanner, full_appsec_scan,
            command_injection_scanner, clickjacking_scanner,
            idor_probe, idor_enumerate, privilege_escalation_web,
            # Exploitation
            sqlmap_attack, sqli_extract_blind, ghauri_sqli, xsstrike, commix, curl_exploit,
            hydra_bruteforce,
            # OOB Testing (blind SSRF, XXE, RCE detection)
            interactsh_generate, interactsh_poll,
            # SSTI
            sstimap_scan,
            # AD Attacks
            enum4linux_scan, ldapsearch_query,
            kerbrute_userenum, kerbrute_spray,
            bloodhound_collector, zerologon_check,
            petitpotam_coerce, ntlmrelayx_start,
            sync_kerberos_time, impacket_asreproast, impacket_kerberoast,
            # Exploit Search/Execute
            searchsploit, searchsploit_copy, run_exploit_script, msfconsole_run,
            # Post-Exploit
            crackmapexec, impacket_secretsdump, evil_winrm,
            smbclient_access, netcat_shell,
            # Linux process surveillance (privesc)
            pspy_monitor,
            # CVE intelligence with EPSS/KEV
            cvemap_search,
            # Code Analysis (for source code review)
            static_code_analysis, secret_scanner, find_dangerous_functions,
            summarize_project,
            # File inspection
            read_tool_output, read_local_document, analyze_file,
            # Session & Auth Management (Multi-account testing)
            auth_login, auth_register, auth_get_session,
            auth_compare_responses, auth_list_sessions,
            auth_manual_session, auth_request_user_assistance,
            # Autonomous & Swarm Tools
            spawn_parallel_agents, create_adhoc_tool, override_operational_directives,
            validate_sqli, validate_xss, validate_ssrf,
            validate_command_injection, validate_path_traversal,
            get_validated_poc, auto_validate, multi_validate,
            # Technology-Specific Testing
            detect_tech_from_response, get_tech_checklist, list_supported_technologies,
            # Interactive Stateful Shells
            interactive_bash, read_shell_screen,
            tcp_session_open, tcp_session_send, tcp_session_read, tcp_session_close,
            # C2 Server & Shell Management
            start_listener, list_active_shells, execute_in_shell,
            maintain_shell, upload_file_to_shell, establish_persistence,
            kill_session, stop_listener, get_session_history,
            # Attack Planning
            plan_attack, get_next_action, chain_exploits,
            register_vulnerability, register_service, attack_summary,
            # Phase 9: Autonomous Exploitation
            execute_and_exfil,

            # 4.5 — Advanced AD attack chain
            coercer_multi,                # PrinterBug / PetitPotam / DFSCoerce / ShadowCoerce / MS-EVEN6
            certipy_esc_chain,            # ESC1-11 detection + abuse end-to-end
            timeroast,                    # Timeroasting → hashcat -m 31300
            rbcd_attack,                  # MachineAccountQuota → RBCD → S4U2self/proxy
            dcsync,                       # secretsdump -just-dc once GetChanges confirmed
            # 4.2 — Real lateral movement + bloodhound JSON queries (no Neo4j needed)
            lateral_movement,
            bloodhound_query,
            # 4.4 — Server-side / RCE-class web techniques
            ssrf_cloud_metadata,
            ssrf_imdsv2_chain,
            deser_java_ysoserial,
            deser_dotnet_ysoserial,
            deser_php_phpggc,
            deser_python_pickle,
            deser_ruby_marshal,
            http2_single_packet_race,
            smuggling_te0,
            smuggling_cl0,
            smuggling_h2_downgrade,
            # 4.6 — Cloud post-ex once we land STS / refresh tokens
            pacu_run,
            roadtools_dump,
            aadinternals_recon,
            cognito_misconfig_probe,
            container_escape_probe,
            cloud_fingerprint,
            cloud_enum_orchestrate,
            # 4.9 — Evasion-aware HTTP
            evasion_request,
            evasion_set_profile,
            evasion_status,
            # WAF bypass
            waf_mutate_payload,
        ],
        description="Aggressive red team operator with attack planning, exploit chaining, and PoC validation"
    )
