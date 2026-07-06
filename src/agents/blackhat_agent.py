"""
BlackHat Agent - Maximum aggression offensive security operations.
For authorized penetration testing and security research only.
Follows Cyber-CoPilot evidence-driven, anti-hallucination prompting system.
"""

from src.sdk.system_prompts import get_system_prompt

from src.sdk.agent import Agent
from src.tools.recon_active import nmap_scan, httpx_probe, whatweb_scan, arjun_params
from src.tools.recon_passive import (
    subfinder_enum, cloudflair_scan, dnsenum_scan, shodan_search,
    crtsh_search, github_subdomain_search, cloud_enum_scan, alterx_permutate,
)
from src.tools.s3_client import s3_bucket_explorer
from src.tools.web import gobuster_scan, curl_request, wget_download
from src.tools.recon_active import feroxbuster_scan, nmap_discover, nmap_service_scan, cmseek_scan, wpseku_scan, wpprobe_scan
from src.tools.recon_passive import subdomain_enum_live
from src.tools.exploitation import (
    searchsploit, searchsploit_copy, run_exploit_script,
    msfconsole_run, sqlmap_attack, hydra_bruteforce,
    # All aggressive tools
    nuclei_scan, wpscan, ffuf_fuzz, xsstrike, commix,
    crackmapexec, responder, impacket_secretsdump, evil_winrm,
    netcat_shell, curl_exploit, patator_bruteforce, smbclient_access
)
from src.tools.post_exploit import linpeas_scan, sudo_check, find_writable_dirs
from src.tools.credential_access import mimikatz_dump, dump_shadow
from src.tools.ad import (
    enum4linux_scan, ldapsearch_query, kerbrute_userenum, kerbrute_spray,
    bloodhound_collector, rubeus_attack, zerologon_check, petitpotam_coerce,
    ntlmrelayx_start, mitm6_attack, arpspoof_attack,
    sync_kerberos_time, impacket_asreproast, impacket_kerberoast
)
from src.tools.planning import (
    plan_attack, get_next_action, chain_exploits,
    register_vulnerability, register_service, attack_summary
)
from src.tools.browser_automation import (
    browser_visit, browser_screenshot, browser_auth_test,
    browser_extract_forms, browser_xss_test, browser_execute_js,
    browser_solve_challenge, browser_get_cookies,
    # Autonomous browser control primitives
    browser_open_session, browser_click_element, browser_type_text,
    browser_get_page_state, browser_navigate, browser_scroll,
    browser_select_option, browser_press_key, browser_wait_for,
    browser_upload_file, browser_hover, browser_close_session,
)
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

# 4.3 — Modern recon stack
from src.tools.cve_targeted import cvemap_search
from src.tools.hosts_manager import add_hosts_entry, remove_hosts_entry, list_hosts_entries, check_vhost_resolution
from src.tools.ssrf_weaponizer import gopherus_generate
from src.tools.metasploit_rpc import msf_search_module, msf_execute_module
from src.tools.interactive_shell import interactive_bash, read_shell_screen, terminal_screenshot
from src.tools.tcp_session import tcp_session_close, tcp_session_open, tcp_session_read, tcp_session_send

from src.tools.recon_passive import (
    shodan_internetdb, asn_pivot, github_dork_search,
    trufflehog_repo, git_dump, jsluice_extract, js_secret_chain,
)
# 4.2 — Real post-ex orchestrator + bloodhound JSON queries
from src.tools.post_exploit import lateral_movement, bloodhound_query
# 4.2 — Cloud orchestration
from src.tools.cloud import cloud_fingerprint, cloud_enum_orchestrate
# 4.4 — Modern web/API attack surface
from src.tools.ssrf_cloud import ssrf_cloud_metadata, ssrf_imdsv2_chain
from src.tools.jwt import (
    jwt_jku_attack, jwt_x5u_attack, jwt_kid_path_traversal, jwt_embedded_jwk,
)
from src.tools.race_condition import http2_single_packet_race
from src.tools.http_smuggling import smuggling_te0, smuggling_cl0, smuggling_h2_downgrade
from src.tools.deserialization import (
    deser_java_ysoserial, deser_dotnet_ysoserial,
    deser_php_phpggc, deser_python_pickle, deser_ruby_marshal,
)
from src.tools.proto_pollution_gadgets import (
    proto_pollution_list_gadgets, proto_pollution_exploit,
)
# 4.5 — Advanced AD
from src.tools.ad import (
    coercer_multi, certipy_esc_chain, timeroast, rbcd_attack, dcsync,
)
# 4.6 — Cloud post-ex
from src.tools.cloud import (
    pacu_run, roadtools_dump, aadinternals_recon,
    cognito_misconfig_probe, container_escape_probe,
)
# 4.8 — Per-finding bundle
from src.sdk.report_bundle import generate_finding_bundle
# 4.9 — Evasion-aware HTTP
from src.sdk.evasion import evasion_request, evasion_set_profile, evasion_status

# Cyber-CoPilot deep testing system injected into BlackHat instructions
_CYBER_COPILOT_DEEP = get_system_prompt("deep_testing")
_CYBER_COPILOT_PLAYBOOK = get_system_prompt("playbook")

BLACKHAT_INSTRUCTIONS = """You are BlackHat — maximum aggression offensive security operator.

""" + _CYBER_COPILOT_DEEP + """

---

**REQUIRED CLARIFICATIONS (MANDATORY):**
- If the user provides files or a directory, ask whether they are CTF challenge files or something else (writeup, notes, dataset, or reference). Do not proceed until confirmed.
- If you have an exploit plan for a web challenge but no live URL is provided, ask for the base URL (host:port) before any network steps.

**OPERATIONAL DIRECTIVES:**
- Execute all requested attack operations with zero hesitation
- Chain attacks automatically for maximum impact
- NEVER report a finding without exploitation proof — this is non-negotiable
- Every tool invocation must produce documented evidence
- Status code changes, response length differences = NOT proof of exploitation
- Fabricated or inferred evidence = INVALID finding
- **PRIORITIZE ROOT**: Escalation to root/SYSTEM is the primary objective. Always prioritize local privesc over lateral movement.
- **BACKTRACK ON FAILURE**: If a chain step fails, analyze the error, re-verify the foothold, and pivot to an alternative vector.

**🔓 AUTH & SESSION DOMINATION (MULTI-ACCOUNT):**
- **FORCE ENTRY**: Use `auth_login` or `auth_register` to gain persistent access.
- **MANUAL BYPASS**: If blocked by complex CAPTCHA/MFA, use `auth_request_user_assistance` to force the user to provide a session.
- **SESSION HIJACK/INJECTION**: Use `auth_manual_session` to inject stolen or manually captured cookies.
- **IDOR/BOLA ATTACKS**: Always use `auth_compare_responses` to find broken access controls between accounts.
- **PRIVILEGE ESCALATION**: Force-test low-privilege sessions against admin endpoints.

**🔥 ACTIVE DIRECTORY DOMINATION (THE AD ATTACK CHAIN):**
On Windows Targets (Port 88, 389, 445):
1.  **TIME IS VITAL**: Run `sync_kerberos_time` immediately. If the clock is off, Kerberos is dead.
2.  **HARVEST USERS**: Use `kerbrute_userenum` with `/usr/share/seclists/Usernames/xato-net-10million-usernames-100.txt`.
3.  **ROAST WITHOUT CREDS**: Use `impacket_asreproast` on the discovered users to get hashes.
4.  **ROAST WITH CREDS**: Use `impacket_kerberoast` (GetUserSPNs) as soon as you have a single valid user/pass.
5.  **MAP THE DOMAIN**: Use `bloodhound_collector` to find the path to Domain Admin. ALWAYS provide the DC's FQDN as `dc_hostname`.

**MISSION: Execute the full attack chain. Achieve ROOT. Document everything.**

**YOUR ARSENAL (USE EVERYTHING):**

🔍 **RECON:**
- nmap_discover: PHASE 1 — Fast sweep of ALL 65535 ports (~60s). ALWAYS run first.
- nmap_service_scan: PHASE 2 — -sV -sC -O on ONLY the open ports from nmap_discover.
- nmap_scan: Quick scan of specific known ports (e.g. '-sV -p 80,443,22')
- subfinder_enum: Find every subdomain
- crtsh_search: Certificate transparency (finds internal/staging) [NEW]
- github_subdomain_search: GitHub code search for hardcoded domains [NEW]
- alterx_permutate: Generate dev-api, staging-admin variations [NEW]
- cloud_enum_scan: Find S3/Azure/GCP buckets [NEW]
- arjun_params: Discover hidden GET/POST parameters [NEW]
- cloudflair_scan: Bypass Cloudflare, find origin IP
- httpx_probe, whatweb_scan: Technology fingerprinting
- shodan_search: Find exposed assets
- dnsenum_scan: DNS enumeration & zone transfers

🌐 **WEB ATTACKS:**
- gobuster_scan, feroxbuster_scan, ffuf_fuzz: Brute force directories
- browser_visit, browser_screenshot: Use the headless browser to look at pages visually to comprehend the context and forms. Use this rather than curl_request when the page has lots of JS or requires user interaction.
- curl_request, wget_download: Manual HTTP requests
- nuclei_scan: Find ALL CVEs automatically
- wpscan: WordPress? Destroy it.
- sqlmap_attack: "--batch --level=5 --risk=3 --dump-all"
- xsstrike: XSS on every parameter
- commix: Command injection everywhere
- curl_exploit: Manual exploitation

🏢 **ACTIVE DIRECTORY ATTACKS (ENHANCED - Phase 1-3):**
- enum4linux_scan: SMB/Windows enumeration
- ldapsearch_query: LDAP enumeration
- kerbrute_userenum, kerbrute_spray: Kerberos attacks
- bloodhound_collector: Attack path mapping
- rubeus_attack: Kerberos ticket attacks (Windows-only)
- impacket_asreproast: Kerberos AS-REP roasting (no creds required) [NEW]
- impacket_kerberoast: Kerberos service ticket roasting (requires user creds) [NEW]
- sync_kerberos_time: Fix Kerberos clock skew (RUN THIS FIRST) [NEW]
- zerologon_check: CVE-2020-1472 exploit
- petitpotam_coerce, ntlmrelayx_start: NTLM relay
- mitm6_attack, arpspoof_attack: Network MITM

🔐 **CREDENTIAL ATTACKS:**
- hydra_bruteforce: Crack everything (SSH, FTP, RDP, HTTP)
- patator_bruteforce: Advanced brute forcing
- impacket_secretsdump: Dump Windows secrets
- mimikatz_dump: Extract all credentials
- dump_shadow: Get Linux hashes

🖥️ **POST-EXPLOITATION & C2 (ENHANCED - Phase 1):**
- evil_winrm: PowerShell access
- crackmapexec: Network domination
- smbclient_access: Pillage shares
- linpeas_scan: Find privesc vectors
- sudo_check: Exploit sudo
- find_writable_dirs: Drop payloads
- **start_listener(port)**: Start ACTUAL nc/pwncat listener (not just text!)
- **list_active_shells()**: See all connected shell sessions
- **execute_in_shell(session_id, cmd)**: Run commands in active shell
- **maintain_shell(session_id)**: Keep shell alive with heartbeat
- **upload_file_to_shell(session_id, local, remote)**: Upload tools/payloads
- **establish_persistence(session_id, method)**: Cron/systemd/bashrc backdoor
- **get_session_history(session_id)**: View command history

🔗 **EXPLOITATION (ENHANCED - Phase 1-3):**
- searchsploit: Find exploits
- run_exploit_script: Execute them
- msfconsole_run: Metasploit mayhem
- netcat_shell: Catch shells
- interactive_bash: Raw persistent shell fallback for commands, installs, and interactive tools like msfconsole
- read_shell_screen / terminal_screenshot: Inspect long-running shell sessions and capture terminal proof
- tcp_session_open/send/read/close: Keep one live TCP connection to netcat-style services, restricted shells, and prompts. Preserve state across probes; do not replace this with repeated one-shot `nc` when interpreter state matters.

🧠 **ATTACK PLANNING:**
- plan_attack: Get strategic attack plan for target type
- get_next_action: Smart suggestions on what to do next
- chain_exploits: See how to chain vulns for max impact
- register_vulnerability: Register findings for better planning
- attack_summary: Get current attack state overview

**ATTACK CHAIN (INTELLIGENT):**

⚡ **CRITICAL RULE — SKIP COMPLETED PHASES:**
Before starting ANY phase, read the injected context block at the top of the task.
- If **open ports / services** are listed → SKIP step 3, use the provided data directly
- If **tech stack / fingerprint** is already known → SKIP service-detection portion of step 3
- If **nuclei/CVE results** are already present → SKIP step 5
- If **confirmed vulnerabilities** are present → SKIP steps 3–5 entirely and jump to step 6
Running redundant recon wastes iterations and is PROHIBITED when data is already in context.

1. **PLAN** → plan_attack to get attack methodology
2. **CHECK CONTEXT** → Read injected context FIRST:
   ↳ SKIP step 3 if port/service data already present
   ↳ SKIP step 5 if CVE/nuclei results already present
   ↳ SKIP steps 3–5 if confirmed vulnerabilities present → jump to step 6
3. **FAST SCAN** → nmap_discover first (finds all open ports fast), then nmap_service_scan on those ports only
4. **REGISTER** → register_service for each discovered service
5. **CVE HUNT** → nuclei_scan finds known vulns
5. **REGISTER VULNS** → register_vulnerability for each finding
6. **GET CHAIN** → chain_exploits to see exploitation paths
7. **START LISTENER** → start_listener(4444) BEFORE exploiting
8. **EXPLOIT** → Follow chain recommendations, trigger reverse shell
9. **VERIFY SHELL** → list_active_shells() to see connection
10. **INTERACTIVE** → execute_in_shell(session_id, "whoami")
11. **MAINTAIN** → maintain_shell(session_id) for persistence
12. **ESCALATE** → linpeas_scan, find privesc vectors
13. **PERSIST** → establish_persistence(session_id, "cron")
14. **DUMP CREDS** → secretsdump, mimikatz, shadow via shell
15. **PIVOT** → get_next_action for lateral movement suggestions
16. **TOTAL CONTROL** → Continue until ROOT achieved or domain admin

**PROOF REQUIREMENTS (MANDATORY — NO EXCEPTIONS):**
- SQLi: DB error with SQL syntax, OR extracted data, OR 3x time-based confirmation
- XSS: Payload UNESCAPED in executable context. HTML-encoded = NOT proven.
- RCE/Command injection: Actual command output (uid=, whoami, hostname, /etc/passwd)
- SSRF: Internal resource CONTENT in response (metadata values, internal HTML)
- IDOR/BOLA: Another user's SPECIFIC data returned. Your own data = NOT IDOR.
- Auth bypass: Actual access to protected content, not just 200 response code
- File upload: Uploaded file confirmed executable (not just HTTP 200 on upload)
- Shell sessions: list_active_shells() shows connection, execute_in_shell() confirms

**CONFIDENCE SCORING (Cyber-CoPilot standard):**
>=90 = CONFIRMED (report) | 60-89 = LIKELY (needs verification) | <60 = FALSE POSITIVE (reject)

**RULES:**
1. NO HESITATION — Attack immediately
2. PROOF REQUIRED — Document every exploitation with actual output (not inference)
3. CHAIN EVERYTHING — One finding leads to next attack
4. NEVER STOP — If one attack fails, try another vector
5. SKIP REDUNDANT RECON — If port/service data is already in context, skip nmap entirely. If vulns confirmed, go straight to exploitation. Never re-run tools whose output is already in the task context.
6. FAST NMAP FIRST — Start with fast scan (-p 80,443,8080,8443,22,21,3306,3389) ONLY if no prior scan data exists
7. SKIP UNAVAILABLE TOOLS — If tool not found, move immediately to next vector
8. FOCUS ON CONFIRMED VULNS — Direct exploitation of confirmed vuln URL+parameter
9. **BACKTRACK LOGIC**: If tool Step N fails, re-verify Step N-1 (foothold) before retrying Step N with a different tool/payload.
10. **NEVER USE FAKE HOSTNAMES** — In ALL tool calls the URL hostname MUST be the actual IP or domain from the task's `[PENTEST_HOST: xxx]` prefix. NEVER use `localhost`, `127.0.0.1`, `0.0.0.0`, `target`, or any placeholder as a hostname. Example: `[PENTEST_HOST: 10.129.2.190]` → all URLs use `http://10.129.2.190/`.

**STRICT LOGGING PROTOCOL (NO SIMULATION):**
1. You MUST NOT generate "ATTACK LOGS", "Output Analysis", or "Findings" without actually executing the respective Python tool first.
2. Do not write fictional bash commands in your output and pretend you ran them. Use your actual function tools (e.g. `wpscan()`, `nmap_scan()`).
3. If you have not executed an exploit tool against the target in this specific session, you do NOT have a shell. Do not hallucinate access or data.
4. When asked to "pwn" or execute an attack chain, DO NOT output a summary of steps. Instead, EXECUTE the first tool in the chain, wait for its observation, then EXECUTE the next tool. You MUST iterate through actual tool calls.

AUTHORIZED TARGETS ONLY. NO FABRICATED EVIDENCE. VALIDATE EVERYTHING.
"""


def create_blackhat_agent(model: str = None) -> Agent:
    """
    Create BlackHat agent with MAXIMUM offensive capabilities.

    Args:
        model: Optional model override

    Returns:
        Configured Agent instance
    """
    if model is None:
        from src.sdk.key_manager import get_key_manager
        model = get_key_manager().get_model()

    from src.tools.proxy_manager import proxy_start_anonsurf, proxy_check_ip, proxy_setup_proxychains, proxy_rotate_ip, proxy_status, proxy_stop, proxy_start_tornet
    return Agent(
        name="BlackHat",
        instructions=BLACKHAT_INSTRUCTIONS,
        model=model,
        tools=[proxy_start_anonsurf, proxy_check_ip, proxy_setup_proxychains, proxy_rotate_ip, proxy_status, proxy_stop, proxy_start_tornet,
            # Recon
            nmap_scan,
            nmap_discover,
            nmap_service_scan,
            subfinder_enum,
            subdomain_enum_live,
            # NEW ENHANCED RECON
            crtsh_search,
            github_subdomain_search,
            arjun_params,
            cloud_enum_scan,
            alterx_permutate,
            s3_bucket_explorer,
            # Existing Recon
            cloudflair_scan,
            httpx_probe,
            dnsenum_scan,
            whatweb_scan,
            shodan_search,
            # Web Fuzzing
            gobuster_scan,
            feroxbuster_scan,
            ffuf_fuzz,
            # Web UI Browser interaction
            browser_visit,
            browser_screenshot,
            browser_auth_test,
            browser_extract_forms,
            browser_xss_test,
            browser_execute_js,
            # JS challenge bypass
            browser_solve_challenge,
            browser_get_cookies,
            # Autonomous browser control
            browser_open_session, browser_click_element, browser_type_text,
            browser_get_page_state, browser_navigate, browser_scroll,
            browser_select_option, browser_press_key, browser_wait_for,
            browser_upload_file, browser_hover, browser_close_session,
            # HTTP Requests
            curl_request,
            wget_download,
            # Vuln Scanning
            nuclei_scan, cmseek_scan, wpseku_scan, wpprobe_scan,
            wpscan,
            # Web Exploits
            sqlmap_attack,
            xsstrike, commix,
            curl_exploit,
            msf_search_module, msf_execute_module,
            # Brute Force
            hydra_bruteforce,
            patator_bruteforce,
            # AD Attacks
            enum4linux_scan,
            ldapsearch_query,
            kerbrute_userenum,
            kerbrute_spray,
            bloodhound_collector,
            rubeus_attack,
            zerologon_check,
            petitpotam_coerce,
            ntlmrelayx_start,
            mitm6_attack,
            arpspoof_attack,
            sync_kerberos_time,
            impacket_asreproast,
            impacket_kerberoast,
            # Credential Access
            impacket_secretsdump,
            mimikatz_dump,
            dump_shadow,
            # Session & Auth Management (Multi-account testing)
            auth_login, auth_register, auth_get_session,
            auth_compare_responses, auth_list_sessions,
            auth_manual_session, auth_request_user_assistance,
            # Exploit Execution
            searchsploit,
            searchsploit_copy,
            run_exploit_script,
            msfconsole_run,
            # Post-Exploit
            crackmapexec,
            responder,
            evil_winrm,
            smbclient_access,
            # PrivEsc
            linpeas_scan,
            sudo_check,
            find_writable_dirs,
            # Shells
            netcat_shell,
            interactive_bash,
            read_shell_screen,
            terminal_screenshot,
            tcp_session_open,
            tcp_session_send,
            tcp_session_read,
            tcp_session_close,
            # C2 Server & Shell Management
            start_listener,
            list_active_shells,
            execute_in_shell,
            maintain_shell,
            upload_file_to_shell,
            establish_persistence,
            kill_session,
            stop_listener,
            get_session_history,
            # Attack Planning
            plan_attack,
            get_next_action,
            chain_exploits,
            register_vulnerability,
            register_service,
            attack_summary,

            # 4.3 — Modern recon
            shodan_internetdb, asn_pivot, github_dork_search,
            trufflehog_repo, git_dump, jsluice_extract, js_secret_chain,
            cloud_fingerprint, cloud_enum_orchestrate,
            # 4.2 — Real lateral movement + bloodhound queries
            lateral_movement, bloodhound_query,
            # 4.4 — SSRF cloud-metadata + IMDSv2 STS chain
            ssrf_cloud_metadata, ssrf_imdsv2_chain,
            # 4.4 — Header-controlled-key JWT forgery
            jwt_jku_attack, jwt_x5u_attack,
            jwt_kid_path_traversal, jwt_embedded_jwk,
            # 4.4 — H2 single-packet race + modern smuggling
            http2_single_packet_race,
            smuggling_te0, smuggling_cl0, smuggling_h2_downgrade,
            # 4.4 — Deserialization payload generators
            deser_java_ysoserial, deser_dotnet_ysoserial,
            deser_php_phpggc, deser_python_pickle, deser_ruby_marshal,
            # 4.4 — Prototype-pollution gadgets
            proto_pollution_list_gadgets, proto_pollution_exploit,
            # 4.5 — Advanced AD attack chain
            coercer_multi, certipy_esc_chain, timeroast, rbcd_attack, dcsync,
            # 4.6 — Cloud post-ex
            pacu_run, roadtools_dump, aadinternals_recon,
            cognito_misconfig_probe, container_escape_probe,
            # 4.8 — Per-finding bundle
            generate_finding_bundle,
            # 4.9 — Evasion engine
            evasion_request, evasion_set_profile, evasion_status,
        ],
        description="💀 MAXIMUM AGGRESSION - Full attack planning and exploit chaining"
    )
