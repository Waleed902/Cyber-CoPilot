"""
Cyber-CoPilot Tools Package
Organized by MITRE ATT&CK Tactics
"""

# Suppress InsecureRequestWarning globally — many tools use verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Reconnaissance (TA0043)
from .tempmail import (
    tempmail_generate_address,
    tempmail_list_messages,
    tempmail_read_message,
    tempmail_wait_for_message,
)
from .recon_active import (
    nmap_scan, httpx_probe, whatweb_scan,
    jarm_scan, kiterunner_scan, corsy_scan, retirejs_scan,
    wafw00f_detect, sslscan_check,
    nc_connect, nc_scan, telnet_connect, telnet_send,
    linkfinder_js, secretfinder_js, jsparser_analyze,
    ffuf_content_fuzz, feroxbuster_scan, katana_crawl, hakrawler,
    httpx_tech_detect, wappalyzer_scan, cors_check, security_headers_check,
    connectivity_check,
    interactsh_start, interactsh_poll, interactsh_stop,
    redis_exploit_check, mongodb_exploit_check, elasticsearch_exploit_check,
    docker_api_exploit_check, snmp_exploit_check, memcached_exploit_check,
    nmap_discover, nmap_service_scan, arjun_params,
    cmseek_scan, wpseku_scan, wpprobe_scan, gqlmap_scan, sql_shell, smbmap_scan,
    snmp_check, certipy_run, odat_run, redis_cli_check, gowitness_screenshot
)
from .recon_passive import (
    whois_lookup, dig_lookup, subfinder_enum, dnsrecon_enum,
    cloudflair_scan, dnsenum_scan, shodan_search,
    amass_enum, fierce_scan,
    sublist3r_enum, waybackurls, paramspider,
    subdomain_takeover_scan, passive_recon_chain,
)

# Advanced Integrations (ScoutSuite, Prowler, NetExec, Gitleaks, etc.)
from .advanced_integrations import (
    scoutsuite_scan, prowler_scan, graphql_cop_scan, inql_scan,
    gopherus_payload, netexec_scan, certify_scan, winpeas_scan,
    pspy_run, traitor_run, seatbelt_run, gitleaks_audit, pip_audit_scan
)

# Web/Initial Access (TA0001)
from .web import (
    gobuster_scan, dirsearch_scan, curl_request, wget_download,
    save_file_to_session,
    # Discovery tools
    arjun_scan, gau_urls, gospider_crawl,
    # Offensive vhost and fuzzing helpers
    vhost_bruteforce, wfuzz_fuzz,
)
from .devtools_pivot import (
    mcp_inspector_audit,
    mcp_inspector_connect_stdio,
    jupyter_terminal_command,
)

# Credential Access (TA0006)
from .crypto import john_crack, john_show, hashcat_crack, hash_identifier, create_hash, nth_identify, ssh_key_crack

# Execution/Exploitation (TA0002)
from .exploit_craft import genetic_mutation_fuzz
from .exploitation import (
    searchsploit, searchsploit_json, searchsploit_copy,
    run_exploit_script, msfconsole_run, sqlmap_attack, hydra_bruteforce,
    # New aggressive tools
    nuclei_scan, nuclei_triage, wpscan, ffuf_fuzz, xsstrike, commix,
    crackmapexec, responder, impacket_secretsdump, evil_winrm,
    netcat_shell, curl_exploit, patator_bruteforce, smbclient_access,
    # Advanced exploitation
    dalfox_scan, tplmap_scan, jwt_tool_attack, nosqlmap_attack, pwncat_shell
)

# Collection/Forensics (TA0009)
from .forensics import (
    tshark_analyze, binwalk_analyze, strings_extract, exiftool_metadata,
    ctf_command,
    read_tool_output, read_local_document,
    wasm_analyze, upx_unpack, java_decompile, javap_disassemble, jar_explore,
    qemu_emulate, binwalk_extract, foremost_extract, steg_analyze, analyze_file
)
from .ctf_analysis import (
    ctf_identify, binary_triage, strings_extract_ctf, forensics_carve,
    stego_check, crypto_identify, decompile_func, pcap_analyze,
    elf_security, ctf_web_triage
)
from .code_analysis import (
    repo_map, pattern_search, concat_code, ast_symbol_search,
    static_code_analysis, semgrep_scan, framework_audit
)
from .godot import godot_pck_extract, godot_gds_decompile

# Privilege Escalation (TA0004)
from .post_exploit import linpeas_scan, sudo_check, find_writable_dirs, gtfobins_check

# Lateral Movement (TA0008)
from .post_exploit import (
    ssh_scan, crackmapexec_smb, psexec_exec, ssh_exec, ftp_connect,
    # Network tunneling & pivoting
    ssh_port_forward, chisel_tunnel, socat_relay,
)

# Credential Access (TA0006) - Advanced
from .credential_access import mimikatz_dump, dump_shadow, responder_capture, secretsdump

# Active Directory Attacks
from .ad import (
    enum4linux_scan, ldapsearch_query,
    kerbrute_userenum, kerbrute_spray,
    bloodhound_collector, rubeus_attack,
    zerologon_check, petitpotam_coerce,
    ntlmrelayx_start, mitm6_attack, arpspoof_attack,
    sync_kerberos_time,
    impacket_asreproast, impacket_kerberoast,
)

# Vulnerability Database
from .vuln_db import (
    register_vulnerability as db_register_vulnerability,
    get_all_vulnerabilities,
    update_vulnerability_status
)

# Attack Planning (Strategic)
from .planning import (
    plan_attack, get_next_action, chain_exploits,
    register_vulnerability, register_service, attack_summary,
    generate_attack_plan, modify_attack_plan, show_current_plan,
    record_ctf_solution, get_ctf_tips,
    # Knowledge Base tools (Phase 2)
    list_vuln_types, get_payloads, get_vuln_info, search_vulns,
    # Exploit Chain Engine (Phase 4)
    build_exploit_chain, list_chain_templates, score_attack_surface,
    # Cross-Scan Learning (Phase 5)
    record_scan_findings, get_tool_recommendations, what_worked_before, scan_history_stats,
    # Workflow Orchestration (NEW — auto-triage, auto-bypass, auto-param)
    nuclei_scan_and_triage, dir_enum_with_bypass, auto_param_scan,
)
from .knowledge_importer import (
    import_bugbounty_knowledge,
    bugbounty_knowledge_stats,
    query_bugbounty_knowledge,
)
from .framework import (
    record_http_observation, suggest_adaptive_tests,
    register_finding_candidate, promote_finding_with_evidence,
    build_attack_chains, generate_evidence_report, framework_maturity_status,
)
from .hypothesis_tools import (
    set_engagement_mode,
    generate_hypotheses,
    show_active_hypotheses,
    schedule_next_hypothesis,
    select_hypothesis_tools,
    record_hypothesis_result,
    show_coverage_requirements,
)

from .artifacts import artifact_glob, artifact_grep, artifact_read, artifact_write
from .long_tasks import long_task_list, long_task_resume, long_task_start, long_task_status
from .tcp_session import tcp_session_close, tcp_session_open, tcp_session_read, tcp_session_send
from .internet import fetch_url, web_search
from .shell_memory import list_uploaded_shells, record_uploaded_shell

# AppSec Tools (XSS, SQLi, SSRF, CSRF, XXE)
from .appsec import (
    xss_scanner, sqli_scanner, ssrf_scanner, path_traversal_scanner,
    csrf_analyzer, xxe_scanner, header_injection_scanner, full_appsec_scan,
    validate_browser_xss, validate_oast_ssrf, validate_oast_xxe,
    managed_oast_blind_validation,
    authenticated_app_mapper, two_account_authz_engine,
    managed_oast_ssrf_validation, build_recon_attack_paths,
    business_workflow_state_recorder,
    open_redirect_scan, nosql_injection_probe, ldap_injection_probe, crlf_injection_probe,
    command_injection_scanner, clickjacking_scanner, registration_tester,
    password_reset_tester
)

# Interactive Shell
from .interactive_shell import interactive_bash, read_shell_screen, terminal_screenshot

# HTTP Proxy Tools
from .http_proxy import (
    http_request, http_intercept_modify, http_compare, http_fuzz,
    session_status, session_set_cookie, session_set_header, session_clear
)

# Browser Automation Tools
from .browser_automation import (
    browser_visit, browser_xss_test, browser_auth_test, browser_execute_js,
    browser_screenshot, browser_extract_forms, browser_check_available,
    dom_vulnerability_scanner,
    # Persistent session tools
    browser_open_session, browser_click_element, browser_type_text,
    browser_get_session_html, browser_close_session,
    # Autonomous browser control primitives
    browser_get_page_state, browser_navigate, browser_scroll,
    browser_select_option, browser_press_key, browser_wait_for,
    browser_upload_file, browser_hover,
    # Challenge bypass
    browser_solve_challenge, browser_get_cookies,
)

# WAF Detector + Bypass Engine (Phase 3)
from .http_evasion import waf_fingerprint, waf_bypass_payloads, apply_waf_bypass

# Proxy Manager — IP Rotation & Anti-Ban
from .proxy_manager import (
    proxy_status, proxy_start_tornet, proxy_start_anonsurf,
    proxy_setup_proxychains, proxy_rotate_ip, proxy_stop, proxy_check_ip,
)

# Code Analysis Tools
from .code_analysis import (
    static_code_analysis, secret_scanner, dependency_scan, find_dangerous_functions,
    summarize_project, repo_map, pattern_search, concat_code, ast_symbol_search,
    semgrep_scan, framework_audit,
)

# CTF Analysis Tools
from .ctf_analysis import (
    ctf_identify,
    binary_triage,
    strings_extract_ctf,
    forensics_carve,
    stego_check,
    crypto_identify,
    decompile_func,
    pcap_analyze,
    elf_security,
    ctf_web_triage,
)

# PoC Validation Tools
from .poc_validation import (
    validate_sqli, validate_xss, validate_ssrf, validate_command_injection,
    validate_path_traversal, get_validated_poc, auto_validate, multi_validate,
    score_finding, batch_score_findings, multi_agent_verify
)

# Advanced Web Detection Tools (CORS, Host Header, GraphQL, JWT, Prototype Pollution, Race Condition, Deser)
from .web import (
    cors_scan, host_header_injection, graphql_probe,
    jwt_confusion_attack, prototype_pollution_scan,
    second_order_sqli, path_confusion_probe
)
from .graphql_security import graphql_schema_inventory, graphql_authz_replay_probe
from .wordpress import wordpress_xmlrpc_audit

# Race Condition & HTTP/2 Tools
from .race_condition import race_condition_scanner
from .race_condition import http2_rapid_reset_check

# Access Control Testing
from .access_control import idor_probe, privilege_escalation_web

# Deserialization Probe
from .deserialization import deserialization_probe

# Camaleon CMS Exploit Tools (CVE-2025-2304, CVE-2024-46987)
from .camaleon_exploit import camaleon_privesc, camaleon_lfi, camaleon_admin_enum

# Phase 7.1 — Advanced Bug Bounty Techniques
from .idor_bola import idor_sequential_probe, idor_uuid_probe, bola_param_tamper
from .oauth import oauth_redirect_uri_bypass, oauth_state_csrf_check, oauth_token_leakage_check, oauth_pkce_downgrade, oauth_security_scanner
from .business_logic import price_manipulation_probe, coupon_abuse_probe, workflow_bypass_probe, account_state_abuse_probe
from .cache_poisoning import cache_poisoning_unkeyed_header, cache_deception_probe, cache_parameter_cloaking
from .mfa_bypass import mfa_response_manipulation, otp_bruteforce_probe, mfa_backup_code_probe
from .llm_injection import llm_prompt_injection_probe, llm_indirect_injection_probe, llm_data_exfiltration_probe, llm_jailbreak_probe

# Real-World Target Expansion
from .saml_attacks import saml_response_decode, saml_xsw_attack, saml_replay_probe, saml_attr_manipulation
from .mass_assignment import mass_assignment_probe, bfla_probe, graphql_batch_attack, graphql_alias_bypass, password_reset_poisoning
from .subdomain_takeover import (
    subdomain_takeover_scan, ns_takeover_probe,
    # New DNS offensive tools
    mx_takeover_probe, wildcard_dns_detect, dns_rebinding_probe,
    spf_dmarc_dkim_check, dns_zone_transfer_exploit,
)
from .dom_attacks import dom_xss_probe, postmessage_attack_probe, cors_exploit_probe, csp_bypass_analysis
from .c2_server import (
    start_listener, list_active_shells, execute_in_shell,
    maintain_shell, upload_file_to_shell, establish_persistence,
    kill_session, stop_listener, get_session_history,
)
from .auth_context import (
    auth_login, auth_register, auth_get_session,
    auth_compare_responses, auth_list_sessions, auth_refresh_session,
    auth_manual_session, auth_request_user_assistance
)

# Cloud Asset Enumeration
from .cloud import s3_bucket_enum, cloudfront_enum, gcp_bucket_enum, azure_blob_enum, cloud_asset_enum

# Shells & Payloads (optional - may not be synced yet)
try:
    from .shells import (
        generate_reverse_shell,
        list_reverse_shells,
        msfvenom_payload,
        start_listener as shell_listener_command,
    )
    _shells_available = True
except ImportError:
    _shells_available = False
    generate_reverse_shell = None
    list_reverse_shells = None
    msfvenom_payload = None
    shell_listener_command = None

__all__ = [
    # Reconnaissance
    "nmap_scan", "whois_lookup", "dig_lookup", "subfinder_enum", "dnsrecon_enum",
    "cloudflair_scan", "httpx_probe", "dnsenum_scan", "whatweb_scan", "shodan_search",
    "wafw00f_detect", "amass_enum", "sslscan_check", "fierce_scan",
    # Network connectivity
    "nc_connect", "nc_scan", "telnet_connect", "telnet_send",
    # Extended recon (merged)
    "sublist3r_enum", "linkfinder_js", "secretfinder_js", "jsparser_analyze",
    "waybackurls", "ffuf_content_fuzz", "feroxbuster_scan", "paramspider",
    "katana_crawl", "hakrawler", "httpx_tech_detect", "wappalyzer_scan",
    "cors_check", "security_headers_check", "subdomain_takeover_scan",
    "passive_recon_chain",
    # Active Recon (New)
    "nmap_discover", "nmap_service_scan", "arjun_params", "wfuzz_fuzz",
    "cmseek_scan", "wpseku_scan", "wpprobe_scan", "gqlmap_scan", "sql_shell", "smbmap_scan",
    "snmp_check", "certipy_run", "odat_run", "redis_cli_check", "gowitness_screenshot",
    # Web
    "gobuster_scan", "dirsearch_scan", "curl_request", "wget_download",
    "save_file_to_session",
    "arjun_scan", "gau_urls", "gospider_crawl", "vhost_bruteforce", "wfuzz_fuzz",
    "mcp_inspector_audit", "mcp_inspector_connect_stdio", "jupyter_terminal_command",
    "wordpress_xmlrpc_audit",
    # Crypto
    "john_crack", "john_show", "hashcat_crack", "hash_identifier", "create_hash", "nth_identify", "ssh_key_crack",
    # Exploitation (basic)
    "searchsploit", "searchsploit_json", "searchsploit_copy",
    "run_exploit_script", "msfconsole_run", "sqlmap_attack", "hydra_bruteforce",
    # Exploitation (aggressive)
    "nuclei_scan", "nuclei_triage", "wpscan", "ffuf_fuzz", "xsstrike", "commix",
    "crackmapexec", "responder", "impacket_secretsdump", "evil_winrm",
    "netcat_shell", "curl_exploit", "patator_bruteforce", "smbclient_access",
    # Advanced exploitation
    "dalfox_scan", "tplmap_scan", "jwt_tool_attack", "nosqlmap_attack", "pwncat_shell",
    # Forensics & CTF Analysis
    "tshark_analyze", "binwalk_analyze", "strings_extract", "exiftool_metadata", "volatility3_analyze",
    "ctf_command",
    "read_tool_output", "read_local_document",
    "wasm_analyze", "upx_unpack", "java_decompile", "javap_disassemble", "jar_explore",
    "qemu_emulate", "binwalk_extract", "foremost_extract", "steg_analyze", "analyze_file",
    "ctf_identify", "binary_triage", "strings_extract_ctf", "forensics_carve",
    "stego_check", "crypto_identify", "decompile_func", "pcap_analyze",
    "elf_security", "ctf_web_triage",
    # Code Analysis
    "repo_map", "pattern_search", "concat_code", "ast_symbol_search",
    "static_code_analysis", "semgrep_scan", "framework_audit",
    # Godot Reversing
    "godot_pck_extract", "godot_gds_decompile",
    # Privilege Escalation
    "linpeas_scan", "sudo_check", "find_writable_dirs", "gtfobins_check",
    "winpeas_scan", "pspy_run", "traitor_run", "seatbelt_run",
    # Lateral Movement
    "ssh_scan", "crackmapexec_smb", "psexec_exec", "ssh_exec", "ftp_connect",
    # Credential Access
    "mimikatz_dump", "dump_shadow", "responder_capture", "secretsdump",
    # Active Directory Attacks
    "enum4linux_scan", "ldapsearch_query", "netexec_scan", "certify_scan",
    "kerbrute_userenum", "kerbrute_spray",
    "bloodhound_collector", "rubeus_attack",
    "zerologon_check", "petitpotam_coerce",
    "ntlmrelayx_start", "mitm6_attack", "arpspoof_attack",
    "sync_kerberos_time",
    # Attack Planning
    "plan_attack", "get_next_action", "chain_exploits",
    "register_vulnerability", "register_service", "attack_summary",
    "generate_attack_plan", "modify_attack_plan", "show_current_plan",
    "update_vulnerability_status", "get_all_vulnerabilities",
    "record_http_observation", "suggest_adaptive_tests",
    "register_finding_candidate", "promote_finding_with_evidence",
    "build_attack_chains", "generate_evidence_report", "framework_maturity_status",
    "set_engagement_mode", "generate_hypotheses", "show_active_hypotheses",
    "schedule_next_hypothesis", "select_hypothesis_tools", "record_hypothesis_result", "show_coverage_requirements",
    "artifact_glob", "artifact_grep", "artifact_read", "artifact_write",
    "web_search", "fetch_url",
    "record_uploaded_shell", "list_uploaded_shells",
    "long_task_start", "long_task_status", "long_task_list", "long_task_resume",
    "tcp_session_open", "tcp_session_send", "tcp_session_read", "tcp_session_close",
    "record_ctf_solution", "get_ctf_tips",
    # Vulnerability Knowledge Base (Phase 2)
    "list_vuln_types", "get_payloads", "get_vuln_info", "search_vulns",
    # Exploit Chain Engine (Phase 4)
    "build_exploit_chain", "list_chain_templates", "score_attack_surface",
    # Cross-Scan Learning (Phase 5)
    "record_scan_findings", "get_tool_recommendations", "what_worked_before", "scan_history_stats",
    "import_bugbounty_knowledge", "bugbounty_knowledge_stats", "query_bugbounty_knowledge",
    # Workflow Orchestration (NEW)
    "nuclei_scan_and_triage", "dir_enum_with_bypass", "auto_param_scan",
    # AppSec Tools (NEW)
    "genetic_mutation_fuzz",
    "xss_scanner", "sqli_scanner", "ssrf_scanner", "path_traversal_scanner",
    "csrf_analyzer", "xxe_scanner", "header_injection_scanner", "full_appsec_scan",
    "validate_browser_xss", "validate_oast_ssrf", "validate_oast_xxe",
    "managed_oast_blind_validation",
    "authenticated_app_mapper", "two_account_authz_engine",
    "managed_oast_ssrf_validation", "build_recon_attack_paths",
    "business_workflow_state_recorder",
    "open_redirect_scan", "nosql_injection_probe", "ldap_injection_probe", "crlf_injection_probe",
    "command_injection_scanner", "clickjacking_scanner", "registration_tester",
    "password_reset_tester",
    # HTTP Proxy Tools (NEW)
    "http_request", "http_intercept_modify", "http_compare", "http_fuzz",
    "session_status", "session_set_cookie", "session_set_header", "session_clear",
    # Browser Automation (NEW)
    "browser_visit", "browser_xss_test", "browser_auth_test", "browser_execute_js",
    "browser_screenshot", "browser_extract_forms", "browser_check_available",
    "dom_vulnerability_scanner",
    # Browser Persistent Session
    "browser_open_session", "browser_click_element", "browser_type_text",
    "browser_get_session_html", "browser_close_session",
    # Browser Autonomous Control
    "browser_get_page_state", "browser_navigate", "browser_scroll",
    "browser_select_option", "browser_press_key", "browser_wait_for",
    "browser_upload_file", "browser_hover",
    # Browser Challenge Bypass
    "browser_solve_challenge", "browser_get_cookies",
    # Code Analysis (NEW)
    "static_code_analysis", "secret_scanner", "dependency_scan", "find_dangerous_functions",
    "gitleaks_audit", "pip_audit_scan",
    # PoC Validation (NEW)
    "validate_sqli", "validate_xss", "validate_ssrf", "validate_command_injection",
    "validate_path_traversal", "get_validated_poc", "auto_validate", "multi_validate",
    "score_finding", "batch_score_findings", "multi_agent_verify",
    # Advanced Web Detection (NEW)
    "cors_scan", "host_header_injection", "graphql_probe",
    "graphql_schema_inventory", "graphql_authz_replay_probe",
    "jwt_confusion_attack", "prototype_pollution_scan",
    "second_order_sqli", "path_confusion_probe",
    "jarm_scan", "kiterunner_scan", "corsy_scan", "retirejs_scan",
    "graphql_cop_scan", "inql_scan", "gopherus_payload",
    # Race Condition & HTTP/2 (NEW)
    "race_condition_scanner", "http2_rapid_reset_check",
    # Deserialization (NEW)
    "deserialization_probe",
    # Camaleon CMS CVE Exploits
    "camaleon_privesc", "camaleon_lfi", "camaleon_admin_enum",
    # WAF Detector + Bypass Engine (Phase 3)
    "waf_fingerprint", "waf_bypass_payloads", "apply_waf_bypass",
    # Phase 7.1 — IDOR / BOLA
    "idor_probe", "idor_sequential_probe", "idor_uuid_probe", "bola_param_tamper", "privilege_escalation_web",
    # Phase 7.1 — OAuth 2.0 / OIDC Attacks
    "oauth_redirect_uri_bypass", "oauth_state_csrf_check", "oauth_token_leakage_check", "oauth_pkce_downgrade",
    # Phase 7.1 — Business Logic
    "price_manipulation_probe", "coupon_abuse_probe", "workflow_bypass_probe", "account_state_abuse_probe",
    # Phase 7.1 — Cache Poisoning
    "cache_poisoning_unkeyed_header", "cache_deception_probe", "cache_parameter_cloaking",
    # Phase 7.1 — MFA / 2FA Bypass
    "mfa_response_manipulation", "otp_bruteforce_probe", "mfa_backup_code_probe",
    # Phase 7.1 — LLM / AI Injection
    "llm_prompt_injection_probe", "llm_indirect_injection_probe", "llm_data_exfiltration_probe", "llm_jailbreak_probe",
    # Real-World — SAML / SSO Attacks
    "saml_response_decode", "saml_xsw_attack", "saml_replay_probe", "saml_attr_manipulation",
    # Real-World — Mass Assignment / BFLA / GraphQL deep
    "mass_assignment_probe", "bfla_probe", "graphql_batch_attack", "graphql_alias_bypass", "password_reset_poisoning",
    # Real-World — Subdomain Takeover (service-fingerprinted)
    "subdomain_takeover_scan", "ns_takeover_probe",
    # DNS Offensive Tools (NEW)
    "mx_takeover_probe", "wildcard_dns_detect", "dns_rebinding_probe",
    "spf_dmarc_dkim_check", "dns_zone_transfer_exploit",
    # Cloud Asset Enumeration (NEW)
    "s3_bucket_enum", "cloudfront_enum", "gcp_bucket_enum", "azure_blob_enum", "cloud_asset_enum",
    # Interactsh OOB Callback Server (NEW)
    "interactsh_start", "interactsh_poll", "interactsh_stop",
    # Service Exploit Modules (NEW)
    "redis_exploit_check", "mongodb_exploit_check", "elasticsearch_exploit_check",
    "docker_api_exploit_check", "snmp_exploit_check", "memcached_exploit_check",
    # Network Tunneling (NEW)
    "ssh_port_forward", "chisel_tunnel", "socat_relay",
    # Real-World — DOM Attacks
    "dom_xss_probe", "postmessage_attack_probe", "cors_exploit_probe", "csp_bypass_analysis",
    # C2 / Shell Session Management
    "start_listener", "list_active_shells", "execute_in_shell",
    "maintain_shell", "upload_file_to_shell", "establish_persistence",
    "kill_session", "stop_listener", "get_session_history",
    # Interactive Shell (Fallback)
    "interactive_bash", "read_shell_screen", "terminal_screenshot",
    "tcp_session_open", "tcp_session_send", "tcp_session_read", "tcp_session_close",
    # 4.2 — Real post-exploitation orchestrator + bloodhound query
    "lateral_movement", "bloodhound_query",
    # 4.2 — Cloud orchestration / fingerprint
    "cloud_fingerprint", "cloud_enum_orchestrate",
    # 4.3 — Modern recon
    "shodan_internetdb", "asn_pivot", "github_dork_search",
    "trufflehog_repo", "git_dump", "jsluice_extract", "js_secret_chain",
    # 4.4 — SSRF cloud-metadata
    "ssrf_cloud_metadata", "ssrf_imdsv2_chain",
    # 4.4 — Advanced JWT
    "jwt_jku_attack", "jwt_x5u_attack", "jwt_kid_path_traversal", "jwt_embedded_jwk",
    # 4.4 — H2 single-packet race + modern smuggling
    "http2_single_packet_race",
    "smuggling_te0", "smuggling_cl0", "smuggling_h2_downgrade",
    # 4.4 — Deserialization payload generators
    "deser_java_ysoserial", "deser_dotnet_ysoserial",
    "deser_php_phpggc", "deser_python_pickle", "deser_ruby_marshal",
    # 4.4 — Prototype-pollution gadgets
    "proto_pollution_list_gadgets", "proto_pollution_exploit",
    # 4.5 — Advanced AD
    "coercer_multi", "certipy_esc_chain", "timeroast", "rbcd_attack", "dcsync",
    # 4.6 — Advanced cloud
    "pacu_run", "roadtools_dump", "aadinternals_recon",
    "cognito_misconfig_probe", "container_escape_probe",
    "scoutsuite_scan", "prowler_scan",
    # 4.8 — Bug-bounty bundle
    "generate_finding_bundle",
    # 4.9 — Evasion / JA3 / proxy-aware
    "evasion_status", "evasion_set_profile", "evasion_request",
    # Proxy Manager — IP Rotation & Anti-Ban
    "proxy_status", "proxy_start_tornet", "proxy_start_anonsurf",
    "proxy_setup_proxychains", "proxy_rotate_ip", "proxy_stop", "proxy_check_ip",
]

# ── Imports for new modules (4.1 → 4.9) ─────────────────────────────────────
# Real post-ex / cloud orchestrators (replaces former cheat-sheet stubs)
from .post_exploit import lateral_movement, bloodhound_query
from .cloud import cloud_fingerprint, cloud_enum_orchestrate
# Modern recon stack
from .recon_passive import (
    shodan_internetdb, asn_pivot, github_dork_search,
    trufflehog_repo, git_dump, jsluice_extract, js_secret_chain,
)
# Web/API technique upgrades
from .ssrf_cloud import ssrf_cloud_metadata, ssrf_imdsv2_chain
from .jwt import (
    jwt_jku_attack, jwt_x5u_attack, jwt_kid_path_traversal, jwt_embedded_jwk,
)
from .race_condition import http2_single_packet_race
from .http_smuggling import smuggling_te0, smuggling_cl0, smuggling_h2_downgrade
from .deserialization import (
    deser_java_ysoserial, deser_dotnet_ysoserial,
    deser_php_phpggc, deser_python_pickle, deser_ruby_marshal,
)
from .proto_pollution_gadgets import (
    proto_pollution_list_gadgets, proto_pollution_exploit,
)
# Advanced AD
from .ad import (
    coercer_multi, certipy_esc_chain, timeroast, rbcd_attack, dcsync,
)
# Advanced cloud
from .cloud import (
    pacu_run, roadtools_dump, aadinternals_recon,
    cognito_misconfig_probe, container_escape_probe,
)
# Bug-bounty bundle generator (lives under sdk/, surfaced as a tool here)
from src.sdk.report_bundle import generate_finding_bundle
# Evasion / JA3
from src.sdk.evasion import evasion_status, evasion_set_profile, evasion_request

# Add shell tools if available
if _shells_available:
    __all__.extend(["generate_reverse_shell", "list_reverse_shells", "msfvenom_payload", "shell_listener_command"])

# ATT&CK Tactic Mapping
ATTACK_TACTICS = {
    "TA0043_Reconnaissance": [
        "nmap_scan", "whois_lookup", "dig_lookup", "subfinder_enum", "dnsrecon_enum",
        "cloudflair_scan", "httpx_probe", "dnsenum_scan", "whatweb_scan", "shodan_search",
        "wafw00f_detect", "amass_enum", "sslscan_check", "fierce_scan",
        "nc_connect", "nc_scan", "telnet_connect", "telnet_send",
        "gowitness_screenshot"
    ],
    "TA0001_Initial_Access": [
        "gobuster_scan", "dirsearch_scan", "ffuf_fuzz", "wpscan", "curl_request",
        "browser_visit", "browser_auth_test", "mcp_inspector_audit",
        "arjun_scan", "gau_urls", "gospider_crawl"
    ],
    "TA0002_Execution": [
        "run_exploit_script", "msfconsole_run", "psexec_exec", "commix", "curl_request",
        "browser_execute_js", "validate_command_injection",
        "mcp_inspector_connect_stdio", "jupyter_terminal_command",
    ],
    "TA0003_Persistence": [],
    "TA0004_Privilege_Escalation": ["linpeas_scan", "sudo_check", "find_writable_dirs", "gtfobins_check",
                                     "camaleon_privesc", "winpeas_scan", "pspy_run", "traitor_run", "seatbelt_run"],
    "TA0005_Defense_Evasion": ["waf_fingerprint", "waf_bypass_payloads", "apply_waf_bypass"],
    "TA0006_Credential_Access": [
        "john_crack", "hashcat_crack", "mimikatz_dump", "dump_shadow",
        "secretsdump", "hydra_bruteforce", "impacket_secretsdump", "patator_bruteforce",
        "nth_identify", "kerbrute_spray", "ssh_key_crack",
    ],
    "TA0007_Discovery": [
        "nmap_scan", "searchsploit", "nuclei_scan", "smbclient_access",
        "enum4linux_scan", "ldapsearch_query", "kerbrute_userenum", "bloodhound_collector",
        "sync_kerberos_time", "certify_scan",
        "browser_extract_forms", "static_code_analysis", "secret_scanner",
        "arjun_scan", "gau_urls", "gospider_crawl"
    ],
    "TA0008_Lateral_Movement": [
        "ssh_scan", "ssh_exec", "ftp_connect", "crackmapexec_smb", "psexec_exec", "crackmapexec", "evil_winrm",
        "ntlmrelayx_start", "petitpotam_coerce", "netexec_scan",
        # 4.5 advanced AD
        "lateral_movement", "bloodhound_query",
        "coercer_multi", "certipy_esc_chain", "rbcd_attack", "dcsync", "timeroast",
    ],
    "TA0009_Collection": [
        "tshark_analyze", "binwalk_analyze", "strings_extract", "exiftool_metadata", "volatility3_analyze",
        "ctf_command", "godot_pck_extract"
    ],
    "TA0011_Command_Control": ["responder_capture", "responder", "netcat_shell", "mitm6_attack", "arpspoof_attack"],
    "TA0010_Exfiltration": [],
    # New Categories
    "AppSec_Vulnerability_Scanning": [
        "genetic_mutation_fuzz",
        "xss_scanner", "sqli_scanner", "ssrf_scanner", "path_traversal_scanner",
        "csrf_analyzer", "xxe_scanner", "header_injection_scanner", "full_appsec_scan",
        "validate_browser_xss", "validate_oast_ssrf", "validate_oast_xxe",
        "authenticated_app_mapper", "two_account_authz_engine",
        "managed_oast_ssrf_validation", "build_recon_attack_paths",
        "business_workflow_state_recorder",
        "command_injection_scanner", "clickjacking_scanner",
    ],
    "HTTP_Proxy_Tools": [
        "http_request", "http_intercept_modify", "http_compare", "http_fuzz",
        "session_status", "session_set_cookie", "session_set_header", "session_clear"
    ],
    "Browser_Automation": [
        "browser_visit", "browser_xss_test", "browser_auth_test", "browser_execute_js",
        "browser_screenshot", "browser_extract_forms", "browser_check_available",
        "dom_vulnerability_scanner",
        # Persistent session
        "browser_open_session", "browser_click_element", "browser_type_text",
        "browser_get_session_html", "browser_close_session",
        # Autonomous control primitives
        "browser_get_page_state", "browser_navigate", "browser_scroll",
        "browser_select_option", "browser_press_key", "browser_wait_for",
        "browser_upload_file", "browser_hover",
        # Challenge bypass
        "browser_solve_challenge", "browser_get_cookies",
    ],
    "Code_Analysis": [
        "static_code_analysis", "secret_scanner", "dependency_scan", "find_dangerous_functions",
        "gitleaks_audit", "pip_audit_scan"
    ],
    "PoC_Validation": [
        "validate_sqli", "validate_xss", "validate_ssrf", "validate_command_injection",
        "validate_path_traversal", "get_validated_poc", "auto_validate", "multi_validate",
        "score_finding", "batch_score_findings", "multi_agent_verify"
    ],
    "Advanced_Web_Detection": [
        "cors_scan", "host_header_injection", "graphql_probe",
        "jwt_confusion_attack", "prototype_pollution_scan",
        "second_order_sqli", "path_confusion_probe",
        "graphql_cop_scan", "inql_scan", "gopherus_payload"
    ],
    "Race_Condition_HTTP2": [
        "race_condition_scanner", "http2_rapid_reset_check",
    ],
    "Deserialization": [
        "deserialization_probe",
    ],
    # WAF Detector + Bypass Engine (Phase 3)
    "WAF_Bypass_Engine": [
        "waf_fingerprint", "waf_bypass_payloads", "apply_waf_bypass",
    ],
    # CMS-Specific Exploits
    "CMS_Exploits": [
        "camaleon_privesc", "camaleon_lfi", "camaleon_admin_enum",
    ],
    # Exploit Chain Engine (Phase 4)
    "Exploit_Chain_Engine": [
        "build_exploit_chain", "list_chain_templates", "score_attack_surface",
    ],
    # Cross-Scan Learning (Phase 5)
    "Cross_Scan_Learning": [
        "record_scan_findings", "get_tool_recommendations",
        "what_worked_before", "scan_history_stats",
        "import_bugbounty_knowledge", "bugbounty_knowledge_stats", "query_bugbounty_knowledge",
    ],
    "Bug_Bounty_Workflow": [
        "record_http_observation", "suggest_adaptive_tests",
        "register_finding_candidate", "promote_finding_with_evidence",
        "build_attack_chains", "generate_evidence_report", "framework_maturity_status",
        "set_engagement_mode", "generate_hypotheses", "show_active_hypotheses",
        "schedule_next_hypothesis", "select_hypothesis_tools", "record_hypothesis_result", "show_coverage_requirements",
        "artifact_glob", "artifact_grep", "artifact_read", "artifact_write",
        "long_task_start", "long_task_status", "long_task_list", "long_task_resume",
        "import_bugbounty_knowledge", "bugbounty_knowledge_stats", "query_bugbounty_knowledge",
        # 4.8 — bundle generator
        "generate_finding_bundle",
    ],
    # 4.3 — Modern Recon Stack
    "Modern_Recon": [
        "shodan_internetdb", "asn_pivot", "github_dork_search",
        "trufflehog_repo", "git_dump", "jsluice_extract", "js_secret_chain",
        "cloud_fingerprint",
    ],
    # 4.4 — SSRF cloud-metadata
    "SSRF_Cloud_Metadata": [
        "ssrf_cloud_metadata", "ssrf_imdsv2_chain",
    ],
    # 4.4 — JWT Advanced
    "JWT_Advanced": [
        "jwt_jku_attack", "jwt_x5u_attack", "jwt_kid_path_traversal", "jwt_embedded_jwk",
    ],
    # 4.4 — H2 race + modern smuggling
    "HTTP2_Race_Smuggling": [
        "http2_single_packet_race",
        "smuggling_te0", "smuggling_cl0", "smuggling_h2_downgrade",
    ],
    # 4.4 — Deserialization payload generation
    "Deser_Payload_Generation": [
        "deser_java_ysoserial", "deser_dotnet_ysoserial",
        "deser_php_phpggc", "deser_python_pickle", "deser_ruby_marshal",
    ],
    # 4.4 — Prototype-pollution gadgets
    "Proto_Pollution_Gadgets": [
        "proto_pollution_list_gadgets", "proto_pollution_exploit",
    ],
    # 4.6 — Advanced cloud post-ex
    "Cloud_Post_Exploitation": [
        "pacu_run", "roadtools_dump", "aadinternals_recon",
        "cognito_misconfig_probe", "container_escape_probe",
        "scoutsuite_scan", "prowler_scan"
    ],
    # 4.9 — Evasion / JA3
    "Evasion_Engine": [
        "evasion_status", "evasion_set_profile", "evasion_request",
    ],
    # Proxy Manager — IP Rotation & Anti-Ban
    "Proxy_IP_Rotation": [
        "proxy_status", "proxy_start_tornet", "proxy_start_anonsurf",
        "proxy_setup_proxychains", "proxy_rotate_ip", "proxy_stop", "proxy_check_ip",
    ],
}

# Tool count for display
TOOL_COUNT = len(__all__)
