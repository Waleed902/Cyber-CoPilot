# Cyber-CoPilot

**Automate. Infiltrate. Report.**

An AI-powered, multi-agent offensive security framework that automates penetration testing operations — from passive reconnaissance to active exploitation to professional reporting — entirely through a natural-language terminal interface.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![Authorized Testing Only](https://img.shields.io/badge/authorized_testing-only-red)

> **LEGAL DISCLAIMER:** This tool is intended for authorized security testing, educational purposes, and research only. Never use this system to scan, probe, or attack any system you do not own or have explicit written permission to test. Unauthorized access is illegal and punishable by law. By using this tool, you accept full responsibility for your actions.

---

## Table of Contents

- [Overview](#overview)
  - [Multi-Agent Architecture](#multi-agent-architecture)
  - [AI Model Providers](#ai-model-providers)
  - [Agent Graph System](#agent-graph-system)
  - [Attack Planning System](#attack-planning-system)
  - [Vector Memory System](#vector-memory-system)
  - [Target Profiles](#target-profiles)
  - [Failure Recovery Engine](#failure-recovery-engine)
  - [Report Generation](#report-generation)
- [Quick Start](#quick-start)
- [System Architecture](#system-architecture)
  - [High-Level Architecture](#high-level-architecture)
  - [Agent Call Flow](#agent-call-flow)
  - [Tool Execution Pipeline](#tool-execution-pipeline)
- [Agents](#agents)
- [SDK Modules](#sdk-modules)
- [Tools Reference](#tools-reference)
- [CLI Commands](#cli-commands)
- [Configuration](#configuration)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Legal](#legal)

---

## Overview

Cyber-CoPilot is a modular, Python-based penetration testing framework that chains automated reconnaissance, multi-agent AI reasoning, and structured reporting into a single, end-to-end offensive security pipeline. Everything runs locally — no external services required beyond an LLM API key — and communicates through a rich terminal interface so each layer is transparent to the operator.

The platform is built around four pillars:

| Pillar | Description |
|--------|-------------|
| **Multi-Agent System** | Ten specialized AI agents — each backed by a real security tool set — orchestrated by a central Orchestrator that routes tasks, injects previously discovered context, and avoids duplicate work. |
| **Attack Execution Engine** | An Agentic Runner implementing the ReAct (Reasoning + Acting) loop: reason about the current state, select and invoke a tool, process results, repeat — until the objective is complete. |
| **Target Intelligence Store** | A persistent per-target profile system that accumulates ports, subdomains, credentials, vulnerabilities, and DNS data across sessions — feeding every agent with prior-collected intelligence before any scan runs. |
| **Structured Reporting Pipeline** | AI-driven markdown and PDF reporting with charts, executive summaries, MITRE alignment, and client-ready formatting. |

---

## Multi-Agent Architecture

Cyber-CoPilot uses a hierarchical multi-agent design where a central **Orchestrator** receives natural-language input, classifies the intent, and delegates to the appropriate specialist agent. Each agent is a self-contained unit with its own system prompt, tool set, and execution scope.

### How Delegation Works

1. **Intent Classification** — The Orchestrator LLM reads the user's request and decides which specialist is best suited.
2. **Context Injection** — Before dispatching, the Orchestrator pulls the current target profile (ports, subdomains, vulnerabilities already discovered) and injects it as a context prefix so sub-agents never repeat scans that were already run.
3. **Task Delegation** — The enriched task string is passed to the specialist agent's Runner, which enters its own ReAct loop.
4. **Result Aggregation** — Results flow back to the Orchestrator, which synthesizes a response and updates the target profile.

### Context Injection — Avoiding Duplicate Work

Before any sub-agent runs, it receives:

- Current target domain/IP
- All discovered open ports and services
- All discovered subdomains
- Previously registered vulnerabilities (severity, CVE, description)
- An explicit `[INSTRUCTION]` directive not to re-run scans already covered

This means a second `scan for vulnerabilities` command in the same session skips the port scan phase entirely and proceeds directly to vulnerability testing.

---

## AI Model Providers

Cyber-CoPilot supports multiple LLM providers out of the box, configurable via environment variables. The `APIKeyManager` handles provider selection, automatic fallback on failure, usage tracking, and runtime switching.

| Provider | Environment Variable | Notes |
|----------|---------------------|-------|
| **NVIDIA** | `NVIDIA_API_KEY` | Default provider using `stepfun-ai/step-3.7-flash`. OpenAI-compatible NVIDIA NIM endpoint. |
| **Longcat** | `LONGCAT_API_KEY` | Disabled for now; leave `LONGCAT_MODEL` empty. |
| **OpenRouter** | `OPENROUTER_API_KEY` | Backup provider. Defaults to Venice, with Nex N2 Pro and Gemma 4 31B IT also available. |
| **OpenAI** | `OPENAI_API_KEY` | Disabled for now; leave `OPENAI_MODEL` empty. |

### Auto-Rotation and Fallback

If the active provider returns an error (rate limit, quota exceeded, network failure), the `APIKeyManager` automatically promotes the next configured provider without interrupting the current agent run.

```bash
❯ api                            # View current provider, model, and usage stats
❯ api nvidia                  # Switch to NVIDIA
❯ api openrouter                 # Switch to OpenRouter
❯ model nvidia stepfun-ai/step-3.7-flash  # Switch to specific model
❯ apikey status                  # Per-key usage stats
```

---

## Agent Graph System

Beyond simple delegation, Cyber-CoPilot implements a **Graph of Agents** (`AgentGraph`) — a dynamic multi-agent collaboration system where specialized agents execute in parallel, share discoveries in real-time, and feed each other's inputs.

### Discovery Bus

The `DiscoveryBus` is a shared, in-memory message bus. When any agent makes a discovery, it publishes a typed `Discovery` object:

| Discovery Type | Description |
|----------------|-------------|
| `VULNERABILITY` | A security finding with severity, CVE, and description |
| `SERVICE` | An open port and running service |
| `CREDENTIAL` | Discovered username/password or hash |
| `ENDPOINT` | A live HTTP endpoint or API route |
| `SUBDOMAIN` | A discovered subdomain |
| `FILE` | A sensitive file or directory |
| `CONFIGURATION` | A misconfiguration finding |
| `EXPLOIT_SUCCESS` | A successful exploitation event |
| `ATTACK_PATH` | A complete viable attack chain |

Other agents that `consume` those discovery types are automatically notified and use the new data in their own reasoning.

### Pre-Built Graph Configurations

```bash
❯ graph recon     # Recon + WebSec run in parallel; share discoveries
❯ graph exploit   # Full kill-chain: Recon → WebSec → RedTeam → Reporter
❯ graph bounty    # Bug-bounty optimized: passive-first, PoC validation
❯ graph status    # View execution status across all nodes
❯ graph discoveries  # All items on the DiscoveryBus
❯ graph validated    # Only findings that passed PoC validation
```

---

## Attack Planning System

After reconnaissance, the framework generates a structured **Attack Plan** — an AI-authored document that outlines attack phases, tools, risk levels, and expected outcomes — presented for human review before any exploitation begins.

### Approval Workflow

1. **Recon Phase** — Ports, subdomains, and vulnerabilities are registered into the Attack Planner's state.
2. **Plan Generation** — The LLM analyzes all findings and produces a structured multi-phase plan with tools, risks, and success probability.
3. **Operator Review** — The plan is displayed in the terminal with all phases.
4. **Approval Gate** — The operator must explicitly approve before execution begins.
5. **Phase Execution** — `plan next` executes one phase at a time; the operator can modify or cancel at any step.

```bash
❯ plan generate          # Generate attack plan from current findings
❯ plan                   # Review the current plan
❯ plan approve           # Approve and begin execution
❯ plan next              # Execute next phase
❯ plan modify Phase2 "focus only on API endpoints"
❯ plan cancel            # Abort the plan
```

### Vulnerability-to-Exploit Mapping

The `AttackPlanner` maintains a `VULN_EXPLOIT_MAP` — a knowledge base mapping vulnerability types to recommended tools and next-steps:

| Vulnerability | Tools | Chains To |
|---------------|-------|-----------|
| `sql_injection` | `sqlmap_attack` | dump_database, extract_credentials |
| `xss` | `xsstrike` | steal_cookies, session_hijack |
| `command_injection` | `commix` | reverse_shell, privilege_escalation |
| `lfi` / `rfi` | `curl_request` | log_poisoning, code_execution |
| `ms17-010` | `msfconsole_run` | EternalBlue, DoublePulsar |
| `zerologon` | `zerologon_check` | reset_dc_password, dcsync |
| `kerberoasting` | `rubeus_attack` | request_tgs, crack_hashes, domain_admin |
| `petitpotam` | `petitpotam_coerce` + `ntlmrelayx_start` | ADCS relay, domain_admin |
| `weak_password` | `hydra_bruteforce` | initial_access |

---

## Vector Memory System

Cyber-CoPilot maintains **long-term persistent memory** across sessions using ChromaDB (vector embeddings) with a flat JSON fallback when ChromaDB is unavailable.

### What Gets Stored

Every tool result, vulnerability, credential, endpoint, and operator note is stored with target context and a semantic embedding — enabling fuzzy cross-session searches.

### Semantic Search

```bash
❯ memory SQL injection vulnerabilities
❯ memory admin credentials for 10.10.14.5
❯ memory open ports example.com
```

The memory engine performs vector similarity search and returns the top-k most relevant entries from any previous session.

### Cross-Session Persistence

Memory survives process restarts. The `.memory/` directory stores:
- `memories.json` — file-based fallback
- ChromaDB collections (one per target/category combination)

---

## Target Profiles

Every target gets a **persistent `TargetProfile`** saved to `targets/<target>/profile.json`. Profiles accumulate data across all sessions:

| Field | Type | Description |
|-------|------|-------------|
| `ip_addresses` | list[str] | Resolved IP addresses |
| `subdomains` | list[str] | Discovered subdomains |
| `ports` | list[PortInfo] | Open ports with service and version |
| `dns_records` | dict | A, AAAA, MX, NS, TXT records |
| `technologies` | list[str] | Detected web technologies |
| `vulnerabilities` | list[VulnerabilityInfo] | Findings with severity, CVE, exploitability flag |
| `credentials` | list[CredentialInfo] | Usernames, passwords, hashes |
| `notes` | list[str] | Operator-added notes |
| `commands_run` | list[str] | History of every tool run against this target |

```bash
❯ target example.com       # Set target and auto-load its profile
❯ profile                  # View full profile for active target
```

---

## Failure Recovery Engine

The `FailureRecoveryEngine` automatically handles tool failures with intelligent retry strategies.

When a tool fails, the engine:

1. **Classifies the failure** — `TIMEOUT`, `CONNECTION_ERROR`, `TOOL_NOT_FOUND`, `PERMISSION_DENIED`, `RATE_LIMITED`, `BLOCKED`, `NO_RESULTS`, etc.
2. **Suggests alternatives** — via `TOOL_ALTERNATIVES` map (e.g., `subfinder_enum` fails → try `amass_enum` → `dnsrecon_enum`)
3. **Adjusts parameters** — reduce thread count, increase timeout, change port range
4. **Displays recovery options** — up to 4 strategies with confidence scores, shown immediately in terminal
5. **Learns in-session** — repeated failures on the same tool suppress low-confidence suggestions

```bash
❯ recovery status      # Active recovery suggestions
❯ recovery history     # All failures this session
```

---

## Report Generation

The **Reporter Agent** and **ReportGenerator SDK module** produce two output formats:

### Markdown Reports

```bash
❯ export                          # Quick markdown report for current target
❯ create report for example.com   # Reporter Agent writes a full pentest narrative
```

### PDF Reports with Graphs

Professional, client-ready PDFs with:
- **Executive Summary** — risk posture for management
- **Attack Phase Sections** — Recon → Discovery → Exploitation → Post-Exploitation
- **Severity Distribution Chart** — matplotlib bar chart of findings by severity
- **Statistics Block** — ports, subdomains, vulnerabilities, credentials counts
- **Up to 10 pages** with header, footer, and page numbers

```bash
❯ generate pdf report
# Output: reports/pentest_report_<target>_<timestamp>.pdf
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- At least one LLM API key (NVIDIA, OpenRouter, or ModelScope)
- Security tools installed on the host (see [Tools Reference](#tools-reference))

### Installation

```bash
git clone https://github.com/yourusername/cyber-copilot.git
cd cyber-copilot
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API key(s)
python main.py
```

### First Session

```bash
❯ target example.com           # Set target + load profile
❯ scan for open ports          # Recon Agent runs nmap
❯ find subdomains              # subfinder + amass
❯ check for SQL injection      # WebSec Agent + sqlmap
❯ plan generate                # AI generates attack plan from findings
❯ plan                         # Review plan
❯ plan approve                 # Approve for execution
❯ plan next                    # Execute first phase
❯ generate pdf report          # Professional PDF deliverable
```

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        main.py (REPL)                           │
│     Rich Terminal UI · Command Router · Callback Hooks          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ natural language input
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Orchestrator Agent                           │
│    Intent Classification · Context Injection · Delegation      │
└────────┬──────────┬──────────┬──────────┬──────────────────────┘
         │          │          │          │
         ▼          ▼          ▼          ▼
    ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
    │  Recon  │ │ WebSec  │ │RedTeam  │ │Reporter │  ...
    │  Agent  │ │  Agent  │ │  Agent  │ │  Agent  │
    └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
         │                                   │
         ▼            [DiscoveryBus]          │
┌─────────────────────────────────────────────────────────────────┐
│                   SDK Runner (ReAct Loop)                       │
│   tool_call → parse → execute → result → next reasoning step   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Tool Layer                               │
│  nmap · subfinder · sqlmap · nuclei · hydra · metasploit · ... │
└──────────────────────────┬──────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
┌──────────────────────┐   ┌──────────────────────────────────────┐
│  Target Profiles     │   │  Vector Memory (ChromaDB)            │
│  targets/<t>/        │   │  .memory/ — semantic cross-session   │
│  profile.json        │   │  search via embeddings               │
└──────────────────────┘   └──────────────────────────────────────┘
```

### Agent Call Flow

```
User Input
    │
    ▼
Orchestrator LLM
    ├─ classify intent
    ├─ pull TargetProfile.get_context_brief()
    └─ inject context + [INSTRUCTION: skip already-run scans]
    │
    ▼
Sub-Agent Runner.run(enriched_task)
    │
    └─ [loop] LLM reasons → selects tool → calls tool → processes output
              │
              ├─ on_tool_start  → terminal display, live dashboard update
              ├─ on_tool_end    → extract findings, failure recovery
              ├─ on_thinking    → verbose reasoning display
              └─ on_finding     → severity alert, auto-update profile
    │
    ▼
RunResult { output, messages, tool_calls_made, findings, duration }
    │
    ▼
TargetProfile update + VectorMemory store
```

### Tool Execution Pipeline

Every tool follows this pipeline inside the Runner:

1. `_build_tool_call()` — resolves LLM tool name to Python function
2. `on_tool_start` callback — terminal display, dashboard update
3. Tool executes — subprocess or requests call
4. `_extract_findings()` — regex + pattern matching pulls ports, URLs, CVEs, credentials
5. `on_tool_end` callback — success/failure display, findings emit, failure recovery trigger
6. Result added to conversation history for next LLM reasoning step

---

## Agents

### Orchestrator Agent

The central coordinator. Receives all user input, routes to specialists, and never runs offensive tools directly.

**Key responsibilities:**
- Intent classification and delegation to 7+ specialist agents
- Context injection from `TargetProfile` before every delegation
- Prevents redundant scans via `[INSTRUCTION]` directives
- Manages the full Attack Planning lifecycle (generate → review → approve → execute)

**Tools (delegation + planning):**
`delegate_to_recon`, `delegate_to_websec`, `delegate_to_ctf`, `delegate_to_dfir`, `delegate_to_redteam`, `delegate_to_blackhat`, `delegate_to_appsec`, `plan_attack`, `generate_attack_plan`, `show_current_plan`, `get_next_action`, `register_vulnerability`, `register_service`, `attack_summary`

---

### Recon Agent

Specialized in network scanning and passive information gathering. Operates with a strict one-tool-per-task rule — never expands scope beyond the request.

| Tool | Binary | Description |
|------|--------|-------------|
| `nmap_scan` | `nmap` | Port scanning, service detection, NSE scripts |
| `subfinder_enum` | `subfinder` | Fast passive subdomain discovery |
| `amass_enum` | `amass` | OWASP Amass advanced subdomain enumeration |
| `dnsrecon_enum` | `dnsrecon` | DNS zone transfer, brute-force, record enumeration |
| `dig_lookup` | `dig` | Manual DNS record queries |
| `whois_lookup` | `whois` | Registrar, dates, nameservers |
| `wafw00f_detect` | `wafw00f` | WAF/CDN fingerprinting |
| `sslscan_check` | `sslscan` | SSL/TLS cipher and certificate audit |
| `fierce_scan` | `fierce` | DNS recon for non-contiguous IP ranges |
| `passive_recon_chain` | multiple | Full OSINT pipeline — zero active traffic |
| `subdomain_takeover_scan` | `subjack` | Dangling DNS → takeover detection |
| `js_secrets_scanner` | custom | API keys and secrets in JavaScript files |
| `js_endpoint_extractor` | custom | Hidden API routes in JS bundles |
| `cve_lookup` | NVD API | CVE data for detected software versions |
| `fingerprint_and_cve_chain` | multiple | Auto-fingerprint then CVE lookup |
| `nuclei_scan` | `nuclei` | Template-based vulnerability scanning |

**Routing rules (enforced in system prompt):**

| User says | Tool |
|-----------|------|
| `"port scan"` | `nmap_scan` only |
| `"find subdomains"` | `subfinder_enum` only |
| `"whois"` | `whois_lookup` only |
| `"full recon"` | all tools in sequence |
| `"passive recon"` | `passive_recon_chain` only |
| `"js analysis"` | `js_secrets_scanner` + `js_endpoint_extractor` |

---

### WebSec Agent

Specialized in web application security testing.

**Tools:** `gobuster_scan`, `nikto_scan`, `sqlmap_attack`, `nuclei_scan`, `wfuzz`, `ffuf`, `arjun`, `gau`, `gospider`, `dalfox`, `tplmap`, `jwt_tool`, `nosqlmap`, `commix`, `xsstrike`, API security checks, HTTP request smuggling, file upload bypass, SSRF testing, deserialization checks, WebSocket security analysis

---

### CTF Agent

Specialized in Capture The Flag challenges — binary exploitation, cryptography, reverse engineering, web CTF.

**Tools:** `binwalk_extract`, `strings_extract`, `file_identify`, `exiftool_metadata`, `base64_decode`, `hex_decode`, `caesar_cipher`, `gdb_analyze`, `pwntools_exploit`, `stegseek`, crypto utilities, format string helpers

---

### DFIR Agent

Digital Forensics and Incident Response — memory analysis, log forensics, malware analysis, network traffic investigation.

**Tools:** `volatility3`, `tshark`, `scapy`, `log_analyzer`, `yara_scan`, `ioc_extractor`, timeline reconstruction, registry analysis, artifact collection

---

### RedTeam Agent

Advanced offensive operations — post-exploitation, lateral movement, Active Directory attacks.

**Tools:** `msfconsole_run`, `pwncat`, `netcat_shell`, privilege escalation suite, lateral movement suite, `ad_attacks`, `kerberoast`, `bloodhound`, `responder`, `ntlmrelayx`, `zerologon_check`, `petitpotam_coerce`, `secretsdump`, `crackmapexec`

---

### AppSec Agent

Application security review — SAST-style code analysis, dependency scanning, OWASP Top 10 coverage.

**Tools:** `code_analysis`, `dependency_check`, `semgrep`, access control testing, authentication review, CORS misconfiguration, security header analysis, tech checklist runner

---

### BugBounty Agent

Purpose-built for bug bounty programs. Authorization context is automatically injected into all prompts. Prioritizes P1/P2 findings and produces HackerOne/Bugcrowd-aligned reports.

**Additional features:**
- Full authorization statement baked into every LLM call
- Built-in PoC validation via `poc_validation` tools
- Structured output with CVSS score, reproduction steps, impact assessment

---

### BlackHat Agent

Unrestricted offensive agent with the complete tool set. For fully authorized red team engagements and isolated lab environments only.

**Additional capabilities beyond RedTeam:** C2 server setup, browser automation for credential harvesting, advanced AD attack chains, custom payload generation, cloud attack tools

> **Warning:** The BlackHat Agent has no built-in scope restrictions. Never deploy against unauthorized targets.

---

### Reporter Agent

Generates professional penetration testing reports by consuming the target profile and session memory.

**Report sections:** Executive Summary · Scope & Methodology · Attack Phase Narrative · Detailed Findings Table (CVSS, CVE, remediation) · Severity Distribution Chart · Appendices (raw output, commands run)

---

## SDK Modules

All framework internals live in `src/sdk/`:

| Module | Description |
|--------|-------------|
| `agent.py` | `Agent` dataclass — name, instructions, model, tools, handoffs, guardrails |
| `runner.py` | ReAct execution loop — tool calling, conversation history, all callbacks |
| `tool.py` | `@function_tool` decorator — wraps Python functions as LLM-callable tools |
| `agent_graph.py` | `AgentGraph` + `DiscoveryBus` — parallel multi-agent collaboration |
| `attack_planner.py` | Vuln-to-exploit mapping, attack path generation, approval tracking |
| `memory.py` | ChromaDB vector memory with file fallback and semantic search |
| `key_manager.py` | API key management — multi-provider, auto-rotation, usage tracking |
| `recovery.py` | Failure recovery — alternative tools, parameter adjustment, confidence scoring |
| `session_memory.py` | In-session conversation state per agent |
| `report_generator.py` | PDF and markdown report builder |
| `cache.py` | Tool result caching — avoid re-running the same scan |
| `scope.py` | Scope enforcement — in-scope/out-of-scope target lists |
| `evidence.py` | Evidence collector — attach screenshots and raw output to findings |
| `dashboard.py` | Real-time terminal dashboard — active tools, findings, phase tracking |
| `async_executor.py` | Background async task management |
| `throttle.py` | Rate limiting for API calls and tool invocations |
| `guardrail.py` | Input/output validation before tool execution |
| `handoffs.py` | Agent-to-agent handoff protocol |
| `output_parser.py` | Structured extraction of findings from raw tool output |
| `confidence.py` | Confidence scoring for discovered vulnerabilities |
| `dedup.py` | Deduplication of repeated discoveries |
| `vuln_chainer.py` | Chain multiple vulnerabilities into a complete attack path |
| `exploit_matcher.py` | Match CVE IDs to Metasploit modules |
| `narrator.py` | Convert technical findings into natural-language report narrative |
| `fp_filter.py` | False positive filtering for common scanner noise |
| `diff_analyzer.py` | Compare scan results across sessions — show what changed |
| `asset_correlation.py` | Correlate IP/domain/service across multiple data sources |
| `validation.py` | PoC-based vulnerability confirmation |
| `model_settings.py` | Per-model temperature, max_tokens, and LLM parameters |
| `attack_visualizer.py` | ASCII kill-chain and attack path visualization |

---

## Tools Reference

Tools are organized by MITRE ATT&CK tactic in `src/tools/`:

### Reconnaissance

| Tool | Binary | Description |
|------|--------|-------------|
| `nmap_scan` | `nmap` | Port scanning, service detection, OS fingerprinting, NSE vulnerability scripts |
| `whois_lookup` | `whois` | Domain registration info |
| `dig_lookup` | `dig` | DNS record queries |
| `subfinder_enum` | `subfinder` | Fast passive subdomain enumeration |
| `dnsrecon_enum` | `dnsrecon` | Zone transfer, brute-force, record enumeration |
| `wafw00f_detect` | `wafw00f` | WAF/CDN identification |
| `amass_enum` | `amass` | Advanced subdomain enumeration |
| `sslscan_check` | `sslscan` | SSL/TLS configuration and cipher audit |
| `fierce_scan` | `fierce` | DNS recon for non-contiguous IP space |
| `passive_recon_chain` | multiple | Full OSINT pipeline with zero active traffic |
| `subdomain_takeover_scan` | `subjack` | Dangling DNS takeover detection |
| `js_secrets_scanner` | custom | API keys and secrets in JavaScript files |
| `js_endpoint_extractor` | custom | Hidden API routes in JS bundles |
| `cve_lookup` | NVD API | CVE data for detected software |
| `fingerprint_and_cve_chain` | multiple | Fingerprint services then auto-lookup CVEs |

### Web Testing

| Tool | Binary | Description |
|------|--------|-------------|
| `gobuster_scan` | `gobuster` | Directory and file bruteforcing |
| `nikto_scan` | `nikto` | Web server misconfiguration scanner |
| `sqlmap_attack` | `sqlmap` | SQL injection detection and exploitation |
| `wfuzz` | `wfuzz` | Web fuzzer for parameters and paths |
| `ffuf` | `ffuf` | Fast web fuzzer — vhost, directory, parameter |
| `arjun` | `arjun` | HTTP parameter discovery |
| `gau` | `gau` | Historical URLs from Wayback, Common Crawl, AlienVault OTX |
| `gospider` | `gospider` | Fast web spider for endpoint discovery |
| `curl_request` | `curl` | Custom HTTP requests and header inspection |
| `dalfox` | `dalfox` | XSS parameter fuzzer with payload generation |
| `tplmap` | `tplmap` | Server-Side Template Injection (SSTI) exploitation |
| `jwt_tool` | `jwt_tool` | JSON Web Token attacks |
| `nosqlmap` | `nosqlmap` | NoSQL injection (MongoDB, Redis) |
| `commix` | `commix` | Command injection exploitation |
| `xsstrike` | `xsstrike` | Advanced XSS scanner with DOM analysis |

### Exploitation

| Tool | Binary | Description |
|------|--------|-------------|
| `searchsploit` | `searchsploit` | Local Exploit-DB lookup |
| `nuclei_scan` | `nuclei` | Template-based scanner — 9,000+ community templates |
| `msfconsole_run` | `msfconsole` | Metasploit Framework exploitation |
| `hydra_bruteforce` | `hydra` | Brute-force for SSH, FTP, HTTP forms, 50+ protocols |

### Post-Exploitation

| Tool | Binary | Description |
|------|--------|-------------|
| `pwncat` | `pwncat-cs` | Post-exploitation shell with escalation helpers |
| `netcat_shell` | `nc` | Reverse/bind shells and port listeners |
| `privilege_escalation` | `linpeas`/`winpeas` | Local privilege escalation enumeration |
| `lateral_movement` | `crackmapexec` | Pass-the-Hash, SMB lateral movement |
| `secretsdump` | `impacket` | Remote credential dumping |

### Active Directory

| Tool | Binary | Description |
|------|--------|-------------|
| `kerbrute` | `kerbrute` | Kerberos user enumeration and password spraying |
| `rubeus_attack` | `rubeus` | Kerberoasting, ASREPRoasting, ticket manipulation |
| `bloodhound` | `bloodhound-python` | AD graph data collection |
| `responder` | `responder` | LLMNR/NBT-NS poisoning and hash capture |
| `ntlmrelayx_start` | `impacket-ntlmrelayx` | NTLM relay attacks |
| `petitpotam_coerce` | `PetitPotam.py` | NTLM coercion via MS-EFSRPC |
| `zerologon_check` | custom | CVE-2020-1472 detection |
| `crackmapexec` | `crackmapexec` | SMB/WinRM credential verification |

### Credential Access

| Tool | Binary | Description |
|------|--------|-------------|
| `john_crack` | `john` | Dictionary and rule-based password cracking |
| `hashcat_crack` | `hashcat` | GPU-accelerated hash cracking |
| `mimikatz_run` | `mimikatz` | Windows in-memory credential extraction |

### Shells

Generate ready-to-use reverse shell payloads for 15+ languages:

```bash
❯ shell bash 10.10.14.5 4444         # Bash reverse shell
❯ shell python 10.10.14.5 4444        # Python reverse shell
❯ shell powershell 10.10.14.5 4444    # PowerShell reverse shell
❯ shell php 10.10.14.5 4444           # PHP reverse shell
❯ listen 4444                          # Start nc listener
❯ revshell                             # Interactive payload menu
```

---

## CLI Commands

### Target Management
```bash
❯ target <domain/IP>          # Set active target and load its profile
❯ profile                     # View full target profile
❯ history                     # Show command history
```

### Agent Selection
```bash
❯ switch                      # Interactive agent selector
```

### Attack Planning
```bash
❯ plan generate               # Generate attack plan from current findings
❯ plan                        # Review current plan
❯ plan approve                # Approve plan for execution
❯ plan next                   # Execute next phase
❯ plan modify <phase> "..."   # Modify a specific phase
❯ plan cancel                 # Abort the plan
```

### Agent Graph
```bash
❯ graph                       # Show graph menu
❯ graph recon                 # Recon-only parallel graph
❯ graph exploit               # Full kill-chain graph
❯ graph bounty                # Bug-bounty optimized graph
❯ graph status                # Execution status
❯ graph discoveries           # All DiscoveryBus items
❯ graph validated             # Only validated vulnerabilities
```

### Memory
```bash
❯ memory <query>              # Semantic search across all memories
❯ remember <text>             # Save a manual note
❯ note <text>                 # Alias for remember
```

### Scope
```bash
❯ scope add <target>          # Add to in-scope list
❯ scope remove <target>       # Remove from scope
❯ scope list                  # View scope
```

### Reporting
```bash
❯ export                      # Quick markdown report
❯ generate pdf report         # Professional PDF with charts
❯ create pentest report       # Full deliverable via Reporter Agent
```

### Shells & Listeners
```bash
❯ shell <type> <ip> <port>    # Generate reverse shell payload
❯ revshell                    # Interactive payload menu
❯ listen <port>               # Start netcat listener
```

### Dashboard & Stats
```bash
❯ live on / live off          # Toggle live terminal dashboard
❯ stats                       # Real-time session statistics
❯ dashboard status            # Dashboard state
```

### Proxy & Anonymity
```bash
❯ proxy add <ip:port>         # Add proxy
❯ proxy enable / disable      # Toggle proxy routing
❯ proxy rotate                # Rotate to next proxy
❯ tor                         # Route via Tor
❯ myip                        # Check current egress IP
```

### Tool Cache & Evidence
```bash
❯ cache status                # Cached results overview
❯ cache clear                 # Clear all cached results
❯ evidence list               # View collected evidence
❯ evidence export             # Export evidence bundle
```

### Async Tasks
```bash
❯ task status                 # Running tasks
❯ task list                   # All tasks
❯ task cancel <id>            # Cancel a task
❯ task results <id>           # View completed task output
```

### API Key Management
```bash
❯ api                         # Current provider and model
❯ api nvidia                  # Switch to NVIDIA
❯ api openrouter              # Switch to OpenRouter
❯ apikey status               # Per-key usage and failure stats
❯ apikey reset                # Reset failure counters
```

### Output Control
```bash
❯ detailed on / off           # Toggle detailed tool output
❯ thinking                    # Toggle agent reasoning visibility
❯ confirm                     # Toggle human-in-the-loop for tools
```

### Bug Bounty Mode
```bash
❯ mode on                     # Enable authorization context injection
❯ mode off                    # Disable bug bounty mode
```

### General
```bash
❯ context                     # Current session context
❯ clear                       # Clear terminal
❯ help / commands             # All available commands
❯ continue / resume           # Resume last interrupted operation
❯ tools-check                 # Verify installed system tools
❯ quit / exit                 # Exit
```

---

## Configuration

### Environment Variables

```env
# ── Providers ─────────────────────────────────────────────────────
# Longcat disabled for now; leave model empty and key commented.
# LONGCAT_API_KEY=your_key_here
LONGCAT_BASE_URL=https://api.longcat.chat/openai
LONGCAT_MODEL=

# ── Backup Providers ──────────────────────────────────────────────
NVIDIA_API_KEY=nvapi-your_key
NVIDIA_MODEL=stepfun-ai/step-3.7-flash

OPENROUTER_API_KEY=sk-or-v1-your_key
OPENROUTER_MODEL=cognitivecomputations/dolphin-mistral-24b-venice-edition:free

# OpenAI disabled for now.
# OPENAI_API_KEY=sk-your_key
OPENAI_MODEL=

# ── Optional Intelligence APIs ────────────────────────────────────
NVD_API_KEY=your_nvd_key           # NIST NVD — faster CVE lookups
SHODAN_API_KEY=your_shodan_key     # Passive host intelligence
VIRUSTOTAL_API_KEY=your_vt_key    # File and URL reputation
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
```

### Python Requirements

```
openai>=1.0.0
rich>=13.0.0
python-dotenv>=1.0.0
loguru>=0.7.0
prompt_toolkit>=3.0.0
chromadb>=0.4.0        # Vector memory (optional but recommended)
fpdf2>=2.7.0           # PDF report generation
matplotlib>=3.7.0      # Report charts
```

### System Tools

The following tools should be installed for full functionality:

| Category | Tools |
|----------|-------|
| Recon | `nmap`, `whois`, `dig`, `subfinder`, `dnsrecon`, `httpx`, `wafw00f`, `amass`, `sslscan`, `fierce` |
| Web Testing | `gobuster`, `dirsearch`, `curl`, `arjun`, `gau`, `gospider`, `nikto`, `wfuzz`, `ffuf` |
| Exploitation | `sqlmap`, `nuclei`, `hydra`, `dalfox`, `tplmap`, `jwt_tool`, `nosqlmap`, `commix`, `xsstrike` |
| Post-Exploitation | `pwncat-cs`, `netcat`, `metasploit-framework` |
| Credentials | `john`, `hashcat`, `crackmapexec`, `responder`, impacket suite |
| Forensics | `tshark`, `binwalk`, `exiftool`, `volatility3` |

Run `tools-check` inside the CLI to see which tools are installed.

---

## Technology Stack

| Category | Component | Purpose |
|----------|-----------|---------|
| Language | Python 3.10+ | Core framework |
| LLM Client | `openai` SDK ≥ 1.0 | Compatible with all providers via base URL switching |
| Terminal UI | `rich` | Panels, tables, progress bars, syntax highlighting |
| Input | `prompt_toolkit` | Multi-line paste, history, tab completion |
| Logging | `loguru` | Structured file + console logging with rotation |
| Async | `asyncio` + `concurrent.futures` | Parallel agent and tool execution |
| Vector Memory | `chromadb` | Semantic search across session memories |
| PDF Reports | `fpdf2` | Client-ready PDF generation |
| Charts | `matplotlib` | Severity distribution graphs |
| Target Profiles | JSON files in `targets/` | Persistent per-target data |
| Session Logs | JSONL files in `sessions/` | Full conversation replay |

---

## Project Structure

```text
cyber-copilot/
|-- main.py                         # Entry point: REPL, command router, callbacks
|-- requirements.txt
|-- pyrightconfig.json
|-- .env.example                    # Safe configuration template
|-- README.md
|-- report.md
|-- assets/
|   `-- screenshots/                # Public, sanitized screenshots
|-- src/
|   |-- agents/                     # Agent definitions
|   |   |-- orchestrator_agent.py
|   |   |-- recon_agent.py
|   |   |-- websec_agent.py
|   |   |-- ctf_agent.py
|   |   |-- dfir_agent.py
|   |   |-- redteam_agent.py
|   |   |-- appsec_agent.py
|   |   |-- bugbounty_agent.py
|   |   |-- blackhat_agent.py
|   |   `-- reporter_agent.py
|   |-- sdk/                        # Core framework SDK
|   |   |-- agent.py
|   |   |-- runner.py
|   |   |-- tool.py
|   |   |-- agent_graph.py
|   |   |-- attack_planner.py
|   |   |-- memory.py
|   |   |-- key_manager.py
|   |   `-- recovery.py
|   |-- tools/                      # Security tool wrappers
|   |   |-- recon_active.py
|   |   |-- recon_passive.py
|   |   |-- web.py
|   |   |-- exploitation.py
|   |   |-- post_exploit.py
|   |   |-- credential_access.py
|   |   |-- forensics.py
|   |   `-- shells.py
|   |-- repl/                       # Terminal interface
|   |   |-- ui.py
|   |   |-- profiles.py
|   |   |-- reports.py
|   |   |-- target_manager.py
|   |   |-- parallel.py
|   |   |-- graph.py
|   |   `-- logging.py
|   `-- prompts/                    # Agent system prompts
|       |-- recon.md
|       |-- web_pentest.md
|       |-- ctf.md
|       `-- dfir.md
`-- tests/                          # Unit and integration tests
```

---

## Legal

Cyber-CoPilot is intended for:
- Authorized penetration testing engagements
- Bug bounty programs with explicit program scope
- CTF competitions
- Security research in isolated lab environments
- Educational use

Never use this tool against systems you do not own or have explicit written permission to test. The authors assume no liability for misuse.

**Use responsibly. Test ethically. Disclose properly.**
