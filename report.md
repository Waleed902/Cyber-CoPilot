**Final Year Project Report**

**Project Title**

**Cyber-CoPilot: An AI-Powered Multi-Agent Offensive Security Framework**

**Submitted by**

**Muhammad Waleed** (BS-DFCS)

Session 2022–2026

**Supervised by**

**Mr. Kaukab Jamal Zuberi**

![](FYP-Report/media/media/image1.jpg){width="1.90625in"
height="1.5208333333333333in"}

**Department of Criminology**

**Lahore Garrison University**

**Lahore**

**\**

> **Cyber-CoPilot: An AI-Powered Multi-Agent Offensive Security Framework**

A project submitted to the

Department of Criminology

In

Partial Fulfillment of the Requirements for the

Bachelor's Degree in Digital Forensics and Cyber Security

By

**Muhammad Waleed**

**[Supervisor]{.underline}**

**Mr. Kaukab Jamal Zuberi \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\**
Associate Dean\
Department of Criminology

**[Chairperson]{.underline}**

**Dr. Kausar Parveen \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\**
Head of Department\
Department of Criminology

**[Associate Dean]{.underline}**

**Mr. Kaukab Jamal Zuberi**

Department of Criminology
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

**COPYRIGHTS**

This is to certify that the project titled "**Cyber-CoPilot: An AI-Powered Multi-Agent Offensive Security Framework**" is the
genuine work carried out by **Muhammad Waleed,** student of BS-DFCS of
Criminology and Forensic Sciences Department, Lahore Garrison
University, Lahore. During the academic year 2025–2026, in
partial fulfilment of the requirements for the award of the degree of
Bachelor of Digital Forensics and Cyber Security and that the project
has not formed the basis for the award previously of any other degree,
diploma, fellowship or any other similar title.

Muhammad Waleed \_\_\_\_\_\_\_\_\_\_\_\_

**DECLARATION**

This is to declare that the project entitled "**Cyber-CoPilot: An AI-Powered Multi-Agent Offensive Security Framework**" is an
original work done by undersigned, in partial fulfillment of the
requirements for the degree "Bachelor of Digital Forensics and Cyber
Security" at Criminology and Forensic Sciences Department, Lahore
Garrison University, Lahore.

All the analysis, design and system development have been accomplished
by the undersigned. Moreover, this project has not been submitted to any
other college or university.

Muhammad Waleed \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

**ACKNOWLEDGEMENTS**

I would like to express my sincere gratitude to my supervisor, **Mr. Kaukab Jamal Zuberi**, for his invaluable guidance, continuous support, and constructive feedback throughout the development of this project. His expertise in cybersecurity and encouragement to explore emerging AI-based approaches were instrumental in shaping Cyber-CoPilot into a comprehensive framework.

I am deeply thankful to **Dr. Kausar Parveen**, Head of the Department of Criminology, for providing an academic environment that fosters innovation and research in digital forensics and cyber security.

I also extend my appreciation to the faculty members at Lahore Garrison University, whose courses in network security, ethical hacking, digital forensics, and software engineering provided the foundational knowledge necessary for this work.

Finally, I am grateful to the open-source security community—the maintainers of tools such as Nmap, Nuclei, SQLMap, Metasploit, and the developers of OpenAI-compatible LLM APIs—whose work made the technical implementation of this framework possible.

**DEDICATION**

This project is dedicated to my family, whose unwavering support and patience made this journey possible, and to the cybersecurity community that tirelessly works to make the digital world a safer place.

------------------------------------------------------------------------

**Table of Contents**

List of Tables\
List of Figures\
List of Abbreviations\
Abstract\
Chapter 1: Introduction\
  1.1 Context and Background\
  1.2 Problem Statement and Objectives\
  1.3 Significance\
  1.4 Organization of Report\
Chapter 2: Problem Definition\
  2.1 Operational Problem\
  2.2 Design Constraints\
  2.3 Required Capabilities\
  2.4 Scope of the Proposed System\
Chapter 3: Literature Review\
  3.1 Traditional Security Toolchains\
  3.2 AI-Assisted Security Automation\
  3.3 Multi-Agent and Memory-Based Systems\
  3.4 Comparison of Existing Approaches\
  3.5 Research Gap and Project Contribution\
Chapter 4: Software Requirement Specification\
  4.1 Functional Requirements\
  4.2 Non-Functional Requirements\
  4.3 System Constraints\
  4.4 Use Cases\
Chapter 5: Methodology\
  5.1 Approach\
  5.2 Tools and Software\
  5.3 System Architecture\
  5.4 Internal Design & SDK Core\
  5.5 System Diagrams\
Chapter 6: Implementation and Testing\
  6.1 Technical Implementation\
  6.2 Multi-Agent Execution\
  6.3 Testing Methodologies\
  6.4 Codebase Audit and Coverage Findings\
Chapter 7: Results and Discussion\
  7.1 Real-World Execution Results\
  7.2 Vulnerability Detection Efficacy\
  7.3 Discussion and Recovery Outcomes\
  7.4 Limitations\
Chapter 8: Conclusion and Future Work\
  8.1 Summary\
  8.2 Core Contributions\
  8.3 Future Directions\
References\
Appendices

------------------------------------------------------------------------

**List of Tables**

| Table No. | Title | Page |
|-----------|-------|------|
| Table 1.1 | Four Pillars of Cyber-CoPilot | — |
| Table 2.1 | Design Constraints and Rationale | — |
| Table 2.2 | Required System Capabilities | — |
| Table 3.1 | Comparison of Traditional Security Tools | — |
| Table 3.2 | AI-Assisted Security Platforms | — |
| Table 3.3 | Comparison of Cyber-CoPilot with Existing Approaches | — |
| Table 3.4 | Discovery Types in the DiscoveryBus | — |

------------------------------------------------------------------------

**List of Figures**

| Figure No. | Title | Page |
|------------|-------|------|
| Figure 1.1 | High-Level System Architecture of Cyber-CoPilot | — |
| Figure 2.1 | Data Flow Diagram — Task Execution Pipeline | — |
| Figure 3.1 | Agent Interaction Sequence Diagram | — |
| Figure 3.2 | ReAct Loop Execution Model | — |
| Figure 4.1 | Cyber-CoPilot Use Case Diagram | — |
| Figure 5.1 | Code SDK Core Class Diagram | — |
| Figure 5.2 | System Component Architecture Diagram | — |
| Figure 6.1 | Agent Execution State Machine | — |
| Figure 7.1 | Tool Coverage by MITRE ATT&CK Tactic | — |

------------------------------------------------------------------------

**List of Abbreviations**

| Abbreviation | Full Form |
|--------------|-----------|
| AI | Artificial Intelligence |
| API | Application Programming Interface |
| AD | Active Directory |
| CLI | Command-Line Interface |
| CTF | Capture The Flag |
| CVE | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| DFCS | Digital Forensics and Cyber Security |
| DFIR | Digital Forensics and Incident Response |
| DNS | Domain Name System |
| DFD | Data Flow Diagram |
| HyDE | Hypothetical Document Embedding |
| IDOR | Insecure Direct Object Reference |
| JWT | JSON Web Token |
| LFI | Local File Inclusion |
| LLM | Large Language Model |
| MITRE | Massachusetts Institute of Technology Research and Engineering |
| NLP | Natural Language Processing |
| NVD | National Vulnerability Database |
| OSINT | Open-Source Intelligence |
| OWASP | Open Web Application Security Project |
| PDF | Portable Document Format |
| PoC | Proof of Concept |
| RAG | Retrieval-Augmented Generation |
| RCE | Remote Code Execution |
| ReAct | Reasoning and Acting |
| REPL | Read-Evaluate-Print Loop |
| RFI | Remote File Inclusion |
| SDK | Software Development Kit |
| SMB | Server Message Block |
| SQL | Structured Query Language |
| SQLi | SQL Injection |
| SSRF | Server-Side Request Forgery |
| SSTI | Server-Side Template Injection |
| TUI | Text User Interface |
| UML | Unified Modeling Language |
| WAF | Web Application Firewall |
| XSS | Cross-Site Scripting |
| XXE | XML External Entity |

------------------------------------------------------------------------

**Abstract**

Penetration testing is a fundamental component of modern cybersecurity practice, yet the workflow remains heavily fragmented. Security analysts must manually orchestrate dozens of specialized tools—from reconnaissance utilities like Nmap and Subfinder to exploitation frameworks such as SQLMap and Metasploit—while tracking discoveries across separate terminal sessions, notes, and ad hoc scripts. This fragmentation leads to repeated scans, missed context, and inconsistent reporting.

Cyber-CoPilot addresses this problem by presenting an AI-powered, multi-agent offensive security framework that automates the full penetration testing lifecycle through a natural-language terminal interface. The system employs a hierarchical architecture comprising a central Orchestrator plus specialist agent modules for Reconnaissance, Web Security, Red Team, DFIR, CTF, AppSec, BugBounty, BlackHat, Reporter, Exploit Craft, Adversarial analysis, and verification workflows. These agents are coordinated by the Orchestrator, which performs intent classification, context injection, and task delegation.

The framework is built on four pillars: (1) a multi-agent system with inter-agent discovery sharing via a DiscoveryBus, (2) a ReAct-based execution engine that reasons, selects tools, executes, and processes results in an iterative loop, (3) a persistent target intelligence store using ChromaDB vector memory and JSON-based target profiles, and (4) a structured reporting pipeline that produces both Markdown and PDF reports with severity charts and executive summaries. Additional subsystems include a failure recovery engine with intelligent retry strategies, an attack planning system with vulnerability-to-exploit mapping, scope enforcement, bug bounty scope import, finding lifecycle management, evidence bundling, and a real-time terminal dashboard.

The audited repository currently contains 223 parsed Python files with no syntax errors. The live `src/` tree contains 177 Python modules, 77,383 non-blank source lines, 167 classes, 1,903 functions, and 583 registered `@function_tool` capabilities across agents, SDK modules, and tool wrappers. Evaluation against existing tools demonstrates that Cyber-CoPilot significantly reduces context switching, eliminates redundant scanning through persistent memory, and produces audit-ready reports—while maintaining operator transparency and human-in-the-loop control at every step.

**\**

------------------------------------------------------------------------

**CHAPTER 1: INTRODUCTION**

**1.1 Context and Background**

The cybersecurity landscape has undergone a paradigm shift. Organizations face an ever-expanding attack surface driven by cloud adoption, microservice architectures, API-first development, and the proliferation of Internet-of-Things devices. To assess the security posture of these environments, penetration testing—authorized simulation of real-world attacks—remains the gold standard. However, the practice itself has not fundamentally changed in over a decade: an analyst opens a terminal, runs a sequence of specialized tools, manually parses their outputs, copies relevant findings into notes, and then repeats this cycle for the next phase of the engagement.

This workflow is inherently fragmented. A typical web application assessment might involve Nmap for port scanning, Subfinder and Amass for subdomain enumeration, Gobuster for directory brute-forcing, Nuclei for template-based vulnerability scanning, SQLMap for SQL injection testing, and Metasploit for exploitation. Each tool produces output in a different format, expects different input parameters, and has no built-in awareness of what the other tools have already discovered. The analyst acts as the sole integration layer—mentally tracking open ports, discovered endpoints, and potential attack paths while context-switching between terminals.

Cyber-CoPilot is designed to eliminate this fragmentation. It is a Python-based, terminal-native framework that combines Large Language Model (LLM) orchestration with a multi-agent architecture to manage the entire penetration testing lifecycle—from passive reconnaissance to active exploitation to professional reporting—through natural-language commands. Instead of memorizing tool syntax, the analyst types a request like "scan for open ports on example.com" or "check for SQL injection," and the system classifies the intent, selects the appropriate specialist agent, injects previously discovered context, executes the relevant tools, extracts findings, and updates a persistent target profile. When the engagement is complete, the analyst can generate a PDF report with severity charts, executive summaries, and attack narratives from a single command.

The platform is built around four architectural pillars, as summarized in Table 1.1.

**Table 1.1: Four Pillars of Cyber-CoPilot**

| Pillar | Description |
|--------|-------------|
| **Multi-Agent System** | A central Orchestrator coordinates specialist agent modules for reconnaissance, web security, application security, bug bounty workflows, exploit crafting, DFIR, CTF, adversarial analysis, verification, red team execution, and reporting. |
| **Attack Execution Engine** | An Agentic Runner implementing the ReAct (Reasoning + Acting) loop: the LLM reasons about the current state, selects and invokes a tool, processes results, and repeats until the objective is met. |
| **Target Intelligence Store** | A persistent per-target profile system that accumulates ports, subdomains, credentials, vulnerabilities, and DNS data across sessions, feeding every agent with prior-collected intelligence before any new scan runs. |
| **Structured Reporting Pipeline** | AI-driven Markdown and PDF reporting with charts, executive summaries, MITRE ATT&CK alignment, and client-ready formatting. |

Figure 1.1 presents the high-level system architecture showing how these pillars interconnect.

![Figure 1.1: High-Level System Architecture of Cyber-CoPilot](FYP-Report/media/fig1_system_architecture.png)

**Figure 1.1: High-Level System Architecture of Cyber-CoPilot**

The architecture follows a layered design. At the top, the user interacts with a Rich-powered terminal interface (REPL) that routes natural-language input to the Orchestrator Agent. The Orchestrator performs intent classification and delegates to one of the specialist agents. Each agent operates within its own ReAct execution loop, calling tools from the Tool Layer. Findings are extracted using regex and pattern-matching, then propagated through the DiscoveryBus to other agents and persisted in both the Target Profile (JSON) and Vector Memory (ChromaDB). This ensures that no agent re-runs a scan that has already been completed and that intelligence accumulates across sessions.

**1.2 Problem Statement and Objectives**

The core problem Cyber-CoPilot aims to solve is the **operational fragmentation** inherent in manual penetration testing workflows. Specifically:

1. **Context Loss**: When an analyst switches from one tool to another, the output of the previous tool is not automatically available. Discovered ports, subdomains, and vulnerabilities must be manually tracked.

2. **Redundant Scanning**: In multi-session engagements, analysts frequently repeat scans because there is no persistent memory of what has already been discovered.

3. **Skill Barrier**: Each security tool has its own syntax, flags, and output format. Learning these across 60+ tools is a non-trivial investment.

4. **Reporting Overhead**: After the technical assessment, analysts spend significant time converting raw tool outputs into structured, client-ready reports.

5. **Failure Handling**: When a tool fails—due to timeouts, rate limiting, missing binaries, or WAF blocking—the analyst must manually diagnose the issue, select an alternative, and restart.

The **primary objective** is to build a framework that automates the repetitive coordination tasks while keeping the operator informed and in control at every step. The secondary objectives are:

- **O1**: Implement natural-language task routing via LLM-based intent classification.
- **O2**: Design a multi-agent architecture where specialist agents share discoveries through a typed message bus (DiscoveryBus) and persistent target profiles.
- **O3**: Build a ReAct-based execution engine with tool calling, conversation memory, context window management, and loop detection.
- **O4**: Create a semantic vector memory system (ChromaDB) that enables cross-session intelligence retrieval via fuzzy search.
- **O5**: Develop an attack planning subsystem that maps discovered vulnerabilities to exploit chains and generates approval-gated execution plans.
- **O6**: Implement a failure recovery engine that classifies errors, suggests alternative tools, adjusts parameters, and applies evasion techniques automatically.
- **O7**: Produce professional PDF and Markdown reports with severity distribution charts, executive summaries, and detailed finding tables.

**1.3 Significance**

The significance of Cyber-CoPilot lies in three areas:

**Academic Contribution**: The project demonstrates how modern LLM orchestration patterns—specifically the ReAct loop, multi-agent delegation with context injection, and semantic memory with Hypothetical Document Embedding (HyDE)—can be applied to an established security workflow. Unlike most LLM-based chatbots that operate statelessly, Cyber-CoPilot maintains a rich, persistent state across sessions, making it a concrete reference implementation for human-in-the-loop agentic systems.

**Practical Value**: For security analysts, the framework reduces engagement time by eliminating context switching, preventing redundant scans, and automating report generation. The natural-language interface lowers the barrier to entry for junior analysts who may not yet be familiar with every tool's command-line syntax. The attack planning subsystem also provides a structured methodology that promotes thoroughness and consistency.

**Industry Relevance**: The cybersecurity industry faces a well-documented talent shortage. Automation tools that augment analyst capability—without replacing human judgment—are increasingly critical. Cyber-CoPilot positions itself in this space by acting as an orchestration layer above existing tooling, maintaining complete transparency through its terminal interface, and preserving human authority over all exploitation decisions through its approval-gated attack planning workflow.

**1.4 Organization of Report**

The report is organized in a standard engineering format:

- **Chapter 1 (Introduction)** provides the context, problem statement, objectives, and significance of the project.
- **Chapter 2 (Problem Definition)** formalizes the operational problem, design constraints, required capabilities, and system scope.
- **Chapter 3 (Literature Review)** surveys traditional security toolchains, AI-assisted automation, multi-agent systems, and identifies the research gap that Cyber-CoPilot addresses.
- **Chapter 4** will present the Software Requirements Specification (SRS).
- **Chapter 5** will describe the methodology, architecture design approach, and detailed system design with UML diagrams.
- **Chapter 6** will cover implementation details and testing methodologies.
- **Chapter 7** will present results, interpretation, and limitations.
- **Chapter 8** will conclude the report with a summary, recommendations, and future directions.

------------------------------------------------------------------------

**CHAPTER 2: PROBLEM DEFINITION**

**2.1 Operational Problem**

Cyber-CoPilot is intended to solve the coordination problem that appears when a security analyst must move through multiple engagement phases—passive reconnaissance, active scanning, vulnerability validation, exploitation support, post-exploitation, and reporting—without losing state. In a typical assessment:

1. The analyst runs **port scanning** (e.g., `nmap -sV -sC target`) and discovers 12 open ports with service versions.
2. Based on these results, they run **subdomain enumeration** (`subfinder -d target`), discovering 35 subdomains.
3. They then move to **directory brute-forcing** (`gobuster dir -u target -w wordlist.txt`), finding 8 accessible paths.
4. Each of these findings should inform the next step—but in practice, the analyst must manually copy port numbers into vulnerability scanner commands, paste discovered URLs into SQLMap, and track which services have already been tested.

This workflow becomes quadratically complex as the number of discoveries grows. Cyber-CoPilot addresses this by maintaining a **centralized context hub** (`src/sdk/context_hub.py`, 61,610 bytes) that records every tool execution, extracts findings using compiled regex patterns, and serves them to any agent that runs next. The Orchestrator's **context injection** mechanism ensures that before any sub-agent runs, it receives:

- The current target domain/IP
- All discovered open ports with services and versions
- All discovered subdomains
- Previously registered vulnerabilities (severity, CVE, description)
- An explicit `[INSTRUCTION]` directive not to re-run scans already covered

This means that a second "scan for vulnerabilities" command in the same session skips the port scan phase entirely and proceeds directly to vulnerability testing—the system has already learned what the target looks like.

**2.2 Design Constraints**

The system operates under several key constraints, summarized in Table 2.1.

**Table 2.1: Design Constraints and Rationale**

| Constraint | Rationale |
|------------|-----------|
| **Transparency** | Every tool invocation must be visible to the operator. The system shows the exact command being run (e.g., `nmap -sV 10.10.14.5`), the raw output, and the findings extracted. No "black box" operation. |
| **Human-in-the-Loop** | Exploitation phases require explicit operator approval through the attack planning approval gate. The system never launches an exploit autonomously without confirmation. |
| **Authorization Scope** | The scope enforcement module (`src/sdk/scope.py`, 14,309 bytes) maintains in-scope and out-of-scope target lists. Any tool invocation against an out-of-scope target is blocked. |
| **Auditability** | All tool executions, findings, and agent decisions are logged via Loguru with file rotation (10 MB). Session logs are stored as JSONL for full conversation replay. |
| **Multi-Target Support** | The system must handle web applications, internal networks, Active Directory environments, and Linux/Windows targets. Different agents and tool chains are activated based on the target profile. |
| **Modularity** | The framework must support adding new agents, tools, and SDK modules without modifying the core execution engine. Each agent is a self-contained unit with its own system prompt, tool set, and execution scope. |
| **Offline Capability** | Vector memory, target profiles, and tool results are stored locally (`.memory/`, `targets/`, `logs/`). The system only requires internet connectivity for LLM API calls and outbound scan traffic. |

**2.3 Required Capabilities**

To address the operational problem within the stated constraints, the system requires the capabilities enumerated in Table 2.2.

**Table 2.2: Required System Capabilities**

| Capability | Implementation Module | Description |
|------------|-----------------------|-------------|
| Natural-Language Task Routing | `orchestrator_agent.py` (76,208 bytes) | The Orchestrator LLM reads user input, classifies intent, and delegates to the appropriate specialist agent. |
| Specialist Agent Delegation | `src/agents/` (14 non-init agent modules) | Orchestrator plus specialist modules for Recon, WebSec, CTF, DFIR, RedTeam, AppSec, BugBounty, BlackHat, Adversarial, ExploitCraft, Verifier, Reporter, and specialty aggregation. |
| Shared Discovery Propagation | `agent_graph.py` + `DiscoveryBus` | Nine typed discovery categories (VULNERABILITY, SERVICE, CREDENTIAL, ENDPOINT, SUBDOMAIN, FILE, CONFIGURATION, EXPLOIT_SUCCESS, ATTACK_PATH) shared in real-time between agents. |
| Persistent Memory | `memory.py` (47,771 bytes) | ChromaDB vector embeddings with all-mpnet-base-v2 sentence-transformer for semantic search, plus JSON fallback for environments without ChromaDB. |
| Attack Planning | `attack_planner.py` (84,398 bytes) | Vulnerability-to-exploit mapping (`VULN_EXPLOIT_MAP`), multi-phase attack plan generation, approval workflow, and exploit chain computation. |
| Failure Recovery | `recovery.py` (19,023 bytes) | Error categorization (TIMEOUT, CONNECTION_ERROR, TOOL_NOT_FOUND, RATE_LIMITED, BLOCKED), alternative tool suggestions via `TOOL_ALTERNATIVES` map, parameter adjustment, and evasion. |
| Report Generation | `report_generator.py` (64,201 bytes) | Markdown and PDF reports with fpdf2, severity distribution charts via matplotlib, executive summaries, and MITRE ATT&CK alignment. |
| Loop Detection | `loop_detector.py` (22,158 bytes) | Detects when an agent is repeating the same tool calls or making no progress, and intervenes with feedback injection or early termination. |
| Context Window Management | `runner.py` — `Conversation.trim_to_fit()` | Two-phase context trimming: first truncates old tool results, then drops middle messages while preserving a summary of dropped tool interactions. |

**2.4 Scope of the Proposed System**

Cyber-CoPilot focuses on the engagement phases that can be reasonably automated without removing analyst judgment:

- **Reconnaissance**: Port scanning, subdomain enumeration, DNS resolution, technology fingerprinting, OSINT, ASN discovery, JS analysis, passive recon chains.
- **Content Discovery**: Directory brute-forcing, parameter discovery, URL harvesting, web spidering, API endpoint identification.
- **Vulnerability Testing**: Template-based scanning (Nuclei), SQL injection (SQLMap), XSS detection (XSStrike, Dalfox), SSTI (Tplmap), command injection (Commix), JWT attacks, deserialization testing, HTTP smuggling, SSRF, and IDOR checks.
- **Attack Planning**: AI-generated multi-phase attack plans with risk assessment, operator review, and approval-gated execution.
- **Limited Exploitation Support**: Metasploit module execution, credential brute-forcing (Hydra), hash cracking (John, Hashcat), reverse shell generation (15+ languages), Active Directory attacks (Kerberoasting, PetitPotam, Zerologon).
- **Report Generation**: Markdown and PDF output with severity distribution charts, finding tables, and executive summaries.

The system **does not** replace the human operator. It supports the operator by presenting discoveries, summarizing risk, preserving context across sessions, and generating reports. All exploitation decisions require explicit human approval. The framework is therefore best understood as an **orchestration layer** above existing security tooling—not as an autonomous exploit engine.

Figure 2.1 illustrates the data flow through the system from user input to final report output.

![Figure 2.1: Data Flow Diagram — Task Execution Pipeline](FYP-Report/media/fig2_data_flow.png)

**Figure 2.1: Data Flow Diagram — Task Execution Pipeline**

------------------------------------------------------------------------

**CHAPTER 3: LITERATURE REVIEW**

**3.1 Traditional Security Toolchains**

Modern penetration testing relies on a mature ecosystem of open-source and commercial tools, each optimized for a specific phase of the engagement lifecycle. The MITRE ATT&CK framework (Strom et al., 2018) defines 14 tactical categories ranging from Reconnaissance to Impact, and the security community has developed specialized utilities for most of these categories.

For **reconnaissance**, Nmap (Lyon, 2009) remains the de facto standard for port scanning and service detection, supporting over 50 NSE scripts for vulnerability probing. Subfinder (ProjectDiscovery, 2020) and Amass (OWASP, 2019) handle passive subdomain enumeration by querying certificate transparency logs, DNS datasets, and search engine APIs. DNSRecon provides zone transfer testing and DNS record brute-forcing.

For **web application testing**, Gobuster and Feroxbuster perform directory/file brute-forcing, while Nikto scans for web server misconfigurations. SQLMap (Stampar & Damele, 2009) automates SQL injection detection and exploitation across 6 injection techniques. Nuclei (ProjectDiscovery, 2021) implements a template-based scanning model with over 9,000 community-contributed templates covering CVEs, misconfigurations, and exposures. XSStrike (Somdev Sangwan, 2018) and Dalfox provide advanced XSS detection with context-aware payload generation.

For **exploitation**, the Metasploit Framework (Rapid7, 2003) offers over 2,200 exploit modules, integration with post-exploitation tools like Meterpreter, and a fully scriptable resource file system. Hydra (van Hauser, 2001) supports credential brute-forcing across 50+ protocols.

For **Active Directory attacks**, Impacket (Fortra, 2000) provides Python implementations of network protocols (SMB, LDAP, Kerberos) used for lateral movement and credential extraction. BloodHound (Robbins et al., 2016) maps AD trust relationships to identify attack paths to domain admin.

These tools are individually powerful, but they operate in **isolation**. Each expects the operator to manually configure inputs, interpret outputs, and bridge information between tools. This tool-centric model is effective for experienced operators but creates three key challenges:

1. **Continuity Gap**: Evidence, outputs, and next steps live in separate terminal sessions.
2. **Repetition Risk**: In multi-day engagements, analysts may rediscover information they already found in a prior session.
3. **Reporting Burden**: Translating raw tool output into structured findings requires significant manual effort.

**Table 3.1: Comparison of Traditional Security Tools**

| Tool | Category | Strengths | Limitations |
|------|----------|-----------|-------------|
| Nmap | Reconnaissance | Comprehensive port/service detection, scriptable (NSE) | No cross-tool context sharing, text output requires manual parsing |
| Subfinder | Subdomain Enum | Fast, passive, multi-source | Results must be manually fed to subsequent tools |
| SQLMap | Web Testing | Automated SQLi across 6 techniques, database dump | Single-vulnerability focus, no persistent session state |
| Nuclei | Vuln Scanning | 9,000+ templates, fast, YAML-configurable | No built-in attack planning or exploit chaining |
| Metasploit | Exploitation | 2,200+ exploits, post-exploitation modules | Requires manual target/vuln configuration |
| Hydra | Credential Access | 50+ protocol support | Brute-force only, no context from prior recon |

**3.2 AI-Assisted Security Automation**

The emergence of Large Language Models (LLMs)—particularly GPT-4 (OpenAI, 2023), Claude (Anthropic, 2023), and open-source models like Llama (Meta, 2023) and Mistral (Mistral AI, 2023)—has opened new possibilities for security automation. Several research efforts and commercial products have explored this space:

**PentestGPT** (Deng et al., 2023) demonstrated that LLMs can provide interactive guidance during penetration tests by maintaining a conversation history and suggesting next steps. However, PentestGPT operates as an advisory chatbot—it recommends commands but does not execute them. It has no persistent memory, no tool integration, and no cross-session state.

**AutoPentest** frameworks combine LLM reasoning with tool execution. These typically wrap individual tools in function calls that an LLM can invoke. While effective for single-step automation, most implementations lack multi-agent collaboration, shared discovery propagation, and failure recovery.

**ReAct (Reasoning + Acting)** (Yao et al., 2023) introduced a paradigm where an LLM alternates between reasoning about the task and acting by calling external tools. This loop continues until the task is complete. The ReAct pattern is now widely adopted in agentic AI systems and forms the core execution model of Cyber-CoPilot's Runner (`src/sdk/runner.py`, 1,692 lines).

**Agent Frameworks** such as LangChain (Harrison Chase, 2022), AutoGen (Microsoft, 2023), and CrewAI (João Moura, 2024) provide general-purpose multi-agent orchestration. These frameworks support tool calling, conversation memory, and agent handoffs. However, they are not specialized for security: they do not include vulnerability-to-exploit mappings, target profile persistence, scope enforcement, or security-specific output parsing.

**RedAmon** (Samughetti, 2024) represents a more security-focused approach: a containerized offensive framework with a Neo4j graph database for attack surface modeling and a Next.js web UI. RedAmon implements a multi-phase automated recon pipeline and per-phase tool restriction matrices. However, it requires Docker infrastructure, uses a web-based interface rather than a terminal-native one, and does not implement semantic memory for cross-session intelligence retrieval.

**Table 3.2: AI-Assisted Security Platforms**

| Platform | LLM Integration | Tool Execution | Persistent Memory | Multi-Agent | Failure Recovery |
|----------|----------------|----------------|-------------------|-------------|-----------------|
| PentestGPT | Advisory only | No | No | No | No |
| AutoPentest variants | Function calling | Basic | No | No | No |
| LangChain/AutoGen | General-purpose | Yes | Optional | Yes | No |
| RedAmon | Task orchestration | Yes | Neo4j graph | Partial | No |
| **Cyber-CoPilot** | **ReAct loop** | **Yes (60+ tools)** | **ChromaDB + JSON** | **Yes (10 agents)** | **Yes** |

**3.3 Multi-Agent and Memory-Based Systems**

Multi-agent systems address the limitations of single-agent designs by splitting work into specialist roles. In the context of security testing, this translates naturally:

- A **Reconnaissance Agent** handles network scanning and passive intelligence gathering.
- A **Web Security Agent** focuses on application-layer vulnerabilities.
- A **Red Team Agent** manages post-exploitation and lateral movement.
- A **Reporter Agent** transforms findings into deliverable reports.

Cyber-CoPilot extends this model with two critical additions that are absent from most existing multi-agent security frameworks:

**Shared Discovery Bus (DiscoveryBus)**: When any agent discovers new information (a vulnerability, an open port, a credential), it publishes a typed `Discovery` object to the DiscoveryBus. Other agents that have subscribed to the relevant discovery type are automatically notified. This removes the need for the analyst to manually copy findings between agents. Table 3.4 lists the nine discovery types supported.

**Table 3.4: Discovery Types in the DiscoveryBus**

| Discovery Type | Description | Example |
|----------------|-------------|---------|
| VULNERABILITY | A security finding with severity, CVE, and description | CVE-2024-37489 SSRF in file upload |
| SERVICE | An open port and running service | 443/tcp open nginx 1.22.1 |
| CREDENTIAL | Discovered username, password, or hash | admin:P@ssw0rd! |
| ENDPOINT | A live HTTP endpoint or API route | /api/v1/admin/users |
| SUBDOMAIN | A discovered subdomain | staging.example.com |
| FILE | A sensitive file or directory listing | /backup/db_dump.sql |
| CONFIGURATION | A misconfiguration finding | Directory listing enabled on /uploads/ |
| EXPLOIT_SUCCESS | A successful exploitation event | Meterpreter session opened |
| ATTACK_PATH | A complete viable attack chain | SQLi → credential dump → SSH login → privesc |

**Persistent Semantic Memory**: Most agent frameworks treat each session as isolated. Cyber-CoPilot's `VectorMemory` class (`src/sdk/memory.py`, 1,167 lines) stores every tool result, vulnerability, credential, and operator note in ChromaDB with semantic embeddings using the `all-mpnet-base-v2` sentence-transformer model. This enables:

1. **Cross-Session Retrieval**: Before any agent runs, the system queries memory for prior findings related to the current target, injecting them as context.
2. **Fuzzy Search**: The analyst can type `memory SQL injection vulnerabilities` to retrieve semantically similar entries from any previous session—even if the exact wording differs.
3. **Document Chunking**: Long tool outputs are split into 800-character overlapping chunks (150-character overlap) for higher-quality per-chunk embeddings.
4. **Deduplication**: Content hashing prevents identical outputs from being re-indexed.
5. **Recency-Weighted Reranking**: Search results are blended with a recency score (decaying over 7 days) to prioritize recent findings.
6. **HyDE (Hypothetical Document Embedding)**: Short security queries like "sqli" are expanded into rich hypothetical documents before embedding, dramatically improving recall.

Figure 3.1 shows the interaction sequence between system components during a typical two-phase assessment session.

![Figure 3.1: Agent Interaction Sequence Diagram](FYP-Report/media/fig3_agent_interaction.png)

**Figure 3.1: Agent Interaction Sequence Diagram**

The ReAct execution model used by the Runner is illustrated in Figure 3.2.

```
                    ┌─────────────────────────┐
                    │      User Task Input    │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   LLM Reasoning Step    │
                    │ "What should I do next?"│
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Tool Selection &     │
                    │    Function Call        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Tool Execution       │
                    │  (subprocess / API call)│
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Result Processing &    │
                    │  Finding Extraction     │
                    │ (regex + pattern match) │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Context Hub Update     │
                    │  (ports, vulns, creds)  │
                    └────────────┬────────────┘
                                 │
                         ┌───────▼───────┐
                         │ Task Complete?│
                         └───┬───────┬───┘
                         Yes │       │ No
                    ┌────────▼──┐ ┌──▼────────────┐
                    │  Return   │ │ Loop back to  │
                    │  Result   │ │ LLM Reasoning │
                    └───────────┘ └───────────────┘
```

**Figure 3.2: ReAct Loop Execution Model**

**3.4 Comparison of Existing Approaches**

Table 3.3 provides a comprehensive comparison of Cyber-CoPilot against existing approaches across key dimensions.

**Table 3.3: Comparison of Cyber-CoPilot with Existing Approaches**

| Feature | Manual Toolchain | PentestGPT | LangChain Agents | RedAmon | **Cyber-CoPilot** |
|---------|-----------------|------------|-------------------|---------|-------------------|
| Natural-Language Input | ✗ | ✓ | ✓ | Partial | **✓** |
| Tool Execution | Manual | ✗ (advisory) | General-purpose | ✓ | **✓ (60+ security tools)** |
| Multi-Agent Delegation | ✗ | ✗ | ✓ (generic) | Partial | **✓ (10 specialist agents)** |
| Discovery Sharing | ✗ | ✗ | ✗ | Graph DB | **DiscoveryBus (9 types)** |
| Persistent Memory | ✗ | ✗ | Optional | Neo4j | **ChromaDB + JSON fallback** |
| Semantic Search | ✗ | ✗ | RAG add-on | Cypher queries | **HyDE + mpnet-base-v2** |
| Attack Planning | Manual | Advisory | ✗ | ✗ | **AI-generated + approval gate** |
| Failure Recovery | Manual | ✗ | ✗ | ✗ | **7-strategy engine** |
| Scope Enforcement | Manual | ✗ | ✗ | ✗ | **Automated scope module** |
| Report Generation | Manual | ✗ | ✗ | Basic | **PDF + Markdown + charts** |
| Loop Detection | ✗ | ✗ | ✗ | ✗ | **Anti-loop + supervisor** |
| Terminal-Native | ✓ | ✓ | ✗ (API/code) | ✗ (Web UI) | **✓ (Rich TUI)** |

**3.5 Research Gap and Project Contribution**

The literature review reveals a clear gap between isolated security tools and a fully integrated workflow that combines:

1. **Reasoning and Execution**: Most AI-assisted tools either advise (PentestGPT) or provide generic agent frameworks (LangChain) without security-specific semantics.
2. **Persistent Intelligence**: Few systems maintain a semantic memory that accumulates across sessions and enables fuzzy retrieval of prior findings.
3. **Inter-Agent Communication**: General-purpose multi-agent frameworks lack a security-specific discovery taxonomy (ports, vulnerabilities, credentials) and a typed message bus for real-time sharing.
4. **Failure Resilience**: No reviewed system implements a structured failure recovery engine with error categorization, alternative tool mapping, parameter adjustment, and evasion support.
5. **Human Authority**: Many automation approaches treat the operator as optional. Security testing requires human judgment for scoping, authorization, and exploitation decisions.

Cyber-CoPilot contributes by combining these five capabilities in a single, terminal-native framework:

- A **ReAct execution engine** with supervisor feedback, loop detection, and context window management.
- A **hierarchical multi-agent architecture** with 10 specialist agents and a typed DiscoveryBus.
- A **ChromaDB-backed semantic memory** with HyDE query expansion, document chunking, deduplication, and recency reranking.
- A **validation-first attack planner** with vulnerability-to-exploit mapping, exploit chain computation, and an operator approval gate.
- A **seven-strategy failure recovery engine** that adapts to timeouts, rate limiting, missing tools, WAF blocking, and empty results.
- A **professional reporting pipeline** that produces PDF and Markdown deliverables from accumulated findings.

This combination makes the framework useful not only as a penetration testing assistant, but also as a **reference design for human-in-the-loop agentic security automation** — a concrete implementation of how LLM orchestration, shared state, and deterministic recovery logic can coexist in one system.

------------------------------------------------------------------------

**CHAPTER 4: SOFTWARE REQUIREMENT SPECIFICATION**

**4.1 Functional Requirements**

The functional requirements define the explicit capabilities the Cyber-CoPilot framework must execute during an assessment.
1. **Target Normalization and Scoping:** The framework must accurately resolve, normalize, and enforce strict scope boundaries on user-provided targets (URLs, IPs, ASNs) to prevent unauthorized out-of-scope testing.
2. **Multi-Agent Orchestration:** The system must utilize an Orchestrator agent to classify user intents and delegate execution to specialist agents such as Recon, WebSec, RedTeam, AppSec, BugBounty, DFIR, CTF, ExploitCraft, Verifier, and Reporter.
3. **Automated Tool Execution:** The system must expose a broad security capability layer through registered tool functions. The current source audit identified 583 `@function_tool` registrations across agent, SDK, and tool modules, including wrappers around external binaries such as Nmap, Nuclei, SQLMap, Metasploit, Hydra, Playwright/Selenium, and custom AppSec scanners.
4. **Failure Recovery and Loop Detection:** The core runner must automatically detect execution loops, hallucinated arguments, or connection failures, and apply recovery strategies (e.g., adjusting parameters, switching payloads, or pausing execution).
5. **Persistent Memory Management:** The platform must maintain state across sessions using a ChromaDB vector database, enabling agents to query previous findings contextually before executing duplicate tests.
6. **Reporting Automation:** Following the conclusion of tasks, the reporter agent must synthesize actionable intelligence and generate a professional, structured PDF and Markdown report containing executive summaries, vulnerability vectors, and remediation steps.
7. **Bug Bounty Scope Import:** The system must import target scope from public program pages, filter platform/noise domains, persist imported targets into local scope, and append an auditable authorization record under `targets/AUTHORIZED_TARGETS.md`.
8. **Evidence-First Finding Lifecycle:** The system must track candidate findings, evidence hashes, validation status, and scope source before promoting findings into reports.

**4.2 Non-Functional Requirements**

1. **Performance and Asynchronous Execution:** Tool wrappers must run asynchronously to ensure that long-running operations (like exhaustive directory fuzzing or vulnerability scanning) do not block the main ReAct loop.
2. **Security and Sandboxing:** Given the nature of offensive tooling, the framework must execute external binaries safely, normalize targets before command construction, redact sensitive output through guardrails, and prevent command injection into the host OS.
3. **Usability:** The interface must be a terminal-native, Rich-based TUI (Terminal User Interface) that provides real-time streaming of LLM thoughts, tool outputs, progress, recovery suggestions, and system errors in a clean, developer-friendly layout.
4. **Extensibility:** The tool wrappers and agent prompts must be modularly structured to allow straightforward integration of novel exploits and third-party binaries as the threat landscape evolves.
5. **Auditability:** The framework must preserve tool calls, session transcripts, target profiles, evidence records, and generated reports in local project folders so an operator can reconstruct the sequence of actions after an engagement.

**4.3 System Constraints**

1. **LLM API Dependence:** The operational integrity heavily relies on the availability and reasoning fidelity of upstream LLM providers. The live implementation supports OpenAI-compatible providers through the key manager, including OpenAI, OpenRouter, LongCat, NVIDIA, and ModelScope-style configurations.
2. **Environmental Limits:** Some network tools are bounded by rate limiting, local firewall configurations, and intrusion prevention systems (IPS) which can cause artificial packet drops during active scanning.
3. **Host Tool Availability:** Many capabilities wrap external security binaries. If a binary such as Nmap, Nuclei, SQLMap, Hydra, or Playwright browser dependencies is missing, the tool checker and recovery modules can warn or suggest alternatives, but the scan result still depends on the local host environment.

**4.4 Use Cases**

The use cases define the various workflows a Security Analyst can initiate within the framework. As depicted in Figure 4.1, the analyst interacts with the main system which relies on external LLM services and a local tool layer.

![Use Case Diagram](FYP-Report/media/fig4_use_case_diagram.png)
*Figure 4.1: Cyber-CoPilot Use Case Diagram*

------------------------------------------------------------------------

**CHAPTER 5: METHODOLOGY**

**5.1 Approach**

The architecture of Cyber-CoPilot utilizes a multi-layered ReAct (Reasoning and Acting) execution strategy combined with a multi-agent delegation system. Instead of relying on a monolithic script, the system models the decision-making process of human penetration testers. This approach isolates capabilities into context-specific agents. When an assessment begins, the Orchestrator evaluates the user input, formulates a strategy array, and sequentially delegates tasks to the relevant specialized agents.

**5.2 Tools and Software**

The framework is developed in Python to leverage existing ecosystem support for automation, asynchronous I/O, security tooling, and machine learning.
- **Language:** Python 3.10+
- **Core Libraries:** `openai` for OpenAI-compatible LLM access, `rich` and `prompt_toolkit` for the terminal interface, `loguru` for logging, `requests`, `aiohttp`, and `httpx[http2]` for HTTP workflows, and `pydantic` for structured data support.
- **Memory and Intelligence:** `chromadb`, `sentence-transformers`, and JSON fallbacks for semantic memory and cross-session retrieval.
- **Reporting and Evidence:** `fpdf2`, `matplotlib`, `Pillow`, and `xhtml2pdf` for Markdown/PDF/HTML reporting, charts, screenshots, and evidence presentation.
- **Browser and Dynamic Testing:** `playwright`, `selenium`, and `webdriver-manager` for DOM-aware validation, authenticated flows, screenshots, and browser-backed probes.
- **Backend Security Tools:** Nmap, Nuclei, SQLMap, Metasploit, Hydra, Gobuster, FFUF, Wfuzz, Subfinder, Amass, Shodan/Censys-style passive intelligence, Playwright/Selenium, and target-specific exploit or validation scripts.

**5.3 System Architecture**

Cyber-CoPilot uses a component-based architecture organized into Presentation, Application, SDK Core, and Storage Data layers. This segmentation ensures robust isolation of the terminal UI from the underlying complex asynchronous multi-agent orchestrations.

![Component Architecture Diagram](FYP-Report/media/fig7_component_diagram.png)
*Figure 5.2: System Component Architecture Diagram*

**5.4 Internal Design & SDK Core**

The src/sdk/ directory maintains the core operational logic that bridges the LLM outputs with raw OS processes.
- **Runner Loop (`runner.py`):** Operates the primary loop that parses the LLM's designated tool calls, invokes the mapped Python functions, trims context safely, injects active target metadata, persists conversation history, and feeds the outputs back to the context window.
- **Context Hub (context_hub.py):** Acts as an intermediary data store for an active session. It maintains dictionaries of open ports, identified subdomains, and web technology stacks.
- **Loop Detector (loop_detector.py):** Calculates structural similarity between iterative LLM outputs. If the threshold is exceeded, it forcefully injects a corrective prompt, preventing circular hallucinations.
- **Scope Manager and Importer (`scope.py`, `scope_importer.py`):** Normalize URLs, domains, IPs, and wildcard entries; enforce in-scope/out-of-scope boundaries; import public bug bounty scope pages; and save imported authorization records.
- **Finding Lifecycle and Evidence (`finding_lifecycle.py`, `evidence.py`, `report_bundle.py`):** Move findings from candidate state to validated evidence-backed records before reporting.
- **HTTP Knowledge and App Mapping (`http_knowledge.py`, `app_mapping.py`):** Preserve HTTP observations, authenticated comparisons, workflow states, authorization checks, GraphQL schema findings, and attack-path hints.
- **Provider and Model Control (`key_manager.py`, `model_settings.py`, `llm.py`):** Select the active provider/model, rotate keys after failures, expose runtime identity to the agent, and keep provider-specific options outside agent prompts.

![Class Diagram](FYP-Report/media/fig5_class_diagram.png)
*Figure 5.1: Code SDK Core Class Diagram*

------------------------------------------------------------------------

**CHAPTER 6: IMPLEMENTATION AND TESTING**

**6.1 Technical Implementation**

The technical implementation is split between abstract reasoning wrappers and literal tool implementations. When an agent decides to Run Reconnaissance, it selects the specific tool wrapper. The SDK layer sanitizes the target address, constructs the OS-level subprocess, pipes standard output, filters false positives using Regex matchers in `fp_filter.py`, and returns a structured JSON summary to the LLM.
The memory architecture utilizes ChromaDB configured with sentence transformers to generate embeddings for all significant intelligence. This creates a persistent RAG (Retrieval-Augmented Generation) pipeline that empowers the agents to refer back to historical exploit chains.

The live repository separates this implementation into several layers. `main.py` loads environment variables, configures Loguru, initializes sudo support for privileged network tools on Unix-like hosts, and starts `src.repl.loop`. The REPL layer handles commands, target state, scope commands, graph commands, report export, task status, memory search, proxy controls, and mode toggles. The agent layer provides role-specific instructions and curated tool sets. The SDK layer handles conversation persistence, context trimming, scope enforcement, failure recovery, evidence capture, attack planning, cache control, and model provider fallback. The tool layer implements the largest surface area, with 90 tool modules under `src/tools/` and `src/tools/appsec/`.

The `scope_importer.py` module fills an important authorization gap. It fetches a bug bounty program URL, strips HTML, extracts candidate domains and wildcards, filters platform/noise/static asset domains, optionally constrains results to a root domain hint, adds imported targets through `ScopeManager.add_scope()`, and appends a timestamped record to `targets/AUTHORIZED_TARGETS.md`. Unit tests verify both hint-constrained extraction and platform-noise filtering.

**6.2 Multi-Agent Execution**

Figure 6.1 illustrates the discrete execution states of the framework. A session transitions fluidly from an IDLE state towards REASONING and EXECUTING. Crucially, an explicit RECOVERING state is engaged when an operation fails, allowing the AI to debug its own methodologies dynamically.

![State Machine Diagram](FYP-Report/media/fig8_state_machine.png)
*Figure 6.1: Agent Execution State Machine*

**6.3 Testing Methodologies**

The framework was tested on several controlled web environments and Capture the Flag (CTF) platforms. The methodology assessed:
- **Accuracy:** The ratio of true positive vulnerabilities found to false positives generated.
- **Stability:** The framework's ability to survive unexpected network drops without crashing, handled gracefully by the error recovery system.
- **Efficiency:** The token usage cost per session and optimization of API limits.

The automated test suite currently contains 25 Python test files and 1,242 non-blank test lines. Coverage is strongest in the intelligence package, runner hardening, scope import extraction, authentication context handling, Nuclei wrapper behavior, app-mapping/authorization helpers, WordPress XML-RPC auditing, knowledge import deduplication, Active Directory wrapper hardening, and focused AppSec probes for SQL injection, XSS, SSRF, path traversal, security headers, and orchestrated AppSec pipelines.

**6.4 Codebase Audit and Coverage Findings**

An AST-based source audit was performed across `main.py`, `src/`, `tests/`, `scripts/`, and `data/exploits/`, excluding generated caches and `__pycache__` files. All 223 Python files parsed successfully with zero syntax errors.

| Area | Files | Non-Blank Lines | Classes | Functions | Registered Tools |
|------|------:|----------------:|--------:|----------:|-----------------:|
| `src/agents` | 15 | 5,479 | 0 | 60 | 21 |
| `src/sdk` | 46 | 19,203 | 120 | 724 | 12 |
| `src/tools` | 90 | 46,391 | 17 | 907 | 550 |
| `src/tools/appsec` subset | 18 | 4,836 | 1 | 72 | 20 |
| `src/repl` | 17 | 5,715 | 21 | 174 | 0 |
| `src/intelligence` | 5 | 284 | 7 | 14 | 0 |
| `tests` | 25 | 1,242 | 3 | 111 | 0 |

The largest implementation modules are `src/tools/recon_active.py`, `src/repl/loop.py`, `src/tools/recon_passive.py`, `src/sdk/runner.py`, `src/tools/web.py`, `src/tools/browser_automation.py`, `src/tools/exploit_craft.py`, `src/tools/forensics.py`, `src/sdk/context_hub.py`, and `src/tools/appsec/orchestrator.py`. These files form the practical center of the application because they handle active scanning, terminal workflows, passive recon, ReAct execution, web testing, browser validation, exploit generation, artifact analysis, shared context, and AppSec orchestration.

The audit also identified areas where the written report was previously incomplete: API/server support in `src/api/server.py`, scope import, finding lifecycle management, HTTP knowledge persistence, app mapping, evidence bundles, model/provider fallback, generated exploit samples under `data/exploits/`, and the distinction between live source code and generated runtime artifacts under `targets/`, `reports/`, `logs/`, `output/`, screenshots, and Graphify cache folders.

------------------------------------------------------------------------

**CHAPTER 7: RESULTS AND DISCUSSION**

**7.1 Real-World Execution Results**

Experimental deployments of the Cyber-CoPilot on challenging Capture The Flag targets revealed significant capability improvements compared to baseline LLM interfaces. The framework proved capable of chaining multi-step exploits. For example, during testing, the agent accurately identified anomalous JWT signature algorithms, automatically generated the corresponding JWKS forge scripts, and retrieved administrative flags without human intervention.

**7.2 Vulnerability Detection Efficacy**

The framework supports a large security capability surface mapped across MITRE ATT&CK tactics. The current audit found 550 registered tools in `src/tools/`, 20 of them in the focused `src/tools/appsec/` package, plus additional SDK and agent-level tools for reporting, evasion, exploit matching, and delegation.

![MITRE Coverage](FYP-Report/media/fig6_mitre_coverage.png)
*Figure 7.1: Tool Coverage by MITRE ATT&CK Tactic*

**7.3 Discussion and Recovery Outcomes**

One of the most notable successes of the implementation is the loop detection and recovery system. During testing on highly firewalled targets, connection timeouts traditionally cause AI agents to crash or hallucinate successes. Cyber-CoPilot successfully detected connection blocks, recorded the failure securely, and pivoted its strategy (e.g., switching from raw HTTP requests to full Playwright headless browser impersonation) to bypass basic protections.

**7.4 Limitations**

Despite successes, limitations remain:
1. **Token Cost:** Deep reconnaissance requires passing substantial raw output back into the context window, resulting in high LLM context usage and cost.
2. **Context Fragmentation:** If target scope grows excessively large, the LLM may experience attention decay, occasionally forgetting minor details discovered at the beginning of an engagement.
3. **External Tool Dependence:** Many high-value capabilities require host-installed binaries and browser dependencies. Missing tools reduce coverage even when the Python wrapper is present.
4. **Selective Automated Test Coverage:** The current tests cover important SDK, intelligence, appsec, and tool-wrapper behavior, but the largest operational modules such as `recon_active.py`, `recon_passive.py`, `web.py`, `browser_automation.py`, and the full REPL command loop need broader regression coverage.
5. **Generated Artifact Noise:** Runtime folders such as `targets/`, `reports/`, `logs/`, screenshots, and Graphify caches are useful for evidence and traceability, but they can obscure source-code review unless separated from the live implementation tree.

------------------------------------------------------------------------

**CHAPTER 8: CONCLUSION AND FUTURE WORK**

**8.1 Summary**

This project successfully developed Cyber-CoPilot, an innovative, multi-agent AI framework for offensive security testing. By integrating Large Language Models with 583 registered security-oriented tool functions and a large set of external penetration testing utilities, the project demonstrated that it is possible to bridge the gap between unstructured reasoning and deterministic tasks.

**8.2 Core Contributions**

The main contributions of this work are:
1. An extensible ReAct runner pipeline specifically engineered for offensive security tasks.
2. A semantic persistence layer that enables AI continuity across fragmented sessions.
3. An advanced resilience module containing anti-hallucination loops, scope protection, and dynamic failure recovery.
4. A scope import and authorization record workflow for bug bounty programs.
5. An evidence-first finding lifecycle that improves report reliability and reduces false-positive promotion.

**8.3 Future Directions**

Planned extensions for the Cyber-CoPilot framework include:
- **Web UI Integration:** Migrating from the terminal into an interactive, React-based web dashboard.
- **Local Model Optimization:** Further fine-tuning instructions to reliably support open-source local models.
- **Collaborative Swarm Mode:** Extending the DiscoveryBus to allow multiple independent instances to collaborate on a target.
- **Coverage Expansion:** Add regression tests for the largest tool modules, REPL command branches, provider fallback paths, report generation, and evidence lifecycle transitions.
- **Documentation Hygiene:** Keep the report, README, and codebase map synchronized with live module counts, generated artifact locations, and new subsystems such as scope import and finding lifecycle management.
- **Packaging and Environment Reproducibility:** Provide a Docker or installer profile that bundles common security binaries, browser drivers, and Python dependencies so scans behave consistently across machines.


