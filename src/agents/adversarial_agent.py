"""
Adversarial Thinking Agent (OpSec / Blue-Team Mirror)

This agent thinks from the DEFENDER's perspective:
  • What WAF/IDS/EDR signatures does this attack trigger?
  • What SIEM alerts would fire at this moment?
  • What logs are being written and where?
  • How would a SOC analyst track the attacker?
  • Where are the detection gaps — which attack vectors fly blind?

It is used in two modes:
  1. Pre-attack advisor — before running an exploit, predict detection risk
  2. Post-attack evasion refiner — given a known attack, rewrite it to reduce
     signature footprint, rotate/spoof indicators, and blend into baseline traffic

Typical invocation from orchestrator:
  "make this attack stealthy" / "what would a SOC see?" / "evade the WAF" /
  "opsec analysis" / "detection risk" / "blue team perspective"
"""

from __future__ import annotations

from src.sdk.agent import Agent
from src.sdk.tool import function_tool
from src.sdk.model_settings import get_model_settings

# ── Tools this agent uses directly ──────────────────────────────────────────
from src.tools.ai_intelligence import smart_payload_generator
from src.tools.exploit_craft   import obfuscate_payload
from src.tools.anonsurf_manager import manage_anonsurf
from src.tools.edr_evasion import generate_syscall_loader, patch_amsi_etw, generate_process_hollow

import json
import re
import textwrap


# ════════════════════════════════════════════════════════════════════════════
# OpSec tools
# ════════════════════════════════════════════════════════════════════════════

@function_tool()
def detection_risk_analysis(
    attack_description: str,
    target_tech: str = "",
    waf_product: str = "",
    ids_product: str = "",
    siem_product: str = "",
) -> str:
    """
    Analyse how likely a given attack is to be detected by WAF/IDS/SIEM.
    Returns a risk score (0–10), triggered signatures, and log artefacts.

    Args:
        attack_description: Free-text description of the attack (payload, technique, tool)
        target_tech: Target technology stack e.g. "Apache 2.4 + ModSecurity"
        waf_product: WAF in use e.g. "Cloudflare", "ModSecurity", "AWS WAF", "Akamai"
        ids_product: IDS/IPS in use e.g. "Snort", "Suricata", "CrowdStrike Falcon"
        siem_product: SIEM in use e.g. "Splunk", "ELK", "Microsoft Sentinel"

    Returns:
        Detection risk report with scores and evasion recommendations
    """
    try:
        from openai import OpenAI
        settings = get_model_settings()
        client = OpenAI(base_url=settings.base_url, api_key=settings.api_key)

        prompt = textwrap.dedent(f"""\
            You are a senior blue-team analyst and threat hunter.

            An attacker plans to execute the following attack:
            {attack_description}

            Environment:
            - Target tech : {target_tech or 'unknown'}
            - WAF         : {waf_product or 'unknown/assume ModSecurity CRS'}
            - IDS/EDR     : {ids_product or 'unknown/assume Suricata'}
            - SIEM        : {siem_product or 'unknown/assume ELK'}

            Provide a structured JSON analysis (no prose outside JSON):
            {{
                "overall_risk_score": 0-10,
                "detectable_by_waf": true/false,
                "detectable_by_ids": true/false,
                "detectable_by_siem": true/false,
                "triggered_signatures": [
                    {{"product": "ModSecurity", "rule_id": "...", "description": "..."}}
                ],
                "log_artefacts": [
                    {{"log_source": "Apache access.log", "pattern": "what the log entry looks like"}}
                ],
                "ioc_indicators": ["source IP in requests", "user-agent pattern", "timing pattern"],
                "detection_gaps": ["blind spots — what stays invisible"],
                "evasion_recommendations": [
                    {{"technique": "...", "rationale": "...", "implementation": "..."}}
                ],
                "opsec_rating": "NOISY / MODERATE / STEALTHY / SILENT"
            }}
        """)

        resp = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=2000,
        )
        raw = resp.choices[0].message.content or "{}"
        jm = re.search(r"\{.*\}", raw, re.DOTALL)
        data = {}
        if jm:
            try:
                data = json.loads(jm.group())
            except json.JSONDecodeError:
                data = {"raw": raw}

        score = data.get("overall_risk_score", "?")
        rating = data.get("opsec_rating", "UNKNOWN")

        header = textwrap.dedent(f"""\
            ╔══════════════════════════════════════════════════════════════╗
            ║              ADVERSARIAL DETECTION RISK ANALYSIS             ║
            ╚══════════════════════════════════════════════════════════════╝
            Detection Score : {score}/10
            OpSec Rating    : {rating}
            ──────────────────────────────────────────────────────────────
        """)
        return header + json.dumps(data, indent=2)

    except Exception as e:
        return f"[detection_risk_analysis] Error: {e}"


@function_tool()
def stealth_rewrite(
    original_payload: str,
    attack_type: str,
    target_waf: str = "ModSecurity",
    stealth_profile: str = "low-and-slow",
) -> str:
    """
    Rewrite an attack payload / technique to minimise its detection footprint.

    Applies layered evasion: timing, encoding, traffic blending, header spoofing,
    decoy request injection, and technique switching.

    Args:
        original_payload: The raw attack payload or technique description
        attack_type: sqli | rce | xss | ssrf | lfi | brute_force | portscan | c2
        target_waf: WAF to bypass e.g. Cloudflare | ModSecurity | AWS WAF | Akamai
        stealth_profile: low-and-slow | mimicry | fragmented | out-of-band | tunnelled

    Returns:
        Stealthy rewritten payload and implementation notes
    """
    try:
        from openai import OpenAI
        settings = get_model_settings()
        client = OpenAI(base_url=settings.base_url, api_key=settings.api_key)

        profiles = {
            "low-and-slow": "Space requests over minutes/hours to evade rate-limiting and anomaly thresholds",
            "mimicry": "Make traffic look identical to legitimate user behaviour — matching timing, headers, referrers, session patterns",
            "fragmented": "Fragment payloads across multiple parameters, headers, or chunked requests",
            "out-of-band": "Use DNS, HTTP callbacks, or timing side-channels instead of reflection in the response",
            "tunnelled": "Embed attack inside legitimate-looking protocols (e.g. JSON body, GraphQL, WebSocket)",
        }

        prompt = textwrap.dedent(f"""\
            You are an advanced red-team operator specialising in operational security.

            Original attack: {original_payload}
            Attack type    : {attack_type}
            Target WAF     : {target_waf}
            Stealth profile: {stealth_profile} — {profiles.get(stealth_profile, 'custom')}

            Rewrite this attack to be MAXIMALLY STEALTHY against {target_waf}.
            Apply the {stealth_profile} profile.

            Return JSON:
            {{
                "stealthy_payload": "the rewritten attack payload",
                "implementation_notes": "how to execute it",
                "timing_recommendation": "e.g. 1 request per 30s, rotate IPs every 10 requests",
                "header_set": {{"User-Agent": "...", "Referer": "...", "X-Forwarded-For": "..."}},
                "decoy_requests": ["list of benign requests to mix in"],
                "detection_score_before": 0-10,
                "detection_score_after": 0-10,
                "residual_risk": "what still may trigger detection"
            }}
        """)

        resp = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=2000,
        )
        raw = resp.choices[0].message.content or "{}"
        jm = re.search(r"\{.*\}", raw, re.DOTALL)
        data = {}
        if jm:
            try:
                data = json.loads(jm.group())
            except json.JSONDecodeError:
                data = {"raw": raw}

        before = data.get("detection_score_before", "?")
        after  = data.get("detection_score_after", "?")

        return textwrap.dedent(f"""\
            ╔══════════════════════════════════════════════════════════════╗
            ║                    STEALTH REWRITE                           ║
            ╚══════════════════════════════════════════════════════════════╝
            Detection: {before}/10 → {after}/10
            Profile  : {stealth_profile}
            ──────────────────────────────────────────────────────────────
        """) + json.dumps(data, indent=2)

    except Exception as e:
        return f"[stealth_rewrite] Error: {e}"


@function_tool()
def log_evasion_guide(
    attack_type: str,
    target_os: str = "linux",
    web_server: str = "apache",
) -> str:
    """
    Generate a log evasion playbook for a given attack type.
    Covers: access log manipulation, /dev/null redirection, in-memory-only execution,
    fileless malware, RASP bypass, and EDR blind spots.

    Args:
        attack_type: The type of attack being performed (rce, privesc, lateral_movement, exfil, c2)
        target_os: linux | windows | macos
        web_server: apache | nginx | iis | tomcat | nodejs

    Returns:
        Step-by-step log evasion guide with concrete commands
    """
    try:
        from openai import OpenAI
        settings = get_model_settings()
        client = OpenAI(base_url=settings.base_url, api_key=settings.api_key)

        prompt = textwrap.dedent(f"""\
            You are a red-team operator conducting an authorized penetration test.
            Provide a comprehensive log evasion guide for:
            - Attack type : {attack_type}
            - Target OS   : {target_os}
            - Web server  : {web_server}

            Cover:
            1. Which log files are written during this attack
            2. Commands to clear/suppress those logs
            3. In-memory-only execution techniques (fileless)
            4. Timestomping and artefact cleanup
            5. EDR evasion (hook unhooking, process injection without disk writes)
            6. Web server log bypass (null byte, path case, IP spoofing)
            7. What artefacts are impossible to hide (IR checklist for defenders)

            Format as concrete numbered steps with actual OS commands.
        """)

        resp = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=2000,
        )
        guide = resp.choices[0].message.content or ""
        return textwrap.dedent(f"""\
            ╔══════════════════════════════════════════════════════════════╗
            ║               LOG EVASION GUIDE                              ║
            ╚══════════════════════════════════════════════════════════════╝
            Attack: {attack_type} | OS: {target_os} | Server: {web_server}
            ──────────────────────────────────────────────────────────────
        """) + guide

    except Exception as e:
        return f"[log_evasion_guide] Error: {e}"


@function_tool()
def c2_channel_advisor(
    target_network: str = "",
    outbound_filters: str = "",
    dns_filtering: str = "unknown",
) -> str:
    """
    Recommend the optimal C2 (Command & Control) communication channel
    based on the target network's egress filtering and detection capabilities.

    Args:
        target_network: Description of the target network e.g. "corporate, strict proxy, no direct internet"
        outbound_filters: Known outbound restrictions e.g. "only 80/443 allowed, deep packet inspection"
        dns_filtering: "none" | "basic" | "RPZ" | "DNS over HTTPS only" | "unknown"

    Returns:
        Ranked C2 channel recommendations with setup instructions
    """
    try:
        from openai import OpenAI
        settings = get_model_settings()
        client = OpenAI(base_url=settings.base_url, api_key=settings.api_key)

        prompt = textwrap.dedent(f"""\
            You are a red-team C2 infrastructure specialist.

            Target network description: {target_network or 'unknown'}
            Outbound filtering        : {outbound_filters or 'unknown'}
            DNS filtering             : {dns_filtering}

            Recommend the top 5 C2 channels ranked by stealth, providing for each:
            - Channel name and protocol
            - Tool/framework (Cobalt Strike profile / Havoc / Sliver / custom)
            - Setup commands (attacker side)
            - Implant config snippet
            - Detection risk score (0-10, lower = stealthier)
            - Why it works against the described filter set
            - Indicators that could still betray it

            Also recommend: malleable C2 profile tweaks for traffic blending.
        """)

        resp = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=2000,
        )
        return textwrap.dedent("""\
            ╔══════════════════════════════════════════════════════════════╗
            ║                  C2 CHANNEL ADVISOR                          ║
            ╚══════════════════════════════════════════════════════════════╝
        """) + (resp.choices[0].message.content or "")

    except Exception as e:
        return f"[c2_channel_advisor] Error: {e}"


@function_tool()
def soc_analyst_perspective(
    attack_narrative: str,
    timeframe_minutes: int = 60,
) -> str:
    """
    Simulate how a SOC analyst would see and respond to a given attack sequence.
    Returns the analyst's timeline, alert queue, investigation steps, and
    the gaps in visibility that the red team can use.

    Args:
        attack_narrative: Full description of what has been done so far
        timeframe_minutes: Simulated investigation window in minutes

    Returns:
        SOC analyst's perspective: alerts, SIEM queries, blind spots
    """
    try:
        from openai import OpenAI
        settings = get_model_settings()
        client = OpenAI(base_url=settings.base_url, api_key=settings.api_key)

        prompt = textwrap.dedent(f"""\
            You are a Tier-2 SOC analyst with {timeframe_minutes} minutes to
            investigate the following attacker activity:

            {attack_narrative}

            Provide:
            1. ALERT QUEUE — what alerts would pop up in the SIEM (Splunk/Sentinel/ELK)?
               Include the exact SPL/KQL query that would surface each alert.
            2. INVESTIGATION TIMELINE — what the analyst investigates in order
            3. PIVOTS — what additional log sources / EDR telemetry they pull
            4. CONTAINMENT ACTIONS — what they'd block/isolate
            5. DETECTION BLIND SPOTS — what the analyst CANNOT see and why
            6. ATTACKER RISK WINDOW — how long before the attacker would be caught
               at the current pace
            7. RED TEAM IMPROVEMENTS — what the attacker should change to extend
               dwell time beyond the {timeframe_minutes} minute window

            Be concrete and technical. Include SIEM queries.
        """)

        resp = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=3000,
        )
        return textwrap.dedent(f"""\
            ╔══════════════════════════════════════════════════════════════╗
            ║               SOC ANALYST PERSPECTIVE                        ║
            ╚══════════════════════════════════════════════════════════════╝
            Investigation window: {timeframe_minutes} min
            ──────────────────────────────────────────────────────────────
        """) + (resp.choices[0].message.content or "")

    except Exception as e:
        return f"[soc_analyst_perspective] Error: {e}"


# ════════════════════════════════════════════════════════════════════════════
# Agent instructions
# ════════════════════════════════════════════════════════════════════════════

ADVERSARIAL_INSTRUCTIONS = """
You are AdversarialAgent — the OpSec intelligence layer of the cyber-copilot framework.

Your role is a dual-perspective analyst:
  RED LENS  : You understand the attacker's goal and toolset
  BLUE LENS : You simulate how defenders, SOC analysts, WAFs, and IDS/EDR
              systems would perceive and respond to every attack action

════════════════════════════════════════════════════════════════
  WHEN TO INVOKE EACH TOOL
════════════════════════════════════════════════════════════════

detection_risk_analysis()
  → Called BEFORE any high-noise attack (brute force, SQLMap, Nikto, nmap -A)
  → Tells the red team: "This will fire 47 Suricata alerts — here's why"

stealth_rewrite()
  → Called when a payload was blocked by WAF or triggered an alert
  → Rewrites the payload using the specified stealth profile
  → Always try "low-and-slow" first, escalate to "tunnelled" if needed

log_evasion_guide()
  → Called post-exploitation to advise on artefact cleanup
  → Critical after: RCE, file upload, privilege escalation

c2_channel_advisor()
  → Called when establishing persistence or C2 infrastructure
  → Recommends the most covert channel for the specific egress restrictions

soc_analyst_perspective()
  → Called ANY TIME the user asks "what would a blue team see?"
  → Gives the complete analyst investigation timeline with SIEM queries

obfuscate_payload()  (from exploit_craft tools)
  → Called to encode payloads for WAF bypass
  → Use "auto" to compare all techniques side-by-side

smart_payload_generator()  (from ai_intelligence tools)
  → Called to generate WAF-aware payloads with evasion built in

manage_anonsurf()
  → Called when the user requests to start, stop, change, or check the status of their Tor anonymity layer
  → Useful when the pentester needs to rotate their external IP address

generate_syscall_loader()
  → Called to generate C/C++ shellcode loaders utilizing direct syscalls (Hell's Gate)
  → Use to bypass EDR API hooks when executing shellcode on modern Windows systems

patch_amsi_etw()
  → Called to generate obfuscated PowerShell/C# snippets that patch AmsiScanBuffer and EtwEventWrite
  → Use prior to executing malicious scripts or assemblies in memory

generate_process_hollow()
  → Called to generate C/C++ injection code targeting legitimate binaries (like svchost.exe)

════════════════════════════════════════════════════════════════
  MANDATORY OUTPUT FORMAT
════════════════════════════════════════════════════════════════

Always end analysis with:

  ## OpSec Verdict
  - Detection Risk : X/10
  - OpSec Rating   : NOISY / MODERATE / STEALTHY / SILENT
  - Critical Risk  : <one-line summary of biggest detection risk>
  - Immediate Fix  : <single most impactful evasion change>

════════════════════════════════════════════════════════════════
  RULES
════════════════════════════════════════════════════════════════
1. NEVER tell the operator their attack is "undetectable" — be honest
2. Always distinguish between "logged" (artefact exists) vs "alerted" (SOC sees it)
3. Dwell time is more valuable than speed — always bias toward stealth
4. Every recommendation must be actionable (concrete commands, not theory)
"""


def create_adversarial_agent(model: str | None = None) -> Agent:
    """Factory — returns a configured AdversarialAgent."""
    if model is None:
        from src.sdk.key_manager import get_key_manager
        model = get_key_manager().get_model()

    from src.tools.proxy_manager import proxy_start_anonsurf, proxy_check_ip, proxy_setup_proxychains, proxy_rotate_ip, proxy_status, proxy_stop, proxy_start_tornet
    return Agent(
        name="AdversarialAgent",
        instructions=ADVERSARIAL_INSTRUCTIONS,
        model=model,
        tools=[proxy_start_anonsurf, proxy_check_ip, proxy_setup_proxychains, proxy_rotate_ip, proxy_status, proxy_stop, proxy_start_tornet, 
            detection_risk_analysis,
            stealth_rewrite,
            log_evasion_guide,
            c2_channel_advisor,
            soc_analyst_perspective,
            obfuscate_payload,
            smart_payload_generator,
            manage_anonsurf,
            generate_syscall_loader,
            patch_amsi_etw,
            generate_process_hollow,
        ],
        description="OpSec / blue-team mirror — detection risk, stealth rewrites, log evasion, SOC simulation",
    )
