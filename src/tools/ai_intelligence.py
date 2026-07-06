"""
AI-Powered Intelligence Tools
Smart vulnerability correlation, payload generation, fuzzing, and reporting
"""

import json
from typing import Any

from src.sdk.tool import function_tool
from src.sdk.key_manager import get_key_manager


def _get_ai_client_and_model() -> tuple[Any, str]:
    """Return the configured OpenAI-compatible client and active model."""
    km = get_key_manager()
    return km.get_client(), km.get_model()


@function_tool()
def ai_vulnerability_correlation(findings: str = "") -> str:
    """
    Use AI to correlate vulnerabilities and suggest attack chains.
    Analyzes relationships between findings to identify exploitation paths.
    
    Args:
        findings: JSON string of findings or "auto" to use current context
    
    Returns:
        AI-generated attack chain analysis with exploitation order
    """
    try:
        # Get findings from context if not provided
        if not findings or findings == "auto":
            from src.sdk.context_hub import get_context_hub
            hub = get_context_hub()
            
            vulns = hub.vulnerabilities
            ports = hub.open_ports
            creds = hub.credentials
            access_gained = hub.access_gained
            
            if not any([vulns, ports, creds, access_gained]):
                return "No findings available for correlation. Run reconnaissance first."
            
            findings_data = {
                "vulnerabilities": [
                    {"name": v.get("name", ""), "severity": v.get("severity", ""), "details": v.get("details", "")}
                    for v in vulns
                ],
                "open_ports": [
                    {"port": p.get("port", ""), "service": p.get("service", ""), "version": p.get("version", "unknown")}
                    for p in ports
                ],
                "credentials": [
                    {"username": c.get("username", ""), "source": c.get("source", "")}
                    for c in creds
                ],
                "access": [
                    {"type": a.get("type", ""), "user": a.get("user", ""), "privilege": a.get("privilege_level", a.get("privilege", ""))}
                    for a in access_gained
                ]
            }
            findings_str = json.dumps(findings_data, indent=2)
        else:
            findings_str = findings
        
        # Use LLM to analyze
        client, model = _get_ai_client_and_model()
        
        prompt = f"""You are an expert penetration tester analyzing security findings.

FINDINGS:
{findings_str}

Analyze these findings and provide:

1. ATTACK CHAIN CORRELATION:
   - How vulnerabilities can be chained together
   - Dependencies between exploits
   - Which findings enable others

2. EXPLOITATION ORDER (prioritized):
   - Low-hanging fruit (easiest wins)
   - Critical path to domain admin/root
   - Alternative attack paths

3. MISSING PIECES:
   - What additional information is needed
   - Recommended next reconnaissance steps
   - Potential blind spots

4. RISK ASSESSMENT:
   - Most dangerous combinations
   - Likelihood of successful exploitation
   - Impact analysis

5. ACTIONABLE RECOMMENDATIONS:
   - Step-by-step exploitation sequence
   - Tools to use for each step
   - Expected outcomes

Format as a structured attack plan."""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert penetration testing analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        analysis = response.choices[0].message.content
        
        result = f"""
╔══════════════════════════════════════════════════════════════╗
║          AI VULNERABILITY CORRELATION ANALYSIS               ║
╚══════════════════════════════════════════════════════════════╝

{analysis}

╔══════════════════════════════════════════════════════════════╗
║                    NEXT ACTIONS                              ║
╚══════════════════════════════════════════════════════════════╝

Use these tools to execute the attack chain:
  • exploit_vulnerability() - Execute specific exploits
  • lateral_movement() - Move between systems
  • auto_exploit_finder() - Find exploits for services
  • smart_payload_generator() - Create custom payloads

Run: ai_report_generator() to create full report
"""
        
        return result
        
    except Exception as e:
        return f"Error in AI correlation: {str(e)}\n\nFallback: Manually review findings and identify attack paths."


@function_tool()
def smart_payload_generator(target_info: str, vuln_type: str, evasion: str = "medium") -> str:
    """
    AI-generated custom payloads based on target environment.
    Adapts payloads for WAF/IDS evasion and target compatibility.
    
    Args:
        target_info: Target details (OS, software, defenses detected)
        vuln_type: Type of vulnerability (sqli, xss, rce, lfi, xxe, ssti, etc.)
        evasion: Evasion level (low, medium, high, extreme)
    
    Returns:
        Custom payload suggestions with explanations
    """
    try:
        client, model = _get_ai_client_and_model()
        
        prompt = f"""Generate custom exploitation payloads for penetration testing.

TARGET INFORMATION:
{target_info}

VULNERABILITY TYPE: {vuln_type}
EVASION LEVEL: {evasion}

Generate 5-10 payloads with:
1. Basic proof-of-concept
2. WAF/IDS bypass techniques
3. Encoded/obfuscated versions
4. OS-specific variations
5. Time-delayed/blind variants

For each payload provide:
- Payload string
- Explanation of technique
- Expected behavior
- Detection evasion method used

Consider:
- Character encoding (URL, Base64, Unicode, etc.)
- Case variation
- Comment injection
- Null byte insertion
- Parameter pollution
- HTTP verb tampering"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert exploit developer and security researcher."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.8,
            max_tokens=2000
        )
        
        payloads = response.choices[0].message.content
        
        return f"""
╔══════════════════════════════════════════════════════════════╗
║          SMART PAYLOAD GENERATOR - {vuln_type.upper()}                    
╚══════════════════════════════════════════════════════════════╝

Target: {target_info[:100]}
Evasion Level: {evasion}

{payloads}

╔══════════════════════════════════════════════════════════════╗
║                    TESTING NOTES                             ║
╚══════════════════════════════════════════════════════════════╝

• Monitor for defensive responses
• Escalate evasion if payloads blocked
• Document working payloads

Use ai_fuzzer() for automated testing of these payloads
"""
        
    except Exception as e:
        # Fallback to manual payload suggestions
        payloads_db = {
            "sqli": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "admin'--",
                "' AND 1=2 UNION SELECT NULL,NULL--",
                "1' ORDER BY 1--"
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>"
            ],
            "rce": [
                "; whoami",
                "| whoami",
                "`whoami`",
                "$(whoami)",
                "&& whoami"
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam"
            ]
        }
        
        base_payloads = payloads_db.get(vuln_type.lower(), ["No payloads available for this type"])
        
        return f"""Error generating AI payloads: {str(e)}

FALLBACK PAYLOADS for {vuln_type}:

""" + "\n".join(f"  {i+1}. {p}" for i, p in enumerate(base_payloads))


@function_tool()
def ai_fuzzer(endpoint: str, vuln_type: str = "auto", wordlist_size: int = 100) -> str:
    """
    LLM-guided intelligent fuzzing for endpoint testing.
    Generates context-aware test cases and learns from responses.
    
    Args:
        endpoint: Target URL or parameter to fuzz
        vuln_type: Vulnerability type to test (auto, sqli, xss, rce, etc.)
        wordlist_size: Number of test cases to generate
    
    Returns:
        Fuzzing results with discovered vulnerabilities
    """
    try:
        client, model = _get_ai_client_and_model()
        
        # Analyze endpoint first
        prompt = f"""Analyze this endpoint for fuzzing: {endpoint}

Generate {wordlist_size} intelligent test cases for vulnerability testing.

If vuln_type is 'auto', analyze the endpoint and test for:
- SQL Injection
- XSS
- Command Injection
- Path Traversal
- SSTI
- XXE
- NoSQL Injection

If specific vuln_type: {vuln_type}

For each test case:
1. The payload
2. Expected vulnerable response indicators
3. Why this test case is relevant

Prioritize:
- Common misconfigurations
- Framework-specific bugs
- Encoding bypasses
- Logic flaws"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert security fuzzing specialist."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.9,
            max_tokens=2000
        )
        
        test_cases = response.choices[0].message.content
        
        return f"""
╔══════════════════════════════════════════════════════════════╗
║              AI-GUIDED INTELLIGENT FUZZER                    ║
╚══════════════════════════════════════════════════════════════╝

Target: {endpoint}
Vulnerability Type: {vuln_type}
Test Cases: {wordlist_size}

{test_cases}

╔══════════════════════════════════════════════════════════════╗
║                    FUZZING EXECUTION                         ║
╚══════════════════════════════════════════════════════════════╝

To execute these test cases:
  1. Save to file: echo "payloads" > fuzz.txt
  2. Use with tools:
     • ffuf -w fuzz.txt -u {endpoint}
     • wfuzz -w fuzz.txt {endpoint}
     • burp intruder
  3. Monitor responses for anomalies
  4. Use ai_vulnerability_correlation() to analyze results

⚠️  Only test on authorized targets
"""
        
    except Exception as e:
        return f"""Error in AI fuzzing: {str(e)}

MANUAL FUZZING ALTERNATIVES:

1. Use traditional fuzzers:
   • ffuf -w /path/to/wordlist -u {endpoint}
   • wfuzz -w wordlist.txt {endpoint}
   
2. Generate payloads:
   • smart_payload_generator()
   • SecLists wordlists

3. Tools:
   • Burp Suite Intruder
   • OWASP ZAP Fuzzer
   • Radamsa
"""


@function_tool()
def ai_report_generator(format_type: str = "markdown") -> str:
    """
    AI-generated professional penetration testing report.
    Creates executive summary, technical details, and remediation.
    
    Args:
        format_type: Report format (markdown, html, json, executive)
    
    Returns:
        Complete professional penetration test report
    """
    try:
        from src.sdk.context_hub import get_context_hub
        hub = get_context_hub()
        
        # Gather all findings
        report_data = {
            "target": hub.current_target,
            "vulnerabilities": hub.vulnerabilities,
            "exploits_used": hub.exploits_used,
            "credentials": hub.credentials,
            "access_gained": hub.access_gained,
            "open_ports": hub.open_ports,
            "subdomains": hub.subdomains,
            "technologies": hub.technologies
        }
        
        if not hub.current_target:
            return "No target set. Run reconnaissance first or use: target <domain/ip>"
        
        client, model = _get_ai_client_and_model()
        
        prompt = f"""Generate a professional penetration testing report.

TARGET: {hub.current_target}

FINDINGS DATA:
{json.dumps(report_data, indent=2, default=str)}

Create a comprehensive report with:

1. EXECUTIVE SUMMARY
   - High-level overview for non-technical stakeholders
   - Critical findings
   - Business impact
   - Overall risk rating

2. TECHNICAL FINDINGS
   - Each vulnerability with:
     * CVSS score
     * Severity (Critical/High/Medium/Low)
     * Description
     * Steps to reproduce
     * Proof of concept
     * Affected systems

3. ATTACK CHAIN ANALYSIS
   - How vulnerabilities were exploited in sequence
   - Attack paths discovered
   - Privilege escalation methods

4. REMEDIATION ROADMAP
   - Prioritized action items
   - Quick wins vs long-term fixes
   - Specific recommendations
   - Vendor patches/updates needed

5. COMPLIANCE MAPPING
   - OWASP Top 10 alignment
   - PCI-DSS relevance
   - NIST framework mapping

6. APPENDICES
   - Tools used
   - Methodology
   - Raw scan data
   - References

Format: {format_type}"""

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an expert penetration testing report writer."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )
        
        report = response.choices[0].message.content
        
        # Save to file
        import os
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"pentest_report_{hub.current_target}_{timestamp}.{format_type}"
        
        report_path = os.path.join("targets", hub.current_target, report_filename)
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, "w") as f:
            f.write(report)
        
        return f"""
╔══════════════════════════════════════════════════════════════╗
║           AI PENETRATION TEST REPORT GENERATED               ║
╚══════════════════════════════════════════════════════════════╝

Target: {hub.current_target}
Format: {format_type}
Saved: {report_path}

{report[:1000]}

... (report continues)

╔══════════════════════════════════════════════════════════════╗
║                    REPORT ACTIONS                            ║
╚══════════════════════════════════════════════════════════════╝

View full report:
  • Markdown: code {report_path}
  • HTML: Open in browser
  • JSON: Parse programmatically

Export options:
  • PDF: pandoc {report_path} -o report.pdf
  • DOCX: pandoc {report_path} -o report.docx
  • HTML: markdown {report_path} > report.html

Generated with AI-powered analysis
"""
        
    except Exception as e:
        return f"Error generating AI report: {str(e)}\n\nUse: export markdown <file> for basic report"


# =============================================================================
# Memory-Augmented Learning Tools
# =============================================================================

@function_tool()
def recall_attack_patterns(tech_stack: str, vuln_type: str = "") -> str:
    """
    Recall similar historical attack chains from vector memory.
    Search for previous successful attack patterns targeting the same
    technology stack or vulnerability type so you don't reinvent the wheel.

    Args:
        tech_stack: Technology stack to search for (e.g. "Apache PHP MySQL", "IIS ASP.NET", "nginx Node.js")
        vuln_type:  Optional vulnerability type hint (e.g. "sqli", "rce", "xss", "ssrf")

    Returns:
        Matching historical attack chains sorted by relevance
    """
    try:
        from src.sdk.memory import VectorMemory
        vm = VectorMemory()
        results = vm.recall_similar_attacks(tech_stack, vuln_type, limit=5)
        if not results:
            return (
                f"No stored attack chains found for tech_stack='{tech_stack}', "
                f"vuln_type='{vuln_type}'. This target appears to be a new profile."
            )
        lines = [f"## Recalled Attack Chains for '{tech_stack}' / '{vuln_type}'", ""]
        for i, r in enumerate(results, 1):
            doc   = r.get("document", "")
            score = r.get("score", 0.0)
            lines.append(f"### Chain #{i} (relevance: {score:.2f})")
            lines.append(doc[:600])
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error recalling attack patterns: {e}"


@function_tool()
def store_attack_chain_memory(
    target: str,
    tech_stack: str,
    chain_summary: str,
    vuln_types: str = "",
    success: bool = True
) -> str:
    """
    Persist a completed attack chain in vector memory for future cross-target learning.
    Call this after a successful exploitation chain so the knowledge can be reused
    on similar targets.

    Args:
        target:        Target domain or IP
        tech_stack:    Technologies involved (e.g. "Apache 2.4 PHP 7.4 MySQL 5.7")
        chain_summary: Narrative of the full attack chain used
        vuln_types:    Comma-separated vulnerability types (e.g. "sqli,rce")
        success:       Whether the chain achieved the objective

    Returns:
        Confirmation with the stored memory ID
    """
    try:
        from src.sdk.memory import VectorMemory
        vm = VectorMemory()
        vuln_list = [v.strip() for v in vuln_types.split(",") if v.strip()]
        entry_id = vm.store_attack_chain(
            target=target,
            tech_stack=tech_stack,
            chain_summary=chain_summary,
            vuln_types=vuln_list,
            success=success
        )
        status = "SUCCESS" if success else "PARTIAL"
        return (
            f"[{status}] Attack chain stored in memory (id={entry_id}) for future recall.\n"
            f"Target: {target} | Stack: {tech_stack} | Vulns: {vuln_types}"
        )
    except Exception as e:
        return f"Error storing attack chain: {e}"
