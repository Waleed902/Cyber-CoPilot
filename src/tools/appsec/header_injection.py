import urllib.parse
from src.sdk.tool import function_tool
from .common import _DEFAULT_HEADERS, register_appsec_vulnerability

@function_tool()
async def header_injection_scanner(url: str, parameter: str = "") -> str:
    """
    Scan for HTTP Header Injection / CRLF Injection vulnerabilities (Async Engine).
    
    Args:
        url: Target URL
        parameter: Parameter to test for header injection. If empty, tests all available parameters.
    
    Returns:
        Header injection scan results
    """
    import requests
    import concurrent.futures
    
    results = []
    
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if not params:
        return f"⛔ No query parameters found in URL: {url}\nHeader/CRLF injection requires a parameter to reflect into a redirect or Location header."

    parameters_to_test = [parameter] if parameter else list(params.keys())

    async_requests = []
    
    payloads = [
        ("%0d%0aX-Injected: header", "URL encoded CRLF"),
        ("%0aX-Injected: header", "URL encoded LF"),
        ("\r\nX-Injected: header", "Raw CRLF"),
        ("%E5%98%8D%E5%98%8AX-Injected: header", "UTF-8 encoded"),
        ("%0d%0a%0d%0a<script>alert(1)</script>", "CRLF + XSS"),
    ]

    for param in parameters_to_test:
        if param not in params:
            continue
            
        for payload, description in payloads:
            test_params = params.copy()
            test_params[param] = "test" + payload
            test_query = urllib.parse.urlencode(test_params, safe='')
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            async_requests.append({
                "url": test_url,
                "headers": _DEFAULT_HEADERS,
                "_param": param,
                "_payload": payload,
                "_desc": description
            })

    results.append(f"## Header Injection Scan (Async Engine) for {parsed.netloc}")
    results.append(f"🚀 Launching async swarm for {len(async_requests)} Header Injection payloads...")
    
    vulnerable = []
    
    def fetch_hi(req_meta):
        try:
            r = requests.get(req_meta["url"], headers=req_meta["headers"], timeout=10, verify=False, allow_redirects=False)
            return req_meta, r, None
        except Exception as e:
            return req_meta, None, e

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_hi, req) for req in async_requests]
        for future in concurrent.futures.as_completed(futures):
            req_meta, r, err = future.result()
            if err or not r: continue
            
            response_text = r.text or ""
            headers_str = str(r.headers)
            
            if "X-Injected: header" in headers_str or "X-Injected: header" in response_text:
                vulnerable.append({
                    "param": req_meta["_param"],
                    "payload": req_meta["_payload"],
                    "description": req_meta["_desc"]
                })

    if vulnerable:
        results.append(f"🔴 Found {len(vulnerable)} Header Injection vulnerabilities!")
        
        for vuln in vulnerable:
            results.append(f"  - ⚠️ CRLF INJECTION via {vuln['param']}: {vuln['description']}")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type="Header Injection (CRLF)",
                severity="HIGH",
                parameter=vuln['param'],
                payload=vuln['payload'],
                evidence=vuln['description']
            )
                
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        results.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\n\nConfirmed Vulnerabilities:\n"
            for v in vulnerable[:2]:
                context_str += f"- Header Injection via {v['param']}\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="Header Injection (CRLF)",
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
        results.append(f"✅ No header injection detected.")

    return "\n".join(results)
