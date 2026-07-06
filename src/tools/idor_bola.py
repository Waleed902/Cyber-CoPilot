"""
IDOR / BOLA (Broken Object Level Authorization) Prober
Systematically tests for insecure direct object references across API endpoints.

Techniques:
- Sequential ID enumeration (integer, UUID, slug)
- Cross-account object access (A accesses B's resource using A's session)
- Parameter tampering (user_id, account_id, order_id substitution)
- Indirect IDOR via path, query param, and body fields
- UUID v1 prediction (timestamp-based)
"""

import uuid
import requests
from src.sdk.core import function_tool


def _make_request(method: str, url: str, headers: dict, body: dict = None,
                  params: dict = None, verify: bool = False, timeout: int = 10):
    """Internal helper for HTTP requests with error wrapping."""
    try:
        resp = requests.request(
            method, url, headers=headers, json=body,
            params=params, verify=verify, timeout=timeout
        )
        return resp
    except Exception:
        return None


def _detect_idor_in_response(r1, r2) -> tuple[bool, str]:
    """
    Compares two responses to detect IDOR.
    Returns (is_vulnerable, evidence) tuple.
    """
    if r2 is None:
        return False, "No response from server"

    # Check for PII in r2
    pii_evidence = ""
    if r2.status_code == 200:
        import re
        text = r2.text.lower()
        pii_found = []
        if re.search(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', text):
            pii_found.append("Email")
        if re.search(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', text):
            pii_found.append("Phone")
        if "creditcard" in text or "ssn" in text or "passport" in text or "password" in text:
            pii_found.append("SensitiveKeywords")
            
        if pii_found:
            try:
                from src.sdk.llm import get_llm
                llm = get_llm()
                pii_val = llm.generate_response(f"Analyze this payload for PII leaks. Reply ONLY with YES if it leaks PII of a user (email, phone, address, ssn), NO otherwise. Payload: {r2.text[:1500]}")
                if "YES" in pii_val:
                    pii_evidence = f" [CRITICAL PII LEAK DETECTED: {', '.join(pii_found)}]"
            except:
                pii_evidence = f" [POTENTIAL PII LEAK: {', '.join(pii_found)}]"

    # Access to data that shouldn't be visible
    if r2.status_code == 200 and r1 and r1.status_code == 200:
        # Both successful — potential IDOR if content differs but is valid
        if len(r2.text) > 100:
            return True, f"HTTP 200 returned {len(r2.text)} bytes for foreign object" + pii_evidence

    if r2.status_code == 200 and (r1 is None or r1.status_code != 200):
        return True, f"HTTP 200 returned {len(r2.text)} bytes for ID you should not own" + pii_evidence

    return False, f"HTTP {r2.status_code} — access properly denied"


@function_tool()
def idor_sequential_probe(
    base_url: str,
    endpoint_template: str,
    own_id: str,
    test_ids: str,
    headers: str = "{}",
    method: str = "GET"
):
    """
    Probe for IDOR by replacing a known owned ID with sequential IDs.

    Args:
        base_url: Base URL of the target (e.g. https://api.example.com)
        endpoint_template: Endpoint with {id} placeholder (e.g. /api/users/{id}/profile)
        own_id: An ID you legitimately own (to establish baseline)
        test_ids: Comma-separated IDs to test (e.g. 1,2,3,100,admin)
        headers: JSON string of request headers including auth token
        method: HTTP method (GET, POST, PUT, DELETE)
    """
    import json
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = []

    # Baseline: fetch own resource
    own_url = f"{base_url}{endpoint_template.replace('{id}', own_id)}"
    baseline = _make_request(method, own_url, hdrs)
    baseline_status = baseline.status_code if baseline else "ERROR"
    results.append(f"[BASELINE] Own ID={own_id} → HTTP {baseline_status}")

    # Test foreign IDs
    ids_to_test = [i.strip() for i in test_ids.split(",") if i.strip()]
    vulnerable = []
    
    methods_to_test = ["GET", "PUT", "DELETE", "PATCH", "POST", "HEAD"] if method == "AUTO" else [method]

    for test_id in ids_to_test:
        if test_id == own_id:
            continue
        test_url = f"{base_url}{endpoint_template.replace('{id}', test_id)}"
        
        for m in methods_to_test:
            resp = _make_request(m, test_url, hdrs)
            is_vuln, evidence = _detect_idor_in_response(baseline, resp)
            status = resp.status_code if resp else "ERROR"

            if is_vuln:
                vulnerable.append(f"{m} {test_id}")
                results.append(f"[VULNERABLE] {m} ID={test_id} → HTTP {status} | {evidence}")
            else:
                results.append(f"[OK] {m} ID={test_id} → HTTP {status}")

    summary = f"\n{'='*50}\nIDOR/BFLA Scan complete: {len(vulnerable)} vectors found across {len(ids_to_test)} IDs"
    if vulnerable:
        summary += f"\nVulnerable Vectors: {', '.join(vulnerable)}"
        summary += f"\nEndpoint: {base_url}{endpoint_template}"
        summary += "\n⚠️  IDOR/BFLA CONFIRMED — object-level or function-level authorization is missing"
    else:
        summary += "\nNo IDOR/BFLA detected with tested IDs and methods"

    return "\n".join(results) + summary


@function_tool()
def idor_uuid_probe(
    base_url: str,
    endpoint_template: str,
    known_uuid: str,
    headers: str = "{}",
    num_attempts: int = 5
):
    """
    Probe for IDOR using UUID v1 timestamp prediction or random UUIDs adjacent to a known one.

    Args:
        base_url: Base URL of the target
        endpoint_template: Endpoint with {id} placeholder
        known_uuid: A valid UUID you own (used to derive timestamps for v1 or as anchor)
        headers: JSON string of auth headers
        num_attempts: Number of UUID variants to try
    """
    import json
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[IDOR-UUID] Target: {base_url}{endpoint_template}"]
    results.append(f"[IDOR-UUID] Anchor UUID: {known_uuid}")

    # Try to detect UUID version
    try:
        parsed = uuid.UUID(known_uuid)
        uuid_version = parsed.version
        results.append(f"[INFO] UUID version: {uuid_version}")
    except Exception:
        results.append("[WARN] Could not parse UUID, generating randoms")
        uuid_version = 4

    vuln_count = 0
    test_uuids = []

    if uuid_version == 1:
        # v1: timestamp-based — generate adjacent timestamps
        ts = uuid.UUID(known_uuid).time
        for i in range(1, num_attempts + 1):
            adjacent_ts = ts + (i * 1000)  # +1ms per step
            try:
                adjacent_uuid = str(uuid.UUID(fields=uuid.UUID(known_uuid).fields[:4] + (adjacent_ts,) + uuid.UUID(known_uuid).fields[5:]))
            except Exception:
                adjacent_uuid = str(uuid.uuid4())
            test_uuids.append(adjacent_uuid)
    else:
        # v4: pure random — just test random UUIDs to confirm randomness + lack of validation
        test_uuids = [str(uuid.uuid4()) for _ in range(num_attempts)]

    for test_uuid in test_uuids:
        url = f"{base_url}{endpoint_template.replace('{id}', test_uuid)}"
        resp = _make_request("GET", url, hdrs)
        status = resp.status_code if resp else "ERROR"
        if status == 200 and resp and len(resp.text) > 50:
            vuln_count += 1
            results.append(f"[VULNERABLE] UUID={test_uuid} → HTTP 200, {len(resp.text)} bytes")
        else:
            results.append(f"[OK] UUID={test_uuid} → HTTP {status}")

    results.append(f"\n{'='*50}")
    if vuln_count > 0:
        results.append(f"⚠️  UUID IDOR: {vuln_count}/{len(test_uuids)} random UUIDs returned data")
    else:
        results.append("No UUID IDOR detected")

    return "\n".join(results)


@function_tool()
def bola_param_tamper(
    url: str,
    param_name: str,
    own_value: str,
    test_values: str,
    method: str = "GET",
    headers: str = "{}",
    body_template: str = "{}"
):
    """
    BOLA test by tampering a user/account/order identifier in request params or body.

    Args:
        url: Full URL to probe
        param_name: Parameter name to tamper (e.g. user_id, account_id, order_id)
        own_value: Legitimate value you own
        test_values: Comma-separated values to test instead
        method: HTTP method
        headers: JSON string of auth headers
        body_template: JSON body template (use {param_name} as placeholder if needed)
    """
    import json
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[BOLA] Probing: {url}", f"[BOLA] Tampering param: {param_name}"]

    # Baseline with own value
    params = {param_name: own_value}
    baseline = _make_request(method, url, hdrs, params=params)
    results.append(f"[BASELINE] {param_name}={own_value} → HTTP {baseline.status_code if baseline else 'ERR'}")

    vuln = []
    test_vals = [v.strip() for v in test_values.split(",") if v.strip()]
    for val in test_vals:
        if val == own_value:
            continue
        params_test = {param_name: val}
        resp = _make_request(method, url, hdrs, params=params_test)
        status = resp.status_code if resp else "ERR"

        if status == 200 and resp and len(resp.text) > 80:
            vuln.append(val)
            results.append(f"[VULNERABLE] {param_name}={val} → HTTP 200 ({len(resp.text)} bytes)")
            # Show snippet
            snippet = resp.text[:200].replace('\n', ' ')
            results.append(f"  Response snippet: {snippet}")
        else:
            results.append(f"[OK] {param_name}={val} → HTTP {status}")

    summary = f"\n{'='*50}\nBOLA Scan: {len(vuln)}/{len(test_vals)} values exposed unauthorized data"
    if vuln:
        summary += f"\n⚠️  BOLA CONFIRMED on param '{param_name}': values {vuln}"
    return "\n".join(results) + summary
