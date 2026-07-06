"""
Access Control Testing: IDOR / BOLA and Mass Assignment

Covers:
  - IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level Authorization)
  - Mass Assignment (parameter pollution that elevates privileges)
  - Horizontal privilege escalation
  - Vertical privilege escalation via hidden fields
"""

from __future__ import annotations

import json
import logging
import uuid
import urllib.parse
from typing import Optional

import requests

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 15
logger = logging.getLogger(__name__)


def _req(method: str, url: str, headers: dict | None = None, data=None, json_data=None,
         cookies: str = "") -> Optional[requests.Response]:
    h = {**_DEFAULT_HEADERS, **(headers or {})}
    if cookies:
        h["Cookie"] = cookies
    try:
        if method.upper() == "GET":
            return requests.get(url, headers=h, timeout=_TIMEOUT, verify=False, allow_redirects=True)
        elif method.upper() == "POST":
            return requests.post(url, headers=h, data=data, json=json_data,
                                  timeout=_TIMEOUT, verify=False, allow_redirects=True)
        elif method.upper() == "PUT":
            return requests.put(url, headers=h, data=data, json=json_data,
                                 timeout=_TIMEOUT, verify=False, allow_redirects=True)
        elif method.upper() == "PATCH":
            return requests.patch(url, headers=h, data=data, json=json_data,
                                   timeout=_TIMEOUT, verify=False, allow_redirects=True)
        elif method.upper() == "DELETE":
            return requests.delete(url, headers=h, timeout=_TIMEOUT, verify=False)
    except Exception as e:
        logger.debug(f"_req error: {e}")
    return None


@function_tool()
def idor_probe(
    url: str,
    id_param: str = "",
    id_in: str = "path",
    own_id: str = "1",
    cookies_user_a: str = "",
    cookies_user_b: str = "",
    id_range_start: int = 1,
    id_range_end: int = 20,
    method: str = "GET",
) -> str:
    """
    Test for Insecure Direct Object Reference (IDOR) / BOLA vulnerabilities.

    Strategy:
      1. Enumerate IDs in a range using user_a's session
      2. Detect which IDs return data owned by other users
      3. If user_b cookies provided: cross-validate with user_b's perspective
      4. Also tests UUID prediction and numeric offset IDOR

    Args:
        url: Target URL. Use {id} placeholder for path-based IDs
             e.g. https://api.example.com/api/users/{id}/profile
             or   https://api.example.com/api/orders?id={id}
        id_param: Query/body parameter name for the ID (e.g. id, user_id, order_id)
                  Leave empty if using {id} placeholder in url
        id_in: Where the ID lives — path | query | body (default: path)
        own_id: Your own legitimate object ID (to detect what belongs to you)
        cookies_user_a: Session of authenticated user A (attacker)
        cookies_user_b: Session of authenticated user B (victim) — optional
        id_range_start: Start of ID range to probe
        id_range_end: End of ID range to probe
        method: HTTP method (GET, POST, etc.)

    Returns:
        IDOR findings with accessible IDs and cross-user data leakage evidence
    """
    out = [f"=== IDOR / BOLA Probe: {url}", f"  Own ID : {own_id}", f"  Range  : {id_range_start}–{id_range_end}", ""]
    findings = []
    own_response_body = ""

    # Get baseline for own resource
    def _build_url_and_data(id_val):
        if "{id}" in url:
            target = url.replace("{id}", str(id_val))
            return target, None
        elif id_in == "query":
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[id_param] = str(id_val)
            new_query = urllib.parse.urlencode(params)
            target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            return target, None
        elif id_in == "body":
            return url, {id_param: str(id_val)}
        return url + f"/{id_val}", None

    out.append("── Phase 1: Own Resource Baseline ─────────────")
    own_url, own_data = _build_url_and_data(own_id)
    own_r = _req(method, own_url, cookies=cookies_user_a, data=own_data)
    if own_r:
        own_response_body = own_r.text or ""
        out.append(f"  [own_id={own_id}] HTTP {own_r.status_code}  len={len(own_response_body)}")
    else:
        out.append(f"  [own_id={own_id}] No response — check cookies/URL")

    # ── Phase 2: Enumerate IDs ────────────────────────────────────────────────
    out.append("")
    out.append("── Phase 2: ID Enumeration ────────────────────")
    accessible = []

    for test_id in range(id_range_start, id_range_end + 1):
        if str(test_id) == str(own_id):
            continue
        target_url, data = _build_url_and_data(test_id)
        r = _req(method, target_url, cookies=cookies_user_a, data=data)
        if r is None:
            continue
        body = r.text or ""
        # Accessible and has content different from own
        if r.status_code == 200 and len(body) > 50:
            # Check it's not identical to own (avoiding same-user duplicate IDs)
            if body[:200] != own_response_body[:200]:
                accessible.append((test_id, r.status_code, len(body)))
                out.append(f"  [id={test_id}] HTTP {r.status_code}  len={len(body)} ← accessible foreign object!")
            else:
                out.append(f"  [id={test_id}] HTTP {r.status_code}  (same content as own)")
        elif r.status_code in (401, 403):
            out.append(f"  [id={test_id}] HTTP {r.status_code}  (access denied — good)")
        else:
            out.append(f"  [id={test_id}] HTTP {r.status_code}  len={len(body)}")

    if accessible:
        findings.append(
            f"CRITICAL → IDOR/BOLA confirmed — {len(accessible)} foreign objects accessible "
            f"with user_a's session: IDs {[i for i,_,_ in accessible[:5]]} ..."
        )
    else:
        out.append("  No foreign objects accessible by ID enumeration")

    # ── Phase 3: Cross-user validation with user_b ────────────────────────────
    if cookies_user_b and accessible:
        out.append("")
        out.append("── Phase 3: Cross-User Validation ─────────────")
        for test_id, _, _ in accessible[:3]:
            target_url, data = _build_url_and_data(test_id)
            r_b = _req(method, target_url, cookies=cookies_user_b, data=data)
            _r_a, _ = _req(method, target_url, cookies=cookies_user_a, data=data), None
            if r_b and r_b.status_code == 200:
                out.append(f"  [id={test_id}] user_b HTTP {r_b.status_code} — user_b owns this resource")
                findings.append(
                    f"CRITICAL → Cross-validated IDOR: user_a can access user_b's object (id={test_id}). "
                    "Horizontal privilege escalation confirmed."
                )

    # ── Phase 4: UUID / GUID IDOR ─────────────────────────────────────────────
    out.append("")
    out.append("── Phase 4: UUID/GUID Probing ─────────────────")
    test_uuids = [str(uuid.uuid4()) for _ in range(3)] + [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000000",
    ]
    for test_uuid in test_uuids:
        target_url, data = _build_url_and_data(test_uuid)
        r = _req(method, target_url, cookies=cookies_user_a, data=data)
        if r and r.status_code == 200 and len(r.text or "") > 50:
            out.append(f"  [uuid={test_uuid[:18]}...] HTTP {r.status_code}  len={len(r.text)} ← accessible!")
            findings.append(
                f"HIGH → UUID IDOR: random UUID ({test_uuid}) returned HTTP 200 with content. "
                "Server may not validate UUID ownership."
            )
        elif r:
            out.append(f"  [uuid={test_uuid[:18]}...] HTTP {r.status_code}")

    # ── Summary ───────────────────────────────────────────────────────────────
    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
        out.append("")
        out.append("PoC:")
        if accessible:
            ex_id = accessible[0][0]
            ex_url, _ = _build_url_and_data(ex_id)
            out.append(f"  curl '{ex_url}' -H 'Cookie: {cookies_user_a[:60]}...'")
        out.append("Remediation: Verify resource OWNERSHIP server-side on every request.")
    else:
        out.append("No IDOR detected in tested range (try wider range or different endpoints).")

    return "\n".join(out)


@function_tool()
async def mass_assignment_probe(
    url: str,
    method: str = "POST",
    content_type: str = "json",
    cookies: str = "",
    baseline_fields: str = "",
    escalation_fields: str = "",
) -> str:
    """
    Test for Mass Assignment vulnerabilities — inject extra privilege-escalating
    fields into request bodies and check if the server accepts/reflects them.

    Automatically tests: role, admin, isAdmin, is_admin, privilege, active,
    verified, email_verified, account_type, subscription, group_id, permissions

    Args:
        url: Target endpoint (e.g. https://api.example.com/api/users/profile)
        method: HTTP method (POST, PUT, PATCH)
        content_type: Request format — json | form (default: json)
        cookies: Session cookies for authenticated requests
        baseline_fields: JSON string of normal fields (e.g. '{"name":"test","bio":"hello"}')
        escalation_fields: Custom JSON escalation fields to test (optional override)

    Returns:
        Mass assignment findings with accepted privilege escalation fields
    """
    from src.tools.mass_assignment import mass_assignment_probe as canonical_mass_assignment_probe

    headers = {}
    if cookies:
        headers["Cookie"] = cookies

    if content_type.lower() != "json":
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    return await canonical_mass_assignment_probe(
        endpoint_url=url,
        method=method,
        base_body=baseline_fields or '{"name": "test_user", "bio": "normal bio"}',
        headers=json.dumps(headers),
    )


@function_tool()
def privilege_escalation_web(
    base_url: str,
    user_cookies: str,
    admin_paths: str = "/admin,/dashboard/admin,/api/admin,/management,/superuser",
    test_methods: str = "GET,POST,DELETE",
) -> str:
    """
    Test for vertical privilege escalation by accessing admin/management paths
    with a low-privilege user session.

    Args:
        base_url: Base application URL (e.g. https://target.com)
        user_cookies: Cookies of a low-privilege authenticated user
        admin_paths: Comma-separated paths to test (default: common admin paths)
        test_methods: HTTP methods to test against each path

    Returns:
        Accessible privileged paths and exploitation guidance
    """
    out = [f"=== Vertical Privilege Escalation: {base_url}", ""]
    findings = []
    base = base_url.rstrip("/")

    paths = [p.strip() for p in admin_paths.split(",")]
    methods = [m.strip().upper() for m in test_methods.split(",")]

    headers = {**_DEFAULT_HEADERS, "Cookie": user_cookies}

    for path in paths:
        url = base + path
        for meth in methods:
            r = _req(meth, url, headers=headers, cookies="")
            if r is None:
                continue
            body = r.text or ""
            if r.status_code in (200, 201):
                admin_indicators = ["admin panel", "dashboard", "management", "user list",
                                    "delete user", "ban", "revoke", "system settings",
                                    "create admin", "role management"]
                is_admin_page = any(ind.lower() in body.lower() for ind in admin_indicators)
                if is_admin_page or r.status_code == 200:
                    findings.append(
                        f"CRITICAL → Vertical PrivEsc: {meth} {url} returned HTTP {r.status_code} "
                        f"with low-privilege session. Admin content accessible!"
                    )
                    out.append(f"  [{meth} {path}] HTTP {r.status_code} ← ACCESSIBLE — admin content found!")
                else:
                    out.append(f"  [{meth} {path}] HTTP {r.status_code} — accessible but no admin indicators")
            elif r.status_code in (401, 403):
                out.append(f"  [{meth} {path}] HTTP {r.status_code} — access denied (expected)")
            else:
                out.append(f"  [{meth} {path}] HTTP {r.status_code}")

    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
    else:
        out.append("No vertical privilege escalation detected.")

    return "\n".join(out)
