"""
Business Logic Vulnerability Fuzzer
Detects logic flaws that scanners miss: price manipulation, workflow bypass,
coupon/voucher abuse, quantity tampering, and privilege escalation via state changes.

Real bug bounty techniques from HackerOne disclosures.
"""

import json
import requests
from src.sdk.core import function_tool


def _req(method, url, headers, body=None, params=None, timeout=10):
    try:
        return requests.request(method, url, headers=headers, json=body,
                                params=params, verify=False, timeout=timeout)
    except Exception:
        return None


@function_tool()
def price_manipulation_probe(
    checkout_url: str,
    cart_url: str,
    product_id: str,
    legitimate_price: str,
    headers: str = "{}"
):
    """
    Test for price manipulation vulnerabilities in checkout flows.
    Attempts to submit orders with negative, zero, or reduced prices.

    Args:
        checkout_url: URL to submit checkout/order (e.g. /api/orders)
        cart_url: URL to add items to cart or update quantities
        product_id: A valid product ID to use in tests
        legitimate_price: The correct price in cents/smallest unit (e.g. 1000 for $10.00)
        headers: JSON string of auth+session headers
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[PRICE-MANIP] Target checkout: {checkout_url}"]
    results.append(f"[INFO] Product: {product_id}, Legitimate price: {legitimate_price}")

    test_prices = [
        ("negative_price", -1),
        ("zero_price", 0),
        ("one_cent", 1),
        ("float_underflow", 0.001),
        ("negative_quantity", -1),  # negative qty × price = negative total
        ("overflow_int", 2**31 - 1),
    ]

    vulnerable = []

    for case, price_val in test_prices:
        body = {
            "product_id": product_id,
            "price": price_val,
            "quantity": 1,
            "amount": price_val,
            "unit_price": price_val,
            "total": price_val
        }
        resp = _req("POST", checkout_url, hdrs, body=body)
        status = resp.status_code if resp else "ERR"

        if resp and status in (200, 201):
            resp_text = resp.text
            if any(kw in resp_text.lower() for kw in ["order_id", "success", "placed", "confirmation", "payment"]):
                vulnerable.append((case, price_val))
                results.append(f"[VULNERABLE] {case} (price={price_val}) → Order accepted! HTTP {status}")
                results.append(f"  Response snippet: {resp_text[:150]}")
            else:
                results.append(f"[UNCERTAIN] {case} → HTTP {status} (response unclear)")
        elif status == 422 or status == 400:
            results.append(f"[BLOCKED] {case} → HTTP {status} — validation rejected")
        else:
            results.append(f"[OK] {case} → HTTP {status}")

    results.append(f"\n{'='*50}")
    if vulnerable:
        results.append(f"⚠️  PRICE MANIPULATION: {len(vulnerable)} test cases accepted")
        for case, val in vulnerable:
            results.append(f"  ✗ {case} with price={val}")
        results.append("Impact: Purchase items at arbitrary price (including free)")
    else:
        results.append("Price validation appears robust")

    return "\n".join(results)


@function_tool()
def coupon_abuse_probe(
    apply_coupon_url: str,
    coupon_codes: str,
    headers: str = "{}",
    max_reuses: int = 5
):
    """
    Test for coupon/voucher reuse and stacking abuse vulnerabilities.

    Args:
        apply_coupon_url: URL to apply coupon code (e.g. /api/cart/coupon)
        coupon_codes: Comma-separated promo codes to test
        headers: JSON string of auth headers
        max_reuses: How many times to reuse each code to detect lack of single-use enforcement
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    codes = [c.strip() for c in coupon_codes.split(",") if c.strip()]
    results = [f"[COUPON-ABUSE] Testing {len(codes)} codes against: {apply_coupon_url}"]

    for code in codes:
        results.append(f"\n[CODE] Testing: {code}")
        success_count = 0

        for attempt in range(max_reuses):
            body = {"coupon_code": code, "code": code, "promo": code}
            resp = _req("POST", apply_coupon_url, hdrs, body=body)
            status = resp.status_code if resp else "ERR"

            if resp and status in (200, 201):
                resp_data = resp.text
                if any(kw in resp_data.lower() for kw in ["discount", "applied", "success", "valid", "savings"]):
                    success_count += 1
                    results.append(f"  [ATTEMPT {attempt+1}] Accepted ✓ (HTTP {status})")
                else:
                    results.append(f"  [ATTEMPT {attempt+1}] HTTP {status} — response unclear")
            elif status == 400:
                results.append(f"  [ATTEMPT {attempt+1}] Rejected (HTTP 400)")
                break
            else:
                results.append(f"  [ATTEMPT {attempt+1}] HTTP {status}")

        if success_count > 1:
            results.append(f"  ⚠️  COUPON REUSE: Code '{code}' accepted {success_count}/{max_reuses} times!")
        elif success_count == 1:
            results.append(f"  [OK] Code '{code}' accepted once (single-use enforced after that)")

    return "\n".join(results)


@function_tool()
def workflow_bypass_probe(
    steps: str,
    direct_step_url: str,
    headers: str = "{}",
    body: str = "{}"
):
    """
    Test if a multi-step workflow can be bypassed by jumping directly to a later step.
    Common in checkout flows, account upgrades, and multi-factor enrollment.

    Args:
        steps: Comma-separated ordered step URLs (e.g. /step1,/step2,/step3)
        direct_step_url: The final/privileged step to jump to directly
        headers: JSON string of auth headers
        body: JSON body to submit to the direct step
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}
    try:
        req_body = json.loads(body)
    except Exception:
        req_body = {}

    step_list = [s.strip() for s in steps.split(",") if s.strip()]
    results = [f"[WORKFLOW-BYPASS] Testing direct access to: {direct_step_url}"]
    results.append(f"[INFO] Expected steps: {' → '.join(step_list)}")

    # Without completing prior steps, hit the last step directly
    for method in ["GET", "POST"]:
        try:
            resp = _req(method, direct_step_url, hdrs, body=req_body if method == "POST" else None)
            status = resp.status_code if resp else "ERR"

            if resp and status in (200, 201):
                text = resp.text
                if any(kw in text.lower() for kw in ["success", "complete", "confirmed", "activated", "upgraded"]):
                    results.append(f"[VULNERABLE] {method} {direct_step_url} → HTTP {status}")
                    results.append(f"  Response: {text[:200]}")
                    results.append("⚠️  WORKFLOW BYPASS: Later step accessible without completing prior steps!")
                else:
                    results.append(f"[UNCERTAIN] {method} → HTTP {status} (response: {text[:100]})")
            elif status in (401, 403):
                results.append(f"[BLOCKED] {method} → HTTP {status} — access denied properly")
            elif status == 302:
                results.append(f"[REDIRECT] {method} → HTTP {status} — redirected (likely back to step 1)")
            else:
                results.append(f"[OK] {method} → HTTP {status}")
        except Exception as e:
            results.append(f"[ERROR] {method}: {e}")

    return "\n".join(results)


@function_tool()
def account_state_abuse_probe(
    action_url: str,
    actions: str,
    current_account_state: str,
    headers: str = "{}"
):
    """
    Test for account state abuse — performing actions not valid for the current account state.
    Example: deleting account then making purchases, or submitting reviews as a banned user.

    Args:
        action_url: URL to perform the action (e.g. /api/reviews, /api/orders)
        actions: Comma-separated HTTP methods to test (GET,POST,PUT,DELETE)
        current_account_state: Description of current state (e.g. 'banned', 'unverified', 'deleted')
        headers: JSON string of auth headers (e.g. session of banned user)
    """
    try:
        hdrs = json.loads(headers)
    except Exception:
        hdrs = {}

    results = [f"[ACCOUNT-STATE] Testing actions as: '{current_account_state}'"]
    results.append(f"[INFO] Target: {action_url}")

    sample_bodies = {
        "POST": {"content": "test review", "rating": 5, "text": "LOGIC_BUG_TEST"},
        "PUT": {"content": "updated", "status": "active"},
        "DELETE": {},
    }

    for method in [m.strip().upper() for m in actions.split(",")]:
        body = sample_bodies.get(method, {})
        resp = _req(method, action_url, hdrs, body=body)
        status = resp.status_code if resp else "ERR"

        if resp and status in (200, 201, 204):
            results.append(f"[VULNERABLE] {method} → HTTP {status} — Action accepted for {current_account_state} account!")
            results.append(f"  Response: {resp.text[:150]}")
        elif status in (401, 403):
            results.append(f"[BLOCKED] {method} → HTTP {status} — Properly denied")
        else:
            results.append(f"[INFO] {method} → HTTP {status}")

    return "\n".join(results)


@function_tool()
def password_reset_invalidation_probe(
    reset_url: str,
    reset_token: str,
    new_password: str,
    headers: str = "{}",
) -> str:
    """
    Test if password reset tokens are properly invalidated after use or after a password change.
    
    Args:
        reset_url: URL to submit the password reset (e.g. /api/auth/reset).
        reset_token: The password reset token to test.
        new_password: The new password to set.
        headers: JSON string of any required headers.
    
    Returns:
        Results of the token reuse test.
    """
    try:
        hdrs = json.loads(headers)
    except:
        hdrs = {}
        
    results = [f"[PASSWORD-RESET-REUSE] Testing token reuse on: {reset_url}"]
    
    body = {"token": reset_token, "password": new_password, "password_confirmation": new_password}
    
    # 1st attempt: Use the token to reset the password
    results.append("Attempt 1: Using reset token for the first time...")
    resp1 = _req("POST", reset_url, hdrs, body=body)
    status1 = resp1.status_code if resp1 else "ERR"
    
    if status1 not in (200, 201, 204, 302):
        results.append(f"  [-] First attempt failed (HTTP {status1}). Cannot test for reuse. Response: {resp1.text[:100] if resp1 else 'None'}")
        return "\n".join(results)
    
    results.append(f"  [+] First attempt successful (HTTP {status1}). Password changed.")
    
    # 2nd attempt: Reuse the exact same token
    results.append("Attempt 2: Reusing the exact same reset token...")
    resp2 = _req("POST", reset_url, hdrs, body=body)
    status2 = resp2.status_code if resp2 else "ERR"
    
    if status2 in (200, 201, 204, 302):
        results.append(f"  🔴 VULNERABLE: Token reuse allowed! (HTTP {status2})")
        results.append("     Impact: Complete account takeover if old reset links are leaked or intercepted.")
    elif status2 in (400, 401, 403, 404, 422):
        results.append(f"  🟢 SECURE: Token was rejected on reuse (HTTP {status2}).")
    else:
        results.append(f"  🟡 UNCERTAIN: Received HTTP {status2}. Check response manually: {resp2.text[:150] if resp2 else 'None'}")
        
    return "\n".join(results)
