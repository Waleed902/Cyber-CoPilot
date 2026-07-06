"""
Authenticated Testing Context - Auth Flow Manager

Manages persistent authenticated sessions across multiple agent tool calls.
Supports:
  - Form-based login
  - HTTP Basic Auth
  - JWT/Bearer token capture
  - Cookie session persistence
  - Multi-step auth flows
  - Session re-authentication on expiry
"""

from __future__ import annotations

import json
import time
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict

import requests

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 20

# Global session store (in-memory across tool calls within same session)
_SESSION_STORE: Dict[str, "AuthSession"] = {}


def _extract_input_names(page_html: str) -> list[str]:
    """Extract unique input names from an HTML form page."""
    names = re.findall(r'<(?:input|textarea|select)[^>]+name\s*=\s*["\']([^"\']+)["\']', page_html or "", re.IGNORECASE)
    # Keep order while removing duplicates.
    return list(dict.fromkeys(n.strip() for n in names if n.strip()))


def _pick_first_present(candidates: list[str], available: list[str], fallback: str) -> str:
    """Pick the first candidate that exists in available input names."""
    available_set = set(available)
    for cand in candidates:
        if cand and cand in available_set:
            return cand
    return fallback


def _detect_csrf_field_and_value(page_html: str, preferred_field: str) -> tuple[str, str]:
    """Extract CSRF field name and value from hidden inputs/meta tags."""
    html = page_html or ""

    # 1) Preferred explicit field.
    if preferred_field:
        m = re.search(
            rf'name=["\']{re.escape(preferred_field)}["\'][^>]*value=["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        )
        if m:
            return preferred_field, m.group(1)

    # 2) Common CSRF hidden inputs.
    m = re.search(
        r'name=["\'](authenticity_token|csrf_token|_token|__RequestVerificationToken)["\'][^>]*value=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if m:
        return m.group(1), m.group(2)

    # 3) Meta tag fallback.
    m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if m:
        return preferred_field or "csrf_token", m.group(1)
    m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']', html, re.IGNORECASE)
    if m:
        return preferred_field or "csrf_token", m.group(1)

    return preferred_field, ""


def _normalize_image_captcha_value(value: str, captcha_url: str) -> str:
    """Normalize OCR/service output for image captcha fields."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", (value or "").strip())
    if not cleaned:
        return (value or "").strip()

    try:
        parsed = urllib.parse.urlparse(captcha_url)
        qs = urllib.parse.parse_qs(parsed.query)
        length_hint = qs.get("len", [""])[0] or qs.get("length", [""])[0]
        if length_hint:
            n = int(length_hint)
            if n > 0 and len(cleaned) > n:
                cleaned = cleaned[:n]
    except Exception:
        pass

    return cleaned


def _email_from_username(username: str) -> str:
    if "@" in (username or ""):
        return username
    return f"{username}@example.local"


def _normalized_path(url: str) -> str:
    try:
        return urllib.parse.urlparse(url or "").path.rstrip("/").lower()
    except Exception:
        return (url or "").rstrip("/").lower()


def _looks_like_login_form(page_html: str) -> bool:
    body = (page_html or "").lower()
    markers = [
        "id=\"login_user\"",
        "action=\"/admin/login\"",
        "name=\"user[username]\"",
        "name=\"user[password]\"",
        "<title>login</title>",
        "please login",
    ]
    return sum(1 for marker in markers if marker in body) >= 2


def _looks_like_register_form(page_html: str) -> bool:
    body = (page_html or "").lower()
    markers = [
        "action=\"/admin/register\"",
        "create an account",
        "password_confirmation",
        "captcha",
    ]
    return sum(1 for marker in markers if marker in body) >= 2


def _classify_login_result(
    status_code: int,
    final_url: str,
    location_header: str,
    body: str,
    has_cookies: bool,
    has_token: bool,
    login_url: str,
) -> tuple[bool, str]:
    body_l = (body or "").lower()
    final_path = _normalized_path(final_url)
    login_path = _normalized_path(login_url)
    location_l = (location_header or "").lower()

    fail_markers = [
        "invalid credentials",
        "incorrect password",
        "username or password incorrect",
        "login failed",
        "wrong password",
        "unauthorized",
        "access denied",
    ]

    if status_code >= 400:
        return False, f"HTTP {status_code}"

    if any(marker in body_l for marker in fail_markers):
        return False, "failure marker in response body"

    if "/login" in location_l and not has_token:
        return False, "redirected to login"

    if _looks_like_login_form(body_l) and ("/login" in final_path or final_path == login_path):
        return False, "returned to login form"

    if has_token:
        return True, "token captured"

    if status_code in (301, 302, 303, 307, 308):
        if "/login" not in location_l:
            return True, "redirected away from login"
        return False, "redirect target is login"

    success_markers = ["dashboard", "logout", "sign out", "profile", "welcome", '"success"']
    if status_code in (200, 201, 204):
        if any(marker in body_l for marker in success_markers) and not _looks_like_login_form(body_l):
            return True, "success marker in response body"
        if login_path and final_path and final_path != login_path and not _looks_like_login_form(body_l):
            return True, "moved away from login URL"

    if has_cookies and not _looks_like_login_form(body_l) and final_path and "/login" not in final_path:
        return True, "session cookies with non-login page"

    return False, "no strong success signal"


def _classify_register_result(
    status_code: int,
    final_url: str,
    location_header: str,
    body: str,
    register_url: str,
) -> tuple[bool, str]:
    body_l = (body or "").lower()
    final_path = _normalized_path(final_url)
    register_path = _normalized_path(register_url)
    location_l = (location_header or "").lower()

    fail_markers = [
        "alert-danger",
        "has already been taken",
        "can't be blank",
        "invalid",
        "error",
    ]

    extracted_errors = []
    import re
    # Extract help-block errors
    for match in re.finditer(r'<[^>]*class=["\'][^"\']*?(?:help-block|alert-danger|invalid-feedback|error-message)[^"\']*?["\'][^>]*>\s*(?:<strong>)?\s*(.*?)\s*(?:</strong>)?\s*</', body, re.IGNORECASE):
        cleaned = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        if cleaned:
            extracted_errors.append(cleaned)
            
    if status_code >= 400:
        return False, f"HTTP {status_code}"

    if (extracted_errors or any(marker in body_l for marker in fail_markers)) and _looks_like_register_form(body_l):
        # Keep the reason stable for downstream logic/tests; the extracted_errors
        # are intentionally not included in this public reason string.
        return False, "registration error marker in response body"

    if status_code in (301, 302, 303, 307, 308):
        if "/register" not in location_l:
            return True, "redirected away from register page"
        return False, "redirect target remains register"

    success_markers = ["account created", "welcome", "dashboard", "logout", "sign out"]
    if any(marker in body_l for marker in success_markers) and not _looks_like_register_form(body_l):
        return True, "success marker in response body"

    if register_path and final_path and final_path != register_path and not _looks_like_register_form(body_l):
        return True, "moved away from register URL"

    return False, "no strong success signal"

@dataclass
class AuthSession:
    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    token: str = ""
    token_type: str = ""  # bearer | basic | cookie
    username: str = ""
    login_url: str = ""
    login_data: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_refresh: float = field(default_factory=time.time)
    authenticated: bool = False
    user_info: dict = field(default_factory=dict)

    def cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def auth_header(self) -> str:
        if self.token:
            return f"{self.token_type or 'Bearer'} {self.token}"
        return ""

    def as_requests_kwargs(self) -> dict:
        kwargs = {"verify": False, "timeout": _TIMEOUT}
        h = {**_DEFAULT_HEADERS, **self.headers}
        if self.token:
            h["Authorization"] = f"{self.token_type or 'Bearer'} {self.token}"
        kwargs["headers"] = h
        if self.cookies:
            kwargs["cookies"] = self.cookies
        return kwargs


@function_tool()
async def auth_login(
    session_name: str,
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    method: str = "POST",
    content_type: str = "form",
    extra_fields: str = "",
    csrf_url: str = "",
    csrf_field: str = "csrf_token",
) -> str:
    """
    Authenticate against a target and store the session for use in subsequent tools.

    Supports form POST, JSON body, and Basic Auth. Automatically captures:
    - Session cookies (PHPSESSID, session, auth, etc.)
    - JWT/Bearer tokens from response body or Authorization header
    - CSRF tokens (fetched from a separate page if csrf_url provided)

    Args:
        session_name: Name for this session (use in other tools e.g. 'user_a')
        login_url: Login endpoint (e.g. https://target.com/api/auth/login)
        username: Login username/email
        password: Login password
        username_field: Form field name for username (default: username)
        password_field: Form field name for password (default: password)
        method: HTTP method — POST | GET (default: POST)
        content_type: Request body format — form | json (default: form)
        extra_fields: Additional form fields as JSON (e.g. '{"remember_me":"1"}')
        csrf_url: Page to fetch CSRF token from before login (optional)
        csrf_field: Name of CSRF token field in form (default: csrf_token)

    Returns:
        Authentication result with session details and reusable cookie/token strings
    """
    out = [f"=== Auth Login: {login_url}", f"  Session: {session_name}", f"  User   : {username}", ""]
    sess = requests.Session()
    sess.headers.update(_DEFAULT_HEADERS)
    sess.verify = False

    auth_session = AuthSession(
        name=session_name,
        username=username,
        login_url=login_url,
    )

    # ── Form pre-fetch / CSRF / field auto-detection ─────────────────────────
    csrf_value = ""
    page_html = ""
    detected_input_names: list[str] = []
    detected_username_field = username_field
    detected_password_field = password_field
    detected_csrf_field = csrf_field
    target_csrf_url = csrf_url or login_url

    if target_csrf_url:
        try:
            csrf_r = sess.get(target_csrf_url, timeout=_TIMEOUT)
            page_html = csrf_r.text or ""
            detected_input_names = _extract_input_names(page_html)
            detected_csrf_field, csrf_value = _detect_csrf_field_and_value(page_html, csrf_field)

            detected_username_field = _pick_first_present(
                [
                    username_field,
                    "user[username]",
                    "user[email]",
                    "email",
                    "username",
                    "login",
                    "session[username]",
                    "session[email]",
                ],
                detected_input_names,
                username_field,
            )
            detected_password_field = _pick_first_present(
                [password_field, "user[password]", "password", "session[password]"],
                detected_input_names,
                password_field,
            )

            if csrf_value:
                out.append(f"  [csrf] Token captured: {detected_csrf_field}={csrf_value[:20]}...")
            else:
                out.append(f"  [csrf] Could not extract token from {target_csrf_url}")

            if (
                detected_username_field != username_field
                or detected_password_field != password_field
            ):
                out.append(
                    "  [form] Field mapping: "
                    f"{username_field}->{detected_username_field}, "
                    f"{password_field}->{detected_password_field}"
                )
        except Exception as e:
            out.append(f"  [csrf] Error: {e}")

        # ── CAPTCHA auto-solve ───────────────────────────────────────────────
        try:
            from src.tools.captcha_solver import solve_captcha, _detect_captcha_type, _detect_captcha_field_name

            captcha_info = _detect_captcha_type(page_html, target_csrf_url)
            captcha_field = _detect_captcha_field_name(page_html)

            if captcha_info['type'] != 'image':
                out.append(f"  [captcha] Detected JS CAPTCHA: {captcha_info['type']} (sitekey: {captcha_info['sitekey'][:20]}...)")
                cookie_str = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())
                captcha_out = await solve_captcha.invoke(
                    captcha_url=target_csrf_url,
                    extraction_method="auto",
                    cookies_string=cookie_str,
                    page_url=target_csrf_url,
                    page_html=page_html,
                )
                captcha_val_match = re.search(r"CAPTCHA Value:\s*(.+)", captcha_out)
                if captcha_val_match:
                    captcha_val = captcha_val_match.group(1).strip()
                    auth_session.login_data[captcha_field] = captcha_val
                    out.append(f"  [captcha] Solved via service: {captcha_val[:30]}...")
                elif '[BAIL]' in captcha_out:
                    out.append("  [captcha] BAIL — CAPTCHA cannot be solved automatically.")
                    out.append("  [captcha] Try: default creds, SQLi auth bypass, password reset, or other entry points.")
                else:
                    out.append("  [captcha] Failed to solve JS CAPTCHA.")
            else:
                captcha_img_match = re.search(r"<img[^>]*src=['\"]([^'\"]*captcha[^'\"]*)['\"]", page_html, re.IGNORECASE)
                if captcha_img_match:
                    captcha_url_img = captcha_img_match.group(1)
                    if captcha_url_img.startswith('/'):
                        parsed = urllib.parse.urlparse(target_csrf_url)
                        captcha_url_img = f"{parsed.scheme}://{parsed.netloc}{captcha_url_img}"
                    elif not captcha_url_img.startswith('http'):
                        captcha_url_img = f"{target_csrf_url.rstrip('/')}/{captcha_url_img}"

                    out.append(f"  [captcha] Detected image captcha: {captcha_url_img}")
                    cookie_str = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())

                    captcha_out = await solve_captcha.invoke(
                        captcha_url=captcha_url_img,
                        extraction_method="auto",
                        cookies_string=cookie_str,
                        page_url=target_csrf_url,
                        page_html=page_html,
                    )
                    captcha_val_match = re.search(r"CAPTCHA Value:\s*(.+)", captcha_out)
                    if captcha_val_match:
                        captcha_val = _normalize_image_captcha_value(
                            captcha_val_match.group(1).strip(),
                            captcha_url_img,
                        )
                        auth_session.login_data[captcha_field] = captcha_val
                        out.append(f"  [captcha] Automatically solved: {captcha_val}")
                    elif '[BAIL]' in captcha_out:
                        out.append("  [captcha] BAIL — all solving methods failed.")
                        out.append("  [captcha] Do NOT retry — try alternative auth paths instead.")
                    else:
                        out.append("  [captcha] Failed to solve image captcha.")
        except Exception as e:
            out.append(f"  [captcha] Error auto-solving: {e}")

    # ── Build login payload ───────────────────────────────────────────────────
    payload: dict = {detected_username_field: username, detected_password_field: password}
    
    if extra_fields:
        try:
            payload.update(json.loads(extra_fields))
        except Exception:
            pass

    # Merge all CAPTCHA-related values solved above (field name was auto-detected)
    for k, v in auth_session.login_data.items():
        payload[k] = v
    if csrf_value:
        payload[detected_csrf_field] = csrf_value

    auth_session.login_data = payload

    # ── Send login request ────────────────────────────────────────────────────
    try:
        parsed_login = urllib.parse.urlparse(login_url)
        request_headers = {}
        if target_csrf_url:
            request_headers["Referer"] = target_csrf_url
        if parsed_login.scheme and parsed_login.netloc:
            request_headers["Origin"] = f"{parsed_login.scheme}://{parsed_login.netloc}"

        if method.upper() == "POST":
            if content_type.lower() == "json":
                request_headers["Content-Type"] = "application/json"
                r = sess.post(
                    login_url,
                    json=payload,
                    timeout=_TIMEOUT,
                    headers=request_headers or None,
                )
            else:
                r = sess.post(
                    login_url,
                    data=payload,
                    timeout=_TIMEOUT,
                    headers=request_headers or None,
                )
        else:
            r = sess.get(
                login_url,
                params=payload,
                timeout=_TIMEOUT,
                headers=request_headers or None,
            )
    except Exception as e:
        return f"Login request failed: {e}"

    out.append(f"  HTTP {r.status_code}  URL after redirect: {r.url}")

    # ── Capture cookies ───────────────────────────────────────────────────────
    all_cookies = dict(sess.cookies)
    auth_session.cookies = all_cookies
    if all_cookies:
        out.append(f"  Cookies: {', '.join(all_cookies.keys())}")

    # ── Capture JWT / Bearer tokens ───────────────────────────────────────────
    body = r.text or ""
    # From Authorization response header
    auth_header_val = r.headers.get("Authorization", "")
    if auth_header_val.startswith("Bearer "):
        auth_session.token = auth_header_val[7:]
        auth_session.token_type = "Bearer"
        out.append(f"  JWT from header: {auth_session.token[:30]}...")
    else:
        # From JSON body: {"token":"...", "access_token":"...", "jwt":"..."}
        for key in ["token", "access_token", "jwt", "auth_token", "id_token", "accessToken"]:
            try:
                body_json = r.json()
                if key in body_json and isinstance(body_json[key], str):
                    auth_session.token = body_json[key]
                    auth_session.token_type = "Bearer"
                    out.append(f"  JWT from body['{key}']: {auth_session.token[:30]}...")
                    # Also try nested
                    if not auth_session.token:
                        for nested_key in ["data", "result", "user"]:
                            subobj = body_json.get(nested_key, {})
                            if isinstance(subobj, dict) and key in subobj:
                                auth_session.token = subobj[key]
                                break
                    break
            except Exception:
                # Try regex fallback
                m = re.search(rf'"{key}"\s*:\s*"(eyJ[^"]+)"', body)
                if m:
                    auth_session.token = m.group(1)
                    auth_session.token_type = "Bearer"
                    out.append(f"  JWT via regex ({key}): {auth_session.token[:30]}...")
                    break

    login_ok, login_reason = _classify_login_result(
        status_code=r.status_code,
        final_url=r.url,
        location_header=r.headers.get("Location", ""),
        body=body,
        has_cookies=bool(all_cookies),
        has_token=bool(auth_session.token),
        login_url=login_url,
    )

    if login_ok:
        auth_session.authenticated = True
        out.append(f"  [auth] SUCCESS — session captured ({login_reason})")
    else:
        out.append(f"  [auth] FAILED — {login_reason}")
        out.append(f"  Response preview: {body[:200]}")

    # ── Store session ─────────────────────────────────────────────────────────
    _SESSION_STORE[session_name] = auth_session

    out.append("")
    out.append("── Session Summary ────────────────────────────")
    out.append(f"  Authenticated : {auth_session.authenticated}")
    out.append(f"  Cookies       : {auth_session.cookie_string()[:200] or '(none)'}")
    out.append(f"  Token         : {auth_session.token[:40] + '...' if auth_session.token else '(none)'}")
    out.append(f"  Token type    : {auth_session.token_type or '(none)'}")
    out.append("")
    out.append("Usage in other tools:")
    out.append(f"  session_name='{session_name}'")

    return "\n".join(out)


@function_tool()
async def auth_register(
    session_name: str,
    register_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    method: str = "POST",
    content_type: str = "form",
    extra_fields: str = "",
    csrf_url: str = "",
    csrf_field: str = "csrf_token",
) -> str:
    """
    Register a new account on a target, handling CSRF tokens and tracking the resulting session.
    
    This operates identically to auth_login, automatically extracting CSRF tokens from the page
    before submitting the registration payload.

    Args:
        session_name: Name for this session (use in other tools e.g. 'registered_user')
        register_url: Registration endpoint (e.g. http://target.htb/admin/register)
        username: Login username/email
        password: Login password
        username_field: Form field name for username
        password_field: Form field name for password
        method: HTTP method — POST | GET (default: POST)
        content_type: Request body format — form | json (default: form)
        extra_fields: Additional form fields as JSON string (e.g. '{"user[first_name]":"Test", "user[last_name]":"User", "user[email]":"test@example.com", "user[password_confirmation]":"TestPass123!"}'). YOU MUST provide this if the form requires nested application fields (like first_name, last_name, email, password_confirmation) or the registration will fail.
        csrf_url: URL to fetch CSRF token from BEFORE registering (e.g. http://target.htb/admin/register)
        csrf_field: Name of CSRF token field in the form (e.g. authenticity_token)

    Returns:
        Registration result with session details, cookies, and tokens captured
    """
    out = [f"=== Auth Register: {register_url}", f"  Session: {session_name}", f"  User   : {username}", ""]
    sess = requests.Session()
    sess.headers.update(_DEFAULT_HEADERS)
    sess.verify = False

    auth_session = AuthSession(
        name=session_name,
        username=username,
        login_url=register_url,
    )

    csrf_value = ""
    page_html = ""
    detected_input_names: list[str] = []
    detected_username_field = username_field
    detected_password_field = password_field
    detected_csrf_field = csrf_field
    target_csrf_url = csrf_url or register_url

    if target_csrf_url:
        try:
            csrf_r = sess.get(target_csrf_url, timeout=_TIMEOUT)
            page_html = csrf_r.text or ""
            detected_input_names = _extract_input_names(page_html)
            detected_csrf_field, csrf_value = _detect_csrf_field_and_value(page_html, csrf_field)

            detected_username_field = _pick_first_present(
                [
                    username_field,
                    "user[username]",
                    "user[email]",
                    "email",
                    "username",
                    "login",
                ],
                detected_input_names,
                username_field,
            )
            detected_password_field = _pick_first_present(
                [password_field, "user[password]", "password"],
                detected_input_names,
                password_field,
            )

            if csrf_value:
                out.append(f"  [csrf] Token captured: {detected_csrf_field}={csrf_value[:20]}...")
            else:
                out.append(f"  [csrf] Could not extract token from {target_csrf_url}")

            if (
                detected_username_field != username_field
                or detected_password_field != password_field
            ):
                out.append(
                    "  [form] Field mapping: "
                    f"{username_field}->{detected_username_field}, "
                    f"{password_field}->{detected_password_field}"
                )
        except Exception as e:
            out.append(f"  [csrf] Error: {e}")

        # ── CAPTCHA auto-solve ───────────────────────────────────────────────
        try:
            from src.tools.captcha_solver import solve_captcha, _detect_captcha_type, _detect_captcha_field_name

            captcha_info = _detect_captcha_type(page_html, target_csrf_url)
            captcha_field = _detect_captcha_field_name(page_html)

            if captcha_info['type'] != 'image':
                out.append(f"  [captcha] Detected JS CAPTCHA: {captcha_info['type']} (sitekey: {captcha_info['sitekey'][:20]}...)")
                cookie_str = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())
                captcha_out = await solve_captcha.invoke(
                    captcha_url=target_csrf_url,
                    extraction_method="auto",
                    cookies_string=cookie_str,
                    page_url=target_csrf_url,
                    page_html=page_html,
                )
                captcha_val_match = re.search(r"CAPTCHA Value:\s*(.+)", captcha_out)
                if captcha_val_match:
                    captcha_val = captcha_val_match.group(1).strip()
                    auth_session.login_data[captcha_field] = captcha_val
                    out.append(f"  [captcha] Solved via service: {captcha_val[:30]}...")
                elif '[BAIL]' in captcha_out:
                    out.append("  [captcha] BAIL — CAPTCHA cannot be solved automatically.")
                    out.append("  [captcha] Try: default creds, SQLi auth bypass, password reset, or other entry points.")
                else:
                    out.append("  [captcha] Failed to solve JS CAPTCHA.")
            else:
                captcha_img_match = re.search(r"<img[^>]*src=['\"]([^'\"]*captcha[^'\"]*)['\"]", page_html, re.IGNORECASE)
                if captcha_img_match:
                    captcha_url_img = captcha_img_match.group(1)
                    if captcha_url_img.startswith('/'):
                        parsed = urllib.parse.urlparse(target_csrf_url)
                        captcha_url_img = f"{parsed.scheme}://{parsed.netloc}{captcha_url_img}"
                    elif not captcha_url_img.startswith('http'):
                        captcha_url_img = f"{target_csrf_url.rstrip('/')}/{captcha_url_img}"

                    out.append(f"  [captcha] Detected image captcha: {captcha_url_img}")
                    cookie_str = "; ".join(f"{k}={v}" for k, v in sess.cookies.items())

                    captcha_out = await solve_captcha.invoke(
                        captcha_url=captcha_url_img,
                        extraction_method="auto",
                        cookies_string=cookie_str,
                        page_url=target_csrf_url,
                        page_html=page_html,
                    )
                    captcha_val_match = re.search(r"CAPTCHA Value:\s*(.+)", captcha_out)
                    if captcha_val_match:
                        captcha_val = _normalize_image_captcha_value(
                            captcha_val_match.group(1).strip(),
                            captcha_url_img,
                        )
                        auth_session.login_data[captcha_field] = captcha_val
                        out.append(f"  [captcha] Automatically solved: {captcha_val}")
                    elif '[BAIL]' in captcha_out:
                        out.append("  [captcha] BAIL — all solving methods failed.")
                        out.append("  [captcha] Do NOT retry — try alternative auth paths instead.")
                    else:
                        out.append("  [captcha] Failed to solve image captcha.")
        except Exception as e:
            out.append(f"  [captcha] Error auto-solving: {e}")

    payload = {detected_username_field: username, detected_password_field: password}

    # Auto-fill common required registration fields when present.
    email_guess = _email_from_username(username)
    username_slug = re.sub(r"[^A-Za-z0-9]", "", username.split("@")[0]) or "testuser"
    first_name_guess = (username_slug[:12] or "Test").capitalize()

    if "user[email]" in detected_input_names and "user[email]" not in payload:
        payload["user[email]"] = email_guess
    if "email" in detected_input_names and "email" not in payload:
        payload["email"] = email_guess
    if "user[first_name]" in detected_input_names and "user[first_name]" not in payload:
        payload["user[first_name]"] = first_name_guess
    if "first_name" in detected_input_names and "first_name" not in payload:
        payload["first_name"] = first_name_guess
    if "user[last_name]" in detected_input_names and "user[last_name]" not in payload:
        payload["user[last_name]"] = "User"
    if "last_name" in detected_input_names and "last_name" not in payload:
        payload["last_name"] = "User"
    if "user[password_confirmation]" in detected_input_names and "user[password_confirmation]" not in payload:
        payload["user[password_confirmation]"] = password
    if "password_confirmation" in detected_input_names and "password_confirmation" not in payload:
        payload["password_confirmation"] = password

    if extra_fields:
        try:
            payload.update(json.loads(extra_fields))
        except Exception:
            pass

    # Merge all CAPTCHA-related values solved above (field name was auto-detected)
    for k, v in auth_session.login_data.items():
        payload[k] = v
    if csrf_value:
        payload[detected_csrf_field] = csrf_value

    try:
        parsed_register = urllib.parse.urlparse(register_url)
        request_headers = {}
        if target_csrf_url:
            request_headers["Referer"] = target_csrf_url
        if parsed_register.scheme and parsed_register.netloc:
            request_headers["Origin"] = f"{parsed_register.scheme}://{parsed_register.netloc}"

        if method.upper() == "POST":
            if content_type.lower() == "json":
                request_headers["Content-Type"] = "application/json"
                r = sess.post(
                    register_url,
                    json=payload,
                    timeout=_TIMEOUT,
                    headers=request_headers or None,
                )
            else:
                r = sess.post(
                    register_url,
                    data=payload,
                    timeout=_TIMEOUT,
                    headers=request_headers or None,
                )
        else:
            r = sess.get(
                register_url,
                params=payload,
                timeout=_TIMEOUT,
                headers=request_headers or None,
            )
    except Exception as e:
        return f"Registration request failed: {e}"

    out.append(f"  HTTP {r.status_code}  URL after redirect: {r.url}")

    all_cookies = dict(sess.cookies)
    auth_session.cookies = all_cookies
    if all_cookies:
        out.append(f"  Cookies: {', '.join(all_cookies.keys())}")

    register_ok, register_reason = _classify_register_result(
        status_code=r.status_code,
        final_url=r.url,
        location_header=r.headers.get("Location", ""),
        body=r.text or "",
        register_url=register_url,
    )

    if register_ok:
        auth_session.authenticated = True
        out.append(f"  [auth] REGISTRATION SUCCESS — session captured ({register_reason})")
    else:
        out.append(f"  [auth] FAILED — {register_reason}")
        out.append(f"  Response preview: {(r.text or '')[:200]}")

    _SESSION_STORE[session_name] = auth_session

    out.append("")
    out.append("── Session Summary ────────────────────────────")
    out.append(f"  Authenticated : {auth_session.authenticated}")
    out.append(f"  Cookies       : {auth_session.cookie_string()[:200] or '(none)'}")
    out.append("")
    out.append("Usage in other tools:")
    out.append(f"  session_name='{session_name}'")

    return "\n".join(out)


@function_tool()
def auth_get_session(session_name: str) -> str:
    """
    Retrieve stored authentication session details.

    Args:
        session_name: Name of the session to retrieve (used in auth_login)

    Returns:
        Session cookies, token, and ready-to-use curl header strings
    """
    sess = _SESSION_STORE.get(session_name)
    if not sess:
        return (f"Session '{session_name}' not found. "
                f"Available sessions: {list(_SESSION_STORE.keys())}")

    out = [f"=== Session: {session_name}", ""]
    out.append(f"  Authenticated : {sess.authenticated}")
    out.append(f"  Username      : {sess.username}")
    out.append(f"  Login URL     : {sess.login_url}")
    out.append(f"  Created       : {time.strftime('%H:%M:%S', time.localtime(sess.created_at))}")
    out.append("")
    out.append("── Cookie String ──────────────────────────────")
    out.append(f"  {sess.cookie_string() or '(no cookies)'}")
    out.append("")
    out.append("── Token / Header ─────────────────────────────")
    if sess.token:
        out.append(f"  Authorization: {sess.token_type} {sess.token}")
    else:
        out.append("  (no token)")
    out.append("")
    out.append("── curl Usage ─────────────────────────────────")
    if sess.cookies:
        out.append(f"  -H 'Cookie: {sess.cookie_string()}'")
    if sess.token:
        out.append(f"  -H 'Authorization: {sess.token_type} {sess.token}'")
    return "\n".join(out)


@function_tool()
def auth_refresh_session(session_name: str) -> str:
    """
    Refresh a stored authenticated session by replaying the captured login data.

    This supports session-expiry recovery for authenticated crawling/scanning
    when auth_login captured enough login context to replay safely.
    """
    sess = _SESSION_STORE.get(session_name)
    if not sess:
        return f"Session '{session_name}' not found. Available sessions: {list(_SESSION_STORE.keys())}"
    if not sess.login_url or not sess.login_data:
        return f"Session '{session_name}' cannot be refreshed automatically: missing login_url or captured login_data."

    client = requests.Session()
    client.headers.update(_DEFAULT_HEADERS)
    client.verify = False
    if sess.cookies:
        client.cookies.update(sess.cookies)

    try:
        r = client.post(sess.login_url, data=sess.login_data, timeout=_TIMEOUT)
    except Exception as exc:
        return f"Session refresh failed for '{session_name}': {exc}"

    sess.cookies = dict(client.cookies)
    body = r.text or ""
    auth_header_val = r.headers.get("Authorization", "")
    if auth_header_val.startswith("Bearer "):
        sess.token = auth_header_val[7:]
        sess.token_type = "Bearer"
    else:
        for key in ["token", "access_token", "jwt", "auth_token", "id_token", "accessToken"]:
            try:
                body_json = r.json()
                if key in body_json and isinstance(body_json[key], str):
                    sess.token = body_json[key]
                    sess.token_type = "Bearer"
                    break
            except Exception:
                m = re.search(rf'"{key}"\s*:\s*"(eyJ[^"]+)"', body)
                if m:
                    sess.token = m.group(1)
                    sess.token_type = "Bearer"
                    break

    login_ok, login_reason = _classify_login_result(
        status_code=r.status_code,
        final_url=r.url,
        location_header=r.headers.get("Location", ""),
        body=body,
        has_cookies=bool(sess.cookies),
        has_token=bool(sess.token),
        login_url=sess.login_url,
    )
    sess.authenticated = login_ok
    sess.last_refresh = time.time()
    _SESSION_STORE[session_name] = sess

    return (
        f"=== Session Refresh: {session_name}\n"
        f"HTTP {r.status_code} URL after redirect: {r.url}\n"
        f"Authenticated: {sess.authenticated} ({login_reason})\n"
        f"Cookies: {sess.cookie_string()[:200] or '(none)'}\n"
        f"Token: {(sess.token[:40] + '...') if sess.token else '(none)'}"
    )


@function_tool()
def auth_compare_responses(
    url: str,
    session_a: str,
    session_b: str = "",
    method: str = "GET",
    body: str = "",
) -> str:
    """
    Make the same request with two different auth sessions and compare the responses.
    Useful for detecting IDOR: user_a requests user_b's resource.

    Args:
        url: URL to request
        session_a: First session name (e.g. 'attacker')
        session_b: Second session name (e.g. 'victim') — empty = unauthenticated
        method: HTTP method
        body: Optional request body (JSON string)

    Returns:
        Side-by-side comparison of responses with access control analysis
    """
    out = [f"=== Auth Response Comparison: {url}", ""]

    def _do_request(sess_name: str) -> dict:
        if not sess_name:
            # Unauthenticated
            try:
                r = requests.request(method, url, headers=_DEFAULT_HEADERS,
                                     json=json.loads(body) if body else None,
                                     verify=False, timeout=_TIMEOUT)
                return {"status": r.status_code, "len": len(r.text or ""), "body": r.text[:300]}
            except Exception as e:
                return {"status": 0, "len": 0, "body": str(e)}

        sess = _SESSION_STORE.get(sess_name)
        if not sess:
            return {"status": -1, "len": 0, "body": f"Session '{sess_name}' not found"}
        kwargs = sess.as_requests_kwargs()
        if body:
            kwargs["json"] = json.loads(body)
        try:
            r = requests.request(method, url, **kwargs)
            return {"status": r.status_code, "len": len(r.text or ""), "body": r.text[:300]}
        except Exception as e:
            return {"status": 0, "len": 0, "body": str(e)}

    res_a = _do_request(session_a)
    res_b = _do_request(session_b)

    out.append(f"  Session A ({session_a}): HTTP {res_a['status']}  len={res_a['len']}")
    out.append(f"  Session B ({session_b or 'unauth'}): HTTP {res_b['status']}  len={res_b['len']}")
    out.append("")

    # Analysis
    if res_a["status"] == 200 and res_b["status"] in (401, 403):
        out.append("Result: Access is properly restricted — session A has legitimate access")
    elif res_a["status"] == 200 and res_b["status"] == 200:
        if abs(res_a["len"] - res_b["len"]) < 50:
            out.append("FINDING: Both sessions return HTTP 200 with similar content length — potential IDOR!")
            out.append("  → session_b can access the same resource as session_a")
        else:
            out.append(f"Both sessions: HTTP 200 but different content lengths ({res_a['len']} vs {res_b['len']})")
    elif res_a["status"] == 403 and res_b["status"] == 200:
        out.append("INTERESTING: session_b has MORE access than session_a — unexpected privilege difference")

    out.append("")
    out.append(f"Session A response:\n{res_a['body']}")
    out.append("")
    out.append(f"Session B response:\n{res_b['body']}")

    return "\n".join(out)


@function_tool()
def auth_list_sessions() -> str:
    """List all stored authentication sessions."""
    if not _SESSION_STORE:
        return "No sessions stored. Use auth_login to create one."
    lines = ["=== Stored Auth Sessions", ""]
    for name, sess in _SESSION_STORE.items():
        lines.append(f"  {name:20s} | authenticated={sess.authenticated} | user={sess.username} | token={'yes' if sess.token else 'no'}")
    return "\n".join(lines)


@function_tool()
def auth_manual_session(
    session_name: str,
    cookies_string: str = "",
    token: str = "",
    token_type: str = "Bearer",
    username: str = "manual_user",
    headers_json: str = "",
) -> str:
    """
    Manually create an authentication session by providing raw cookies or tokens.
    Use this when automated login fails or when you have captured cookies from a browser.

    Args:
        session_name: Name for this session (e.g. 'admin_session')
        cookies_string: Raw cookie string (e.g. 'PHPSESSID=abc; security=low')
        token: Authorization token / JWT
        token_type: Type of token (default: Bearer)
        username: Identifier for the user (default: manual_user)
        headers_json: Additional headers as JSON string (optional)

    Returns:
        Status message confirming the session is stored and ready for use
    """
    auth_session = AuthSession(
        name=session_name,
        username=username,
        authenticated=True,
        token=token,
        token_type=token_type,
    )

    if cookies_string:
        # Parse PHPSESSID=abc; security=low
        parts = [p.strip() for p in cookies_string.split(";") if p.strip()]
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                auth_session.cookies[k.strip()] = v.strip()

    if headers_json:
        try:
            auth_session.headers.update(json.loads(headers_json))
        except Exception:
            pass

    _SESSION_STORE[session_name] = auth_session
    
    out = [f"=== Manual Session Stored: {session_name}", ""]
    out.append(f"  Username   : {username}")
    if auth_session.cookies:
        out.append(f"  Cookies    : {len(auth_session.cookies)} captured")
    if auth_session.token:
        out.append(f"  Token      : {auth_session.token[:30]}... ({token_type})")
    out.append("\nYou can now use this session in other tools like idor_probe or auth_compare_responses.")
    
    return "\n".join(out)


@function_tool()
def auth_request_user_assistance(
    action_required: str,
    target_url: str = "",
    session_name: str = "manual_session",
) -> str:
    """
    Pause automation and request manual intervention from the user.
    Use this when:
    - You need a second account for IDOR testing but registration is complex/protected.
    - Automated login/registration fails repeatedly.
    - A complex CAPTCHA (SMS, MFA, slide-to-verify) is blocking automation.
    - You need the user to paste cookies from their own browser.

    The user will perform the action and provide the details/cookies in the next turn.

    Args:
        action_required: Detailed description of what the user should do (e.g. 'Please register a second account at /register and provide the cookies')
        target_url: The URL where the action should be performed
        session_name: The name you plan to give this session (e.g. 'victim_session')

    Returns:
        A formal request message to the user
    """
    out = ["⚠️  MANUAL INTERVENTION REQUIRED", ""]
    out.append("The agent has requested your help to proceed with testing.")
    out.append(f"\nACTION: {action_required}")
    if target_url:
        out.append(f"URL   : {target_url}")
    out.append(f"GOAL  : Create/Capture session '{session_name}'")
    out.append("\nINSTRUCTIONS:")
    out.append("1. Perform the requested action in your browser.")
    out.append("2. Copy the resulting cookies or credentials.")
    out.append("3. Provide them in your next message (e.g., 'Here are the cookies for victim_session: ...').")
    out.append("4. The agent will then use auth_manual_session to store them and continue.")
    
    return "\n".join(out)
