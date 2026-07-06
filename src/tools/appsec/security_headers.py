import re
import urllib.parse
from http.cookies import SimpleCookie

import requests

from src.sdk.tool import function_tool
from .common import _DEFAULT_HEADERS, _TIMEOUT


def _header(headers, name: str) -> str:
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value.strip()
    return ""


def _set_cookie_headers(response) -> list[str]:
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers and hasattr(raw_headers, "get_all"):
        values = raw_headers.get_all("Set-Cookie")
        if values:
            return [v for v in values if v]

    value = _header(response.headers, "Set-Cookie")
    return [value] if value else []


def _cookie_name(set_cookie: str) -> str:
    return set_cookie.split(";", 1)[0].split("=", 1)[0].strip()


def _cookie_attrs(set_cookie: str) -> dict[str, str]:
    cookie = SimpleCookie()
    try:
        cookie.load(set_cookie)
    except Exception:
        return {}
    if not cookie:
        return {}
    morsel = next(iter(cookie.values()))
    attrs: dict[str, str] = {}
    for key in ("secure", "httponly", "samesite", "domain", "path"):
        value = morsel[key]
        if value:
            attrs[key.lower()] = value
    return attrs


def _is_session_cookie(name: str) -> bool:
    low = name.lower()
    return any(marker in low for marker in ("session", "sid", "auth", "token", "jwt", "login"))


@function_tool()
def security_headers_scanner(url: str, cookies: str = "", include_info: bool = True) -> str:
    """
    Scan for low and informational web hardening issues.

    Covers missing or weak security headers, exposed framework headers, and
    Set-Cookie flags. This scanner intentionally reports LOW/INFO observations
    instead of suppressing them because these findings are useful in hardening
    reports and chained AppSec analysis.
    """
    headers = {**_DEFAULT_HEADERS}
    if cookies:
        headers["Cookie"] = cookies

    try:
        response = requests.get(url, headers=headers, timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except Exception as exc:
        return f"## Security Headers and Cookie Scan\n\nTarget: {url}\nError: {exc}"

    parsed = urllib.parse.urlparse(response.url or url)
    is_https = parsed.scheme.lower() == "https"
    response_headers = response.headers
    findings: list[dict[str, str]] = []

    def add(severity: str, title: str, evidence: str, remediation: str) -> None:
        if severity == "INFO" and not include_info:
            return
        findings.append({
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "remediation": remediation,
        })

    hsts = _header(response_headers, "Strict-Transport-Security")
    if is_https and not hsts:
        add(
            "LOW",
            "Missing Strict-Transport-Security",
            "HTTPS response did not include Strict-Transport-Security.",
            "Send HSTS with an appropriate max-age after confirming HTTPS is stable.",
        )
    elif hsts:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if not match:
            add("LOW", "HSTS missing max-age", f"Strict-Transport-Security: {hsts}", "Include a max-age directive.")
        elif int(match.group(1)) < 15552000:
            add(
                "LOW",
                "HSTS max-age is short",
                f"Strict-Transport-Security: {hsts}",
                "Use a longer max-age once HTTPS deployment is mature.",
            )

    csp = _header(response_headers, "Content-Security-Policy")
    csp_ro = _header(response_headers, "Content-Security-Policy-Report-Only")
    if not csp:
        add(
            "LOW",
            "Missing Content-Security-Policy",
            "No enforced Content-Security-Policy header was observed.",
            "Deploy an enforced CSP that matches the application asset model.",
        )
        if csp_ro:
            add(
                "LOW",
                "CSP is report-only",
                f"Content-Security-Policy-Report-Only: {csp_ro[:180]}",
                "Move validated policy rules into the enforced Content-Security-Policy header.",
            )
    else:
        csp_low = csp.lower()
        if "'unsafe-inline'" in csp_low or "'unsafe-eval'" in csp_low:
            add(
                "LOW",
                "CSP allows unsafe script execution",
                f"Content-Security-Policy: {csp[:180]}",
                "Replace unsafe script allowances with nonces, hashes, or stricter source lists.",
            )
        if re.search(r"(?:^|;)\s*(?:script-src|default-src)[^;]*\*", csp, re.I):
            add(
                "LOW",
                "CSP uses wildcard sources",
                f"Content-Security-Policy: {csp[:180]}",
                "Replace wildcards with explicit trusted origins.",
            )

    xcto = _header(response_headers, "X-Content-Type-Options")
    if xcto.lower() != "nosniff":
        add(
            "LOW",
            "Missing X-Content-Type-Options nosniff",
            f"X-Content-Type-Options: {xcto or '(missing)'}",
            "Send X-Content-Type-Options: nosniff.",
        )

    xfo = _header(response_headers, "X-Frame-Options")
    has_frame_ancestors = bool(re.search(r"frame-ancestors\s+", csp, re.I))
    if not xfo and not has_frame_ancestors:
        add(
            "LOW",
            "Missing frame protection",
            "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
            "Set CSP frame-ancestors and optionally X-Frame-Options for legacy coverage.",
        )

    referrer_policy = _header(response_headers, "Referrer-Policy")
    if not referrer_policy:
        add(
            "INFO",
            "Missing Referrer-Policy",
            "No Referrer-Policy header was observed.",
            "Set a policy such as strict-origin-when-cross-origin or no-referrer.",
        )
    elif referrer_policy.lower() == "unsafe-url":
        add(
            "LOW",
            "Weak Referrer-Policy",
            f"Referrer-Policy: {referrer_policy}",
            "Avoid unsafe-url because it can leak full paths and query strings cross-origin.",
        )

    if not _header(response_headers, "Permissions-Policy"):
        add("INFO", "Missing Permissions-Policy", "No Permissions-Policy header was observed.", "Disable unused browser features explicitly.")
    if not _header(response_headers, "Cross-Origin-Opener-Policy"):
        add("INFO", "Missing Cross-Origin-Opener-Policy", "No COOP header was observed.", "Consider COOP for pages that handle sensitive browser state.")
    if not _header(response_headers, "Cross-Origin-Resource-Policy"):
        add("INFO", "Missing Cross-Origin-Resource-Policy", "No CORP header was observed.", "Consider CORP for resources that should not be embedded cross-site.")

    server = _header(response_headers, "Server")
    powered_by = _header(response_headers, "X-Powered-By")
    if server:
        add("INFO", "Server header exposes technology", f"Server: {server}", "Reduce banner detail where possible.")
    if powered_by:
        add("INFO", "X-Powered-By exposes technology", f"X-Powered-By: {powered_by}", "Remove framework/version disclosure headers.")

    acao = _header(response_headers, "Access-Control-Allow-Origin")
    acac = _header(response_headers, "Access-Control-Allow-Credentials")
    if acao == "*" and acac.lower() != "true":
        add(
            "LOW",
            "CORS wildcard origin",
            "Access-Control-Allow-Origin: *",
            "Use explicit origins for APIs that expose non-public data.",
        )

    set_cookies = _set_cookie_headers(response)
    for set_cookie in set_cookies:
        name = _cookie_name(set_cookie)
        attrs = _cookie_attrs(set_cookie)
        lname = name.lower()
        session_like = _is_session_cookie(name)

        if is_https and "secure" not in attrs:
            add("LOW", f"Cookie missing Secure flag: {name}", set_cookie, "Set Secure on cookies delivered over HTTPS.")
        if session_like and "httponly" not in attrs:
            add("LOW", f"Session-like cookie missing HttpOnly: {name}", set_cookie, "Set HttpOnly on session and authentication cookies.")
        if "samesite" not in attrs:
            add("LOW", f"Cookie missing SameSite: {name}", set_cookie, "Set SameSite=Lax or Strict unless cross-site use is required.")
        elif attrs["samesite"].lower() == "none" and "secure" not in attrs:
            add("MEDIUM", f"SameSite=None cookie missing Secure: {name}", set_cookie, "Pair SameSite=None with Secure.")
        if attrs.get("domain", "").startswith("."):
            add("LOW", f"Cookie has broad Domain scope: {name}", set_cookie, "Scope cookies to the narrowest required host.")
        if lname.startswith("__host-"):
            if "secure" not in attrs or attrs.get("path") != "/" or attrs.get("domain"):
                add("LOW", f"Invalid __Host- cookie prefix usage: {name}", set_cookie, "__Host- cookies must be Secure, Path=/, and omit Domain.")
        if lname.startswith("__secure-") and "secure" not in attrs:
            add("LOW", f"Invalid __Secure- cookie prefix usage: {name}", set_cookie, "__Secure- cookies must include Secure.")

    cache_control = _header(response_headers, "Cache-Control").lower()
    if cookies and not any(marker in cache_control for marker in ("no-store", "private")):
        add(
            "LOW",
            "Authenticated response may be cacheable",
            f"Cache-Control: {cache_control or '(missing)'}",
            "Use Cache-Control: no-store or private on authenticated responses.",
        )

    out = [
        "## Security Headers and Cookie Scan",
        f"Target: {url}",
        f"Final URL: {response.url}",
        f"HTTP status: {response.status_code}",
        "",
        "### Header Snapshot",
    ]
    for name in [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Access-Control-Allow-Origin",
        "Set-Cookie",
    ]:
        value = _header(response_headers, name)
        out.append(f"- {name}: {value[:220] if value else '(missing)'}")

    out.append("")
    if findings:
        out.append("### Findings")
        for finding in findings:
            out.append(f"- {finding['severity']} -> {finding['title']}")
            out.append(f"  Evidence: {finding['evidence'][:260]}")
            out.append(f"  Remediation: {finding['remediation']}")
        out.append(f"\nTotal findings: {len(findings)}")
    else:
        out.append("No security header or cookie issues detected.")
        out.append("Total findings: 0")

    return "\n".join(out)
