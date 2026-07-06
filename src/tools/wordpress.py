import re
import ipaddress
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import requests

from src.sdk.tool import function_tool


def _xmlrpc_candidates(target: str, endpoint: str = "") -> list[str]:
    raw = (endpoint or target or "").strip()
    if not raw:
        return []

    if "://" in raw:
        parsed = urlparse(raw)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path if parsed.path and parsed.path != "/" else "/xmlrpc.php"
        return [base + path]

    host = raw.strip("/")
    if "/" in host:
        host = host.split("/", 1)[0]
    return [f"https://{host}/xmlrpc.php", f"http://{host}/xmlrpc.php"]


def _call_xmlrpc(endpoint: str, method: str, params: list[str] | None = None, timeout: int = 20) -> tuple[int, str, str]:
    param_xml = ""
    for value in params or []:
        param_xml += f"<param><value><string>{escape(str(value))}</string></value></param>"
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<methodCall>"
        f"<methodName>{escape(method)}</methodName>"
        f"<params>{param_xml}</params>"
        "</methodCall>"
    )
    try:
        response = requests.post(
            endpoint,
            data=body.encode("utf-8"),
            headers={"Content-Type": "text/xml"},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        return response.status_code, response.text or "", ""
    except requests.RequestException as exc:
        return 0, "", str(exc)


def _extract_xmlrpc_strings(xml: str) -> list[str]:
    return re.findall(r"<string>(.*?)</string>", xml, flags=re.IGNORECASE | re.DOTALL)


def _extract_fault(xml: str) -> str:
    code = re.search(r"<name>faultCode</name>\s*<value><int>(.*?)</int></value>", xml, re.IGNORECASE | re.DOTALL)
    message = re.search(r"<name>faultString</name>\s*<value><string>(.*?)</string></value>", xml, re.IGNORECASE | re.DOTALL)
    if code or message:
        return f"{code.group(1).strip() if code else '?'}: {message.group(1).strip() if message else ''}".strip()
    return ""


def _is_public_ip_or_hostname(url: str) -> bool:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").strip()
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return host.lower() not in {"localhost", "metadata.google.internal"}


@function_tool()
def wordpress_xmlrpc_audit(
    target: str,
    endpoint: str = "",
    probe_auth_methods: bool = True,
    test_pingback: bool = False,
    callback_url: str = "",
) -> str:
    """
    Safely audit a WordPress XML-RPC endpoint.

    Uses a canonical HTTPS-first endpoint, sends well-formed XML-RPC requests,
    classifies exposed/auth-gated methods, and avoids unsafe pingback callbacks
    unless a controlled public callback URL is explicitly provided.

    Args:
        target: Domain or URL for the WordPress site.
        endpoint: Optional explicit XML-RPC endpoint. Defaults to /xmlrpc.php.
        probe_auth_methods: Send one non-bruteforce invalid-credential request to classify auth gating.
        test_pingback: Test pingback.ping only with callback_url.
        callback_url: Controlled public callback URL for pingback testing.
    """
    candidates = _xmlrpc_candidates(target, endpoint)
    if not candidates:
        return "Error: target or endpoint is required."

    lines = [
        "# WordPress XML-RPC Audit",
        f"Target: {target}",
        "",
        "## Endpoint Selection",
    ]

    chosen = ""
    list_body = ""
    list_status = 0
    attempts = []
    for candidate in candidates:
        status, body, error = _call_xmlrpc(candidate, "system.listMethods")
        attempts.append((candidate, status, error or _extract_fault(body) or "response received"))
        if status and "<methodResponse" in body and ("system.listMethods" in body or "<array>" in body):
            chosen = candidate
            list_body = body
            list_status = status
            break

    for candidate, status, note in attempts:
        status_text = str(status) if status else "no response"
        lines.append(f"- {candidate} -> {status_text} ({note})")

    if not chosen:
        lines.append("")
        lines.append("## Conclusion")
        lines.append("No usable XML-RPC endpoint was confirmed. Do not continue guessing paths with raw curl.")
        return "\n".join(lines)

    methods = sorted(set(_extract_xmlrpc_strings(list_body)))
    sensitive_prefixes = ("wp.", "metaWeblog.", "blogger.", "mt.")
    sensitive_methods = [m for m in methods if m.startswith(sensitive_prefixes)]
    pingback_enabled = "pingback.ping" in methods

    lines.extend([
        "",
        "## Confirmed Endpoint",
        f"- Endpoint: {chosen}",
        f"- HTTP status: {list_status}",
        f"- Methods exposed: {len(methods)}",
        "",
        "## Method Classification",
        f"- Public introspection: {'yes' if 'system.listMethods' in methods else 'no'}",
        f"- Pingback method listed: {'yes' if pingback_enabled else 'no'}",
        f"- WordPress/content-management methods listed: {len(sensitive_methods)}",
    ])

    if methods:
        preview = ", ".join(methods[:20])
        more = f" (+{len(methods) - 20} more)" if len(methods) > 20 else ""
        lines.append(f"- Method preview: {preview}{more}")

    if probe_auth_methods:
        status, body, error = _call_xmlrpc(
            chosen,
            "wp.getUsers",
            ["0", "__cyber_copilot_invalid_probe__", "__invalid_password__"],
        )
        fault = _extract_fault(body)
        lines.extend([
            "",
            "## Auth-Gating Probe",
            "- Method tested once with intentionally invalid non-real credentials: wp.getUsers",
            f"- HTTP status: {status if status else 'no response'}",
            f"- Result: {error or fault or 'response received'}",
        ])
        if "disabled" in (fault or body).lower():
            lines.append("- Interpretation: XML-RPC sensitive services appear disabled/gated server-side; no authentication bypass proven.")
        elif "incorrect" in (fault or body).lower() or "credentials" in (fault or body).lower() or "forbidden" in (fault or body).lower():
            lines.append("- Interpretation: Sensitive XML-RPC methods require valid authentication; no bypass proven.")
        else:
            lines.append("- Interpretation: Review raw response before claiming exploitability.")

    lines.append("")
    lines.append("## Pingback Assessment")
    if not pingback_enabled:
        lines.append("- pingback.ping is not listed; no pingback testing performed.")
    elif not test_pingback:
        lines.append("- pingback.ping is listed, but no callback was sent.")
        lines.append("- This is exposure only. Do not claim SSRF/DoS without a controlled callback proof.")
    elif not callback_url:
        lines.append("- Pingback test skipped: callback_url is required.")
    elif not _is_public_ip_or_hostname(callback_url):
        lines.append("- Pingback test skipped: callback_url must be a controlled public URL, not localhost/private/link-local metadata.")
    else:
        status, body, error = _call_xmlrpc(chosen, "pingback.ping", [callback_url, target if target.startswith("http") else f"https://{target}/"])
        lines.append(f"- Sent one pingback.ping request to controlled callback: {callback_url}")
        lines.append(f"- HTTP status: {status if status else 'no response'}")
        lines.append(f"- Result: {error or _extract_fault(body) or 'response received'}")
        lines.append("- Confirm impact only if the callback server logs an inbound request from the target.")

    lines.extend([
        "",
        "## Reportability",
        "- Confirmed: XML-RPC endpoint/method listing exposure.",
        "- Not confirmed: authentication bypass, credential compromise, SSRF, or DoS.",
        "- Recommended remediation: disable XML-RPC if unused; otherwise restrict method access, disable pingbacks, and rate-limit XML-RPC authentication paths.",
    ])

    try:
        host = urlparse(chosen).hostname or target
        from src.repl.profiles import get_profile_manager
        get_profile_manager().add_note(
            host,
            "XML-RPC audit: endpoint confirmed; method listing exposed; no authentication bypass proven by safe probe.",
            category="wordpress_xmlrpc",
        )
    except Exception:
        pass

    return "\n".join(lines)
