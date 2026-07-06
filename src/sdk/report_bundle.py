"""
Per-finding report bundle generator.

Given a single finding (PoC-validated) we assemble:
  - raw HTTP request / response
  - curl reproduction one-liner
  - screenshot via Playwright (if a URL was visited)
  - OOB callback log (interactsh)
  - CVSS 3.1 vector + base score
  - MITRE CWE ID + CAPEC pattern (best-effort mapping)
  - markdown-formatted summary ready for HackerOne / Bugcrowd

The bundle is written under  evidence/<engagement>/<finding-id>/
"""

from __future__ import annotations

import json
import os
import re
import shlex
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# CWE / CAPEC mapping (curated, not exhaustive)
# ─────────────────────────────────────────────────────────────────────────────

CWE_MAP: dict[str, tuple[str, str, str]] = {
    # vuln_type -> (CWE, CAPEC, OWASP top10)
    "sql_injection":     ("CWE-89",  "CAPEC-66",  "A03:2021"),
    "xss":               ("CWE-79",  "CAPEC-63",  "A03:2021"),
    "ssrf":              ("CWE-918", "CAPEC-664", "A10:2021"),
    "command_injection": ("CWE-78",  "CAPEC-248", "A03:2021"),
    "rce":               ("CWE-94",  "CAPEC-242", "A03:2021"),
    "lfi":               ("CWE-22",  "CAPEC-126", "A05:2021"),
    "rfi":               ("CWE-98",  "CAPEC-193", "A05:2021"),
    "path_traversal":    ("CWE-22",  "CAPEC-126", "A05:2021"),
    "open_redirect":     ("CWE-601", "CAPEC-178", "A03:2021"),
    "csrf":              ("CWE-352", "CAPEC-62",  "A01:2021"),
    "xxe":               ("CWE-611", "CAPEC-201", "A05:2021"),
    "idor":              ("CWE-639", "CAPEC-639", "A01:2021"),
    "auth_bypass":       ("CWE-287", "CAPEC-115", "A07:2021"),
    "jwt_forgery":       ("CWE-347", "CAPEC-593", "A02:2021"),
    "cache_poisoning":   ("CWE-444", "CAPEC-141", "A06:2021"),
    "smuggling":         ("CWE-444", "CAPEC-33",  "A06:2021"),
    "race_condition":    ("CWE-362", "CAPEC-26",  "A04:2021"),
    "ssti":              ("CWE-1336","CAPEC-242", "A03:2021"),
    "deserialization":   ("CWE-502", "CAPEC-586", "A08:2021"),
    "prototype_pollution": ("CWE-1321","CAPEC-242","A08:2021"),
    "exposed_credential": ("CWE-798","CAPEC-560", "A07:2021"),
    "sensitive_data_exposure": ("CWE-200","CAPEC-118","A02:2021"),
    "subdomain_takeover": ("CWE-350","CAPEC-141","A05:2021"),
}


# ─────────────────────────────────────────────────────────────────────────────
# CVSS 3.1 minimal scorer (vector → base score)
# ─────────────────────────────────────────────────────────────────────────────

def cvss_score(vector: str) -> float:
    """Compute CVSS 3.1 base score from a vector string. Spec-faithful."""
    metrics = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").split("/") if ":" in p)
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC"), 0.77)
    pr_unscoped = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics.get("PR"), 0.85)
    pr_scoped =   {"N": 0.85, "L": 0.68, "H": 0.50}.get(metrics.get("PR"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI"), 0.85)
    s = metrics.get("S", "U")
    pr = pr_scoped if s == "C" else pr_unscoped
    c = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("C"), 0.0)
    i = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("I"), 0.0)
    a = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get("A"), 0.0)
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if s == "U":
        base = min(impact + expl, 10)
    else:
        base = min(1.08 * (impact + expl), 10)
    return round((round(base * 10 + 0.999) / 10), 1)  # round-up nearest 0.1


def cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "None"


# ─────────────────────────────────────────────────────────────────────────────
# Dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FindingBundle:
    finding_id: str
    title: str
    target: str
    vuln_type: str = ""
    severity: str = "medium"
    description: str = ""
    request_raw: str = ""
    response_raw: str = ""
    curl_repro: str = ""
    screenshot_path: str = ""
    oob_log: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    capec: str = ""
    owasp: str = ""
    extra: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Builders
# ─────────────────────────────────────────────────────────────────────────────

def build_curl_repro(method: str, url: str, headers: dict, body: str = "") -> str:
    parts = ["curl", "-i", "-k", "--path-as-is"]
    if method.upper() != "GET":
        parts += ["-X", method.upper()]
    for k, v in (headers or {}).items():
        parts += ["-H", f"{k}: {v}"]
    if body:
        parts += ["--data-raw", body]
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


def take_screenshot(url: str, output_path: str, headers: dict | None = None) -> str:
    """Best-effort Playwright screenshot. Returns path or empty string."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return ""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            ctx = browser.new_context(ignore_https_errors=True,
                                      extra_http_headers=headers or {})
            page = ctx.new_page()
            page.goto(url, wait_until="networkidle", timeout=20000)
            page.screenshot(path=output_path, full_page=True)
            browser.close()
        return output_path
    except Exception as e:
        logger.debug(f"Screenshot failed: {e}")
        return ""


def fetch_oob_log() -> str:
    """Pull recent interactsh interactions if the session has one running."""
    try:
        from src.tools.recon_active import interactsh_poll  # registered tool
        # FunctionTool — invoke is async-wrapped
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            res = loop.run_until_complete(interactsh_poll.invoke())
        finally:
            loop.close()
        return str(res or "").strip()[:4000]
    except Exception as e:
        return f"(no OOB log: {e})"


# ─────────────────────────────────────────────────────────────────────────────
# Main entrypoint
# ─────────────────────────────────────────────────────────────────────────────

def write_bundle(bundle: FindingBundle, base_dir: str = "evidence") -> str:
    """
    Persist the bundle to disk and return the directory path.
    Files written:
      - request.http
      - response.http
      - repro.sh           (curl one-liner)
      - screenshot.png
      - oob.log
      - bundle.json        (full structured record)
      - REPORT.md          (the deliverable)
    """
    safe_id = re.sub(r"[^A-Za-z0-9_.\-]", "_", bundle.finding_id)
    out_dir = Path(base_dir) / safe_id
    out_dir.mkdir(parents=True, exist_ok=True)

    if bundle.request_raw:
        (out_dir / "request.http").write_text(bundle.request_raw, encoding="utf-8")
    if bundle.response_raw:
        (out_dir / "response.http").write_text(bundle.response_raw, encoding="utf-8")
    if bundle.curl_repro:
        (out_dir / "repro.sh").write_text("#!/usr/bin/env bash\n" + bundle.curl_repro + "\n", encoding="utf-8")
        try:
            os.chmod(out_dir / "repro.sh", 0o755)
        except Exception:
            pass
    if bundle.oob_log:
        (out_dir / "oob.log").write_text(bundle.oob_log, encoding="utf-8")

    (out_dir / "bundle.json").write_text(json.dumps(asdict(bundle), indent=2), encoding="utf-8")
    (out_dir / "REPORT.md").write_text(_render_markdown(bundle), encoding="utf-8")
    return str(out_dir)


def _render_markdown(b: FindingBundle) -> str:
    sev_label = cvss_severity(b.cvss_score) if b.cvss_score else b.severity.title()
    lines = [
        f"# {b.title}",
        "",
        f"**Severity:** {sev_label}  ",
        f"**Target:**   `{b.target}`  ",
        f"**Finding ID:** `{b.finding_id}`",
        "",
        "## Classification",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| CVSS 3.1 Vector | `{b.cvss_vector or '—'}` |",
        f"| CVSS Base Score | **{b.cvss_score or '—'}** ({sev_label}) |",
        f"| CWE  | {b.cwe or '—'} |",
        f"| CAPEC | {b.capec or '—'} |",
        f"| OWASP Top 10 | {b.owasp or '—'} |",
        "",
        "## Description",
        "",
        b.description.strip() or "_No description provided._",
        "",
        "## Reproduction",
        "",
        "```bash",
        b.curl_repro or "# (no curl repro recorded)",
        "```",
        "",
    ]
    if b.request_raw:
        lines += ["### Raw Request", "", "```http", b.request_raw[:4000], "```", ""]
    if b.response_raw:
        lines += ["### Raw Response", "", "```http", b.response_raw[:4000], "```", ""]
    if b.oob_log:
        lines += ["### Out-of-band Callback Evidence", "", "```", b.oob_log[:1500], "```", ""]
    if b.screenshot_path:
        rel = os.path.basename(b.screenshot_path)
        lines += ["### Screenshot", "", f"![screenshot]({rel})", ""]
    if b.extra:
        lines += ["### Additional Evidence", "", "```json", json.dumps(b.extra, indent=2)[:3000], "```", ""]
    return "\n".join(lines)


def make_finding_bundle(
    finding_id: str,
    title: str,
    target: str,
    vuln_type: str = "",
    method: str = "GET",
    url: str = "",
    request_headers: Optional[dict] = None,
    request_body: str = "",
    response_status: int = 0,
    response_headers: Optional[dict] = None,
    response_body: str = "",
    description: str = "",
    cvss_vector: str = "",
    capture_screenshot: bool = True,
    capture_oob: bool = True,
    base_dir: str = "evidence",
) -> str:
    """High-level helper — build the full bundle and return its directory."""
    request_headers = request_headers or {}
    response_headers = response_headers or {}

    cvss_v = cvss_vector or _suggest_vector(vuln_type)
    score = cvss_score(cvss_v) if cvss_v else 0.0
    cwe, capec, owasp = CWE_MAP.get(vuln_type, ("", "", ""))

    req_raw = ""
    if url:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        req_lines = [f"{method.upper()} {path} HTTP/1.1",
                     f"Host: {parsed.netloc}"]
        for k, v in request_headers.items():
            req_lines.append(f"{k}: {v}")
        if request_body:
            req_lines.append(f"Content-Length: {len(request_body.encode())}")
        req_lines.append("")
        if request_body:
            req_lines.append(request_body)
        req_raw = "\n".join(req_lines)

    resp_raw = ""
    if response_status:
        resp_lines = [f"HTTP/1.1 {response_status}"]
        for k, v in response_headers.items():
            resp_lines.append(f"{k}: {v}")
        resp_lines.append("")
        if response_body:
            resp_lines.append(response_body[:4000])
        resp_raw = "\n".join(resp_lines)

    curl = build_curl_repro(method, url, request_headers, request_body) if url else ""

    safe_id = re.sub(r"[^A-Za-z0-9_.\-]", "_", finding_id)
    screenshot_path = ""
    if capture_screenshot and url:
        out_path = str(Path(base_dir) / safe_id / "screenshot.png")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        screenshot_path = take_screenshot(url, out_path, request_headers)

    oob = fetch_oob_log() if capture_oob else ""

    sev_label = (cvss_severity(score) or "Medium").lower() if score else "medium"

    b = FindingBundle(
        finding_id=finding_id,
        title=title,
        target=target,
        vuln_type=vuln_type,
        severity=sev_label,
        description=description,
        request_raw=req_raw,
        response_raw=resp_raw,
        curl_repro=curl,
        screenshot_path=screenshot_path,
        oob_log=oob,
        cvss_vector=cvss_v,
        cvss_score=score,
        cwe=cwe, capec=capec, owasp=owasp,
    )
    return write_bundle(b, base_dir=base_dir)


def _suggest_vector(vuln_type: str) -> str:
    """Suggest a reasonable default CVSS vector when the operator didn't supply one."""
    defaults = {
        "rce":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "command_injection": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "sql_injection":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "ssrf":              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "xss":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "idor":              "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "auth_bypass":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "jwt_forgery":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "ssti":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "deserialization":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "smuggling":         "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "race_condition":    "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "exposed_credential":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "subdomain_takeover":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    }
    return defaults.get(vuln_type, "")


# ─────────────────────────────────────────────────────────────────────────────
# Function-tool surface (so agents can call this)
# ─────────────────────────────────────────────────────────────────────────────

from src.sdk.tool import function_tool


@function_tool()
def generate_finding_bundle(
    finding_id: str,
    title: str,
    target: str,
    vuln_type: str = "",
    method: str = "GET",
    url: str = "",
    request_headers_json: str = "{}",
    request_body: str = "",
    response_status: int = 0,
    response_headers_json: str = "{}",
    response_body: str = "",
    description: str = "",
    cvss_vector: str = "",
    capture_screenshot: bool = True,
    capture_oob: bool = True,
) -> str:
    """
    Produce a full per-finding bundle (HTTP req/resp, curl repro, screenshot,
    OOB log, CVSS, CWE, CAPEC, markdown report). Returns the bundle dir.

    Use AFTER a finding has been validated. The output is what you submit to
    HackerOne / Bugcrowd / a client report.
    """
    try:
        rh = json.loads(request_headers_json) if request_headers_json else {}
    except Exception:
        rh = {}
    try:
        sh = json.loads(response_headers_json) if response_headers_json else {}
    except Exception:
        sh = {}

    out_dir = make_finding_bundle(
        finding_id=finding_id,
        title=title,
        target=target,
        vuln_type=vuln_type,
        method=method,
        url=url,
        request_headers=rh,
        request_body=request_body,
        response_status=response_status,
        response_headers=sh,
        response_body=response_body,
        description=description,
        cvss_vector=cvss_vector,
        capture_screenshot=capture_screenshot,
        capture_oob=capture_oob,
    )
    return f"## Bundle generated: {out_dir}\n\nDeliverable files: REPORT.md, bundle.json, request.http, response.http, repro.sh, screenshot.png, oob.log"
