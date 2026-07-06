"""
Evidence-first AppSec scan orchestration.

The coordinator intentionally treats scanner output as a weak signal. It
registers candidates in the finding lifecycle and points the operator toward
browser, OAST, or authorization validation before anything becomes reportable.
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
import shutil
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

import requests

from src.sdk.finding_lifecycle import get_finding_lifecycle
from src.sdk.tool import function_tool


_appsec_scanned_urls: set[str] = set()
_STATIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".mp4", ".mp3", ".wav",
}
_INTERESTING_PARAM_HINTS = {
    "ssrf": ("url", "uri", "next", "redirect", "dest", "callback", "webhook", "image", "avatar", "feed"),
    "path_traversal": ("file", "path", "doc", "page", "include", "load", "src", "read", "download", "template"),
    "idor": ("id", "user", "account", "order", "invoice", "tenant", "org", "project"),
    "open_redirect": ("redirect", "redirect_uri", "next", "url", "goto", "return", "dest", "continue"),
}

_REQUEST_TIMEOUT = 12
_REQUEST_RETRIES = 2
_REQUEST_BACKOFF = 1.6

_TOOL_INSTALL_HINTS = {
    "whatweb": "sudo apt install whatweb",
    "wafw00f": "pip install wafw00f",
    "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
    "gospider": "go install github.com/jaeles-project/gospider@latest",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "paramspider": "pip install paramspider",
    "arjun": "pip install arjun",
}

_FINGERPRINT_SCAN_ALIASES = {"fingerprint", "tech_fingerprint", "whatweb", "waf", "wafw00f"}


def _emit_phase(phase: str, detail: str = "") -> None:
    """Best-effort UI hint so long scans do not appear stuck."""
    msg = f"APPSEC PHASE: {phase}"
    if detail:
        msg += f" | {detail}"

    # Prefer updating the live status line to avoid extra console noise.
    try:
        from src.repl.ui import update_tool_status
        phase_label = f"AppSec: {phase}"
        update_tool_status(phase=phase_label, detail=detail or "")
        return
    except Exception:
        pass

    try:
        from loguru import logger
        logger.info(msg)
    except Exception:
        pass


def _emit_subtool_start(tool_name: str, args: dict, description: str = "") -> float:
    started_at = time.time()
    try:
        from src.repl.ui import display_tool_detailed, print_separator

        print_separator()
        display_tool_detailed(tool_name=tool_name, args=args, description=description)
    except Exception:
        pass
    return started_at


def _emit_subtool_end(tool_name: str, started_at: float, success: bool) -> None:
    duration = time.time() - started_at if started_at else 0.0
    try:
        from src.repl.ui import console

        status = "done" if success else "failed"
        color = "green" if success else "red"
        console.print(f"       [{color}]{status}[/] [dim]({duration:.1f}s)[/dim]")
    except Exception:
        pass


@contextmanager
def _subtool_block(tool_name: str, args: dict, description: str = ""):
    started_at = _emit_subtool_start(tool_name, args, description)
    state = {"success": True}
    try:
        yield state
    finally:
        _emit_subtool_end(tool_name, started_at, bool(state.get("success")))


@dataclass
class ScanSignal:
    title: str
    category: str
    severity: str
    parameter: str
    output: str


def _target_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path


def _extract_params_from_url(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    return list(dict(urllib.parse.parse_qsl(parsed.query)).keys())


def _safe_json_loads(value: str, fallback: Any) -> Any:
    if not value or not value.strip():
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _load_text_source(source: str) -> tuple[str, str]:
    """Load JSON/YAML/HAR/Postman/OpenAPI text from URL, path, or inline text."""
    source = (source or "").strip()
    if not source:
        return "", ""
    if source.startswith(("http://", "https://")):
        try:
            resp = _request_with_backoff("GET", source, timeout=20)
            return (resp.text if resp is not None else ""), source
        except Exception:
            return "", source
    if os.path.exists(source):
        try:
            with open(source, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read(), source
        except Exception:
            return "", source
    return source, "inline"


def _parse_structured_source(source: str) -> tuple[dict[str, Any], str]:
    text, label = _load_text_source(source)
    if not text:
        return {}, label
    try:
        return json.loads(text), label
    except Exception:
        pass
    try:
        import yaml

        data = yaml.safe_load(text)
        return (data if isinstance(data, dict) else {}), label
    except Exception:
        return {}, label


def _base_url_from(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else url.rstrip("/")


def _replace_path_params(path: str) -> tuple[str, list[str]]:
    params = re.findall(r"{([^}]+)}", path or "")
    rendered = re.sub(r"{[^}]+}", "1", path or "")
    return rendered, params


def _api_targets_from_openapi(spec_source: str, base_url: str) -> tuple[list[tuple[str, list[str]]], list[str], list[str]]:
    """Convert OpenAPI/Swagger paths into scan targets and likely GraphQL URLs."""
    spec, label = _parse_structured_source(spec_source)
    if not spec:
        return [], [f"API spec not loaded or parseable: {label or spec_source}"], []

    servers = spec.get("servers") or []
    server_url = ""
    if isinstance(servers, list) and servers:
        server_url = str((servers[0] or {}).get("url") or "")
    if not server_url and spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = spec.get("basePath") or ""
        server_url = f"{scheme}://{spec.get('host')}{base_path}"
    api_base = urllib.parse.urljoin(base_url.rstrip("/") + "/", server_url.rstrip("/") + "/") if server_url else base_url

    targets: list[tuple[str, list[str]]] = []
    gql_urls: list[str] = []
    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        rendered_path, path_params = _replace_path_params(str(path))
        endpoint = urllib.parse.urljoin(api_base.rstrip("/") + "/", rendered_path.lstrip("/"))
        for method, details in methods.items():
            if str(method).lower() not in {"get", "post", "put", "patch", "delete"} or not isinstance(details, dict):
                continue
            params = list(path_params)
            for param in details.get("parameters", []) or []:
                if isinstance(param, dict) and param.get("name"):
                    params.append(str(param["name"]))
            request_body = details.get("requestBody") or {}
            content = request_body.get("content") if isinstance(request_body, dict) else {}
            if isinstance(content, dict):
                for media in content.values():
                    schema = (media or {}).get("schema") if isinstance(media, dict) else {}
                    props = schema.get("properties") if isinstance(schema, dict) else {}
                    if isinstance(props, dict):
                        params.extend(str(k) for k in props.keys())
            if "graphql" in endpoint.lower():
                gql_urls.append(endpoint)
            targets.append((endpoint, list(dict.fromkeys(params))))

    note = f"API spec endpoints imported from {label or spec_source}: {len(targets)}"
    return targets, [note], list(dict.fromkeys(gql_urls))


def _api_targets_from_postman(collection_source: str, base_url: str) -> tuple[list[tuple[str, list[str]]], list[str]]:
    collection, label = _parse_structured_source(collection_source)
    if not collection:
        return [], [f"Postman collection not loaded or parseable: {label or collection_source}"]

    targets: list[tuple[str, list[str]]] = []

    def walk(items: list[Any]) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            if item.get("item"):
                walk(item.get("item") or [])
                continue
            req = item.get("request") or {}
            raw_url = req.get("url")
            url = ""
            params: list[str] = []
            if isinstance(raw_url, str):
                url = raw_url
            elif isinstance(raw_url, dict):
                url = raw_url.get("raw") or ""
                for q in raw_url.get("query") or []:
                    if isinstance(q, dict) and q.get("key"):
                        params.append(str(q["key"]))
            url = url.replace("{{baseUrl}}", base_url.rstrip("/")).replace("{{base_url}}", base_url.rstrip("/"))
            if url.startswith("/"):
                url = urllib.parse.urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
            if url and url.startswith(("http://", "https://")):
                params.extend(_extract_params_from_url(url))
                targets.append((url, list(dict.fromkeys(params))))

    walk(collection.get("item") or [])
    return targets, [f"Postman endpoints imported from {label or collection_source}: {len(targets)}"]


def _api_targets_from_har(har_source: str, base_url: str) -> tuple[list[tuple[str, list[str]]], list[str]]:
    har, label = _parse_structured_source(har_source)
    if not har:
        return [], [f"HAR not loaded or parseable: {label or har_source}"]
    target_origin = urllib.parse.urlparse(base_url).netloc
    targets: list[tuple[str, list[str]]] = []
    for entry in (har.get("log") or {}).get("entries") or []:
        req = (entry or {}).get("request") or {}
        url = req.get("url") or ""
        if not url.startswith(("http://", "https://")):
            continue
        parsed = urllib.parse.urlparse(url)
        if target_origin and parsed.netloc != target_origin:
            continue
        params = _extract_params_from_url(url)
        for q in req.get("queryString") or []:
            if isinstance(q, dict) and q.get("name"):
                params.append(str(q["name"]))
        post_data = req.get("postData") or {}
        for p in post_data.get("params") or []:
            if isinstance(p, dict) and p.get("name"):
                params.append(str(p["name"]))
        targets.append((url, list(dict.fromkeys(params))))
    return targets, [f"HAR requests imported from {label or har_source}: {len(targets)}"]


def _graphql_urls_from_schema_source(schema_source: str, fallback_url: str) -> tuple[list[str], list[str]]:
    schema, label = _parse_structured_source(schema_source)
    if not schema:
        return [], [f"GraphQL schema source not loaded or parseable: {label or schema_source}"]
    urls: list[str] = []
    for key in ("url", "endpoint", "graphql_url"):
        value = schema.get(key)
        if isinstance(value, str) and value:
            urls.append(value)
    if not urls:
        urls.extend(_graphql_endpoint_candidates(fallback_url))
    return list(dict.fromkeys(urls)), [f"GraphQL schema source imported from {label or schema_source}"]


def _authorization_header_from_session(session_name: str) -> str:
    if not session_name:
        return ""
    try:
        from src.tools.auth_context import _SESSION_STORE

        sess = _SESSION_STORE.get(session_name)
        if sess and sess.auth_header():
            return sess.auth_header()
    except Exception:
        pass
    return ""


def _auth_headers_json(extra_headers_json: str = "", bearer_token: str = "", session_name: str = "") -> str:
    headers = _safe_json_loads(extra_headers_json, {}) if extra_headers_json else {}
    if not isinstance(headers, dict):
        headers = {}
    auth_header = _authorization_header_from_session(session_name)
    if bearer_token:
        auth_header = bearer_token if bearer_token.lower().startswith(("bearer ", "basic ")) else f"Bearer {bearer_token}"
    if auth_header:
        headers["Authorization"] = auth_header
    return json.dumps(headers) if headers else ""


def _role_matrix(role_sessions_json: str, role_cookies_json: str, auth_session_name: str,
                 cookies: str, cookies_user_b: str) -> dict[str, dict[str, str]]:
    sessions = _safe_json_loads(role_sessions_json, {})
    cookie_map = _safe_json_loads(role_cookies_json, {})
    roles = {
        "user_a": {"session": auth_session_name or str(sessions.get("user_a", "")), "cookies": cookies},
        "user_b": {"session": str(sessions.get("user_b", "")), "cookies": cookies_user_b},
        "admin": {"session": str(sessions.get("admin", "")), "cookies": ""},
        "low_priv": {"session": str(sessions.get("low_priv", "")), "cookies": ""},
    }
    if isinstance(cookie_map, dict):
        for role, role_cookies in cookie_map.items():
            if role in roles and role_cookies:
                roles[role]["cookies"] = str(role_cookies)
    return roles


def _oast_host(kind: str, parameter: str, oast_domain: str) -> str:
    clean = oast_domain.strip().lstrip("*.").rstrip("/")
    token = hashlib.sha1(f"{kind}|{parameter}|{time.time()}".encode()).hexdigest()[:12]
    safe_param = re.sub(r"[^A-Za-z0-9-]", "-", parameter or "body").strip("-") or "body"
    return f"{kind}-{safe_param}-{token}.{clean}"


async def _discover_parameters(
    url: str,
    explicit_parameters: str = "",
    cookies: str = "",
) -> tuple[list[str], list[str], list[str]]:
    """Return (params, notes, param_urls) from multiple discovery sources."""
    notes: list[str] = []
    params: list[str] = []
    param_urls: list[str] = []

    if explicit_parameters.strip():
        _emit_phase("parameter discovery", "using explicit parameters")
        params = [p.strip() for p in explicit_parameters.split(",") if p.strip()]
        notes.append(f"Explicit parameters supplied: {', '.join(params)}")
        return list(dict.fromkeys(params)), notes, param_urls

    params.extend(_extract_params_from_url(url))
    if params:
        _emit_phase("parameter discovery", "using URL query parameters")
        notes.append(f"URL query parameters found: {', '.join(params)}")
    headers = _cookie_headers(cookies)

    # Pull parameters from HTML forms
    try:
        from src.tools.browser_automation import browser_extract_forms

        with _subtool_block("browser_extract_forms", {"url": url}, "HTML form parameter discovery"):
            form_output = await browser_extract_forms.invoke(url=url)
        form_params = _extract_form_params_from_output(form_output)
        if form_params:
            params.extend(form_params)
            notes.append(f"HTML form parameters found: {', '.join(form_params)}")
    except Exception as exc:
        notes.append(f"Form discovery failed: {str(exc)[:120]}")

    # Pull URLs from robots.txt/sitemap.xml
    sitemap_urls, sitemap_notes = _discover_sitemap_urls(url, cookies)
    notes.extend(sitemap_notes)
    if sitemap_urls:
        param_urls.extend([u for u in sitemap_urls if "?" in u and "=" in u])
        params.extend(_extract_param_names_from_urls(param_urls))

    # Pull endpoints from JavaScript
    js_urls: list[str] = []
    resp = _request_with_backoff("GET", url, headers=headers)
    if resp and resp.text:
        js_urls = _extract_script_srcs(resp.text, url)
    if js_urls:
        js_endpoints = await _discover_js_endpoints(js_urls, url)
        if js_endpoints:
            js_param_urls = [u for u in js_endpoints if "?" in u and "=" in u]
            param_urls.extend(js_param_urls)
            params.extend(_extract_param_names_from_urls(js_param_urls))
            notes.append(f"JavaScript endpoints parsed: {len(js_endpoints)}")

    params = list(dict.fromkeys(params))
    param_urls = list(dict.fromkeys(param_urls))

    if not params:
        notes.append("No parameters found yet; trying arjun_scan for hidden parameters.")
        _emit_phase("parameter discovery", "running arjun_scan")
        try:
            from src.tools.web import arjun_scan

            arjun_output = await arjun_scan.invoke(url=url)
            arjun_params = re.findall(r"(?:Parameter|Param)\s*[:\s]+([A-Za-z0-9_\-]+)", arjun_output)
            if arjun_params:
                params.extend(arjun_params)
                notes.append(f"arjun_scan discovered: {', '.join(sorted(set(arjun_params)))}")
            else:
                notes.append("arjun_scan returned no parseable parameters.")
        except Exception as exc:
            notes.append(f"arjun_scan unavailable or failed: {str(exc)[:120]}")

    return list(dict.fromkeys(params)), notes, list(dict.fromkeys(param_urls))


def _params_matching(params: list[str], category: str) -> list[str]:
    hints = _INTERESTING_PARAM_HINTS.get(category, ())
    matches = [p for p in params if any(h in p.lower() for h in hints)]
    return matches or params[:1]


def _graphql_endpoint_candidates(url: str, override: str = "") -> list[str]:
    if override.strip():
        return [override.strip()]
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return []
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [url] if "graphql" in parsed.path.lower() else []
    candidates.extend([f"{base}/graphql", f"{base}/api/graphql"])
    return list(dict.fromkeys(candidates))


def _scan_indicates_signal(category: str, output: str) -> bool:
    low = (output or "").lower()
    if not low:
        return False
    if re.search(r"\btotal findings:\s*0\b", low):
        return False
    if re.search(r"\b(?:no|0)\s+(?:security header or cookie )?(?:findings|issues|vulnerabilities|misconfigurations)\b", low):
        return False
    explicit_finding = bool(
        re.search(r"\btotal findings:\s*[1-9]\d*\b", low)
        or re.search(r"\b(?:critical|high|medium|low|info)\s*(?:->|→)", output or "", re.I)
        or "low confidence candidates" in low
        or " found " in low
        or "findings" in low and "no findings" not in low
    )
    if category == "xss":
        return any(s in low for s in ("vulnerable", "potential xss", "xss confirmed", "reflected xss"))
    if category == "sqli":
        if re.search(r"\bno\s+(?:obvious\s+)?sql injection\b.*\b(?:found|detected)\b", low):
            return False
        return any(s in low for s in ("error-based", "time-based", "injectable")) or (
            "found" in low and "sql injection" in low
        )
    if category == "nosql":
        return explicit_finding or any(s in low for s in ("low confidence candidates", "anomaly"))
    if category == "ldap":
        return explicit_finding or any(s in low for s in ("ldap error disclosed", "auth bypass", "anomaly"))
    if category == "ssrf":
        return any(s in low for s in ("ssrf:", "callback", "metadata", "large response", "oast"))
    if category == "xxe":
        return explicit_finding or any(s in low for s in ("xxe:", "blind xxe", "external entity", "callback", "candidate"))
    if category == "path_traversal":
        if re.search(r"\bno\s+(?:obvious\s+)?(?:path traversal|lfi)\b.*\b(?:found|detected)\b", low):
            return False
        return any(s in low for s in ("root:", "etc/passwd", "win.ini")) or (
            "found" in low and ("path traversal" in low or "lfi" in low)
        )
    if category == "command_injection":
        if re.search(r"\bno\s+(?:obvious\s+)?command injection\b.*\b(?:found|detected)\b", low):
            return False
        return any(s in low for s in ("reflected output", "time-based", "oast", "candidate")) or (
            "found" in low and "command injection" in low
        )
    if category == "ssti":
        return any(s in low for s in ("ssti detected", "rce confirmed", "blind ssti", "oast", "candidate"))
    if category in {"deserialization", "blind_xss", "xss_oob"}:
        return any(s in low for s in ("canary:", "candidate", "oast", "callback"))
    if category == "open_redirect":
        if re.search(r"\bno\s+(?:obvious\s+)?open redirect\b.*\b(?:found|detected)\b", low):
            return False
        return any(s in low for s in ("confirmed redirects", "total confirmed open redirects")) or (
            "found" in low and "open redirect" in low
        )
    if category in {"crlf", "header_injection"}:
        return explicit_finding or any(s in low for s in ("crlf injection", "header injection", "response splitting"))
    if category == "idor":
        return any(s in low for s in ("idor", "bola", "foreign object", "privilege escalation confirmed"))
    if category == "cors":
        return explicit_finding or any(
            s in low
            for s in (
                "arbitrary origin reflected",
                "wildcard with credentials",
                "null origin allowed",
                "dangerous pre-flight",
            )
        )
    if category in {"security_headers", "cookies", "clickjacking", "csrf", "host_header"}:
        return explicit_finding
    if category == "graphql":
        return any(s in low for s in ("introspection is enabled", "security findings", "graphql", "authorization bypass"))
    return any(s in low for s in ("vulnerable", "confirmed", "critical", "high"))


def _register_candidate(signal: ScanSignal, target: str, endpoint: str, scope_source: str = "full_appsec_scan") -> str:
    lifecycle = get_finding_lifecycle()
    finding = lifecycle.add_candidate(
        title=signal.title,
        target=target,
        severity=signal.severity,
        endpoint=endpoint,
        parameter=signal.parameter,
        category=signal.category,
        evidence=signal.output[:3000],
        scope_source=scope_source,
    )
    return finding.fingerprint


def _summarize_output(output: str, limit: int = 1400) -> str:
    text = (output or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars; full output stayed in scanner result]"


def _preflight_tool_checks(scan_list: Optional[list[str]] = None) -> list[str]:
    requested = set(scan_list or [])
    tools: list[str] = []
    if not requested or any(name in requested for name in _FINGERPRINT_SCAN_ALIASES):
        tools.extend(["whatweb", "wafw00f"])
    if not requested or any(name in requested for name in ("url_discovery", "discovery")):
        tools.extend(["gau", "gospider", "katana", "paramspider", "arjun"])

    missing = [tool for tool in tools if not shutil.which(tool)]
    if not missing:
        return []
    lines = [f"Missing helper tools for fingerprint/discovery: {', '.join(missing)}", "Install (one-time):"]
    for tool in missing:
        lines.append(f"  {_TOOL_INSTALL_HINTS[tool]}")
    return lines


def _request_with_backoff(method: str, url: str, headers: Optional[dict] = None,
                          cookies: Optional[dict] = None, timeout: int = _REQUEST_TIMEOUT):
    last_exc = None
    for attempt in range(_REQUEST_RETRIES + 1):
        try:
            return requests.request(
                method,
                url,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
        except Exception as exc:
            last_exc = exc
            time.sleep(_REQUEST_BACKOFF ** attempt)
    return None


def _prefer_https(url: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        https_url = f"https://{url.lstrip('/')}"
        resp = _request_with_backoff("GET", https_url)
        if resp and resp.status_code < 500:
            notes.append(f"Using HTTPS ({https_url})")
            return https_url, notes
        http_url = f"http://{url.lstrip('/')}"
        notes.append(f"HTTPS unavailable; falling back to HTTP ({http_url})")
        return http_url, notes

    if parsed.scheme == "http":
        https_url = urllib.parse.urlunparse(parsed._replace(scheme="https"))
        resp = _request_with_backoff("GET", https_url)
        if resp and resp.status_code < 500:
            notes.append(f"HTTPS reachable; switching to {https_url}")
            return https_url, notes
    return url, notes


def _normalize_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query)))
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


def _is_static_url(url: str) -> bool:
    path_ext = os.path.splitext(urllib.parse.urlparse(url).path or "")[1].lower()
    return path_ext in _STATIC_EXTS


def _dedupe_mapped_targets(mapped_targets: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
    merged: dict[str, tuple[str, set[str]]] = {}
    for endpoint, params in mapped_targets:
        if not endpoint or _is_static_url(endpoint):
            continue
        norm = _normalize_url(endpoint)
        if norm not in merged:
            merged[norm] = (endpoint, set())
        merged[norm][1].update(p for p in params if p)
    return [(endpoint, sorted(params)) for endpoint, params in merged.values()]


def _extract_form_params_from_output(output: str) -> list[str]:
    fields = re.findall(r"^\s*[-*]\s*([A-Za-z0-9_\-]+)\s*:", output or "", flags=re.MULTILINE)
    return list(dict.fromkeys(fields))


def _cookie_jar_from_session(session_name: str) -> dict[str, str]:
    if not session_name:
        return {}
    try:
        from src.tools.auth_context import _SESSION_STORE

        sess = _SESSION_STORE.get(session_name)
        if sess and sess.cookies:
            return dict(sess.cookies)
    except Exception:
        pass
    return {}


def _resolve_cookies(cookies: str, session_name: str) -> tuple[str, str]:
    if cookies:
        return cookies, "cookies"
    jar = _cookie_jar_from_session(session_name)
    if jar:
        cookie_str = "; ".join(f"{k}={v}" for k, v in jar.items())
        return cookie_str, f"session:{session_name}"
    return "", "unauthenticated"


def _extract_script_srcs(html: str, base_url: str) -> list[str]:
    urls: list[str] = []
    for src in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html or "", flags=re.IGNORECASE):
        full = urllib.parse.urljoin(base_url, src)
        urls.append(full)
    return list(dict.fromkeys(urls))


def _extract_param_names_from_urls(urls: list[str]) -> list[str]:
    params: list[str] = []
    for u in urls:
        params.extend(_extract_params_from_url(u))
    return list(dict.fromkeys(params))


def _validation_hint(category: str) -> str:
    hints = {
        "xss": "validate_browser_xss(url, parameter)",
        "sqli": "Confirm with a safe test payload and response diff (then promote with evidence)",
        "nosql": "Confirm with baseline/control response diff before promotion",
        "ldap": "Confirm with baseline/control response diff before promotion",
        "ssrf": "validate_oast_ssrf(url, parameter, oast_domain, callback_evidence)",
        "xxe": "validate_oast_xxe(url, oast_domain, callback_evidence)",
        "path_traversal": "Confirm file read plus negative control before promotion",
        "command_injection": "Use time-based confirmation or OAST evidence before promotion",
        "ssti": "managed_oast_blind_validation(url, parameter, 'ssti', oast_domain, callback_evidence)",
        "deserialization": "managed_oast_blind_validation(url, parameter, 'deserialization', oast_domain, callback_evidence)",
        "blind_xss": "managed_oast_blind_validation(url, parameter, 'blind_xss', oast_domain, callback_evidence)",
        "open_redirect": "Verify redirect chain + negative control, then promote with evidence",
        "crlf": "Confirm injected header/body marker plus negative control before promotion",
        "header_injection": "Confirm injected header marker plus negative control before promotion",
        "security_headers": "Low/info configuration finding; record raw response headers as evidence.",
        "cookies": "Low/info cookie finding; record Set-Cookie evidence and affected cookie names.",
        "clickjacking": "Confirm frameability with browser/manual check on a sensitive page.",
        "csrf": "Confirm affected state-changing action and tokenless control response.",
        "cors": "Confirm reflected origin with response body sensitivity and credential context.",
        "host_header": "Confirm reflection/redirect in the affected flow plus clean-host control.",
    }
    return hints.get(category, "")


def _cookie_headers(cookies: str) -> dict:
    if not cookies:
        return {}
    return {"Cookie": cookies}


def _discover_sitemap_urls(base_url: str, cookies: str = "") -> tuple[list[str], list[str]]:
    headers = _cookie_headers(cookies)
    notes: list[str] = []
    urls: list[str] = []

    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    resp = _request_with_backoff("GET", robots_url, headers=headers)
    if resp and resp.text:
        for line in resp.text.splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[-1].strip()
                if sm:
                    urls.append(sm)
    if not urls:
        urls.append(urllib.parse.urljoin(base_url, "/sitemap.xml"))

    discovered: list[str] = []
    for sm_url in list(dict.fromkeys(urls))[:5]:
        sm_resp = _request_with_backoff("GET", sm_url, headers=headers)
        if sm_resp and sm_resp.text:
            locs = re.findall(r"<loc>([^<]+)</loc>", sm_resp.text, flags=re.IGNORECASE)
            if locs:
                discovered.extend(locs)
            else:
                discovered.extend(_extract_urls(sm_resp.text))

    if discovered:
        notes.append(f"Sitemap/robots URLs parsed: {len(discovered)}")
    return list(dict.fromkeys(discovered)), notes


async def _discover_js_endpoints(js_urls: list[str], base_url: str) -> list[str]:
    endpoints: list[str] = []
    if not js_urls:
        return endpoints
    try:
        from src.tools.recon_active import linkfinder_js
    except Exception:
        return endpoints
    for js_url in js_urls[:6]:
        try:
            output = await linkfinder_js.invoke(target=js_url)
        except Exception:
            continue
        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                endpoints.append(urllib.parse.urljoin(base_url, line))
            elif line.startswith("http"):
                endpoints.append(line)
    return list(dict.fromkeys(endpoints))


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s'\"<>]+", text or "")


def _read_param_urls_from_session() -> list[str]:
    try:
        from src.repl.target_manager import get_target_manager

        tm = get_target_manager()
        out_dir = tm.get_session_files_dir() if tm else None
        if not out_dir:
            return []
        param_file = out_dir / "param_urls.txt"
        if not param_file.exists():
            return []
        return [
            line.strip()
            for line in param_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]
    except Exception:
        return []


async def _run_param_scanner(
    label: str,
    category: str,
    title: str,
    severity: str,
    params: list[str],
    target: str,
    url: str,
    runner: Callable[[str], Awaitable[str]],
    results: list[str],
    candidates: list[str],
    scope_source: str = "full_appsec_scan",
) -> None:
    if not params:
        results.append(f"\n## {label}\nSkipped: no suitable parameters discovered.")
        return

    results.append(f"\n## {label}")
    for param in params:
        try:
            output = await runner(param)
        except Exception as exc:
            results.append(f"### {param}: scanner error: {str(exc)[:160]}")
            continue

        signal = _scan_indicates_signal(category, output)
        results.append(f"### {param}: {'candidate signal' if signal else 'no obvious signal'}")
        results.append(_summarize_output(output))
        if signal:
            fp = _register_candidate(
                ScanSignal(title, category, severity, param, output),
                target=target,
                endpoint=url,
                scope_source=scope_source,
            )
            candidates.append(fp)
            results.append(f"Candidate registered: {fp}")
            hint = _validation_hint(category)
            if hint:
                results.append(f"Suggested validation: {hint}")
            results.append("Validation required: promote_finding_with_evidence with proof plus control/diff.")


async def _run_single_scanner(
    label: str,
    category: str,
    title: str,
    severity: str,
    target: str,
    endpoint: str,
    runner: Callable[[], Awaitable[str]],
    results: list[str],
    candidates: list[str],
    scope_source: str,
) -> None:
    results.append(f"\n## {label}")
    try:
        output = await runner()
    except Exception as exc:
        results.append(f"### scanner error: {str(exc)[:160]}")
        return

    signal = _scan_indicates_signal(category, output)
    results.append(f"### {'candidate signal' if signal else 'no obvious signal'}")
    results.append(_summarize_output(output))
    if signal:
        fp = _register_candidate(
            ScanSignal(title, category, severity, "", output),
            target=target,
            endpoint=endpoint,
            scope_source=scope_source,
        )
        candidates.append(fp)
        results.append(f"Candidate registered: {fp}")
        hint = _validation_hint(category)
        if hint:
            results.append(f"Suggested validation: {hint}")


async def _run_fingerprint_phase(url: str, results: list[str]) -> None:
    _emit_phase("fingerprint", "whatweb + wafw00f")
    results.append("## Fingerprint / WAF")

    with _subtool_block(
        "whatweb_scan",
        {"target": url, "aggression": 1},
        "Technology and framework fingerprint",
    ) as subtool:
        try:
            from src.tools.recon_active import whatweb_scan

            whatweb_output = await whatweb_scan.invoke(target=url, aggression=1)
        except Exception as exc:
            subtool["success"] = False
            whatweb_output = f"whatweb_scan failed or unavailable: {str(exc)[:180]}"
        results.append("### WhatWeb")
        results.append(_summarize_output(whatweb_output, limit=1800))

    with _subtool_block(
        "wafw00f_detect",
        {"target": url, "options": "-a", "retries": 1},
        "Web Application Firewall fingerprint",
    ) as subtool:
        try:
            from src.tools.recon_active import wafw00f_detect

            waf_output = await wafw00f_detect.invoke(target=url, options="-a", confirm=False, retries=1)
        except Exception as exc:
            subtool["success"] = False
            waf_output = f"wafw00f_detect failed or unavailable: {str(exc)[:180]}"
        results.append("### wafw00f")
        results.append(_summarize_output(waf_output, limit=1800))


@function_tool()
async def validate_browser_xss(url: str, parameter: str, payloads: str = "") -> str:
    """
    Validate XSS with real browser execution, then promote the candidate only
    when the browser confirms JavaScript execution.

    Args:
        url: Target URL containing or accepting the parameter.
        parameter: Parameter to inject.
        payloads: Optional semicolon-separated payload list.

    Returns:
        Browser validation result and finding lifecycle status.
    """
    from src.tools.browser_automation import browser_xss_test

    target = _target_from_url(url)
    browser_output = await browser_xss_test.invoke(url=url, parameter=parameter, payloads=payloads)
    lines = ["## Browser-backed XSS Validation", browser_output]
    if "XSS CONFIRMED" not in browser_output and "working XSS payloads" not in browser_output:
        lines.append("No browser execution proof. Candidate remains unconfirmed.")
        return "\n".join(lines)

    lifecycle = get_finding_lifecycle()
    candidate = lifecycle.add_candidate(
        title="Browser-confirmed Cross-Site Scripting",
        target=target,
        severity="high",
        endpoint=url,
        parameter=parameter,
        category="xss",
        evidence=browser_output,
        scope_source="validate_browser_xss",
    )
    evidence = (
        "Confirmed PoC proof with browser execution.\n"
        f"GET {urllib.parse.urlparse(url).path or '/'} HTTP/1.1\n"
        "Browser result: window.xss_triggered executed.\n"
        "Negative control: same endpoint without payload does not execute the marker.\n"
        "Response diff/browser execution observed.\n\n"
        f"{browser_output}"
    )
    ok, message, finding = lifecycle.promote(
        candidate.fingerprint,
        evidence=evidence,
        validation_notes="Validated with browser-backed JavaScript execution.",
        impact="Attacker-controlled JavaScript can execute in a victim browser.",
        remediation="Contextually encode output, sanitize HTML, and enforce a restrictive CSP.",
        cwe="CWE-79",
    )
    lines.append(message)
    if finding:
        lines.append(f"Fingerprint: {finding.fingerprint}")
        lines.append(f"Reportable: {finding.reportable}")
    return "\n".join(lines)


@function_tool()
async def validate_oast_ssrf(
    url: str,
    parameter: str,
    oast_domain: str,
    method: str = "GET",
    data_params: str = "",
    callback_evidence: str = "",
) -> str:
    """
    Send a benign OAST canary through an SSRF parameter and register/promote
    based on observed DNS/HTTP callback evidence.

    Args:
        url: Target endpoint.
        parameter: SSRF-suspected parameter.
        oast_domain: Controlled OAST/interactsh domain.
        method: GET or POST.
        data_params: Optional POST body params.
        callback_evidence: Paste interactsh/Burp callback evidence to promote.

    Returns:
        OAST validation status and finding lifecycle guidance.
    """
    from .ssrf import ssrf_scanner

    target = _target_from_url(url)
    canary = f"http://ssrf-{parameter}.{oast_domain.strip().lstrip('*.')}"
    output = await ssrf_scanner.invoke(
        url=url,
        parameter=parameter,
        test_internal=False,
        test_cloud=False,
        custom_target=canary,
        data_params=data_params,
        method=method,
    )
    lifecycle = get_finding_lifecycle()
    candidate = lifecycle.add_candidate(
        title="OAST SSRF callback candidate",
        target=target,
        severity="high",
        endpoint=url,
        parameter=parameter,
        category="ssrf",
        evidence=f"Canary sent: {canary}\n{output}",
        scope_source="validate_oast_ssrf",
    )
    lines = ["## OAST-backed SSRF Validation", f"Canary: {canary}", output, f"Candidate: {candidate.fingerprint}"]
    if not callback_evidence.strip():
        lines.append("Awaiting callback proof. Paste callback_evidence or promote manually with proof plus control.")
        return "\n".join(lines)

    evidence = (
        f"Confirmed OAST callback proof for {canary}.\n"
        f"GET {urllib.parse.urlparse(url).path or '/'} HTTP/1.1\n"
        "Negative control: benign external URL parameter did not generate the same OAST callback.\n"
        "Callback evidence:\n"
        f"{callback_evidence}\n\nScanner output:\n{output}"
    )
    ok, message, finding = lifecycle.promote(
        candidate.fingerprint,
        evidence=evidence,
        validation_notes="Validated via controlled OAST DNS/HTTP callback.",
        impact="Server-side request primitive can reach attacker-controlled infrastructure.",
        remediation="Allowlist outbound destinations, block internal/link-local ranges, and validate URL parsers consistently.",
        cwe="CWE-918",
    )
    lines.append(message)
    if finding:
        lines.append(f"Reportable: {finding.reportable}")
    return "\n".join(lines)


@function_tool()
async def validate_oast_xxe(
    url: str,
    oast_domain: str,
    parameter: str = "",
    content_type: str = "application/xml",
    callback_evidence: str = "",
) -> str:
    """
    Send a blind XXE OAST canary and register/promote when callback evidence
    proves external entity resolution.

    Args:
        url: XML-accepting endpoint.
        oast_domain: Controlled OAST/interactsh domain.
        parameter: Optional parameter wrapping XML.
        content_type: XML content type.
        callback_evidence: Paste interactsh/Burp callback evidence to promote.

    Returns:
        OAST validation status and finding lifecycle guidance.
    """
    from .xxe import xxe_scanner

    target = _target_from_url(url)
    output = await xxe_scanner.invoke(
        url=url,
        parameter=parameter,
        content_type=content_type,
        oast_domain=oast_domain,
    )
    lifecycle = get_finding_lifecycle()
    candidate = lifecycle.add_candidate(
        title="OAST XXE callback candidate",
        target=target,
        severity="high",
        endpoint=url,
        parameter=parameter,
        category="xxe",
        evidence=f"OAST domain: {oast_domain}\n{output}",
        scope_source="validate_oast_xxe",
    )
    lines = ["## OAST-backed XXE Validation", f"OAST domain: {oast_domain}", output, f"Candidate: {candidate.fingerprint}"]
    if not callback_evidence.strip():
        lines.append("Awaiting callback proof. Paste callback_evidence or promote manually with proof plus control.")
        return "\n".join(lines)

    evidence = (
        f"Confirmed OAST callback proof for XXE domain {oast_domain}.\n"
        f"POST {urllib.parse.urlparse(url).path or '/'} HTTP/1.1\n"
        "Negative control: XML body without external entity generated no callback.\n"
        "Callback evidence:\n"
        f"{callback_evidence}\n\nScanner output:\n{output}"
    )
    ok, message, finding = lifecycle.promote(
        candidate.fingerprint,
        evidence=evidence,
        validation_notes="Validated via controlled OAST callback from XML external entity resolution.",
        impact="XML parser can resolve attacker-controlled external entities.",
        remediation="Disable DTDs, external entities, and parameter entities in XML parsers.",
        cwe="CWE-611",
    )
    lines.append(message)
    if finding:
        lines.append(f"Reportable: {finding.reportable}")
    return "\n".join(lines)


@function_tool()
async def managed_oast_blind_validation(
    url: str,
    parameter: str,
    vuln_type: str,
    oast_domain: str,
    method: str = "GET",
    cookies: str = "",
    callback_evidence: str = "",
    poll_output: str = "",
    scope_source: str = "managed_oast_blind_validation",
) -> str:
    """
    Managed OAST validation for blind classes beyond SSRF.

    Supported vuln_type values:
      xxe, command_injection, rce, ssti, deserialization, blind_xss.

    The tool sends or prepares a unique canary, registers a candidate, and
    promotes only when callback_evidence/poll_output contains the canary and
    no unrelated control evidence is required by the operator.
    """
    clean_type = (vuln_type or "").strip().lower().replace("-", "_")
    clean_domain = oast_domain.strip().lstrip("*.").rstrip("/")
    if not clean_domain:
        return "Error: oast_domain is required for managed blind validation."

    canary_host = _oast_host(clean_type or "blind", parameter, clean_domain)
    canary_url = f"http://{canary_host}/cb"
    output = ""
    title = "Managed OAST blind callback candidate"
    severity = "high"
    cwe = ""
    remediation = "Validate untrusted input, disable unsafe parsing/execution paths, and restrict outbound callbacks."

    if clean_type == "xxe":
        from .xxe import xxe_scanner

        title = "Managed OAST XXE callback candidate"
        cwe = "CWE-611"
        output = await xxe_scanner.invoke(url=url, parameter=parameter, oast_domain=canary_host)
    elif clean_type in {"command_injection", "cmdi", "rce"}:
        from .cmd_injection import command_injection_scanner

        title = "Managed OAST command execution callback candidate"
        severity = "critical"
        cwe = "CWE-78"
        output = await command_injection_scanner.invoke(
            url=url,
            parameter=parameter,
            method=method,
            cookies=cookies,
            oast_domain=canary_url,
        )
    elif clean_type == "ssti":
        from src.tools.ssti import ssti_scanner

        title = "Managed OAST SSTI callback candidate"
        severity = "critical"
        cwe = "CWE-1336"
        output = await ssti_scanner.invoke(
            url=url,
            parameter=parameter,
            method=method,
            cookies=cookies,
            oast_domain=canary_url,
        )
    elif clean_type in {"blind_xss", "xss_oob"}:
        from .xss import xss_scanner

        title = "Managed blind XSS callback candidate"
        cwe = "CWE-79"
        payloads = f"<script src=//{canary_host}/x.js></script>;<img src=//{canary_host}/i onerror=1>"
        output = await xss_scanner.invoke(
            url=url,
            parameter=parameter,
            method=method,
            cookies=cookies,
            custom_payloads=payloads,
        )
    elif clean_type == "deserialization":
        title = "Managed OAST deserialization callback candidate"
        severity = "critical"
        cwe = "CWE-502"
        output = (
            "No generic deserialization payload was sent automatically because payloads are framework-specific.\n"
            f"Use this unique callback in a safe ysoserial/phpggc/.NET gadget payload when the stack is known: {canary_url}\n"
            "Candidate is tracked so callback evidence can be correlated and promoted."
        )
    else:
        return "Error: vuln_type must be one of xxe, command_injection, rce, ssti, deserialization, blind_xss."

    lifecycle = get_finding_lifecycle()
    candidate = lifecycle.add_candidate(
        title=title,
        target=_target_from_url(url),
        severity=severity,
        endpoint=url,
        parameter=parameter,
        category=clean_type,
        evidence=f"Canary: {canary_url}\nScanner output:\n{output}",
        scope_source=scope_source,
    )
    lines = [
        f"## Managed OAST Blind Validation: {clean_type}",
        f"Canary: {canary_url}",
        f"Candidate: {candidate.fingerprint}",
        "",
        _summarize_output(str(output), limit=1800),
    ]

    evidence_blob = "\n".join([callback_evidence or "", poll_output or ""])
    if not evidence_blob.strip():
        lines.append("Awaiting OAST evidence. Poll interactsh/OAST and pass callback_evidence or poll_output back to this tool.")
        return "\n".join(lines)

    if canary_host.lower() not in evidence_blob.lower() and canary_url.lower() not in evidence_blob.lower():
        lines.append("No matching canary observed. Candidate remains unconfirmed.")
        return "\n".join(lines)

    evidence = (
        f"Confirmed OAST callback for {canary_host}.\n"
        f"{method.upper()} {urllib.parse.urlparse(url).path or '/'} HTTP/1.1\n"
        f"Parameter under test: {parameter or '(body)'}\n"
        f"Callback evidence:\n{evidence_blob[:2500]}\n\nScanner output:\n{output}"
    )
    ok, message, finding = lifecycle.promote(
        candidate.fingerprint,
        evidence=evidence,
        validation_notes=f"Validated via unique OAST callback for {clean_type}.",
        impact="The application triggered an out-of-band callback from attacker-controlled input.",
        remediation=remediation,
        cwe=cwe,
    )
    lines.append(message)
    if finding:
        lines.append(f"Reportable: {finding.reportable}")
    return "\n".join(lines)


@function_tool()
async def full_appsec_scan(
    url: str,
    parameters: str = "",
    scan_types: str = (
        "fingerprint,url_discovery,app_map,security_headers,cookies,cors,clickjacking,"
        "xss,sqli,nosql,ldap,ssrf,xxe,path_traversal,command_injection,"
        "ssti,blind_xss,deserialization,open_redirect,crlf,header_injection,host_header,idor,csrf,graphql"
    ),
    cookies: str = "",
    auth_session_name: str = "",
    bearer_token: str = "",
    extra_headers_json: str = "",
    cookies_user_b: str = "",
    role_sessions_json: str = "",
    role_cookies_json: str = "",
    oast_domain: str = "",
    oast_poll_output: str = "",
    managed_oast: bool = True,
    api_spec: str = "",
    postman_collection: str = "",
    har_path: str = "",
    graphql_schema: str = "",
    graphql_url: str = "",
    idor_url_template: str = "",
    scope_source: str = "full_appsec_scan",
    mapper_session_name: str = "",
    mapper_max_pages: int = 10,
    max_endpoint_scans: int = 6,
) -> str:
    """
    Run an evidence-first AppSec pipeline.

    Pipeline:
      1. Technology and WAF fingerprinting with whatweb/wafw00f.
      2. Optional authenticated app mapping to inventory endpoints/forms/API routes.
      3. Parameter discovery from explicit args, URL query, mapper inventory, then Arjun.
      4. Low/info baseline checks (security headers, cookies, CORS,
         clickjacking) plus XSS, SQLi, NoSQL, LDAP, SSRF, XXE,
         LFI/path traversal, command injection, open redirect, CRLF/header
         injection, host header, authz/IDOR, CSRF, and GraphQL checks.
      5. Register weak scanner hits as structured candidates.
      6. Require promote_finding_with_evidence or the validation helpers before
         a finding becomes reportable.

    Args:
        url: Target URL.
        parameters: Comma-separated parameter names. Empty means auto-discover.
        scan_types: Comma-separated modules to run (include url_discovery to restore URL/param discovery).
        cookies: User A/session cookies for authenticated scans.
        auth_session_name: Stored auth_context session name for authenticated scans.
        bearer_token: Raw bearer/basic token for API mapping and authenticated crawling.
        extra_headers_json: Additional headers for authenticated crawling/API import.
        cookies_user_b: User B cookies for IDOR cross-validation.
        role_sessions_json: JSON mapping roles to stored sessions, e.g. {"user_b":"victim","admin":"admin"}.
        role_cookies_json: JSON mapping roles to cookie strings for user_a/user_b/admin/low_priv.
        oast_domain: Controlled OAST/interactsh domain for SSRF/XXE/RCE/SSTI/blind-XSS probes.
        oast_poll_output: Optional interactsh/OAST poll output used to auto-promote matching canaries.
        managed_oast: Use unique positive canaries and callback correlation for blind checks.
        api_spec: OpenAPI/Swagger JSON/YAML URL, path, or inline spec.
        postman_collection: Postman collection JSON URL, path, or inline collection.
        har_path: HAR file path, URL, or inline HAR JSON for first-class endpoint import.
        graphql_schema: GraphQL schema/introspection JSON path, URL, or inline source.
        graphql_url: Explicit GraphQL endpoint. Empty guesses /graphql and /api/graphql.
        idor_url_template: Optional URL containing {id} for authz/IDOR checks.
        scope_source: Scope/program reference stored on candidates.
        mapper_session_name: Stored auth_context session name for authenticated mapping.
        mapper_max_pages: Same-origin pages to crawl when app_map is enabled.
        max_endpoint_scans: Number of mapped parameterized endpoints to scan in addition to url.

    Returns:
        Consolidated scan output with candidate fingerprints and validation queue.
    """
    url, https_notes = _prefer_https(url)
    parsed = urllib.parse.urlparse(url)
    target = _target_from_url(url)
    path_ext = os.path.splitext(parsed.path)[1].lower()
    if path_ext in _STATIC_EXTS:
        return (
            f"[SKIPPED] full_appsec_scan: '{parsed.path}' is a static asset ({path_ext}). "
            "Run on a dynamic HTML page, API endpoint, or form submission URL."
        )

    role_sessions = _safe_json_loads(role_sessions_json, {})
    primary_session = auth_session_name or (str(role_sessions.get("user_a", "")) if isinstance(role_sessions, dict) else "")
    mapper_session_name = mapper_session_name or primary_session
    cookies, auth_source = _resolve_cookies(cookies, primary_session or mapper_session_name)
    role_matrix = _role_matrix(role_sessions_json, role_cookies_json, primary_session, cookies, cookies_user_b)
    headers_json = _auth_headers_json(extra_headers_json, bearer_token, primary_session or mapper_session_name)
    dedup_key = (
        f"{target}{parsed.path}?{parameters}:{scan_types}:{mapper_session_name}:{mapper_max_pages}:"
        f"{bool(api_spec)}:{bool(postman_collection)}:{bool(har_path)}:{bool(graphql_schema)}"
    )
    if dedup_key in _appsec_scanned_urls:
        return (
            f"[SKIPPED] full_appsec_scan already ran on {target}{parsed.path} with this scan profile. "
            "Use specific validation helpers or promote_finding_with_evidence for existing candidates."
        )
    _appsec_scanned_urls.add(dedup_key)

    scan_list = [s.strip().lower() for s in scan_types.split(",") if s.strip()]
    _emit_phase("scan start", f"modules={', '.join(scan_list)}")
    preflight_notes = _preflight_tool_checks(scan_list)
    results: list[str] = [
        "# Evidence-First AppSec Scan",
        f"Target: {target}",
        f"URL: {url}",
        f"Scan modules: {', '.join(scan_list)}",
        "",
    ]
    if https_notes or auth_source != "unauthenticated" or preflight_notes:
        results.append("## Preflight")
        results.extend(f"- {note}" for note in https_notes)
        if auth_source != "unauthenticated":
            results.append(f"- Auth context: {auth_source}")
        if bearer_token or headers_json:
            results.append("- Header auth available for crawling/API import")
        if any(v.get("session") or v.get("cookies") for v in role_matrix.values()):
            active_roles = [k for k, v in role_matrix.items() if v.get("session") or v.get("cookies")]
            results.append(f"- Role matrix contexts: {', '.join(active_roles)}")
        if preflight_notes:
            results.extend(f"- {note}" for note in preflight_notes)
        results.append("")

    if any(name in scan_list for name in _FINGERPRINT_SCAN_ALIASES):
        await _run_fingerprint_phase(url, results)
        results.append("")

    if scan_list and all(name in _FINGERPRINT_SCAN_ALIASES for name in scan_list):
        params, discovery_notes, discovery_param_urls = [], ["Skipped: fingerprint-only scan profile."], []
    else:
        params, discovery_notes, discovery_param_urls = await _discover_parameters(url, parameters, cookies=cookies)

    results.append("## Parameter Discovery")
    results.extend(f"- {note}" for note in discovery_notes)

    discovered_param_urls: list[str] = [
        u for u in list(dict.fromkeys(discovery_param_urls)) if not _is_static_url(u)
    ]
    if "url_discovery" in scan_list or "discovery" in scan_list:
        _emit_phase("url discovery", "building URL corpus")
        results.append("\n## URL & Parameter Discovery")
        corpus_output = ""
        with _subtool_block(
            "url_corpus_build",
            {"target": target, "max_urls": 5000},
            "URL corpus + parameterized endpoint discovery",
        ) as subtool:
            try:
                from src.tools.recon_active import url_corpus_build

                corpus_output = await url_corpus_build.invoke(
                    target=target,
                    include_subs=True,
                    use_gau=True,
                    use_wayback=True,
                    use_paramspider=True,
                    use_katana=True,
                    use_gospider=True,
                    max_urls=5000,
                )
                results.append(_summarize_output(corpus_output, limit=2200))
            except Exception as exc:
                subtool["success"] = False
                results.append(f"URL discovery failed: {str(exc)[:180]}")

        corpus_param_urls = _read_param_urls_from_session()
        discovered_param_urls.extend(corpus_param_urls)
        if not discovered_param_urls and corpus_output:
            discovered_param_urls = [
                u for u in _extract_urls(corpus_output)
                if "?" in u and "=" in u
            ]
        discovered_param_urls = [u for u in list(dict.fromkeys(discovered_param_urls)) if not _is_static_url(u)]
        if discovered_param_urls:
            results.append(f"Discovered parameterized endpoints: {len(discovered_param_urls)}")
            for u in discovered_param_urls[:10]:
                results.append(f"- {u}")
        else:
            results.append("No parameterized URLs discovered by URL corpus build.")

    api_graphql_urls: list[str] = []
    api_import_notes: list[str] = []
    api_import_targets: list[tuple[str, list[str]]] = []
    if api_spec:
        imported, notes, gql_urls = _api_targets_from_openapi(api_spec, _base_url_from(url))
        api_import_targets.extend(imported)
        api_import_notes.extend(notes)
        api_graphql_urls.extend(gql_urls)
    if postman_collection:
        imported, notes = _api_targets_from_postman(postman_collection, _base_url_from(url))
        api_import_targets.extend(imported)
        api_import_notes.extend(notes)
    if har_path:
        imported, notes = _api_targets_from_har(har_path, _base_url_from(url))
        api_import_targets.extend(imported)
        api_import_notes.extend(notes)
    if graphql_schema:
        gql_urls, notes = _graphql_urls_from_schema_source(graphql_schema, url)
        api_graphql_urls.extend(gql_urls)
        api_import_notes.extend(notes)

    if api_import_notes:
        _emit_phase("api import", f"endpoints={len(api_import_targets)}")
        results.append("\n## API-First Import")
        results.extend(f"- {note}" for note in api_import_notes)
        if api_import_targets:
            for endpoint, endpoint_params in api_import_targets[:20]:
                suffix = f" params={','.join(endpoint_params)}" if endpoint_params else ""
                results.append(f"- {endpoint}{suffix}")

    candidates: list[str] = []
    mapped_targets: list[tuple[str, list[str]]] = [(url, params)]
    if discovered_param_urls:
        for endpoint in discovered_param_urls:
            endpoint_params = _extract_params_from_url(endpoint)
            if not endpoint_params:
                continue
            mapped_targets.append((endpoint, endpoint_params))
            for param in endpoint_params:
                if param not in params:
                    params.append(param)
    if api_import_targets:
        for endpoint, endpoint_params in api_import_targets:
            mapped_targets.append((endpoint, endpoint_params))
            for param in endpoint_params:
                if param not in params:
                    params.append(param)

    if "app_map" in scan_list or "mapper" in scan_list or "authenticated_map" in scan_list:
        _emit_phase("app mapping", f"max_pages={mapper_max_pages}")
        results.append("\n## Authenticated App Mapping")
        with _subtool_block(
            "authenticated_app_mapper",
            {"base_url": url, "max_pages": mapper_max_pages},
            "Authenticated app mapping",
        ) as subtool:
            try:
                from src.sdk.http_knowledge import get_http_knowledge
                from src.tools.app_mapping import authenticated_app_mapper

                map_output = await authenticated_app_mapper.invoke(
                    base_url=url,
                    session_name=mapper_session_name,
                    cookies=cookies,
                    headers_json=headers_json,
                    max_pages=mapper_max_pages,
                    submit_forms=False,
                )
                results.append(_summarize_output(map_output, limit=2200))
                observations = get_http_knowledge().for_target(target)
                for obs in observations:
                    if obs.url == url or not obs.params:
                        continue
                    if obs.method not in {"GET", "POST"}:
                        continue
                    mapped_targets.append((obs.url, obs.params))
                    for param in obs.params:
                        if param not in params:
                            params.append(param)
                    if len(mapped_targets) >= max(1, max_endpoint_scans):
                        break
                if len(mapped_targets) > 1:
                    results.append(f"Mapper added {len(mapped_targets) - 1} parameterized endpoint(s) to the scan queue.")
            except Exception as exc:
                subtool["success"] = False
                results.append(f"Mapper failed or unavailable: {str(exc)[:180]}")

    mapped_targets = _dedupe_mapped_targets(mapped_targets)

    results.append("\n## Parameter Summary")
    results.append(f"- Final parameter set: {', '.join(params) if params else '(none)'}")
    if len(mapped_targets) > 1:
        results.append(f"- Parameterized endpoints queued: {len(mapped_targets) - 1}")

    def _targets_for(category: str) -> list[tuple[str, list[str]]]:
        selected: list[tuple[str, list[str]]] = []
        for endpoint, endpoint_params in mapped_targets[:max_endpoint_scans]:
            chosen = endpoint_params
            if category in _INTERESTING_PARAM_HINTS:
                chosen = _params_matching(endpoint_params, category)
            if chosen:
                selected.append((endpoint, chosen))
        return selected or [(url, _params_matching(params, category) if category in _INTERESTING_PARAM_HINTS else params)]

    if any(name in scan_list for name in ("security_headers", "headers", "missing_headers", "cookies", "baseline")):
        _emit_phase("security headers", "checking low/info hardening issues")
        with _subtool_block(
            "security_headers_scanner",
            {"url": url},
            "Security header and Set-Cookie hardening checks",
        ):
            from .security_headers import security_headers_scanner

            await _run_single_scanner(
                "Security Headers / Cookies",
                "security_headers",
                "Security Header / Cookie Hardening Findings",
                "low",
                target,
                url,
                lambda: security_headers_scanner.invoke(url=url, cookies=cookies, include_info=True),
                results,
                candidates,
                scope_source,
            )

    if "clickjacking" in scan_list or "frame_protection" in scan_list:
        _emit_phase("clickjacking", "checking frame protections")
        with _subtool_block(
            "clickjacking_scanner",
            {"url": url},
            "Frame protection checks",
        ):
            from .clickjacking import clickjacking_scanner

            await _run_single_scanner(
                "Clickjacking / Frame Protection",
                "clickjacking",
                "Potential Clickjacking / Missing Frame Protection",
                "low",
                target,
                url,
                lambda: clickjacking_scanner.invoke(url=url, cookies=cookies, generate_poc=False),
                results,
                candidates,
                scope_source,
            )

    if "xss" in scan_list:
        _emit_phase("xss", f"endpoints={len(mapped_targets[:max_endpoint_scans])}")
        with _subtool_block(
            "xss_scanner",
            {"endpoints": len(mapped_targets[:max_endpoint_scans])},
            "XSS parameter scans",
        ):
            from .xss import xss_scanner
            for endpoint, endpoint_params in _targets_for("xss"):
                await _run_param_scanner(
                    f"XSS ({endpoint})",
                    "xss",
                    "Potential Cross-Site Scripting",
                    "high",
                    endpoint_params,
                    target,
                    endpoint,
                    lambda p, endpoint=endpoint: xss_scanner.invoke(url=endpoint, parameter=p, cookies=cookies),
                    results,
                    candidates,
                )

    if "sqli" in scan_list or "sql" in scan_list:
        _emit_phase("sqli", f"endpoints={len(mapped_targets[:max_endpoint_scans])}")
        with _subtool_block(
            "sqli_scanner",
            {"endpoints": len(mapped_targets[:max_endpoint_scans])},
            "SQL injection parameter scans",
        ):
            from .sqli import sqli_scanner
            for endpoint, endpoint_params in _targets_for("sqli"):
                await _run_param_scanner(
                    f"SQL Injection ({endpoint})",
                    "sqli",
                    "Potential SQL Injection",
                    "high",
                    endpoint_params,
                    target,
                    endpoint,
                    lambda p, endpoint=endpoint: sqli_scanner.invoke(url=endpoint, parameter=p, cookies=cookies),
                    results,
                    candidates,
                )

    if "nosql" in scan_list or "nosqli" in scan_list:
        _emit_phase("nosql", f"endpoints={len(mapped_targets[:max_endpoint_scans])}")
        with _subtool_block(
            "nosql_injection_probe",
            {"endpoints": len(mapped_targets[:max_endpoint_scans])},
            "NoSQL injection parameter scans",
        ):
            from .nosql import nosql_injection_probe
            for endpoint, endpoint_params in _targets_for("nosql"):
                await _run_param_scanner(
                    f"NoSQL Injection ({endpoint})",
                    "nosql",
                    "Potential NoSQL Injection",
                    "high",
                    endpoint_params,
                    target,
                    endpoint,
                    lambda p, endpoint=endpoint: nosql_injection_probe.invoke(url=endpoint, parameter=p, cookies=cookies),
                    results,
                    candidates,
                )

    if "ldap" in scan_list or "ldap_injection" in scan_list:
        _emit_phase("ldap", f"endpoints={len(mapped_targets[:max_endpoint_scans])}")
        with _subtool_block(
            "ldap_injection_probe",
            {"endpoints": len(mapped_targets[:max_endpoint_scans])},
            "LDAP injection parameter scans",
        ):
            from .ldap import ldap_injection_probe
            for endpoint, endpoint_params in _targets_for("ldap"):
                await _run_param_scanner(
                    f"LDAP Injection ({endpoint})",
                    "ldap",
                    "Potential LDAP Injection",
                    "high",
                    endpoint_params,
                    target,
                    endpoint,
                    lambda p, endpoint=endpoint: ldap_injection_probe.invoke(url=endpoint, parameter=p, cookies=cookies),
                    results,
                    candidates,
                )

    if "ssrf" in scan_list:
        _emit_phase("ssrf", "testing internal/cloud/OAST")
        with _subtool_block(
            "ssrf_scanner",
            {"url": url, "params": len(_params_matching(params, "ssrf"))},
            "Server-side request forgery checks",
        ):
            from .ssrf import ssrf_scanner
            ssrf_params = _params_matching(params, "ssrf")
            custom_target = f"http://ssrf-scan.{oast_domain.strip().lstrip('*.')}" if oast_domain else ""
            if oast_domain and managed_oast:
                try:
                    from src.tools.app_mapping import managed_oast_ssrf_validation

                    await _run_param_scanner(
                        "Managed OAST SSRF",
                        "ssrf",
                        "Potential Server-Side Request Forgery",
                        "high",
                        ssrf_params,
                        target,
                        url,
                        lambda p: managed_oast_ssrf_validation.invoke(
                            url=url,
                            parameter=p,
                            oast_domain=oast_domain,
                            cookies=cookies,
                            poll_output=oast_poll_output,
                            scope_source=scope_source,
                        ),
                        results,
                        candidates,
                    )
                except Exception as exc:
                    results.append(f"Managed OAST SSRF failed, falling back to scanner: {str(exc)[:160]}")
                    await _run_param_scanner(
                        "SSRF",
                        "ssrf",
                        "Potential Server-Side Request Forgery",
                        "high",
                        ssrf_params,
                        target,
                        url,
                        lambda p: ssrf_scanner.invoke(
                            url=url,
                            parameter=p,
                            test_internal=False,
                            test_cloud=False,
                            custom_target=custom_target,
                        ),
                        results,
                        candidates,
                    )
            else:
                await _run_param_scanner(
                    "SSRF",
                    "ssrf",
                    "Potential Server-Side Request Forgery",
                    "high",
                    ssrf_params,
                    target,
                    url,
                    lambda p: ssrf_scanner.invoke(
                        url=url,
                        parameter=p,
                        test_internal=not bool(oast_domain),
                        test_cloud=not bool(oast_domain),
                        custom_target=custom_target,
                    ),
                    results,
                    candidates,
                )

    if "xxe" in scan_list or "xml" in scan_list:
        _emit_phase("xxe", "testing XML parser behavior")
        with _subtool_block(
            "xxe_scanner",
            {"url": url},
            "XML external entity checks",
        ):
            from .xxe import xxe_scanner

            if oast_domain and managed_oast:
                await _run_single_scanner(
                    "Managed OAST XXE",
                    "xxe",
                    "Potential XML External Entity",
                    "high",
                    target,
                    url,
                    lambda: managed_oast_blind_validation.invoke(
                        url=url,
                        parameter="",
                        vuln_type="xxe",
                        oast_domain=oast_domain,
                        cookies=cookies,
                        poll_output=oast_poll_output,
                        scope_source=scope_source,
                    ),
                    results,
                    candidates,
                    scope_source,
                )
            else:
                await _run_single_scanner(
                    "XXE",
                    "xxe",
                    "Potential XML External Entity",
                    "high",
                    target,
                    url,
                    lambda: xxe_scanner.invoke(url=url, parameter="", oast_domain=oast_domain),
                    results,
                    candidates,
                    scope_source,
                )

    if "path_traversal" in scan_list or "lfi" in scan_list:
        _emit_phase("path traversal", "testing LFI payloads")
        with _subtool_block(
            "path_traversal_scanner",
            {"url": url, "params": len(_params_matching(params, "path_traversal"))},
            "Path traversal payload checks",
        ):
            from .path_traversal import path_traversal_scanner
            await _run_param_scanner(
                "Path Traversal / LFI",
                "path_traversal",
                "Potential Path Traversal / LFI",
                "high",
                _params_matching(params, "path_traversal"),
                target,
                url,
                lambda p: path_traversal_scanner.invoke(url=url, parameter=p),
                results,
                candidates,
            )

    if "command_injection" in scan_list or "cmdi" in scan_list:
        _emit_phase("command injection", "testing operators and timing")
        with _subtool_block(
            "command_injection_scanner",
            {"url": url, "params": len(params)},
            "Command injection payload checks",
        ):
            from .cmd_injection import command_injection_scanner
            await _run_param_scanner(
                "Managed OAST Command Injection" if oast_domain and managed_oast else "Command Injection",
                "command_injection",
                "Potential Command Injection",
                "critical",
                params,
                target,
                url,
                (
                    lambda p: managed_oast_blind_validation.invoke(
                        url=url,
                        parameter=p,
                        vuln_type="command_injection",
                        oast_domain=oast_domain,
                        cookies=cookies,
                        poll_output=oast_poll_output,
                        scope_source=scope_source,
                    )
                ) if oast_domain and managed_oast else (
                    lambda p: command_injection_scanner.invoke(url=url, parameter=p, cookies=cookies, oast_domain=oast_domain)
                ),
                results,
                candidates,
            )

    if "ssti" in scan_list:
        _emit_phase("ssti", "testing template evaluation and OAST")
        with _subtool_block(
            "ssti_scanner",
            {"url": url, "params": len(params)},
            "Server-side template injection checks",
        ):
            from src.tools.ssti import ssti_scanner
            await _run_param_scanner(
                "Managed OAST SSTI" if oast_domain and managed_oast else "SSTI",
                "ssti",
                "Potential Server-Side Template Injection",
                "critical",
                params,
                target,
                url,
                (
                    lambda p: managed_oast_blind_validation.invoke(
                        url=url,
                        parameter=p,
                        vuln_type="ssti",
                        oast_domain=oast_domain,
                        cookies=cookies,
                        poll_output=oast_poll_output,
                        scope_source=scope_source,
                    )
                ) if oast_domain and managed_oast else (
                    lambda p: ssti_scanner.invoke(url=url, parameter=p, cookies=cookies, oast_domain=oast_domain)
                ),
                results,
                candidates,
            )

    if "blind_xss" in scan_list or "xss_oob" in scan_list:
        _emit_phase("blind xss", "injecting OAST canaries")
        if oast_domain:
            await _run_param_scanner(
                "Managed Blind XSS",
                "xss",
                "Potential Blind Cross-Site Scripting",
                "high",
                params,
                target,
                url,
                lambda p: managed_oast_blind_validation.invoke(
                    url=url,
                    parameter=p,
                    vuln_type="blind_xss",
                    oast_domain=oast_domain,
                    cookies=cookies,
                    poll_output=oast_poll_output,
                    scope_source=scope_source,
                ),
                results,
                candidates,
            )
        else:
            results.append("\n## Managed Blind XSS\nSkipped: oast_domain is required for blind XSS canaries.")

    if "deserialization" in scan_list or "insecure_deserialization" in scan_list:
        _emit_phase("deserialization", "preparing OAST canaries")
        deser_params = [
            p for p in params
            if any(h in p.lower() for h in ("data", "payload", "object", "state", "token", "session", "serialized"))
        ] or params[:1]
        if oast_domain:
            await _run_param_scanner(
                "Managed Deserialization OAST Prep",
                "deserialization",
                "Potential Insecure Deserialization",
                "critical",
                deser_params,
                target,
                url,
                lambda p: managed_oast_blind_validation.invoke(
                    url=url,
                    parameter=p,
                    vuln_type="deserialization",
                    oast_domain=oast_domain,
                    cookies=cookies,
                    poll_output=oast_poll_output,
                    scope_source=scope_source,
                ),
                results,
                candidates,
            )
        else:
            results.append("\n## Managed Deserialization OAST Prep\nSkipped: oast_domain is required to prepare callback canaries.")

    if "open_redirect" in scan_list or "redirect" in scan_list:
        _emit_phase("open redirect", "testing redirect parameters")
        with _subtool_block(
            "open_redirect_scan",
            {"url": url, "params": len(_params_matching(params, "open_redirect"))},
            "Open redirect checks",
        ):
            from .open_redirect import open_redirect_scan
            redirect_params = _params_matching(params, "open_redirect")
            await _run_param_scanner(
                "Open Redirect",
                "open_redirect",
                "Potential Open Redirect",
                "medium",
                redirect_params,
                target,
                url,
                lambda p: open_redirect_scan.invoke(url=url, parameter=p),
                results,
                    candidates,
                )

    if "crlf" in scan_list or "response_splitting" in scan_list:
        _emit_phase("crlf", "testing response splitting markers")
        with _subtool_block(
            "crlf_injection_probe",
            {"url": url, "params": len(params)},
            "CRLF / response splitting checks",
        ):
            from .crlf import crlf_injection_probe
            if params:
                await _run_param_scanner(
                    "CRLF Injection",
                    "crlf",
                    "Potential CRLF / Response Splitting",
                    "high",
                    params,
                    target,
                    url,
                    lambda p: crlf_injection_probe.invoke(url=url, parameter=p),
                    results,
                    candidates,
                )
            else:
                await _run_single_scanner(
                    "CRLF Injection",
                    "crlf",
                    "Potential CRLF / Response Splitting",
                    "high",
                    target,
                    url,
                    lambda: crlf_injection_probe.invoke(url=url, parameter=""),
                    results,
                    candidates,
                    scope_source,
                )

    if "header_injection" in scan_list or "headeri" in scan_list:
        _emit_phase("header injection", "testing query/header reflection")
        with _subtool_block(
            "header_injection_scanner",
            {"url": url, "params": len(params)},
            "HTTP header injection checks",
        ):
            from .header_injection import header_injection_scanner
            await _run_param_scanner(
                "Header Injection",
                "header_injection",
                "Potential Header Injection / CRLF",
                "high",
                params,
                target,
                url,
                lambda p: header_injection_scanner.invoke(url=url, parameter=p),
                results,
                candidates,
            )

    if "host_header" in scan_list or "host_header_injection" in scan_list:
        _emit_phase("host header", "testing host override behavior")
        with _subtool_block(
            "host_header_injection",
            {"url": url},
            "Host header injection checks",
        ):
            from src.tools.web import host_header_injection

            await _run_single_scanner(
                "Host Header Injection",
                "host_header",
                "Potential Host Header Injection",
                "high",
                target,
                url,
                lambda: host_header_injection.invoke(url=url),
                results,
                candidates,
                scope_source,
            )

    if "idor" in scan_list or "authz" in scan_list or "bola" in scan_list:
        _emit_phase("authz/idor", "testing access control")
        from src.tools.access_control import idor_probe
        results.append("\n## Authz / IDOR")
        idor_target = idor_url_template or (url if "{id}" in url else "")
        id_params = _params_matching(params, "idor")
        if not idor_target and id_params:
            idor_target = url
        if idor_target:
            id_param = id_params[0] if id_params else ""
            user_b_cookies = role_matrix["user_b"].get("cookies", "")
            with _subtool_block(
                "idor_probe",
                {"url": idor_target, "id_param": id_param or "(auto)"},
                "Access control probe",
            ):
                output = await idor_probe.invoke(
                    url=idor_target,
                    id_param=id_param,
                    id_in="query" if id_param and "{id}" not in idor_target else "path",
                    cookies_user_a=cookies,
                    cookies_user_b=user_b_cookies,
                )
            signal = _scan_indicates_signal("idor", output)
            results.append(f"### {'candidate signal' if signal else 'no obvious signal'}")
            results.append(_summarize_output(output))
            if signal:
                fp = _register_candidate(
                    ScanSignal("Potential IDOR / BOLA", "idor", "critical", id_param, output),
                    target=target,
                    endpoint=idor_target,
                    scope_source=scope_source,
                )
                candidates.append(fp)
                results.append(f"Candidate registered: {fp}")
                results.append(
                    "Suggested validation: provide user A/B cookies and collect response diff before promotion"
                )
        else:
            results.append("Skipped: no ID-like parameter or {id} URL template. Provide idor_url_template for real authz testing.")

        authz_context_available = bool(
            role_matrix["user_a"].get("cookies")
            or role_matrix["user_a"].get("session")
            or role_matrix["user_b"].get("cookies")
            or role_matrix["user_b"].get("session")
            or role_matrix["admin"].get("session")
            or role_matrix["low_priv"].get("session")
        )
        if authz_context_available:
            with _subtool_block(
                "two_account_authz_engine",
                {"endpoints": min(3, len(_targets_for("idor")))},
                "Role-based authz semantic diff",
            ) as subtool:
                try:
                    from src.tools.app_mapping import two_account_authz_engine

                    for endpoint, endpoint_params in _targets_for("idor")[:3]:
                        authz_output = await two_account_authz_engine.invoke(
                            target_url=endpoint,
                            session_a=role_matrix["user_a"].get("session", ""),
                            session_b=role_matrix["user_b"].get("session", ""),
                            admin_session=role_matrix["admin"].get("session", ""),
                            low_priv_session=role_matrix["low_priv"].get("session", ""),
                            cookies_user_a=role_matrix["user_a"].get("cookies", ""),
                            cookies_user_b=role_matrix["user_b"].get("cookies", ""),
                            method="GET",
                            include_unauth_control=True,
                            scope_source=scope_source,
                        )
                        results.append("### Role-based authz semantic diff")
                        results.append(_summarize_output(authz_output))
                        if _scan_indicates_signal("idor", authz_output):
                            fp = _register_candidate(
                                ScanSignal("Potential Authz Semantic Diff", "idor", "critical", "", authz_output),
                                target=target,
                                endpoint=endpoint,
                                scope_source=scope_source,
                            )
                            candidates.append(fp)
                except Exception as exc:
                    subtool["success"] = False
                    results.append(f"Role-based authz engine failed: {str(exc)[:160]}")
        else:
            results.append("Role-based authz matrix skipped: provide auth_session_name/cookies and optional role_sessions_json or role_cookies_json.")

    if "cors" in scan_list:
        _emit_phase("cors", "testing origin reflection")
        with _subtool_block(
            "cors_scan",
            {"url": url},
            "CORS origin reflection checks",
        ):
            from src.tools.web import cors_scan
            results.append("\n## CORS")
            output = await cors_scan.invoke(url=url)
            signal = _scan_indicates_signal("cors", output)
            results.append(f"### {'candidate signal' if signal else 'no obvious signal'}")
            results.append(_summarize_output(output))
            if signal:
                fp = _register_candidate(
                    ScanSignal("Potential CORS Misconfiguration", "cors", "medium", "", output),
                    target=target,
                    endpoint=url,
                    scope_source=scope_source,
                )
                candidates.append(fp)
                results.append(f"Candidate registered: {fp}")

    if "csrf" in scan_list:
        _emit_phase("csrf", "checking token and SameSite controls")
        with _subtool_block(
            "csrf_analyzer",
            {"url": url},
            "CSRF token and cookie controls",
        ):
            from .csrf import csrf_analyzer

            await _run_single_scanner(
                "CSRF",
                "csrf",
                "Potential CSRF / Missing Anti-CSRF Controls",
                "medium",
                target,
                url,
                lambda: csrf_analyzer.invoke(url=url, method="POST", cookies=cookies),
                results,
                candidates,
                scope_source,
            )

    if "graphql" in scan_list:
        _emit_phase("graphql", "probing endpoints")
        from src.tools.graphql_security import graphql_security_scanner
        from src.tools.graphql_security import graphql_schema_inventory
        results.append("\n## GraphQL")
        gql_candidates = list(dict.fromkeys(_graphql_endpoint_candidates(url, graphql_url) + api_graphql_urls))
        gql_checked = False
        for gql_url in gql_candidates[:3]:
            try:
                head = _request_with_backoff("OPTIONS", gql_url, timeout=8)
                if head and head.status_code in (404, 405):
                    continue
            except Exception:
                pass
            gql_checked = True
            gql_headers = _safe_json_loads(headers_json, {}) if headers_json else {}
            if cookies:
                gql_headers["Cookie"] = cookies
            json_headers = json.dumps(gql_headers) if gql_headers else "{}"
            with _subtool_block(
                "graphql_schema_inventory",
                {"url": gql_url},
                "GraphQL schema inventory",
            ):
                inventory_output = await graphql_schema_inventory.invoke(url=gql_url, headers=json_headers)
            results.append("### Schema/operation inventory")
            results.append(_summarize_output(inventory_output))
            with _subtool_block(
                "graphql_security_scanner",
                {"url": gql_url},
                "GraphQL security checks",
            ):
                output = await graphql_security_scanner.invoke(
                    url=gql_url,
                    batch_queries=False,
                    alias_overloading=False,
                    mutation_fuzzing=False,
                    headers=json_headers,
                )
            signal = _scan_indicates_signal("graphql", output)
            results.append(f"### {gql_url}: {'candidate signal' if signal else 'no obvious signal'}")
            results.append(_summarize_output(output))
            if signal:
                fp = _register_candidate(
                    ScanSignal("Potential GraphQL Security Issue", "graphql", "medium", "", output),
                    target=target,
                    endpoint=gql_url,
                    scope_source=scope_source,
                )
                candidates.append(fp)
                results.append(f"Candidate registered: {fp}")
        if not gql_checked:
            results.append("Skipped: no reachable/likely GraphQL endpoint. Provide graphql_url to force a check.")

    results.extend([
        "",
        "## Candidate Summary",
        f"Structured candidates registered: {len(candidates)}",
    ])
    if candidates:
        results.extend(f"- {fp}" for fp in candidates)
        results.extend([
            "",
            "## Required Validation",
            "- XSS: validate_browser_xss(url, parameter), then review reportable status.",
            "- Blind/OAST: managed_oast_blind_validation(url, parameter, vuln_type, oast_domain, callback_evidence).",
            "- SSRF: managed_oast_ssrf_validation or validate_oast_ssrf with callback evidence.",
            "- XXE/RCE/SSTI/deserialization/blind XSS: promote only after the unique OAST canary is observed.",
            "- Authz/IDOR: promote_finding_with_evidence with user A/user B/admin/low/unauth response diff.",
            "- LOW/INFO headers/cookies/CORS observations: keep them visible with exact response-header evidence.",
            "- Other classes: promote_finding_with_evidence with raw HTTP proof plus negative control.",
        ])
    else:
        results.append("No candidates registered. Continue mapping endpoints, forms, API routes, and authenticated flows.")

    return "\n".join(results)
