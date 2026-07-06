"""
Authenticated application mapping and evidence-first validation helpers.

These tools fill the gap between recon wrappers and vulnerability scanners:
they build a target inventory, preserve auth/session context, compare roles,
and turn weak signals into lifecycle candidates that require proof before
reporting.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

import requests

from src.sdk.finding_lifecycle import get_finding_lifecycle
from src.sdk.http_knowledge import get_http_knowledge
from src.sdk.tool import function_tool


_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0 AppMapper)"}
_TIMEOUT = 15
_STATEFUL_WORDS = (
    "checkout", "cart", "order", "payment", "coupon", "discount", "upgrade",
    "subscription", "invite", "team", "org", "tenant", "role", "mfa",
    "password", "reset", "email", "delete", "transfer", "withdraw",
)
_ID_RE = re.compile(
    r"(?i)(?:^|[/?&=:\"])([a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}|\d{2,}|[A-Za-z0-9_-]{18,})"
)
_JS_ENDPOINT_RE = re.compile(
    r"""(?:"|')((?:/|\.\./|https?://)[A-Za-z0-9_./?&=%:;,\-{}[\]~+@#]+)(?:"|')"""
)


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""


@dataclass
class ParsedForm:
    action: str
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)

    @property
    def params(self) -> list[str]:
        return [field.name for field in self.fields if field.name]


class _InventoryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[ParsedForm] = []
        self.meta_csrf: dict[str, str] = {}
        self._current_form: ParsedForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v or "" for k, v in attrs}
        tag_l = tag.lower()
        if tag_l in {"a", "link"} and attr.get("href"):
            self.links.append(attr["href"])
        elif tag_l == "script" and attr.get("src"):
            self.scripts.append(attr["src"])
        elif tag_l == "form":
            self._current_form = ParsedForm(
                action=attr.get("action", ""),
                method=(attr.get("method") or "GET").upper(),
            )
        elif tag_l in {"input", "textarea", "select"} and self._current_form is not None:
            name = attr.get("name", "")
            if name:
                self._current_form.fields.append(
                    FormField(name=name, field_type=attr.get("type", tag_l), value=attr.get("value", ""))
                )
        elif tag_l == "meta":
            name = attr.get("name", "").lower()
            if name in {"csrf-token", "csrf", "_csrf"} and attr.get("content"):
                self.meta_csrf[name] = attr["content"]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _target_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc or parsed.path


def _origin(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _same_origin(url: str, base: str) -> bool:
    try:
        return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(base).netloc
    except Exception:
        return False


def _absolute_url(base_url: str, value: str) -> str:
    if not value:
        return base_url
    return urllib.parse.urljoin(base_url, value)


def _normalise_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query)))
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


def _session_kwargs(session_name: str = "", cookies: str = "", headers_json: str = "") -> dict[str, Any]:
    headers = dict(_DEFAULT_HEADERS)
    jar: dict[str, str] = {}
    if headers_json.strip():
        try:
            headers.update(json.loads(headers_json))
        except Exception:
            pass
    if cookies:
        headers["Cookie"] = cookies
    if session_name:
        try:
            from src.tools.auth_context import _SESSION_STORE

            sess = _SESSION_STORE.get(session_name)
            if sess:
                kwargs = sess.as_requests_kwargs()
                headers.update(kwargs.get("headers", {}))
                jar.update(kwargs.get("cookies", {}) or {})
        except Exception:
            pass
    return {"headers": headers, "cookies": jar or None, "verify": False, "timeout": _TIMEOUT}


def _parse_html(html: str) -> _InventoryParser:
    parser = _InventoryParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    return parser


def _extract_json_params(body: str) -> list[str]:
    params: set[str] = set()

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                key_s = str(key)
                params.add(key_s)
                walk(nested, f"{prefix}.{key_s}" if prefix else key_s)
        elif isinstance(value, list):
            for item in value[:5]:
                walk(item, prefix)

    try:
        data = json.loads(body or "")
        walk(data)
    except Exception:
        pass
    return sorted(params)


def _extract_object_ids(text: str) -> list[str]:
    ids = [m.group(1) for m in _ID_RE.finditer(text or "")]
    return list(dict.fromkeys(ids))[:80]


def _semantic_signature(text: str) -> dict[str, Any]:
    text = text or ""
    lower = text.lower()
    keys = set(re.findall(r'"([A-Za-z0-9_]{2,40})"\s*:', text))
    sensitive_keys = sorted(k for k in keys if any(h in k.lower() for h in (
        "email", "phone", "token", "role", "admin", "owner", "tenant", "org", "account", "balance", "ssn"
    )))
    return {
        "length": len(text),
        "hash16": hashlib.sha256(text[:5000].encode("utf-8", errors="ignore")).hexdigest()[:16],
        "json_keys": sorted(keys)[:40],
        "sensitive_keys": sensitive_keys[:20],
        "auth_markers": [m for m in ("login", "forbidden", "unauthorized", "permission", "csrf") if m in lower],
        "object_ids": _extract_object_ids(text)[:20],
    }


def _request(method: str, url: str, kwargs: dict[str, Any], body: dict[str, str] | None = None) -> requests.Response:
    method_u = (method or "GET").upper()
    if method_u in {"POST", "PUT", "PATCH", "DELETE"}:
        return requests.request(method_u, url, data=body or {}, allow_redirects=True, **kwargs)
    return requests.request(method_u, url, allow_redirects=True, **kwargs)


def _record_observation(
    url: str,
    method: str,
    response: requests.Response | None,
    params: list[str] | None = None,
    body: str = "",
    notes: str = "",
    source_tool: str = "authenticated_app_mapper",
) -> None:
    kb = get_http_knowledge()
    text = response.text if response is not None else ""
    kb.record(
        target=_target_from_url(url),
        url=url,
        method=method,
        status_code=response.status_code if response is not None else 0,
        params=params,
        body=body,
        content_type=response.headers.get("Content-Type", "") if response is not None else "",
        response_length=len(text or ""),
        response_excerpt=(text or "")[:500],
        source_tool=source_tool,
        notes=notes,
    )


def _safe_form_payload(form: ParsedForm) -> dict[str, str]:
    payload: dict[str, str] = {}
    for field in form.fields:
        name_l = field.name.lower()
        type_l = field.field_type.lower()
        if type_l in {"submit", "button", "file", "password"}:
            continue
        if any(k in name_l for k in ("csrf", "token", "authenticity", "__requestverificationtoken")):
            payload[field.name] = field.value
        elif field.value:
            payload[field.name] = field.value
        elif "email" in name_l:
            payload[field.name] = "cybercopilot-test@example.local"
        elif any(k in name_l for k in ("url", "uri", "link", "callback", "webhook")):
            payload[field.name] = "https://example.com/"
        elif any(k in name_l for k in ("amount", "price", "total")):
            payload[field.name] = "1"
        elif any(k in name_l for k in ("qty", "quantity")):
            payload[field.name] = "1"
        else:
            payload[field.name] = "cybercopilot-test"
    return payload


@function_tool()
def authenticated_app_mapper(
    base_url: str,
    session_name: str = "",
    cookies: str = "",
    headers_json: str = "",
    max_pages: int = 25,
    max_js_files: int = 8,
    submit_forms: bool = False,
    include_js_endpoints: bool = True,
) -> str:
    """
    Crawl an authenticated application surface and record endpoint inventory.

    The mapper keeps to same-origin URLs, extracts links, forms, scripts, API
    routes, parameters, object IDs, CSRF fields, and state-changing endpoints.
    Form submission is opt-in and uses benign values while skipping password and
    file fields.
    """
    base_url = base_url.rstrip("/") or base_url
    kwargs = _session_kwargs(session_name=session_name, cookies=cookies, headers_json=headers_json)
    queue = [_normalise_url(base_url)]
    seen: set[str] = set()
    discovered: set[str] = set(queue)
    forms_seen: list[tuple[str, ParsedForm]] = []
    js_files: list[str] = []
    object_ids: set[str] = set()
    csrf_fields: set[str] = set()
    stateful: set[str] = set()
    api_endpoints: set[str] = set()
    notes: list[str] = []

    while queue and len(seen) < max(1, max_pages):
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = requests.get(url, allow_redirects=True, **kwargs)
        except Exception as exc:
            notes.append(f"{url}: request failed: {str(exc)[:90]}")
            continue

        text = response.text or ""
        parser = _parse_html(text)
        query_params = list(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())
        json_params = _extract_json_params(text) if "json" in response.headers.get("Content-Type", "").lower() else []
        _record_observation(url, "GET", response, sorted(set(query_params + json_params)))
        object_ids.update(_extract_object_ids(url + "\n" + text[:20000]))
        csrf_fields.update(parser.meta_csrf.keys())

        for form in parser.forms:
            forms_seen.append((url, form))
            action = _absolute_url(url, form.action)
            if not _same_origin(action, base_url):
                continue
            method = form.method.upper() or "GET"
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                stateful.add(action)
            _record_observation(
                action,
                method,
                response,
                form.params,
                body=urllib.parse.urlencode(_safe_form_payload(form)),
                notes=f"Form discovered on {url}",
            )
            for field in form.fields:
                if any(k in field.name.lower() for k in ("csrf", "token", "authenticity")):
                    csrf_fields.add(field.name)
            if submit_forms and method in {"GET", "POST"} and not any(f.field_type.lower() in {"password", "file"} for f in form.fields):
                payload = _safe_form_payload(form)
                try:
                    if method == "POST":
                        submitted = requests.post(action, data=payload, allow_redirects=True, **kwargs)
                    else:
                        submitted = requests.get(action, params=payload, allow_redirects=True, **kwargs)
                    _record_observation(
                        submitted.url,
                        method,
                        submitted,
                        list(payload.keys()),
                        body=urllib.parse.urlencode(payload),
                        notes=f"Benign form submission from {url}",
                    )
                except Exception as exc:
                    notes.append(f"{action}: benign form submit failed: {str(exc)[:90]}")

        candidates = parser.links + parser.scripts
        for raw in candidates:
            absolute = _normalise_url(_absolute_url(url, raw))
            if not _same_origin(absolute, base_url):
                continue
            if raw in parser.scripts:
                if len(js_files) < max_js_files:
                    js_files.append(absolute)
            else:
                discovered.add(absolute)
                path = urllib.parse.urlparse(absolute).path.lower()
                if any(word in path for word in _STATEFUL_WORDS):
                    stateful.add(absolute)
                if "/api/" in path or path.endswith((".json", ".graphql")) or "graphql" in path:
                    api_endpoints.add(absolute)
                if absolute not in seen and len(queue) + len(seen) < max_pages:
                    queue.append(absolute)

    if include_js_endpoints:
        for js_url in js_files[:max_js_files]:
            try:
                js_resp = requests.get(js_url, allow_redirects=True, **kwargs)
            except Exception:
                continue
            _record_observation(js_url, "GET", js_resp, source_tool="authenticated_app_mapper:js")
            for match in _JS_ENDPOINT_RE.findall(js_resp.text or ""):
                if match.startswith(("data:", "javascript:", "#")):
                    continue
                endpoint = _normalise_url(_absolute_url(js_url, match))
                if _same_origin(endpoint, base_url):
                    discovered.add(endpoint)
                    path = urllib.parse.urlparse(endpoint).path.lower()
                    if "/api/" in path or "graphql" in path:
                        api_endpoints.add(endpoint)
                    if any(word in path for word in _STATEFUL_WORDS):
                        stateful.add(endpoint)
                    _record_observation(endpoint, "GET", None, notes="Endpoint extracted from JavaScript", source_tool="authenticated_app_mapper:js")

    suggestions = get_http_knowledge().suggest_tests(_target_from_url(base_url))[:12]
    lines = [
        "## Authenticated App Mapper",
        f"Base URL: {base_url}",
        f"Auth source: {session_name or ('cookies' if cookies else 'unauthenticated')}",
        f"Pages fetched: {len(seen)}",
        f"Unique endpoints discovered: {len(discovered)}",
        f"Forms discovered: {len(forms_seen)}",
        f"API/GraphQL endpoints: {len(api_endpoints)}",
        f"State-changing/business endpoints: {len(stateful)}",
        f"Object IDs harvested: {len(object_ids)}",
        f"CSRF fields/tokens observed: {', '.join(sorted(csrf_fields)) if csrf_fields else '(none)'}",
        "",
        "### High-Value Endpoints",
    ]
    for endpoint in list(sorted(api_endpoints | stateful))[:30]:
        lines.append(f"- {endpoint}")
    lines.append("")
    lines.append("### Harvested Object IDs")
    lines.append(", ".join(list(object_ids)[:30]) if object_ids else "(none)")
    lines.append("")
    lines.append("### Adaptive Test Queue")
    if suggestions:
        for item in suggestions:
            lines.append(f"- {item['kind']}: {item['url']} -> {item['tool']} ({item['reason']})")
    else:
        lines.append("- No targeted tests inferred yet.")
    if notes:
        lines.append("")
        lines.append("### Mapper Notes")
        lines.extend(f"- {note}" for note in notes[:10])
    return "\n".join(lines)


@function_tool()
def two_account_authz_engine(
    target_url: str,
    session_a: str = "",
    session_b: str = "",
    admin_session: str = "",
    low_priv_session: str = "",
    cookies_user_a: str = "",
    cookies_user_b: str = "",
    method: str = "GET",
    body_json: str = "",
    id_replacements_json: str = "{}",
    include_unauth_control: bool = True,
    scope_source: str = "two_account_authz_engine",
) -> str:
    """
    Compare one request across user A, user B, optional admin/low role, and
    unauthenticated control. Registers a candidate only when a lower-privilege
    context appears to access the protected object.
    """
    replacements: dict[str, str] = {}
    try:
        replacements = json.loads(id_replacements_json or "{}")
    except Exception:
        replacements = {}

    def mutate_url(url: str, mapping: dict[str, str]) -> str:
        for old, new in mapping.items():
            url = url.replace(str(old), str(new))
        return url

    body: Any = None
    if body_json.strip():
        try:
            body = json.loads(body_json)
            if isinstance(body, dict):
                for old, new in replacements.items():
                    for key, value in list(body.items()):
                        if str(value) == str(old):
                            body[key] = new
        except Exception:
            body = body_json

    target_mutated = mutate_url(target_url, replacements)
    contexts: list[tuple[str, dict[str, Any]]] = []
    contexts.append(("user_a", _session_kwargs(session_a, cookies_user_a)))
    if session_b or cookies_user_b:
        contexts.append(("user_b", _session_kwargs(session_b, cookies_user_b)))
    if admin_session:
        contexts.append(("admin", _session_kwargs(admin_session)))
    if low_priv_session:
        contexts.append(("low_priv", _session_kwargs(low_priv_session)))
    if include_unauth_control:
        contexts.append(("unauth", _session_kwargs()))

    results: dict[str, dict[str, Any]] = {}
    for label, kwargs in contexts:
        try:
            request_kwargs = dict(kwargs)
            if isinstance(body, dict):
                request_kwargs["json"] = body
            elif isinstance(body, str):
                request_kwargs["data"] = body
            response = requests.request(method.upper(), target_mutated, allow_redirects=True, **request_kwargs)
            sig = _semantic_signature(response.text or "")
            results[label] = {
                "status": response.status_code,
                "length": len(response.text or ""),
                "url": response.url,
                "signature": sig,
                "preview": (response.text or "")[:240],
            }
            _record_observation(
                target_mutated,
                method.upper(),
                response,
                body=json.dumps(body) if isinstance(body, dict) else (body or ""),
                notes=f"Authz comparison context={label}",
                source_tool="two_account_authz_engine",
            )
        except Exception as exc:
            results[label] = {"status": 0, "length": 0, "error": str(exc)[:160], "signature": {}}

    baseline = results.get("user_a", {})
    risky_labels = []
    for label in ("user_b", "low_priv", "unauth"):
        current = results.get(label)
        if not current:
            continue
        same_status = current.get("status") == baseline.get("status") == 200
        same_body = current.get("signature", {}).get("hash16") == baseline.get("signature", {}).get("hash16")
        similar_len = abs(int(current.get("length", 0)) - int(baseline.get("length", 0))) < 80
        sensitive = bool(current.get("signature", {}).get("sensitive_keys") or current.get("signature", {}).get("object_ids"))
        if same_status and (same_body or similar_len or sensitive):
            risky_labels.append(label)

    lines = ["## Two-Account Authorization Engine", f"URL: {target_mutated}", f"Method: {method.upper()}", ""]
    for label, data in results.items():
        sig = data.get("signature", {})
        lines.append(
            f"- {label}: HTTP {data.get('status')} len={data.get('length')} "
            f"hash={sig.get('hash16', '-')}; sensitive={','.join(sig.get('sensitive_keys', [])[:5]) or '-'}"
        )
    if replacements:
        lines.append("")
        lines.append(f"Object/tenant substitutions: {json.dumps(replacements, sort_keys=True)}")

    if risky_labels:
        evidence = (
            f"Authz comparison candidate for {target_mutated}\n"
            f"GET/POST equivalent method: {method.upper()}\n"
            f"Baseline user_a: HTTP {baseline.get('status')} len={baseline.get('length')}\n"
            f"Risky contexts: {', '.join(risky_labels)}\n"
            "Negative control included: unauthenticated or lower-privilege comparison.\n"
            f"Semantic diff/signatures:\n{json.dumps(results, indent=2)[:2500]}"
        )
        finding = get_finding_lifecycle().add_candidate(
            title="Potential Broken Object Level Authorization",
            target=_target_from_url(target_url),
            severity="critical",
            endpoint=target_mutated,
            parameter=",".join(replacements.keys()),
            category="idor",
            evidence=evidence,
            scope_source=scope_source,
        )
        lines.append("")
        lines.append(f"Candidate registered: {finding.fingerprint}")
        lines.append("Promotion requires ownership proof: show user_b/tenant ownership and user_a unauthorized access with response diff.")
    else:
        lines.append("")
        lines.append("No authz candidate registered from these contexts. Try harvested UUIDs, nested JSON IDs, method override, or GraphQL node IDs.")
    return "\n".join(lines)


@function_tool()
async def managed_oast_ssrf_validation(
    url: str,
    parameter: str,
    oast_domain: str,
    method: str = "GET",
    data_params: str = "",
    cookies: str = "",
    callback_evidence: str = "",
    poll_output: str = "",
    scope_source: str = "managed_oast_ssrf_validation",
) -> str:
    """
    Managed blind SSRF validation with unique positive and negative canaries.

    The tool injects a unique OAST URL, sends a negative control canary through
    an unrelated value, correlates callback evidence by canary token, registers
    a candidate, and promotes only when the positive canary is observed while
    the negative canary is absent.
    """
    from src.tools.appsec.ssrf import ssrf_scanner

    clean_domain = oast_domain.strip().lstrip("*.").rstrip("/")
    if not clean_domain:
        return "Error: oast_domain is required for managed OAST SSRF validation."
    token_seed = f"{url}|{parameter}|{time.time()}"
    token = hashlib.sha1(token_seed.encode()).hexdigest()[:12]
    positive_host = f"ssrf-{parameter}-{token}.{clean_domain}"
    negative_host = f"control-{parameter}-{token}.{clean_domain}"
    positive_url = f"http://{positive_host}/p"
    negative_url = f"http://{negative_host}/n"

    output = await ssrf_scanner.invoke(
        url=url,
        parameter=parameter,
        test_internal=False,
        test_cloud=False,
        custom_target=positive_url,
        data_params=data_params,
        method=method,
    )
    # Send a low-risk negative control by placing the control in a benign extra
    # value rather than the suspected injectable parameter.
    try:
        kwargs = _session_kwargs(cookies=cookies)
        parsed = urllib.parse.urlparse(url)
        if method.upper() == "POST":
            body = dict(urllib.parse.parse_qsl(data_params))
            body["_cybercopilot_control"] = negative_url
            requests.post(url, data=body, allow_redirects=True, **kwargs)
        else:
            q = dict(urllib.parse.parse_qsl(parsed.query))
            q["_cybercopilot_control"] = negative_url
            control_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urllib.parse.urlencode(q), ""))
            requests.get(control_url, allow_redirects=True, **kwargs)
    except Exception:
        pass

    evidence_blob = "\n".join([callback_evidence or "", poll_output or ""])
    pos_seen = positive_host.lower() in evidence_blob.lower() or positive_url.lower() in evidence_blob.lower()
    neg_seen = negative_host.lower() in evidence_blob.lower() or negative_url.lower() in evidence_blob.lower()
    lifecycle = get_finding_lifecycle()
    candidate = lifecycle.add_candidate(
        title="Managed OAST SSRF callback candidate",
        target=_target_from_url(url),
        severity="high",
        endpoint=url,
        parameter=parameter,
        category="ssrf",
        evidence=f"Positive canary: {positive_url}\nNegative canary: {negative_url}\nScanner output:\n{output}",
        scope_source=scope_source,
    )

    lines = [
        "## Managed OAST SSRF Validation",
        f"Positive canary: {positive_url}",
        f"Negative control canary: {negative_url}",
        f"Candidate: {candidate.fingerprint}",
        "",
        str(output),
    ]
    if not evidence_blob.strip():
        lines.append("Awaiting OAST evidence. Poll your OAST provider and pass poll_output/callback_evidence back to this tool.")
        return "\n".join(lines)
    if pos_seen and not neg_seen:
        evidence = (
            f"Confirmed OAST callback for {positive_host}.\n"
            f"{method.upper()} {urllib.parse.urlparse(url).path or '/'} HTTP/1.1\n"
            f"Parameter under test: {parameter}\n"
            f"Negative control {negative_host} did not appear in callback logs.\n"
            f"Callback evidence:\n{evidence_blob[:2500]}"
        )
        ok, message, finding = lifecycle.promote(
            candidate.fingerprint,
            evidence=evidence,
            validation_notes="Validated with unique positive OAST canary and absent negative-control canary.",
            impact="Server-side request primitive can reach attacker-controlled infrastructure.",
            remediation="Allowlist outbound destinations, block internal/link-local ranges, and normalize URL parsing before fetch.",
            cwe="CWE-918",
        )
        lines.append(message)
        if finding:
            lines.append(f"Reportable: {finding.reportable}")
    elif pos_seen and neg_seen:
        lines.append("Positive and negative canaries both appeared. Treat as inconclusive; the OAST evidence may be polluted or a generic scanner fetched both values.")
    else:
        lines.append("No matching positive canary observed. Candidate remains unconfirmed.")
    return "\n".join(lines)


@function_tool()
def build_recon_attack_paths(target: str = "") -> str:
    """
    Convert recorded recon/app-map observations into prioritized exploit hypotheses.
    """
    kb = get_http_knowledge()
    summary = kb.summary(target)
    observations = kb.for_target(target) if target else kb.observations
    paths: list[tuple[int, str, str]] = []
    for obs in observations:
        params = {p.lower() for p in obs.params}
        path_l = obs.path.lower()
        if "/graphql" in path_l:
            paths.append((95, obs.url, "GraphQL endpoint: run schema inventory, then resolver-level two-account authz replay."))
        if obs.auth_required and obs.method in {"POST", "PUT", "PATCH", "DELETE"}:
            paths.append((90, obs.url, "State-changing authenticated request: compare user A/B/unauth and check CSRF/business state."))
        if any(p in params for p in ("id", "user_id", "account_id", "org_id", "tenant_id", "owner_id")):
            paths.append((88, obs.url, "Object identifier parameter: run two_account_authz_engine with harvested IDs."))
        if any(p in params for p in ("url", "uri", "callback", "webhook", "avatar", "image", "feed")):
            paths.append((84, obs.url, "URL-fetch parameter: run managed_oast_ssrf_validation with unique canaries."))
        if any(p in params for p in ("amount", "price", "total", "quantity", "coupon", "plan_id")):
            paths.append((82, obs.url, "Business/financial parameter: record baseline workflow and test state before/after."))
        if "/api/" in path_l and not obs.auth_required:
            paths.append((70, obs.url, "Unauthenticated API route: test sensitive fields, legacy versions, and mass assignment."))

    lines = ["## Recon-To-Attack Path Builder", json.dumps(summary, indent=2), "", "## Prioritized Hypotheses"]
    if not paths:
        lines.append("No attack paths inferred yet. Run authenticated_app_mapper or record_http_observation first.")
        return "\n".join(lines)
    for score, url, reason in sorted(paths, reverse=True)[:25]:
        lines.append(f"- [{score}] {url} -> {reason}")
    return "\n".join(lines)


@function_tool()
def business_workflow_state_recorder(
    workflow_name: str,
    baseline_url: str,
    action_url: str,
    session_name: str = "",
    cookies: str = "",
    action_method: str = "POST",
    action_body_json: str = "{}",
    csrf_source_url: str = "",
    state_markers: str = "balance,credits,plan,status,role,quantity,total,subscription",
) -> str:
    """
    Record before/action/after state for business logic testing.

    This gives brittle business-logic probes the missing context: CSRF handling,
    baseline state, action result, and after-state diff.
    """
    kwargs = _session_kwargs(session_name=session_name, cookies=cookies)
    markers = [m.strip().lower() for m in state_markers.split(",") if m.strip()]
    body: dict[str, Any] = {}
    try:
        body = json.loads(action_body_json or "{}")
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    csrf_notes = []
    if csrf_source_url:
        try:
            csrf_resp = requests.get(csrf_source_url, allow_redirects=True, **kwargs)
            parsed = _parse_html(csrf_resp.text or "")
            for key, value in parsed.meta_csrf.items():
                body.setdefault(key, value)
                csrf_notes.append(f"{key}={value[:16]}...")
            for form in parsed.forms:
                for field in form.fields:
                    if any(k in field.name.lower() for k in ("csrf", "token", "authenticity")) and field.value:
                        body.setdefault(field.name, field.value)
                        csrf_notes.append(f"{field.name}={field.value[:16]}...")
        except Exception as exc:
            csrf_notes.append(f"CSRF fetch failed: {str(exc)[:80]}")

    before = requests.get(baseline_url, allow_redirects=True, **kwargs)
    action_kwargs = dict(kwargs)
    action_kwargs["json"] = body
    action = requests.request(action_method.upper(), action_url, allow_redirects=True, **action_kwargs)
    after = requests.get(baseline_url, allow_redirects=True, **kwargs)

    def marker_snapshot(text: str) -> dict[str, list[str]]:
        snap: dict[str, list[str]] = {}
        for marker in markers:
            matches = re.findall(rf'(?i)"?{re.escape(marker)}"?\s*[:=]\s*"?([^",<}} ]+)', text or "")
            if matches:
                snap[marker] = matches[:5]
        return snap

    before_sig = _semantic_signature(before.text or "")
    after_sig = _semantic_signature(after.text or "")
    diff = {
        "before_status": before.status_code,
        "action_status": action.status_code,
        "after_status": after.status_code,
        "before_len": len(before.text or ""),
        "after_len": len(after.text or ""),
        "before_markers": marker_snapshot(before.text or ""),
        "after_markers": marker_snapshot(after.text or ""),
        "before_hash": before_sig["hash16"],
        "after_hash": after_sig["hash16"],
    }
    _record_observation(baseline_url, "GET", before, source_tool="business_workflow_state_recorder", notes=f"{workflow_name} before state")
    _record_observation(action_url, action_method.upper(), action, list(body.keys()), body=json.dumps(body), source_tool="business_workflow_state_recorder", notes=f"{workflow_name} action")
    _record_observation(baseline_url, "GET", after, source_tool="business_workflow_state_recorder", notes=f"{workflow_name} after state")

    lines = [
        "## Business Workflow State Recorder",
        f"Workflow: {workflow_name}",
        f"Baseline: {baseline_url}",
        f"Action: {action_method.upper()} {action_url}",
        f"CSRF: {', '.join(csrf_notes) if csrf_notes else '(none observed)'}",
        "",
        "### Before/After Diff",
        json.dumps(diff, indent=2),
        "",
        "Next: run price/coupon/workflow probes using this request body, then promote only if after-state proves unauthorized benefit.",
    ]
    return "\n".join(lines)
