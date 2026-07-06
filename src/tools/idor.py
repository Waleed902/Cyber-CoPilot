"""
IDOR / BOLA Enumerator

Detects the ID pattern in a URL or request parameter, generates variants,
sends them in parallel, and reports responses that differ from the baseline
— indicating unauthorised data access (Broken Object Level Authorization).

Supported ID patterns:
  - UUIDv4  (random)
  - UUIDv1  (timestamp-based — enumerable)
  - Sequential integers
  - Base64-encoded integers
  - Timestamp-based IDs
  - Short alphanumeric slugs
"""

import re
import uuid
import time
import base64
import asyncio
import hashlib
from typing import Optional
from src.sdk.tool import function_tool


# ── Pattern detection ──────────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-([14])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_INT_RE = re.compile(r"\b(\d{1,12})\b")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_SLUG_RE = re.compile(r"[a-zA-Z0-9]{8,24}")


def _detect_pattern(value: str) -> str:
    """Return the detected ID pattern type."""
    if _UUID_RE.fullmatch(value.strip()):
        version = int(_UUID_RE.fullmatch(value.strip()).group(1))
        return f"uuid_v{version}"
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        if decoded.isdigit():
            return "base64_int"
    except Exception:
        pass
    if re.fullmatch(r"\d+", value.strip()):
        return "integer"
    if value.strip().isdigit() is False and _SLUG_RE.fullmatch(value.strip()):
        return "slug"
    return "unknown"


def _generate_variants(value: str, pattern: str, count: int) -> list[str]:
    """Generate ID variants based on the detected pattern."""
    variants: list[str] = []

    if pattern == "integer":
        base = int(value.strip())
        # enumerate around the base value
        for delta in range(-count // 2, count // 2 + 1):
            candidate = base + delta
            if candidate > 0 and str(candidate) != value.strip():
                variants.append(str(candidate))
        # also try very small IDs (admin accounts are often id=1,2,3)
        for i in range(1, min(6, count)):
            if str(i) not in variants and str(i) != value.strip():
                variants.append(str(i))

    elif pattern == "base64_int":
        raw = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        base = int(raw) if raw.isdigit() else 0
        for delta in range(1, count + 1):
            variants.append(
                base64.b64encode(str(base + delta).encode()).decode().rstrip("=")
            )

    elif pattern == "uuid_v1":
        # UUIDv1 embeds a timestamp — increment the timestamp field
        try:
            u = uuid.UUID(value.strip())
            ts = u.time
            for i in range(1, count + 1):
                new_ts = ts + i * 10_000  # 100-ns increments
                new_uuid = uuid.UUID(
                    fields=(
                        new_ts & 0xFFFFFFFF,
                        (new_ts >> 32) & 0xFFFF,
                        ((new_ts >> 48) & 0x0FFF) | 0x1000,
                        u.clock_seq_hi_variant,
                        u.clock_seq_low,
                        u.node,
                    ),
                    version=1,
                )
                variants.append(str(new_uuid))
        except Exception:
            pass

    elif pattern == "uuid_v4":
        # UUIDv4 is fully random — generate fresh random UUIDs
        for _ in range(count):
            variants.append(str(uuid.uuid4()))

    elif pattern == "slug":
        # Mutate the last 2 chars
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        base = list(value.strip())
        seen = {value.strip()}
        for i in range(count * 4):
            idx = i % len(base)
            orig = base[idx]
            base[idx] = chars[(chars.index(orig.lower()) + i + 1) % len(chars)]
            candidate = "".join(base)
            if candidate not in seen:
                variants.append(candidate)
                seen.add(candidate)
            base[idx] = orig
            if len(variants) >= count:
                break

    return variants[:count]


# ── Response comparison ────────────────────────────────────────────────────────

def _fingerprint(resp) -> tuple:
    """Return a (status, content_length_bucket, body_hash) tuple for diffing."""
    body = resp.text or ""
    length_bucket = len(body) // 50  # bucket by 50-byte blocks
    body_hash = hashlib.md5(body[:2000].encode("utf-8", errors="ignore")).hexdigest()
    return (resp.status_code, length_bucket, body_hash)


def _is_different(baseline_fp: tuple, candidate_fp: tuple) -> bool:
    """Return True if the candidate response meaningfully differs from baseline."""
    b_status, b_bucket, b_hash = baseline_fp
    c_status, c_bucket, c_hash = candidate_fp
    if c_status != b_status:
        return True
    # Same status but body differs by more than one size bucket
    if abs(c_bucket - b_bucket) > 1:
        return True
    return False


# ── Main tool ──────────────────────────────────────────────────────────────────

@function_tool()
async def idor_enumerate(
    url: str,
    id_value: str,
    id_param: str = "",
    method: str = "GET",
    headers: str = "",
    cookies: str = "",
    post_data: str = "",
    count: int = 30,
    concurrency: int = 10,
    timeout: int = 10,
    auth_header: str = "",
) -> str:
    """
    IDOR / BOLA enumerator — detects the ID pattern and bulk-probes variants.

    Automatically identifies whether the ID is a UUID, integer, base64, or slug,
    generates plausible alternatives, sends them in parallel, and reports any
    responses that differ from the baseline (indicating data leakage).

    Args:
        url:         URL containing the ID (e.g. 'http://site.com/api/users/123'
                     or 'http://site.com/profile?id=abc-def-...')
        id_value:    The known valid ID value to use as baseline
                     (e.g. '123', 'a1b2c3d4-...', 'MTIz')
        id_param:    If the ID is a query/body param, specify its name.
                     Leave blank if the ID is embedded in the URL path.
        method:      HTTP method — GET (default) or POST
        headers:     Extra headers as 'Name: Value\\nName2: Value2'
        cookies:     Cookie string as 'name=val; name2=val2'
        post_data:   POST body template as 'key=val&key2=val2'
        count:       Number of ID variants to probe (default 30)
        concurrency: Parallel request workers (default 10)
        timeout:     Per-request timeout in seconds (default 10)
        auth_header: Authorization header value to send with every request
                     (e.g. 'Bearer eyJ...' or 'Basic dXNlcjpwYXNz')

    Returns:
        Markdown report listing all differing responses and their content.
    """
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed

    output: list[str] = [
        f"# IDOR Enumeration — {url}",
        f"**ID value:** `{id_value}` | **Method:** {method.upper()}\n",
    ]

    # Build request kwargs
    req_headers: dict = {}
    if auth_header:
        if auth_header.lower().startswith("bearer ") or auth_header.lower().startswith("basic "):
            req_headers["Authorization"] = auth_header
        else:
            req_headers["Authorization"] = f"Bearer {auth_header}"
    if headers:
        for line in headers.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                req_headers[k.strip()] = v.strip()

    req_cookies: dict = {}
    if cookies:
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                req_cookies[k.strip()] = v.strip()

    base_post: dict = {}
    if post_data:
        for part in post_data.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                base_post[k.strip()] = v.strip()

    def _make_url(variant: str) -> str:
        if id_param:
            return url
        # Replace the id_value directly in the URL path
        return url.replace(id_value, variant, 1)

    def _make_params(variant: str) -> dict:
        if id_param:
            return {id_param: variant}
        return {}

    def _make_body(variant: str) -> dict:
        body = dict(base_post)
        if id_param and method.upper() == "POST":
            body[id_param] = variant
        return body

    session = requests.Session()
    session.headers.update(req_headers)
    session.cookies.update(req_cookies)

    # ── Baseline request ───────────────────────────────────────────────────────
    output.append("## Step 1 — Baseline request")
    try:
        if method.upper() == "POST":
            baseline_resp = session.post(
                url, data=_make_body(id_value),
                params=_make_params(id_value), timeout=timeout,
            )
        else:
            baseline_resp = session.get(
                _make_url(id_value),
                params=_make_params(id_value), timeout=timeout,
            )
    except Exception as e:
        return f"Error reaching target: {e}"

    baseline_fp = _fingerprint(baseline_resp)
    output.append(
        f"Status: `{baseline_resp.status_code}` | "
        f"Length: `{len(baseline_resp.text)}` bytes\n"
    )

    # ── Pattern detection ──────────────────────────────────────────────────────
    pattern = _detect_pattern(id_value)
    output.append(f"## Step 2 — Pattern detection")
    output.append(f"Detected pattern: **{pattern}**")

    if pattern == "uuid_v4":
        output.append(
            "⚠️  UUIDv4 IDs are cryptographically random — "
            "enumeration is not feasible. "
            "Check for IDOR via parameter tampering or role-based access instead."
        )

    variants = _generate_variants(id_value, pattern, count)
    output.append(f"Generated **{len(variants)}** variants to probe\n")

    # ── Parallel probing ───────────────────────────────────────────────────────
    output.append(f"## Step 3 — Probing {len(variants)} variants")

    findings: list[dict] = []

    def _probe(variant: str) -> dict | None:
        try:
            if method.upper() == "POST":
                resp = session.post(
                    url, data=_make_body(variant),
                    params=_make_params(variant), timeout=timeout,
                )
            else:
                resp = session.get(
                    _make_url(variant),
                    params=_make_params(variant), timeout=timeout,
                )
            fp = _fingerprint(resp)
            if _is_different(baseline_fp, fp):
                return {
                    "id": variant,
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "snippet": resp.text[:300].replace("\n", " "),
                }
        except Exception:
            pass
        return None

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(_probe, v): v for v in variants}
        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            result = future.result()
            if result:
                findings.append(result)

    # ── Report ─────────────────────────────────────────────────────────────────
    output.append(f"Probed {done_count} variants — **{len(findings)} differ** from baseline\n")

    if not findings:
        output.append(
            "✅ No differing responses found.\n"
            "The endpoint may enforce proper authorization, "
            "or the ID space is too sparse for the tested range."
        )
    else:
        output.append("### Differing responses (potential IDOR)\n")
        output.append("| ID | Status | Length | Snippet |")
        output.append("|----|--------|--------|---------|")
        for f in sorted(findings, key=lambda x: x["status"]):
            snippet = f["snippet"][:80].replace("|", "\\|")
            output.append(
                f"| `{f['id']}` | {f['status']} | {f['length']} | {snippet} |"
            )
        output.append("")
        output.append(
            f"⚠️  **{len(findings)} IDs returned different responses** — "
            "review each for unauthorized data disclosure."
        )

    return "\n".join(output)
