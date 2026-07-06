"""
JavaScript Analysis & Secret Discovery

Extracts and analyzes JavaScript files from a target web application:
  - API keys, tokens, passwords, private keys in JS source
  - Hidden API endpoints extracted from JS routes/fetch calls
  - Source map disclosure (.map files leaking original source)
  - Webpack bundle analysis for exposed internal paths
  - Subdomains and internal hosts mentioned in JS
  - AJAX endpoint enumeration (XMLHttpRequest, fetch, axios, jQuery $.ajax)
"""

from __future__ import annotations

import re
import urllib.parse
from typing import List, Optional, Set
from collections import defaultdict

import requests
import urllib3
from loguru import logger

# Suppress noisy InsecureRequestWarning when using verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from src.sdk.tool import function_tool

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (CyberCoPilot/1.0)"}
_TIMEOUT = 60

# ── Regex patterns for secret detection ───────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth":         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "GitHub Token":         r"ghp_[0-9a-zA-Z]{36}|github_pat_[a-zA-Z0-9_]{82}",
    "Stripe Secret":        r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable":   r"pk_live_[0-9a-zA-Z]{24}",
    "SendGrid API Key":     r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Slack Token":          r"xox[baprs]-[0-9A-Za-z\-]+",
    "Slack Webhook":        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Twilio API Key":       r"SK[0-9a-fA-F]{32}",
    # Require a Twilio-contextual keyword within 40 chars before the hex token
    # to avoid matching every 32-char hex string in minified polyfill libraries.
    "Twilio Auth Token":    r"(?:authToken|auth_token|TWILIO[_A-Z]*TOKEN|twilio).{0,40}([a-f0-9]{32})",
    "Firebase URL":         r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key":     r"AIza[0-9A-Za-z]{35}",
    "JWT Token":            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
    "Bearer Token":         r"(?i)bearer\s+[a-zA-Z0-9\-_=.]{20,}",
    "Hardcoded Password":   r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "Hardcoded API Key":    r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Private Key Header":   r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Basic Auth (b64)":     r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}",
    "Mailchimp API":        r"[0-9a-f]{32}-us[0-9]{1,2}",
    "HerokuAPI":            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Shopify Token":        r"shpat_[a-fA-F0-9]{32}",
    "Internal URL":         r"(?i)(?:https?://|['\"])(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:'\"/ ]",
}

ENDPOINT_PATTERNS = [
    # fetch / axios / $http / XHR patterns
    r"""['"`](\/api\/[a-zA-Z0-9/_-]{3,50})['"`]""",
    r"""['"`](\/v[0-9]+\/[a-zA-Z0-9/_-]{3,50})['"`]""",
    r"""['"`](\/?[a-zA-Z0-9_-]+\/[a-zA-Z0-9_/-]{3,60})['"`]""",
    r"""fetch\(['"`](https?://[^'"` ]{10,100})['"`]""",
    r"""axios\.[a-z]+\(['"`](https?://[^'"` ]{10,100})['"`]""",
    r"""\$\.(?:get|post|ajax)\(['"`](https?://[^'"` ]{10,100})['"`]""",
    r"""XMLHttpRequest[^;]*open\(['"](GET|POST)['"]\s*,\s*['"`]([^'"` ]{5,100})['"`]""",
    r"""(?:url|endpoint|baseURL|apiUrl)\s*[:=]\s*['"`](https?://[^'"` ]{10,100})['"`]""",
    r"""(?:url|endpoint)\s*[:=]\s*['"`](\/[a-zA-Z0-9/_.-]{3,80})['"`]""",
]

SUBDOMAIN_PATTERN = re.compile(
    r"""['"`]((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})['"`]""",
    re.IGNORECASE
)


def _fetch_js(url: str) -> Optional[str]:
    try:
        r = requests.get(url, headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
        if r.status_code == 200 and r.text:
            return r.text
    except Exception as e:
        logger.debug(f"_fetch_js {url}: {e}")
    return None


def _collect_js_urls(base_url: str) -> List[str]:
    """Extract all JS file URLs from the target page HTML."""
    try:
        r = requests.get(base_url, headers=_DEFAULT_HEADERS, timeout=_TIMEOUT, verify=False)
        html = r.text or ""
    except Exception:
        return []

    js_urls = []
    parsed = urllib.parse.urlparse(base_url)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"

    # <script src="..."> tags
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
        src = m.group(1)
        if src.startswith("http"):
            js_urls.append(src)
        elif src.startswith("//"):
            js_urls.append(parsed.scheme + ":" + src)
        elif src.startswith("/"):
            js_urls.append(base_domain + src)
        else:
            js_urls.append(base_domain + "/" + src)

    return list(dict.fromkeys(js_urls))  # deduplicate


@function_tool()
def js_secrets_scanner(
    url: str,
    deep: bool = True,
    extra_js_urls: str = "",
    max_files: int = 500,
    include_external: bool = True,
    scan_source_maps: bool = True,
) -> str:
    """
    Extract and analyze JavaScript files from a target website for:
    - Hardcoded API keys, secrets, tokens (AWS, Google, GitHub, Stripe, JWT, etc.)
    - Internal/private URLs and IP addresses
    - Hidden API endpoints discoverable from JS source

    Args:
        url: Target website URL (e.g. https://target.com). All linked JS files
             will be fetched and scanned automatically.
        deep: If True, also follow webpack chunk URLs discovered in first-level JS
              (default: True)
        extra_js_urls: Comma-separated additional JS URLs to scan directly

    Returns:
        All discovered secrets, tokens, credentials and their locations
    """
    out = [f"=== JavaScript Secrets Scanner: {url}", ""]
    findings = defaultdict(list)
    all_js_urls = []

    # Collect JS files from main page
    out.append("── Collecting JS Files ─────────────────────────")
    page_js = _collect_js_urls(url)
    all_js_urls.extend(page_js)
    out.append(f"  Found {len(page_js)} JS files from main page")

    # Add extra URLs
    if extra_js_urls:
        for extra in extra_js_urls.split(","):
            extra = extra.strip()
            if extra:
                all_js_urls.append(extra)

    # Deep: find webpack chunks from first-pass
    if deep and page_js:
        first_content = _fetch_js(page_js[0]) or ""
        re.compile(r'"([0-9a-f]{8,20})":\s*\d+')
        # Common webpack chunk URL patterns
        chunks_pattern = re.compile(r'["\'](.*?chunk.*?\.js)["\']', re.IGNORECASE)
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for m in chunks_pattern.finditer(first_content):
            chunk_path = m.group(1)
            if not chunk_path.startswith("http"):
                chunk_path = base + "/" + chunk_path.lstrip("/")
            if chunk_path not in all_js_urls:
                all_js_urls.append(chunk_path)
                out.append(f"  Discovered chunk: {chunk_path}")

    # Deduplicate
    all_js_urls = list(dict.fromkeys(all_js_urls))
    out.append(f"  Total JS files to scan: {len(all_js_urls)}")
    out.append("")

    # ── Scan each JS file ─────────────────────────────────────────────────────
    out.append("── Scanning Files for Secrets ──────────────────")
    total_secrets = 0

    # Known public library filenames — scanning these produces only false positives.
    # They contain hex strings, UUIDs, and tokens in their source/minified form
    # that match secret patterns but are part of the library itself.
    _KNOWN_PUBLIC_LIBS = {
        "respond.min.js", "respond.js",          # scottjehl/Respond polyfill
        "html5shiv.min.js", "html5shiv.js",      # HTML5 shiv
        "jquery.min.js", "jquery.js",             # jQuery
        "jquery-migrate.min.js",
        "bootstrap.min.js", "bootstrap.js",       # Bootstrap
        "modernizr.min.js", "modernizr.js",       # Modernizr
        "lodash.min.js", "lodash.js",             # Lodash
        "underscore.min.js", "underscore.js",     # Underscore
        "moment.min.js", "moment.js",             # Moment.js
        "vue.min.js", "vue.js",                   # Vue
        "react.min.js", "react-dom.min.js",       # React
        "angular.min.js", "angularjs",            # Angular
        "d3.min.js", "chart.min.js",              # D3/Chart.js
    }
    _KNOWN_CDN_DOMAINS = (
        "cdnjs.cloudflare.com", "unpkg.com", "jsdelivr.net",
        "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
        "maxcdn.bootstrapcdn.com",
    )

    map_urls: list[str] = []
    for js_url in all_js_urls[:max(1, max_files)]:
        _js_filename = js_url.rstrip("/").split("/")[-1].split("?")[0].lower()
        _js_domain = urllib.parse.urlparse(js_url).netloc.lower()
        if not include_external and (
            _js_filename in _KNOWN_PUBLIC_LIBS or any(cdn in _js_domain for cdn in _KNOWN_CDN_DOMAINS)
        ):
            out.append(f"  [SKIP] {js_url[-70:]} — known public library, skipping to avoid false positives")
            continue
        content = _fetch_js(js_url)
        if not content:
            out.append(f"  [SKIP] {js_url[-60:]} — could not fetch")
            continue

        out.append(f"  [SCAN] {js_url[-70:]} ({len(content)} bytes)")

        if scan_source_maps:
            sm = re.search(r"sourceMappingURL=([^\s]+)", content)
            if sm:
                sm_url = sm.group(1).strip().strip("'\"")
                if sm_url.startswith("http"):
                    map_urls.append(sm_url)
                else:
                    base = js_url.rsplit("/", 1)[0]
                    map_urls.append(f"{base}/{sm_url.lstrip('/')}" )

        for secret_type, pattern in SECRET_PATTERNS.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    match_str = match if isinstance(match, str) else str(match)
                    # Trim long matches
                    match_str = match_str[:120]
                    # Avoid false positives: skip very short or placeholder matches
                    if len(match_str.strip()) < 8:
                        continue
                    if any(fp in match_str.lower() for fp in ["example", "xxx", "your_", "placeholder", "<", ">"]):
                        continue
                    findings[secret_type].append({
                        "file": js_url,
                        "value": match_str,
                    })
                    total_secrets += 1
            except re.error:
                pass

    # ── Source map disclosure ─────────────────────────────────────────────────
    out.append("")
    out.append("── Source Map Disclosure ───────────────────────")
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    if scan_source_maps:
        map_urls += [js_url + ".map" for js_url in all_js_urls[:max(1, max_files)]]
        map_urls += [
            base + "/app.js.map", base + "/main.js.map",
            base + "/bundle.js.map", base + "/static/js/main.js.map",
        ]
        # Deduplicate
        map_urls = list(dict.fromkeys(map_urls))
        for map_url in map_urls[:25]:
            r_map = _fetch_js(map_url)
            if r_map and '"sources"' in r_map:
                findings["Source Map Disclosure"].append({
                    "file": map_url,
                    "value": "Source map found — original source code exposed"
                })
                out.append(f"  [MAP] SOURCE MAP FOUND: {map_url}")
            elif r_map:
                out.append(f"  [map] {map_url[-60:]} — 200 but no sources key")
    else:
        out.append("  [skip] source map scan disabled")

    # ── Report ────────────────────────────────────────────────────────────────
    out.append("")
    if total_secrets > 0 or findings:
        out.append("── FINDINGS ──────────────────────────────────")
        for secret_type, hits in findings.items():
            out.append(f"\n[{secret_type}] — {len(hits)} occurrence(s):")
            for hit in hits[:5]:  # Show up to 5 per type
                out.append(f"  File   : {hit['file'][-70:]}")
                out.append(f"  Value  : {hit['value'][:100]}")
        out.append(f"\nTotal secrets found: {total_secrets}")
    else:
        out.append("No hardcoded secrets detected in JS files.")

    return "\n".join(out)


@function_tool()
def js_endpoint_extractor(
    url: str,
    extra_js_urls: str = "",
    include_external: bool = False,
    max_files: int = 25,
) -> str:
    """
    Extract hidden API endpoints and routes from JavaScript source files.

    Finds endpoints defined in fetch(), axios, $.ajax, XHR, router configs,
    and string literals that look like API paths.

    Args:
        url: Target website URL — all linked JS will be auto-discovered
        extra_js_urls: Comma-separated additional JS URLs to scan
        include_external: Also include endpoints pointing to external domains
                          (default: False — only same-origin paths)

    Returns:
        Discovered API endpoints sorted by uniqueness, ready for further testing
    """
    out = [f"=== JS Endpoint Extractor: {url}", ""]
    parsed = urllib.parse.urlparse(url)
    own_domain = parsed.netloc

    # If the caller passed a direct JS file URL, treat it as the sole file to scan
    # rather than trying to scrape it as an HTML page for <script> tags.
    _looks_like_js = parsed.path.lower().endswith((".js", ".mjs", ".cjs"))
    all_js_urls = [url] if _looks_like_js else _collect_js_urls(url)

    if extra_js_urls:
        for eu in extra_js_urls.split(","):
            eu = eu.strip()
            if eu:
                all_js_urls.append(eu)

    out.append(f"  Found {len(all_js_urls)} JS files")

    discovered: Set[str] = set()
    subdomains: Set[str] = set()

    for js_url in all_js_urls[:max(1, max_files)]:
        content = _fetch_js(js_url)
        if not content:
            continue

        # Extract API endpoints
        for pattern in ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for m in matches:
                    endpoint = m if isinstance(m, str) else (m[-1] if m else "")
                    if not endpoint:
                        continue
                    # Filter: must look like a real path
                    if len(endpoint) < 4 or len(endpoint) > 120:
                        continue
                    if endpoint.startswith("http") and not include_external:
                        if own_domain not in endpoint:
                            continue
                    # Skip common non-endpoint strings
                    if any(skip in endpoint.lower() for skip in
                           [".js", ".css", ".png", ".jpg", ".svg", ".woff",
                            "localhost:", "127.0.0.1", "example.com"]):
                        continue
                    discovered.add(endpoint)
            except re.error:
                pass

        # Extract subdomains
        for m in SUBDOMAIN_PATTERN.finditer(content):
            subdomain = m.group(1).lower()
            if own_domain in subdomain or subdomain.endswith(own_domain):
                subdomains.add(subdomain)

    # Sort and deduplicate
    api_paths = sorted([e for e in discovered if e.startswith(("/", "http"))])
    out.append(f"  Discovered {len(api_paths)} unique endpoints")
    out.append("")
    out.append("── API Endpoints ──────────────────────────────")
    for ep in api_paths[:100]:
        out.append(f"  {ep}")

    if subdomains:
        out.append("")
        out.append("── Subdomains Mentioned in JS ──────────────────")
        for sub in sorted(subdomains)[:30]:
            out.append(f"  {sub}")

    out.append("")
    out.append(f"Total: {len(api_paths)} endpoints, {len(subdomains)} subdomains")
    out.append("Next: Test discovered endpoints with idor_probe, mass_assignment_probe, ffuf_fuzz")

    return "\n".join(out)
