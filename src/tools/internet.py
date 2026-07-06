"""
Internet Access Tools — Live web search and URL fetching for agents.

  web_search  — Multi-engine web search with auto-fetch of top results
  fetch_url   — Fetch a URL and return clean, readable text

Search engine priority (fastest/best first):
  1. Brave Search API  (BRAVE_SEARCH_KEY env var — free tier: 2000/mo)
  2. DuckDuckGo JSON API (no key, fast)
  3. DuckDuckGo HTML scrape (fallback)
  4. DuckDuckGo Instant Answer (last resort)

Primary use cases:
  - Read live CVE advisories and PoC writeups
  - Research unknown technology versions and their known vulnerabilities
  - Fetch bug bounty program scope / rules pages
  - Read exploit writeups or vulnerability research papers
  - Retrieve robots.txt / security.txt / sitemap.xml from a target
"""

from __future__ import annotations

import concurrent.futures
import html as _html_stdlib
import os
import re
import time
import urllib.parse

import requests
from loguru import logger

from src.sdk.tool import function_tool

# ── Constants ─────────────────────────────────────────────────────────────────
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_TIMEOUT = 12          # per-request timeout (seconds) — fast fail
_MAX_CONTENT = 8000    # default char cap returned to the agent
_FETCH_TIMEOUT = 18    # timeout for auto-fetching top result pages


# ════════════════════════════════════════════════════════════════════════════
# HTML stripping helpers
# ════════════════════════════════════════════════════════════════════════════

def _strip_html(raw: str, max_chars: int = _MAX_CONTENT) -> str:
    """Remove HTML tags and decode entities; collapse whitespace."""
    raw = re.sub(r"<(script|style|nav|footer|header|aside)[^>]*>.*?</\1>",
                 "", raw, flags=re.DOTALL | re.IGNORECASE)
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = _html_stdlib.unescape(raw)
    raw = re.sub(r"[ \t]+", " ", raw)
    raw = re.sub(r"\n{3,}", "\n\n", raw)
    raw = raw.strip()
    if len(raw) > max_chars:
        return raw[:max_chars] + " …[truncated]"
    return raw


def _clean_tag_text(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s)
    return _html_stdlib.unescape(s).strip()


def _extract_main_content(html: str, max_chars: int = _MAX_CONTENT) -> str:
    """
    Extract the main readable content from a page, preferring <article>,
    <main>, or the largest <div> block over noisy nav/sidebar content.
    """
    # Try to pull the article/main block first
    for tag in ("article", "main", "div"):
        block = re.search(
            rf"<{tag}[^>]*>(.*?)</{tag}>",
            html, re.DOTALL | re.IGNORECASE
        )
        if block:
            candidate = _strip_html(block.group(1), max_chars)
            if len(candidate) > 300:
                return candidate

    # Fallback: strip everything
    return _strip_html(html, max_chars)


# ════════════════════════════════════════════════════════════════════════════
# Search result data class
# ════════════════════════════════════════════════════════════════════════════

class _Result:
    __slots__ = ("title", "url", "snippet", "page_content")

    def __init__(self, title: str = "", url: str = "", snippet: str = ""):
        self.title = title.strip()
        self.url = url.strip()
        self.snippet = snippet.strip()
        self.page_content: str = ""  # filled in by auto-fetch

    def __repr__(self) -> str:
        return f"<Result {self.url!r}>"


# ════════════════════════════════════════════════════════════════════════════
# Search backends
# ════════════════════════════════════════════════════════════════════════════

def _brave_search(query: str, max_results: int, api_key: str) -> list[_Result]:
    """Brave Search API — best quality, free tier (2000 req/mo)."""
    try:
        resp = requests.get(
            "https://api.search.brave.com/res/v1/web/search",
            params={"q": query, "count": max_results, "search_lang": "en"},
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
                "X-Subscription-Token": api_key,
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        items = data.get("web", {}).get("results", [])
        results = []
        for item in items[:max_results]:
            results.append(_Result(
                title=item.get("title", ""),
                url=item.get("url", ""),
                snippet=item.get("description", ""),
            ))
        return results
    except Exception as e:
        logger.debug(f"[web_search] Brave failed: {e}")
        return []


def _serpapi_search(query: str, max_results: int, api_key: str) -> list[_Result]:
    """SerpAPI — real Google results."""
    try:
        resp = requests.get(
            "https://serpapi.com/search.json",
            params={
                "q": query,
                "api_key": api_key,
                "num": max_results,
                "engine": "google",
                "hl": "en",
                "gl": "us",
            },
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        results = []
        for r in data.get("organic_results", [])[:max_results]:
            results.append(_Result(
                title=r.get("title", ""),
                url=r.get("link", ""),
                snippet=r.get("snippet", ""),
            ))
        return results
    except Exception as e:
        logger.debug(f"[web_search] SerpAPI failed: {e}")
        return []


def _ddg_json_search(query: str, max_results: int) -> list[_Result]:
    """
    DuckDuckGo via the ddg4 JSON endpoint — fast, no scraping needed.
    This hits the same backend as the DDG browser extension.
    """
    try:
        session = requests.Session()
        # Step 1: get a vqd token (required by DDG API)
        token_resp = session.get(
            "https://duckduckgo.com/",
            params={"q": query, "ia": "web"},
            headers={
                "User-Agent": _UA,
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=_TIMEOUT,
        )
        vqd_match = re.search(r'vqd=["\']([\d-]+)["\']', token_resp.text)
        if not vqd_match:
            vqd_match = re.search(r'"vqd":\s*"([\d-]+)"', token_resp.text)
        if not vqd_match:
            return []
        vqd = vqd_match.group(1)

        # Step 2: fetch JSON results
        api_resp = session.get(
            "https://links.duckduckgo.com/d.js",
            params={
                "q": query,
                "vqd": vqd,
                "p": "1",
                "kl": "us-en",
                "df": "",
            },
            headers={
                "User-Agent": _UA,
                "Referer": "https://duckduckgo.com/",
                "Accept": "application/json, */*",
            },
            timeout=_TIMEOUT,
        )
        # The response is a JS file: DDG.pageLayout.load('d',[ ... ]);
        raw = api_resp.text
        json_match = re.search(r"DDG\.pageLayout\.load\('d',(\[.*?\])\);", raw, re.DOTALL)
        if not json_match:
            return []

        import json
        items = json.loads(json_match.group(1))
        results = []
        for item in items:
            if not isinstance(item, dict) or not item.get("u"):
                continue
            results.append(_Result(
                title=_clean_tag_text(item.get("t", "")),
                url=item.get("u", ""),
                snippet=_clean_tag_text(item.get("a", "")),
            ))
            if len(results) >= max_results:
                break
        return results
    except Exception as e:
        logger.debug(f"[web_search] DDG JSON failed: {e}")
        return []


def _ddg_html_search(query: str, max_results: int) -> list[_Result]:
    """DuckDuckGo HTML scrape — reliable fallback."""
    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query, "b": "", "kl": "us-en"},
            headers={
                "User-Agent": _UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.text

        titles   = re.findall(r'class="result__a"[^>]*>(.*?)</a>', body, re.DOTALL)
        urls_raw = re.findall(r'class="result__url"[^>]*>(.*?)</a>', body, re.DOTALL)
        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', body, re.DOTALL)

        titles   = [_clean_tag_text(t) for t in titles]
        urls_raw = [_clean_tag_text(u).replace(" ", "") for u in urls_raw]
        snippets = [_clean_tag_text(s) for s in snippets]

        results = []
        count = min(max_results, len(titles))
        for i in range(count):
            results.append(_Result(
                title=titles[i] if i < len(titles) else "",
                url=urls_raw[i] if i < len(urls_raw) else "",
                snippet=snippets[i] if i < len(snippets) else "",
            ))
        return results
    except Exception as e:
        logger.debug(f"[web_search] DDG HTML scrape failed: {e}")
        return []


def _ddg_instant_answer(query: str) -> list[_Result]:
    """DuckDuckGo Instant Answer API — last resort."""
    try:
        resp = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_redirect": "1", "no_html": "1"},
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        data = resp.json()
        abstract = data.get("AbstractText", "") or data.get("Answer", "")
        if abstract:
            return [_Result(
                title=data.get("Heading", query),
                url=data.get("AbstractURL", ""),
                snippet=abstract,
            )]
        return []
    except Exception:
        return []


# ════════════════════════════════════════════════════════════════════════════
# Auto-fetch: read top result pages in parallel
# ════════════════════════════════════════════════════════════════════════════

# Domains where fetching the page adds nothing (login walls, social, tracking)
_SKIP_FETCH_DOMAINS = frozenset({
    "twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com",
    "reddit.com",  # Reddit blocks bots heavily
    "youtube.com", "youtu.be",
    "amazon.com", "ebay.com",
    "docs.google.com", "drive.google.com",
})

# Domains with very high signal content for security research
_PRIORITY_FETCH_DOMAINS = frozenset({
    "github.com", "raw.githubusercontent.com",
    "nvd.nist.gov", "cve.mitre.org",
    "exploit-db.com", "packetstormsecurity.com",
    "hackerone.com", "bugcrowd.com",
    "portswigger.net", "owasp.org",
    "thehackernews.com", "bleepingcomputer.com",
    "securityweek.com", "rapid7.com",
})


def _domain_of(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _fetch_one(result: _Result, max_chars: int = 3000) -> None:
    """Fetch a single result's page content in-place (for ThreadPoolExecutor)."""
    url = result.url
    if not url or not url.startswith("http"):
        return

    domain = _domain_of(url)
    if domain in _SKIP_FETCH_DOMAINS:
        return

    # For GitHub, rewrite to raw content when it's a blob URL
    if "github.com" in domain and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    try:
        resp = requests.get(
            url,
            headers={
                "User-Agent": _UA,
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            },
            timeout=_FETCH_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
        ct = resp.headers.get("Content-Type", "")
        if "html" in ct or not ct:
            content = _extract_main_content(resp.text, max_chars)
        elif "json" in ct:
            content = resp.text[:max_chars]
        else:
            content = resp.text[:max_chars]

        result.page_content = content.strip()
    except Exception as e:
        logger.debug(f"[web_search] fetch {url} failed: {e}")


def _parallel_fetch(results: list[_Result], max_chars: int = 3000,
                    max_workers: int = 4, timeout: float = 15.0) -> None:
    """Fetch top results in parallel with a wall-clock timeout."""
    # Prioritise high-signal domains
    def _priority(r: _Result) -> int:
        d = _domain_of(r.url)
        if d in _SKIP_FETCH_DOMAINS:
            return 2
        if d in _PRIORITY_FETCH_DOMAINS:
            return 0
        return 1

    ordered = sorted(results, key=_priority)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch_one, r, max_chars): r for r in ordered}
        try:
            concurrent.futures.wait(futures, timeout=timeout)
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
# Deduplication
# ════════════════════════════════════════════════════════════════════════════

def _dedupe(results: list[_Result]) -> list[_Result]:
    """Remove duplicate domains and near-identical snippets."""
    seen_domains: set[str] = set()
    seen_snippets: set[str] = set()
    out: list[_Result] = []
    for r in results:
        domain = _domain_of(r.url)
        snippet_key = r.snippet[:60].lower().strip()
        if domain and domain in seen_domains:
            continue
        if snippet_key and snippet_key in seen_snippets:
            continue
        if domain:
            seen_domains.add(domain)
        if snippet_key:
            seen_snippets.add(snippet_key)
        out.append(r)
    return out


# ════════════════════════════════════════════════════════════════════════════
# Output formatter
# ════════════════════════════════════════════════════════════════════════════

def _format_results(results: list[_Result], query: str, engine: str,
                    auto_fetched: bool) -> str:
    lines = [f"## 🌐 Web Search: {query}"]
    lines.append(f"_Engine: {engine} · {len(results)} results"
                 + (" · top pages auto-fetched" if auto_fetched else "") + "_\n")

    for i, r in enumerate(results, 1):
        lines.append(f"**[{i}] {r.title or 'No title'}**")
        lines.append(f"    URL: {r.url}")
        if r.snippet:
            lines.append(f"    {r.snippet}")
        if r.page_content and len(r.page_content) > 80:
            # Indent and cap the fetched content
            preview = r.page_content[:2000]
            indented = "\n".join("    " + ln for ln in preview.splitlines())
            lines.append(f"\n    📄 Page content:\n{indented}")
            if len(r.page_content) > 2000:
                lines.append(f"    …[{len(r.page_content) - 2000} more chars available via fetch_url]")
        lines.append("")

    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
# TOOL 1 — web_search
# ════════════════════════════════════════════════════════════════════════════

@function_tool()
def web_search(
    query: str,
    max_results: int = 8,
    site: str = "",
    auto_fetch: bool = True,
) -> str:
    """
    Search the live web and return result titles, URLs, snippets, AND
    auto-fetched page content from the top results — all in one call.

    Search engine priority (automatic, no config needed):
      1. Brave Search API  (set BRAVE_SEARCH_KEY for 2000 free searches/mo)
      2. SerpAPI / Google  (set SERPAPI_KEY)
      3. DuckDuckGo JSON   (free, no key)
      4. DuckDuckGo HTML   (scrape fallback)
      5. DDG Instant Answer (last resort)

    Best used for:
    - Finding live CVE advisories and PoC writeups
      e.g. web_search("CVE-2024-12345 PoC exploit site:github.com")
    - Researching unknown software versions for known vulnerabilities
      e.g. web_search("Apache 2.4.51 RCE vulnerability")
    - Fetching bug bounty program scope pages
      e.g. web_search("HackerOne example.com bug bounty scope")
    - Reading exploit writeups after discovering a service
    - Any question requiring up-to-date information

    Args:
        query:       Plain-language search query (be specific for better results)
        max_results: Number of results to return (1-20, default 8)
        site:        Restrict results to one domain (e.g. "github.com")
        auto_fetch:  Also fetch page content from top results (default True).
                     Set False if you only need URLs/snippets.

    Returns:
        Numbered results with title, URL, snippet, and fetched page content.
    """
    max_results = max(1, min(max_results, 20))
    full_query = f"site:{site} {query}" if site else query

    # ── Engine selection ──────────────────────────────────────────────────
    results: list[_Result] = []
    engine_label = ""

    brave_key = os.environ.get("BRAVE_SEARCH_KEY", "")
    serpapi_key = os.environ.get("SERPAPI_KEY", "")

    if brave_key:
        results = _brave_search(full_query, max_results, brave_key)
        engine_label = "Brave Search"

    if not results and serpapi_key:
        results = _serpapi_search(full_query, max_results, serpapi_key)
        engine_label = "SerpAPI/Google"

    if not results:
        results = _ddg_json_search(full_query, max_results)
        engine_label = "DuckDuckGo"

    if not results:
        results = _ddg_html_search(full_query, max_results)
        engine_label = "DuckDuckGo (HTML)"

    if not results:
        results = _ddg_instant_answer(full_query)
        engine_label = "DuckDuckGo (Instant)"

    if not results:
        hint = ""
        if not brave_key:
            hint = " Set BRAVE_SEARCH_KEY in .env for reliable free search (2000/mo)."
        return f"No results found for: {full_query}.{hint}"

    # ── Deduplicate ───────────────────────────────────────────────────────
    results = _dedupe(results)

    # ── Auto-fetch page content in parallel ───────────────────────────────
    fetched = False
    if auto_fetch and results:
        # Only auto-fetch top 4 to stay fast
        fetch_targets = results[:4]
        _parallel_fetch(fetch_targets, max_chars=3000, max_workers=4, timeout=12.0)
        fetched = any(r.page_content for r in fetch_targets)

    return _format_results(results, query, engine_label, fetched)


# ════════════════════════════════════════════════════════════════════════════
# JS rendering helper (Playwright)
# ════════════════════════════════════════════════════════════════════════════

def _should_use_js_fetch(body: str, content_type: str) -> bool:
    """Heuristic to detect JS-heavy or bot-protected pages."""
    if content_type and "html" not in content_type.lower():
        return False
    if not body:
        return True

    lc = body.lower()
    challenge_markers = (
        "enable javascript", "checking your browser", "just a moment",
        "attention required", "cloudflare", "cf-ray", "captcha",
        "ddos protection", "access denied", "please enable cookies",
    )
    if any(m in lc for m in challenge_markers):
        return True

    shell_markers = (
        'id="app"', 'id="root"', 'id="__next"', "data-reactroot",
        "ng-app", "ng-version", "data-ng-app",
        "id='app'", "id='root'", "id='__next'",
    )
    stripped = _strip_html(body, max_chars=2000)
    if len(stripped) < 200 and any(m in lc for m in shell_markers):
        return True
    return len(stripped) < 80


def _fetch_with_playwright(url: str, max_chars: int, raw_html: bool) -> str:
    """Fetch and render a URL using Playwright for JS-heavy pages."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except Exception as e:
        return f"JS fetch failed: Playwright not available ({e})"

    response = None
    goto_warning = ""

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(user_agent=_UA)
                page = context.new_page()
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=60000)
                except PlaywrightTimeoutError as e:
                    goto_warning = f"Page.goto timeout: {e}"
                except Exception as e:
                    goto_warning = f"Page.goto error: {e}"

                time.sleep(2)
                html = page.content() or ""
            finally:
                try:
                    browser.close()
                except Exception:
                    pass

        status = response.status if response else "Unknown"
        content_type = ""
        if response:
            content_type = response.headers.get("content-type", "")
        if not content_type:
            content_type = "text/html (rendered)"

        body = html[:max_chars] if raw_html else _strip_html(html, max_chars)
        warning = f"Warning: {goto_warning}\n" if goto_warning else ""
        return (
            f"## 🌐 Fetched (JS): {url}\n"
            f"{warning}"
            f"Status: {status}  |  Content-Type: {content_type.split(';')[0]}\n\n"
            f"{body}"
        )
    except Exception as e:
        return f"JS fetch failed: {e}"


# ════════════════════════════════════════════════════════════════════════════
# TOOL 2 — fetch_url
# ════════════════════════════════════════════════════════════════════════════

@function_tool()
def fetch_url(
    url: str,
    max_chars: int = 8000,
    raw_html: bool = False,
    render_js: bool = False,
    extract_links: bool = False,
) -> str:
    """
    Fetch a URL over HTTP/HTTPS and return its main readable content.

    HTML is automatically cleaned to extract the main article/content block
    (not just stripped — nav/footer/sidebar are removed). JSON and plain-text
    responses are returned as-is.

    Best used for:
    - Reading a CVE/NVD advisory page after web_search returned the URL
    - Reading a GitHub PoC (use raw.githubusercontent.com for raw code)
    - Fetching bug bounty scope / rules pages from HackerOne or Bugcrowd
    - Reading security research posts or vulnerability writeups
    - Retrieving target meta-files: robots.txt, security.txt, sitemap.xml
    - Reading changelogs / release notes to identify vulnerable versions

    Args:
        url:           Full URL to fetch (must start with http:// or https://)
        max_chars:     Maximum characters to return (default 8000, cap 32000)
        raw_html:      Return raw HTML source instead of extracted text
        render_js:     Render with Playwright for JS-heavy/SPA pages
        extract_links: Also return all <a href> links found on the page

    Returns:
        Readable page content (and optionally links), or an error message
    """
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return "Error: Only http:// and https:// URLs are supported."

    # Rewrite GitHub blob URLs to raw content
    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    max_chars = max(500, min(max_chars, 32000))
    js_error = ""

    if render_js:
        js_result = _fetch_with_playwright(url, max_chars, raw_html)
        if not js_result.startswith("JS fetch failed:"):
            return js_result
        js_error = js_result

    try:
        # ── Virtual host awareness ──────────────────────────────────────────
        import re as _re
        from urllib.parse import urlparse as _urlparse
        _req_url = url
        _extra_headers: dict = {}
        _parsed_u = _urlparse(url)
        _fetch_host = _parsed_u.hostname or ""
        if _fetch_host and not _re.match(r'^\d+\.\d+\.\d+\.\d+$', _fetch_host):
            # Use cached DNS check to avoid a blocking gethostbyname() on every call
            try:
                from src.tools.http_proxy import _dns_resolves as _dr
                _host_resolves = _dr(_fetch_host)
            except Exception:
                import socket as _socket
                try:
                    _socket.gethostbyname(_fetch_host)
                    _host_resolves = True
                except Exception:
                    _host_resolves = False
            if not _host_resolves:
                # hostname unresolvable — try to substitute IP from context hub
                try:
                    from src.sdk.context_hub import get_context_hub
                    _hub = get_context_hub()
                    _vip = ""
                    for _sd in _hub.findings.get("subdomains", []):
                        if _sd.get("subdomain") == _fetch_host and _sd.get("ip"):
                            _vip = _sd["ip"]
                            break
                    if not _vip:
                        _ct = _hub.current_target or ""
                        if _re.match(r'^\d+\.\d+\.\d+\.\d+$', _ct):
                            _vip = _ct
                    if _vip:
                        _req_url = url.replace(
                            f"{_parsed_u.scheme}://{_fetch_host}",
                            f"{_parsed_u.scheme}://{_vip}"
                        )
                        _extra_headers["Host"] = _fetch_host
                except Exception:
                    pass

        resp = requests.get(
            _req_url,
            headers={
                "User-Agent": _UA,
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                **_extra_headers,
            },
            timeout=_FETCH_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )

        content_type = resp.headers.get("Content-Type", "")
        status = resp.status_code

        # Auto JS rendering if the response looks like a JS shell or bot challenge
        if not render_js and _should_use_js_fetch(resp.text, content_type):
            js_result = _fetch_with_playwright(url, max_chars, raw_html)
            if not js_result.startswith("JS fetch failed:"):
                return js_result
            if not js_error:
                js_error = js_result

        warning = f"Warning: {js_error}\n" if js_error else ""

        if raw_html:
            body = resp.text[:max_chars]
            return (
                f"## 🌐 Raw HTML: {url}\n"
                f"{warning}"
                f"Status: {status}  |  Content-Type: {content_type.split(';')[0]}\n\n"
                f"{body}"
            )

        # Return JSON / plain text as-is; extract main content for HTML
        if "json" in content_type:
            text = resp.text[:max_chars]
        elif "html" in content_type or not content_type:
            text = _extract_main_content(resp.text, max_chars)
        else:
            text = resp.text[:max_chars]

        output = (
            f"## 🌐 Fetched: {url}\n"
            f"{warning}"
            f"Status: {status}  |  Content-Type: {content_type.split(';')[0]}\n\n"
            f"{text}"
        )

        # Optionally extract links
        if extract_links:
            all_links = re.findall(r'href=["\'](https?://[^"\']+)["\']', resp.text)
            unique_links = list(dict.fromkeys(all_links))[:50]
            if unique_links:
                output += "\n\n### Links Found\n" + "\n".join(f"  {ln}" for ln in unique_links)

        return output

    except requests.exceptions.ConnectionError as e:
        return f"Connection error fetching {url}: {e}"
    except requests.exceptions.Timeout:
        return f"Timeout fetching {url} (limit: {_FETCH_TIMEOUT}s). Try a different URL."
    except Exception as e:
        return f"Error fetching {url}: {e}"
