"""
Evasion-aware HTTP session.

Three mechanisms folded into one Session:

  1. JA3/JA4 fingerprint rotation (curl_cffi `Session(impersonate=...)` if
     installed; falls back to plain requests).
  2. Header-order randomization — many bot-detection systems hash the order
     of request headers, not just their values. We shuffle order while keeping
     a sane `Host`/`User-Agent` placement.
  3. Proxy rotation honoring src/repl/* proxy state so EVERY tool that uses
     this session honors the operator's proxy/Tor toggle.

Tools should call `get_session()` instead of `requests.request(...)` directly.
"""

from __future__ import annotations

import os
import random
from typing import Any, Optional

import requests
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Browser impersonation profiles for curl_cffi (when installed)
# ─────────────────────────────────────────────────────────────────────────────

CURL_CFFI_PROFILES = [
    "chrome120", "chrome119", "chrome116", "chrome110", "chrome107",
    "edge99", "edge101",
    "safari15_3", "safari15_5", "safari17_0",
    "firefox109",
]


def _try_curl_cffi():
    try:
        from curl_cffi import requests as cf_requests  # type: ignore
        return cf_requests
    except ImportError:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Default header palette (shuffled per-request)
# ─────────────────────────────────────────────────────────────────────────────

UA_POOL = [
    # Chrome on Windows / Mac
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def random_browser_headers() -> dict:
    ua = random.choice(UA_POOL)
    is_chrome = "Chrome/" in ua and "Edg/" not in ua and "OPR/" not in ua
    is_firefox = "Firefox/" in ua
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.7", "en-US,en;q=0.5"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "DNT": random.choice(["1", "0"]),
        "Upgrade-Insecure-Requests": "1",
    }
    if is_chrome:
        headers.update({
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })
    if is_firefox:
        headers["TE"] = "trailers"
    return headers


def shuffle_headers(headers: dict) -> dict:
    """Return a dict whose keys are reordered. Python preserves insertion order."""
    keys = list(headers.keys())
    if "Host" in keys:
        keys.remove("Host")
    if "User-Agent" in keys:
        keys.remove("User-Agent")
    random.shuffle(keys)
    out: dict = {}
    if "Host" in headers:
        out["Host"] = headers["Host"]
    if "User-Agent" in headers:
        out["User-Agent"] = headers["User-Agent"]
    for k in keys:
        out[k] = headers[k]
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Proxy state — read from REPL / env
# ─────────────────────────────────────────────────────────────────────────────

def _current_proxies() -> dict | None:
    """
    Source order:
      1. proxy_manager active proxy (TorNet/Anonsurf)
      2. REPL proxy state (src.repl.session.global_session.env_overrides PROXY)
      3. http_proxy / https_proxy environment vars
      4. None
    """
    # Check proxy_manager first
    try:
        from src.tools.proxy_manager import get_proxy_url
        pm_proxy = get_proxy_url()
        if pm_proxy:
            return {"http": pm_proxy, "https": pm_proxy}
    except Exception:
        pass

    try:
        from src.repl.session import global_session
        env = getattr(global_session, "env_overrides", {}) or {}
        proxy = env.get("HTTP_PROXY") or env.get("PROXY")
        if proxy:
            return {"http": proxy, "https": proxy}
    except Exception:
        pass

    p = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if p:
        return {"http": p, "https": p}
    return None


# ─────────────────────────────────────────────────────────────────────────────
# EvasionSession — drop-in replacement for requests.Session
# ─────────────────────────────────────────────────────────────────────────────

class EvasionSession:
    """
    Drop-in replacement for requests.Session() that:
      - rotates JA3 via curl_cffi when available
      - rotates User-Agent + browser-like headers
      - shuffles header order
      - honors proxy/Tor state
      - sets verify=False by default (offensive tools usually want this)
    """

    def __init__(self, impersonate: str | None = None):
        self._cf = _try_curl_cffi()
        self._impersonate = impersonate or random.choice(CURL_CFFI_PROFILES)
        if self._cf:
            self._sess = self._cf.Session(impersonate=self._impersonate)
        else:
            self._sess = requests.Session()

    def request(self, method: str, url: str, **kw) -> Any:
        # Merge a randomized header palette over user-supplied headers
        headers = dict(random_browser_headers())
        headers.update(kw.pop("headers", None) or {})
        headers = shuffle_headers(headers)

        proxies = kw.pop("proxies", None) or _current_proxies()
        verify = kw.pop("verify", False)

        # curl_cffi accepts `impersonate=` per-request; rotate if not pinned
        if self._cf and "impersonate" not in kw:
            kw["impersonate"] = random.choice(CURL_CFFI_PROFILES)

        try:
            return self._sess.request(method, url, headers=headers,
                                      proxies=proxies, verify=verify, **kw)
        except Exception as e:
            logger.debug(f"[evasion] request failed via primary, retrying plain: {e}")
            # Hard fallback to plain requests
            return requests.request(method, url, headers=headers,
                                    proxies=proxies, verify=verify, **kw)

    def get(self, url, **kw):    return self.request("GET", url, **kw)
    def post(self, url, **kw):   return self.request("POST", url, **kw)
    def put(self, url, **kw):    return self.request("PUT", url, **kw)
    def delete(self, url, **kw): return self.request("DELETE", url, **kw)
    def head(self, url, **kw):   return self.request("HEAD", url, **kw)
    def patch(self, url, **kw):  return self.request("PATCH", url, **kw)


_global_session: Optional[EvasionSession] = None


def get_session(impersonate: str | None = None) -> EvasionSession:
    """Get (or create) the process-wide evasion session."""
    global _global_session
    if _global_session is None:
        _global_session = EvasionSession(impersonate=impersonate)
    return _global_session


# ─────────────────────────────────────────────────────────────────────────────
# Function-tool surface
# ─────────────────────────────────────────────────────────────────────────────

from src.sdk.tool import function_tool


@function_tool()
def evasion_status() -> str:
    """Show the active evasion configuration (JA3 profile, proxy, UA pool size)."""
    sess = get_session()
    cf = "curl_cffi" if sess._cf else "plain requests (install curl_cffi for JA3 forging)"
    proxies = _current_proxies() or "(none)"
    return "\n".join([
        "## Evasion status",
        f"  HTTP backend:   {cf}",
        f"  JA3 profile:    {sess._impersonate}",
        f"  Proxy:          {proxies}",
        f"  UA pool:        {len(UA_POOL)} entries",
        "  Header shuffle: enabled",
    ])


@function_tool()
def evasion_set_profile(profile: str) -> str:
    """
    Pin the JA3 impersonation profile (curl_cffi).

    Args:
        profile: One of chrome120, chrome119, chrome116, edge99, safari15_5,
                 firefox109, etc. Pass 'random' to rotate per-request.
    """
    global _global_session
    if profile == "random":
        _global_session = None  # next get_session() will rotate
        return "Evasion profile: per-request rotation"
    if profile not in CURL_CFFI_PROFILES:
        return f"Error: unknown profile. Valid: {', '.join(CURL_CFFI_PROFILES)}"
    _global_session = EvasionSession(impersonate=profile)
    return f"Evasion profile pinned: {profile}"


@function_tool()
def evasion_request(url: str, method: str = "GET", headers_json: str = "{}", body: str = "") -> str:
    """
    Send a single request via the evasion session — useful when an LLM-driven
    tool needs to hand-craft a probe but still wants the JA3 + proxy stack.

    Args:
        url:           Target URL
        method:        HTTP verb
        headers_json:  JSON of override headers
        body:          Body (string)
    """
    import json as _json
    try:
        hdrs = _json.loads(headers_json) if headers_json else {}
    except Exception:
        hdrs = {}

    sess = get_session()
    try:
        if body:
            r = sess.request(method, url, headers=hdrs, data=body, timeout=15)
        else:
            r = sess.request(method, url, headers=hdrs, timeout=15)
    except Exception as e:
        return f"Error: {e}"

    snippet = (r.text or "")[:1500]
    out = [f"## evasion_request: {method} {url}",
           f"HTTP {r.status_code}",
           f"Length: {len(r.content)}",
           f"Server: {r.headers.get('Server','?')}"]
    out.append(f"\n--- body (first 1500B) ---\n{snippet}")
    return "\n".join(out)
