"""
Tool Call Throttler
Enforces per-category rate limits between consecutive tool calls so that
agents don't hammer targets with dozens of requests per second.

Configuration
-------------
Limits are read from environment variables at import time and can also be
overridden at runtime via ``get_throttler().configure()``.

  THROTTLE_ENABLED=1          # "0" to disable entirely (default: enabled)
  THROTTLE_HTTP_DELAY=0.1     # seconds between curl/HTTP tools (default 0.1)
  THROTTLE_SCAN_DELAY=0.0     # seconds between heavy scanners (default 0)
  THROTTLE_BRUTE_DELAY=0.0    # seconds between brute-force tools (default 0)
  THROTTLE_DEFAULT_DELAY=0.0  # fallback for tools not in any category

Usage
-----
  from src.sdk.throttle import get_throttler

  # In runner.py, just before tool.invoke():
  get_throttler().wait(tool_name)

  # In main.py, to change limits live:
  get_throttler().configure(http=1.0, scan=2.0)
"""

from __future__ import annotations

import os
import time
import threading
from typing import Optional
from loguru import logger


# ─────────────────────────────────────────────────────────────────────────────
# Category definitions
# ─────────────────────────────────────────────────────────────────────────────

# HTTP/curl tools that can easily trigger rate-limiting or bans
_HTTP_TOOLS: frozenset[str] = frozenset({
    "curl_request", "curl_exploit", "httpx_probe", "gospider_crawl",
    "gau_urls", "arjun_scan", "gobuster_scan", "dirsearch_scan",
    "ffuf_fuzz", "dalfox_scan", "xsstrike", "commix",
    "wpscan", "wafw00f_detect", "whatweb_scan",
    "nosqlmap_attack", "tplmap_scan", "jwt_tool_attack",
})

# Heavy background scanners (slower; no need for delay between invocations)
_SCAN_TOOLS: frozenset[str] = frozenset({
    "nmap_scan", "nuclei_scan", "nikto_scan", "sqlmap_attack",
    "wapiti_scan", "masscan", "rustscan",
})

# Brute-force tools (already internally rate-limited by hydra/patator)
_BRUTE_TOOLS: frozenset[str] = frozenset({
    "hydra_bruteforce", "patator_bruteforce", "crackmapexec",
    "kerbrute_userenum", "kerbrute_spray", "evil_winrm",
})

# Maps category name → member set (used for display / config)
_CATEGORIES: dict[str, frozenset[str]] = {
    "http":  _HTTP_TOOLS,
    "scan":  _SCAN_TOOLS,
    "brute": _BRUTE_TOOLS,
}


def _tool_category(tool_name: str) -> str:
    """Return the throttle category for a given tool name."""
    for cat, members in _CATEGORIES.items():
        if tool_name in members:
            return cat
    return "default"


# ─────────────────────────────────────────────────────────────────────────────
# Throttler
# ─────────────────────────────────────────────────────────────────────────────

class ToolThrottler:
    """
    Enforces minimum inter-call delays per tool category.

    Thread-safe: uses per-category locks so parallel tool categories don't
    block each other while still serialising within the same category.
    """

    def __init__(self):
        self.enabled: bool = os.getenv("THROTTLE_ENABLED", "1") != "0"

        # Default delays (seconds) — tuned for polite scanning
        self._delays: dict[str, float] = {
            "http":    float(os.getenv("THROTTLE_HTTP_DELAY",  "0.1")),
            "scan":    float(os.getenv("THROTTLE_SCAN_DELAY",  "0.0")),
            "brute":   float(os.getenv("THROTTLE_BRUTE_DELAY", "0.0")),
            "default": float(os.getenv("THROTTLE_DEFAULT_DELAY", "0.0")),
        }

        # Last call timestamp per category
        self._last_call: dict[str, float] = {}

        # Per-category lock to avoid races when parallel tool calls happen
        self._locks: dict[str, threading.Lock] = {
            cat: threading.Lock() for cat in ("http", "scan", "brute", "default")
        }

        # Per-tool override delays (set via configure())
        self._tool_overrides: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(
        self,
        http:    Optional[float] = None,
        scan:    Optional[float] = None,
        brute:   Optional[float] = None,
        default: Optional[float] = None,
        enabled: Optional[bool]  = None,
        tool_overrides: Optional[dict[str, float]] = None,
    ) -> None:
        """
        Update throttle settings at runtime.

        Args:
            http:    Delay between HTTP tool calls (seconds).
            scan:    Delay between heavy scanner calls (seconds).
            brute:   Delay between brute-force tool calls (seconds).
            default: Fallback delay for uncategorised tools (seconds).
            enabled: Enable/disable throttling entirely.
            tool_overrides: Per-tool delay dict e.g. {"curl_request": 1.0}.
        """
        if http    is not None: self._delays["http"]    = max(0.0, http)
        if scan    is not None: self._delays["scan"]    = max(0.0, scan)
        if brute   is not None: self._delays["brute"]   = max(0.0, brute)
        if default is not None: self._delays["default"] = max(0.0, default)
        if enabled is not None: self.enabled = enabled
        if tool_overrides:
            self._tool_overrides.update(tool_overrides)
        logger.debug(f"Throttle config updated: {self._delays}, enabled={self.enabled}")

    def get_delay(self, tool_name: str) -> float:
        """Return the configured delay for a given tool (seconds, ≥ 0)."""
        if not self.enabled:
            return 0.0
        # Per-tool override takes priority
        if tool_name in self._tool_overrides:
            return self._tool_overrides[tool_name]
        cat = _tool_category(tool_name)
        return self._delays.get(cat, 0.0)

    # ------------------------------------------------------------------
    # Core wait
    # ------------------------------------------------------------------

    def wait(self, tool_name: str) -> float:
        """
        Block until the minimum inter-call delay for this tool's category
        has elapsed since the last call in that category.

        Returns the actual time slept (seconds) — 0 if no sleep was needed.
        """
        if not self.enabled:
            return 0.0

        delay = self.get_delay(tool_name)
        if delay <= 0.0:
            # Update timestamp even when delay is zero (for tracking)
            cat = _tool_category(tool_name)
            self._last_call[cat] = time.monotonic()
            return 0.0

        cat = _tool_category(tool_name)
        lock = self._locks.get(cat, self._locks["default"])

        with lock:
            now = time.monotonic()
            last = self._last_call.get(cat, 0.0)
            elapsed = now - last
            sleep_for = max(0.0, delay - elapsed)

            if sleep_for > 0.0:
                logger.debug(
                    f"Throttle [{cat}]: sleeping {sleep_for:.2f}s before {tool_name}"
                )
                time.sleep(sleep_for)

            self._last_call[cat] = time.monotonic()
            return sleep_for

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return a snapshot of current throttle configuration and state."""
        return {
            "enabled": self.enabled,
            "delays": dict(self._delays),
            "tool_overrides": dict(self._tool_overrides),
            "categories": {cat: sorted(members) for cat, members in _CATEGORIES.items()},
        }

    def category_for(self, tool_name: str) -> str:
        """Return the category string for a tool name."""
        return _tool_category(tool_name)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_throttler: Optional[ToolThrottler] = None


def get_throttler() -> ToolThrottler:
    """Get (or lazily create) the global ToolThrottler instance."""
    global _throttler
    if _throttler is None:
        _throttler = ToolThrottler()
    return _throttler
