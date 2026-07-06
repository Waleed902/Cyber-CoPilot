"""Import bug bounty scope from program pages."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import requests

from src.sdk.scope import get_scope_manager, extract_domain_from_target


_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0"
)
_TIMEOUT = 25
_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?![\w.-])",
    re.IGNORECASE,
)
_NOISE_DOMAINS = {
    "bugcrowd.com",
    "www.bugcrowd.com",
    "docs.bugcrowd.com",
    "hackerone.com",
    "www.hackerone.com",
    "intigriti.com",
    "www.intigriti.com",
    "yeswehack.com",
    "www.yeswehack.com",
    "google.com",
    "www.google.com",
    "gstatic.com",
    "googleapis.com",
    "cloudflare.com",
    "w3.org",
    "schema.org",
}
_STATIC_SUFFIXES = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
)


@dataclass
class ScopeImportResult:
    url: str
    imported: list[str]
    ignored: list[str]
    status_code: int | None = None
    error: str = ""

    def format(self) -> str:
        if self.error:
            return f"Scope import failed for {self.url}: {self.error}"

        lines = [
            f"Scope import completed from {self.url}",
            f"HTTP status: {self.status_code}",
            f"Imported: {len(self.imported)}",
        ]
        for target in self.imported:
            lines.append(f"  - {target}")
        if self.ignored:
            lines.append(f"Ignored/noise candidates: {len(self.ignored)}")
        return "\n".join(lines)


def _strip_html(raw: str) -> str:
    raw = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = html.unescape(raw)
    return re.sub(r"\s+", " ", raw)


def _registrable_hint_match(domain: str, hint: str) -> bool:
    if not hint:
        return True
    hint = hint.lower().lstrip("*.").strip()
    domain_clean = domain.lower().lstrip("*.")
    return domain_clean == hint or domain_clean.endswith("." + hint)


def extract_scope_domains(page_text: str, root_hint: str = "", source_host: str = "") -> tuple[list[str], list[str]]:
    """Extract domain-like in-scope candidates from a bug bounty page."""
    root_hint = extract_domain_from_target(root_hint).lower() if root_hint else ""
    source_host = (source_host or "").lower()
    source_root = ".".join(source_host.split(".")[-2:]) if source_host else ""

    candidates: set[str] = set()
    ignored: set[str] = set()

    for match in _DOMAIN_RE.finditer(page_text):
        wildcard, domain = match.groups()
        value = ((wildcard or "") + domain).lower().rstrip(".")
        clean = value.lstrip("*.")
        following = page_text[match.end():match.end() + 32].lower()

        if clean.endswith(_STATIC_SUFFIXES) or re.match(r"^/[^\s\"'<>]*(" + "|".join(re.escape(s) for s in _STATIC_SUFFIXES) + r")\b", following):
            ignored.add(value)
            continue
        if clean in _NOISE_DOMAINS or clean.endswith(".bugcrowd.com"):
            ignored.add(value)
            continue
        if source_root and clean == source_root:
            ignored.add(value)
            continue
        if root_hint and not _registrable_hint_match(value, root_hint):
            ignored.add(value)
            continue
        if "." not in clean:
            ignored.add(value)
            continue

        candidates.add(value)

    return sorted(candidates), sorted(ignored)


def _append_authorized_targets(targets: Iterable[str], source_url: str):
    targets = sorted(set(targets))
    if not targets:
        return

    auth_path = Path("targets") / "AUTHORIZED_TARGETS.md"
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    existing = auth_path.read_text(encoding="utf-8") if auth_path.exists() else "# Authorized Security Testing Targets\n"

    lines = []
    for target in targets:
        marker = f"- `{target}`"
        if marker not in existing:
            lines.append(f"- `{target}` - imported from bug bounty scope: {source_url}")

    if not lines:
        return

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block = (
        "\n\n## Imported Bug Bounty Scope\n"
        f"Imported: {stamp}\n"
        f"Source: {source_url}\n"
        + "\n".join(lines)
        + "\n"
    )
    auth_path.write_text(existing.rstrip() + block, encoding="utf-8")


def import_scope_from_url(url: str, root_hint: str = "") -> ScopeImportResult:
    """Fetch a bug bounty program URL and add extracted targets to local scope."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return ScopeImportResult(url=url, imported=[], ignored=[], error="URL must start with http:// or https://")

    try:
        resp = requests.get(
            url,
            headers={
                "User-Agent": _UA,
                "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            },
            timeout=_TIMEOUT,
            allow_redirects=True,
        )
    except Exception as exc:
        return ScopeImportResult(url=url, imported=[], ignored=[], error=str(exc))

    text = resp.text
    parsed = urlparse(url)
    readable = text if "json" in resp.headers.get("Content-Type", "") else _strip_html(text)
    targets, ignored = extract_scope_domains(readable, root_hint=root_hint, source_host=parsed.hostname or "")

    manager = get_scope_manager()
    imported: list[str] = []
    notes = f"Imported from bug bounty program page: {url}"
    for target in targets:
        manager.add_scope(
            target,
            "in",
            notes=notes,
            program_url=url,
            platform=(parsed.hostname or "").lower(),
            allowed_testing="See imported bug bounty program page",
            excluded_tests="See imported bug bounty program page",
            rate_limits="See imported bug bounty program page",
            last_verified=datetime.now().isoformat(),
        )
        imported.append(target)

    _append_authorized_targets(imported, url)

    return ScopeImportResult(
        url=url,
        imported=imported,
        ignored=ignored,
        status_code=resp.status_code,
    )
