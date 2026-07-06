"""
Target HTTP knowledge graph.

This module stores the application map that agents discover while crawling,
probing, and validating a bug bounty target.  It is intentionally lightweight:
tools can record observations without needing a database, and agents can ask
for adaptive next tests from the accumulated structure.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def _clean_target(target: str) -> str:
    target = (target or "").strip().lower()
    if not target:
        return "unknown"
    parsed = urllib.parse.urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


def _parse_params(url: str, body: str = "") -> list[str]:
    parsed = urllib.parse.urlparse(url or "")
    params = set(urllib.parse.parse_qs(parsed.query).keys())
    body = body or ""
    if body.strip().startswith("{"):
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                params.update(str(k) for k in data.keys())
        except Exception:
            pass
    else:
        params.update(urllib.parse.parse_qs(body).keys())
    return sorted(p for p in params if p)


def _infer_auth_required(status_code: int, response_excerpt: str = "") -> bool:
    text = (response_excerpt or "").lower()
    return status_code in (401, 403) or any(
        marker in text
        for marker in ("login", "sign in", "unauthorized", "forbidden", "csrf", "permission")
    )


def _resource_hint(path: str) -> str:
    path = path or "/"
    if "/graphql" in path.lower():
        return "graphql"
    if re.search(r"/(?:users?|accounts?|orders?|invoices?|orgs?|teams?)/\d+", path, re.I):
        return "object_id"
    if re.search(r"/api/v\d+/", path):
        return "versioned_api"
    if any(k in path.lower() for k in ("/admin", "/dashboard", "/settings")):
        return "privileged_area"
    return "generic"


@dataclass
class HttpObservation:
    target: str
    url: str
    method: str = "GET"
    status_code: int = 0
    params: list[str] = field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""
    response_length: int = 0
    source_tool: str = ""
    notes: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def host(self) -> str:
        parsed = urllib.parse.urlparse(self.url if "://" in self.url else f"https://{self.url}")
        return parsed.hostname or self.target

    @property
    def path(self) -> str:
        parsed = urllib.parse.urlparse(self.url if "://" in self.url else f"https://{self.url}")
        return parsed.path or "/"

    @property
    def fingerprint(self) -> str:
        return f"{self.method.upper()} {self.host}{self.path}"


class HttpKnowledgeBase:
    def __init__(self, storage_path: str = ".memory/http_knowledge.json"):
        self.storage_path = Path(storage_path)
        self.observations: list[HttpObservation] = []
        self._load()

    def _load(self) -> None:
        if not self.storage_path.exists():
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            self.observations = [HttpObservation(**item) for item in data.get("observations", [])]
        except Exception:
            self.observations = []

    def _save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"observations": [asdict(obs) for obs in self.observations[-2000:]]}
        self.storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def record(
        self,
        target: str,
        url: str,
        method: str = "GET",
        status_code: int = 0,
        params: Optional[list[str]] = None,
        body: str = "",
        auth_required: Optional[bool] = None,
        content_type: str = "",
        response_length: int = 0,
        response_excerpt: str = "",
        source_tool: str = "",
        notes: str = "",
    ) -> HttpObservation:
        target = _clean_target(target or url)
        parsed_params = params if params is not None else _parse_params(url, body)
        inferred_auth = _infer_auth_required(status_code, response_excerpt) if auth_required is None else auth_required
        obs = HttpObservation(
            target=target,
            url=url,
            method=(method or "GET").upper(),
            status_code=int(status_code or 0),
            params=sorted(set(parsed_params)),
            auth_required=bool(inferred_auth),
            content_type=content_type,
            response_length=int(response_length or 0),
            source_tool=source_tool,
            notes=notes,
        )

        existing = next((item for item in self.observations if item.fingerprint == obs.fingerprint), None)
        if existing:
            existing.status_code = obs.status_code or existing.status_code
            existing.params = sorted(set(existing.params + obs.params))
            existing.auth_required = existing.auth_required or obs.auth_required
            existing.content_type = obs.content_type or existing.content_type
            existing.response_length = obs.response_length or existing.response_length
            existing.source_tool = obs.source_tool or existing.source_tool
            existing.notes = obs.notes or existing.notes
            existing.observed_at = obs.observed_at
            obs = existing
        else:
            self.observations.append(obs)

        self._save()
        return obs

    def for_target(self, target: str) -> list[HttpObservation]:
        wanted = _clean_target(target)
        return [
            obs for obs in self.observations
            if obs.target == wanted or obs.host == wanted or obs.host.endswith(f".{wanted}")
        ]

    def summary(self, target: str = "") -> dict[str, Any]:
        observations = self.for_target(target) if target else self.observations
        methods = sorted(set(obs.method for obs in observations))
        params = sorted(set(p for obs in observations for p in obs.params))
        auth_required = [obs for obs in observations if obs.auth_required]
        object_id_paths = [obs.url for obs in observations if _resource_hint(obs.path) == "object_id"]
        api_versions = sorted(set(re.findall(r"/api/(v\d+)/", "\n".join(obs.path for obs in observations), re.I)))
        return {
            "target": _clean_target(target) if target else "all",
            "endpoints": len(observations),
            "methods": methods,
            "parameters": params[:80],
            "auth_required_endpoints": len(auth_required),
            "object_id_paths": object_id_paths[:30],
            "api_versions": api_versions,
        }

    def suggest_tests(self, target: str = "") -> list[dict[str, str]]:
        observations = self.for_target(target) if target else self.observations
        suggestions: list[dict[str, str]] = []
        seen: set[str] = set()

        def add(kind: str, url: str, reason: str, tool: str) -> None:
            key = f"{kind}:{url}:{tool}"
            if key not in seen:
                seen.add(key)
                suggestions.append({"kind": kind, "url": url, "reason": reason, "tool": tool})

        for obs in observations:
            params = {p.lower() for p in obs.params}
            hint = _resource_hint(obs.path)
            if hint == "object_id":
                add("idor", obs.url, "numeric object identifier in URL", "idor_probe or auth_compare_responses")
            if obs.auth_required and obs.method in {"POST", "PUT", "PATCH", "DELETE"}:
                add("access_control", obs.url, "state-changing authenticated endpoint", "auth_compare_responses")
            if any(p in params for p in ("url", "uri", "next", "redirect", "return", "callback")):
                add("redirect_ssrf", obs.url, "URL-like parameter discovered", "open_redirect_scan or ssrf_scanner")
            if any(p in params for p in ("file", "path", "page", "template", "include", "download")):
                add("path_traversal", obs.url, "file/path parameter discovered", "path_traversal_scanner")
            if any(p in params for p in ("q", "query", "search", "keyword", "id")):
                add("injection", obs.url, "search/id parameter discovered", "sqli_scanner and xss_scanner")
            if hint == "graphql":
                add("graphql", obs.url, "GraphQL endpoint discovered", "graphql_introspection")
            if "/api/" in obs.path.lower():
                add("api_authz", obs.url, "API endpoint should be tested across roles", "rest_api_fuzzing")

        return suggestions[:40]


_http_kb: Optional[HttpKnowledgeBase] = None


def get_http_knowledge() -> HttpKnowledgeBase:
    global _http_kb
    if _http_kb is None:
        _http_kb = HttpKnowledgeBase()
    return _http_kb
