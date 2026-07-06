"""Persistence helpers for replayable uploaded shell artifacts."""

from __future__ import annotations

import json
from typing import Any

from src.sdk.tool import function_tool


def _current_target() -> str:
    try:
        from src.sdk.context_hub import get_context_hub

        target = (get_context_hub().current_target or "").strip()
        if target:
            return target
    except Exception:
        pass
    try:
        from src.agents.orchestrator_agent import get_current_target

        return (get_current_target() or "").strip()
    except Exception:
        return ""


def _payload(entry: dict[str, Any]) -> dict[str, str]:
    return {k: str(v or "") for k, v in entry.items()}


@function_tool()
def record_uploaded_shell(
    filename: str = "",
    url: str = "",
    payload_path: str = "",
    payload_body: str = "",
    upload_url: str = "",
    upload_field: str = "",
    cookies_ref: str = "",
    verification_command: str = "",
    source_tool: str = "",
    notes: str = "",
    target: str = "",
) -> str:
    """
    Record an uploaded shell or replayable payload artifact in the active target profile.

    Use this after a shell upload succeeds, after finding an existing shell URL in
    prior notes, or before handing a reupload task to another agent.
    """
    selected_target = (target or _current_target()).strip()
    if not selected_target:
        return "Failed: no active target is set."

    entry = _payload(
        {
            "filename": filename,
            "url": url,
            "payload_path": payload_path,
            "payload_body": payload_body,
            "upload_url": upload_url,
            "upload_field": upload_field,
            "cookies_ref": cookies_ref,
            "verification_command": verification_command,
            "source_tool": source_tool,
            "notes": notes,
        }
    )
    if not any(entry.get(k) for k in ("filename", "url", "payload_path", "payload_body")):
        return "Failed: provide at least filename, url, payload_path, or payload_body."

    from src.repl.profiles import get_profile_manager

    pm = get_profile_manager()
    pm.add_uploaded_shell(selected_target, entry)
    label = filename or url or payload_path or "uploaded shell"
    return f"Recorded uploaded shell artifact for {selected_target}: {label}"


@function_tool()
def list_uploaded_shells(query: str = "", target: str = "") -> str:
    """
    List uploaded shell/payload artifacts stored in the active target profile.

    Args:
        query: Optional filename/URL/source substring filter.
        target: Optional target override; defaults to active target.
    """
    selected_target = (target or _current_target()).strip()
    if not selected_target:
        return "Failed: no active target is set."

    from src.repl.profiles import get_profile_manager

    profile = get_profile_manager().load_profile(selected_target)
    shells = list(getattr(profile, "uploaded_shells", []) or [])
    needle = query.strip().lower()
    if needle:
        shells = [
            s
            for s in shells
            if needle in json.dumps(s, sort_keys=True).lower()
        ]

    if not shells:
        return f"No uploaded shell artifacts recorded for {selected_target}."

    lines = [f"Uploaded shell artifacts for {selected_target}:"]
    for idx, shell in enumerate(shells, 1):
        label = shell.get("filename") or shell.get("url") or shell.get("payload_path") or "(unnamed)"
        lines.append(f"{idx}. {label}")
        for key in ("url", "payload_path", "upload_url", "upload_field", "verification_command", "source_tool", "notes"):
            value = shell.get(key)
            if value:
                lines.append(f"   {key}: {value}")
    return "\n".join(lines)
