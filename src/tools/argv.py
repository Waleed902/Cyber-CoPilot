"""Helpers for turning wrapper option strings into safe argv lists."""

from __future__ import annotations

import shlex
from typing import Iterable


_SHELL_CONTROL_WORDS = {
    "|",
    "||",
    "&",
    "&&",
    ";",
    ">",
    ">>",
    "<",
    "<<",
    "2>",
    "2>>",
    "2>&1",
}


def safe_split_options(options: str | None, field_name: str = "options") -> tuple[list[str], str | None]:
    """
    Split an option string with shell-like quoting, while rejecting shell syntax.

    Tool wrappers call subprocess with shell=False. Passing shell fragments such
    as ``| tee out.txt`` does not pipe output; it becomes broken tool argv. This
    helper fails early with a clear message instead.
    """
    if not options or not options.strip():
        return [], None

    raw = options.strip()
    if "`" in raw or "$(" in raw:
        return [], f"Error: {field_name} contains shell expansion syntax; pass only tool flags."

    try:
        parts = shlex.split(raw, posix=True)
    except ValueError as exc:
        return [], f"Error: could not parse {field_name}: {exc}"

    blocked = [
        part
        for part in parts
        if part in _SHELL_CONTROL_WORDS
        or part.startswith(("|", ";", "<", ">"))
        or part.endswith(("|", ";"))
        or "&&" in part
        or "||" in part
        or "2>" in part
    ]
    if blocked:
        return [], (
            f"Error: {field_name} contains shell control token(s): {' '.join(blocked)}. "
            "Use wrapper parameters or session artifact logging instead of pipes/redirection."
        )

    return parts, None


def drop_managed_options(parts: Iterable[str], managed_flags: set[str]) -> tuple[list[str], list[str]]:
    """Drop flags whose values are already controlled by the wrapper."""
    accepted: list[str] = []
    dropped: list[str] = []
    skip_next = False

    for idx, part in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        if part in managed_flags:
            dropped.append(part)
            skip_next = True
            continue
        if any(part.startswith(flag + "=") for flag in managed_flags):
            dropped.append(part)
            continue
        accepted.append(part)

    return accepted, dropped
