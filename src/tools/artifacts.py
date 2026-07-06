"""Generic, scoped artifact exploration tools."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Iterable

from src.sdk.tool import function_tool


MAX_READ_CHARS = 80_000
MAX_GREP_MATCHES = 200
MAX_GLOB_RESULTS = 500


def _workspace_root() -> Path:
    return Path.cwd().resolve()


def _target_root() -> Path:
    try:
        from src.repl.target_manager import get_target_manager

        manager = get_target_manager()
        if getattr(manager, "current_target", None):
            safe = str(manager.current_target).replace("://", "_").replace("/", "_").replace(":", "_")
            return (Path.cwd() / "targets" / safe).resolve()
    except Exception:
        pass
    return (Path.cwd() / "targets").resolve()


def _session_root() -> Path:
    try:
        from src.repl.target_manager import get_target_manager

        manager = get_target_manager()
        if getattr(manager, "session_dir", None):
            return Path(manager.session_dir).resolve()
    except Exception:
        pass
    return _target_root()


def _root_for(scope: str) -> Path:
    selected = (scope or "session").strip().lower()
    if selected == "workspace":
        return _workspace_root()
    if selected == "target":
        return _target_root()
    return _session_root()


def _resolve(path: str = "", scope: str = "session") -> tuple[Path, Path, str | None]:
    root = _root_for(scope)
    candidate = root if not path else (root / path)
    try:
        resolved = candidate.resolve()
    except FileNotFoundError:
        resolved = candidate.parent.resolve() / candidate.name
    try:
        resolved.relative_to(root)
    except ValueError:
        return root, resolved, f"Path escapes {scope or 'session'} scope: {path}"
    return root, resolved, None


def _iter_files(root: Path, pattern: str, include_hidden: bool) -> Iterable[Path]:
    clean_pattern = pattern or "**/*"
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if not include_hidden and any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        if fnmatch.fnmatch(rel, clean_pattern) or fnmatch.fnmatch(path.name, clean_pattern):
            yield path


@function_tool(name_override="artifact_glob")
def artifact_glob(pattern: str = "**/*", scope: str = "session", include_hidden: bool = False, limit: int = 200) -> str:
    """
    List files in the current session, target, or workspace using a glob pattern.

    Args:
        pattern: Glob pattern such as **/*.js, tools/*.txt, or profile.json.
        scope: One of session, target, or workspace. Defaults to session.
        include_hidden: Include hidden dotfiles and hidden directories.
        limit: Maximum results to return.
    """
    root = _root_for(scope)
    if not root.exists():
        return f"Artifact root does not exist: {root}"
    capped = max(1, min(int(limit or 200), MAX_GLOB_RESULTS))
    rows = []
    for path in _iter_files(root, pattern, include_hidden):
        rows.append(path.relative_to(root).as_posix())
        if len(rows) >= capped:
            break
    if not rows:
        return f"No files matched {pattern!r} under {root}"
    suffix = "\n...[artifact-glob-truncated]" if len(rows) >= capped else ""
    return f"Artifact root: {root}\n" + "\n".join(rows) + suffix


@function_tool(name_override="artifact_read")
def artifact_read(path: str, scope: str = "session", max_chars: int = 40000) -> str:
    """
    Read a text artifact from the current session, target, or workspace.

    Args:
        path: Relative path inside the selected scope.
        scope: One of session, target, or workspace. Defaults to session.
        max_chars: Maximum characters to return.
    """
    root, resolved, error = _resolve(path, scope)
    if error:
        return error
    if not resolved.exists() or not resolved.is_file():
        return f"Artifact not found: {resolved}"
    try:
        content = resolved.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"Failed to read artifact: {exc}"
    capped = max(1, min(int(max_chars or 40000), MAX_READ_CHARS))
    rel = resolved.relative_to(root).as_posix()
    if len(content) > capped:
        return f"[{scope}:{rel}]\n{content[:capped]}\n...[artifact-read-truncated {len(content) - capped} chars]"
    return f"[{scope}:{rel}]\n{content}"


@function_tool(name_override="artifact_write")
def artifact_write(path: str, content: str, scope: str = "session", overwrite: bool = False) -> str:
    """
    Write a text artifact inside the current session, target, or workspace.

    Args:
        path: Relative path inside the selected scope.
        content: Text content to write.
        scope: One of session, target, or workspace. Defaults to session.
        overwrite: Allow replacing an existing file.
    """
    root, resolved, error = _resolve(path, scope)
    if error:
        return error
    if resolved.exists() and not overwrite:
        return f"Refusing to overwrite existing artifact without overwrite=true: {resolved}"
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content or "", encoding="utf-8")
    except Exception as exc:
        return f"Failed to write artifact: {exc}"
    return f"Wrote artifact: {resolved.relative_to(root).as_posix()} ({len(content or '')} chars) under {root}"


@function_tool(name_override="artifact_grep")
def artifact_grep(pattern: str, path_glob: str = "**/*", scope: str = "session", regex: bool = True, case_sensitive: bool = False, limit: int = 100) -> str:
    """
    Search text artifacts in the current session, target, or workspace.

    Args:
        pattern: Regex or literal text to search for.
        path_glob: File glob to search within.
        scope: One of session, target, or workspace. Defaults to session.
        regex: Treat pattern as a regular expression when true.
        case_sensitive: Use case-sensitive matching.
        limit: Maximum matching lines to return.
    """
    if not pattern:
        return "Search pattern is required."
    root = _root_for(scope)
    if not root.exists():
        return f"Artifact root does not exist: {root}"
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        compiled = re.compile(pattern if regex else re.escape(pattern), flags)
    except re.error as exc:
        return f"Invalid regex: {exc}"
    capped = max(1, min(int(limit or 100), MAX_GREP_MATCHES))
    matches = []
    for file_path in _iter_files(root, path_glob, include_hidden=False):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = file_path.relative_to(root).as_posix()
        for line_no, line in enumerate(text.splitlines(), 1):
            if compiled.search(line):
                matches.append(f"{rel}:{line_no}: {line[:500]}")
                if len(matches) >= capped:
                    break
        if len(matches) >= capped:
            break
    if not matches:
        return f"No matches for {pattern!r} in {path_glob!r} under {root}"
    suffix = "\n...[artifact-grep-truncated]" if len(matches) >= capped else ""
    return f"Artifact root: {root}\n" + "\n".join(matches) + suffix
