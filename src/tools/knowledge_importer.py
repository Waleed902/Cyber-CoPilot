"""
Import bug bounty reports and offensive security writeups into the local
adversarial knowledge dataset used by KnowledgeAugmentor.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Iterable

from src.sdk.tool import function_tool


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "bugbounty_dataset.json"

SUPPORTED_EXTENSIONS = {
    ".md", ".markdown", ".txt", ".log", ".rst",
    ".html", ".htm", ".json", ".yaml", ".yml", ".csv", ".xml",
    ".rtf", ".docx", ".odt", ".pdf",
}

EXCLUDED_DIRS = {
    ".git", ".github", "__pycache__", ".pytest_cache", ".mypy_cache",
    "node_modules", "vendor", "venv", ".venv", "env", ".env",
    "dist", "build", "target", ".idea", ".vscode",
}

VULN_KEYWORDS = {
    "idor": ("idor", "bola", "broken object", "object level", "authorization bypass", "access control"),
    "sqli": ("sqli", "sql injection", "union select", "blind sql", "time based sql"),
    "xss": ("xss", "cross-site scripting", "cross site scripting", "dom xss", "stored xss", "reflected xss"),
    "ssrf": ("ssrf", "server-side request forgery", "server side request forgery", "metadata", "169.254.169.254"),
    "csrf": ("csrf", "cross-site request forgery", "cross site request forgery"),
    "cors": ("cors", "access-control-allow-origin", "acao"),
    "open_redirect": ("open redirect", "redirect_uri", "unvalidated redirect"),
    "file_upload": ("file upload", "upload bypass", "webshell", "mime type", "content-type bypass"),
    "path_traversal": ("path traversal", "lfi", "local file inclusion", "../", "..%2f"),
    "command_injection": ("command injection", "rce", "remote code execution", "os command", "shell injection"),
    "xxe": ("xxe", "external entity", "doctype", "xml external"),
    "nosql": ("nosql", "mongodb", "$ne", "$regex"),
    "ldap": ("ldap injection", "ldap"),
    "ssti": ("ssti", "server-side template", "template injection", "{{7*7}}"),
    "jwt": ("jwt", "jku", "kid", "algorithm confusion", "json web token"),
    "oauth": ("oauth", "oidc", "pkce", "state parameter", "redirect_uri"),
    "graphql": ("graphql", "introspection", "batch query", "alias abuse"),
    "race_condition": ("race condition", "race", "single packet", "turbo intruder"),
    "cache_poisoning": ("cache poisoning", "web cache", "cache deception"),
    "http_smuggling": ("request smuggling", "cl.te", "te.cl", "http desync"),
    "prototype_pollution": ("prototype pollution", "__proto__", "constructor.prototype"),
    "deserialization": ("deserialization", "insecure deserialize", "pickle", "ysoserial", "phpggc"),
    "subdomain_takeover": ("subdomain takeover", "dangling cname", "takeover"),
    "business_logic": ("business logic", "price manipulation", "coupon", "workflow bypass"),
    "auth_logic": ("password reset", "account takeover", "mfa bypass", "2fa bypass", "session fixation"),
    "header_injection": ("header injection", "crlf", "response splitting", "host header"),
}


def _resolve_dataset_path(dataset_path: str = "") -> Path:
    if not dataset_path:
        return DEFAULT_DATASET_PATH
    path = Path(dataset_path).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def _load_dataset(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if isinstance(data, list):
        return [entry for entry in data if isinstance(entry, dict)]
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [entry for entry in data["items"] if isinstance(entry, dict)]
    return []


def _save_dataset(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")


def _hash_text(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _clean_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"```[a-zA-Z0-9_-]*\n", "```\n", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _read_document(path: Path) -> str:
    try:
        from src.tools.forensics import _read_document_content

        text, _fmt = _read_document_content(str(path))
        return _clean_text(text)
    except Exception:
        return _clean_text(path.read_text(encoding="utf-8", errors="replace"))


def _iter_supported_files(root: Path, max_files: int) -> Iterable[Path]:
    count = 0
    for path in sorted(root.rglob("*")):
        if count >= max_files:
            return
        if not path.is_file():
            continue
        parts = set(path.relative_to(root).parts)
        if parts & EXCLUDED_DIRS:
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        count += 1
        yield path


def _split_sections(text: str, max_chars: int) -> list[tuple[str, str]]:
    text = _clean_text(text)
    if not text:
        return []

    matches = list(re.finditer(r"(?m)^(#{1,3})\s+(.+?)\s*$", text))
    sections: list[tuple[str, str]] = []
    if matches:
        for idx, match in enumerate(matches):
            start = match.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
            title = match.group(2).strip()
            body = text[start:end].strip()
            sections.extend(_chunk_body(title, body, max_chars))
    else:
        sections.extend(_chunk_body("Document notes", text, max_chars))
    return sections


def _chunk_body(title: str, body: str, max_chars: int) -> list[tuple[str, str]]:
    body = body.strip()
    if not body:
        return []
    if len(body) <= max_chars:
        return [(title, body)]

    chunks: list[tuple[str, str]] = []
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
    current: list[str] = []
    current_len = 0
    part = 1
    for paragraph in paragraphs:
        if current and current_len + len(paragraph) + 2 > max_chars:
            chunks.append((f"{title} (part {part})", "\n\n".join(current)))
            current = []
            current_len = 0
            part += 1
        if len(paragraph) > max_chars:
            for i in range(0, len(paragraph), max_chars):
                chunks.append((f"{title} (part {part})", paragraph[i:i + max_chars]))
                part += 1
            continue
        current.append(paragraph)
        current_len += len(paragraph) + 2
    if current:
        chunks.append((f"{title} (part {part})" if part > 1 else title, "\n\n".join(current)))
    return chunks


def _guess_vuln_type(text: str, fallback: str = "methodology") -> str:
    haystack = text.lower()
    scores: dict[str, int] = {}
    for vuln_type, keywords in VULN_KEYWORDS.items():
        score = sum(1 for keyword in keywords if keyword in haystack)
        if score:
            scores[vuln_type] = score
    if not scores:
        return fallback
    return max(scores.items(), key=lambda item: item[1])[0]


def _tags_for(text: str, vuln_type: str) -> list[str]:
    tags = {vuln_type}
    lower = text.lower()
    for token in ("api", "mobile", "web", "auth", "cloud", "aws", "azure", "gcp", "wordpress", "graphql"):
        if token in lower:
            tags.add(token)
    return sorted(tags)


def _github_source_parts(source: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(source)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    clone_url = f"https://github.com/{owner}/{repo}.git"
    subpath = ""
    if len(parts) >= 5 and parts[2] in {"tree", "blob"}:
        subpath = "/".join(parts[4:])
    return clone_url, subpath


def _download_single_file(source: str, dest: Path) -> Path:
    parsed = urllib.parse.urlparse(source)
    filename = Path(parsed.path).name or "downloaded_writeup.txt"
    output = dest / filename
    urllib.request.urlretrieve(source, output)
    return output


def _materialize_source(source: str, temp_dir: Path) -> tuple[Path, str]:
    local = Path(source).expanduser()
    if local.exists():
        return local, f"local:{local}"

    github = _github_source_parts(source)
    if github:
        clone_url, subpath = github
        repo_dir = temp_dir / "repo"
        if not shutil.which("git"):
            raise RuntimeError("git is required to import GitHub repositories")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, str(repo_dir)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "git clone failed").strip()[:500])
        root = repo_dir / subpath if subpath else repo_dir
        if not root.exists():
            raise RuntimeError(f"GitHub subpath not found after clone: {subpath}")
        return root, source

    if source.startswith(("http://", "https://")):
        downloaded = _download_single_file(source, temp_dir)
        return downloaded, source

    raise RuntimeError(f"Source path or URL not found: {source}")


def _entry_for_chunk(source_label: str, rel_path: str, title: str, body: str) -> dict:
    source_ref = f"{source_label}::{rel_path}::{title}"
    vuln_type = _guess_vuln_type(f"{rel_path}\n{title}\n{body}")
    content_hash = _hash_text(f"{source_ref}\n{body}")
    return {
        "instruction": f"Apply bug bounty methodology from {rel_path}: {title}",
        "output": body,
        "vuln_type": vuln_type,
        "source": source_label,
        "source_path": rel_path,
        "section": title,
        "tags": _tags_for(f"{rel_path}\n{title}\n{body}", vuln_type),
        "content_hash": content_hash,
    }


@function_tool()
def import_bugbounty_knowledge(
    source: str,
    dataset_path: str = "data/bugbounty_dataset.json",
    max_files: int = 200,
    max_chars_per_entry: int = 3500,
    min_chars_per_entry: int = 180,
    reindex: bool = True,
) -> str:
    """
    Import local or GitHub bug bounty writeups into data/bugbounty_dataset.json.

    Args:
        source: Local file/folder path, public GitHub repo/tree URL, or direct document URL.
        dataset_path: JSON dataset path to append to.
        max_files: Maximum supported files to process.
        max_chars_per_entry: Maximum characters per knowledge entry.
        min_chars_per_entry: Skip tiny sections shorter than this many characters.
        reindex: Re-index KnowledgeAugmentor after writing the dataset.

    Returns:
        Import summary with counts and dataset path.
    """
    dataset_file = _resolve_dataset_path(dataset_path)
    existing = _load_dataset(dataset_file)
    seen_hashes = {
        entry.get("content_hash") or _hash_text(f"{entry.get('instruction', '')}\n{entry.get('output', '')}")
        for entry in existing
        if isinstance(entry, dict)
    }

    added: list[dict] = []
    skipped_small = 0
    skipped_duplicate = 0
    processed_files = 0
    errors: list[str] = []

    max_files = max(1, min(int(max_files or 200), 2000))
    max_chars_per_entry = max(800, min(int(max_chars_per_entry or 3500), 12000))
    min_chars_per_entry = max(0, min(int(min_chars_per_entry or 180), max_chars_per_entry))

    with tempfile.TemporaryDirectory(prefix="bb_knowledge_") as tmp:
        temp_dir = Path(tmp)
        try:
            root, source_label = _materialize_source(source, temp_dir)
        except Exception as exc:
            return f"Import failed: {exc}"

        files = [root] if root.is_file() else list(_iter_supported_files(root, max_files))
        for path in files[:max_files]:
            try:
                text = _read_document(path)
                if not text:
                    continue
                rel_path = path.name if root.is_file() else str(path.relative_to(root)).replace("\\", "/")
                processed_files += 1
                for title, body in _split_sections(text, max_chars_per_entry):
                    body = _clean_text(body)
                    if len(body) < min_chars_per_entry:
                        skipped_small += 1
                        continue
                    entry = _entry_for_chunk(source_label, rel_path, title, body)
                    if entry["content_hash"] in seen_hashes:
                        skipped_duplicate += 1
                        continue
                    seen_hashes.add(entry["content_hash"])
                    added.append(entry)
            except Exception as exc:
                errors.append(f"{path}: {str(exc)[:160]}")

    combined = existing + added
    _save_dataset(dataset_file, combined)

    index_note = "Reindex skipped."
    if reindex:
        try:
            from src.sdk.knowledge_augmentor import get_augmentor

            augmentor = get_augmentor()
            augmentor.dataset_path = dataset_file
            augmentor.index_dataset()
            index_note = "KnowledgeAugmentor reindex requested."
        except Exception as exc:
            index_note = f"Dataset saved; reindex failed/unavailable: {str(exc)[:180]}"

    counts = Counter(entry.get("vuln_type", "unknown") for entry in added)
    lines = [
        "## Bug Bounty Knowledge Import",
        f"Source: {source}",
        f"Dataset: {dataset_file}",
        f"Files processed: {processed_files}",
        f"Added entries: {len(added)}",
        f"Skipped duplicates: {skipped_duplicate}",
        f"Skipped tiny sections: {skipped_small}",
        f"Total dataset entries: {len(combined)}",
        index_note,
    ]
    if counts:
        lines.append("New entries by vuln_type:")
        for vuln_type, count in counts.most_common():
            lines.append(f"- {vuln_type}: {count}")
    if errors:
        lines.append("Errors:")
        for error in errors[:10]:
            lines.append(f"- {error}")
    return "\n".join(lines)


@function_tool()
def bugbounty_knowledge_stats(dataset_path: str = "data/bugbounty_dataset.json") -> str:
    """
    Show counts and coverage for the bug bounty knowledge dataset.

    Args:
        dataset_path: JSON dataset path to inspect.

    Returns:
        Markdown summary of dataset entries by vulnerability type and source.
    """
    dataset_file = _resolve_dataset_path(dataset_path)
    entries = _load_dataset(dataset_file)
    if not entries:
        return f"No bug bounty knowledge entries found at {dataset_file}"

    by_type = Counter(entry.get("vuln_type", "unknown") for entry in entries)
    by_source = Counter(entry.get("source", "(unknown)") for entry in entries)
    with_hash = sum(1 for entry in entries if entry.get("content_hash"))

    lines = [
        "## Bug Bounty Knowledge Dataset",
        f"Dataset: {dataset_file}",
        f"Total entries: {len(entries)}",
        f"Entries with content_hash: {with_hash}",
        "",
        "### By Vulnerability Type",
    ]
    for vuln_type, count in by_type.most_common():
        lines.append(f"- {vuln_type}: {count}")

    lines.append("")
    lines.append("### Top Sources")
    for source, count in by_source.most_common(10):
        lines.append(f"- {source}: {count}")

    return "\n".join(lines)


@function_tool()
def query_bugbounty_knowledge(
    query: str,
    dataset_path: str = "data/bugbounty_dataset.json",
    n_results: int = 5,
    prefer_chroma: bool = True,
) -> str:
    """
    Query imported bug bounty methodology patterns.

    Args:
        query: Technique, vulnerability class, technology, or testing scenario.
        dataset_path: JSON dataset path to query.
        n_results: Number of matching knowledge entries to return.
        prefer_chroma: Use KnowledgeAugmentor/Chroma when available; fallback to keyword search.

    Returns:
        Relevant methodology snippets from the local bug bounty knowledge dataset.
    """
    dataset_file = _resolve_dataset_path(dataset_path)
    n_results = max(1, min(int(n_results or 5), 15))

    if prefer_chroma:
        try:
            from src.sdk.knowledge_augmentor import get_augmentor

            augmentor = get_augmentor()
            augmentor.dataset_path = dataset_file
            augmentor.index_dataset()
            result = augmentor.get_relevant_patterns(query, n_results=n_results)
            if result:
                return result
        except Exception:
            pass

    entries = _load_dataset(dataset_file)
    if not entries:
        return f"No bug bounty knowledge entries found at {dataset_file}"

    tokens = [
        token
        for token in re.findall(r"[a-z0-9_.$-]{3,}", query.lower())
        if token not in {"the", "and", "for", "with", "from", "into", "this", "that"}
    ]
    scored: list[tuple[int, dict]] = []
    for entry in entries:
        haystack = " ".join(
            [
                str(entry.get("instruction", "")),
                str(entry.get("output", "")),
                str(entry.get("vuln_type", "")),
                " ".join(entry.get("tags", []) if isinstance(entry.get("tags"), list) else []),
            ]
        ).lower()
        score = sum(haystack.count(token) for token in tokens)
        if score:
            scored.append((score, entry))

    if not scored:
        return f"No bug bounty knowledge matches found for: {query}"

    lines = [f"## Bug Bounty Knowledge Matches: {query}"]
    for score, entry in sorted(scored, key=lambda item: item[0], reverse=True)[:n_results]:
        output = str(entry.get("output", "")).strip()
        if len(output) > 1200:
            output = output[:1200] + "\n... [truncated]"
        lines.extend(
            [
                "",
                f"### {entry.get('instruction', '(untitled)')}",
                f"- Type: {entry.get('vuln_type', 'unknown')}",
                f"- Source: {entry.get('source_path') or entry.get('source', '(unknown)')}",
                f"- Match score: {score}",
                "",
                output,
            ]
        )
    return "\n".join(lines)
