"""
Forensics tools - tshark, binwalk, strings, etc.
"""

import subprocess
import os
import re
import difflib
import shutil
import json
import csv
import html
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from collections import deque
from src.sdk.tool import function_tool

# CTF runtime guardrails and evidence ledger (process-local memory)
# Each entry: (normalized_command, had_error) so error-correction retries are allowed.
_CTF_COMMAND_HISTORY: deque = deque(maxlen=20)
_CTF_LOW_YIELD_COUNT = 0
_CTF_EVIDENCE_LEDGER = []
_CTF_TECHNIQUES_TRIED = set()


def _normalize_command(cmd: str) -> str:
    """Normalize command text for similarity checks."""
    if not isinstance(cmd, str):
        return ""
    collapsed = " ".join(cmd.strip().lower().split())
    # Replace long hex literals and long digit groups to reduce minor-variant loops
    collapsed = re.sub(r"0x[0-9a-f]+", "0xHEX", collapsed)
    collapsed = re.sub(r"\b\d{3,}\b", "N", collapsed)
    return collapsed


def _extract_artifacts(text: str) -> list[str]:
    """Extract concrete artifacts from command output to measure progress."""
    if not text:
        return []

    artifacts = set()

    # Addresses/offsets and known identifiers (6+ hex digit addresses)
    for addr in re.findall(r"0x[0-9a-fA-F]{6,}", text):
        artifacts.add(addr.lower())
    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE):
        artifacts.add(cve.upper())
    for fn in re.findall(r"\b(?:fcn\.|sub_|sym\.|main|validate|check|init|exit|probe)\w*", text):
        artifacts.add(fn)
    for sig in re.findall(r"\b(?:ELF\d+|ARM|AArch64|x86-64|MIPS|RISC-V|Thumb|NX|PIE|Canary|RELRO)\b", text):
        artifacts.add(sig)

    # Constraints and branch/comparison clues
    for op in re.findall(r"\b(?:cmp|test|je|jne|jg|jl|beq|bne|bl|ret|call)\b", text):
        artifacts.add(op)

    # GDB byte-dump sequences: x/Nbx output like "0x07 0x65 0xa9 0xf2"
    # Count any run of 3+ short hex values as a productive byte extraction artifact
    byte_seqs = re.findall(r"(?:0x[0-9a-fA-F]{1,2}\s*){3,}", text)
    for seq in byte_seqs:
        # Represent the whole sequence as a single normalised artifact token
        normed = "byte_dump:" + re.sub(r"\s+", ":", seq.strip())
        artifacts.add(normed)

    # GDB printf output (e.g. from 'printf "key: "') — any printable run ≥6 chars
    for txt in re.findall(r"(?:[A-Za-z0-9+/=_\-]{6,})", text):
        if any(c.isalpha() for c in txt):   # must have at least one letter
            artifacts.add(f"str:{txt[:30]}")

    # Base64-ish strings that are likely extracted targets
    for b64 in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text):
        artifacts.add(f"b64:{b64[:20]}")

    return sorted(list(artifacts))[:30]


# Known CTF flag patterns — ordered from most specific to most generic
_FLAG_PATTERNS = [
    re.compile(r"flag\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"HTB\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"THM\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"picoCTF\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"ARENA\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}\r\n]{1,200}\}", re.IGNORECASE),
    re.compile(r"[A-Z]{2,8}\{[A-Za-z0-9_\-!@#$%^&*()+=]{4,120}\}", re.IGNORECASE),
]


def _detect_ctf_flag(text: str) -> list[str]:
    """Return a list of likely flag strings found in tool output."""
    found: list[str] = []
    seen: set[str] = set()
    for pat in _FLAG_PATTERNS:
        for m in pat.finditer(text):
            flag = m.group(0)
            key = flag.lower()
            if key not in seen:
                seen.add(key)
                found.append(flag)
    return found


def _is_duplicate_command(normalized: str, threshold: float = 0.93) -> bool:
    """Return True if command is too similar to a recent successful command.

    Commands that previously errored are excluded so the agent can correct flags
    or arguments without being blocked.
    """
    for entry in _CTF_COMMAND_HISTORY:
        # Support both old plain-string entries and new (cmd, had_error) tuples.
        if isinstance(entry, tuple):
            prev, had_error = entry
            if had_error:
                continue  # allow corrections after an error
        else:
            prev = entry
        if normalized == prev:
            return True
        score = difflib.SequenceMatcher(a=normalized, b=prev).ratio()
        if score >= threshold:
            return True
    return False


def _requires_pivot(low_yield_count: int, command: str) -> str | None:
    """Enforce pivot gates after repeated low-yield actions."""
    cmd = command.lower()

    if low_yield_count >= 24:
        # Algorithm reconstruction gate
        allowed = ["ghidra", "objdump", "readelf", "nm", "r2", "radare2", "python3 -c", "gdb"]
        if not any(k in cmd for k in allowed):
            return (
                "[PIVOT BLOCK] 24 low-yield actions reached. "
                "Force algorithm reconstruction now: decompile specific validator functions, "
                "extract constants/branch conditions, and reconstruct checker logic before more probing."
            )

    if low_yield_count >= 16:
        # Dynamic trace gate
        allowed = ["gdb", "qemu-", "strace", "ltrace", "rr"]
        if not any(k in cmd for k in allowed):
            return (
                "[PIVOT BLOCK] 16 low-yield actions reached. "
                "Force dynamic trace now (gdb/qemu -g/strace) and capture PC, stack trace, and branch behavior."
            )

    if low_yield_count >= 8:
        # Function-targeted RE gate
        allowed = ["ghidra", "objdump", "readelf", "nm", "r2", "radare2", "godot_"]
        if not any(k in cmd for k in allowed):
            return (
                "[PIVOT BLOCK] 8 low-yield actions reached. "
                "Force function-targeted reverse engineering now (map input-read, validator, compare site, success path). "
                "HINT: If this is a Godot game, use the framework tool 'godot_pck_extract' now."
            )

    return None


def _command_quality_error(command: str) -> str | None:
    """Catch common shell patterns that create false findings or guaranteed errors."""
    cmd = command or ""
    lower = cmd.lower()

    if re.search(r"\bldapsearch\b[^\n;|]*\s-h\s+", cmd):
        return (
            "[COMMAND BLOCKED] `ldapsearch -h` is invalid on this Kali/OpenLDAP build.\n"
            "Use `ldapsearch -x -H ldap://<dc-ip> -b \"DC=domain,DC=tld\" \"<filter>\" <attrs>` instead."
        )

    if re.search(r"\bcrackmapexec\b", cmd):
        return (
            "[COMMAND BLOCKED] `crackmapexec` is not available in this environment.\n"
            "Use NetExec instead, e.g. `nxc smb <target> -u <user> -p <pass> --shares` "
            "or `nxc ldap <target> -u <user> -p <pass> --users`."
        )

    if re.search(r"\|\s*timeout\s+\d+\b", cmd):
        return (
            "[COMMAND BLOCKED] `cmd | timeout 5` is the wrong order and only times out stdin.\n"
            "Use `timeout 5 <command>` or put `timeout` before the command you want to limit."
        )

    if (
        "5985" in lower
        and "/wsman" in lower
        and "curl" in lower
        and re.search(r"\s-u\s+|\s--user\s+", lower)
    ):
        return (
            "[COMMAND BLOCKED] Do not validate WinRM credentials with curl HTTP status codes. "
            "WinRM often returns HTTP 405/401 behavior that is not proof of valid credentials.\n"
            "Use `nxc winrm <target> -u <user> -p <pass>` or `evil-winrm` for a real auth check."
        )

    if (
        re.search(r"\b(?:impacket-)?GetNPUsers(?:\.py)?\b", cmd)
        and "-no-pass" in lower
        and "-usersfile" not in lower
        and not re.search(r"\b(?:impacket-)?GetNPUsers(?:\.py)?\b\s+\S+/[^\s]+", cmd)
    ):
        return (
            "[COMMAND BLOCKED] GetNPUsers with `-no-pass` needs a username or `-usersfile`.\n"
            "Example: `printf \"administrator\\n\" > valid_users.txt && "
            "GetNPUsers.py checkpoint.htb/ -dc-ip <dc-ip> -usersfile valid_users.txt -no-pass`."
        )

    return None

def _convert_to_linux_path(path: str) -> str:
    """Helper to convert Windows-style paths to Linux-style for WSL."""
    if not path or not isinstance(path, str):
        return path
        
    # Case 1: Windows-style with drive letter
    if ":" in path and "\\" in path:
        # e.g., C:\Users\Waleed\... -> /mnt/c/Users/Waleed/...
        drive, rest = path.split(":", 1)
        path = f"/mnt/{drive.lower()}{rest.replace('\\', '/')}"
        
    # Case 2: Windows-style without drive letter (e.g. \Users\...)
    elif path.startswith("\\"):
        path = path.replace("\\", "/")
        
    # Case 3: Ensure no double slashes from accidental joining
    while "//" in path and not path.startswith("//"): # Preserve // for network paths if needed
        path = path.replace("//", "/")
        
    return path


# ═══════════════════════════════════════════════════════════════════════════
# SMART OUTPUT: Save large outputs to file, return intelligent summary
# ═══════════════════════════════════════════════════════════════════════════

# Configurable threshold: outputs larger than this get saved to file
_LARGE_OUTPUT_THRESHOLD = 8000  # characters (~2000 tokens)

# Patterns to auto-grep in saved outputs (CTF + forensics relevant)
_INTERESTING_PATTERNS = [
    r'(?i)flag\{[^}]*\}',           # flag{...}
    r'(?i)ctf\{[^}]*\}',            # ctf{...}
    r'(?i)HTB\{[^}]*\}',            # HTB{...}
    r'(?i)picoCTF\{[^}]*\}',        # picoCTF{...}
    r'(?i)password\s*[:=]\s*\S+',   # password: xxx
    r'(?i)secret\s*[:=]\s*\S+',     # secret: xxx
    r'(?i)key\s*[:=]\s*\S+',        # key: xxx
    r'(?i)token\s*[:=]\s*\S+',      # token: xxx
    r'(?i)admin',                    # admin references
    r'(?i)strcmp|strncmp|memcmp',    # comparison functions (RE)
    r'(?i)gets\(|scanf\(|read\(',   # vulnerable functions (PWN)
    r'(?i)system\(|exec\(|popen\(', # code execution
    r'(?i)\/bin\/sh|\/bin\/bash',   # shell references
    r'base64',                       # encoding hints
    r'0x[0-9a-fA-F]{8,}',          # long hex constants
]

from src.sdk.utils import smart_output, _LARGE_OUTPUT_THRESHOLD


def _chunk_text(content: str, chunk_size: int, chunk_index: int) -> tuple[str, int, int, int]:
    """Return the requested text chunk and chunk metadata."""
    if chunk_size <= 0:
        chunk_size = 12000
    if chunk_index <= 0:
        chunk_index = 1

    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    chunk_index = min(chunk_index, total_chunks)
    start = (chunk_index - 1) * chunk_size
    end = start + chunk_size
    return content[start:end], chunk_index, total_chunks, len(content)


def _extract_docx_text(file_path: str) -> str:
    """Extract text from a DOCX file using the zipped XML structure."""
    paragraphs: list[str] = []
    with zipfile.ZipFile(file_path) as zf:
        xml_data = zf.read("word/document.xml")
    root = ET.fromstring(xml_data)
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    for para in root.findall(".//w:p", ns):
        parts = []
        for node in para.findall(".//w:t", ns):
            if node.text:
                parts.append(node.text)
        if parts:
            paragraphs.append("".join(parts))
    return "\n".join(paragraphs)


def _extract_odt_text(file_path: str) -> str:
    """Extract text from an ODT file using content.xml."""
    with zipfile.ZipFile(file_path) as zf:
        xml_data = zf.read("content.xml")
    root = ET.fromstring(xml_data)
    text_parts = []
    for node in root.iter():
        if node.text and node.text.strip():
            text_parts.append(node.text.strip())
    return "\n".join(text_parts)


def _extract_pdf_text(file_path: str) -> str:
    """Extract text from a PDF using available Python libraries or pdftotext."""
    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(file_path)
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        pass

    try:
        from PyPDF2 import PdfReader  # type: ignore
        reader = PdfReader(file_path)
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["pdftotext", "-layout", file_path, "-"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except Exception:
        pass

    raise RuntimeError(
        "PDF text extraction is unavailable. Install 'pypdf' or 'PyPDF2', or ensure 'pdftotext' is present."
    )


def _extract_html_text(content: str) -> str:
    """Strip scripts/styles/tags from HTML-ish content."""
    content = re.sub(r"(?is)<script.*?>.*?</script>", " ", content)
    content = re.sub(r"(?is)<style.*?>.*?</style>", " ", content)
    content = re.sub(r"(?s)<[^>]+>", " ", content)
    content = html.unescape(content)
    content = re.sub(r"\r\n?", "\n", content)
    content = re.sub(r"[ \t]+", " ", content)
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


def _extract_rtf_text(content: str) -> str:
    """Best-effort plain text extraction from RTF."""
    content = re.sub(r"\\'[0-9a-fA-F]{2}", " ", content)
    content = re.sub(r"\\par[d]?", "\n", content)
    content = re.sub(r"\\[a-zA-Z]+\d* ?", " ", content)
    content = content.replace("{", " ").replace("}", " ")
    content = re.sub(r"[ \t]+", " ", content)
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


def _read_document_content(file_path: str) -> tuple[str, str]:
    """Read a document into normalized plain text and report detected format."""
    path = Path(file_path)
    suffix = path.suffix.lower()

    if suffix in {".txt", ".md", ".log", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".py", ".js", ".sh"}:
        return path.read_text(encoding="utf-8", errors="replace"), suffix or "text"

    if suffix == ".json":
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return json.dumps(raw, indent=2, ensure_ascii=False), "json"

    if suffix == ".csv":
        rows = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                rows.append(" | ".join(row))
        return "\n".join(rows), "csv"

    if suffix in {".html", ".htm", ".xml"}:
        raw = path.read_text(encoding="utf-8", errors="replace")
        return _extract_html_text(raw), suffix.lstrip(".")

    if suffix == ".rtf":
        raw = path.read_text(encoding="utf-8", errors="replace")
        return _extract_rtf_text(raw), "rtf"

    if suffix == ".docx":
        return _extract_docx_text(str(path)), "docx"

    if suffix == ".odt":
        return _extract_odt_text(str(path)), "odt"

    if suffix == ".pdf":
        return _extract_pdf_text(str(path)), "pdf"

    raw = path.read_text(encoding="utf-8", errors="replace")
    return raw, suffix.lstrip(".") or "text"


@function_tool()
def ctf_list_files(path: str) -> str:
    """
    List and triage all files in a CTF challenge directory.

    Runs `file` on every entry and returns a structured, prioritised summary so
    the agent immediately knows which files deserve attention first — executables
    and archives take priority over text and data files.

    Use this BEFORE binary_triage when the challenge gives you a directory or
    multiple files.

    Args:
        path: Absolute path to the challenge directory or a space-separated list
              of challenge file paths.

    Returns:
        Prioritised file list with type, size, and suggested starting tool.
    """
    import stat

    paths: list[Path] = []
    # Accept either a single directory or space-separated file paths
    candidates = [p.strip() for p in path.replace(",", " ").split() if p.strip()]
    for cand in candidates:
        linux_path = _convert_to_linux_path(cand)
        p = Path(linux_path)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file():
                    paths.append(child)
        elif p.is_file():
            paths.append(p)

    if not paths:
        return f"[ctf_list_files] No files found under: {path}"

    # Run 'file' on all of them via the bash helper if available, else fallback
    rows: list[dict] = []
    for fp in paths[:60]:  # cap at 60 to avoid giant output
        try:
            size = fp.stat().st_size
            is_exec = bool(fp.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except Exception:
            size = 0
            is_exec = False

        try:
            result = subprocess.run(
                ["file", "--brief", str(fp)],
                capture_output=True, text=True, timeout=5
            )
            ftype = result.stdout.strip() or "unknown"
        except Exception:
            ftype = "unknown"

        # Suggest first tool
        ftype_l = ftype.lower()
        if any(k in ftype_l for k in ("elf", "pe32", "mach-o", "executable")):
            suggestion = "binary_triage"
        elif any(k in ftype_l for k in ("zip", "gzip", "bzip", "xz", "7-zip", "rar", "tar")):
            suggestion = "binwalk_extract / binwalk_analyze"
        elif any(k in ftype_l for k in ("png", "jpeg", "gif", "tiff", "bmp", "webp")):
            suggestion = "stego_check / steg_analyze"
        elif any(k in ftype_l for k in ("pcap", "pcapng", "capture")):
            suggestion = "pcap_analyze"
        elif any(k in ftype_l for k in ("pdf", "word", "excel", "odf")):
            suggestion = "read_local_document"
        elif any(k in ftype_l for k in ("java", "jar", "class")):
            suggestion = "java_decompile / jar_explore"
        elif any(k in ftype_l for k in ("wasm", "webassembly")):
            suggestion = "wasm_analyze"
        elif any(k in ftype_l for k in ("ascii", "utf-8 unicode", "text")):
            suggestion = "strings_extract_ctf / read_local_document"
        else:
            suggestion = "analyze_file"

        rows.append({"path": str(fp), "size": size, "type": ftype, "exec": is_exec, "start": suggestion})

    # Sort: executables first, then archives, then images, then text
    _priority = {"binary_triage": 0, "binwalk": 1, "stego": 2, "pcap": 3, "java": 4, "wasm": 5, "read": 6, "analyze": 7}
    rows.sort(key=lambda r: next((v for k, v in _priority.items() if k in r["start"]), 8))

    lines = [
        f"[CTF FILE TRIAGE] Found {len(rows)} file(s) under: {path}",
        f"{'#':<4} {'File':<40} {'Size':>8}  {'Type':<40} {'Start with'}",
        "-" * 110,
    ]
    for i, r in enumerate(rows, 1):
        fname = Path(r["path"]).name
        lines.append(
            f"{i:<4} {fname:<40} {r['size']:>8}  {r['type'][:40]:<40} {r['start']}"
        )

    lines.append("")
    lines.append("Suggested start: " + rows[0]["start"] + f" on {Path(rows[0]['path']).name}")
    return "\n".join(lines)


@function_tool()
def read_local_document(file_path: str, chunk_index: int = 1, chunk_size: int = 12000, include_metadata: bool = True) -> str:
    """
    Read a local document in a format-aware way and return either the full text or a chunk.

    Supported formats include: txt, md, log, json, csv, html, xml, rtf, docx, odt, and pdf.

    Args:
        file_path: Path to the local file
        chunk_index: 1-based chunk number to return if the file is large
        chunk_size: Maximum characters per chunk
        include_metadata: Include file/format/chunk metadata in the output

    Returns:
        Extracted plain text from the document, optionally chunked with navigation hints
    """
    file_path = _convert_to_linux_path(file_path)

    if not os.path.exists(file_path):
        return f"Error: File '{file_path}' not found."
    if os.path.isdir(file_path):
        return f"Error: '{file_path}' is a directory. Provide a file path instead."

    try:
        content, detected_format = _read_document_content(file_path)
    except UnicodeDecodeError:
        return f"Error: Could not decode '{file_path}' as text."
    except KeyError as exc:
        return f"Error: Missing expected internal document part {exc} in '{file_path}'."
    except zipfile.BadZipFile:
        return f"Error: '{file_path}' is not a valid Office/OpenDocument zip container."
    except Exception as exc:
        return f"Error reading document '{file_path}': {exc}"

    content = content.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not content:
        return f"Read document: {file_path}\nFormat: {detected_format}\nThe extracted text is empty."

    chunk, chunk_index, total_chunks, total_chars = _chunk_text(content, chunk_size, chunk_index)

    header = ""
    if include_metadata:
        header = (
            f"Read document: {file_path}\n"
            f"Format: {detected_format}\n"
            f"Characters: {total_chars}\n"
            f"Chunk: {chunk_index}/{total_chunks}\n"
            "────────────────────\n"
        )

    footer = ""
    if total_chunks > 1:
        footer = (
            f"\n────────────────────\n"
            f"Use read_local_document(file_path=\"{file_path}\", chunk_index={chunk_index + 1}, chunk_size={chunk_size}) "
            f"for the next chunk."
            if chunk_index < total_chunks
            else "\n────────────────────\nEnd of document."
        )

    return f"{header}{chunk}{footer}"


@function_tool()
def read_tool_output(file_path: str, start_line: int = 1, end_line: int = 100, grep_pattern: str = "", **kwargs) -> str:
    """
    Read a section of a previously saved large tool output file.
    Use this to explore outputs that were too large to fit in context.
    
    Args:
        file_path: Path to the saved output file (given by the tool's summary)
        start_line: First line to read (1-indexed, default: 1)
        end_line: Last line to read (1-indexed, default: 100)
        grep_pattern: Optional: instead of reading by line range, grep for this pattern (returns matching lines with line numbers)
    
    Returns:
        The requested section of the output, or grep results
    """
    file_path = _convert_to_linux_path(file_path)
    
    if not os.path.exists(file_path):
        return f"Error: File '{file_path}' not found. Check the path from the tool's output summary."
    
    try:
        if not grep_pattern:
            # Read line range efficiently using islice
            from itertools import islice
            with open(file_path, "r", errors="replace") as f:
                # Skip to start line
                selected = list(islice(f, max(0, start_line - 1), end_line))
            
            content = "".join(selected)
            
            # Get total line count efficiently if file is large (using wc -l on Linux)
            try:
                wc_res = subprocess.run(["wc", "-l", file_path], capture_output=True, text=True)
                total = int(wc_res.stdout.split()[0])
            except:
                # Fallback for small files or if wc fails
                with open(file_path, "r", errors="replace") as f:
                    total = sum(1 for _ in f)
            
            start = max(1, start_line)
            end = start + len(selected) - 1
            
            # Add context
            header = f"── Lines {start}-{end} of {total} total ──\n"
            if end < total:
                footer = f"\n── [{total - end} more lines. Use read_tool_output(\"{file_path}\", start_line={end+1}, end_line={end+100}) to continue] ──"
            else:
                footer = "\n── End of file ──"
            
            return header + content + footer
        else:
            # Use grep with line numbers (already handles large files efficiently)
            result = subprocess.run(
                ["grep", "-n", "-i", grep_pattern, file_path],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout.strip()
            if not output:
                return f"No matches for pattern '{grep_pattern}' in {file_path}"
            lines = output.split("\n")
            if len(lines) > 200:
                return "\n".join(lines[:200]) + f"\n\n... [{len(lines) - 200} more matches]"
            return output
    except Exception as e:
        return f"Error reading file: {str(e)}"





@function_tool()
def analyze_file(file_path: str, mode: str = "auto", max_lines: int = 200) -> str:
    """
    Deep-inspect a file and produce a structured semantic digest for reasoning.

    Unlike read_local_document (raw text dump), this tool actively ANALYZES the
    content and surfaces what matters for security/CTF work:
      - File type, encoding, size
      - Key code constructs: functions, classes, imports, entry points
      - Hardcoded constants, strings, magic bytes
      - CTF-relevant patterns: flag formats, crypto keys, encoding hints,
        comparison/validation logic, vulnerable sinks
      - Hex dump header for binary files
      - Actionable next-step recommendations

    Use this BEFORE read_local_document when you need to UNDERSTAND a file,
    not just read it. Especially valuable for:
      - Challenge source code (Python, C, PHP, JS)
      - Binary files / executables
      - Config files with embedded secrets

    Args:
        file_path: Path to the file to analyze
        mode:      "auto" (default), "code", "binary", or "text"
        max_lines: Max source lines to include in code snippets (default 200)

    Returns:
        Structured digest: type info, key constructs, patterns, recommendations
    """
    import subprocess as _sp
    file_path = _convert_to_linux_path(file_path)
    if not os.path.exists(file_path):
        return f"Error: File not found: {file_path}"

    if os.path.isdir(file_path):
        out = [f"## Directory: {file_path}"]
        for root_d, dirs, files_in in os.walk(file_path):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules", ".git", "venv")]
            depth = root_d.replace(file_path, "").count(os.sep)
            if depth > 3:
                continue
            rel = os.path.relpath(root_d, file_path)
            if rel != ".":
                out.append("  " * depth + f"[DIR] {os.path.basename(root_d)}/")
            for fname in sorted(files_in)[:20]:
                sz = os.path.getsize(os.path.join(root_d, fname))
                out.append("  " * depth + f"  {fname} ({sz:,} B)")
        out.append("Tip: call analyze_file on individual files for deep inspection.")
        return "\n".join(out[:100])

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    suffix = os.path.splitext(file_name)[1].lower()
    out = [f"## File Analysis: {file_name}",
           f"- Path: {file_path}",
           f"- Size: {file_size:,} bytes"]

    CODE_EXTS = {".py", ".js", ".ts", ".php", ".rb", ".go", ".rs", ".c", ".cpp",
                 ".h", ".java", ".cs", ".sh", ".bash", ".pl", ".lua", ".swift", ".kt"}
    TEXT_EXTS = {".txt", ".md", ".log", ".yaml", ".yml", ".ini", ".cfg", ".conf",
                 ".json", ".xml", ".html", ".htm", ".csv", ".env", ".toml"}

    if mode == "auto":
        if suffix in CODE_EXTS:
            mode = "code"
        elif suffix in TEXT_EXTS:
            mode = "text"
        else:
            try:
                with open(file_path, "rb") as fh:
                    head = fh.read(512)
                mode = "binary" if head.count(b"\x00") > 8 else "text"
            except Exception:
                mode = "text"
    out.append(f"- Mode: {mode}\n")

    CTF_PATS = [
        (r"(?i)flag\{[^}]*\}",                           "FLAG"),
        (r"(?i)HTB\{[^}]*\}",                            "HTB FLAG"),
        (r"(?i)ctf\{[^}]*\}",                            "CTF FLAG"),
        (r"(?i)thm\{[^}]*\}",                            "THM FLAG"),
        (r"-----BEGIN [A-Z ]+KEY-----",                  "PEM KEY"),
        (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S+)",    "HARDCODED PASS"),
        (r"(?i)(secret|token|api.?key)\s*[=:]\s*['\"]?(\S+)",  "SECRET/TOKEN"),
        (r"(?i)(aes|des|rsa|rc4|xor|chacha|blowfish)",         "CRYPTO ALGO"),
        (r"(?i)(base64|b64|rot13|hex\.decode|binascii)",       "ENCODING HINT"),
        (r"(?i)(strcmp|strncmp|memcmp|check_flag|validate|verify|correct)", "VALIDATOR"),
        (r"(?i)(eval|exec|os\.system|subprocess|shell=True)",  "CODE EXEC SINK"),
        (r"(?i)(gets\(|scanf\(|strcpy\(|sprintf\()",           "OVERFLOW RISK"),
        (r"(?i)(render_template_string|\.render\s*\()",        "SSTI SINK"),
        (r"0x[0-9a-fA-F]{8,}",                                "HEX CONSTANT"),
    ]

    def _scan_patterns(text_lines):
        hits = []
        for pat, label in CTF_PATS:
            for i, line in enumerate(text_lines, 1):
                for m in re.findall(pat, line):
                    val = m if isinstance(m, str) else " ".join(m)
                    hits.append(f"  L{i:4d} [{label}]: {val[:120]}")
                    if len(hits) >= 40:
                        return hits
        return hits

    # ── BINARY mode ───────────────────────────────────────────────────────────
    if mode == "binary":
        out.append("### Binary File")
        try:
            with open(file_path, "rb") as fh:
                magic = fh.read(16).hex(" ")
            out.append(f"- Magic bytes: {magic}")
            try:
                ft = _sp.run(["file", file_path], capture_output=True, text=True, timeout=5)
                out.append(f"- File type:   {ft.stdout.strip().split(':', 1)[-1].strip()}")
            except Exception:
                pass
            try:
                s_res = _sp.run(["strings", "-n", "6", file_path], capture_output=True, text=True, timeout=15)
                all_str = s_res.stdout.splitlines()
                boring = re.compile(r"^[\s\d._/-]{0,3}$|^lib|^GLIBC|^GCC|^_ITM|^__")
                interesting = [sl for sl in all_str if not boring.match(sl) and len(sl) > 4]
                out.append(f"\n### Strings ({len(all_str)} total — interesting subset)")
                out.append("\n".join(interesting[:80]))
                hits = _scan_patterns(all_str)
                if hits:
                    out.append("\n### CTF Patterns Found in Strings")
                    out.extend(hits)
            except Exception as e:
                out.append(f"strings extraction failed: {e}")
            try:
                xxd = _sp.run(["xxd", file_path], capture_output=True, text=True, timeout=5)
                hex_ls = xxd.stdout.splitlines()[:24]
                out.append(f"\n### Hex Dump (first {len(hex_ls)} lines)")
                out.append("```\n" + "\n".join(hex_ls) + "\n```")
            except Exception:
                pass
        except Exception as e:
            out.append(f"Binary analysis error: {e}")
        out += [
            "\n### Recommended Next Steps",
            "1. ctf_command('file <path>') — confirm exact architecture/format",
            "2. checksec — check protections (PIE, NX, Canary, RELRO)",
            "3. ghidra_decompile — decompile main / validate / check_flag functions",
            '4. ctf_command(\'gdb -batch -ex "info functions" <path>\') — list all functions',
        ]
        return "\n".join(out)

    # ── CODE mode ─────────────────────────────────────────────────────────────
    if mode == "code":
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"Error reading source file: {e}"
        code_lines = content.splitlines()
        out += [f"- Lines: {len(code_lines)}", f"- Lang:  {suffix.lstrip('.')}\n"]

        func_pat = re.compile(
            r"^\s*(def |async def |function |class |public |private |protected |fn |func |sub )",
            re.IGNORECASE
        )
        constructs = [f"  L{i:4d}: {l.strip()}"
                      for i, l in enumerate(code_lines, 1) if func_pat.match(l)]
        if constructs:
            out.append("### Key Constructs (functions / classes)")
            out.append("\n".join(constructs[:60]))

        import_re = re.compile(r"^\s*(import |from |require\s*\(|#include|use )", re.IGNORECASE)
        imports = [l.strip() for l in code_lines if import_re.match(l)]
        if imports:
            out += ["\n### Imports / Dependencies", "\n".join(imports[:25])]

        hits = _scan_patterns(code_lines)
        if hits:
            out += ["\n### CTF / Security Patterns"]
            out.extend(hits)

        const_re = re.compile(r"""(["'])([^"']{8,})\1|0x[0-9a-fA-F]{4,}|\b\d{6,}\b""")
        constants = []
        for i, line in enumerate(code_lines, 1):
            for m in const_re.finditer(line):
                constants.append(f"  L{i:4d}: {m.group(0)[:100]}")
            if len(constants) > 30:
                break
        if constants:
            out += ["\n### Hardcoded Constants / Strings"]
            out.extend(constants[:30])

        snippet = min(max_lines, len(code_lines))
        out += [
            f"\n### Source Code (first {snippet} lines)",
            "```" + suffix.lstrip("."),
            "\n".join(code_lines[:snippet]),
            "```",
        ]
        if len(code_lines) > snippet:
            out.append(
                f"\n{len(code_lines) - snippet} more lines — "
                f"use read_local_document('{file_path}', chunk_index=2) for more."
            )
        out += [
            "\n### Recommended Next Steps",
            "1. Focus on VALIDATOR patterns above — those gate the correct answer.",
            "2. Trace ENCODING HINT patterns — decode/reconstruct the expected input.",
            "3. Use find_dangerous_functions for sink-based vulnerability identification.",
            "4. Use static_code_analysis for automated pattern matching.",
        ]
        return "\n".join(out)

    # ── TEXT mode ─────────────────────────────────────────────────────────────
    try:
        content, fmt = _read_document_content(file_path)
    except Exception as e:
        return f"Error reading file: {e}"
    text_lines = content.splitlines()
    out += [f"- Format: {fmt}", f"- Lines:  {len(text_lines)}\n"]

    hits = _scan_patterns(text_lines)
    if hits:
        out += ["### CTF / Security Patterns Found"]
        out.extend(hits)

    from collections import Counter as _Counter
    words = re.findall(r"\b[A-Za-z_]\w{3,}\b", content)
    if words:
        out += ["\n### Top Keywords",
                ", ".join(f"{w}({c})" for w, c in _Counter(words).most_common(20))]

    preview = min(max_lines, len(text_lines))
    out += [f"\n### Content Preview (first {preview} lines)", "\n".join(text_lines[:preview])]
    if len(text_lines) > preview:
        out.append(
            f"\n...{len(text_lines) - preview} more lines — "
            f"use read_local_document('{file_path}', chunk_index=2) to continue."
        )
    return "\n".join(out)

@function_tool()
def tshark_analyze(pcap_file: str, filter_expr: str = "") -> str:
    """
    Analyze PCAP file with TShark.
    
    Args:
        pcap_file: Path to PCAP file
        filter_expr: Optional display filter (e.g., 'http', 'tcp.port==80')
    
    Returns:
        Packet analysis output
    """
    try:
        pcap_file = _convert_to_linux_path(pcap_file)
        cmd = ["tshark", "-r", pcap_file, "-c", "100"]  # Limit to 100 packets
        if filter_expr:
            cmd.extend(["-Y", filter_expr])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        raw = result.stdout or result.stderr or "No packets found"
        return smart_output(raw, "tshark_analyze", os.path.basename(pcap_file))
    except subprocess.TimeoutExpired:
        return "Error: TShark analysis timed out"
    except FileNotFoundError:
        return "Error: tshark not found. Please install wireshark/tshark."
    except Exception as e:
        return f"Error running tshark: {str(e)}"


@function_tool()
def binwalk_analyze(file_path: str, **kwargs) -> str:
    """
    Scan a file for embedded files and executable signatures using binwalk.
    
    Args:
        file_path: Path to the file to analyze
    
    Returns:
        Analysis summary
    """
    file_path = _convert_to_linux_path(file_path)
    _CTF_TECHNIQUES_TRIED.add(f"binwalk_analyze: {os.path.basename(file_path)}")
    try:
        result = subprocess.run(
            ["binwalk", file_path],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout or result.stderr or "No output from binwalk"
        
        # Logic Check: Warn about common false positives
        warnings = []
        if "YAFFS" in output and "game" in file_path.lower():
            warnings.append("⚠️ NOTICE: YAFFS detection in game files is often a false positive. If this is a Godot game, you MUST use the framework tool 'godot_pck_extract(file_path=\"...\")' instead of shell commands.")
        if "ESP32" in output and "x86" in output:
            warnings.append("⚠️ NOTICE: Contradictory signatures detected (ESP32 vs x86). Binwalk signatures may be overlapping.")
            
        if warnings:
            output = "\n".join(warnings) + "\n\n" + output
            
        return output
    except FileNotFoundError:
        return "Error: binwalk not found. Please install binwalk."
    except Exception as e:
        return f"Error running binwalk: {str(e)}"


@function_tool()
def binwalk_extract(file_path: str, **kwargs) -> str:
    """
    Automatically extract embedded files from a binary using binwalk -e.
    
    Args:
        file_path: Path to the file to extract
    
    Returns:
        Extraction status and output directory
    """
    file_path = _convert_to_linux_path(file_path)
    try:
        # -e: extract, -M: matryoshka (recursive)
        cmd = ["binwalk", "-e", "-M", "--run-as-root", file_path]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120
        )
        # Binwalk creates a directory named _<filename>.extracted
        base_name = os.path.basename(file_path)
        extracted_dir = os.path.join(os.path.dirname(file_path), f"_{base_name}.extracted")
        
        if os.path.exists(extracted_dir):
            return f"✅ Extraction successful! Files saved to '{extracted_dir}'.\nOutput:\n{result.stdout}"
        return f"❌ binwalk extraction failed or no files found.\nOutput: {result.stdout or result.stderr}"
    except Exception as e:
        return f"Error running binwalk extraction: {str(e)}"


@function_tool()
def foremost_extract(file_path: str, **kwargs) -> str:
    """
    Recover files based on their headers/footers using foremost.
    Useful when binwalk fails or for raw disk images.
    
    Args:
        file_path: Path to the file/image
    
    Returns:
        Extraction status
    """
    file_path = _convert_to_linux_path(file_path)
    try:
        out_dir = f"foremost_{os.path.basename(file_path)}"
        result = subprocess.run(
            ["foremost", "-i", file_path, "-o", out_dir],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists(out_dir):
            return f"✅ foremost extraction complete! Check '{out_dir}/audit.txt' for results."
        return f"❌ foremost failed: {result.stdout or result.stderr}"
    except FileNotFoundError:
        return "Error: foremost not found. Install with: sudo apt install foremost"
    except Exception as e:
        return f"Error running foremost: {str(e)}"


@function_tool()
def strings_extract(file_path: str, min_length: int = 4) -> str:
    """
    Extract printable strings from a file.
    
    Args:
        file_path: Path to file
        min_length: Minimum string length (default: 4)
    
    Returns:
        Extracted strings (limited to first 500 lines)
    """
    try:
        file_path = _convert_to_linux_path(file_path)
        result = subprocess.run(
            ["strings", "-n", str(min_length), file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        raw = result.stdout or "No strings found"
        # Sanitize to fix JSON parsing issues with control characters
        raw = "".join(ch for ch in raw if ch.isprintable() or ch in ('\n', '\r', '\t'))
        return smart_output(raw, "strings_extract", os.path.basename(file_path))
    except FileNotFoundError:
        return "Error: strings not found."
    except Exception as e:
        return f"Error running strings: {str(e)}"


@function_tool()
def exiftool_metadata(file_path: str) -> str:
    """
    Extract metadata from file using ExifTool.
    
    Args:
        file_path: Path to file
    
    Returns:
        File metadata
    """
    try:
        file_path = _convert_to_linux_path(file_path)
        result = subprocess.run(
            ["exiftool", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout or result.stderr or "No metadata found"
    except FileNotFoundError:
        return "Error: exiftool not found. Please install exiftool."
    except Exception as e:
        return f"Error running exiftool: {str(e)}"


@function_tool()
def ctf_command(command: str, timeout: int = 120, stdin_data: str = "", cwd: str | None = None, justification: str = "", **kwargs) -> str:
    """
    Execute a shell command in the CTF analysis environment (Linux VM via WSL).

    This is the primary tool for running ANY shell command during CTF analysis:
    file, strings, objdump, readelf, gdb, python3, ltrace, strace, nc, curl,
    openssl, john, hashcat, or any custom one-liner.

    Guardrails (to prevent wasted loops):
    - Duplicate detection: blocks commands >93% similar to recent ones
    - Low-yield pivot gates at 8 / 16 / 24 low-yield actions (forces RE tools)
    - Use justification= to explain why a command is necessary when blocked

    Args:
        command:       Shell command string to run (bash syntax)
        timeout:       Seconds before kill (default 120)
        stdin_data:    Data to pipe into the command's stdin
        cwd:           Working directory (default: current)
        justification: Reason for the command (used when pivot gate triggers)

    Returns:
        Command stdout/stderr, capped and summarised via smart_output
    """
    global _CTF_LOW_YIELD_COUNT

    quality_error = _command_quality_error(command)
    if quality_error:
        return quality_error

    # ── Duplicate / pivot gate ────────────────────────────────────────────────
    norm = _normalize_command(command)
    if _is_duplicate_command(norm):
        return (
            f"[DUPLICATE BLOCKED] Command too similar to a recent one.\n"
            f"Normalised form: {norm}\n"
            f"Vary your approach or use a different tool."
        )
    pivot_msg = _requires_pivot(_CTF_LOW_YIELD_COUNT, command)
    if pivot_msg and not justification:
        return pivot_msg

    # Append as (norm, had_error=False); updated to True at end if command errors.
    _CTF_COMMAND_HISTORY.append((norm, False))
    _CTF_TECHNIQUES_TRIED.add(command[:60])

    # ── Build command (route through WSL on Windows) ──────────────────────────
    import platform
    if platform.system() == "Windows":
        # Translate embedded Windows paths (e.g. D:\path\to\file) to WSL paths
        command = re.sub(
            r'([A-Za-z]):\\([^\s"\'|><;]+)',
            lambda m: f"/mnt/{m.group(1).lower()}/{m.group(2).replace('\\', '/')}",
            command
        )
        wsl_cmd = ["wsl", "--", "bash", "-c", command]
    else:
        wsl_cmd = ["bash", "-c", command]

    stdin_bytes = stdin_data.encode("utf-8", errors="replace") if stdin_data else None

    try:
        result = subprocess.run(
            wsl_cmd,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
        )
        raw = (result.stdout or b"") + (result.stderr or b"")
        output = raw.decode("utf-8", errors="replace")

        if not output.strip():
            output = f"(Command exited with code {result.returncode}, no output)"

        # Mark this history entry as errored so corrections aren't blocked.
        if result.returncode != 0:
            _CTF_COMMAND_HISTORY[-1] = (norm, True)

        # ── Artifact extraction & yield accounting ────────────────────────────
        artifacts = _extract_artifacts(output)
        if artifacts:
            _CTF_EVIDENCE_LEDGER.extend(a for a in artifacts if a not in _CTF_EVIDENCE_LEDGER)
            _CTF_LOW_YIELD_COUNT = max(0, _CTF_LOW_YIELD_COUNT - 1)
        else:
            _CTF_LOW_YIELD_COUNT += 1

        artifact_note = ""
        if artifacts:
            artifact_note = f"\n[ARTIFACTS] {', '.join(artifacts[:10])}"
        else:
            artifact_note = f"\n[ARTIFACTS] none (low-yield count: {_CTF_LOW_YIELD_COUNT})"

        # Flag detection — append a prominent note so the agent doesn't miss it
        flag_note = ""
        detected_flags = _detect_ctf_flag(output)
        if detected_flags:
            flag_lines = "\n".join(f"  {f}" for f in detected_flags[:5])
            flag_note = (
                f"\n\n╔══ FLAG DETECTED ══════════════════════════════════════\n"
                f"{flag_lines}\n"
                f"╠═ ACTION REQUIRED ═════════════════════════════════════\n"
                f"║  1. Output the flag clearly: FLAG: <value>\n"
                f"║  2. Call record_ctf_solution() to store the solve chain\n"
                f"║     so future similar challenges benefit from this run.\n"
                f"╚═══════════════════════════════════════════════════════"
            )

        full_output = f"$ {command}\n{output}{artifact_note}{flag_note}"
        return smart_output(full_output, "ctf_command", command[:40])

    except subprocess.TimeoutExpired:
        _CTF_COMMAND_HISTORY[-1] = (norm, True)
        _CTF_LOW_YIELD_COUNT += 1
        return f"[TIMEOUT] Command killed after {timeout}s: {command}"
    except FileNotFoundError as e:
        _CTF_COMMAND_HISTORY[-1] = (norm, True)
        return f"[ERROR] Command runner not found: {e}\nOn Windows, ensure WSL is installed."
    except Exception as e:
        _CTF_COMMAND_HISTORY[-1] = (norm, True)
        return f"[ERROR] {type(e).__name__}: {e}"


@function_tool(name_override="execute_bash")
async def execute_bash(command: str, timeout: int = 120, stdin_data: str = "", cwd: str | None = None, justification: str = "", **kwargs) -> str:
    """
    Execute a bash command with the same safety, deduplication, timeout, and
    artifact-handling guardrails as ctf_command.

    Use this when an agent needs a deliberate shell probe for local CTF/lab
    analysis, source inspection, short one-liners, debugger helpers, or
    evidence extraction. Prefer purpose-built tools when they exist.

    Args:
        command:       Shell command string to run (bash syntax)
        timeout:       Seconds before kill (default 120)
        stdin_data:    Data to pipe into the command's stdin
        cwd:           Working directory for local file commands
        justification: Reason for the command if pivot gates trigger

    Returns:
        Command stdout/stderr, capped and summarised via smart_output
    """
    return await ctf_command.invoke(
        command=command,
        timeout=timeout,
        stdin_data=stdin_data,
        cwd=cwd,
        justification=justification,
    )


@function_tool()
def steg_analyze(file_path: str, passphrase: str = "") -> str:
    """
    Comprehensive steganography analysis — runs multiple steg tools in one call.
    Checks: zsteg (PNG/BMP), steghide (JPEG), exiftool metadata, and binwalk embedded files.
    
    Args:
        file_path: Path to image file to analyze
        passphrase: Optional passphrase for steghide extraction
    
    Returns:
        Combined results from all steganography tools
    """
    import os
    import shutil
    
    file_path = _convert_to_linux_path(file_path)
    
    results = [f"=== Steganography Analysis: {os.path.basename(file_path)} ===\n"]
    
    # 1. File type identification
    try:
        file_res = subprocess.run(["file", file_path], capture_output=True, text=True, timeout=10)

        results.append(f"[File Type] {file_res.stdout.strip()}\n")
    except Exception:
        pass
    
    # 2. Exiftool metadata (look for hidden comments, unusual fields)
    try:
        exif_res = subprocess.run(
            ["exiftool", file_path], capture_output=True, text=True, timeout=15
        )
        if exif_res.stdout:
            # Highlight suspicious fields
            suspicious = []
            for line in exif_res.stdout.splitlines():
                lower = line.lower()
                if any(kw in lower for kw in ["comment", "flag", "secret", "password", "hidden", "base64", "hint"]):
                    suspicious.append(f"  ⚠️  {line.strip()}")
            
            if suspicious:
                results.append("[Exiftool — SUSPICIOUS FIELDS]")
                results.extend(suspicious)
            else:
                results.append("[Exiftool] No suspicious metadata fields found")
            results.append("")
    except FileNotFoundError:
        results.append("[Exiftool] Not installed (apt install libimage-exiftool-perl)\n")
    except Exception:
        pass
    
    # 3. zsteg (PNG/BMP LSB steganography)
    zsteg_bin = shutil.which("zsteg")
    if zsteg_bin:
        try:
            zsteg_res = subprocess.run(
                ["zsteg", file_path], capture_output=True, text=True, timeout=30
            )
            output = zsteg_res.stdout.strip()
            if output:
                # Filter for interesting results (skip noise)
                interesting = []
                for line in output.splitlines()[:30]:
                    if any(kw in line.lower() for kw in [
                        "flag", "ctf", "text:", "utf-8", "ascii", "http", "base64",
                        "png", "jpg", "pdf", "zip", "pk"
                    ]):
                        interesting.append(f"  🔍 {line}")
                    elif "b1,lsb" in line or "b1,msb" in line:
                        interesting.append(f"  {line}")
                
                if interesting:
                    results.append("[zsteg — FINDINGS]")
                    results.extend(interesting)
                else:
                    results.append("[zsteg] No obvious hidden data in LSB channels")
            else:
                results.append("[zsteg] No results (may not be PNG/BMP)")
            results.append("")
        except Exception as e:
            results.append(f"[zsteg] Error: {e}\n")
    else:
        results.append("[zsteg] Not installed (gem install zsteg)\n")
    
    # 4. steghide (JPEG/BMP/WAV/AU steganography)
    steghide_bin = shutil.which("steghide")
    if steghide_bin:
        try:
            # First try info (no passphrase needed)
            info_res = subprocess.run(
                ["steghide", "info", file_path, "-f"],
                capture_output=True, text=True, timeout=15,
                input="\n"  # Skip passphrase prompt
            )
            info_out = (info_res.stdout + info_res.stderr).strip()
            if "embedded" in info_out.lower():
                results.append(f"[steghide — INFO]\n{info_out}")
                
                # Try extraction with empty passphrase or provided one
                try:
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False) as tf:
                        temp_path = tf.name
                    extract_res = subprocess.run(
                        ["steghide", "extract", "-sf", file_path,
                         "-p", passphrase, "-f", "-xf", temp_path],
                        capture_output=True, text=True, timeout=15
                    )
                    if extract_res.returncode == 0:
                        try:
                            with open(temp_path, "r", encoding="utf-8", errors="replace") as f:
                                extracted_data = f.read()
                            results.append(f"[steghide — EXTRACTED DATA]\n{extracted_data[:2000]}")
                        except Exception as read_err:
                            results.append(f"[steghide] Extracted data unreadable: {read_err}")
                    elif "could not extract" in extract_res.stderr.lower():
                        results.append("[steghide] Data embedded but needs correct passphrase")
                    else:
                        results.append(f"[steghide] Extraction failed: {extract_res.stderr.strip()}")
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception:
                    results.append("[steghide] Extraction failed — try with correct passphrase")
            else:
                results.append("[steghide] No embedded data detected (or not a supported format)")
            results.append("")
        except Exception as e:
            results.append(f"[steghide] Error: {e}\n")
    else:
        results.append("[steghide] Not installed (apt install steghide)\n")
    
    # 5. Binwalk for embedded files
    try:
        binwalk_res = subprocess.run(
            ["binwalk", file_path], capture_output=True, text=True, timeout=30
        )
        output = binwalk_res.stdout.strip()
        sig_count = len([l for l in output.splitlines() if l.strip() and not l.startswith("DECIMAL")])
        if sig_count > 2:  # More than just the image header
            results.append(f"[binwalk — {sig_count - 1} SIGNATURES FOUND]")
            results.append(output[:2000])
            results.append("\nTip: Run 'binwalk -e <file>' to extract embedded files")
        else:
            results.append("[binwalk] No unusual embedded signatures")
        results.append("")
    except FileNotFoundError:
        results.append("[binwalk] Not installed (apt install binwalk)\n")
    except Exception:
        pass
    
    return "\n".join(results)


@function_tool()
def wasm_analyze(file_path: str, **kwargs) -> str:
    """
    Analyze WebAssembly (.wasm) files using WABT tools.
    Attempts wasm-decompile (C-like), wasm2wat (WAT text), and wasm-objdump.
    
    Args:
        file_path: Path to the .wasm file
    
    Returns:
        Decompiled or disassembled WASM output
    """
    file_path = _convert_to_linux_path(file_path)
    results = [f"=== WASM Analysis: {os.path.basename(file_path)} ===\n"]
    
    # 1. wasm-decompile (C-like output)
    try:
        res = subprocess.run(["wasm-decompile", file_path], capture_output=True, text=True, timeout=30)
        if res.stdout:
            results.append("[wasm-decompile]")
            results.append(smart_output(res.stdout, "wasm_analyze", "decompile"))
            # If decompile works, return it immediately as it's the most useful
            return "\n".join(results)
    except:
        pass
        
    # 2. wasm2wat (textual representation)
    try:
        res = subprocess.run(["wasm2wat", file_path], capture_output=True, text=True, timeout=30)
        if res.stdout:
            results.append("[wasm2wat]")
            results.append(smart_output(res.stdout, "wasm_analyze", "wat"))
    except:
        pass
        
    # 3. wasm-objdump (headers/sections)
    try:
        res = subprocess.run(["wasm-objdump", "-x", file_path], capture_output=True, text=True, timeout=30)
        if res.stdout:
            results.append("[wasm-objdump -x]")
            results.append(res.stdout)
    except:
        pass
        
    if len(results) <= 1:
        return "Error: WABT tools (wasm-decompile, wasm2wat) not found or failed. Install: sudo apt install wabt"
        
    return "\n".join(results)


@function_tool()
def upx_unpack(file_path: str, **kwargs) -> str:
    """
    Attempt to unpack a binary compressed with UPX.
    
    Args:
        file_path: Path to the compressed binary
    
    Returns:
        UPX output and success status
    """
    file_path = _convert_to_linux_path(file_path)
    try:
        res = subprocess.run(["upx", "-d", file_path], capture_output=True, text=True, timeout=30)
        return res.stdout or res.stderr or "UPX failed with no output"
    except FileNotFoundError:
        return "Error: upx not found. Install: sudo apt install upx-ucl"
    except Exception as e:
        return f"Error running upx: {str(e)}"


@function_tool()
def java_decompile(file_path: str, **kwargs) -> str:
    """
    Decompile Java .class, .jar, or .apk files using jadx.
    
    Args:
        file_path: Path to .class, .jar, or .apk file
    
    Returns:
        Status message and source location
    """
    file_path = _convert_to_linux_path(file_path)
    try:
        # Create output directory
        out_dir = f"java_source_{os.path.basename(file_path)}"
        res = subprocess.run(["jadx", "-d", out_dir, "--no-res", file_path], capture_output=True, text=True, timeout=180)
        
        if os.path.exists(out_dir):
            return f"✅ Decompilation successful! Source files saved to '{out_dir}'. Use 'ls -R {out_dir}' to explore."
        
        return f"❌ jadx failed: {res.stdout or res.stderr}"
    except FileNotFoundError:
        return "Error: jadx not found. Please install jadx."
    except Exception as e:
        return f"Error running jadx: {str(e)}"


@function_tool()
def javap_disassemble(file_path: str, **kwargs) -> str:
    """
    Disassemble a Java .class file using javap.
    Useful when jadx fails or you need to see raw bytecode/constants.
    
    Args:
        file_path: Path to .class file
    
    Returns:
        Disassembled bytecode and constant pool
    """
    file_path = _convert_to_linux_path(file_path)
    try:
        res = subprocess.run(["javap", "-v", "-p", "-c", file_path], capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            return smart_output(res.stdout, "javap_disassemble", os.path.basename(file_path))
        return f"❌ javap failed: {res.stderr or res.stdout}"
    except FileNotFoundError:
        return "Error: javap not found. Please install a JDK."
    except Exception as e:
        return f"Error running javap: {str(e)}"


@function_tool()
def jar_explore(jar_path: str, search_query: str = "", **kwargs) -> str:
    """
    Explore contents of a JAR file and search for strings in resources/properties.
    Specifically checks for ClassFinal indicators.
    
    Args:
        jar_path: Path to .jar file
        search_query: Optional string to search for in all files (grep)
    
    Returns:
        JAR structure and search results
    """
    jar_path = _convert_to_linux_path(jar_path)
    results = [f"### JAR Exploration: {os.path.basename(jar_path)}"]
    
    try:
        # 1. List contents
        ls_res = subprocess.run(["unzip", "-l", jar_path], capture_output=True, text=True, timeout=30)
        ls_out = ls_res.stdout
        
        # Check for ClassFinal
        if "libclassfinal.so" in ls_out or "ClassFinal" in ls_out:
            results.append("⚠️  Indicator of ClassFinal protection detected!")
            results.append("Tips for ClassFinal:")
            results.append("- Look for 'application.properties', 'application.yml', or 'config.properties'")
            results.append("- Search for 'password', 'pwd', 'key' or 'license'")
            results.append("- It uses -javaagent:application.jar to decrypt classes at runtime.")
        
        if not search_query:
            results.append(smart_output(ls_out, "jar_explore", "list"))
        else:
            # Search in all files
            grep_res = subprocess.run(["zipgrep", "-i", search_query, jar_path], capture_output=True, text=True, timeout=60)
            if grep_res.stdout:
                results.append(f"🔍 Search results for '{search_query}':")
                results.append(smart_output(grep_res.stdout, "jar_explore", f"search_{search_query}"))
            else:
                results.append(f"No matches for '{search_query}' found in JAR resources.")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error exploring JAR: {str(e)}"


@function_tool()
def qemu_emulate(binary_path: str, arch: str = "", args: str = "", gdb_port: int = 0, **kwargs) -> str:
    """
    Emulate non-native binaries (ARM, MIPS, etc.) using QEMU user-mode.
    
    Args:
        binary_path: Path to the non-native binary
        arch: Architecture (arm, aarch64, mips, mipsel, ppc, i386). Auto-detected if empty.
        args: Command line arguments to pass to the binary
        gdb_port: If > 0, start QEMU GDB stub on this port (e.g. 1234)
    
    Returns:
        Binary output or QEMU error
    """
    binary_path = _convert_to_linux_path(binary_path)
    
    # Auto-detect architecture if not provided
    if not arch:
        try:
            file_res = subprocess.run(["file", binary_path], capture_output=True, text=True, timeout=10)
            file_out = file_res.stdout.lower()
            if "aarch64" in file_out: arch = "aarch64"
            elif "arm" in file_out: arch = "arm"
            elif "mips" in file_out:
                arch = "mips" if "msb" in file_out else "mipsel"
            elif "intel 80386" in file_out: arch = "i386"
            elif "powerpc" in file_out: arch = "ppc"
        except:
            pass
            
    if not arch:
        return "Error: Could not auto-detect architecture. Please specify 'arch' (arm, mips, aarch64, etc.)."

    qemu_bin = f"qemu-{arch}-static"
    # Try non-static if static not found
    import shutil
    if not shutil.which(qemu_bin):
        qemu_bin = f"qemu-{arch}"
        
    cmd = [qemu_bin]
    if gdb_port > 0:
        cmd.extend(["-g", str(gdb_port)])
    
    cmd.append(binary_path)
    if args:
        cmd.extend(args.split())
        
    try:
        # Note: We run with a timeout because emulated binaries can sometimes hang
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        output = result.stdout
        if result.stderr:
            output += f"\n--- STDERR ---\n{result.stderr}"
            
        if not output and result.returncode != 0:
            return f"QEMU failed with exit code {result.returncode}. Ensure qemu-{arch} is installed."
            
        return output or f"(Binary exited with code {result.returncode}, no output)"
    except FileNotFoundError:
        return f"Error: QEMU emulator for {arch} ({qemu_bin}) not found. Install: sudo apt install qemu-user-static"
    except subprocess.TimeoutExpired:
        return "Error: Emulation timed out after 60s. Use gdb_port if you need to debug."
    except Exception as e:
        return f"Error running QEMU: {str(e)}"


# ═══════════════════════════════════════════════════════════════════════════
# GO BINARY RECOVERY — gopclntab patch + GoReSym symbol recovery
# ═══════════════════════════════════════════════════════════════════════════

@function_tool()
def go_binary_recover(binary_path: str, output_json: str = "") -> str:
    """
    Recover symbols and function addresses from a stripped or garbled Go binary.

    Performs three steps automatically:
      1. Check .gopclntab section magic bytes via readelf.  If corrupted,
         create a patched copy and restore the correct Go pclntab magic
         (\\xf1\\xff\\xff\\xff for Go 1.20+).
      2. Install GoReSym (github.com/mandiant/GoReSym) if not already present
         at /tmp/gobin/GoReSym.
      3. Run GoReSym on the (patched) binary and return a sorted function list
         with name, start VA, and end VA.  Also saves raw JSON if output_json
         is provided.

    Use this as Step 1 whenever binary_triage identifies a Go binary that is
    stripped (nm returns no symbols) — especially garble-obfuscated binaries.

    Args:
        binary_path: Path to the Go ELF binary (can be original or already patched).
        output_json: Optional path to save the full GoReSym JSON output.

    Returns:
        Sorted function table with addresses, or error with remediation hint.
    """
    binary_path = _convert_to_linux_path(binary_path)
    if not os.path.exists(binary_path):
        return f"Error: binary not found: {binary_path}"

    out = [f"## Go Binary Recovery: {os.path.basename(binary_path)}"]

    # ── Step 1: Locate .gopclntab offset via readelf ──────────────────────────
    gopclntab_offset = None
    try:
        re_res = subprocess.run(
            ["readelf", "-S", binary_path],
            capture_output=True, text=True, timeout=30
        )
        for line in re_res.stdout.splitlines():
            if ".gopclntab" in line:
                # Format: [Nr] Name Type Addr Off Size ...
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == ".gopclntab" or (i > 0 and parts[i-1] == ".gopclntab"):
                        # Offset is 5th column (0-indexed)
                        try:
                            # readelf column layout: idx name type addr off size ...
                            # Find the 'Off' value (5th non-bracket field)
                            fields = [f for f in parts if f not in ("[", "]") and not f.startswith("[")]
                            # fields: name type addr off size ...
                            gopclntab_offset = int(fields[3], 16)  # 'off' column
                        except Exception:
                            pass
                        break
    except Exception as e:
        out.append(f"⚠ readelf failed: {e}")

    # ── Step 2: Check/patch magic bytes ──────────────────────────────────────
    work_binary = binary_path  # default: use original
    GO_MAGIC_120 = b"\xf1\xff\xff\xff"   # Go 1.20+
    GO_MAGIC_116 = b"\xfa\xff\xff\xff"   # Go 1.16-1.19
    GO_MAGIC_112 = b"\xfb\xff\xff\xff"   # Go 1.12-1.15

    if gopclntab_offset is not None:
        try:
            with open(binary_path, "rb") as f:
                f.seek(gopclntab_offset)
                current_magic = f.read(4)

            out.append(f"  .gopclntab offset : 0x{gopclntab_offset:x}")
            out.append(f"  Current magic     : {current_magic.hex(' ')}")

            valid_magics = {GO_MAGIC_120, GO_MAGIC_116, GO_MAGIC_112}
            if current_magic not in valid_magics:
                # Magic is corrupted — patch a copy
                patched_path = f"/tmp/{os.path.basename(binary_path)}.patched"
                import shutil as _sh
                _sh.copy2(binary_path, patched_path)
                with open(patched_path, "r+b") as f:
                    f.seek(gopclntab_offset)
                    f.write(GO_MAGIC_120)
                work_binary = patched_path
                out.append(f"  ⚠ Magic corrupted — patched copy: {patched_path}")
                out.append(f"  Restored magic    : {GO_MAGIC_120.hex(' ')}")
            else:
                out.append(f"  ✅ Magic is valid ({current_magic.hex(' ')})")
        except Exception as e:
            out.append(f"  ⚠ Magic check/patch failed: {e}")
    else:
        out.append("  ⚠ .gopclntab section not found in readelf output — binary may be very stripped")
        out.append("    GoReSym will attempt raw scan mode")

    # ── Step 3: Locate or install GoReSym ────────────────────────────────────
    gobin = "/tmp/gobin"
    goresym_bin = os.path.join(gobin, "GoReSym")

    if not os.path.exists(goresym_bin):
        out.append("\n  GoReSym not found — attempting install via 'go install'...")
        go_bin = shutil.which("go")
        if not go_bin:
            out.append("  ❌ 'go' not found in PATH.")
            out.append("  Manual install: GOBIN=/tmp/gobin go install github.com/mandiant/GoReSym@latest")
            out.append("  Alternative: Download from https://github.com/mandiant/GoReSym/releases")
            return "\n".join(out)

        env = os.environ.copy()
        env["GOBIN"] = gobin
        os.makedirs(gobin, exist_ok=True)
        install_res = subprocess.run(
            [go_bin, "install", "github.com/mandiant/GoReSym@latest"],
            capture_output=True, text=True, timeout=120, env=env
        )
        if not os.path.exists(goresym_bin):
            out.append(f"  ❌ GoReSym install failed: {install_res.stderr[:400]}")
            out.append("  Manual: GOBIN=/tmp/gobin go install github.com/mandiant/GoReSym@latest")
            return "\n".join(out)
        out.append(f"  ✅ GoReSym installed: {goresym_bin}")

    # ── Step 4: Run GoReSym ───────────────────────────────────────────────────
    out.append(f"\n  Running GoReSym on: {work_binary}")
    try:
        gr_res = subprocess.run(
            [goresym_bin, "-d", work_binary],
            capture_output=True, text=True, timeout=120
        )
        json_text = gr_res.stdout.strip()

        if not json_text:
            out.append(f"  ❌ GoReSym produced no output. stderr: {gr_res.stderr[:300]}")
            return "\n".join(out)

        # Save raw JSON if requested
        if output_json:
            with open(output_json, "w") as f:
                f.write(json_text)
            out.append(f"  Raw JSON saved: {output_json}")

        # Parse and present function table
        try:
            data = json.loads(json_text)
            funcs = data.get("Functions", [])
            out.append(f"\n### Recovered Functions ({len(funcs)} total)")
            out.append(f"{'Start VA':<18} {'End VA':<18} Name")
            out.append("-" * 70)

            # Sort by start VA
            funcs_sorted = sorted(
                funcs,
                key=lambda f: int(f.get("Start", "0x0"), 16) if isinstance(f.get("Start"), str) else f.get("Start", 0)
            )
            for fn in funcs_sorted[:100]:
                name = fn.get("FullName", fn.get("Name", "?"))
                start = fn.get("Start", "?")
                end   = fn.get("End", "?")
                # Normalise to hex strings
                if isinstance(start, int):
                    start = hex(start)
                if isinstance(end, int):
                    end = hex(end)
                out.append(f"  {start:<16} {end:<16} {name}")

            if len(funcs) > 100:
                out.append(f"  ... [{len(funcs) - 100} more functions]")

            # Highlight main.* functions
            main_funcs = [fn for fn in funcs_sorted if fn.get("FullName", "").startswith("main.")]
            if main_funcs:
                out.append("\n### main.* functions (key targets)")
                for fn in main_funcs[:30]:
                    name = fn.get("FullName", fn.get("Name", "?"))
                    start = fn.get("Start", "?")
                    end   = fn.get("End", "?")
                    if isinstance(start, int): start = hex(start)
                    if isinstance(end, int):   end   = hex(end)
                    out.append(f"  {start:<16} {end:<16} {name}")

            # GoReSym VA adjustment hint
            out.append("\n### Notes")
            out.append("  GoReSym VAs may need an offset adjustment.")
            out.append("  Find actual text section base: readelf -S binary | grep '\\.text'")
            out.append("  Verify with: objdump -d binary | grep -m1 '^[0-9a-f]\\+ <'")
            out.append("  If needed, apply: actual_VA = goresym_VA + adjustment")

        except json.JSONDecodeError:
            out.append("  ⚠ Could not parse GoReSym JSON. Raw output (first 3000 chars):")
            out.append(json_text[:3000])

    except subprocess.TimeoutExpired:
        out.append("  ❌ GoReSym timed out after 120s (very large binary?)")
        out.append("  Try running manually: /tmp/gobin/GoReSym -d binary > /tmp/goresym.json")
    except Exception as e:
        out.append(f"  ❌ GoReSym error: {e}")

    return "\n".join(out)
