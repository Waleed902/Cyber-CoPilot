"""
CTF Analysis Tools — Binary, Forensics, Crypto, RE, Web

Tools:
  ctf_identify        — auto-detect challenge category from files/structure
  binary_triage       — file/strings/checksec/readelf in one shot
  strings_extract_ctf — enhanced strings with CTF pattern highlighting
  forensics_carve     — binwalk/foremost + magic byte scan
  stego_check         — exiftool, zsteg, steghide, LSB, appended-data detection
  crypto_identify     — detect encoding/cipher, attempt auto-decode
  decompile_func      — radare2/objdump/nm disassembly
  pcap_analyze        — tshark protocol summary + credential extraction
  elf_security        — PIE, NX, canary, RELRO, FORTIFY
  ctf_web_triage      — JWT/cookie decode, SSTI/LFI/SQLi canary patterns
"""

from __future__ import annotations

import base64
import collections
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from src.sdk.tool import function_tool


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 60, stdin_data: str = "") -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=stdin_data or None,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def _magic_type(path: Path) -> str:
    """Identify file type from magic bytes (first 16 bytes)."""
    _MAGIC: list[tuple[bytes, int, str]] = [
        (b"\x7fELF", 0, "ELF binary"),
        (b"MZ", 0, "PE/Windows executable"),
        (b"PK\x03\x04", 0, "ZIP archive"),
        (b"PK\x05\x06", 0, "ZIP (empty)"),
        (b"\x1f\x8b", 0, "gzip compressed"),
        (b"BZh", 0, "bzip2 compressed"),
        (b"\xfd7zXZ\x00", 0, "XZ compressed"),
        (b"Rar!\x1a\x07", 0, "RAR archive"),
        (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
        (b"\xff\xd8\xff", 0, "JPEG image"),
        (b"GIF87a", 0, "GIF image"),
        (b"GIF89a", 0, "GIF image"),
        (b"BM", 0, "BMP image"),
        (b"RIFF", 0, "RIFF (WAV/AVI)"),
        (b"OggS", 0, "OGG media"),
        (b"%PDF", 0, "PDF document"),
        (b"\xca\xfe\xba\xbe", 0, "Java class / Mach-O fat"),
        (b"\xce\xfa\xed\xfe", 0, "Mach-O 32-bit"),
        (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit"),
        (b"SQLite format", 0, "SQLite database"),
        (b"-----BEGIN", 0, "PEM certificate/key"),
        (b"\x1aE\xdf\xa3", 0, "Matroska/WebM"),
        (b"ftyp", 4, "MP4/MOV video"),
        (b"IHDR", 12, "PNG (IHDR chunk)"),
    ]
    try:
        raw = path.read_bytes()[:32]
        for magic, offset, label in _MAGIC:
            if raw[offset : offset + len(magic)] == magic:
                return label
        # Heuristic: mostly printable → text
        printable = sum(1 for b in raw[:64] if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        if printable > len(raw[:64]) * 0.85:
            return "text file"
        return "unknown binary"
    except Exception:
        return "unreadable"


_CTF_PATTERNS = [
    (r"[A-Z]{2,8}\{[^\}]{4,60}\}", "FLAG pattern"),
    (r"flag\{[^\}]+\}", "flag{} pattern"),
    (r"/bin/sh|/bin/bash", "Shell string"),
    (r"system\(|execve\(|popen\(", "Exec sink"),
    (r"password|passwd|secret|token|key", "Credential keyword"),
    (r"admin|root|sudo", "Privilege keyword"),
    (r"GET /|POST /|HTTP/1\.", "HTTP traffic"),
    (r"SELECT |UNION |INSERT |UPDATE ", "SQL keyword"),
    (r"0x[0-9a-fA-F]{8,}", "Large hex constant"),
    (r"[A-Za-z0-9+/]{32,}={0,2}$", "Potential base64"),
    (r"-----BEGIN", "PEM header"),
    (r"ssh-rsa|ecdsa-sha2", "SSH key material"),
]


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1 — ctf_identify
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def ctf_identify(path: str) -> str:
    """
    Auto-detect CTF challenge category and suggest initial attack approach.

    Examines files, directory structure, README content, and binary headers to
    classify: RE, PWN, Web, Forensics, Crypto, Stego, Misc.

    Args:
        path: Challenge file or directory
    """
    root = Path(path)
    if not root.exists():
        return f"Error: path not found: {path}"

    _SKIP_DIRS = {"node_modules", "vendor", "__pycache__", ".git", "venv", ".venv", "dist", "build"}
    if root.is_dir():
        files = [
            f for f in root.rglob("*")
            if f.is_file() and not any(p in _SKIP_DIRS for p in f.parts)
        ]
    else:
        files = [root]

    # Categorise each file
    cats: dict[str, list[str]] = collections.defaultdict(list)
    ext_map: dict[str, str] = {
        ".pcap": "forensics", ".pcapng": "forensics",
        ".vmdk": "forensics", ".img": "forensics", ".iso": "forensics",
        ".mem": "forensics", ".raw": "forensics", ".dd": "forensics",
        ".apk": "re", ".jar": "re", ".class": "re",
        ".wasm": "re",
        ".pck": "re",   # Godot
        ".so": "re",
        ".pyc": "re",
        # Web source files
        ".php": "web", ".aspx": "web", ".html": "web", ".htm": "web",
        ".js": "web", ".mjs": "web", ".cjs": "web",
        ".ts": "web", ".tsx": "web", ".jsx": "web",
        ".rb": "web", ".erb": "web",   # Rails
        ".go": "web",                  # Go web apps
        # Stego
        ".wav": "stego", ".mp3": "stego", ".bmp": "stego",
        ".png": "stego", ".jpg": "stego", ".jpeg": "stego",
        ".gif": "stego",
    }
    # Filename-based web signals (Dockerfile, nginx.conf, etc.)
    _WEB_FILENAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml",
                      "nginx.conf", "apache.conf", "supervisord.conf",
                      "package.json", "requirements.txt", "composer.json",
                      "app.py", "wsgi.py", "manage.py", "server.js", "index.js"}

    readme_text = ""
    for f in files:
        name_lower = f.name.lower()
        if name_lower in ("readme.md", "readme.txt", "challenge.txt", "description.txt", "task.txt"):
            try:
                readme_text = f.read_text(errors="ignore")[:2000]
            except Exception:
                pass

        # Filename-based web signal
        if f.name.lower() in _WEB_FILENAMES:
            cats["web"].append(f.name)
            continue

        # Extension-based
        ext = f.suffix.lower()
        if ext in ext_map:
            cats[ext_map[ext]].append(f.name)
            continue

        # Magic-byte based
        mtype = _magic_type(f)
        if "ELF" in mtype:
            cats["pwn/re"].append(f.name)
        elif "PE/Windows" in mtype:
            # Check if it's a .NET/CLR binary
            try:
                raw_pe = f.read_bytes()
                if b"mscoree.dll" in raw_pe or b"mscorlib" in raw_pe or b"_CorExeMain" in raw_pe:
                    cats["re"].append(f"{f.name} (.NET/CLR)")
                else:
                    cats["re"].append(f.name)
            except Exception:
                cats["re"].append(f.name)
        elif "Mach-O" in mtype:
            cats["re"].append(f.name)
        elif "Java class" in mtype:
            cats["re"].append(f.name)
        elif "ZIP" in mtype or "gzip" in mtype or "bzip2" in mtype or "XZ" in mtype or "RAR" in mtype:
            cats["forensics"].append(f.name)
        elif any(x in mtype for x in ("PNG", "JPEG", "GIF", "BMP")):
            cats["stego"].append(f.name)
        elif "PCAP" in mtype or "Libpcap" in mtype:
            cats["forensics"].append(f.name)
        elif "SQLite" in mtype:
            cats["forensics"].append(f.name)
        elif "text file" in mtype:
            try:
                snippet = f.read_text(errors="ignore")[:500]
                if re.search(r"[A-Za-z0-9+/]{20,}={0,2}", snippet):
                    cats["crypto"].append(f.name)
                elif re.search(r"[0-9a-fA-F\s]{40,}", snippet):
                    cats["crypto"].append(f.name)
                elif any(c in name_lower for c in ("docker", "flask", "django", "express", "nginx")):
                    cats["web"].append(f.name)
                else:
                    cats["misc"].append(f.name)
            except Exception:
                pass

    # Keyword scan of README
    readme_lower = readme_text.lower()
    if any(w in readme_lower for w in ("buffer overflow", "rop", "shellcode", "libc", "heap", "stack")):
        cats["pwn"].append("(README hints)")
    if any(w in readme_lower for w in ("reverse", "decompile", "disassemble", "obfuscat")):
        cats["re"].append("(README hints)")
    if any(w in readme_lower for w in ("sql", "xss", "lfi", "rce", "injection", "flask", "django")):
        cats["web"].append("(README hints)")
    if any(w in readme_lower for w in ("encrypt", "cipher", "rsa", "aes", "xor", "base64")):
        cats["crypto"].append("(README hints)")
    if any(w in readme_lower for w in ("pcap", "memory", "forensic", "artifact", "dump")):
        cats["forensics"].append("(README hints)")
    if any(w in readme_lower for w in ("hidden", "stegano", "lsb", "image", "audio")):
        cats["stego"].append("(README hints)")

    # Build output
    out = [f"## CTF Challenge Identification: {root.name}", f"Files scanned: {len(files)}", ""]

    if readme_text:
        out.append(f"### README snippet\n```\n{readme_text[:400]}\n```\n")

    if not cats:
        out.append("No category signals found — likely Misc or unknown format.")
        out.append("\n### Suggested first steps")
        out.append("  1. `binary_triage(path)` — run on the main file")
        out.append("  2. `strings_extract_ctf(path)` — hunt for flag/credential strings")
        return "\n".join(out)

    out.append("### Detected Categories")
    for cat, items in sorted(cats.items(), key=lambda x: -len(x[1])):
        out.append(f"  **{cat.upper()}**: {', '.join(items[:5])}{'...' if len(items) > 5 else ''}")

    # Primary category = most signals
    primary = max(cats, key=lambda c: len(cats[c]))

    playbooks = {
        "pwn/re": [
            "1. `elf_security(binary)` — check PIE/NX/canary/RELRO",
            "2. `binary_triage(binary)` — full triage",
            "3. `decompile_func(binary, 'main')` — r2/objdump decompile",
            "4. `strings_extract_ctf(binary)` — hunt constants/flags",
            "5. `ctf_command('gdb -q binary')` via interactive_bash for dynamic analysis",
        ],
        "pwn": [
            "1. `elf_security(binary)` — NO-PIE + no-canary = classic BOF",
            "2. `decompile_func(binary, 'main')` — find gets/strcpy/read",
            "3. `ctf_command('ROPgadget --binary binary')` — build ROP chain",
            "4. `generate_rop_chain(binary)` — automated chain",
        ],
        "re": [
            "1. `binary_triage(path)` — file format + architecture",
            "2. `strings_extract_ctf(path)` — find flag patterns and keys",
            "3. `decompile_func(path, 'main')` — static disassembly",
            "4. For .apk/.jar: `java_decompile(path)`",
            "5. For .wasm: `wasm_analyze(path)`",
            "6. For .pyc: `ctf_command('uncompyle6 file.pyc')`",
        ],
        "forensics": [
            "1. `forensics_carve(path)` — extract embedded files",
            "2. `pcap_analyze(path)` — if PCAP, extract HTTP/creds",
            "3. `binary_triage(path)` — check file type",
            "4. `ctf_command('volatility3 -f dump.mem windows.pslist')` — if memory dump",
            "5. `ctf_command('autopsy')` — if disk image",
        ],
        "stego": [
            "1. `stego_check(image)` — all-in-one: exiftool + zsteg + steghide",
            "2. `strings_extract_ctf(image)` — appended text/flag",
            "3. `forensics_carve(image)` — embedded files in image",
            "4. `ctf_command('stegsolve image.png')` — visual steg analysis",
            "5. `ctf_command('pngcheck -v image.png')` — PNG chunk analysis",
        ],
        "crypto": [
            "1. `crypto_identify(ciphertext)` — auto-detect encoding/cipher",
            "2. `hash_identifier(hash)` — if it's a hash, identify and crack",
            "3. Check for RSA: small e, common modulus, repeated nonce",
            "4. Check for XOR: frequency analysis, crib dragging",
            "5. `ctf_command('python3 solver.py')` via ctf_command",
        ],
        "web": [
            "1. `repo_map(path)` + `ast_symbol_search(path)` — map routes/sinks",
            "2. `pattern_search(path, 'eval|exec|render_template_string|system|os.popen')` — sinks",
            "3. `ctf_web_triage(url)` — JWT/cookie decode + canary probes",
            "4. `static_code_analysis(path)` — full vuln scan",
            "5. `semgrep_scan(path)` — deep static analysis",
        ],
    }

    playbook = playbooks.get(primary, playbooks.get("re", []))
    out.append(f"\n### Primary Category: **{primary.upper()}**")
    out.append("\n### Recommended Attack Plan")
    for step in playbook:
        out.append(f"  {step}")

    if readme_text:
        out.append("\n### README Keywords Found")
        kws = re.findall(r"\b(flag|key|password|secret|token|cipher|encrypt|overflow|shell|inject)\b",
                         readme_lower)
        if kws:
            out.append(f"  {', '.join(set(kws))}")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2 — binary_triage
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def binary_triage(path: str) -> str:
    """
    One-shot binary analysis: magic type, file(1), readelf headers, architecture,
    linked libraries, entry point. Run this first on any unknown file.

    Falls back to manual magic + struct parsing if external tools are missing.

    Args:
        path: File to analyze
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    out = [f"## Binary Triage: {p.name}", f"Size: {p.stat().st_size:,} bytes"]

    # --- Magic bytes ---
    mtype = _magic_type(p)
    out.append(f"Magic type : {mtype}")

    # --- file(1) ---
    rc, fout, _ = _run(["file", path])
    if rc == 0 and fout.strip():
        out.append(f"file(1)    : {fout.strip().split(':', 1)[-1].strip()}")

    # --- ELF-specific ---
    is_elf = mtype.startswith("ELF") or (rc == 0 and "ELF" in fout)
    if is_elf:
        # readelf -h
        rc2, rout, _ = _run(["readelf", "-h", path])
        if rc2 == 0:
            for key in ("Class", "Data", "Type", "Machine", "Entry point address"):
                m = re.search(rf"{key}:\s+(.+)", rout)
                if m:
                    out.append(f"  {key:<28}: {m.group(1).strip()}")

        # linked libraries
        rc3, lout, _ = _run(["readelf", "-d", path])
        if rc3 == 0:
            libs = re.findall(r"\(NEEDED\).*?\[(.+?)\]", lout)
            if libs:
                out.append(f"  Linked libs: {', '.join(libs)}")

        # nm symbols (interesting ones only)
        rc4, nout, _ = _run(["nm", "-D", "--defined-only", path], timeout=15)
        interesting_syms = []
        for sym in ("system", "execve", "gets", "strcpy", "strcat", "scanf",
                    "malloc", "free", "printf", "puts", "open", "read", "write"):
            if sym in (nout or ""):
                interesting_syms.append(sym)
        if interesting_syms:
            out.append(f"  Interesting syms: {', '.join(interesting_syms)}")

    # --- PE-specific ---
    is_pe = mtype.startswith("PE") or (rc == 0 and "PE32" in fout)
    if is_pe:
        rc5, pout, _ = _run(["objdump", "-f", path])
        if rc5 == 0:
            for line in pout.splitlines()[:5]:
                if line.strip():
                    out.append(f"  {line.strip()}")

    # --- checksec ---
    rc6, cout, _ = _run(["checksec", "--file=" + path, "--output=json"], timeout=15)
    if rc6 == 0 and cout.strip():
        try:
            data = json.loads(cout)
            props = list(data.values())[0] if data else {}
            flags = []
            for k in ("relro", "canary", "nx", "pie", "fortify_source", "rpath", "runpath"):
                v = props.get(k, "")
                if v:
                    flags.append(f"{k}={v}")
            if flags:
                out.append(f"  checksec: {', '.join(flags)}")
        except Exception:
            out.append(f"  checksec raw: {cout.strip()[:200]}")
    else:
        # fallback: python-checksec style via objdump
        rc7, oout, _ = _run(["objdump", "-p", path], timeout=10)
        if rc7 == 0:
            has_nx  = "STACK" in oout and "X" not in oout
            has_pie = "DYN" in fout if rc == 0 else False
            out.append(f"  NX(approx)={'yes' if has_nx else 'no'}  PIE={'yes' if has_pie else 'no'}")

    # --- strings preview (top CTF hits) ---
    rc8, sout, _ = _run(["strings", "-n", "8", path], timeout=20)
    if rc8 == 0 and sout:
        hits = []
        for pat, label in _CTF_PATTERNS:
            for line in sout.splitlines():
                if re.search(pat, line, re.IGNORECASE):
                    hits.append(f"  [{label}] {line.strip()[:100]}")
                    if len(hits) >= 10:
                        break
            if len(hits) >= 10:
                break
        if hits:
            out.append("\nNotable strings:")
            out.extend(hits)

    # --- Entropy (packer/encryption detection) ---
    try:
        import math as _math
        raw_data = p.read_bytes()
        if len(raw_data) > 0:
            sample = raw_data[:min(65536, len(raw_data))]
            freq_e = collections.Counter(sample)
            total_e = len(sample)
            entropy = -sum((c/total_e) * _math.log2(c/total_e) for c in freq_e.values() if c > 0)
            entropy_label = (
                "🔴 HIGH (packed/encrypted — try upx_unpack or binwalk_extract)" if entropy > 7.2
                else "🟡 MEDIUM (possibly compressed sections)" if entropy > 6.0
                else "🟢 NORMAL (typical compiled binary)"
            )
            out.append(f"\n  Entropy   : {entropy:.2f} bits/byte  {entropy_label}")
            # UPX detection
            if b"UPX!" in raw_data[:1024] or b"UPX0" in raw_data[:512]:
                out.append("  Packer    : ⚠ UPX detected — run upx_unpack(path) first")
            # High-entropy sections may indicate custom packers
            elif entropy > 7.5:
                out.append("  Packer    : ⚠ Very high entropy — likely custom packer or encryption")
    except Exception as _ee:
        pass  # non-critical

    # --- Binary fingerprinting (.NET / Rust / Go / PyInstaller) ---
    try:
        fp_data = raw_data if 'raw_data' in dir() else p.read_bytes()
        fingerprints = []
        if b"mscoree.dll" in fp_data or b"_CorExeMain" in fp_data or b"mscorlib" in fp_data:
            fingerprints.append(".NET/CLR binary — decompile: ctf_command('ilspycmd binary.exe') or use dotnet-decompiler")
        if b"rustc" in fp_data[:8192] or b"rust_begin_unwind" in fp_data or b"__rust_" in fp_data:
            fingerprints.append("Rust binary — symbols may be stripped; try: nm binary | rustfilt")
        if b"runtime.main" in fp_data or b"go.buildid" in fp_data[:4096] or b"\x00Go build" in fp_data:
            fingerprints.append("Go binary — use: strings binary | grep -E '^main\\.' for exported func names")
        if b"PyInstaller" in fp_data[:32768] or b"pyi-" in fp_data[:32768]:
            fingerprints.append("PyInstaller bundle — extract: python3 pyinstxtractor.py binary")
        if b"__nuitka" in fp_data[:8192] or b"Nuitka" in fp_data[:8192]:
            fingerprints.append("Nuitka-compiled Python")
        if fingerprints:
            out.append("\nBinary fingerprints:")
            for fp in fingerprints:
                out.append(f"  🏷 {fp}")
    except Exception:
        pass

    out.append(f"\n[Next] elf_security({path!r}) for full mitigation flags, decompile_func({path!r}) for disassembly")
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3 — strings_extract_ctf
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def strings_extract_ctf(path: str, min_len: int = 6) -> str:
    """
    Enhanced strings extraction with CTF pattern highlighting.

    Runs strings(1) and categorises output into flag patterns, credentials,
    shell/exec sinks, URLs/IPs, crypto material, SQL and format strings.
    Hard-capped at 50 000 lines to stay fast on large binaries.

    Args:
        path: Binary or text file to scan
        min_len: Minimum string length (default 6)
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    _MAX_LINES = 50_000   # never process more than this many lines
    _TIMEOUT   = 20       # seconds per strings invocation

    # ── Run strings (ASCII) ──────────────────────────────────────────────────
    rc, raw, _ = _run(["strings", f"-n{min_len}", str(p)], timeout=_TIMEOUT)
    if rc == -2:          # strings not installed — read as text
        try:
            raw = p.read_text(errors="ignore")
        except Exception as e:
            return f"Error: strings not found and file unreadable: {e}"

    # ── Run strings wide-char (UTF-16LE) — only if binary is small enough ───
    file_size = p.stat().st_size
    raw_w = ""
    wide_count = 0
    if file_size < 20 * 1024 * 1024:   # skip wide pass on files >20 MB
        rc_w, raw_w, _ = _run(
            ["strings", "-e", "l", f"-n{min_len}", str(p)], timeout=_TIMEOUT
        )
        if rc_w == 0 and raw_w.strip():
            wide_count = raw_w.count("\n")

    # ── Merge and cap lines BEFORE any regex work ────────────────────────────
    combined = (raw or "") + ("\n" + raw_w if raw_w else "")
    all_lines = combined.splitlines()
    total     = len(all_lines)
    truncated = total > _MAX_LINES
    lines     = all_lines[:_MAX_LINES]   # hard cap — regex only sees this

    # ── Pre-compile patterns once (not per-line) ─────────────────────────────
    _BUCKETS = [
        ("🚩 Flag patterns",
         re.compile(r"[A-Z]{2,8}\{[^\}]{4,60}\}|flag\{[^\}]+\}", re.I)),
        ("🔑 Credentials",
         re.compile(r"(?i)(password|passwd|secret|api.?key|token|auth)\s*[=:]\s*\S+")),
        ("💀 Exec/Shell sinks",
         re.compile(r"(?i)(/bin/sh|/bin/bash|system\(|execve|popen|os\.system|subprocess)")),
        ("🌐 URLs / IPs",
         re.compile(r"https?://\S+|ftp://\S+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
        ("🔐 Crypto / Keys",
         re.compile(r"-----BEGIN|ssh-rsa|ecdsa-sha2|[A-Za-z0-9+/]{40,}={0,2}$|0x[0-9a-fA-F]{16,}")),
        ("🗄️ SQL",
         re.compile(r"(?i)(SELECT|UNION|INSERT|UPDATE|DROP|CREATE)\s")),
        ("📌 Format strings",
         re.compile(r"%[0-9]*[sdxpn]")),
        ("🏷️ Version / build info",
         re.compile(r"(?i)(version|build|compile|copyright|author)")),
    ]
    _MAX_PER_BUCKET = 25   # stop collecting for a bucket once full

    buckets: dict[str, list[str]] = {label: [] for label, _ in _BUCKETS}

    # ── Single pass over lines ───────────────────────────────────────────────
    # Build a set of labels that are already full to skip their regex
    full_buckets: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        for label, pat in _BUCKETS:
            if label in full_buckets:
                continue
            if pat.search(stripped):
                buckets[label].append(stripped[:120])
                if len(buckets[label]) >= _MAX_PER_BUCKET:
                    full_buckets.add(label)
                break  # each line goes in at most one bucket

        # Once all buckets are full we can stop scanning
        if len(full_buckets) == len(_BUCKETS):
            break

    # ── Build output ─────────────────────────────────────────────────────────
    wide_suffix = f" + {wide_count} wide-char UTF-16LE" if wide_count else ""
    trunc_note  = f" ⚠ TRUNCATED to {_MAX_LINES:,} lines for speed" if truncated else ""
    out = [
        f"## CTF Strings: {p.name}",
        f"Total strings (len≥{min_len}): {total:,}{wide_suffix}{trunc_note}",
        f"File size: {file_size:,} bytes",
    ]

    for label, _ in _BUCKETS:
        hits = buckets.get(label, [])
        if not hits:
            continue
        out.append(f"\n### {label} ({len(hits)} hits)")
        for item in hits:
            out.append(f"  {item}")

    categorised   = sum(len(v) for v in buckets.values())
    uncategorised = min(total, _MAX_LINES) - categorised
    out.append(f"\n({uncategorised:,} strings uncategorised in scanned window)")
    if truncated:
        out.append(
            f"⚠ Only first {_MAX_LINES:,} of {total:,} strings scanned. "
            "Use ctf_command(\"strings binary | grep -i flag\") for targeted search."
        )

    return "\n".join(out)




# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4 — forensics_carve
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def forensics_carve(path: str, output_dir: str = "") -> str:
    """
    Extract embedded/appended files from a binary using binwalk and foremost.
    Also performs manual magic-byte scan to detect nested formats.

    Useful for: steghide payloads, hidden ZIPs in images, firmware extraction,
    appended data after ELF/PE EOF markers.

    Args:
        path: File to carve
        output_dir: Extraction directory (default: auto temp dir)
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    if not output_dir:
        output_dir = str(Path(tempfile.gettempdir()) / f"carve_{p.stem[:20]}")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    out = [f"## Forensics Carve: {p.name}", f"Output dir: {output_dir}"]

    # --- Manual magic scan ---
    _SIGS = [
        (b"\x7fELF", "ELF"),
        (b"PK\x03\x04", "ZIP"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF8", "GIF"),
        (b"-----BEGIN", "PEM"),
        (b"MZ", "PE"),
        (b"\xca\xfe\xba\xbe", "Java class"),
    ]
    try:
        raw = p.read_bytes()
        found_offsets = []
        for sig, label in _SIGS:
            start = 0
            while True:
                pos = raw.find(sig, start)
                if pos == -1:
                    break
                found_offsets.append((pos, label))
                start = pos + 1
        found_offsets.sort()
        if found_offsets:
            out.append(f"\n### Magic-byte signatures found ({len(found_offsets)})")
            for offset, label in found_offsets[:20]:
                out.append(f"  offset 0x{offset:08x} ({offset:,}) — {label}")
            if len(found_offsets) > 20:
                out.append(f"  ... +{len(found_offsets)-20} more")
        else:
            out.append("\nNo secondary magic signatures detected in file body.")
    except Exception as e:
        out.append(f"Manual scan error: {e}")

    # --- binwalk ---
    if shutil.which("binwalk"):
        out.append("\n### binwalk scan")
        rc, bwout, bwerr = _run(["binwalk", path], timeout=60)
        if rc == 0 and bwout.strip():
            lines = [l for l in bwout.splitlines() if l.strip() and not l.startswith("DECIMAL")]
            out.append("\n".join(lines[:40]))
        else:
            out.append(f"binwalk: {bwerr[:200] or 'no findings'}")

        out.append("\n### binwalk extract (-eM)")
        rc2, _, bwerr2 = _run(["binwalk", "-eM", "--directory", output_dir, path], timeout=120)
        extracted = list(Path(output_dir).rglob("*"))
        extracted_files = [f for f in extracted if f.is_file()]
        if extracted_files:
            out.append(f"Extracted {len(extracted_files)} file(s):")
            for f in extracted_files[:20]:
                out.append(f"  {f}  ({f.stat().st_size} bytes, {_magic_type(f)})")
        else:
            out.append(f"Nothing extracted ({bwerr2[:100] if bwerr2 else 'binwalk found nothing to extract'})")
    else:
        out.append("\n⚠ binwalk not installed — install: pip install binwalk OR apt install binwalk")

    # --- foremost ---
    if shutil.which("foremost"):
        fm_out = str(Path(output_dir) / "foremost")
        out.append("\n### foremost carve")
        rc3, _, fmerr = _run(["foremost", "-i", path, "-o", fm_out, "-T"], timeout=120)
        audit = Path(fm_out) / "audit.txt"
        if audit.exists():
            audit_text = audit.read_text(errors="ignore")
            m = re.search(r"(\d+) FILES EXTRACTED", audit_text)
            if m:
                out.append(f"foremost: {m.group(1)} files extracted → {fm_out}")
            else:
                out.append(f"foremost: {audit_text[-300:]}")
        else:
            out.append(f"foremost: no audit.txt ({fmerr[:100] if fmerr else 'check output dir'})")
    else:
        out.append("\n⚠ foremost not installed — apt install foremost")

    out.append(f"\n[Next] Inspect extracted files in: {output_dir}")
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 5 — stego_check
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def stego_check(path: str, password: str = "") -> str:
    """
    All-in-one steganography analysis:
      - exiftool metadata (embedded comments, GPS, creator)
      - zsteg LSB analysis (PNG/BMP)
      - steghide probe (JPEG/WAV)
      - strings for appended text
      - file size vs content analysis (appended data after EOF marker)
      - pngcheck for corrupt/extra chunks

    Args:
        path: Image or audio file
        password: Optional passphrase for steghide
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    out = [f"## Stego Check: {p.name}", f"Size: {p.stat().st_size:,} bytes", f"Type: {_magic_type(p)}"]

    # --- exiftool ---
    rc, emeta, _ = _run(["exiftool", path], timeout=30)
    if rc == 0 and emeta.strip():
        out.append("\n### exiftool metadata")
        interesting_fields = [
            "Comment", "Artist", "Author", "Creator", "Description",
            "UserComment", "XPComment", "Software", "Make", "Model",
            "GPS", "Warning", "Error", "Thumbnail"
        ]
        lines = emeta.splitlines()
        interesting = [l for l in lines if any(f in l for f in interesting_fields)]
        if interesting:
            out.extend(interesting[:20])
        else:
            # Show first 15 fields anyway
            out.extend(lines[:15])
    else:
        out.append("\n⚠ exiftool not installed / failed — apt install libimage-exiftool-perl")

    # --- zsteg (PNG/BMP) ---
    ext = p.suffix.lower()
    if ext in (".png", ".bmp"):
        if shutil.which("zsteg"):
            out.append("\n### zsteg LSB analysis")
            rc2, zout, zerr = _run(["zsteg", path], timeout=60)
            if rc2 == 0 and zout.strip():
                # Highlight interesting hits
                z_lines = zout.splitlines()
                flaglines = [l for l in z_lines if re.search(r"[A-Z]{2,8}\{|flag\{|\btext\b", l, re.I)]
                out.extend((flaglines or z_lines)[:30])
            else:
                out.append(f"zsteg: {zerr[:200] or 'no findings'}")
        else:
            out.append("\n⚠ zsteg not installed — gem install zsteg")

    # --- steghide (JPEG / WAV) ---
    if ext in (".jpg", ".jpeg", ".wav", ".bmp", ".au"):
        if shutil.which("steghide"):
            out.append("\n### steghide probe")
            pw_args = ["-p", password] if password else ["-p", ""]
            rc3, shout, sherr = _run(["steghide", "info", path] + pw_args, timeout=30)
            if rc3 == 0 and shout.strip():
                out.append(shout.strip())
            else:
                out.append(f"steghide (no password): {sherr[:200] or 'no embedded data detected'}")
        else:
            out.append("\n⚠ steghide not installed — apt install steghide")

    # --- Appended data after EOF ---
    out.append("\n### Appended data check")
    try:
        raw = p.read_bytes()
        trailer_pos = None
        if ext in (".jpg", ".jpeg") and b"\xff\xd9" in raw:
            trailer_pos = raw.rfind(b"\xff\xd9") + 2
        elif ext == ".png":
            iend = raw.rfind(b"IEND")
            if iend != -1:
                trailer_pos = iend + 8
        elif ext == ".gif":
            trailer_pos = raw.rfind(b"\x3b") + 1

        if trailer_pos is not None and trailer_pos < len(raw):
            tail = raw[trailer_pos:]
            out.append(f"  ⚠ {len(tail)} bytes AFTER EOF marker!")
            # Try to decode as text
            try:
                text = tail.decode("utf-8", errors="ignore").strip()
                if text:
                    out.append(f"  Tail text: {text[:200]}")
                else:
                    out.append(f"  Tail (hex): {tail[:32].hex()}")
            except Exception:
                out.append(f"  Tail (hex): {tail[:32].hex()}")
        else:
            out.append("  No data after EOF marker")
    except Exception as e:
        out.append(f"  Appended-data check failed: {e}")

    # --- pngcheck ---
    if ext == ".png" and shutil.which("pngcheck"):
        out.append("\n### pngcheck")
        rc4, pcout, _ = _run(["pngcheck", "-v", path], timeout=15)
        out.append(pcout.strip()[:400] if pcout else "pngcheck: no output")

    # --- Quick strings for flags ---
    out.append("\n### Strings (flag patterns only)")
    rc5, sout, _ = _run(["strings", "-n6", path], timeout=20)
    if rc5 == 0:
        flaghits = [l.strip() for l in sout.splitlines()
                    if re.search(r"[A-Z]{2,8}\{[^\}]{4,}\}|flag\{", l, re.I)]
        if flaghits:
            out.extend(f"  🚩 {h}" for h in flaghits[:10])
        else:
            out.append("  No flag patterns in strings")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 6 — crypto_identify
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def crypto_identify(text: str) -> str:
    """
    Auto-detect encoding/cipher type and attempt decode.

    Handles: base64, base32, base58, base85, hex, rot13, rot-N, binary,
    URL encoding, morse code, XOR single-byte, reversed strings.
    Reports entropy and frequency analysis for unknown ciphers.

    Args:
        text: Encoded/ciphered text to analyze
    """
    text = text.strip()
    out = ["## Crypto Identify", f"Input length: {len(text)}", f"Input (first 80): {text[:80]}"]

    decoded_results = []

    # --- Base64 ---
    b64_clean = re.sub(r"\s", "", text)
    if re.match(r"^[A-Za-z0-9+/]+=*$", b64_clean) and len(b64_clean) % 4 == 0:
        try:
            decoded = base64.b64decode(b64_clean).decode("utf-8", errors="replace")
            decoded_results.append(("Base64", decoded[:200]))
        except Exception:
            pass

    # --- Base32 ---
    b32_clean = re.sub(r"[\s=]", "", text).upper()
    if re.match(r"^[A-Z2-7]+$", b32_clean):
        padded = b32_clean + "=" * (-len(b32_clean) % 8)
        try:
            decoded = base64.b32decode(padded).decode("utf-8", errors="replace")
            decoded_results.append(("Base32", decoded[:200]))
        except Exception:
            pass

    # --- Base85 ---
    try:
        decoded = base64.b85decode(text).decode("utf-8", errors="replace")
        if decoded.isprintable():
            decoded_results.append(("Base85", decoded[:200]))
    except Exception:
        pass

    # --- Hex ---
    hex_clean = re.sub(r"[\s:0x]", "", text)
    if re.match(r"^[0-9a-fA-F]+$", hex_clean) and len(hex_clean) % 2 == 0:
        try:
            decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="replace")
            decoded_results.append(("Hex", decoded[:200]))
        except Exception:
            pass

    # --- URL encoding ---
    if "%" in text:
        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            if decoded != text:
                decoded_results.append(("URL-encoded", decoded[:200]))
        except Exception:
            pass

    # --- Binary string ---
    bin_clean = re.sub(r"\s", "", text)
    if re.match(r"^[01]+$", bin_clean) and len(bin_clean) % 8 == 0:
        try:
            decoded = "".join(chr(int(bin_clean[i:i+8], 2)) for i in range(0, len(bin_clean), 8))
            decoded_results.append(("Binary (8-bit)", decoded[:200]))
        except Exception:
            pass

    # --- Morse code ---
    if re.match(r"^[.\-/| ]+$", text):
        morse_map = {
            ".-":"A", "-...":"B", "-.-.":"C", "-..":"D", ".":"E", "..-.":"F",
            "--.":"G", "....":"H", "..":"I", ".---":"J", "-.-":"K", ".-..":"L",
            "--":"M", "-.":"N", "---":"O", ".--.":"P", "--.-":"Q", ".-.":"R",
            "...":"S", "-":"T", "..-":"U", "...-":"V", ".--":"W", "-..-":"X",
            "-.--":"Y", "--..":"Z",
            "-----":"0",".----":"1","..---":"2","...--":"3",
            "....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9",
        }
        words = text.strip().split("/")
        decoded_words = []
        for word in words:
            chars = [morse_map.get(c.strip(), "?") for c in word.strip().split()]
            decoded_words.append("".join(chars))
        decoded = " ".join(decoded_words)
        decoded_results.append(("Morse Code", decoded[:200]))

    # --- ROT-N (try all rotations, pick most-English) ---
    def rot_n(s: str, n: int) -> str:
        result = []
        for c in s:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result.append(chr((ord(c) - base + n) % 26 + base))
            else:
                result.append(c)
        return "".join(result)

    def english_score(s: str) -> float:
        freq = collections.Counter(c.lower() for c in s if c.isalpha())
        total = sum(freq.values()) or 1
        english = "etaoinshrdlu"
        return sum(freq[c]/total for c in english)

    if re.match(r"^[A-Za-z\s.,!?'-]+$", text) and len(text) > 5:
        best_n, best_score, best_decoded = 0, 0.0, ""
        for n in range(1, 26):
            candidate = rot_n(text, n)
            score = english_score(candidate)
            if score > best_score:
                best_n, best_score, best_decoded = n, score, candidate
        if best_n > 0 and best_score > 0.3:
            decoded_results.append((f"ROT-{best_n}", best_decoded[:200]))
        # Always show ROT-13
        if best_n != 13:
            decoded_results.append(("ROT-13", rot_n(text, 13)[:200]))

    # --- XOR single-byte brute force ---
    try:
        raw_bytes = bytes.fromhex(hex_clean) if (
            re.match(r"^[0-9a-fA-F]+$", hex_clean) and len(hex_clean) % 2 == 0
        ) else text.encode("latin-1", errors="replace")

        if len(raw_bytes) <= 256:
            best_key, best_xor_score, best_xor = 0, 0.0, b""
            for key in range(256):
                candidate = bytes(b ^ key for b in raw_bytes)
                score = english_score(candidate.decode("latin-1", errors="replace"))
                if score > best_xor_score:
                    best_key, best_xor_score, best_xor = key, score, candidate
            if best_xor_score > 0.3:
                decoded_results.append((
                    f"XOR key=0x{best_key:02x}",
                    best_xor.decode("latin-1", errors="replace")[:200]
                ))
    except Exception:
        pass

    # --- Entropy ---
    try:
        raw = text.encode("utf-8", errors="replace")
        freq = collections.Counter(raw)
        total = len(raw)
        import math
        entropy = -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)
        out.append(f"Entropy: {entropy:.2f} bits/byte  (random≈8, English≈3.5-4.5, compressed≈7-8)")
    except Exception:
        pass

    # --- Output ---
    if decoded_results:
        out.append("\n### Decode Candidates")
        for label, decoded in decoded_results:
            out.append(f"\n**{label}:**")
            out.append(f"  {decoded}")
    else:
        out.append("\n### No automatic decode — manual analysis needed")
        out.append("  Possibilities: Vigenere, substitution cipher, custom encoding, compressed data")
        out.append("  Try: https://cyberchef.org  |  dcode.fr/cipher-identifier")

    # --- Base58 ---
    _BASE58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    b58_clean = re.sub(r"\s", "", text)
    if b58_clean and len(b58_clean) >= 8 and all(c in _BASE58_ALPHA for c in b58_clean):
        try:
            num = 0
            for char in b58_clean:
                num = num * 58 + _BASE58_ALPHA.index(char)
            decoded_bytes = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num > 0 else b'\x00'
            leading_ones = len(b58_clean) - len(b58_clean.lstrip('1'))
            decoded_bytes = b'\x00' * leading_ones + decoded_bytes
            decoded_text = decoded_bytes.decode('utf-8', errors='replace')
            out.append("\n### Base58 Decode")
            out.append(f"  {decoded_text[:200]}")
        except Exception:
            pass

    # --- AES-ECB block repeat detection ---
    try:
        ecb_raw = bytes.fromhex(hex_clean) if (
            re.match(r'^[0-9a-fA-F]+$', hex_clean) and len(hex_clean) % 2 == 0
        ) else text.encode('latin-1', errors='replace')
        if len(ecb_raw) >= 32 and len(ecb_raw) % 16 == 0:
            blocks_16 = [ecb_raw[i:i+16] for i in range(0, len(ecb_raw), 16)]
            unique_blocks = set(blocks_16)
            if len(unique_blocks) < len(blocks_16):
                repeats = len(blocks_16) - len(unique_blocks)
                out.append(f"\n⚠ AES-ECB DETECTED: {repeats} repeated 16-byte block(s)")
                out.append("  → Deterministic encryption: identical plaintext → identical ciphertext")
                out.append("  → Chosen-plaintext attack possible (byte-at-a-time decryption)")
    except Exception:
        pass

    # --- Vigenere / polyalphabetic cipher (Index of Coincidence) ---
    alpha_only = re.sub(r'[^A-Za-z]', '', text).upper()
    if len(alpha_only) >= 20:
        import math as _math2
        freq_v = collections.Counter(alpha_only)
        n_v = len(alpha_only)
        ioc = sum(f * (f - 1) for f in freq_v.values()) / (n_v * (n_v - 1)) if n_v > 1 else 0
        if 0.038 <= ioc <= 0.058:  # polyalphabetic zone (random≈0.038, English≈0.065)
            # Estimate key length via IoC across subsequences
            best_keylen, best_ioc = 1, 0.0
            for klen in range(2, min(21, len(alpha_only) // 4)):
                sub_iocs = []
                for start in range(klen):
                    sub = alpha_only[start::klen]
                    sf = collections.Counter(sub)
                    ns = len(sub)
                    sub_ioc = sum(f * (f - 1) for f in sf.values()) / (ns * (ns - 1)) if ns > 1 else 0
                    sub_iocs.append(sub_ioc)
                avg_ioc = sum(sub_iocs) / len(sub_iocs) if sub_iocs else 0
                if avg_ioc > best_ioc:
                    best_ioc, best_keylen = avg_ioc, klen
            out.append("\n### Vigenere/Polyalphabetic Cipher suspected")
            out.append(f"  IoC = {ioc:.4f}  (English=0.065, random=0.038)")
            out.append(f"  Estimated key length: {best_keylen} (avg sub-IoC={best_ioc:.4f})")
            out.append("  Tools: https://www.dcode.fr/vigenere-cipher | quipqiup.com")
        elif ioc >= 0.060:
            out.append(f"\n### Monoalphabetic cipher likely (IoC={ioc:.4f}) — try frequency analysis, quipqiup.com")

    # --- RSA / PEM material hints ---
    if "-----BEGIN" in text:
        out.append("\n### PEM / RSA Material Detected")
        if "PRIVATE KEY" in text:
            out.append("  Private key — extract params: openssl rsa -in key.pem -text -noout")
        if "PUBLIC KEY" in text:
            out.append("  Public key — extract n,e: openssl rsa -pubin -in key.pem -text -noout")
        if "CERTIFICATE" in text:
            out.append("  Certificate — inspect: openssl x509 -in cert.pem -text -noout")
        out.append("  For CTF attacks: rsa_attack(n=..., e=..., c=...)")

    # --- Character set analysis ---
    charset = set(text)
    out.append(f"\n### Character set ({len(charset)} unique): {repr(''.join(sorted(charset)))[:80]}")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 7 — decompile_func
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def decompile_func(path: str, function: str = "main") -> str:
    """
    Disassemble/decompile a binary function using objdump (fast, <10s) then
    radare2 (deeper, if objdump misses). Returns symbol table + disassembly.

    Fast path: objdump runs first — no 120s r2 analysis wait.
    r2 uses `aa` (fast analysis ~10s) instead of `aaa`/`-A` (~120s).
    For stripped/garble binaries: lists all available symbols immediately.

    Args:
        path:     Binary file path
        function: Function name or address to disassemble (default: main)
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    out = [f"## Decompile: {p.name} @ {function}"]

    # --- nm: symbol table (fast, always first) ---
    rc, nout, _ = _run(["nm", path], timeout=15)
    sym_lines = []
    is_stripped = True
    if rc == 0 and nout.strip():
        sym_lines = [l for l in nout.splitlines() if not l.strip().startswith("U")]
        is_stripped = len(sym_lines) == 0
        out.append(f"\n### Symbol table ({len(sym_lines)} defined symbols):")
        interesting = [l for l in sym_lines if any(
            s in l.lower() for s in ("main", "flag", "check", "valid", "win", "secret",
                                      "password", "auth", "key", "encrypt", "decrypt",
                                      "compare", "verify", "vuln", "shell", "input")
        )]
        shown = interesting or sym_lines
        for l in shown[:30]:
            out.append(f"  {l.strip()}")
        if is_stripped:
            out.append("  ⚠ Binary is STRIPPED — no symbol names (garble/UPX/custom packer?)")
            out.append("  💡 Try: binary_triage to detect packer, strings_extract_ctf for flag patterns,")
            out.append("      ltrace/strace via ctf_command to trace runtime behaviour")

    # ── FAST PATH: objdump first (5-15s vs r2's 120s) ─────────────────────
    objdump_found = False
    if shutil.which("objdump"):
        out.append(f"\n### objdump -d (searching for '{function}')")
        rc3, odout, oderr = _run(
            ["objdump", "-d", "-M", "intel", path], timeout=45
        )
        if rc3 == 0 and odout:
            func_pattern = re.compile(
                rf"<{re.escape(function)}[^>]*>:", re.IGNORECASE
            )
            lines = odout.splitlines()
            func_start = None
            for i, line in enumerate(lines):
                if func_pattern.search(line):
                    func_start = i
                    break

            if func_start is not None:
                func_lines = []
                for line in lines[func_start:func_start + 300]:
                    func_lines.append(line)
                    if len(func_lines) > 1 and re.match(r"^[0-9a-f]+ <", line):
                        break
                out.append("\n".join(func_lines[:200]))
                objdump_found = True
                # If we got a good disassembly, skip slow r2
                return "\n".join(out)
            else:
                # List available functions so agent can pick the right one
                funcs = [l.strip() for l in lines if re.match(r"^[0-9a-f]+ <", l)]
                if funcs:
                    out.append(f"  Function '{function}' not found. Available ({len(funcs)} total, first 50):")
                    out.extend(f"    {f}" for f in funcs[:50])
                    objdump_found = True  # We got useful info
                else:
                    out.append(f"  No functions found via objdump (stripped binary)")
        else:
            out.append(f"  objdump error: {oderr[:200]}")

    # ── SLOW PATH: radare2 with FAST analysis (aa, not aaa) ───────────────
    # Only fall back to r2 if objdump gave no usable output
    if not objdump_found and shutil.which("r2"):
        out.append(f"\n### radare2 (fast analysis) — pdf @ {function}")
        out.append("  ⏱ Running r2 aa (fast ~15s, not aaa/120s) ...")
        # Use 'aa' (fast) instead of 'aaa' or '-A' (full, very slow)
        r2_cmds = f"aa;pdf @ {function}"
        rc2, r2out, r2err = _run(
            ["r2", "-q", "-c", r2_cmds, path], timeout=30
        )
        if rc2 == 0 and r2out.strip():
            out.append(r2out[:6000])
        else:
            out.append(f"  r2 error: {r2err[:200]}")
            # Last resort: list r2 functions
            rc_fl, fl_out, _ = _run(
                ["r2", "-q", "-c", "aa;afl", path], timeout=30
            )
            if rc_fl == 0 and fl_out.strip():
                out.append("\n  r2 function list (afl):")
                for fl in fl_out.splitlines()[:40]:
                    out.append(f"    {fl}")

    if not shutil.which("objdump") and not shutil.which("r2"):
        out.append("\n⚠ Neither objdump nor r2 found. Install: apt install radare2 binutils")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 8 — pcap_analyze
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def pcap_analyze(path: str) -> str:
    """
    Analyze a PCAP/PCAPNG file with tshark.

    Extracts: protocol hierarchy, HTTP requests/responses, DNS queries,
    cleartext credentials (FTP/Telnet/HTTP Basic), file transfers,
    and any flag patterns in payload data.

    Args:
        path: PCAP or PCAPNG file
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    if not shutil.which("tshark"):
        return "⚠ tshark not installed — apt install tshark"

    out = [f"## PCAP Analysis: {p.name}"]

    # --- Protocol hierarchy ---
    rc, phout, _ = _run(["tshark", "-r", path, "-q", "-z", "io,phs"], timeout=30)
    if rc == 0 and phout.strip():
        out.append("\n### Protocol Hierarchy")
        out.append(phout.strip()[:1000])

    # --- Packet count + duration ---
    rc2, capout, _ = _run(["tshark", "-r", path, "-q", "-z", "conv,ip"], timeout=30)
    if rc2 == 0 and capout.strip():
        out.append("\n### IP Conversations (top 10)")
        lines = capout.strip().splitlines()
        header_done = False
        count = 0
        for line in lines:
            if line.strip().startswith("IP") or line.strip().startswith("="):
                out.append(line)
                header_done = True
            elif header_done and count < 10 and line.strip():
                out.append(line)
                count += 1

    # --- HTTP requests ---
    rc3, httpout, _ = _run(
        ["tshark", "-r", path, "-Y", "http.request", "-T", "fields",
         "-e", "ip.src", "-e", "http.request.method", "-e", "http.request.full_uri",
         "-e", "http.file_data"],
        timeout=30
    )
    if rc3 == 0 and httpout.strip():
        out.append("\n### HTTP Requests")
        for line in httpout.strip().splitlines()[:30]:
            out.append(f"  {line.strip()[:140]}")

    # --- HTTP responses with bodies (flag hunting) ---
    rc4, respout, _ = _run(
        ["tshark", "-r", path, "-Y", "http.response", "-T", "fields",
         "-e", "ip.src", "-e", "http.response.code", "-e", "http.file_data"],
        timeout=30
    )
    if rc4 == 0 and respout.strip():
        flag_hits = []
        for line in respout.strip().splitlines():
            if re.search(r"[A-Z]{2,8}\{[^\}]+\}|flag\{", line, re.I):
                flag_hits.append(line.strip()[:200])
        if flag_hits:
            out.append("\n### 🚩 Flag patterns in HTTP responses")
            out.extend(flag_hits[:10])

    # --- DNS queries ---
    rc5, dnsout, _ = _run(
        ["tshark", "-r", path, "-Y", "dns.flags.response eq 0", "-T", "fields",
         "-e", "dns.qry.name", "-e", "dns.qry.type"],
        timeout=30
    )
    if rc5 == 0 and dnsout.strip():
        dns_queries = list(set(dnsout.strip().splitlines()))
        out.append(f"\n### DNS Queries ({len(dns_queries)} unique)")
        for q in dns_queries[:30]:
            out.append(f"  {q.strip()}")

    # --- Cleartext credentials ---
    rc6, credout, _ = _run(
        ["tshark", "-r", path, "-Y",
         "ftp.request.command==\"PASS\" or telnet.data or http.authorization",
         "-T", "fields", "-e", "ip.src", "-e", "ftp.request.arg",
         "-e", "http.authorization", "-e", "telnet.data"],
        timeout=30
    )
    if rc6 == 0 and credout.strip():
        out.append("\n### 🔑 Cleartext Credentials")
        for line in credout.strip().splitlines()[:20]:
            if line.strip():
                out.append(f"  {line.strip()[:140]}")

    # --- Global flag search in all payloads ---
    rc7, payload_out, _ = _run(
        ["tshark", "-r", path, "-T", "fields", "-e", "data.text"],
        timeout=30
    )
    if rc7 == 0 and payload_out.strip():
        flag_in_data = [l for l in payload_out.splitlines()
                        if re.search(r"[A-Z]{2,8}\{[^\}]+\}", l, re.I)]
        if flag_in_data:
            out.append("\n### 🚩 Flag patterns in raw payload data")
            out.extend(flag_in_data[:10])

    if len(out) <= 2:
        out.append("No tshark output — file may be empty or corrupt.")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 9 — elf_security
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def elf_security(path: str) -> str:
    """
    Full ELF security mitigation check: PIE, NX/DEP, stack canary, RELRO,
    FORTIFY_SOURCE, RUNPATH, RPATH. Interprets each flag for exploit impact.

    Args:
        path: ELF binary
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"

    out = [f"## ELF Security: {p.name}"]

    # --- checksec JSON ---
    rc, cout, _ = _run(["checksec", "--file=" + path, "--output=json"], timeout=20)
    props = {}
    if rc == 0 and cout.strip():
        try:
            data = json.loads(cout)
            props = list(data.values())[0] if data else {}
        except Exception:
            pass

    if not props:
        # Try checksec text output
        rc2, ctxt, _ = _run(["checksec", "--file=" + path], timeout=20)
        if rc2 == 0 and ctxt:
            out.append(ctxt.strip()[:500])
            return "\n".join(out)
        # Full fallback via readelf
        out.append("checksec not found — using readelf fallback")
        rc3, rout, _ = _run(["readelf", "-l", path], timeout=15)
        if rc3 == 0:
            has_gnu_stack = "GNU_STACK" in rout
            nx = has_gnu_stack and "RWE" not in rout
            out.append(f"  NX (approx): {'ENABLED ✅' if nx else 'DISABLED ❌ — shellcode injectable'}")
        rc4, dout, _ = _run(["readelf", "-d", path], timeout=15)
        if rc4 == 0:
            out.append(f"  RPATH: {'present ⚠' if 'RPATH' in dout else 'none'}")
            out.append(f"  RUNPATH: {'present ⚠' if 'RUNPATH' in dout else 'none'}")
        rc5, fout, _ = _run(["file", path], timeout=10)
        if rc5 == 0:
            pie = "shared object" in fout.lower() or "pie" in fout.lower()
            out.append(f"  PIE (approx): {'ENABLED ✅' if pie else 'DISABLED ❌ — fixed addresses usable in ROP'}")
        return "\n".join(out)

    # Interpret each flag
    _EXPLANATIONS = {
        "relro": {
            "full":    ("FULL RELRO ✅", "GOT is read-only — GOT overwrite attacks blocked"),
            "partial": ("PARTIAL RELRO ⚠",  "GOT still writable — GOT overwrite possible"),
            "no":      ("NO RELRO ❌",       "GOT fully writable — easy GOT overwrite"),
        },
        "canary": {
            "yes":  ("CANARY ✅",    "Stack smashing protection enabled — need canary leak for BOF"),
            "no":   ("NO CANARY ❌", "No stack canary — straightforward stack BOF"),
        },
        "nx": {
            "yes":  ("NX ✅",    "Non-executable stack — shellcode on stack won't execute; need ROP"),
            "no":   ("NO NX ❌", "Executable stack — shellcode injectable directly"),
        },
        "pie": {
            "yes":  ("PIE ✅",    "Position-independent — addresses randomised; need info leak for ROP"),
            "no":   ("NO PIE ❌", "Fixed base address — gadgets/GOT at static addresses"),
        },
        "fortify_source": {
            "yes":  ("FORTIFY ✅",    "Dangerous libc functions replaced with checked versions"),
            "no":   ("NO FORTIFY ⚠", "No fortification — format strings and overflows not extra-checked"),
        },
        "rpath": {
            "yes": ("RPATH ⚠", "Library search path in binary — potential hijacking"),
            "no":  ("RPATH: none", ""),
        },
        "runpath": {
            "yes": ("RUNPATH ⚠", "Library runpath set — potential hijacking"),
            "no":  ("RUNPATH: none", ""),
        },
    }

    out.append("")
    exploit_notes = []
    for key, explanations in _EXPLANATIONS.items():
        val = str(props.get(key, "no")).lower()
        # Normalise checksec output variance
        if val in ("enabled", "true", "1"):
            val = "yes"
        elif val in ("disabled", "false", "0", ""):
            val = "no"
        info = explanations.get(val, (f"{key}={val}", ""))
        label, note = info
        out.append(f"  {label}")
        if note:
            out.append(f"    → {note}")
            if "❌" in label or "⚠" in label:
                exploit_notes.append(note)

    if exploit_notes:
        out.append("\n### Exploit Implications")
        for n in exploit_notes:
            out.append(f"  • {n}")

        # Suggest exploit approach
        pie_off = "no pie" in " ".join(exploit_notes).lower() or not props.get("pie", "yes").startswith("yes")
        canary_off = "no canary" in " ".join(exploit_notes).lower()
        nx_off = "no nx" in " ".join(exploit_notes).lower()

        out.append("\n### Suggested Approach")
        if nx_off and canary_off:
            out.append("  Classic ret2shellcode: inject shellcode on stack, overwrite return address")
        elif canary_off and not nx_off:
            out.append("  ROP chain: no canary means direct BOF, NX means use gadgets not shellcode")
        elif not canary_off:
            out.append("  Need canary leak first (format string, info disclosure) before BOF")
        if pie_off:
            out.append("  Static addresses: use objdump/ghidra to find gadgets at fixed addresses")
        else:
            out.append("  PIE enabled: need info leak to defeat ASLR (e.g., libc address from puts)")

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 10 — ctf_web_triage
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def ctf_web_triage(target: str) -> str:
    """
    Web CTF quick-triage:
      - JWT decode (header + payload, no signature verification)
      - Cookie base64/hex decode
      - SSTI canary probe ({{7*7}}, ${7*7})
      - LFI probe (/etc/passwd, ../../../../etc/passwd)
      - SQLi canary probe (' OR 1=1--, \" OR 1=1--)
      - Debug endpoint enumeration (/debug, /console, /phpinfo.php, /.git)
      - Tech stack fingerprint from headers

    Args:
        target: URL (for live probing) OR raw JWT/cookie string (for decode-only)
    """
    import urllib.request
    import urllib.parse
    import urllib.error

    out = [f"## CTF Web Triage: {target[:80]}"]

    # --- JWT / base64 string decode (no HTTP needed) ---
    raw = target.strip()
    # Looks like a JWT
    if raw.count(".") == 2 and all(
        re.match(r"^[A-Za-z0-9_\-]+$", part) for part in raw.split(".")
    ):
        out.append("\n### JWT Decode")
        parts = raw.split(".")
        for i, label in enumerate(("Header", "Payload")):
            try:
                padded = parts[i] + "=" * (-len(parts[i]) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
                obj = json.loads(decoded)
                out.append(f"  **{label}**: {json.dumps(obj, indent=2)}")
                # Flag specific issues
                if label == "Header":
                    alg = obj.get("alg", "")
                    if alg.lower() == "none":
                        out.append("  ⚠ alg=none — signature not verified! Try forging with alg:none")
                    elif alg.upper() in ("HS256", "HS384", "HS512"):
                        out.append(f"  ⚠ Symmetric {alg} — try algorithm confusion (RS256 pub key as HS256 secret)")
                if label == "Payload":
                    for field in ("admin", "role", "is_admin", "user_id", "uid", "sub"):
                        if field in obj:
                            out.append(f"  🎯 Interesting field: {field}={obj[field]!r} — try tampering")
            except Exception as e:
                out.append(f"  {label} decode error: {e}")
        out.append(f"  Signature: {parts[2][:30]}...")
        out.append("  Tools: jwt_tool_attack(), or: jwt.io decoder, hashcat -a 0 -m 16500 for weak secret")

    # --- Base64/hex cookie decode ---
    if not raw.startswith("http") and not raw.count(".") == 2:
        out.append("\n### Cookie / Token Decode Attempts")
        # URL-decode first
        try:
            from urllib.parse import unquote
            unquoted = unquote(raw)
            if unquoted != raw:
                out.append(f"  URL-decoded: {unquoted[:200]}")
                raw = unquoted
        except Exception:
            pass
        # Base64
        for attempt in (raw, raw + "=" * (-len(raw) % 4)):
            try:
                decoded = base64.b64decode(attempt).decode("utf-8", errors="replace")
                if decoded.isprintable() and len(decoded) > 2:
                    out.append(f"  Base64: {decoded[:200]}")
                    try:
                        obj = json.loads(decoded)
                        out.append(f"  → JSON: {json.dumps(obj, indent=2)[:300]}")
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        # Hex
        hex_clean = re.sub(r"[\s:]", "", raw)
        if re.match(r"^[0-9a-fA-F]+$", hex_clean) and len(hex_clean) % 2 == 0:
            try:
                decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="replace")
                out.append(f"  Hex decoded: {decoded[:200]}")
            except Exception:
                pass

    if not raw.startswith("http"):
        return "\n".join(out)

    # --- Live HTTP probing ---
    base_url = raw.rstrip("/")

    def _get(url: str, headers: dict | None = None, timeout: int = 8) -> tuple[int, dict, str]:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (CTFBot)",
                **(headers or {}),
            })
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(8192).decode("utf-8", errors="replace")
                resp_headers = dict(r.headers)
                return r.status, resp_headers, body
        except urllib.error.HTTPError as e:
            return e.code, {}, ""
        except Exception:
            return -1, {}, ""

    # Tech fingerprint from headers
    status, resp_headers, body = _get(base_url)
    out.append(f"\n### Base URL: {base_url} → HTTP {status}")
    if resp_headers:
        for h in ("Server", "X-Powered-By", "X-Framework", "Set-Cookie", "Content-Type"):
            v = resp_headers.get(h, resp_headers.get(h.lower(), ""))
            if v:
                out.append(f"  {h}: {v}")

    # SSTI canary
    out.append("\n### SSTI Canary Probes")
    ssti_payloads = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "Mako/FreeMarker"),
        ("#{7*7}", "49", "Thymeleaf"),
        ("<%= 7*7 %>", "49", "ERB"),
        ("{{7*'7'}}", "7777777", "Jinja2 string mul"),
    ]
    for payload, expected, engine in ssti_payloads:
        url = f"{base_url}/?name={urllib.parse.quote(payload)}"
        sc, _, rbody = _get(url, timeout=5)
        if expected in rbody:
            out.append(f"  🔴 SSTI ({engine}): {payload!r} → {expected!r} reflected!")
        else:
            out.append(f"  [{engine}] {payload!r} → no reflection at {url}")

    # LFI canary
    out.append("\n### LFI Canary Probes")
    lfi_payloads = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    for payload in lfi_payloads:
        for param in ("file", "path", "page", "include", "template", "view"):
            url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
            sc, _, rbody = _get(url, timeout=5)
            if "root:" in rbody:
                out.append(f"  🔴 LFI via ?{param}= with payload {payload!r}!")
                break

    # Debug endpoints
    out.append("\n### Debug / Sensitive Endpoints")
    debug_paths = [
        "/debug", "/console", "/.git/HEAD", "/.env",
        "/phpinfo.php", "/info.php", "/.git/config",
        "/admin", "/api/debug", "/actuator", "/actuator/env",
        "/flask-debug", "/_debugger", "/wp-admin",
        "/robots.txt", "/sitemap.xml",
    ]
    found_endpoints = []
    for path_seg in debug_paths:
        url = f"{base_url}{path_seg}"
        sc, _, rbody = _get(url, timeout=5)
        if sc and sc not in (404, 403, -1):
            indicator = ""
            if "root:" in rbody:
                indicator = " (contains /etc/passwd!)"
            elif "ref:" in rbody and "HEAD" in path_seg:
                indicator = " (git repo exposed!)"
            elif "APP_KEY" in rbody or "DB_PASSWORD" in rbody:
                indicator = " (.env exposed!)"
            found_endpoints.append(f"  {sc} {url}{indicator}")
    if found_endpoints:
        out.extend(found_endpoints)
    else:
        out.append("  No interesting debug endpoints found")

    # SQLi quick canary
    out.append("\n### SQLi Canary")
    sqli_tests = [("'", "syntax error|sql|mysql|ORA-|sqlite"), ("\"", "syntax error|sql|mysql")]
    for char, err_pat in sqli_tests:
        for param in ("id", "user", "username", "q", "search", "page"):
            url = f"{base_url}/?{param}={urllib.parse.quote(char)}"
            sc, _, rbody = _get(url, timeout=5)
            err_match = re.search(err_pat, rbody, re.I)
            if err_match:
                out.append(f"  🔴 SQLi error via ?{param}={char!r} → {err_match.group()!r}")
                break

    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 11 — usb_hid_decode
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def usb_hid_decode(pcap_path: str, device_filter: str = "") -> str:
    """
    Reconstruct keystrokes from USB HID interrupt transfers in a PCAP capture.

    Extracts USB HID keyboard scan codes and converts them to readable text,
    handling Shift/CapsLock/Ctrl/Alt modifiers and special keys. Commonly
    used in forensics CTF challenges where a password or flag was typed and
    captured on a USB bus.

    Args:
        pcap_path: Path to PCAP/PCAPNG file containing USB traffic.
        device_filter: Optional tshark USB address filter e.g. '1.5.1' (bus.device.endpoint).

    Returns:
        Reconstructed keystrokes including a cleaned (backspace-processed) version
        and flag pattern matches.
    """
    p = Path(pcap_path)
    if not p.exists():
        return f"Error: file not found: {pcap_path}"

    if not shutil.which("tshark"):
        return "⚠ tshark not installed — apt install tshark (Wireshark)"

    out = [f"## USB HID Decode: {p.name}"]

    # HID Usage ID → (normal, shifted) character (USB HID Spec 1.11, keyboard usage page 0x07)
    _HID_MAP: dict[int, tuple[str, str]] = {
        0x04: ('a','A'), 0x05: ('b','B'), 0x06: ('c','C'), 0x07: ('d','D'),
        0x08: ('e','E'), 0x09: ('f','F'), 0x0a: ('g','G'), 0x0b: ('h','H'),
        0x0c: ('i','I'), 0x0d: ('j','J'), 0x0e: ('k','K'), 0x0f: ('l','L'),
        0x10: ('m','M'), 0x11: ('n','N'), 0x12: ('o','O'), 0x13: ('p','P'),
        0x14: ('q','Q'), 0x15: ('r','R'), 0x16: ('s','S'), 0x17: ('t','T'),
        0x18: ('u','U'), 0x19: ('v','V'), 0x1a: ('w','W'), 0x1b: ('x','X'),
        0x1c: ('y','Y'), 0x1d: ('z','Z'),
        0x1e: ('1','!'), 0x1f: ('2','@'), 0x20: ('3','#'), 0x21: ('4','$'),
        0x22: ('5','%'), 0x23: ('6','^'), 0x24: ('7','&'), 0x25: ('8','*'),
        0x26: ('9','('), 0x27: ('0',')'),
        0x28: ('[ENTER]','[ENTER]'), 0x29: ('[ESC]','[ESC]'),
        0x2a: ('[BS]','[BS]'),   0x2b: ('[TAB]','[TAB]'),
        0x2c: (' ',' '),         0x2d: ('-','_'),  0x2e: ('=','+'),
        0x2f: ('[','{'),         0x30: (']','}'),  0x31: ('\\','|'),
        0x33: (';',':'),         0x34: ("'",'"'),  0x35: ('`','~'),
        0x36: (',','<'),         0x37: ('.', '>'), 0x38: ('/','?'),
        0x39: ('[CAPS]','[CAPS]'),
        0x3a: ('[F1]','[F1]'),   0x3b: ('[F2]','[F2]'),   0x3c: ('[F3]','[F3]'),
        0x3d: ('[F4]','[F4]'),   0x3e: ('[F5]','[F5]'),   0x3f: ('[F6]','[F6]'),
        0x40: ('[F7]','[F7]'),   0x41: ('[F8]','[F8]'),   0x42: ('[F9]','[F9]'),
        0x43: ('[F10]','[F10]'), 0x44: ('[F11]','[F11]'), 0x45: ('[F12]','[F12]'),
        0x4f: ('[RIGHT]','[RIGHT]'), 0x50: ('[LEFT]','[LEFT]'),
        0x51: ('[DOWN]','[DOWN]'),   0x52: ('[UP]','[UP]'),
        0x4c: ('[DEL]','[DEL]'),     0x4a: ('[HOME]','[HOME]'),
        0x4d: ('[END]','[END]'),
    }

    # Try both usb.capdata and usbhid.data field names
    cap_out = ""
    for field in ("usb.capdata", "usbhid.data"):
        filter_str = field
        if device_filter:
            filter_str = f"{field} and usb.addr == \"{device_filter}\""
        rc, cap_out, _ = _run(
            ["tshark", "-r", pcap_path, "-Y", filter_str,
             "-T", "fields", "-e", field],
            timeout=30
        )
        if cap_out.strip():
            break

    if not cap_out.strip():
        out.append("No USB HID data found in this capture.")
        out.append("Verify it contains keyboard interrupt transfers:")
        out.append("  tshark -r file.pcap -Y 'usb.transfer_type == 0x01'")
        # Show USB device info
        rc2, dev_out, _ = _run(
            ["tshark", "-r", pcap_path, "-T", "fields",
             "-e", "usb.idVendor", "-e", "usb.idProduct"],
            timeout=15
        )
        if dev_out.strip():
            out.append(f"\nUSB device info found:\n{dev_out.strip()[:400]}")
        return "\n".join(out)

    raw_packets = [line.strip() for line in cap_out.splitlines() if line.strip()]
    out.append(f"HID packets found: {len(raw_packets)}")

    keystrokes: list[str] = []
    caps_lock = False
    prev_key = 0x00

    for pkt in raw_packets:
        pkt_clean = pkt.replace(":", "").replace(" ", "")
        if len(pkt_clean) < 4:
            continue
        try:
            data = bytes.fromhex(pkt_clean)
        except ValueError:
            continue
        if len(data) < 3:
            continue

        modifier  = data[0]   # bit0/4=Ctrl, bit1/5=Shift, bit2/6=Alt
        key_code  = data[2]   # first key code (byte 2, after reserved byte 1)

        if key_code == 0x00 or key_code == prev_key:
            prev_key = key_code
            continue
        prev_key = key_code

        shift = bool(modifier & 0x22)   # left or right shift
        ctrl  = bool(modifier & 0x11)
        alt   = bool(modifier & 0x44)

        if key_code == 0x39:  # Caps Lock toggle
            caps_lock = not caps_lock
            keystrokes.append('[CAPS]')
            continue

        if key_code in _HID_MAP:
            normal, shifted = _HID_MAP[key_code]
            use_shift = shift ^ caps_lock if normal.isalpha() else shift
            char = shifted if use_shift else normal
            if ctrl:
                char = f'[CTRL+{shifted.upper() if shifted.isalpha() else normal}]'
            elif alt:
                char = f'[ALT+{normal}]'
            keystrokes.append(char)
        else:
            keystrokes.append(f'[0x{key_code:02x}]')

    if not keystrokes:
        out.append("No decodable keystrokes. Try device_filter= to narrow to one USB endpoint.")
        return "\n".join(out)

    raw_text = "".join(keystrokes)

    # Apply backspace and clean
    clean_chars: list[str] = []
    _NOISE = {'[CAPS]','[ESC]','[TAB]','[BS]','[UP]','[DOWN]','[LEFT]','[RIGHT]',
              '[HOME]','[END]','[DEL]','[ENTER]'}
    for k in keystrokes:
        if k == '[BS]':
            if clean_chars:
                clean_chars.pop()
        elif k.startswith('[F') or k.startswith('[CTRL') or k.startswith('[ALT') or k in _NOISE:
            pass
        else:
            clean_chars.append(k)

    clean_text = "".join(clean_chars)

    out.append(f"\n### Raw Keystroke Sequence ({len(keystrokes)} events)")
    out.append(raw_text[:3000])
    out.append(f"\n### Cleaned Text (backspace-processed, {len(clean_text)} chars)")
    out.append(clean_text[:3000])

    # Flag pattern search
    flag_hits = re.findall(
        r'[A-Z]{2,8}\{[^}]{3,60}\}|flag\{[^}]+\}',
        clean_text, re.IGNORECASE
    )
    if flag_hits:
        out.append("\n### 🚩 Flag patterns detected")
        for h in flag_hits:
            out.append(f"  {h}")

    return "\n".join(out)
