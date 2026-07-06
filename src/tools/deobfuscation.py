"""
LLM-Assisted Code Deobfuscation for CTF Challenges

Feeds decompiled / disassembled / obfuscated code to the LLM with a tightly
structured forensic prompt that extracts exactly what is needed to solve the
challenge — not a general explanation, but actionable structured output:

  INPUT_FORMAT        — length, charset, prefix/suffix constraints
  COMPARISON_TARGETS  — every hardcoded value the algorithm checks against
  TRANSFORMATION_STEPS — numbered concrete steps (XOR, add, rotate, etc.)
  INVERSE_ALGORITHM   — how to reverse it
  SOLVE_SCRIPT        — minimal Python that computes the flag
  KEY_INSIGHT         — the one non-obvious thing to know
"""

from __future__ import annotations

import json
import re
from src.sdk.tool import function_tool

# ---------------------------------------------------------------------------
# Structured extraction system prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are an expert CTF binary reverse engineer and malware analyst.
When shown decompiled, disassembled, or obfuscated code you perform forensic algorithm extraction.

CRITICAL: Do NOT give general explanations. Extract ONLY the following six items:

1. INPUT_FORMAT
   - Exact required length in bytes or characters (if determinable)
   - Character set (hex digits, alphanumeric, printable ASCII, raw bytes, etc.)
   - Required prefix or suffix (e.g. "must start with HTB{", "must end with }")
   - Any delimiter / group structure (e.g. "4 groups of 8 separated by -")
   - Write "unknown" for anything not determinable from the snippet

2. COMPARISON_TARGETS
   - Every hardcoded constant, byte array, string literal, or lookup table the code compares against
   - Include exact hex values where visible
   - Note which offset or index in the (transformed) input each target corresponds to
   - Write "none found" if there are no obvious hardcoded targets

3. TRANSFORMATION_STEPS
   - Numbered list of what the code does to the input before comparing
   - Be concrete: "byte[i] = input[i] XOR key[i % 8]" not "some XOR operation"
   - Include loop bounds, modular arithmetic, bitwise ops, table lookups
   - For VM bytecode: list each opcode and its effect on the virtual stack/registers
   - For multi-stage transforms: label them Stage 1, Stage 2, etc.

4. INVERSE_ALGORITHM
   - How to reverse each transformation to recover the original input from the target
   - XOR: "XOR target[i] with same key"
   - Additive cipher: "subtract constant mod 256"
   - Hash comparison: "need brute force or rainbow table — note hash function and target"
   - Substitution box: "build reverse lookup: rev[sbox[i]] = i for all i"
   - VM: "symbolically trace what stack value would pass each check"

5. SOLVE_SCRIPT
   - Minimal Python (≤ 35 lines) that computes or recovers the flag
   - Use UNKNOWN as placeholder for any value not visible in the snippet
   - If brute-force is required, show the loop structure
   - End with: print("FLAG:", result)

6. KEY_INSIGHT
   - One sentence on the single non-obvious trick that makes this challenge work
   - Example: "The key is stored reversed in .rodata at 0x4040a0"
   - Example: "The VM compares ASCII value + 13 against each target byte"

Respond with ONLY a valid JSON object with exactly these keys:
  input_format, comparison_targets, transformation_steps,
  inverse_algorithm, solve_script, key_insight

No markdown fences. No prose outside the JSON."""

# ---------------------------------------------------------------------------
# Language hint to improve prompt context
# ---------------------------------------------------------------------------

_LANG_HINTS = {
    "go":      "This is Go (possibly garble-obfuscated). Focus on string comparison functions.",
    "rust":    "This is Rust. Watch for iterator chains and trait method calls.",
    "c":       "This is C/C++ decompilation (Ghidra/IDA style). Watch for pointer arithmetic.",
    "python":  "This is Python bytecode or source. Watch for exec/eval and string mutations.",
    "java":    "This is Java bytecode / decompiled class. Watch for charAt and byte[] ops.",
    "wasm":    "This is WebAssembly. Ops are stack-based; i32.xor/i32.add are common.",
    "llvm":    "This is LLVM IR. Watch for getelementptr and icmp instructions.",
    "asm":     "This is x86/ARM assembly. Map registers to variables; trace comparisons.",
    "auto":    "",
}

# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------

@function_tool()
def deobfuscate_code(
    code_snippet: str,
    context: str = "",
    language: str = "auto",
    goal: str = "flag",
) -> str:
    """
    LLM-assisted structured deobfuscation for CTF challenges.

    Feed a snippet of decompiled, disassembled, or obfuscated code here.
    The model will extract:
      - Input format/length constraints
      - Hardcoded comparison targets
      - Exact transformation steps (concrete, not vague)
      - Inverse algorithm to recover the flag
      - A minimal Python solve script
      - The key insight that unlocks the challenge

    Use this BEFORE spending time manually tracing through code.
    Works on: Ghidra decompilation, objdump output, garble'd Go, LLVM IR,
              custom VM bytecode, Python obfuscation, packed strings.

    Args:
        code_snippet: The decompiled / disassembled / obfuscated text.
                      Paste 20-200 lines for best results.
        context:      Optional free-text context (binary name, function name,
                      observed runtime behaviour, input you already know).
        language:     Hint for the code language: "c", "go", "rust", "python",
                      "java", "wasm", "llvm", "asm", or "auto" (default).
        goal:         What you are trying to recover — default "flag".

    Returns:
        Structured analysis with solve script.
    """
    if not code_snippet or not code_snippet.strip():
        return "[deobfuscate_code] No code snippet provided."

    lang_key = (language or "auto").lower().strip()
    lang_hint = _LANG_HINTS.get(lang_key, "")

    # Build the user prompt
    user_parts: list[str] = []
    if lang_hint:
        user_parts.append(f"Language context: {lang_hint}")
    if context:
        user_parts.append(f"Additional context: {context}")
    user_parts.append(f"Goal: recover the {goal}")
    user_parts.append("")
    user_parts.append("=== CODE SNIPPET ===")
    # Cap snippet at 8000 chars to stay within a single LLM call
    snippet = code_snippet.strip()
    if len(snippet) > 8000:
        snippet = snippet[:7900] + "\n... [truncated — paste a smaller focused snippet for best results]"
    user_parts.append(snippet)
    user_parts.append("=== END SNIPPET ===")

    user_message = "\n".join(user_parts)

    # Call the LLM
    try:
        from src.sdk.llm import get_llm
        llm = get_llm()
        raw = llm.generate_response(
            prompt=user_message,
            system_prompt=_SYSTEM_PROMPT,
            temperature=0.15,
            max_tokens=1800,
        )
    except Exception as e:
        return f"[deobfuscate_code] LLM call failed: {e}"

    if not raw or not raw.strip():
        return "[deobfuscate_code] LLM returned empty response."

    # Parse JSON response
    # Strip accidental markdown fences the model may add despite instructions
    cleaned = re.sub(r"^```[a-z]*\n?", "", raw.strip(), flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```$", "", cleaned.strip())

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        # Partial JSON / prose fallback — return raw but still useful
        return (
            "[deobfuscate_code] LLM returned non-JSON output (model may have included prose).\n"
            "Raw analysis:\n\n" + raw
        )

    # Format the structured output for easy reading
    lines: list[str] = [
        "╔══════════════════════════════════════════════════════════",
        "║  DEOBFUSCATION ANALYSIS",
        "╠══════════════════════════════════════════════════════════",
    ]

    def _section(title: str, key: str):
        value = data.get(key, "not extracted")
        if isinstance(value, list):
            body = "\n".join(f"  {v}" for v in value) if value else "  none"
        else:
            body = str(value)
        lines.append(f"║")
        lines.append(f"║  ▶ {title}")
        for ln in body.splitlines():
            lines.append(f"║    {ln}")

    _section("INPUT FORMAT", "input_format")
    _section("COMPARISON TARGETS", "comparison_targets")
    _section("TRANSFORMATION STEPS", "transformation_steps")
    _section("INVERSE ALGORITHM", "inverse_algorithm")

    # Solve script gets a code block
    solve = data.get("solve_script", "")
    if solve:
        lines.append("║")
        lines.append("║  ▶ SOLVE SCRIPT (Python)")
        lines.append("║  ┌─────────────────────────────────────────")
        for ln in str(solve).splitlines():
            lines.append(f"║  │ {ln}")
        lines.append("║  └─────────────────────────────────────────")

    insight = data.get("key_insight", "")
    if insight:
        lines.append("║")
        lines.append(f"║  ★ KEY INSIGHT: {insight}")

    lines.append("╚══════════════════════════════════════════════════════════")

    return "\n".join(lines)
