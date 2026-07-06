import os
import re
import time
import hashlib
import difflib
from pathlib import Path

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


def get_project_root() -> Path:
    """Return the absolute path to the project root."""
    # This file is in src/sdk/utils.py, so root is 3 levels up
    return Path(__file__).parent.parent.parent.absolute()


def get_output_dir() -> str:
    """Get the directory for storing large tool outputs."""
    # Try session directory first
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        if tm.session_dir:
            out_dir = os.path.join(str(tm.session_dir), "tool_outputs")
            os.makedirs(out_dir, exist_ok=True)
            return out_dir
    except Exception:
        pass
    # Fallback to /tmp
    out_dir = "/tmp/ctf_tool_outputs"
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def smart_output(raw_output: str, tool_name: str, context_hint: str = "") -> str:
    """
    Intelligent output handler for tools that produce large outputs.
    
    If output is small: return it directly.
    If output is large: save full output to file, return a smart summary.
    """
    if not raw_output or len(raw_output) <= _LARGE_OUTPUT_THRESHOLD:
        return raw_output
    
    # ── Save full output to file ──
    timestamp = int(time.time())
    safe_hint = re.sub(r'[^\w\-.]', '_', context_hint)[:40] if context_hint else ""
    filename = f"{tool_name}_{safe_hint}_{timestamp}.txt"
    out_dir = get_output_dir()
    filepath = os.path.join(out_dir, filename)
    
    try:
        with open(filepath, "w", errors="replace") as f:
            f.write(raw_output)
    except Exception as e:
        # If save fails, fall back to truncation
        half = _LARGE_OUTPUT_THRESHOLD // 2
        return (
            f"{raw_output[:half]}\n\n"
            f"... [TRUNCATED — save failed: {e}] ...\n\n"
            f"{raw_output[-half:]}"
        )
    
    lines = raw_output.split("\n")
    total_lines = len(lines)
    total_chars = len(raw_output)
    
    # ── Create preview (first 50 and last 50 lines) ──
    preview_lines = raw_output.splitlines()
    if len(preview_lines) > 100:
        preview = "\n".join(preview_lines[:50]) + "\n\n... [TRUNCATED] ...\n\n" + "\n".join(preview_lines[-50:])
    else:
        preview = raw_output
    
    # ── Auto-grep for interesting patterns ──
    grep_hits = []
    for pattern in _INTERESTING_PATTERNS:
        matches = re.findall(pattern, raw_output)
        if matches:
            unique = list(dict.fromkeys(matches))[:5]
            grep_hits.append(f"  🔍 Pattern '{pattern}': {', '.join(repr(m) for m in unique)}")
    
    # ── Build summary ──
    summary_parts = [
        "═══ OUTPUT SAVED TO FILE (too large for context window) ═══",
        f"📄 File: {filepath}",
        f"📊 Size: {total_lines} lines, {total_chars:,} characters",
        f"🔧 Tool: {tool_name}",
        f"📝 Argument: {context_hint}" if context_hint else "",
        "",
    ]
    
    if grep_hits:
        summary_parts.append("🎯 AUTO-DETECTED INTERESTING PATTERNS (Potential Flags/Secrets):")
        summary_parts.extend(grep_hits)
        summary_parts.append("⚠️  IMPORTANT: Review the patterns above. If you see a partial flag, the full flag is likely in the saved file.")
        summary_parts.append("")
    
    summary_parts.extend([
        "── PREVIEW (first/last lines) ──",
        preview,
        "",
        "── HOW TO EXPLORE FULL OUTPUT ──",
        "Use ctf_command to search the saved file:",
        f'  ctf_command("grep -n -i \'flag\' {filepath}")',
        f'  ctf_command("read_tool_output(\'{filepath}\', start_line=100, end_line=200)")',
    ])
    
    return "\n".join(summary_parts)


def robust_json_loads(raw: str):
    """
    Attempts to parse JSON from a string that might contain LLM noise or 
    common formatting errors like unescaped backslashes.
    """
    import json
    import re
    
    if not raw or not isinstance(raw, str):
        return raw

    # 1. Clean up prose noise and markdown fences
    if "```" in raw:
        json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', raw, re.DOTALL)
        if json_match:
            raw = json_match.group(1).strip()
        else:
            raw = raw.replace("```json", "").replace("```", "").strip()
            
    # 2. Extract first valid looking JSON structure if there's trailing/leading garbage
    start_obj = raw.find('{')
    start_arr = raw.find('[')
    
    if start_obj == -1 and start_arr == -1:
        # Might be a simple string, number, or boolean - try direct parse
        try:
            return json.loads(raw)
        except:
            return raw
    
    # Pick the structure that starts first
    if start_obj != -1 and (start_arr == -1 or start_obj < start_arr):
        start = start_obj
        end = raw.rfind('}')
    else:
        start = start_arr
        end = raw.rfind(']')
    
    if start != -1 and end != -1:
        raw = raw[start:end+1]
    
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        # 3. Fix common errors: unescaped backslashes (common in Windows paths)
        # This regex finds a \ that is NOT followed by a valid JSON escape char
        fixed = re.sub(r'\\(?![/\\bfnrtu])', r'\\\\', raw)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            # If still failing, return raw or raise
            raise e


def extract_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()


def normalize_text(text: str, max_len: int = 4000) -> str:
    if not text:
        return ""
    # Strip tags to reduce noise from HTML structure
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    if max_len and len(text) > max_len:
        text = text[:max_len]
    return text


def similarity_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def response_signature(body: str, max_len: int = 4000) -> dict:
    norm = normalize_text(body, max_len=max_len)
    digest = hashlib.sha1(norm.encode("utf-8", errors="replace")).hexdigest()[:10] if norm else ""
    return {
        "length": len(body or ""),
        "title": extract_title(body or ""),
        "norm": norm,
        "digest": digest,
    }
