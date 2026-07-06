from src.sdk.core import function_tool
from src.sdk.tmux_session import TmuxSessionManager
import hashlib
import os
from pathlib import Path

# Global managers dictionary to handle multiple concurrent sessions
_managers: dict[str, TmuxSessionManager] = {}

def get_manager(session_name: str) -> TmuxSessionManager:
    """Get or create a TmuxSessionManager for the given session name."""
    if session_name not in _managers:
        _managers[session_name] = TmuxSessionManager(session=session_name)
    return _managers[session_name]


@function_tool(name_override="interactive_bash")
def interactive_bash(command: str = "", session: str = "main", is_input: bool = False, timeout: int = 120) -> str:
    """
    Run shell commands inside a persistent tmux session. Supports interactive tools (msfconsole, ssh).
    Automatically detects when a tool drops into a prompt.

    Args:
        command: The shell command or input string to send.
        session: The name of the session (e.g. 'main', 'msf').
        is_input: Set to True if this command is input to an ALREADY RUNNING interactive program.
        timeout: Wait time in seconds.
    """
    mgr = get_manager(session)
    if not command and not is_input:
        return mgr.read_screen()
    return mgr.execute(command, is_input=is_input, timeout=timeout)


@function_tool(name_override="read_shell_screen")
def read_shell_screen(session: str = "main") -> str:
    """
    Read the current visible screen of a backgrounded or stalled tmux session.

    Args:
        session: The name of the session to read.
    """
    mgr = get_manager(session)
    return mgr.read_screen()


@function_tool(name_override="terminal_screenshot")
def terminal_screenshot(session: str = "main", filename: str = "", label: str = "") -> str:
    """
    Capture a screenshot of a backgrounded tmux session and save it as a PNG image.
    Renders the terminal output in a dark-themed, monospace-font image suitable for
    embedding in pentest/bug-bounty reports.

    Args:
        session: The name of the tmux session to screenshot (default: 'main').
        filename: Output PNG filename. Auto-generated from session name + timestamp if empty.
        label:    Optional caption/label text printed at the top of the image (e.g. 'nmap scan output').

    Returns:
        Absolute path of the saved PNG, or an error string.
    """
    # ── 1. Grab raw screen text ──────────────────────────────────────────────
    mgr = get_manager(session)
    try:
        raw_text = mgr._capture()
    except RuntimeError as e:
        return f"[terminal_screenshot] ERROR reading session '{session}': {e}"

    if not raw_text.strip():
        raw_text = "(empty screen — no output captured)"

    # Strip ANSI escape codes so the image renderer doesn't see control chars
    import re
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    clean_text = ansi_escape.sub("", raw_text)

    # ── 2. Resolve output directory (mirrors browser_screenshot pattern) ─────
    try:
        from src.repl.target_manager import get_target_manager
        tm = get_target_manager()
        screenshots_dir = (tm.session_dir / "screenshots") if tm.session_dir else Path(os.getcwd()) / "screenshots"
    except Exception:
        screenshots_dir = Path(os.getcwd()) / "screenshots"

    screenshots_dir.mkdir(parents=True, exist_ok=True)

    if not filename:
        import time as _time
        ts = int(_time.time())
        session_slug = session.replace("/", "_").replace(" ", "_")
        filename = f"terminal_{session_slug}_{ts}.png"

    filepath = screenshots_dir / filename

    # ── 3. Render PNG with Pillow ────────────────────────────────────────────
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        # Pillow not installed — save as plain .txt fallback and inform caller
        txt_path = filepath.with_suffix(".txt")
        txt_path.write_text(clean_text, encoding="utf-8")
        return (
            f"[terminal_screenshot] Pillow not installed. "
            f"Plain-text fallback saved: {txt_path.absolute()}\n"
            f"Install Pillow: pip install Pillow"
        )

    # Terminal colour palette
    BG_COLOR      = (18, 18, 18)        # near-black background
    FG_COLOR      = (204, 204, 204)     # light grey text
    HEADER_COLOR  = (30, 30, 30)        # slightly lighter header bar
    ACCENT_COLOR  = (97, 214, 214)      # cyan accent (label text)
    BTN_RED       = (255, 95, 86)
    BTN_YELLOW    = (255, 189, 46)
    BTN_GREEN     = (39, 201, 63)

    PADDING       = 20
    HEADER_H      = 36
    FONT_SIZE     = 14
    LINE_SPACING  = 4

    # Try to load a bundled monospace font; fall back to default
    _FONT_CANDIDATES = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "C:/Windows/Fonts/consola.ttf",   # Windows Consolas
        "C:/Windows/Fonts/cour.ttf",      # Windows Courier New
    ]
    font = None
    for candidate in _FONT_CANDIDATES:
        if Path(candidate).exists():
            try:
                font = ImageFont.truetype(candidate, FONT_SIZE)
                break
            except Exception:
                continue
    if font is None:
        font = ImageFont.load_default()

    lines = clean_text.split("\n")

    # Measure dimensions using a dummy draw surface
    dummy = Image.new("RGB", (1, 1))
    ddraw = ImageDraw.Draw(dummy)
    char_w, char_h = 0, 0
    for ln in lines:
        bb = ddraw.textbbox((0, 0), ln if ln else " ", font=font)
        w = bb[2] - bb[0]
        h = bb[3] - bb[1]
        char_w = max(char_w, w)
        char_h = max(char_h, h)

    row_h   = char_h + LINE_SPACING
    img_w   = max(char_w + PADDING * 2, 600)
    img_h   = HEADER_H + PADDING + row_h * len(lines) + PADDING

    img  = Image.new("RGB", (img_w, img_h), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # ── Header bar ──────────────────────────────────────────────────────────
    draw.rectangle([(0, 0), (img_w, HEADER_H)], fill=HEADER_COLOR)
    # Traffic-light dots
    for x_dot, col in [(16, BTN_RED), (36, BTN_YELLOW), (56, BTN_GREEN)]:
        draw.ellipse([(x_dot - 6, HEADER_H // 2 - 6), (x_dot + 6, HEADER_H // 2 + 6)], fill=col)
    # Session label in header
    header_text = f"tmux: {session}" + (f"  —  {label}" if label else "")
    draw.text((76, HEADER_H // 2 - char_h // 2), header_text, font=font, fill=FG_COLOR)

    # ── Body text ───────────────────────────────────────────────────────────
    y = HEADER_H + PADDING
    for ln in lines:
        draw.text((PADDING, y), ln, font=font, fill=FG_COLOR)
        y += row_h

    # ── Cyan bottom bar with metadata ────────────────────────────────────────
    import time as _time2
    meta = f"  captured: {_time2.strftime('%Y-%m-%d %H:%M:%S')}  |  session: {session}"
    draw.rectangle([(0, img_h - 22), (img_w, img_h)], fill=(25, 25, 40))
    draw.text((PADDING, img_h - 18), meta, font=font, fill=ACCENT_COLOR)

    img.save(str(filepath), "PNG")
    return f"✅ Terminal screenshot saved: {filepath.absolute()}"
