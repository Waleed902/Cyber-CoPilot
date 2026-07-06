import time
import re
import subprocess
import threading
from typing import Tuple
from loguru import logger

# ─── Constants ───────────────────────────────────────────────────────────

PS1_PATTERN = re.compile(r"\[DCPTN:(\d+):(.+?)\]")
POLL_INTERVAL: float = 0.5
STALL_SECONDS: float = 3.0
MAX_OUTPUT_CHARS: int = 30_000
SIZE_WATCHDOG_CHARS: int = 5_000_000
AUTO_BACKGROUND_SECONDS: float = 60.0

# Semantic exit code interpretation
_EXIT_CODE_MESSAGES: dict[int, str] = {
    1: "general error",
    2: "misuse of shell builtin",
    126: "permission denied (not executable)",
    127: "command not found \u2014 tool may not be installed",
    128: "invalid exit argument",
    130: "interrupted by Ctrl+C (SIGINT)",
    137: "killed (SIGKILL) \u2014 likely OOM or size limit exceeded",
    139: "segmentation fault (SIGSEGV)",
    143: "terminated (SIGTERM)",
}

def _interpret_exit_code(code: int) -> str:
    if code == 0:
        return ""
    if code in _EXIT_CODE_MESSAGES:
        return f" \u2014 {_EXIT_CODE_MESSAGES[code]}"
    if code > 128:
        return f" \u2014 killed by signal {code - 128}"
    return ""

def _extract_interactive_output(screen: str, baseline: str) -> str:
    matches = list(PS1_PATTERN.finditer(baseline))
    if matches:
        last = matches[-1]
        new_content = screen[last.end():].strip()
        return new_content if new_content else screen.strip()
    baseline_lines = set(baseline.strip().split("\n"))
    screen_lines = screen.strip().split("\n")
    new_lines = [ln for ln in screen_lines if ln not in baseline_lines]
    return "\n".join(new_lines) if new_lines else screen.strip()

def _extract_output(screen: str, command: str, initial_count: int) -> Tuple[str, int, str]:
    matches = list(PS1_PATTERN.finditer(screen))
    if not matches:
        return screen, -1, ""
    last = matches[-1]
    exit_code = int(last.group(1))
    cwd = last.group(2)
    if len(matches) >= 2:
        raw = screen[matches[-2].end() : last.start()]
    else:
        raw = screen[: last.start()]
    lines = raw.strip().split("\n")
    if lines and command and lines[0].strip().endswith(command.strip()):
        lines = lines[1:]
    return "\n".join(lines).strip(), exit_code, cwd

def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    head_chars = int(MAX_OUTPUT_CHARS * 0.6)
    tail_chars = MAX_OUTPUT_CHARS - head_chars
    mid_text = text[head_chars:-tail_chars]
    mid_lines = mid_text.count("\n")
    mid_chars = len(mid_text)
    return (
        f"{text[:head_chars]}\n\n"
        f"[... {mid_lines} lines / {mid_chars} chars truncated ...]\n\n"
        f"{text[-tail_chars:]}"
    )


class TmuxSessionManager:
    """Manages a single named tmux session natively on the host OS."""
    
    _initialized: set[str] = set()
    _init_lock: threading.RLock = threading.RLock()

    def __init__(self, session: str = "main") -> None:
        # Sanitize session name: replace any character that is not alphanumeric, underscore, or hyphen with _
        self.session = re.sub(r"[^a-zA-Z0-9_-]", "_", session or "main")

    def _tmux(self, args: list[str], timeout: int = 10) -> str:
        """Run a tmux command on the host."""
        try:
            result = subprocess.run(
                ["tmux"] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                if "no server running" in error_msg or "server exited" in error_msg or "session not found" in error_msg:
                    with self._init_lock:
                        self._initialized.discard(self.session)
                raise RuntimeError(error_msg.strip())
            return result.stdout
        except FileNotFoundError:
            raise RuntimeError("CRITICAL ERROR: 'tmux' is not installed or not in PATH. Please install tmux.")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"tmux command timed out after {timeout}s: tmux {' '.join(args)}")

    def _send(self, text: str, enter: bool = True) -> None:
        lines = text.splitlines()
        if len(lines) > 1:
            for line in lines:
                if line:
                    self._tmux(["send-keys", "-t", self.session, "-l", line])
                self._tmux(["send-keys", "-t", self.session, "Enter"])
            if text.endswith("\n") and enter:
                self._tmux(["send-keys", "-t", self.session, "Enter"])
            return

        if text:
            self._tmux(["send-keys", "-t", self.session, "-l", text])
        if enter:
            self._tmux(["send-keys", "-t", self.session, "Enter"])

    def _clear_screen(self) -> None:
        self._tmux(["send-keys", "-t", self.session, "C-l"])
        time.sleep(0.1)
        self._tmux(["clear-history", "-t", self.session])

    def _capture(self) -> str:
        return self._tmux(["capture-pane", "-J", "-p", "-S", "-", "-E", "-", "-t", self.session])

    def _install_prompt_marker(self) -> None:
        ps1_cmd = "export PROMPT_COMMAND='export PS1=\"[DCPTN:$?:$PWD] \"'; export PS2=''; clear"
        self._send(ps1_cmd)
        time.sleep(0.5)
        self._clear_screen()
        time.sleep(0.2)

    def initialize(self) -> None:
        """Create session and inject the PS1 marker."""
        with self._init_lock:
            if self.session in self._initialized:
                return

        try:
            self._tmux(["has-session", "-t", self.session], timeout=5)
            session_exists = True
        except RuntimeError:
            session_exists = False

        if not session_exists:
            logger.info(f"Creating tmux session: {self.session}")
            try:
                self._tmux(["new-session", "-d", "-s", self.session, "bash --noprofile --norc"])
                # Increase scrollback buffer history
                self._tmux(["set-option", "-t", self.session, "history-limit", "50000"])
            except RuntimeError as e:
                if "duplicate session" not in str(e):
                    raise
                logger.debug(f"Session {self.session} exists (race), reusing it.")
            time.sleep(0.3)

        # Inject the Bash prompt marker used for command-completion detection.
        # If an old session was started in fish/zsh, move it into a clean Bash shell first.
        self._install_prompt_marker()
        if not PS1_PATTERN.search(self._capture()):
            logger.warning(f"Session {self.session} did not accept Bash prompt marker; switching to bash")
            self._tmux(["send-keys", "-t", self.session, "C-c"])
            time.sleep(0.2)
            self._send("exec bash --noprofile --norc")
            time.sleep(0.5)
            self._install_prompt_marker()

        with self._init_lock:
            self._initialized.add(self.session)

    def execute(self, command: str, is_input: bool = False, timeout: int = 120) -> str:
        """
        Execute command and poll for completion marker.
        Auto-detects interactive prompts if the shell stalls.
        """
        if not is_input:
            self.initialize()

        try:
            baseline = self._capture()
        except RuntimeError as e:
            error_msg = str(e)
            if "no server" in error_msg or "session not found" in error_msg:
                logger.warning(f"Session '{self.session}' is dead. Attempting recovery...")
                with self._init_lock:
                    self._initialized.discard(self.session)
                try:
                    self.initialize()
                    baseline = self._capture()
                except RuntimeError as retry_err:
                    return f"[ERROR] Session recovery failed: {retry_err}"
            else:
                return f"[ERROR] Tmux error: {e}"

        initial_count = len(PS1_PATTERN.findall(baseline))

        if command:
            if is_input:
                if command in ("C-c", "C-z", "C-d"):
                    self._tmux(["send-keys", "-t", self.session, command])
                else:
                    self._send(command, enter=True)
            else:
                self._send(command, enter=True)

        start = time.time()
        prev_screen = baseline
        last_change_time = start

        while time.time() - start < timeout:
            time.sleep(POLL_INTERVAL)
            try:
                screen = self._capture()
            except RuntimeError as poll_err:
                if "no server" in str(poll_err) or "session not found" in str(poll_err):
                    with self._init_lock:
                        self._initialized.discard(self.session)
                    return f"[ERROR] tmux session '{self.session}' was destroyed mid-command (did you exit?)."
                continue

            current_count = len(PS1_PATTERN.findall(screen))

            if current_count > initial_count:
                # Command finished normally
                output, exit_code, cwd = _extract_output(screen, command, initial_count)
                logger.info(f"Command completed: exit={exit_code} cwd={cwd} [{command[:50]}]")
                self._clear_screen()
                result = _truncate(output).strip()
                hint = _interpret_exit_code(exit_code)
                
                if not result:
                    result = f"[Command completed with no output. Exit code: {exit_code}{hint}]"
                elif exit_code != 0:
                    result += f"\n[Exit code: {exit_code}{hint}]"
                if cwd:
                    result += f"\n[cwd: {cwd}]"
                return result

            # Size watchdog
            if len(screen) > SIZE_WATCHDOG_CHARS:
                logger.warning(f"Size watchdog triggered ({len(screen)} chars) \u2014 killing session [{command[:50]}]")
                try:
                    self._tmux(["send-keys", "-t", self.session, "C-c"])
                except RuntimeError:
                    pass
                output = _extract_interactive_output(screen, baseline)
                return (
                    f"{_truncate(output).strip()}\n\n"
                    f"[SIZE LIMIT] Output exceeded limit. Command interrupted via C-c.\n"
                    f"Redirect output to a file if large outputs are expected."
                )

            # Auto-backgrounding for long-running non-interactive
            elapsed = time.time() - start
            if elapsed >= AUTO_BACKGROUND_SECONDS and command and not is_input:
                logger.info(f"Auto-backgrounding after {int(elapsed)}s: {command[:50]}")
                output = _extract_interactive_output(screen, baseline)
                preview = _truncate(output).strip()
                return (
                    f"[AUTO-BACKGROUND] Command running >{int(AUTO_BACKGROUND_SECONDS)}s in session '{self.session}'.\n"
                    f"--- partial output ---\n{preview[-1000:] if preview else '(no output yet)'}\n"
                    f"--- end ---\n"
                    f"Agent may proceed with other objectives. Check later using read_screen()."
                )

            # Stall detection for interactive prompts
            if screen != prev_screen:
                last_change_time = time.time()
                prev_screen = screen
            elif screen != baseline and time.time() - last_change_time >= STALL_SECONDS:
                logger.info(f"Stall detected after {time.time() - start:.1f}s \u2014 interactive program suspected")
                output = _extract_interactive_output(screen, baseline)
                return (
                    f"{_truncate(output).strip()}\n"
                    f"[session: {self.session} \u2014 interactive prompt detected, send next command with is_input=True]"
                )

        # Full timeout reached
        try:
            final_screen = self._capture()
        except RuntimeError:
            final_screen = ""
        screen_tail = "\n".join(final_screen.strip().split("\n")[-20:])
        
        return (
            f"[TIMEOUT] Command exceeded {timeout}s limit.\n"
            f"Session '{self.session}' is still running in background.\n"
            f"--- screen preview ---\n{screen_tail}"
        )

    def read_screen(self) -> str:
        """Read the absolute current state of the screen without sending commands."""
        self.initialize()
        screen = self._capture()
        matches = list(PS1_PATTERN.finditer(screen))
        if matches:
            last = matches[-1]
            exit_code = int(last.group(1))
            cwd = last.group(2)
            recent = screen[last.end():].strip()
            if recent:
                return f"[RUNNING/PROMPT] cwd={cwd}\n{_truncate(recent)}"
            return f"[IDLE] exit_code={exit_code} cwd={cwd}\nSession is ready for commands."
        return f"[UNKNOWN INTERACTIVE STATE]\n{screen[-2000:]}"
