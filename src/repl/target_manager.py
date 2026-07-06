"""
Target Session Manager - Organize logs by target
Creates folders for each target with detailed txt logs
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from loguru import logger


def _bootstrap_planner_from_profile(target: str | None) -> None:
    """
    Seed the in-memory AttackPlanner with data already stored in profile.json.

    Called once at the start of every session so that attack_summary() reflects
    real historical findings instead of always showing zeros.

    Safe to call even when the profile has no data or the planner/profile
    modules are unavailable — all errors are silently swallowed.
    """
    if not target:
        return
    try:
        from src.repl.profiles import get_profile_manager
        from src.sdk.attack_planner import get_attack_planner, reset_attack_planner, Vulnerability

        # Always reset first — ensures switching targets never bleeds stale data
        reset_attack_planner()

        pm = get_profile_manager()
        profile = pm.load_profile(target)
        planner = get_attack_planner()

        # ── Ports / services ────────────────────────────────────────────────
        for p in profile.ports:
            try:
                port_num = int(p.get("port", 0))
                service = p.get("service", "")
                version = p.get("version", "")
                if port_num and service:
                    planner.add_service(port_num, service, version)
            except Exception:
                pass

        # ── Vulnerabilities ─────────────────────────────────────────────────
        for v in profile.vulnerabilities:
            try:
                vuln = Vulnerability(
                    name=v.get("name", "Unknown"),
                    severity=v.get("severity", "info"),
                    cve=v.get("cve") or None,
                    exploitable=v.get("verified", False),
                )
                planner.add_vulnerability(vuln)
            except Exception:
                pass

        loaded_ports = len(profile.ports)
        loaded_vulns = len(profile.vulnerabilities)
        if loaded_ports or loaded_vulns:
            logger.info(
                f"[bootstrap] AttackPlanner seeded from profile: "
                f"{loaded_ports} port(s), {loaded_vulns} vuln(s) for {target}"
            )
    except Exception as e:
        logger.debug(f"_bootstrap_planner_from_profile failed (non-fatal): {e}")



class TargetSessionManager:
    """
    Manages organized session logs per target.
    Creates: ./targets/<target_name>/<session_timestamp>/
    """
    
    def __init__(self, base_dir: str = "./targets"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.current_target: Optional[str] = None
        self.session_dir: Optional[Path] = None
        self.session_start: Optional[datetime] = None
        
        # File handles
        self.input_file: Optional[Path] = None
        self.output_file: Optional[Path] = None
        self.tools_file: Optional[Path] = None
        self.summary_file: Optional[Path] = None
        
        # Counters
        self.input_count = 0
        self.output_count = 0
        self.tool_count = 0
    
    def _sanitize_target(self, target: str) -> str:
        """Sanitize target name for folder creation."""
        # Remove protocol
        target = re.sub(r'^https?://', '', target)
        # Replace invalid chars but allow / for categories (e.g. CTF_challs/mybin)
        target = re.sub(r'[^\w\-./]', '_', target)
        return target[:100]  # Increased limit for nested paths
    
    def start_session(self, target: str, agent_name: str = "Orchestrator") -> Path:
        """
        Start a new session for a target.
        
        Args:
            target: Target domain/IP
            agent_name: Agent being used
        
        Returns:
            Path to session directory
        """
        self.session_start = datetime.now()
        
        # Check if target is an existing local directory
        target_path = Path(target)
        if target_path.exists() and target_path.is_dir():
            target_dir = target_path
            self.current_target = str(target_path.absolute())
        else:
            self.current_target = target
            # Create target folder
            target_safe = self._sanitize_target(target)
            target_dir = self.base_dir / target_safe
            target_dir.mkdir(parents=True, exist_ok=True)
        
        # Create session folder with timestamp
        timestamp = self.session_start.strftime("%Y%m%d_%H%M%S")
        self.session_dir = target_dir / f"session_{timestamp}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize log files
        self.input_file = self.session_dir / "user_inputs.txt"
        self.output_file = self.session_dir / "agent_outputs.txt"
        self.tools_file = self.session_dir / "tool_calls.txt"
        self.summary_file = self.session_dir / "summary.txt"
        
        # Reset counters
        self.input_count = 0
        self.output_count = 0
        self.tool_count = 0
        
        # Write session header
        header = f"""{'='*60}
CYBER-COPILOT SESSION LOG
{'='*60}
Target: {target}
Agent: {agent_name}
Started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}
Session ID: {timestamp}
{'='*60}

"""
        for f in [self.input_file, self.output_file, self.tools_file]:
            with open(f, 'w', encoding='utf-8') as file:
                file.write(header)
        
        logger.info(f"Session started: {self.session_dir}")

        # ── Bootstrap AttackPlanner from persisted profile ──────────────────
        # The AttackPlanner is RAM-only and starts empty every process launch.
        # Load whatever profile.json already knows so attack_summary() shows
        # real data from the very first query of a new session.
        _bootstrap_planner_from_profile(self.current_target)

        return self.session_dir
    
    def log_input(self, message: str):
        """Log user input."""
        if not self.input_file:
            return
        
        self.input_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        entry = f"""
[{timestamp}] INPUT #{self.input_count}
{'-'*40}
{message}
{'-'*40}

"""
        with open(self.input_file, 'a', encoding='utf-8') as f:
            f.write(entry)
    
    def log_output(self, response: str, tool_calls: int = 0):
        """Log agent output."""
        if not self.output_file:
            return
        
        self.output_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        entry = f"""
[{timestamp}] OUTPUT #{self.output_count} (Tools used: {tool_calls})
{'='*60}
{response}
{'='*60}

"""
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write(entry)
    
    def log_tool_call(self, tool_name: str, args: dict, result: str):
        """Log tool execution summary to tool_calls.txt index."""
        if not self.tools_file:
            return
        
        self.tool_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Truncate long results for the index file
        result = result or ""  # coerce None → empty string
        result_preview = result[:10000] if result else "No output"
        if len(result) > 10000:
            result_preview += f"\n... [truncated, {len(result)} total chars]"
        
        entry = f"""
[{timestamp}] TOOL #{self.tool_count}: {tool_name}
{'-'*40}
Arguments: {args}
{'-'*40}
Result:
{result_preview}
{'='*60}

"""
        with open(self.tools_file, 'a', encoding='utf-8') as f:
            f.write(entry)

    def save_tool_output(self, tool_name: str, args: dict, result: str) -> Optional[Path]:
        """Save full untruncated tool output to a dedicated file in tools/ subfolder."""
        if not self.session_dir:
            return None

        tools_dir = self.session_dir / "tools"
        tools_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%H%M%S")
        filename = f"{self.tool_count:03d}_{tool_name}_{timestamp}.txt"
        filepath = tools_dir / filename

        header = f"""{'='*60}
TOOL: {tool_name}
{'='*60}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Tool #: {self.tool_count}
Arguments: {args}
{'='*60}
OUTPUT:
{'-'*60}
"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(result or "No output")

        return filepath

    def get_session_downloads_dir(self) -> Optional[Path]:
        """Return (and create) the downloads/ subfolder for the active session."""
        if not self.session_dir:
            return None
        d = self.session_dir / "downloads"
        d.mkdir(exist_ok=True)
        return d

    def get_session_exploits_dir(self) -> Optional[Path]:
        """Return (and create) the exploits/ subfolder for the active session."""
        if not self.session_dir:
            return None
        d = self.session_dir / "exploits"
        d.mkdir(exist_ok=True)
        return d

    def get_session_files_dir(self, subfolder: str = "files") -> Optional[Path]:
        """Return (and create) a named subfolder inside the active session directory."""
        if not self.session_dir:
            return None
        d = self.session_dir / subfolder
        d.mkdir(exist_ok=True)
        return d

    def get_js_dir(self) -> Optional[Path]:
        """Return (and create) the js/ subfolder for downloaded JS files."""
        if not self.session_dir:
            return None
        d = self.session_dir / "js"
        d.mkdir(exist_ok=True)
        return d

    def save_subdomains(self, subdomains: list) -> Optional[Path]:
        """
        Persist a list of subdomains to session_dir/subdomains.txt.
        Merges with any previously saved entries (deduplicates and sorts).
        Returns the file path on success, None if no session is active.
        """
        if not self.session_dir:
            return None
        filepath = self.session_dir / "subdomains.txt"
        existing: set = set()
        if filepath.exists():
            existing = set(filepath.read_text(encoding="utf-8").splitlines())
        all_subs = sorted(existing | set(s.strip() for s in subdomains if s.strip()))
        filepath.write_text("\n".join(all_subs), encoding="utf-8")
        return filepath

    def get_subdomains_file(self) -> Optional[Path]:
        """Return the subdomains.txt path if it exists for the active session."""
        if not self.session_dir:
            return None
        fp = self.session_dir / "subdomains.txt"
        return fp if fp.exists() else None

    def end_session(self) -> dict:
        """End session and write summary."""
        if not self.session_dir:
            return {}
        
        end_time = datetime.now()
        duration = end_time - self.session_start if self.session_start else None
        
        # --- NEW: Save to Cross-Session Memory ---
        if self.current_target:
            try:
                from src.sdk.memory import get_session_memory
                get_session_memory().save_session_findings(self.current_target)
            except Exception as e:
                logger.debug(f"TargetManager: memory snapshot failed: {e}")
        
        summary = {
            "target": self.current_target,
            "session_dir": str(self.session_dir),
            "started": self.session_start.isoformat() if self.session_start else None,
            "ended": end_time.isoformat(),
            "duration_seconds": duration.total_seconds() if duration else 0,
            "total_inputs": self.input_count,
            "total_outputs": self.output_count,
            "total_tool_calls": self.tool_count
        }
        
        # Write summary file
        summary_content = f"""{'='*60}
SESSION SUMMARY
{'='*60}
Target: {self.current_target}
Session Directory: {self.session_dir}

Started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S') if self.session_start else 'N/A'}
Ended: {end_time.strftime('%Y-%m-%d %H:%M:%S')}
Duration: {duration if duration else 'N/A'}

STATISTICS
{'-'*40}
User Inputs: {self.input_count}
Agent Outputs: {self.output_count}
Tool Calls: {self.tool_count}

FILES
{'-'*40}
- user_inputs.txt: All user queries
- agent_outputs.txt: All agent responses
- tool_calls.txt: Detailed tool execution logs
- summary.txt: This file

{'='*60}
Generated by Cyber-CoPilot
"""
        
        if self.summary_file:
            with open(self.summary_file, 'w', encoding='utf-8') as f:
                f.write(summary_content)
        
        logger.info(f"Session ended: {self.session_dir}")
        return summary
    
    def get_target_history(self, target: str) -> list:
        """Get all sessions for a target."""
        target_safe = self._sanitize_target(target)
        target_dir = self.base_dir / target_safe
        
        if not target_dir.exists():
            return []
        
        sessions = []
        for session_dir in sorted(target_dir.iterdir(), reverse=True):
            if session_dir.is_dir() and session_dir.name.startswith("session_"):
                summary_file = session_dir / "summary.txt"
                sessions.append({
                    "path": str(session_dir),
                    "name": session_dir.name,
                    "has_summary": summary_file.exists()
                })
        
        return sessions


# Global instance
_target_manager: Optional[TargetSessionManager] = None


def get_target_manager() -> TargetSessionManager:
    """Get or create the global target session manager."""
    global _target_manager
    if _target_manager is None:
        _target_manager = TargetSessionManager()
    return _target_manager
