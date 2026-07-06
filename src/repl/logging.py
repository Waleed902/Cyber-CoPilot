"""
Session Logging - Auto-log all agent sessions
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from loguru import logger


class SessionLogger:
    """Logs agent sessions to files for later review."""
    
    def __init__(self, log_dir: str = "./sessions"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id: Optional[str] = None
        self.session_file: Optional[Path] = None
        self.entries: list = []
    
    def start_session(self, agent_name: str) -> str:
        """Start a new logging session."""
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_file = self.log_dir / f"session_{self.session_id}_{agent_name}.jsonl"
        self.entries = []
        
        # Write session header
        self._write_entry({
            "type": "session_start",
            "timestamp": datetime.now().isoformat(),
            "agent": agent_name
        })
        
        logger.info(f"Session logging started: {self.session_file}")
        return self.session_id
    
    def log_user_input(self, message: str):
        """Log user input."""
        self._write_entry({
            "type": "user_input",
            "timestamp": datetime.now().isoformat(),
            "content": message
        })
    
    def log_tool_call(self, tool_name: str, args: dict, result: str):
        """Log a tool call."""
        self._write_entry({
            "type": "tool_call",
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "args": args,
            "result": result[:1000] if result else ""  # Truncate long results
        })
    
    def log_agent_response(self, response: str, tool_calls: int = 0):
        """Log agent response."""
        self._write_entry({
            "type": "agent_response",
            "timestamp": datetime.now().isoformat(),
            "content": response,
            "tool_calls": tool_calls
        })
    
    def log_error(self, error: str):
        """Log an error."""
        self._write_entry({
            "type": "error",
            "timestamp": datetime.now().isoformat(),
            "error": error
        })
    
    def end_session(self):
        """End the current session."""
        self._write_entry({
            "type": "session_end",
            "timestamp": datetime.now().isoformat(),
            "total_entries": len(self.entries)
        })
        logger.info(f"Session ended: {len(self.entries)} entries logged")
    
    def _write_entry(self, entry: dict):
        """Write an entry to the session file."""
        self.entries.append(entry)
        if self.session_file:
            with open(self.session_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    
    def get_session_summary(self) -> dict:
        """Get a summary of the current session."""
        tool_calls = sum(1 for e in self.entries if e["type"] == "tool_call")
        user_inputs = sum(1 for e in self.entries if e["type"] == "user_input")
        errors = sum(1 for e in self.entries if e["type"] == "error")
        
        return {
            "session_id": self.session_id,
            "file": str(self.session_file),
            "total_entries": len(self.entries),
            "user_inputs": user_inputs,
            "tool_calls": tool_calls,
            "errors": errors
        }


# Global session logger
_session_logger: Optional[SessionLogger] = None


def get_session_logger() -> SessionLogger:
    """Get or create the global session logger."""
    global _session_logger
    if _session_logger is None:
        _session_logger = SessionLogger()
    return _session_logger
