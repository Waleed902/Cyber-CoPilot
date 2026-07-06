"""
Command Dispatcher for REPL.
Maps user string commands to command handler functions.
"""
from typing import Callable, Dict, Tuple
from .session import global_session

class CommandDispatcher:
    """Dispatches CLI commands to handlers."""
    
    def __init__(self):
        self.handlers: Dict[str, Callable] = {}
        
    def register(self, trigger: str, handler: Callable):
        """Registers a command trigger (e.g., 'scan') to a handler function."""
        self.handlers[trigger] = handler
        
    def dispatch(self, cmd: str) -> Tuple[bool, bool]:
        """
        Takes raw string command and dispatches it.
        Returns (Handled_boolean, Exit_requested_boolean).
        """
        parts = cmd.strip().split()
        if not parts:
            return False, False
            
        parts[0].lower()
        
        # Check longest matches first (e.g. 'scope add')
        for length in range(min(len(parts), 3), 0, -1):
            sub_trigger = " ".join(parts[:length]).lower()
            if sub_trigger in self.handlers:
                args = parts[length:]
                try:
                    # Handler should return True if it wants to exit the REPL
                    wants_exit = self.handlers[sub_trigger](args, global_session)
                    return True, bool(wants_exit)
                except Exception as e:
                    # Safely handle command exceptions here if needed
                    from src.repl.ui import display_error
                    display_error(f"Error handling '{sub_trigger}': {str(e)}")
                    return True, False
                    
        return False, False

# Global Dispatcher instance
dispatcher = CommandDispatcher()
