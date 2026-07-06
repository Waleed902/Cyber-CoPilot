"""
REPL Module - CLI Interface Components
"""

from .ui import (
    display_banner, 
    display_quick_guide, 
    display_agents_table,
    display_response,
    display_target_status,
    display_session_summary,
    display_error,
    display_success,
    display_warning,
    display_info,
    display_tool_execution,
    display_tool_result,
    print_separator,
    get_prompt,
    console
)
from .logging import SessionLogger, get_session_logger
from .parallel import ParallelRunner, ParallelTask, ParallelResult, run_recon_and_websec, run_full_assessment
from .target_manager import TargetSessionManager, get_target_manager
from .profiles import TargetProfile, TargetProfileManager, get_profile_manager
from .reports import ReportGenerator, get_report_generator

__all__ = [
    # UI
    "display_banner",
    "display_quick_guide",
    "display_agents_table",
    "display_response",
    "display_target_status",
    "display_session_summary",
    "display_error",
    "display_success",
    "display_warning",
    "display_info",
    "display_tool_execution",
    "display_tool_result",
    "print_separator",
    "get_prompt",
    "console",
    # Logging
    "SessionLogger",
    "get_session_logger",
    # Target Manager
    "TargetSessionManager",
    "get_target_manager",
    # Profiles
    "TargetProfile",
    "TargetProfileManager",
    "get_profile_manager",
    # Reports
    "ReportGenerator",
    "get_report_generator",
    # Parallel
    "ParallelRunner",
    "ParallelTask",
    "ParallelResult",
    "run_recon_and_websec",
    "run_full_assessment"
]
