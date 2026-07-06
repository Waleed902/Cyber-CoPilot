"""
Enhanced Error Handling and Logging

Provides structured error handling with proper logging, stack traces,
and recovery strategies.
"""

import traceback
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass
from enum import Enum
from loguru import logger
from functools import wraps


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for better classification."""
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PERMISSION = "permission"
    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_EXECUTION = "tool_execution"
    API_ERROR = "api_error"
    RATE_LIMIT = "rate_limit"
    CONTEXT_OVERFLOW = "context_overflow"
    VALIDATION = "validation"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    UNKNOWN = "unknown"


@dataclass
class StructuredError:
    """Structured error with context and recovery information."""
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    original_exception: Optional[Exception]
    stack_trace: str
    context: Dict[str, Any]
    recovery_suggestion: str
    user_message: str  # User-friendly message
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging/serialization."""
        return {
            'category': self.category.value,
            'severity': self.severity.value,
            'message': self.message,
            'exception_type': type(self.original_exception).__name__ if self.original_exception else None,
            'stack_trace': self.stack_trace,
            'context': self.context,
            'recovery_suggestion': self.recovery_suggestion,
            'user_message': self.user_message
        }


class ErrorHandler:
    """
    Centralized error handling with structured logging and recovery.
    """
    
    # Exception type to category mapping
    EXCEPTION_CATEGORIES = {
        ConnectionError: ErrorCategory.NETWORK,
        TimeoutError: ErrorCategory.NETWORK,
        PermissionError: ErrorCategory.PERMISSION,
        FileNotFoundError: ErrorCategory.TOOL_NOT_FOUND,
        ValueError: ErrorCategory.VALIDATION,
        KeyError: ErrorCategory.CONFIGURATION,
    }
    
    def __init__(self):
        self.error_history: list[StructuredError] = []
        self.error_counts: Dict[ErrorCategory, int] = {}
    
    def handle_error(
        self,
        exception: Exception,
        context: Dict[str, Any] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        user_message: Optional[str] = None
    ) -> StructuredError:
        """
        Handle an exception with structured logging.
        
        Args:
            exception: The exception to handle
            context: Additional context (tool name, args, etc.)
            severity: Error severity level
            user_message: Optional user-friendly message
        
        Returns:
            StructuredError with full details
        """
        # Classify the error
        category = self._classify_error(exception)
        
        # Get stack trace
        stack_trace = ''.join(traceback.format_exception(
            type(exception), exception, exception.__traceback__
        ))
        
        # Generate recovery suggestion
        recovery_suggestion = self._get_recovery_suggestion(category, exception)
        
        # Generate user-friendly message
        if not user_message:
            user_message = self._generate_user_message(category, exception)
        
        # Create structured error
        structured_error = StructuredError(
            category=category,
            severity=severity,
            message=str(exception),
            original_exception=exception,
            stack_trace=stack_trace,
            context=context or {},
            recovery_suggestion=recovery_suggestion,
            user_message=user_message
        )
        
        # Log appropriately based on severity
        self._log_error(structured_error)
        
        # Track error
        self.error_history.append(structured_error)
        self.error_counts[category] = self.error_counts.get(category, 0) + 1
        
        return structured_error
    
    def _classify_error(self, exception: Exception) -> ErrorCategory:
        """Classify an exception into a category."""
        # Check exact type match
        exc_type = type(exception)
        if exc_type in self.EXCEPTION_CATEGORIES:
            return self.EXCEPTION_CATEGORIES[exc_type]
        
        # Check message patterns
        msg = str(exception).lower()
        
        if any(word in msg for word in ['network', 'connection', 'timeout', 'unreachable']):
            return ErrorCategory.NETWORK
        
        if any(word in msg for word in ['auth', 'unauthorized', 'forbidden', 'api key', 'token']):
            return ErrorCategory.AUTHENTICATION
        
        if any(word in msg for word in ['permission', 'denied', 'access']):
            return ErrorCategory.PERMISSION
        
        if any(word in msg for word in ['not found', 'command not found', 'no such file']):
            return ErrorCategory.TOOL_NOT_FOUND
        
        if any(word in msg for word in ['rate limit', '429', 'too many requests']):
            return ErrorCategory.RATE_LIMIT
        
        if any(word in msg for word in ['context', 'token limit', 'too long']):
            return ErrorCategory.CONTEXT_OVERFLOW
        
        if any(word in msg for word in ['database', 'chroma', 'sqlite']):
            return ErrorCategory.DATABASE
        
        return ErrorCategory.UNKNOWN
    
    def _get_recovery_suggestion(self, category: ErrorCategory, exception: Exception) -> str:
        """Generate recovery suggestion based on error category."""
        suggestions = {
            ErrorCategory.NETWORK: (
                "Check network connectivity. Verify target is reachable. "
                "Consider increasing timeout or using a proxy."
            ),
            ErrorCategory.AUTHENTICATION: (
                "Verify API key is valid and has not expired. "
                "Check environment variables are set correctly."
            ),
            ErrorCategory.PERMISSION: (
                "Run with appropriate permissions. Some tools require root/admin access. "
                "Check file permissions if accessing local files."
            ),
            ErrorCategory.TOOL_NOT_FOUND: (
                "Install the required tool. Run 'bash install_tools.sh' or "
                "install the specific tool manually. Check PATH environment variable."
            ),
            ErrorCategory.RATE_LIMIT: (
                "Wait before retrying. Consider switching to a different API key. "
                "Reduce request frequency or use caching."
            ),
            ErrorCategory.CONTEXT_OVERFLOW: (
                "Context window exceeded. The conversation will be automatically trimmed. "
                "Consider starting a new session or using a model with larger context."
            ),
            ErrorCategory.DATABASE: (
                "Database error occurred. Try resetting the database with --reset-db flag. "
                "Check disk space and file permissions."
            ),
            ErrorCategory.VALIDATION: (
                "Input validation failed. Check that all required parameters are provided "
                "and in the correct format."
            ),
            ErrorCategory.CONFIGURATION: (
                "Configuration error. Check .env file and configuration settings. "
                "Ensure all required environment variables are set."
            ),
        }
        
        return suggestions.get(category, "Review error details and try an alternative approach.")
    
    def _generate_user_message(self, category: ErrorCategory, exception: Exception) -> str:
        """Generate user-friendly error message."""
        messages = {
            ErrorCategory.NETWORK: f"Network error: Unable to reach target. {str(exception)[:100]}",
            ErrorCategory.AUTHENTICATION: "Authentication failed. Please check your API key.",
            ErrorCategory.PERMISSION: "Permission denied. This operation requires elevated privileges.",
            ErrorCategory.TOOL_NOT_FOUND: "Required tool not found. Please install it first.",
            ErrorCategory.RATE_LIMIT: "Rate limit reached. Please wait before retrying.",
            ErrorCategory.CONTEXT_OVERFLOW: "Context limit exceeded. Trimming conversation history.",
            ErrorCategory.DATABASE: "Database error occurred. Consider resetting the database.",
        }
        
        return messages.get(category, f"Error: {str(exception)[:150]}")
    
    def _log_error(self, error: StructuredError):
        """Log error with appropriate level."""
        log_data = error.to_dict()
        
        if error.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"[{error.category.value}] {error.message}", extra=log_data)
            logger.critical(f"Stack trace:\n{error.stack_trace}")
        elif error.severity == ErrorSeverity.HIGH:
            logger.error(f"[{error.category.value}] {error.message}", extra=log_data)
            logger.debug(f"Stack trace:\n{error.stack_trace}")
        elif error.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"[{error.category.value}] {error.message}")
            logger.debug(f"Stack trace:\n{error.stack_trace}")
        else:
            logger.info(f"[{error.category.value}] {error.message}")
    
    def get_error_summary(self) -> Dict:
        """Get summary of all errors."""
        return {
            'total_errors': len(self.error_history),
            'by_category': dict(self.error_counts),
            'recent_errors': [
                {
                    'category': e.category.value,
                    'severity': e.severity.value,
                    'message': e.message,
                    'user_message': e.user_message
                }
                for e in self.error_history[-10:]
            ]
        }


def safe_execute(
    func: Callable,
    *args,
    error_handler: Optional[ErrorHandler] = None,
    context: Optional[Dict] = None,
    default_return: Any = None,
    **kwargs
) -> Any:
    """
    Safely execute a function with error handling.
    
    Args:
        func: Function to execute
        *args: Positional arguments
        error_handler: Optional ErrorHandler instance
        context: Additional context for error logging
        default_return: Value to return on error
        **kwargs: Keyword arguments
    
    Returns:
        Function result or default_return on error
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        if error_handler:
            structured_error = error_handler.handle_error(
                e,
                context=context or {'function': func.__name__}
            )
            logger.error(f"Safe execute failed: {structured_error.user_message}")
        else:
            logger.exception(f"Error in {func.__name__}: {e}")
        
        return default_return


def with_error_handling(
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    default_return: Any = None,
    reraise: bool = False
):
    """
    Decorator for automatic error handling.
    
    Args:
        category: Error category
        severity: Error severity
        default_return: Value to return on error
        reraise: Whether to reraise the exception after handling
    
    Example:
        @with_error_handling(category=ErrorCategory.TOOL_EXECUTION, default_return="")
        def my_tool(target: str) -> str:
            # Tool implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handler = get_error_handler()
                context = {
                    'function': func.__name__,
                    'args': str(args)[:200],
                    'kwargs': str(kwargs)[:200]
                }
                
                handler.handle_error(
                    e,
                    context=context,
                    severity=severity
                )
                
                if reraise:
                    raise
                
                return default_return
        
        return wrapper
    return decorator


# Global error handler instance
_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """Get or create the global error handler instance."""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler


def log_exception(
    exception: Exception,
    context: Optional[Dict] = None,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
) -> StructuredError:
    """
    Convenience function to log an exception with full context.
    
    Args:
        exception: The exception to log
        context: Additional context
        severity: Error severity
    
    Returns:
        StructuredError
    """
    return get_error_handler().handle_error(exception, context, severity)
