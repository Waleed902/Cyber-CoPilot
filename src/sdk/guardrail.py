"""
Guardrails: Input/output validation for agents.
"""

from dataclasses import dataclass
from typing import Callable
from loguru import logger
import re


@dataclass
class GuardrailResult:
    """Result of a guardrail check."""
    passed: bool
    message: str = ""
    modified_content: str = None  # If guardrail modifies the content


@dataclass
class Guardrail:
    """
    A guardrail that validates or modifies agent input/output.
    
    Attributes:
        name: Name of the guardrail
        check: Function that validates content, returns GuardrailResult
        on_input: Apply to user input
        on_output: Apply to agent output
    """
    name: str
    check: Callable[[str], GuardrailResult]
    on_input: bool = True
    on_output: bool = True


# Pre-built guardrails

def block_private_ips() -> Guardrail:
    """
    Block scanning of private/internal IP ranges.

    When the ``ScopeManager`` is available it is consulted first so that an
    explicitly in-scope private IP is respected.  Only the hard-coded pattern
    list is used as a fallback when ``ScopeManager`` cannot be imported.
    """
    def check(content: str) -> GuardrailResult:
        # --- Defer to ScopeManager when available ---
        try:
            from src.sdk.scope import check_scope
            allowed, message = check_scope(content)
            if not allowed:
                return GuardrailResult(passed=False, message=message)
            # Explicitly in-scope — don't second-guess with pattern matching.
            return GuardrailResult(passed=True)
        except ImportError:
            pass

        # --- Fallback: simple pattern matching ---
        private_patterns = [
            r'192\.168\.\d{1,3}\.\d{1,3}',
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}',
            r'127\.0\.0\.1',
            r'localhost'
        ]
        for pattern in private_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return GuardrailResult(
                    passed=False,
                    message="Blocked: Private IP detected. Add to scope or use --allow-private to override."
                )
        return GuardrailResult(passed=True)

    return Guardrail(name="block_private_ips", check=check, on_input=True, on_output=False)


def block_dangerous_commands() -> Guardrail:
    """Block potentially dangerous system commands."""
    def check(content: str) -> GuardrailResult:
        dangerous = [
            r'\brm\s+-rf\s+/',
            r'\bmkfs\b',
            r'\bdd\s+if=.*of=/dev/',
            r':(){:|:&};:',  # Fork bomb
            r'\bshutdown\b',
            r'\breboot\b',
        ]
        for pattern in dangerous:
            if re.search(pattern, content, re.IGNORECASE):
                return GuardrailResult(
                    passed=False,
                    message="Blocked: Dangerous command pattern detected."
                )
        return GuardrailResult(passed=True)
    
    return Guardrail(name="block_dangerous", check=check, on_input=True, on_output=True)


def require_authorization() -> Guardrail:
    """Require explicit authorization keywords for exploitation."""
    def check(content: str) -> GuardrailResult:
        exploit_keywords = ['exploit', 'attack', 'hack', 'pwn', 'compromise']
        auth_keywords = ['authorized', 'permission', 'pentest', 'ctf', 'lab']
        
        has_exploit = any(kw in content.lower() for kw in exploit_keywords)
        has_auth = any(kw in content.lower() for kw in auth_keywords)
        
        if has_exploit and not has_auth:
            return GuardrailResult(
                passed=True,  # Warning but don't block
                message="⚠️ Reminder: Only use on authorized targets."
            )
        return GuardrailResult(passed=True)
    
    return Guardrail(name="require_auth", check=check, on_input=True, on_output=False)


def sanitize_output() -> Guardrail:
    """Sanitize sensitive data from output."""
    def check(content: str) -> GuardrailResult:
        # Mask potential passwords/tokens in output
        sanitized = content
        patterns = [
            (r'password[=:]\s*\S+', 'password=***REDACTED***'),
            (r'token[=:]\s*\S+', 'token=***REDACTED***'),
            (r'api_key[=:]\s*\S+', 'api_key=***REDACTED***'),
        ]
        for pattern, replacement in patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        return GuardrailResult(passed=True, modified_content=sanitized)
    
    return Guardrail(name="sanitize_output", check=check, on_input=False, on_output=True)


def max_output_length(max_chars: int = 10000) -> Guardrail:
    """Limit output length to prevent overwhelming responses."""
    def check(content: str) -> GuardrailResult:
        if len(content) > max_chars:
            truncated = content[:max_chars] + f"\n\n... [TRUNCATED - {len(content) - max_chars} chars removed]"
            return GuardrailResult(passed=True, modified_content=truncated)
        return GuardrailResult(passed=True)
    
    return Guardrail(name="max_output", check=check, on_input=False, on_output=True)


def apply_guardrails(content: str, guardrails: list[Guardrail], is_input: bool = True) -> tuple[bool, str, list[str]]:
    """
    Apply a list of guardrails to content.
    
    Returns:
        (passed, content, messages) - Whether all passed, possibly modified content, any messages
    """
    messages = []
    current_content = content
    
    for guardrail in guardrails:
        # Check if guardrail applies
        if is_input and not guardrail.on_input:
            continue
        if not is_input and not guardrail.on_output:
            continue
        
        result = guardrail.check(current_content)
        
        if not result.passed:
            logger.warning(f"Guardrail {guardrail.name} blocked: {result.message}")
            return False, current_content, [result.message]
        
        if result.message:
            messages.append(result.message)
        
        if result.modified_content:
            current_content = result.modified_content
    
    return True, current_content, messages
