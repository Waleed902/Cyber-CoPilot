"""Agent primitive – compatibility shim. See src/sdk/core.py."""
from .core import (  # noqa
    Agent,
    BUG_BOUNTY_AUTHORIZATION_SHORT, BUG_BOUNTY_AUTHORIZATION_FULL,
    enable_bug_bounty_mode, is_bug_bounty_mode, get_bug_bounty_preamble,
)
