"""Compatibility exports for legacy HTTP smuggling imports."""

from .http_smuggling import (
    http_smuggling_exploit,
    http_smuggling_scanner,
    request_smuggling_probe,
    smuggling_cl0,
    smuggling_h2_downgrade,
    smuggling_poison_request,
    smuggling_te0,
)

__all__ = [
    "http_smuggling_exploit",
    "http_smuggling_scanner",
    "request_smuggling_probe",
    "smuggling_cl0",
    "smuggling_h2_downgrade",
    "smuggling_poison_request",
    "smuggling_te0",
]
