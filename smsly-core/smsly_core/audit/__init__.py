"""
Audit Logging Module
====================
Append-only, tamper-evident audit trail with hash chaining.
Includes fail-closed middleware for mandatory auditing.
"""

# Re-export all public APIs for backwards compatibility
from .event_types import AuditEventType
from .models import AuditEvent
from .hashing import compute_event_hash, verify_chain_integrity
from .logger import AuditLogger
from .middleware import MandatoryAuditMiddleware, get_audit_client, MandatoryAuditClient

__all__ = [
    # Event Types
    "AuditEventType",
    # Models
    "AuditEvent",
    # Hashing
    "compute_event_hash",
    "verify_chain_integrity",
    # Logger
    "AuditLogger",
    # Middleware
    "MandatoryAuditMiddleware",
    "get_audit_client",
    "MandatoryAuditClient",
]
