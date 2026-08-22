"""
SMSLYCLOUD Audit Integration — shared audit client and middleware.

Provides:
    - AuditClient: async batched gRPC client with circuit breaker + fallback
    - DjangoAuditMiddleware: Django middleware for request lifecycle audit
    - FastAPIAuditMiddleware: FastAPI/Starlette middleware for request lifecycle audit
    - Pydantic event schemas matching the proto AuditEvent definition
"""

from .audit_client import AuditClient, AuditUnavailableError, get_audit_client
from .django_audit_middleware import DjangoAuditMiddleware, audit_log as django_audit_log
from .fastapi_audit_middleware import FastAPIAuditMiddleware, audit_log as fastapi_audit_log
from .events import (
    AuditEvent,
    AuditEventBatch,
    BatchResult,
    Category,
    Outcome,
    Severity,
    make_event,
)

__all__ = [
    "AuditClient",
    "AuditUnavailableError",
    "get_audit_client",
    "DjangoAuditMiddleware",
    "django_audit_log",
    "FastAPIAuditMiddleware",
    "fastapi_audit_log",
    "AuditEvent",
    "AuditEventBatch",
    "BatchResult",
    "Category",
    "Outcome",
    "Severity",
    "make_event",
]
