"""
Django Audit Middleware — integrates audit logging into the Backend request lifecycle.

Wires into Django's middleware stack to emit audit events at:
  - Phase 1 (Ingress): api.request_start
  - Phase 6 (Response): api.request_complete

Business operations are NEVER blocked by audit failures (fail-open with fallback).

The middleware also exposes a thread-safe sync wrapper around the async
AuditClient for use in Django views, signals, and model save() hooks.

Usage (settings.py):
    MIDDLEWARE = [
        ...
        "audit.integration.django_audit_middleware.DjangoAuditMiddleware",
        ...
    ]

Then in views:
    from audit.integration.django_audit_middleware import audit_log

    audit_log("sms.sent", message_id, actor_id=user.id, category="messaging")
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import threading
from typing import Any, Callable, Dict, Optional

from .audit_client import AuditClient, get_audit_client
from .events import Category, Outcome, Severity

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

SERVICE_NAME = os.getenv("SERVICE_NAME", "smsly-backend")

SKIP_PATHS = frozenset({
    "/health", "/ready", "/metrics", "/admin/jsi18n/",
    "/static/", "/favicon.ico",
})
SKIP_PREFIXES = ("/api/v1/audit", "/v1/health", "/v1/ready")

# ============================================================================
# Thread-safe async bridge
# ============================================================================

_event_loop: Optional[asyncio.AbstractEventLoop] = None
_loop_lock = threading.Lock()


def _get_event_loop() -> asyncio.AbstractEventLoop:
    """Get or create a background event loop for sync callers."""
    global _event_loop
    with _loop_lock:
        if _event_loop is None or _event_loop.is_closed():
            _event_loop = asyncio.new_event_loop()
            thread = threading.Thread(target=_event_loop.run_forever, daemon=True)
            thread.start()
        return _event_loop


def _run_async(coro):
    """Run an async coroutine from sync code (Django views, signals)."""
    loop = _get_event_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout=5.0)
    except Exception as e:
        logger.warning("audit_async_bridge_failed", error=str(e))
        return False


# ============================================================================
# Sync audit logging helper (for Django views / signals)
# ============================================================================

def audit_log(
    event_type: str,
    resource_id: str,
    *,
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Outcome = Outcome.SUCCESS,
    category: Category = Category.GENERAL,
    severity: Severity = Severity.INFO,
    ip_address: Optional[str] = None,
    request_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    pii_accessed: bool = False,
) -> bool:
    """
    Synchronous audit logging for Django code paths.

    Non-blocking: returns False on failure, never raises in production.
    """
    client = get_audit_client()
    return _run_async(
        client.log(
            event_type=event_type,
            resource_id=resource_id,
            actor_id=actor_id,
            resource_type=resource_type,
            action=action,
            outcome=outcome,
            category=category,
            severity=severity,
            ip_address=ip_address,
            request_id=request_id,
            payload=payload,
            pii_accessed=pii_accessed,
            fail_closed=False,
        )
    )


# ============================================================================
# Django Middleware
# ============================================================================

class DjangoAuditMiddleware:
    """
    Django middleware that emits audit events at ingress and egress.

    Lifecycle wiring:
      Phase 1 (Ingress):  emit api.request_start
      Phase 6 (Response): emit api.request_complete

    Audit failures NEVER block the request (fail-open + local fallback).
    """

    def __init__(self, get_response: Callable):
        self.get_response = get_response
        self._client: Optional[AuditClient] = None

    def __call__(self, request):
        # Skip system paths
        path = request.path
        if path in SKIP_PATHS or any(path.startswith(p) for p in SKIP_PREFIXES):
            return self.get_response(request)

        request_id = request.headers.get("X-Request-ID", "")
        actor_id = self._extract_actor_id(request)
        ip_address = self._extract_ip(request)
        start_time = time.perf_counter()

        # --- Phase 1: Ingress audit (non-blocking) ---
        self._emit(
            event_type="api.request_start",
            action=f"{request.method} {path}",
            request_id=request_id,
            actor_id=actor_id,
            resource_type="api",
            resource_id=path,
            outcome=Outcome.PENDING,
            ip_address=ip_address,
            payload={
                "method": request.method,
                "path": path,
                "query": request.META.get("QUERY_STRING", ""),
            },
        )

        # --- Execute request (always proceeds) ---
        status_code = 500
        try:
            response = self.get_response(request)
            status_code = response.status_code
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            # --- Phase 6: Response audit (non-blocking) ---
            latency_ms = (time.perf_counter() - start_time) * 1000
            self._emit(
                event_type="api.request_complete",
                action=f"{request.method} {path}",
                request_id=request_id,
                actor_id=actor_id,
                resource_type="api",
                resource_id=path,
                outcome=Outcome.SUCCESS if status_code < 400 else Outcome.FAILURE,
                severity=Severity.INFO if status_code < 400 else Severity.WARNING,
                ip_address=ip_address,
                payload={
                    "status_code": status_code,
                    "latency_ms": round(latency_ms, 2),
                },
            )

    def _emit(self, **kwargs):
        """Best-effort emit — never blocks the request."""
        try:
            client = self._ensure_client()
            _run_async(client.log(**kwargs, fail_closed=False))
        except Exception as e:
            logger.debug("audit_middleware_emit_failed", error=str(e))

    def _ensure_client(self) -> AuditClient:
        if self._client is None:
            self._client = get_audit_client()
        return self._client

    @staticmethod
    def _extract_actor_id(request) -> Optional[str]:
        user = getattr(request, "user", None)
        if user and hasattr(user, "id") and user.is_authenticated:
            return str(user.id)
        return request.headers.get("X-Smsly-Account-Id")

    @staticmethod
    def _extract_ip(request) -> Optional[str]:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")


# Backward compat alias
DjangoResilientAuditMiddleware = DjangoAuditMiddleware
