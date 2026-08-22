"""
FastAPI Audit Middleware — integrates audit logging into the request lifecycle.

Wires into FastAPI/Starlette middleware stack to emit audit events at:
  - Phase 1 (Ingress): api.request_start
  - Phase 6 (Response): api.request_complete

Business operations are NEVER blocked by audit failures (fail-open with fallback).

Usage (main.py):
    from audit.integration.fastapi_audit_middleware import FastAPIAuditMiddleware

    app = FastAPI()
    app.add_middleware(FastAPIAuditMiddleware)

Then in route handlers:
    from audit.integration.fastapi_audit_middleware import audit_log

    await audit_log("sms.sent", message_id, actor_id=user_id, category="messaging")
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .audit_client import get_audit_client
from .events import Category, Outcome, Severity

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")

SKIP_PATHS = frozenset({"/health", "/ready", "/metrics", "/docs", "/openapi.json"})
SKIP_PREFIXES = ("/api/v1/audit", "/v1/health", "/v1/ready")


# ============================================================================
# Async audit logging helper (for FastAPI route handlers / dependencies)
# ============================================================================

async def audit_log(
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
    Async audit logging for FastAPI route handlers.

    Non-blocking: returns False on failure, never raises in production.
    """
    client = get_audit_client()
    return await client.log(
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


# ============================================================================
# FastAPI Middleware
# ============================================================================

class FastAPIAuditMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware that emits audit events at ingress and egress.

    Lifecycle wiring:
      Phase 1 (Ingress):  emit api.request_start
      Phase 6 (Response): emit api.request_complete

    Audit failures NEVER block the request (fail-open + local fallback).
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip system paths
        path = request.url.path
        if path in SKIP_PATHS or any(path.startswith(p) for p in SKIP_PREFIXES):
            return await call_next(request)

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        actor_id = request.headers.get("X-Smsly-Account-Id")
        ip_address = request.client.host if request.client else None
        start_time = time.perf_counter()

        client = get_audit_client()

        # --- Phase 1: Ingress audit (non-blocking) ---
        try:
            await client.log(
                event_type="api.request_start",
                resource_id=path,
                actor_id=actor_id,
                resource_type="api",
                action=f"{request.method} {path}",
                outcome=Outcome.PENDING,
                request_id=request_id,
                ip_address=ip_address,
                payload={
                    "method": request.method,
                    "path": path,
                    "query": str(request.query_params),
                },
                fail_closed=False,
            )
        except Exception as e:
            logger.debug("audit_ingress_emit_failed", error=str(e))

        # --- Execute request (always proceeds) ---
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            # --- Phase 6: Response audit (non-blocking) ---
            latency_ms = (time.perf_counter() - start_time) * 1000
            try:
                await client.log(
                    event_type="api.request_complete",
                    resource_id=path,
                    actor_id=actor_id,
                    resource_type="api",
                    action=f"{request.method} {path}",
                    outcome=Outcome.SUCCESS if status_code < 400 else Outcome.FAILURE,
                    severity=Severity.INFO if status_code < 400 else Severity.WARNING,
                    request_id=request_id,
                    ip_address=ip_address,
                    payload={
                        "status_code": status_code,
                        "latency_ms": round(latency_ms, 2),
                    },
                    fail_closed=False,
                )
            except Exception as e:
                logger.debug("audit_egress_emit_failed", error=str(e))


# Backward compat alias
ResilientAuditMiddleware = FastAPIAuditMiddleware
