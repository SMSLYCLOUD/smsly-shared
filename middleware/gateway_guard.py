"""
Gateway Guard Middleware for FastAPI Microservices

Blocks direct access to microservices - all requests MUST come through
the Security Gateway via SPIFFE mTLS.

Phase 4: HMAC removed. Only SPIFFE mTLS accepted.

Usage:
    from shared.middleware.gateway_guard import GatewayGuardMiddleware

    app.add_middleware(
        GatewayGuardMiddleware,
        service_name="smsly-rate-limit",
    )
"""

import logging
from typing import Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

try:
    from smsly_core.spiffe_auth import (
        DualAuthValidator,
        get_allowed_callers,
    )
    _SPIFFE_AVAILABLE = True
except ImportError:
    _SPIFFE_AVAILABLE = False

logger = logging.getLogger(__name__)


class GatewayGuardMiddleware(BaseHTTPMiddleware):
    """
    Middleware that blocks direct access to microservices.

    All traffic MUST come through Security Gateway via SPIFFE mTLS.
    Uses fail-closed design - blocks everything if SPIFFE unavailable.

    Phase 4: HMAC removed. Only SPIFFE mTLS accepted.
    """

    # Paths that bypass authentication (health checks, etc.)
    DEFAULT_PUBLIC_PATHS: Set[str] = {
        "/",
        "/health",
        "/ready",
        "/live",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/.well-known/openapi.json",
    }

    def __init__(
        self,
        app,
        service_name: str = "unknown",
        public_paths: Set[str] = None,
    ):
        super().__init__(app)
        self.service_name = service_name
        self.public_paths = public_paths or self.DEFAULT_PUBLIC_PATHS

        # Initialize SPIFFE validator
        self._spiffe_validator = None
        if _SPIFFE_AVAILABLE:
            allowed = get_allowed_callers(service_name)
            self._spiffe_validator = DualAuthValidator(
                service_name=service_name,
                allowed_callers=allowed,
            )
            logger.info(
                "gateway_guard_initialized",
                service=service_name,
                phase=self._spiffe_validator.flags.migration_phase.value,
                allowed_callers=len(allowed),
            )
        else:
            logger.error(
                "gateway_guard_no_spiffe",
                service=service_name,
                msg="SPIFFE module not available — all requests will be blocked",
            )

    def _is_public_path(self, path: str) -> bool:
        """Check if path is public (bypasses auth)."""
        path_normalized = path.rstrip("/")
        return (
            path_normalized in self.public_paths or
            path in self.public_paths or
            any(path_normalized.startswith(p.rstrip("/")) for p in self.public_paths)
        )

    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP from headers."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public paths
        if self._is_public_path(path):
            return await call_next(request)

        # Allow OPTIONS for CORS
        if request.method == "OPTIONS":
            return await call_next(request)

        # SPIFFE mTLS validation
        if not self._spiffe_validator:
            logger.error(
                "gateway_guard_no_validator",
                service=self.service_name,
                path=path,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "service_unavailable",
                    "message": "Authentication service not configured",
                    "code": "AUTH_SERVICE_UNAVAILABLE",
                }
            )

        headers = {k: v for k, v in request.headers.items()}
        result = self._spiffe_validator.validate(
            headers=headers,
            method=request.method,
            path=path,
        )

        if result.authenticated:
            logger.debug(
                "gateway_guard_passed",
                extra={
                    "service": self.service_name,
                    "path": path,
                    "method": result.method.value,
                    "spiffe_id": result.spiffe_id,
                }
            )
            return await call_next(request)

        # Authentication failed
        client_ip = self._get_client_ip(request)
        logger.warning(
            "gateway_guard_blocked",
            extra={
                "service": self.service_name,
                "path": path,
                "client_ip": client_ip,
                "reason": result.reason,
                "method": request.method,
            }
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": "forbidden",
                "message": "Direct access not allowed. Use Security Gateway.",
                "code": "GATEWAY_REQUIRED",
            }
        )
