"""
Gateway Guard Middleware for FastAPI Microservices

Blocks direct access to microservices - all requests MUST come through
the Security Gateway or authorized internal services.

Usage:
    from shared.middleware.gateway_guard import GatewayGuardMiddleware
    
    app.add_middleware(
        GatewayGuardMiddleware,
        gateway_secret=settings.GATEWAY_SECRET,
        platform_api_secret=settings.PLATFORM_API_SECRET,
        service_name="smsly-rate-limit",
    )
"""

import hmac
import logging
import time
from typing import List, Optional, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class GatewayGuardMiddleware(BaseHTTPMiddleware):
    """
    Middleware that blocks direct access to microservices.
    
    All traffic MUST come through Security Gateway or authorized internal services.
    Uses fail-closed design - if no secrets configured, blocks everything.
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
        gateway_secret: str = "",
        platform_api_secret: str = "",
        backend_secret: str = "",
        additional_secrets: List[str] = None,
        service_name: str = "unknown",
        public_paths: Set[str] = None,
        header_name: str = "X-Internal-Secret",
        alt_header_name: str = "X-Gateway-Secret",
        fail_closed: bool = True,
    ):
        super().__init__(app)
        self.gateway_secret = gateway_secret
        self.platform_api_secret = platform_api_secret
        self.backend_secret = backend_secret
        self.additional_secrets = additional_secrets or []
        self.service_name = service_name
        self.public_paths = public_paths or self.DEFAULT_PUBLIC_PATHS
        self.header_name = header_name
        self.alt_header_name = alt_header_name
        self.fail_closed = fail_closed
        
        # Collect all valid secrets
        self._valid_secrets = set()
        for secret in [
            gateway_secret,
            platform_api_secret,
            backend_secret,
            *self.additional_secrets,
        ]:
            if secret:
                self._valid_secrets.add(secret)
        
        # Log configuration
        if self._valid_secrets:
            logger.info(
                f"GatewayGuardMiddleware configured for {service_name}",
                extra={"secrets_count": len(self._valid_secrets)}
            )
        elif fail_closed:
            logger.warning(
                f"GatewayGuardMiddleware: No secrets configured for {service_name} - "
                "FAIL-CLOSED mode active, all non-public requests will be blocked"
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
    
    def _validate_secret(self, provided: str) -> bool:
        """Validate provided secret using constant-time comparison."""
        if not provided:
            return False
        for valid_secret in self._valid_secrets:
            if hmac.compare_digest(provided, valid_secret):
                return True
        return False
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Allow public paths
        if self._is_public_path(path):
            return await call_next(request)
        
        # Allow OPTIONS for CORS
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # FAIL-CLOSED: If no secrets configured, block everything
        if self.fail_closed and not self._valid_secrets:
            logger.error(
                "gateway_guard_misconfigured",
                extra={
                    "service": self.service_name,
                    "path": path,
                    "reason": "no_secrets_configured",
                }
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "service_unavailable",
                    "message": "Service is misconfigured",
                    "code": "GATEWAY_GUARD_MISCONFIGURED",
                }
            )
        
        # Get provided secret from headers
        provided_secret = (
            request.headers.get(self.header_name) or
            request.headers.get(self.alt_header_name) or
            ""
        )
        
        client_ip = self._get_client_ip(request)
        
        # Missing secret
        if not provided_secret:
            logger.warning(
                "gateway_guard_blocked",
                extra={
                    "service": self.service_name,
                    "path": path,
                    "client_ip": client_ip,
                    "reason": "missing_secret",
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
        
        # Invalid secret
        if not self._validate_secret(provided_secret):
            logger.warning(
                "gateway_guard_blocked",
                extra={
                    "service": self.service_name,
                    "path": path,
                    "client_ip": client_ip,
                    "reason": "invalid_secret",
                    "method": request.method,
                }
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "forbidden",
                    "message": "Invalid service credentials",
                    "code": "INVALID_SERVICE_CREDENTIALS",
                }
            )
        
        # Valid - proceed
        logger.debug(
            "gateway_guard_passed",
            extra={
                "service": self.service_name,
                "path": path,
                "client_ip": client_ip,
            }
        )
        
        return await call_next(request)
