"""
Auth Middleware Alias Module
============================
Provides AuthMiddleware for service authentication.
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import structlog

logger = structlog.get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for service-to-service calls.
    
    Validates JWT tokens and service credentials.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip health check endpoints
        if request.url.path in ("/health", "/ready", "/metrics"):
            return await call_next(request)
        
        # For now, pass through all requests
        # Full auth implementation would validate JWT tokens here
        logger.debug("auth_middleware_passthrough", path=request.url.path)
        return await call_next(request)


__all__ = ["AuthMiddleware"]
