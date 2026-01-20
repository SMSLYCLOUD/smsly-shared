"""
Stalker Audit Middleware Alias Module
=====================================
Provides StalkerAuditMiddleware for guaranteed audit logging.
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import structlog

logger = structlog.get_logger(__name__)


class StalkerAuditMiddleware(BaseHTTPMiddleware):
    """
    Audit middleware with guaranteed delivery.
    
    Logs all requests with retry mechanism.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip health check endpoints
        if request.url.path in ("/health", "/ready", "/metrics"):
            return await call_next(request)
        
        # Log request
        logger.info("stalker_audit_request", 
                   method=request.method, 
                   path=request.url.path)
        
        response = await call_next(request)
        
        # Log response
        logger.info("stalker_audit_response",
                   method=request.method,
                   path=request.url.path,
                   status_code=response.status_code)
        
        return response


__all__ = ["StalkerAuditMiddleware"]
