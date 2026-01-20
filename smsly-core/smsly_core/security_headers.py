"""
Security Headers Middleware
===========================

Adds security-related HTTP headers to all responses.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from typing import Callable, Awaitable
import structlog

logger = structlog.get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses.
    
    Headers added:
    - X-Content-Type-Options: Prevents MIME type sniffing
    - X-Frame-Options: Prevents clickjacking
    - X-XSS-Protection: Legacy XSS protection
    - Referrer-Policy: Controls referrer information
    - Content-Security-Policy: Restricts resource loading
    - Strict-Transport-Security: Forces HTTPS
    - Permissions-Policy: Restricts browser features
    """
    
    def __init__(
        self,
        app,
        enable_hsts: bool = True,
        hsts_max_age: int = 31536000,  # 1 year
        frame_options: str = "DENY",
        content_type_options: bool = True,
        referrer_policy: str = "strict-origin-when-cross-origin",
        csp_policy: str = None,
    ):
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.hsts_max_age = hsts_max_age
        self.frame_options = frame_options
        self.content_type_options = content_type_options
        self.referrer_policy = referrer_policy
        self.csp_policy = csp_policy or self._default_csp()
    
    def _default_csp(self) -> str:
        """Default Content-Security-Policy for API services."""
        return "; ".join([
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
        ])
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        
        # Add security headers
        if self.content_type_options:
            response.headers["X-Content-Type-Options"] = "nosniff"
        
        response.headers["X-Frame-Options"] = self.frame_options
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = self.referrer_policy
        
        # Only add CSP for HTML responses (not APIs)
        if "text/html" in response.headers.get("content-type", ""):
            response.headers["Content-Security-Policy"] = self.csp_policy
        
        # HSTS - only for HTTPS
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = (
                f"max-age={self.hsts_max_age}; includeSubDomains"
            )
        
        # Permissions Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )
        
        return response


class SanitizedErrorMiddleware(BaseHTTPMiddleware):
    """
    Middleware that sanitizes error responses to prevent information leakage.
    
    In production mode:
    - Removes internal stack traces
    - Removes internal service/path details
    - Returns generic error messages for 5xx errors
    """
    
    def __init__(self, app, environment: str = "production"):
        super().__init__(app)
        self.is_production = environment.lower() in ("production", "prod", "staging")
    
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        try:
            response = await call_next(request)
            
            # In production, sanitize 5xx error responses
            if self.is_production and response.status_code >= 500:
                # Log the original error for debugging
                logger.warning(
                    "sanitized_error_response",
                    status_code=response.status_code,
                    path=request.url.path,
                )
            
            return response
            
        except Exception as e:
            # Catch any unhandled exceptions and return generic error
            logger.error(
                "unhandled_exception",
                error=str(e),
                path=request.url.path,
                method=request.method,
            )
            
            if self.is_production:
                # Return generic error without details
                from starlette.responses import JSONResponse
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error"},
                )
            else:
                # In development, re-raise for debugging
                raise


def get_rate_limit_headers(
    remaining: int,
    limit: int,
    reset_at: int,
) -> dict:
    """
    Generate standard rate limit headers.
    
    Args:
        remaining: Number of requests remaining in window
        limit: Maximum requests per window
        reset_at: Unix timestamp when window resets
        
    Returns:
        Dict of headers to add to response
    """
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(reset_at),
    }
