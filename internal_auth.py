"""
Internal Authentication Middleware for SMSLYCLOUD Microservices

This middleware validates X-Internal-Secret header for gateway-to-service
communication. Should be added to all FastAPI microservices.

Usage:
    from internal_auth import InternalAuthMiddleware, get_internal_context
    
    app.add_middleware(InternalAuthMiddleware, internal_secret=os.environ["INTERNAL_API_SECRET"])
    
    @app.get("/v1/messages")
    async def list_messages(context: InternalContext = Depends(get_internal_context)):
        user_id = context.user_id
        ...
"""

import os
from dataclasses import dataclass
from typing import Optional
from fastapi import Request, HTTPException, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import hmac
import logging

logger = logging.getLogger(__name__)


@dataclass
class InternalContext:
    """Context passed from the gateway to the microservice."""
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    organization_id: Optional[str] = None
    account_type: str = "casual"
    request_id: Optional[str] = None
    is_internal: bool = False


class InternalAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate internal authentication from the gateway.
    
    Validates X-Internal-Secret header and extracts user context.
    """
    
    def __init__(self, app, internal_secret: str = None, skip_paths: list = None):
        super().__init__(app)
        self.internal_secret = internal_secret or os.environ.get("INTERNAL_API_SECRET", "")
        self.skip_paths = skip_paths or ["/health", "/docs", "/redoc", "/openapi.json", "/metrics"]
    
    async def dispatch(self, request: Request, call_next):
        # Skip health checks and documentation
        if any(request.url.path.startswith(p) for p in self.skip_paths):
            return await call_next(request)
        
        # Check internal secret
        provided_secret = request.headers.get("X-Internal-Secret", "")
        
        if not self.internal_secret:
            logger.warning("INTERNAL_API_SECRET not configured, allowing all requests")
        elif not hmac.compare_digest(provided_secret, self.internal_secret):
            logger.warning(f"Invalid internal secret from {request.client.host}")
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized", "detail": "Invalid internal secret"}
            )
        
        # Extract context from headers
        context = InternalContext(
            user_id=request.headers.get("X-User-ID"),
            user_email=request.headers.get("X-User-Email"),
            organization_id=request.headers.get("X-Organization-ID"),
            account_type=request.headers.get("X-Account-Type", "casual"),
            request_id=request.headers.get("X-Request-ID"),
            is_internal=True
        )
        
        # Store context in request state
        request.state.internal_context = context
        
        # Add request ID to response headers
        response = await call_next(request)
        if context.request_id:
            response.headers["X-Request-ID"] = context.request_id
        
        return response


def get_internal_context(request: Request) -> InternalContext:
    """
    Dependency to get internal context from request.
    
    Usage:
        @app.get("/v1/resource")
        async def get_resource(context: InternalContext = Depends(get_internal_context)):
            print(context.user_id)
    """
    context = getattr(request.state, 'internal_context', None)
    if context is None:
        # Create empty context for non-gateway requests (e.g., direct API access)
        context = InternalContext(is_internal=False)
    return context


def require_internal_auth(request: Request) -> InternalContext:
    """
    Dependency that requires internal authentication.
    Raises 401 if request is not from gateway.
    """
    context = get_internal_context(request)
    if not context.is_internal:
        raise HTTPException(
            status_code=401,
            detail="This endpoint requires internal gateway authentication"
        )
    return context


def require_user_context(request: Request) -> InternalContext:
    """
    Dependency that requires user context from gateway.
    Raises 401 if no user context is present.
    """
    context = require_internal_auth(request)
    if not context.user_id:
        raise HTTPException(
            status_code=401,
            detail="User context required"
        )
    return context


# Rate limiter that respects account type
class AccountTypeRateLimiter:
    """
    Rate limiter that uses different limits based on account type.
    """
    
    DEFAULT_LIMITS = {
        "casual": {"requests_per_second": 5, "requests_per_minute": 60},
        "developer": {"requests_per_second": 20, "requests_per_minute": 300},
        "enterprise": {"requests_per_second": 100, "requests_per_minute": 1000},
        "reseller": {"requests_per_second": 50, "requests_per_minute": 500},
    }
    
    def __init__(self, redis_client=None, limits: dict = None):
        self.redis = redis_client
        self.limits = limits or self.DEFAULT_LIMITS
    
    async def check_rate_limit(self, context: InternalContext) -> bool:
        """Check if request is within rate limits."""
        if self.redis is None:
            return True  # No Redis, no rate limiting
        
        account_type = context.account_type
        limits = self.limits.get(account_type, self.limits["casual"])
        
        # Use user_id or organization_id as key
        key_base = context.organization_id or context.user_id or "anonymous"
        
        # Check per-second limit
        second_key = f"rate:{key_base}:second"
        current = await self.redis.incr(second_key)
        if current == 1:
            await self.redis.expire(second_key, 1)
        if current > limits["requests_per_second"]:
            return False
        
        # Check per-minute limit
        minute_key = f"rate:{key_base}:minute"
        current = await self.redis.incr(minute_key)
        if current == 1:
            await self.redis.expire(minute_key, 60)
        if current > limits["requests_per_minute"]:
            return False
        
        return True
