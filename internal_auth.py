"""
Internal Authentication Middleware for SMSLYCLOUD Microservices

This middleware validates SPIFFE mTLS identity for gateway-to-service
communication. Should be added to all FastAPI microservices.

Phase 4: HMAC removed. Only SPIFFE mTLS accepted.

Usage:
    from internal_auth import InternalAuthMiddleware, get_internal_context
    
    app.add_middleware(InternalAuthMiddleware, service_name="my-service")
    
    @app.get("/v1/messages")
    async def list_messages(context: InternalContext = Depends(get_internal_context)):
        user_id = context.user_id
        ...
"""

from dataclasses import dataclass
from typing import Optional
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging

try:
    from smsly_core.spiffe_auth import (
        DualAuthValidator,
        get_allowed_callers,
        MigrationPhase,
    )
    _SPIFFE_AVAILABLE = True
except ImportError:
    _SPIFFE_AVAILABLE = False

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
    spiffe_id: Optional[str] = None


class InternalAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate internal authentication from the gateway.
    
    Validates SPIFFE mTLS identity and extracts user context.
    
    Phase 4: HMAC removed. Only SPIFFE mTLS accepted.
    """
    
    def __init__(self, app, skip_paths: list = None, service_name: str = "unknown"):
        super().__init__(app)
        self.skip_paths = skip_paths or ["/health", "/docs", "/redoc", "/openapi.json", "/metrics"]
        self.service_name = service_name

        # Initialize SPIFFE validator
        self._spiffe_validator = None
        if _SPIFFE_AVAILABLE:
            allowed = get_allowed_callers(service_name)
            self._spiffe_validator = DualAuthValidator(
                service_name=service_name,
                allowed_callers=allowed,
            )
            logger.info(
                "internal_auth_initialized",
                service=service_name,
                phase=self._spiffe_validator.flags.migration_phase.value,
            )
        else:
            logger.error(
                "internal_auth_no_spiffe",
                service=service_name,
                msg="SPIFFE module not available — all requests will be rejected",
            )

    async def dispatch(self, request: Request, call_next):
        # Skip health checks and documentation
        if any(request.url.path.startswith(p) for p in self.skip_paths):
            return await call_next(request)

        # SPIFFE mTLS validation
        if not self._spiffe_validator:
            logger.error("internal_auth_no_validator", path=request.url.path)
            return JSONResponse(
                status_code=503,
                content={"error": "authentication_unavailable", "detail": "Auth service not configured"}
            )

        headers = {k: v for k, v in request.headers.items()}
        result = self._spiffe_validator.validate(
            headers=headers,
            method=request.method,
            path=request.url.path,
        )

        if not result.authenticated:
            logger.warning(
                "internal_auth_failed",
                path=request.url.path,
                reason=result.reason,
                client=request.client.host if request.client else "unknown",
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": result.reason or "Valid SPIFFE mTLS identity required",
                }
            )

        # Extract context from headers
        context = InternalContext(
            user_id=request.headers.get("X-User-ID"),
            user_email=request.headers.get("X-User-Email"),
            organization_id=request.headers.get("X-Organization-ID"),
            account_type=request.headers.get("X-Account-Type", "casual"),
            request_id=request.headers.get("X-Request-ID"),
            is_internal=True,
            spiffe_id=result.spiffe_id,
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
            logger.warning("rate_limit_no_redis", msg="Redis unavailable, denying request")
            return False  # Fail-closed
        
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
