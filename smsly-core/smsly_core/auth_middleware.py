"""
Auth Middleware
===============
Phase 4: HMAC removed. Only SPIFFE mTLS accepted.

Validates that incoming requests carry a valid SPIFFE X.509 SVID
from the mTLS TLS handshake. All traffic to internal services MUST
flow through the gateway — this middleware enforces that contract.
"""

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
import structlog

try:
    from smsly_core.spiffe_auth import (
        DualAuthValidator,
        get_allowed_callers,
    )
    _SPIFFE_AVAILABLE = True
except ImportError:
    _SPIFFE_AVAILABLE = False

logger = structlog.get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authenticates requests by verifying SPIFFE mTLS identity.

    The gateway establishes mTLS with downstream services and forwards
    the caller's SPIFFE ID via X-SPIFFE-ID header after verifying
    the mTLS connection.

    This middleware verifies that identity before allowing the request
    to reach route handlers. Without a valid SPIFFE identity, the request
    is rejected with 401.

    Environment variables:
        MIGRATION_PHASE — phase4 (default)
        FEATURE_SPIFFE_MTLS — enable SPIFFE mTLS (default: true)
        SPIFFE_MTLS_STRICT_MODE — require mTLS (default: true)
        SPIFFE_TRUST_DOMAIN — trust domain (default: trulay.co)
    """

    def __init__(self, app, service_name: str = "unknown"):
        super().__init__(app)
        self._service_name = service_name

        # Initialize SPIFFE validator
        self._spiffe_validator = None
        if _SPIFFE_AVAILABLE:
            allowed = get_allowed_callers(service_name)
            self._spiffe_validator = DualAuthValidator(
                service_name=service_name,
                allowed_callers=allowed,
            )
            logger.info(
                "auth_middleware_initialized",
                service=service_name,
                phase=self._spiffe_validator.flags.migration_phase,
            )
        else:
            logger.error(
                "auth_middleware_no_spiffe",
                service=service_name,
                msg="SPIFFE module not available — all requests will be rejected",
            )

    async def dispatch(self, request: Request, call_next) -> Response:
        # Health endpoints bypass auth (needed for orchestrators)
        if request.url.path in ("/health", "/ready", "/metrics", "/"):
            return await call_next(request)

        # Internal-only endpoints (K8s probes, inter-service status)
        if request.url.path in ("/internal/health", "/internal/ready"):
            return await call_next(request)

        if not self._spiffe_validator:
            logger.error("auth_no_validator", path=request.url.path)
            return JSONResponse(
                status_code=503,
                content={"error": "authentication_unavailable", "detail": "Auth service not configured"}
            )

        # Extract SPIFFE ID from X-SPIFFE-ID header (set by Gateway after mTLS)
        spiffe_id = request.headers.get("X-SPIFFE-ID")

        # Also try to extract from TLS peer certificate
        peer_cert_der = None
        connection = request.scope.get("connection")
        if connection:
            ssl_obj = getattr(connection, "_ssl_object", None)
            if ssl_obj:
                try:
                    peer_cert_der = ssl_obj.getpeercert(binary_form=True)
                except Exception:
                    pass

        result = self._spiffe_validator.validate(
            peer_cert_der=peer_cert_der,
            spiffe_id=spiffe_id,
            method=request.method,
            path=request.url.path,
        )

        if result.authenticated:
            request.state.authenticated = True
            request.state.auth_source = result.method
            request.state.spiffe_id = result.spiffe_id
            return await call_next(request)

        # Authentication failed
        logger.warning(
            "auth_failed",
            path=request.url.path,
            reason=result.reason,
        )
        return JSONResponse(
            status_code=401,
            content={
                "error": "authentication_failed",
                "detail": result.reason or "Valid SPIFFE mTLS identity required",
            }
        )


__all__ = ["AuthMiddleware"]
