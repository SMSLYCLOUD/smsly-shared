"""
Auth Middleware
===============
Gateway-signed request authentication middleware.

Validates that incoming requests carry a valid HMAC-SHA256 signature from
the Security Gateway, using constant-time comparison. All traffic to internal
services MUST flow through the gateway — this middleware enforces that contract.
"""

import os
import hashlib
import hmac
from datetime import datetime, timezone
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse
import structlog

logger = structlog.get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authenticates requests by verifying the Security Gateway's HMAC signature.

    The gateway signs every forwarded request with:
        HMAC-SHA256(GATEWAY_SECRET, "timestamp:path[:body_hash]")

    This middleware verifies that signature before allowing the request
    to reach route handlers. Without a valid signature, the request is rejected
    with 401.

    Environment variables:
        GATEWAY_SECRET — shared secret with the Security Gateway (required)
        SIGNATURE_TTL_SECONDS — max age of timestamps (default: 300)
    """

    def __init__(self, app, gateway_secret: str = None):
        super().__init__(app)
        self._gateway_secret = gateway_secret or os.getenv("GATEWAY_SECRET", "")
        self._ttl_seconds = int(os.getenv("SIGNATURE_TTL_SECONDS", "300"))
        if not self._gateway_secret:
            logger.warning(
                "auth_middleware_no_secret",
                msg="GATEWAY_SECRET not set — all requests will be rejected"
            )

    async def dispatch(self, request: Request, call_next) -> Response:
        # Health endpoints bypass auth (needed for orchestrators)
        if request.url.path in ("/health", "/ready", "/metrics", "/"):
            return await call_next(request)

        # Internal-only endpoints (K8s probes, inter-service status)
        if request.url.path.startswith("/internal"):
            return await call_next(request)

        # Verify gateway signature
        if not self._gateway_secret:
            logger.error("auth_rejected_no_secret", path=request.url.path)
            return JSONResponse(
                status_code=401,
                content={"error": "authentication_unavailable", "detail": "Service not configured with gateway secret"}
            )

        timestamp = request.headers.get("X-Gateway-Timestamp")
        signature = request.headers.get("X-Gateway-Signature")

        if not timestamp or not signature:
            logger.warning("auth_missing_signature_headers", path=request.url.path)
            return JSONResponse(
                status_code=401,
                content={"error": "missing_signature", "detail": "Request must carry gateway signature headers"}
            )

        # Verify timestamp freshness
        try:
            ts_str = timestamp
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+00:00'
            ts = datetime.fromisoformat(ts_str)
            now = datetime.now(timezone.utc)
            if abs((now - ts).total_seconds()) > self._ttl_seconds:
                logger.warning("auth_expired_timestamp", path=request.url.path, age_seconds=abs((now - ts).total_seconds()))
                return JSONResponse(
                    status_code=401,
                    content={"error": "expired_signature", "detail": "Gateway signature timestamp has expired"}
                )
        except Exception:
            logger.warning("auth_invalid_timestamp_format", timestamp=timestamp)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_timestamp", "detail": "Gateway timestamp format is invalid"}
            )

        # Read body for signature verification
        path = request.url.path
        try:
            body = await request.body()
            body_hash = hashlib.sha256(body).hexdigest() if body else None

            # Restore body for downstream consumers
            async def receive_body():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive_body
        except Exception:
            logger.warning("auth_body_read_failed", path=path)
            return JSONResponse(
                status_code=401,
                content={"error": "signature_error", "detail": "Unable to verify request body"}
            )

        # Compute expected signature
        msg = f"{timestamp}:{path}"
        if body_hash:
            msg += f":{body_hash}"

        expected = hmac.new(
            self._gateway_secret.encode(),
            msg.encode(),
            hashlib.sha256
        ).hexdigest()

        # Constant-time comparison
        if not hmac.compare_digest(expected, signature):
            logger.warning("auth_invalid_signature", path=path)
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_signature", "detail": "Gateway signature verification failed"}
            )

        # Valid — proceed
        request.state.authenticated = True
        request.state.auth_source = "gateway"
        return await call_next(request)


__all__ = ["AuthMiddleware"]
