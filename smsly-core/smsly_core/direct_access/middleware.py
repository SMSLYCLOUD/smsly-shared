"""
Direct Access Protection Middleware
====================================
Middleware that protects microservices from direct access bypassing the Security Gateway.

Phase 4: HMAC removed. Only SPIFFE mTLS accepted.
"""

import os
from typing import Set
from datetime import datetime, timezone
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import structlog

from .config import (
    SERVICE_NAME,
    GATEWAY_URL,
    MAX_WARNINGS,
    BLACKLIST_DURATION_HOURS,
    DEFAULT_EXCLUDED_PATHS,
)
from .ip_utils import is_gateway_ip
import ipaddress as _ipaddress

try:
    from smsly_core.spiffe_auth import (
        DualAuthValidator,
        get_allowed_callers,
    )
    try:
        from smsly_core.spiffe_auth import MigrationPhase  # noqa: F401, optional compat
    except ImportError:
        MigrationPhase = None  # type: ignore
    _SPIFFE_AVAILABLE = True
except ImportError:
    _SPIFFE_AVAILABLE = False
    MigrationPhase = None  # type: ignore

logger = structlog.get_logger(__name__)


class DirectAccessProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that protects microservices from direct access.
    
    Any IP attempting to access the service without going through the
    Security Gateway will be:
    1. Warned (1st-2nd attempt) with guidance on the proper URL
    2. Blocked and blacklisted (3rd+ attempt)
    
    Phase 4: HMAC removed. Only SPIFFE mTLS accepted.
    Uses Redis for distributed tracking across multiple service instances.
    """
    
    def __init__(
        self,
        app,
        service_name: str = None,
        gateway_url: str = None,
        max_warnings: int = None,
        blacklist_hours: int = None,
        redis_url: str = None,
        excluded_paths: Set[str] = None,
    ):
        super().__init__(app)
        self.service_name = service_name or SERVICE_NAME
        self.gateway_url = gateway_url or GATEWAY_URL
        self.max_warnings = max_warnings if max_warnings is not None else MAX_WARNINGS
        self.blacklist_hours = (
            blacklist_hours if blacklist_hours is not None
            else BLACKLIST_DURATION_HOURS
        )
        self.excluded_paths = excluded_paths or DEFAULT_EXCLUDED_PATHS
        
        # Initialize Redis for distributed tracking
        self._redis = None
        self._memory_attempts = {}
        self._memory_blacklist = set()
        self._init_redis(redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        
        # Initialize SPIFFE validator
        self._spiffe_validator = None
        if _SPIFFE_AVAILABLE:
            try:
                allowed = get_allowed_callers(self.service_name)
                self._spiffe_validator = DualAuthValidator(
                    service_name=self.service_name,
                    allowed_callers=allowed,
                )
                _phase = getattr(
                    self._spiffe_validator.flags.migration_phase, "value",
                    self._spiffe_validator.flags.migration_phase,
                )
                logger.info(
                    "direct_access_initialized",
                    service=self.service_name,
                    phase=_phase,
                )
            except Exception as e:
                logger.error("direct_access_init_failed", error=str(e))
    
    def _init_redis(self, redis_url: str):
        """Initialize Redis connection."""
        try:
            import redis
            self._redis = redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
            logger.info("direct_access_protection_redis_connected")
        except Exception as e:
            logger.warning(
                "direct_access_protection_redis_unavailable",
                error=str(e),
                fallback="in-memory tracking (not distributed)"
            )
            self._redis = None
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP from request."""
        client = request.client
        if client:
            return client.host
        return "unknown"
    
    def _get_attempt_key(self, ip: str) -> str:
        """Generate Redis key for tracking attempts."""
        return f"direct_access:attempts:{ip}"
    
    def _get_blacklist_key(self, ip: str) -> str:
        """Generate Redis key for blacklist."""
        return f"direct_access:blacklist:{ip}"
    
    def _is_blacklisted(self, ip: str) -> bool:
        """Check if IP is blacklisted."""
        if self._redis:
            try:
                return self._redis.exists(self._get_blacklist_key(ip)) > 0
            except Exception:
                pass
        return ip in self._memory_blacklist
    
    def _add_to_blacklist(self, ip: str):
        """Add IP to blacklist."""
        ttl_seconds = self.blacklist_hours * 3600
        
        if self._redis:
            try:
                key = self._get_blacklist_key(ip)
                self._redis.setex(key, ttl_seconds, datetime.now(timezone.utc).isoformat())
                logger.warning(
                    "ip_blacklisted_direct_access",
                    ip=ip,
                    service=self.service_name,
                    duration_hours=self.blacklist_hours
                )
                return
            except Exception as e:
                logger.error("redis_blacklist_failed", error=str(e))
        
        self._memory_blacklist.add(ip)
    
    def _get_attempt_count(self, ip: str) -> int:
        """Get current attempt count for IP."""
        if self._redis:
            try:
                count = self._redis.get(self._get_attempt_key(ip))
                return int(count) if count else 0
            except Exception:
                pass
        return self._memory_attempts.get(ip, 0)
    
    def _increment_attempts(self, ip: str) -> int:
        """Increment and return attempt count."""
        if self._redis:
            try:
                key = self._get_attempt_key(ip)
                pipe = self._redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, 3600)
                results = pipe.execute()
                return results[0]
            except Exception as e:
                logger.error("redis_increment_failed", error=str(e))
        
        self._memory_attempts[ip] = self._memory_attempts.get(ip, 0) + 1
        return self._memory_attempts[ip]
    
    async def _verify_gateway_identity(self, request: Request) -> bool:
        """Verify SPIFFE mTLS identity from gateway — peer cert only."""
        if not self._spiffe_validator:
            logger.error("direct_access_no_validator")
            return False

        peer_cert_der = None
        try:
            conn = request.scope.get("connection")
            ssl_obj = getattr(conn, "_ssl_object", None) if conn else None
            if ssl_obj is not None:
                peer_cert_der = ssl_obj.getpeercert(binary_form=True)
        except Exception:
            peer_cert_der = None
        result = self._spiffe_validator.validate(
            peer_cert_der=peer_cert_der,
            method=request.method,
            path=request.url.path,
        )

        if result.authenticated:
            return True

        logger.debug(
            "direct_access_spiffe_failed",
            path=request.url.path,
            reason=result.reason,
        )
        return False
    
    async def dispatch(self, request: Request, call_next):
        """Process request and enforce direct access protection."""
        path = request.url.path
        
        # Allow health checks and metrics
        if path in self.excluded_paths:
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        
        # Allow requests from Security Gateway (IP-based)
        if is_gateway_ip(client_ip):
            return await call_next(request)
        
        # Verify SPIFFE mTLS identity
        if await self._verify_gateway_identity(request):
            return await call_next(request)

        # Mesh attestation: the gateway authenticated the caller and
        # attested it over the private mesh (see _verify_attested_mesh).
        # Opt-in via TRUST_ATTESTED_MESH + CIDR pin; fail closed otherwise.
        if self._verify_attested_mesh(request, client_ip):
            return await call_next(request)

        # DIRECT ACCESS DETECTED
        return await self._handle_direct_access(request, client_ip, path)

    def _verify_attested_mesh(self, request: Request, client_ip: str) -> bool:
        """Accept gateway-attested mesh traffic (explicit opt-in only)."""
        if os.getenv("TRUST_ATTESTED_MESH", "false").strip().lower() not in (
            "1", "true", "yes",
        ):
            return False
        raw = request.headers.get("x-smsly-validated", "") or ""
        if not any(p.strip().lower() == "true" for p in raw.split(",")):
            return False
        # Pin: exact IPs (GATEWAY_IPS) and/or CIDRs (GATEWAY_ALLOWED_IPS).
        # At least one pin must exist AND match — no pin, no trust.
        exact = {
            p.strip() for p in os.getenv("GATEWAY_IPS", "").split(",") if p.strip()
        }
        pinned = False
        if client_ip and client_ip in exact:
            pinned = True
        else:
            cidrs = [
                p.strip() for p in os.getenv("GATEWAY_ALLOWED_IPS", "").split(",")
                if p.strip()
            ]
            try:
                addr = _ipaddress.ip_address(client_ip)
            except ValueError:
                return False
            for cidr in cidrs:
                try:
                    if addr in _ipaddress.ip_network(cidr, strict=False):
                        pinned = True
                        break
                except ValueError:
                    continue
        if not pinned:
            logger.debug(
                "attested_mesh_unpinned",
                ip=client_ip,
                service=self.service_name,
            )
            return False
        logger.debug(
            "attested_mesh_passed",
            ip=client_ip,
            service=self.service_name,
            path=request.url.path,
        )
        return True
    
    async def _handle_direct_access(self, request: Request, client_ip: str, path: str):
        """Handle a direct access attempt."""
        # Check if already blacklisted
        if self._is_blacklisted(client_ip):
            logger.warning("blocked_blacklisted_ip", ip=client_ip, path=path)
            return self._blocked_response()
        
        # Increment attempt counter
        attempt_count = self._increment_attempts(client_ip)
        
        logger.warning(
            "direct_access_attempt",
            ip=client_ip,
            path=path,
            method=request.method,
            service=self.service_name,
            attempt=attempt_count,
        )
        
        # Check if should be blocked
        if attempt_count > self.max_warnings:
            self._add_to_blacklist(client_ip)
            return self._blacklisted_response()
        
        # Warning response
        return self._warning_response(attempt_count)
    
    def _blocked_response(self) -> JSONResponse:
        """Return response for already-blacklisted IP."""
        return JSONResponse(
            status_code=403,
            content={
                "error": "access_denied",
                "message": "Your IP has been blocked due to repeated unauthorized access.",
                "code": "IP_BLACKLISTED",
                "support": "Contact support@trulay.co if this is an error."
            }
        )
    
    def _blacklisted_response(self) -> JSONResponse:
        """Return response when IP is being blacklisted."""
        return JSONResponse(
            status_code=403,
            content={
                "error": "access_denied",
                "message": f"Blocked for {self.blacklist_hours}h due to unauthorized access.",
                "code": "IP_BLOCKED_AND_BLACKLISTED",
                "gateway_url": self.gateway_url,
            }
        )
    
    def _warning_response(self, attempt_count: int) -> JSONResponse:
        """Return warning response for direct access attempt."""
        warnings_remaining = self.max_warnings - attempt_count + 1
        return JSONResponse(
            status_code=403,
            content={
                "error": "direct_access_forbidden",
                "message": f"Direct access not allowed. Attempt {attempt_count}/{self.max_warnings + 1}.",
                "code": "DIRECT_ACCESS_WARNING",
                "attempt": attempt_count,
                "warnings_remaining": warnings_remaining,
                "gateway_url": self.gateway_url,
            }
        )
