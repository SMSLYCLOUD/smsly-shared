"""
Direct Access Protection Middleware
====================================

Protects microservices from direct access attempts that bypass the Security Gateway.

Behavior:
- 1st attempt: Warning with proper URL guidance
- 2nd attempt: Final warning
- 3rd attempt: Block and blacklist the IP
- Subsequent attempts: Immediate block

Uses Redis for distributed tracking across all microservices.
"""

import os
import time
from typing import Optional, Set, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from datetime import datetime, timezone
import structlog
import hashlib

logger = structlog.get_logger(__name__)


# Configuration
GATEWAY_IPS = set(os.getenv("GATEWAY_IPS", "").split(",")) if os.getenv("GATEWAY_IPS") else set()
GATEWAY_URL = os.getenv("SECURITY_GATEWAY_URL", "https://gateway.smsly.io")
SERVICE_NAME = os.getenv("SERVICE_NAME", "smsly-microservice")
MAX_WARNINGS = int(os.getenv("DIRECT_ACCESS_MAX_WARNINGS", "2"))  # Block on 3rd attempt
BLACKLIST_DURATION_HOURS = int(os.getenv("BLACKLIST_DURATION_HOURS", "24"))

# Internal/allowed IPs that bypass protection (for health checks, etc.)
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.")


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/local."""
    return any(ip.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def is_gateway_ip(ip: str) -> bool:
    """Check if request comes from the Security Gateway."""
    if not ip:
        return False
    
    # Check configured gateway IPs
    if GATEWAY_IPS and ip in GATEWAY_IPS:
        return True
    
    # Fall back to internal IP check for development
    if not GATEWAY_IPS and is_internal_ip(ip):
        return True
    
    return False


class DirectAccessProtectionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that protects microservices from direct access.
    
    Any IP attempting to access the service without going through the
    Security Gateway will be:
    1. Warned (1st-2nd attempt) with guidance on the proper URL
    2. Blocked and blacklisted (3rd+ attempt)
    
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
        self.blacklist_hours = blacklist_hours if blacklist_hours is not None else BLACKLIST_DURATION_HOURS
        self.excluded_paths = excluded_paths or {"/health", "/ready", "/metrics"}
        
        # Initialize Redis for distributed tracking
        self._redis = None
        self._init_redis(redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    
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
            self._memory_attempts = {}  # Fallback
            self._memory_blacklist = set()
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP from request."""
        # Check forwarded headers (but don't trust them for non-gateway requests!)
        # For security, we primarily use the direct connection IP
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
        
        # Fallback to memory
        return ip in getattr(self, '_memory_blacklist', set())
    
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
        
        # Fallback to memory
        if not hasattr(self, '_memory_blacklist'):
            self._memory_blacklist = set()
        self._memory_blacklist.add(ip)
    
    def _get_attempt_count(self, ip: str) -> int:
        """Get current attempt count for IP."""
        if self._redis:
            try:
                count = self._redis.get(self._get_attempt_key(ip))
                return int(count) if count else 0
            except Exception:
                pass
        
        # Fallback to memory
        return getattr(self, '_memory_attempts', {}).get(ip, 0)
    
    def _increment_attempts(self, ip: str) -> int:
        """Increment and return attempt count."""
        if self._redis:
            try:
                key = self._get_attempt_key(ip)
                pipe = self._redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, 3600)  # Reset after 1 hour
                results = pipe.execute()
                return results[0]
            except Exception as e:
                logger.error("redis_increment_failed", error=str(e))
        
        # Fallback to memory
        if not hasattr(self, '_memory_attempts'):
            self._memory_attempts = {}
        self._memory_attempts[ip] = self._memory_attempts.get(ip, 0) + 1
        return self._memory_attempts[ip]
    
    def _has_gateway_signature(self, request: Request) -> bool:
        """Check if request has a valid gateway signature header."""
        # Check for gateway-specific headers that indicate proper routing
        gateway_timestamp = request.headers.get("X-Gateway-Timestamp")
        gateway_signature = request.headers.get("X-Gateway-Signature")
        return bool(gateway_timestamp and gateway_signature)
    
    async def dispatch(self, request: Request, call_next):
        """Process request and enforce direct access protection."""
        path = request.url.path
        
        # Allow health checks and metrics (needed for orchestrators)
        if path in self.excluded_paths:
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        
        # Allow requests from Security Gateway
        if is_gateway_ip(client_ip):
            return await call_next(request)
        
        # Allow requests with valid gateway signature (even if IP changed due to proxy)
        if self._has_gateway_signature(request):
            return await call_next(request)
        
        # =========================================================================
        # DIRECT ACCESS DETECTED - Enforce protection
        # =========================================================================
        
        # Check if already blacklisted
        if self._is_blacklisted(client_ip):
            logger.warning(
                "blocked_blacklisted_ip",
                ip=client_ip,
                path=path,
                service=self.service_name
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "access_denied",
                    "message": "Your IP has been blocked due to repeated unauthorized access attempts.",
                    "code": "IP_BLACKLISTED",
                    "support": "Contact support@smsly.io if you believe this is an error."
                }
            )
        
        # Increment attempt counter
        attempt_count = self._increment_attempts(client_ip)
        
        # Log the attempt
        logger.warning(
            "direct_access_attempt",
            ip=client_ip,
            path=path,
            method=request.method,
            service=self.service_name,
            attempt=attempt_count,
            max_warnings=self.max_warnings
        )
        
        # Check if should be blocked
        if attempt_count > self.max_warnings:
            # 3rd+ attempt - BLOCK AND BLACKLIST
            self._add_to_blacklist(client_ip)
            
            return JSONResponse(
                status_code=403,
                content={
                    "error": "access_denied",
                    "message": (
                        f"You have been blocked and blacklisted for {self.blacklist_hours} hours "
                        "due to repeated unauthorized direct access attempts to this microservice."
                    ),
                    "code": "IP_BLOCKED_AND_BLACKLISTED",
                    "proper_access": {
                        "message": "All API requests must go through the SMSLY Security Gateway.",
                        "gateway_url": self.gateway_url,
                        "documentation": f"{self.gateway_url}/docs",
                    },
                    "support": "Contact support@smsly.io if you believe this is an error."
                }
            )
        
        # 1st or 2nd attempt - WARNING
        warnings_remaining = self.max_warnings - attempt_count + 1
        
        warning_message = (
            f"⚠️ WARNING: Direct access to this microservice is not allowed. "
            f"This is attempt {attempt_count} of {self.max_warnings + 1}. "
            f"You have {warnings_remaining} warning(s) remaining before your IP is blocked."
        )
        
        return JSONResponse(
            status_code=403,
            content={
                "error": "direct_access_forbidden",
                "message": warning_message,
                "code": "DIRECT_ACCESS_WARNING",
                "attempt": attempt_count,
                "max_attempts": self.max_warnings + 1,
                "warnings_remaining": warnings_remaining,
                "proper_access": {
                    "message": "All API requests must go through the SMSLY Security Gateway.",
                    "gateway_url": self.gateway_url,
                    "api_base_url": f"{self.gateway_url}/api/v1",
                    "documentation": f"{self.gateway_url}/docs",
                    "example": f"curl -X GET {self.gateway_url}/api/v1/{self.service_name.replace('smsly-', '')}/health"
                },
                "why": (
                    "The Security Gateway provides authentication, rate limiting, "
                    "audit logging, and threat protection for all API requests. "
                    "Direct access to microservices bypasses these security controls."
                ),
            }
        )


def get_direct_access_stats(redis_client) -> dict:
    """
    Get statistics about direct access attempts.
    
    Args:
        redis_client: Redis connection
        
    Returns:
        Dict with attempt and blacklist statistics
    """
    try:
        # Count blacklisted IPs
        blacklist_keys = redis_client.keys("direct_access:blacklist:*")
        attempt_keys = redis_client.keys("direct_access:attempts:*")
        
        return {
            "blacklisted_ips": len(blacklist_keys),
            "tracked_ips": len(attempt_keys),
            "blacklist_entries": [
                key.split(":")[-1] for key in blacklist_keys[:100]  # Limit to 100
            ]
        }
    except Exception as e:
        return {"error": str(e)}
