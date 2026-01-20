"""
Inter-Service Authentication - Zero Trust Module

This module provides consistent inter-service authentication across all SMSLY microservices.
Each service-to-service communication path uses a UNIQUE secret.

Usage (FastAPI):
    from shared.auth.inter_service import require_internal_auth, InternalAuthConfig
    
    config = InternalAuthConfig(
        gateway_secret=settings.GATEWAY_SECRET,
        platform_api_secret=settings.PLATFORM_API_SECRET,
    )
    
    @app.middleware("http")
    async def auth_middleware(request, call_next):
        await require_internal_auth(request, config)
        return await call_next(request)

Usage (Django):
    from shared.auth.inter_service import validate_internal_secret
    
    class InternalAuthMiddleware:
        def process_request(self, request):
            if not validate_internal_secret(request, settings.GATEWAY_SECRET, settings.PLATFORM_API_SECRET):
                return JsonResponse({'error': 'Forbidden'}, status=403)
"""

import hmac
import logging
from typing import Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class InternalAuthConfig:
    """Configuration for inter-service authentication."""
    
    # Secrets this service accepts (from different senders)
    gateway_secret: str = ""          # From Security Gateway
    platform_api_secret: str = ""     # From Platform API
    backend_secret: str = ""          # From Django Backend
    
    # Public paths that bypass authentication
    public_paths: List[str] = field(default_factory=lambda: [
        "/health",
        "/ready",
        "/live",
        "/metrics",
        "/docs",
        "/redoc",
        "/openapi.json",
    ])
    
    # Header name for the secret
    header_name: str = "X-Internal-Secret"
    
    # Alternative header name (backward compatibility)
    alt_header_name: str = "X-Gateway-Secret"
    
    # Fail closed on missing config
    fail_closed: bool = True


# =============================================================================
# Validation Functions
# =============================================================================

def validate_secret(provided: str, expected: str) -> bool:
    """
    Validate a secret using constant-time comparison.
    
    Args:
        provided: The secret provided in the request
        expected: The expected secret
        
    Returns:
        True if valid, False otherwise
    """
    if not expected:
        return False
    if not provided:
        return False
    return hmac.compare_digest(provided, expected)


def validate_internal_secret(
    request_headers: dict,
    *accepted_secrets: str,
    header_name: str = "X-Internal-Secret",
    alt_header_name: str = "X-Gateway-Secret",
) -> bool:
    """
    Validate that a request contains a valid internal secret.
    
    Args:
        request_headers: Dictionary of request headers
        *accepted_secrets: One or more secrets that are valid for this endpoint
        header_name: Primary header name to check
        alt_header_name: Alternative header name (backward compat)
        
    Returns:
        True if valid, False otherwise
    """
    # Get provided secret from headers
    provided = request_headers.get(header_name) or request_headers.get(alt_header_name)
    
    if not provided:
        logger.warning("internal_auth_missing_header", 
                      header=header_name,
                      alt_header=alt_header_name)
        return False
    
    # Check against all accepted secrets
    for secret in accepted_secrets:
        if secret and validate_secret(provided, secret):
            return True
    
    logger.warning("internal_auth_invalid_secret")
    return False


def get_client_ip(request_headers: dict, remote_addr: str = "") -> str:
    """Extract real client IP from headers."""
    forwarded = request_headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return remote_addr


# =============================================================================
# FastAPI Integration
# =============================================================================

async def require_internal_auth_fastapi(request, config: InternalAuthConfig):
    """
    FastAPI middleware function to require internal authentication.
    
    Usage:
        @app.middleware("http")
        async def auth_middleware(request, call_next):
            await require_internal_auth_fastapi(request, config)
            return await call_next(request)
    """
    from fastapi import HTTPException
    
    # Check if path is public
    path = request.url.path.rstrip("/")
    if any(path.startswith(p.rstrip("/")) for p in config.public_paths):
        return
    
    # Skip OPTIONS for CORS
    if request.method == "OPTIONS":
        return
    
    # Fail closed if no secrets configured
    if config.fail_closed and not any([
        config.gateway_secret,
        config.platform_api_secret,
        config.backend_secret,
    ]):
        logger.error("internal_auth_no_secrets_configured")
        raise HTTPException(
            status_code=503, 
            detail="Service temporarily unavailable. Please try again in 30-60 minutes."
        )
    
    # Validate
    headers = dict(request.headers)
    valid = validate_internal_secret(
        headers,
        config.gateway_secret,
        config.platform_api_secret,
        config.backend_secret,
        header_name=config.header_name,
        alt_header_name=config.alt_header_name,
    )
    
    if not valid:
        client_ip = get_client_ip(headers, request.client.host if request.client else "")
        logger.warning("internal_auth_rejected",
                      path=path,
                      client_ip=client_ip)
        raise HTTPException(
            status_code=403,
            detail="Invalid service credentials"
        )


# =============================================================================
# Django Integration
# =============================================================================

class DjangoInternalAuthMixin:
    """
    Mixin for Django middleware to validate internal service authentication.
    
    Usage:
        class MyMiddleware(DjangoInternalAuthMixin, MiddlewareMixin):
            def __init__(self, get_response):
                super().__init__(get_response)
                self.config = InternalAuthConfig(
                    gateway_secret=settings.GATEWAY_SECRET,
                    platform_api_secret=settings.PLATFORM_API_SECRET,
                )
    """
    
    config: InternalAuthConfig = None
    
    def is_path_public(self, path: str) -> bool:
        """Check if path is public."""
        if not self.config:
            return False
        path = path.rstrip("/")
        return any(path.startswith(p.rstrip("/")) for p in self.config.public_paths)
    
    def validate_request(self, request) -> bool:
        """Validate the request has valid internal credentials."""
        if not self.config:
            return False
        
        headers = {
            self.config.header_name: request.headers.get(self.config.header_name),
            self.config.alt_header_name: request.headers.get(self.config.alt_header_name),
        }
        
        return validate_internal_secret(
            headers,
            self.config.gateway_secret,
            self.config.platform_api_secret,
            self.config.backend_secret,
            header_name=self.config.header_name,
            alt_header_name=self.config.alt_header_name,
        )


# =============================================================================
# Secret Generation Utility
# =============================================================================

def generate_secret(length: int = 32) -> str:
    """Generate a cryptographically secure secret."""
    import secrets
    return secrets.token_hex(length)


def generate_all_secrets() -> dict:
    """Generate all required inter-service secrets."""
    return {
        # Gateway secrets
        "GATEWAY_TO_PLATFORM_SECRET": generate_secret(),
        "GATEWAY_TO_BACKEND_SECRET": generate_secret(),
        "GATEWAY_TO_RATELIMIT_SECRET": generate_secret(),
        "GATEWAY_TO_AUDIT_SECRET": generate_secret(),
        
        # Platform API secrets
        "PLATFORM_TO_BACKEND_SECRET": generate_secret(),
        "PLATFORM_TO_SMS_SECRET": generate_secret(),
        "PLATFORM_TO_WHATSAPP_SECRET": generate_secret(),
        "PLATFORM_TO_VOICE_SECRET": generate_secret(),
        "PLATFORM_TO_EMAIL_SECRET": generate_secret(),
        "PLATFORM_TO_VERIFICATION_SECRET": generate_secret(),
        "PLATFORM_TO_CAMPAIGNS_SECRET": generate_secret(),
        "PLATFORM_TO_IDENTITY_SECRET": generate_secret(),
        "PLATFORM_TO_POLICY_SECRET": generate_secret(),
        "PLATFORM_TO_CRM_SECRET": generate_secret(),
        "PLATFORM_TO_LIVECHAT_SECRET": generate_secret(),
        "PLATFORM_TO_SURVEY_SECRET": generate_secret(),
        "PLATFORM_TO_MARKETING_SECRET": generate_secret(),
        "PLATFORM_TO_NUMBER_SECRET": generate_secret(),
        "PLATFORM_TO_ANALYTICS_SECRET": generate_secret(),
        "PLATFORM_TO_AI_SECRET": generate_secret(),
        "PLATFORM_TO_VIDEO_SECRET": generate_secret(),
        "PLATFORM_TO_MMS_SECRET": generate_secret(),
        "PLATFORM_TO_RCS_SECRET": generate_secret(),
        "PLATFORM_TO_SILENTOTP_SECRET": generate_secret(),
        "PLATFORM_TO_WEBHOOK_SECRET": generate_secret(),
        "PLATFORM_TO_AUDIT_SECRET": generate_secret(),
        
        # Backend secrets
        "BACKEND_TO_PAYMENT_SECRET": generate_secret(),
        "BACKEND_TO_AUDIT_SECRET": generate_secret(),
        "BACKEND_TO_IDENTITY_SECRET": generate_secret(),
    }


if __name__ == "__main__":
    # Generate all secrets when run directly
    print("# SMSLY Inter-Service Secrets (Zero Trust)")
    print("# Generated at:", __import__("datetime").datetime.now().isoformat())
    print("#" + "=" * 70)
    print()
    
    secrets = generate_all_secrets()
    for name, value in secrets.items():
        print(f"{name}={value}")
