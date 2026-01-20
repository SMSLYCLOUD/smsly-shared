"""
SMSLY Shared Authentication Module

Zero-trust inter-service authentication for all microservices.
"""

from .inter_service import (
    InternalAuthConfig,
    validate_secret,
    validate_internal_secret,
    require_internal_auth_fastapi,
    DjangoInternalAuthMixin,
    generate_secret,
    generate_all_secrets,
)

__all__ = [
    "InternalAuthConfig",
    "validate_secret",
    "validate_internal_secret",
    "require_internal_auth_fastapi",
    "DjangoInternalAuthMixin",
    "generate_secret",
    "generate_all_secrets",
]
