"""
Internal Authentication Module
==============================
Secure inter-service communication with HMAC signing and replay protection.
"""

# Re-export all public APIs for backwards compatibility
from .models import AuthDecision, BlockReason, SignedRequest, AuthResult
from .signature import (
    compute_signature,
    hash_body,
    verify_signature,
    check_timestamp_skew,
    generate_nonce,
    MAX_TIMESTAMP_SKEW_SECONDS,
    SIGNATURE_ALGORITHM,
)
from .headers import create_signed_headers, parse_signed_headers
from .nonce_cache import NonceCache

__all__ = [
    # Models
    "AuthDecision",
    "BlockReason",
    "SignedRequest",
    "AuthResult",
    # Signature
    "compute_signature",
    "hash_body",
    "verify_signature",
    "check_timestamp_skew",
    "generate_nonce",
    "MAX_TIMESTAMP_SKEW_SECONDS",
    "SIGNATURE_ALGORITHM",
    # Headers
    "create_signed_headers",
    "parse_signed_headers",
    # Nonce Cache
    "NonceCache",
]
