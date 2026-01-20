"""
Internal Authentication Module
==============================
Secure inter-service communication with HMAC signing and replay protection.
"""

import hmac
import hashlib
import time
import uuid
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class AuthDecision(str, Enum):
    """Security gateway decision types."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class BlockReason(str, Enum):
    """Reasons for blocking a request."""
    INVALID_KEY = "invalid_api_key"
    REVOKED_KEY = "revoked_api_key"
    EXPIRED_KEY = "expired_api_key"
    INVALID_SIGNATURE = "invalid_signature"
    REPLAY_DETECTED = "replay_detected"
    TIMESTAMP_SKEW = "timestamp_skew"
    RATE_LIMITED = "rate_limited"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    CONCURRENCY_EXCEEDED = "concurrency_exceeded"


@dataclass
class SignedRequest:
    """A request with HMAC signature for verification."""
    method: str
    path: str
    timestamp: int
    nonce: str
    body_hash: str
    signature: str
    key_id: str


@dataclass
class AuthResult:
    """Result of authentication check."""
    decision: AuthDecision
    reason: Optional[str] = None
    reason_code: Optional[BlockReason] = None
    request_id: Optional[str] = None
    key_id: Optional[str] = None
    scopes: Optional[list] = None
    ttl_ms: int = 30000


# Configuration
MAX_TIMESTAMP_SKEW_SECONDS = 300  # 5 minutes
SIGNATURE_ALGORITHM = "sha256"


def compute_signature(
    secret: str,
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body_hash: str,
) -> str:
    """
    Compute HMAC-SHA256 signature for request authentication.
    
    The signature covers:
    - HTTP method
    - Request path
    - Timestamp (Unix epoch seconds)
    - Unique nonce
    - SHA-256 hash of request body
    
    Args:
        secret: Shared secret or API key secret
        method: HTTP method (GET, POST, etc.)
        path: Request path (e.g., /v1/messages)
        timestamp: Unix timestamp in seconds
        nonce: Unique request identifier
        body_hash: SHA-256 hash of request body (empty string hash for no body)
        
    Returns:
        Hex-encoded HMAC-SHA256 signature
    """
    message = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()
    return signature


def hash_body(body: bytes) -> str:
    """
    Compute SHA-256 hash of request body.
    
    Args:
        body: Raw request body bytes
        
    Returns:
        Hex-encoded SHA-256 hash
    """
    return hashlib.sha256(body).hexdigest()


def verify_signature(
    secret: str,
    method: str,
    path: str,
    timestamp: int,
    nonce: str,
    body_hash: str,
    provided_signature: str,
) -> bool:
    """
    Verify request signature.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        secret: Shared secret
        method: HTTP method
        path: Request path
        timestamp: Request timestamp
        nonce: Request nonce
        body_hash: Body hash from request
        provided_signature: Signature to verify
        
    Returns:
        True if signature is valid
    """
    expected_signature = compute_signature(
        secret, method, path, timestamp, nonce, body_hash
    )
    return hmac.compare_digest(expected_signature, provided_signature)


def check_timestamp_skew(timestamp: int, max_skew: int = MAX_TIMESTAMP_SKEW_SECONDS) -> bool:
    """
    Check if timestamp is within acceptable skew.
    
    Args:
        timestamp: Unix timestamp from request
        max_skew: Maximum allowed skew in seconds
        
    Returns:
        True if timestamp is acceptable
    """
    current_time = int(time.time())
    return abs(current_time - timestamp) <= max_skew


def generate_nonce() -> str:
    """Generate a unique nonce for request signing."""
    return str(uuid.uuid4())


def create_signed_headers(
    secret: str,
    key_id: str,
    method: str,
    path: str,
    body: bytes = b"",
) -> Dict[str, str]:
    """
    Create headers for a signed request.
    
    Args:
        secret: API key secret or shared secret
        key_id: API key ID for identification
        method: HTTP method
        path: Request path
        body: Request body (optional)
        
    Returns:
        Dictionary of headers to include in request
    """
    timestamp = int(time.time())
    nonce = generate_nonce()
    body_hash = hash_body(body)
    signature = compute_signature(secret, method, path, timestamp, nonce, body_hash)
    
    return {
        "X-SMSLY-Key-ID": key_id,
        "X-SMSLY-Timestamp": str(timestamp),
        "X-SMSLY-Nonce": nonce,
        "X-SMSLY-Signature": signature,
    }


def parse_signed_headers(headers: Dict[str, str], body_hash: str) -> Optional[SignedRequest]:
    """
    Parse signed request headers.
    
    Args:
        headers: Request headers
        body_hash: Computed body hash
        
    Returns:
        SignedRequest if all required headers present, None otherwise
    """
    try:
        return SignedRequest(
            method=headers.get("X-SMSLY-Method", ""),  # Set by gateway
            path=headers.get("X-SMSLY-Path", ""),  # Set by gateway
            timestamp=int(headers.get("X-SMSLY-Timestamp", "0")),
            nonce=headers.get("X-SMSLY-Nonce", ""),
            body_hash=body_hash,
            signature=headers.get("X-SMSLY-Signature", ""),
            key_id=headers.get("X-SMSLY-Key-ID", ""),
        )
    except (ValueError, KeyError) as e:
        logger.warning("Failed to parse signed headers", error=str(e))
        return None


class NonceCache:
    """
    In-memory nonce cache for replay protection.
    
    In production, use Redis for distributed caching.
    """
    
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, float] = {}
    
    def check_and_store(self, nonce: str) -> bool:
        """
        Check if nonce is fresh and store it.
        
        Args:
            nonce: The nonce to check
            
        Returns:
            True if nonce is fresh (not seen before)
        """
        self._cleanup()
        
        if nonce in self._cache:
            logger.warning("Replay attack detected", nonce=nonce[:8])
            return False
        
        self._cache[nonce] = time.time()
        return True
    
    def _cleanup(self) -> None:
        """Remove expired nonces."""
        current_time = time.time()
        expired = [
            nonce for nonce, ts in self._cache.items()
            if current_time - ts > self.ttl_seconds
        ]
        for nonce in expired:
            del self._cache[nonce]
