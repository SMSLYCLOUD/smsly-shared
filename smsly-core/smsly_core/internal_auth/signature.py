"""
Signature Functions
===================
HMAC signature computation and verification for request authentication.
"""

import hmac
import hashlib
import time
import uuid

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
        body_hash: SHA-256 hash of request body
        
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
    Verify request signature using constant-time comparison.
    
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


def check_timestamp_skew(
    timestamp: int,
    max_skew: int = MAX_TIMESTAMP_SKEW_SECONDS
) -> bool:
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
