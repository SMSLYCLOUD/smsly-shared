"""
Internal Auth Models
====================
Data models and enums for internal authentication.
"""

from typing import Optional
from dataclasses import dataclass
from enum import Enum


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
