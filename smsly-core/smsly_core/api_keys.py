"""
API Key Management Module
=========================
Secure API key generation, validation, and rotation.
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from dataclasses import dataclass
from enum import Enum


class APIKeyScope(str, Enum):
    """Available API key scopes/permissions."""
    SMS_SEND = "sms:send"
    SMS_READ = "sms:read"
    MMS_SEND = "mms:send"
    WHATSAPP_SEND = "whatsapp:send"
    RCS_SEND = "rcs:send"
    VOICE_CALL = "voice:call"
    VERIFY_START = "verify:start"
    VERIFY_CHECK = "verify:check"
    CAMPAIGNS_CREATE = "campaigns:create"
    CAMPAIGNS_MANAGE = "campaigns:manage"
    ADMIN = "admin"


@dataclass
class APIKeyInfo:
    """API key metadata (never includes the actual key)."""
    id: str
    name: str
    prefix: str
    scopes: List[str]
    created_at: datetime
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    
    @property
    def is_active(self) -> bool:
        """Check if the key is currently active."""
        if self.revoked_at:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True


def generate_api_key(prefix: str = "sk_live") -> tuple[str, str, str]:
    """
    Generate a new API key.
    
    Returns:
        Tuple of (full_key, key_prefix, key_hash)
        - full_key: The complete API key (show to user ONCE)
        - key_prefix: First 8 chars for identification
        - key_hash: SHA-256 hash for storage
    """
    # Generate 32 random bytes -> 64 char hex string
    random_part = secrets.token_hex(32)
    full_key = f"{prefix}_{random_part}"
    
    # Extract prefix for display (sk_live_abc12345)
    key_prefix = f"{prefix}_{random_part[:8]}"
    
    # Hash for secure storage
    key_hash = hash_api_key(full_key)
    
    return full_key, key_prefix, key_hash


def hash_api_key(key: str) -> str:
    """
    Hash an API key using SHA-256.
    
    Args:
        key: The full API key
        
    Returns:
        SHA-256 hex digest
    """
    return hashlib.sha256(key.encode()).hexdigest()


def validate_api_key(provided_key: str, stored_hash: str) -> bool:
    """
    Validate an API key against its stored hash.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        provided_key: The key provided by the user
        stored_hash: The stored hash to compare against
        
    Returns:
        True if the key is valid
    """
    provided_hash = hash_api_key(provided_key)
    return secrets.compare_digest(provided_hash, stored_hash)


def generate_test_key() -> tuple[str, str, str]:
    """Generate a test mode API key."""
    return generate_api_key(prefix="sk_test")


def parse_key_prefix(key: str) -> tuple[str, str]:
    """
    Parse an API key to extract its mode and prefix.
    
    Args:
        key: Full API key (e.g., "sk_live_abc123...")
        
    Returns:
        Tuple of (mode, identifier) e.g., ("live", "abc12345")
    """
    parts = key.split("_", 2)
    if len(parts) < 3:
        raise ValueError("Invalid API key format")
    
    mode = parts[1]  # "live" or "test"
    identifier = parts[2][:8]  # First 8 chars of random part
    
    return mode, identifier


def mask_api_key(key: str) -> str:
    """
    Mask an API key for safe display.
    
    Args:
        key: Full API key
        
    Returns:
        Masked key (e.g., "sk_live_abc1****")
    """
    if "_" not in key:
        return "****"
    
    parts = key.rsplit("_", 1)
    prefix = parts[0]
    secret_part = parts[1] if len(parts) > 1 else ""
    
    if len(secret_part) > 8:
        masked = secret_part[:4] + "****"
    else:
        masked = "****"
    
    return f"{prefix}_{masked}"
