"""
OTP Hashing Utilities
=====================
Secure hashing and verification functions for OTP codes.

Uses Argon2id for OTP hashing to prevent brute-force attacks.
With only 1M possible values for 6-digit OTPs, SHA-256 is too fast.
"""

import secrets
import hashlib

from smsly_core.password.hasher import get_cached_hasher


def generate_otp(length: int = 6, alphanumeric: bool = False) -> str:
    """
    Generate a secure random OTP.
    
    Args:
        length: Number of characters/digits
        alphanumeric: Use letters in addition to digits
        
    Returns:
        OTP string
    """
    if alphanumeric:
        # Exclude confusing characters (0, O, 1, l, I)
        chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return ''.join(secrets.choice(chars) for _ in range(length))
    else:
        # Numeric OTP
        max_value = 10 ** length - 1
        otp = secrets.randbelow(max_value + 1)
        return str(otp).zfill(length)


def hash_otp(otp: str, salt: str) -> str:
    """
    Hash an OTP with salt using Argon2id.
    
    Args:
        otp: Plain OTP
        salt: Random salt
        
    Returns:
        Argon2id hash
    """
    hasher = get_cached_hasher()
    return hasher.hash(f"{salt}:{otp}")


def verify_otp_hash(otp: str, salt: str, stored_hash: str) -> bool:
    """
    Verify an OTP against its Argon2id hash.
    
    Args:
        otp: User-provided OTP
        salt: Original salt
        stored_hash: Stored Argon2id hash
        
    Returns:
        True if OTP matches
    """
    try:
        hasher = get_cached_hasher()
        hasher.verify(stored_hash, f"{salt}:{otp}")
        return True
    except Exception:
        return False


def generate_salt() -> str:
    """Generate a random salt for OTP hashing."""
    return secrets.token_hex(16)


def hash_phone(phone: str, pepper: str = "") -> str:
    """
    Hash a phone number for privacy.
    
    Args:
        phone: E.164 phone number
        pepper: Optional secret pepper
        
    Returns:
        SHA-256 hash
    """
    return hashlib.sha256(f"{pepper}:{phone}".encode()).hexdigest()
