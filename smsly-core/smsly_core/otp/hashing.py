"""
OTP Hashing Utilities
=====================
Secure hashing and verification functions for OTP codes.
"""

import secrets
import hashlib
import hmac


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
    Hash an OTP with salt using SHA-256.
    
    Args:
        otp: Plain OTP
        salt: Random salt
        
    Returns:
        Hashed OTP
    """
    return hashlib.sha256(f"{salt}:{otp}".encode()).hexdigest()


def verify_otp_hash(otp: str, salt: str, stored_hash: str) -> bool:
    """
    Verify an OTP against its hash.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        otp: User-provided OTP
        salt: Original salt
        stored_hash: Stored hash to compare
        
    Returns:
        True if OTP matches
    """
    computed_hash = hash_otp(otp, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


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
