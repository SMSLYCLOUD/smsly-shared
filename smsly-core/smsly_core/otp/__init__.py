"""
OTP Generation and Verification
================================
Secure OTP generation with rate limiting and brute-force protection.
"""

# Re-export all public APIs for backwards compatibility
from .models import OTPMethod, OTPConfig, OTPSession
from .hashing import generate_otp, hash_otp, verify_otp_hash, generate_salt, hash_phone
from .generator import OTPGenerator
from .proof_token import ProofToken

__all__ = [
    # Models
    "OTPMethod",
    "OTPConfig",
    "OTPSession",
    # Hashing
    "generate_otp",
    "hash_otp",
    "verify_otp_hash",
    "generate_salt",
    "hash_phone",
    # Generator
    "OTPGenerator",
    # Proof Token
    "ProofToken",
]
