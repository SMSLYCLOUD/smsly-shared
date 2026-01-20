"""
OTP Generation and Verification
================================
Secure OTP generation with rate limiting and brute-force protection.
"""

import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class OTPMethod(str, Enum):
    SMS = "sms"
    EMAIL = "email"
    VOICE = "voice"
    PUSH = "push"
    SILENT = "silent"


@dataclass
class OTPConfig:
    """Configuration for OTP generation."""
    length: int = 6
    expiry_seconds: int = 300  # 5 minutes
    max_attempts: int = 3
    rate_limit_seconds: int = 60  # Min time between OTPs
    use_alphanumeric: bool = False


@dataclass
class OTPSession:
    """An OTP verification session."""
    id: str
    phone_hash: str
    otp_hash: str
    salt: str
    method: OTPMethod
    attempts_remaining: int
    expires_at: datetime
    created_at: datetime
    verified_at: Optional[datetime] = None
    
    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None


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
    
    Uses constant-time comparison.
    
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


class OTPGenerator:
    """
    High-level OTP generation and verification.
    """
    
    def __init__(self, config: Optional[OTPConfig] = None):
        self.config = config or OTPConfig()
    
    def generate(self) -> Tuple[str, str, str]:
        """
        Generate an OTP with salt and hash.
        
        Returns:
            Tuple of (otp, salt, hash)
        """
        otp = generate_otp(
            length=self.config.length,
            alphanumeric=self.config.use_alphanumeric,
        )
        salt = generate_salt()
        otp_hash = hash_otp(otp, salt)
        
        return otp, salt, otp_hash
    
    def create_session(
        self,
        phone: str,
        method: OTPMethod = OTPMethod.SMS,
    ) -> Tuple[str, OTPSession]:
        """
        Create a new OTP session.
        
        Args:
            phone: Phone number
            method: Delivery method
            
        Returns:
            Tuple of (plain_otp, session)
        """
        import uuid
        
        otp, salt, otp_hash = self.generate()
        now = datetime.now(timezone.utc)
        
        session = OTPSession(
            id=str(uuid.uuid4()),
            phone_hash=hash_phone(phone),
            otp_hash=otp_hash,
            salt=salt,
            method=method,
            attempts_remaining=self.config.max_attempts,
            expires_at=now + timedelta(seconds=self.config.expiry_seconds),
            created_at=now,
        )
        
        logger.info(
            "OTP session created",
            session_id=session.id,
            method=method.value,
            expires_in=self.config.expiry_seconds,
        )
        
        return otp, session
    
    def verify(self, session: OTPSession, otp: str) -> Tuple[bool, str]:
        """
        Verify an OTP against a session.
        
        Args:
            session: The OTP session
            otp: User-provided OTP
            
        Returns:
            Tuple of (success, message)
        """
        if session.is_verified:
            return False, "OTP already used"
        
        if session.is_expired:
            logger.warning("OTP expired", session_id=session.id)
            return False, "OTP expired"
        
        if session.attempts_remaining <= 0:
            logger.warning("OTP attempts exhausted", session_id=session.id)
            return False, "Too many attempts"
        
        # Decrement attempts
        session.attempts_remaining -= 1
        
        if verify_otp_hash(otp, session.salt, session.otp_hash):
            session.verified_at = datetime.now(timezone.utc)
            logger.info("OTP verified successfully", session_id=session.id)
            return True, "Verified"
        else:
            logger.warning(
                "Invalid OTP attempt",
                session_id=session.id,
                remaining=session.attempts_remaining,
            )
            return False, f"Invalid OTP. {session.attempts_remaining} attempts remaining"


class ProofToken:
    """
    Generates cryptographic proof of successful verification.
    """
    
    def __init__(self, secret: str):
        self.secret = secret
    
    def generate(self, session_id: str, phone_hash: str) -> str:
        """
        Generate a proof token for a verified session.
        
        Args:
            session_id: Verified session ID
            phone_hash: Hashed phone number
            
        Returns:
            Signed proof token
        """
        import time
        import base64
        import json
        
        payload = {
            "sid": session_id,
            "ph": phone_hash[:16],  # Truncated for privacy
            "ts": int(time.time()),
            "ver": "1",
        }
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
        
        signature = hmac.new(
            self.secret.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()[:32]
        
        return f"{payload_b64}.{signature}"
    
    def verify(self, token: str, max_age_seconds: int = 3600) -> Optional[dict]:
        """
        Verify a proof token.
        
        Args:
            token: The proof token
            max_age_seconds: Maximum token age
            
        Returns:
            Payload if valid, None otherwise
        """
        import time
        import base64
        import json
        
        try:
            parts = token.split('.')
            if len(parts) != 2:
                return None
            
            payload_b64, signature = parts
            
            # Verify signature
            expected_sig = hmac.new(
                self.secret.encode(),
                payload_b64.encode(),
                hashlib.sha256,
            ).hexdigest()[:32]
            
            if not hmac.compare_digest(signature, expected_sig):
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            payload = json.loads(payload_json)
            
            # Check expiry
            if time.time() - payload.get("ts", 0) > max_age_seconds:
                return None
            
            return payload
        except Exception:
            return None
