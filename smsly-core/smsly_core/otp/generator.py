"""
OTP Generator
=============
High-level OTP generation and verification class.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
import structlog

from .models import OTPMethod, OTPConfig, OTPSession
from .hashing import generate_otp, generate_salt, hash_otp, hash_phone, verify_otp_hash

logger = structlog.get_logger(__name__)


class OTPGenerator:
    """High-level OTP generation and verification."""
    
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
