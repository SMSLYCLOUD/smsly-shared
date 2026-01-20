"""
OTP Models
==========
Data models and enums for OTP generation and verification.
"""

from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass
from enum import Enum


class OTPMethod(str, Enum):
    """OTP delivery methods."""
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
