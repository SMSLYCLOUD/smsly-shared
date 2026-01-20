"""
Rate Limit Models
=================
Data models for rate limiting results.
"""

from typing import Optional
from dataclasses import dataclass
from enum import Enum


class RateLimitResult(str, Enum):
    """Rate limit decision result."""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    DEGRADED = "degraded"


@dataclass
class RateLimitInfo:
    """Rate limit check result with quota information."""
    allowed: bool
    remaining: int
    limit: int
    reset_at: int  # Unix timestamp
    retry_after: Optional[int] = None  # Seconds until retry allowed
    
    @property
    def result(self) -> RateLimitResult:
        return RateLimitResult.ALLOWED if self.allowed else RateLimitResult.BLOCKED
