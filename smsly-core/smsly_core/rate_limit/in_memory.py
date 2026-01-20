"""
In-Memory Rate Limiter
======================
Simple in-memory token bucket rate limiter for development and testing.
"""

import time
from .models import RateLimitInfo


class InMemoryRateLimiter:
    """
    Simple in-memory token bucket rate limiter.
    
    For development and testing only.
    Use RedisRateLimiter in production.
    """
    
    def __init__(self, rate: int = 100, window: int = 60):
        """
        Args:
            rate: Number of requests allowed per window
            window: Window size in seconds
        """
        self.rate = rate
        self.window = window
        self._buckets: dict = {}
    
    def check(self, key: str) -> RateLimitInfo:
        """
        Check if request is allowed.
        
        Args:
            key: Unique identifier (e.g., API key, user ID)
            
        Returns:
            RateLimitInfo with decision and quota
        """
        now = time.time()
        window_start = int(now / self.window) * self.window
        
        if key not in self._buckets:
            self._buckets[key] = {"window": window_start, "count": 0}
        
        bucket = self._buckets[key]
        
        # Reset if new window
        if bucket["window"] < window_start:
            bucket["window"] = window_start
            bucket["count"] = 0
        
        remaining = self.rate - bucket["count"]
        reset_at = int(window_start + self.window)
        
        if bucket["count"] >= self.rate:
            return RateLimitInfo(
                allowed=False,
                remaining=0,
                limit=self.rate,
                reset_at=reset_at,
                retry_after=reset_at - int(now),
            )
        
        bucket["count"] += 1
        return RateLimitInfo(
            allowed=True,
            remaining=remaining - 1,
            limit=self.rate,
            reset_at=reset_at,
        )
    
    def get_key_pattern(self, prefix: str, identifier: str) -> str:
        """Generate a rate limit key."""
        return f"ratelimit:{prefix}:{identifier}"
