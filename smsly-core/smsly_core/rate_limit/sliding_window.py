"""
Sliding Window Rate Limiter
===========================
Sliding window rate limiter using Redis sorted sets.
"""

import time

from .models import RateLimitInfo


class SlidingWindowLimiter:
    """
    Sliding window rate limiter using Redis sorted sets.
    
    More accurate than token bucket but slightly more expensive.
    """
    
    def __init__(self, redis_client, rate: int = 100, window: int = 60):
        self.redis = redis_client
        self.rate = rate
        self.window = window
    
    async def check(self, key: str) -> RateLimitInfo:
        """Check using sliding window algorithm."""
        now = time.time()
        window_start = now - self.window
        
        # Remove old entries
        await self.redis.zremrangebyscore(key, 0, window_start)
        
        # Count current entries
        count = await self.redis.zcard(key)
        
        reset_at = int(now + self.window)
        
        if count >= self.rate:
            # Find oldest entry to calculate retry_after
            oldest = await self.redis.zrange(key, 0, 0, withscores=True)
            retry_after = (
                int(oldest[0][1] + self.window - now) 
                if oldest else self.window
            )
            
            return RateLimitInfo(
                allowed=False,
                remaining=0,
                limit=self.rate,
                reset_at=reset_at,
                retry_after=retry_after,
            )
        
        # Add new entry
        await self.redis.zadd(key, {str(now): now})
        await self.redis.expire(key, self.window * 2)
        
        return RateLimitInfo(
            allowed=True,
            remaining=self.rate - count - 1,
            limit=self.rate,
            reset_at=reset_at,
        )
