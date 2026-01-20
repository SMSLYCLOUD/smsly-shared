"""
Rate Limiting Module for SMSLY Core
====================================
Token bucket and sliding window rate limiters with Redis backend.
"""

import time
import json
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class RateLimitResult(str, Enum):
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


# Lua script for atomic token bucket in Redis
TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local bucket = redis.call('HGETALL', key)
local window_start = math.floor(now / window) * window
local count = 0

if #bucket > 0 then
    local saved_window = tonumber(bucket[2])
    local saved_count = tonumber(bucket[4])
    
    if saved_window >= window_start then
        count = saved_count
    end
end

if count >= rate then
    local reset_at = window_start + window
    local retry_after = reset_at - now
    return {0, 0, rate, reset_at, retry_after}
end

count = count + 1
redis.call('HSET', key, 'window', window_start, 'count', count)
redis.call('EXPIRE', key, window * 2)

local remaining = rate - count
local reset_at = window_start + window

return {1, remaining, rate, reset_at, 0}
"""


class RedisRateLimiter:
    """
    Redis-backed token bucket rate limiter.
    
    Uses Lua scripts for atomic operations.
    """
    
    def __init__(self, redis_client, rate: int = 100, window: int = 60):
        """
        Args:
            redis_client: Async Redis client
            rate: Requests per window
            window: Window size in seconds
        """
        self.redis = redis_client
        self.rate = rate
        self.window = window
        self._script_sha: Optional[str] = None
    
    async def _ensure_script(self) -> str:
        """Load Lua script into Redis if needed."""
        if self._script_sha is None:
            self._script_sha = await self.redis.script_load(TOKEN_BUCKET_SCRIPT)
        return self._script_sha
    
    async def check(self, key: str) -> RateLimitInfo:
        """
        Check if request is allowed using Redis.
        
        Args:
            key: Rate limit key
            
        Returns:
            RateLimitInfo with decision
        """
        script_sha = await self._ensure_script()
        now = int(time.time())
        
        try:
            result = await self.redis.evalsha(
                script_sha,
                1,
                key,
                self.rate,
                self.window,
                now,
            )
            
            allowed, remaining, limit, reset_at, retry_after = result
            
            return RateLimitInfo(
                allowed=bool(allowed),
                remaining=int(remaining),
                limit=int(limit),
                reset_at=int(reset_at),
                retry_after=int(retry_after) if retry_after else None,
            )
        except Exception as e:
            logger.error("Rate limit check failed", error=str(e))
            # Fail open in case of Redis issues
            return RateLimitInfo(
                allowed=True,
                remaining=self.rate,
                limit=self.rate,
                reset_at=int(time.time()) + self.window,
            )
    
    def get_key(self, service: str, api_key_id: str) -> str:
        """Generate a rate limit key for an API key."""
        return f"ratelimit:{service}:{api_key_id}"


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
            retry_after = int(oldest[0][1] + self.window - now) if oldest else self.window
            
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
