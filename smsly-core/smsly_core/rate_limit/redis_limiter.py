"""
Redis Rate Limiter
==================
Redis-backed token bucket rate limiter using Lua scripts for atomic operations.
"""

import time
from typing import Optional
import structlog

from .models import RateLimitInfo

logger = structlog.get_logger(__name__)

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
