"""
Nonce Cache
===========
Distributed nonce cache for replay protection with Redis backend
and in-memory fallback for dev/test.
"""

import os
import time
from typing import Dict, Optional
import structlog

logger = structlog.get_logger(__name__)


class NonceCache:
    """
    Nonce cache for replay protection.
    
    Uses Redis for distributed caching in production.
    Falls back to in-memory dict for dev/test environments.
    """
    
    def __init__(self, ttl_seconds: int = 600, redis_url: Optional[str] = None):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, float] = {}
        self._redis = None
        
        url = redis_url or os.getenv("REDIS_URL")
        if url:
            try:
                import redis
                self._redis = redis.from_url(url, decode_responses=True)
                self._redis.ping()
                logger.info("nonce_cache_redis_connected")
            except Exception as e:
                logger.warning(
                    "nonce_cache_redis_unavailable",
                    error=str(e),
                    fallback="in-memory",
                )
                self._redis = None
    
    def check_and_store(self, nonce: str) -> bool:
        """
        Check if nonce is fresh and store it.
        
        Uses Redis SET NX EX for atomic check-and-store in production.
        Falls back to in-memory dict for dev/test environments.
        
        Args:
            nonce: The nonce to check
            
        Returns:
            True if nonce is fresh (not seen before)
        """
        if self._redis:
            try:
                # SET NX: only set if key does not exist; EX sets TTL
                added = self._redis.set(
                    f"nonce:{nonce}", "1", nx=True, ex=self.ttl_seconds
                )
                if not added:
                    logger.warning("Replay attack detected", nonce=nonce[:8])
                return bool(added)
            except Exception as e:
                logger.error("nonce_cache_redis_error", error=str(e))
                # Fail-closed: reject request when Redis is unavailable
                return False
        
        # In-memory fallback only for dev/test (no Redis configured)
        self._cleanup()
        
        if nonce in self._cache:
            logger.warning("Replay attack detected", nonce=nonce[:8])
            return False
        
        self._cache[nonce] = time.time()
        return True
    
    def _cleanup(self) -> None:
        """Remove expired nonces (in-memory only)."""
        current_time = time.time()
        expired = [
            nonce for nonce, ts in self._cache.items()
            if current_time - ts > self.ttl_seconds
        ]
        for nonce in expired:
            del self._cache[nonce]
