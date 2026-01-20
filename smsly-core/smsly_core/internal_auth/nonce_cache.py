"""
Nonce Cache
===========
In-memory nonce cache for replay protection.
"""

import time
from typing import Dict
import structlog

logger = structlog.get_logger(__name__)


class NonceCache:
    """
    In-memory nonce cache for replay protection.
    
    In production, use Redis for distributed caching.
    """
    
    def __init__(self, ttl_seconds: int = 600):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, float] = {}
    
    def check_and_store(self, nonce: str) -> bool:
        """
        Check if nonce is fresh and store it.
        
        Args:
            nonce: The nonce to check
            
        Returns:
            True if nonce is fresh (not seen before)
        """
        self._cleanup()
        
        if nonce in self._cache:
            logger.warning("Replay attack detected", nonce=nonce[:8])
            return False
        
        self._cache[nonce] = time.time()
        return True
    
    def _cleanup(self) -> None:
        """Remove expired nonces."""
        current_time = time.time()
        expired = [
            nonce for nonce, ts in self._cache.items()
            if current_time - ts > self.ttl_seconds
        ]
        for nonce in expired:
            del self._cache[nonce]
