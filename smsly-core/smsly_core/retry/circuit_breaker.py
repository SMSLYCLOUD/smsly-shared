"""
Simple Circuit Breaker
======================
Circuit breaker pattern for preventing cascading failures.
Note: For full-featured circuit breaker, use smsly_core.circuit_breaker package.
"""

import time
from typing import TypeVar, Callable, Awaitable, Optional
import structlog

from .exceptions import CircuitBreakerOpen

logger = structlog.get_logger(__name__)

T = TypeVar('T')


class CircuitBreaker:
    """
    Circuit breaker pattern for preventing cascading failures.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failures exceeded threshold, requests fail fast
    - HALF_OPEN: Testing if service recovered
    """
    
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"
    
    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout_seconds: float = 30.0,
    ):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout_seconds = timeout_seconds
        
        self._state = self.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
    
    @property
    def state(self) -> str:
        return self._state
    
    def _should_attempt(self) -> bool:
        """Check if a request should be allowed."""
        if self._state == self.CLOSED:
            return True
        
        if self._state == self.OPEN:
            if self._last_failure_time:
                if time.time() - self._last_failure_time >= self.timeout_seconds:
                    self._state = self.HALF_OPEN
                    self._success_count = 0
                    logger.info("Circuit breaker half-open, testing recovery")
                    return True
            return False
        
        # HALF_OPEN
        return True
    
    def record_success(self) -> None:
        """Record a successful request."""
        self._failure_count = 0
        
        if self._state == self.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._state = self.CLOSED
                logger.info("Circuit breaker closed, service recovered")
    
    def record_failure(self) -> None:
        """Record a failed request."""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._state == self.HALF_OPEN:
            self._state = self.OPEN
            logger.warning("Circuit breaker opened from half-open")
        elif self._failure_count >= self.failure_threshold:
            self._state = self.OPEN
            logger.warning("Circuit breaker opened", failures=self._failure_count)
    
    async def execute(
        self,
        func: Callable[..., Awaitable[T]],
        *args,
        **kwargs,
    ) -> T:
        """
        Execute a function through the circuit breaker.
        
        Args:
            func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Result of func
            
        Raises:
            CircuitBreakerOpen: If circuit is open
        """
        if not self._should_attempt():
            raise CircuitBreakerOpen("Circuit breaker is open")
        
        try:
            result = await func(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise
