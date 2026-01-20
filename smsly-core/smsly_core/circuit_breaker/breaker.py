"""
Circuit Breaker Core
====================
The main CircuitBreaker class for async-compatible circuit breaker pattern.
"""

import asyncio
import time
from typing import Optional, Dict, Any, Callable, TypeVar, Awaitable
import structlog

from .models import (
    CircuitState,
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitBreakerError,
)

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class CircuitBreaker:
    """
    Async-compatible circuit breaker.
    
    Example:
        breaker = CircuitBreaker("identity-service")
        
        try:
            result = await breaker.call(some_async_func())
        except CircuitBreakerError:
            return fallback_value
    """
    
    def __init__(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None,
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState()
        self._lock = asyncio.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state.state
    
    @property
    def metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics."""
        return {
            "name": self.name,
            "state": self._state.state.value,
            "failure_count": self._state.failure_count,
            "success_count": self._state.success_count,
            "total_calls": self._state.total_calls,
            "total_failures": self._state.total_failures,
            "total_successes": self._state.total_successes,
            "total_rejections": self._state.total_rejections,
            "last_failure": self._state.last_failure_time,
        }
    
    async def _check_state(self) -> bool:
        """Check and possibly transition state. Returns True if allowed."""
        async with self._lock:
            now = time.time()
            
            if self._state.state == CircuitState.CLOSED:
                return True
            
            elif self._state.state == CircuitState.OPEN:
                time_since_open = now - self._state.last_state_change
                if time_since_open >= self.config.timeout:
                    self._state.state = CircuitState.HALF_OPEN
                    self._state.last_state_change = now
                    self._state.half_open_calls = 0
                    self._state.success_count = 0
                    logger.info("circuit_half_open", service=self.name)
                    return True
                else:
                    self._state.total_rejections += 1
                    return False
            
            elif self._state.state == CircuitState.HALF_OPEN:
                if self._state.half_open_calls < self.config.half_open_max_calls:
                    self._state.half_open_calls += 1
                    return True
                else:
                    self._state.total_rejections += 1
                    return False
        
        return False
    
    async def _record_success(self):
        """Record a successful call."""
        async with self._lock:
            self._state.total_successes += 1
            self._state.total_calls += 1
            
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.success_count += 1
                if self._state.success_count >= self.config.success_threshold:
                    self._state.state = CircuitState.CLOSED
                    self._state.failure_count = 0
                    self._state.last_state_change = time.time()
                    logger.info("circuit_closed", service=self.name)
            
            elif self._state.state == CircuitState.CLOSED:
                self._state.failure_count = 0
    
    async def _record_failure(self, exc: Exception):
        """Record a failed call."""
        if isinstance(exc, self.config.excluded_exceptions):
            return
        
        async with self._lock:
            self._state.total_failures += 1
            self._state.total_calls += 1
            self._state.failure_count += 1
            self._state.last_failure_time = time.time()
            
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.state = CircuitState.OPEN
                self._state.last_state_change = time.time()
                logger.warning("circuit_reopened", service=self.name, error=str(exc))
            
            elif self._state.state == CircuitState.CLOSED:
                if self._state.failure_count >= self.config.fail_threshold:
                    self._state.state = CircuitState.OPEN
                    self._state.last_state_change = time.time()
                    logger.warning(
                        "circuit_opened",
                        service=self.name,
                        failures=self._state.failure_count,
                    )
    
    async def call(
        self,
        coro: Awaitable[T],
        fallback: Optional[Callable[[], Awaitable[T]]] = None,
    ) -> T:
        """Execute a coroutine with circuit breaker protection."""
        allowed = await self._check_state()
        
        if not allowed:
            if fallback:
                logger.debug("circuit_fallback", service=self.name)
                return await fallback()
            
            retry_after = self.config.timeout - (
                time.time() - self._state.last_state_change
            )
            raise CircuitBreakerError(self.name, self._state.state, max(0, retry_after))
        
        try:
            result = await coro
            await self._record_success()
            return result
        except Exception as e:
            await self._record_failure(e)
            raise
    
    async def __aenter__(self):
        """Context manager entry."""
        allowed = await self._check_state()
        if not allowed:
            retry_after = self.config.timeout - (
                time.time() - self._state.last_state_change
            )
            raise CircuitBreakerError(self.name, self._state.state, max(0, retry_after))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type is None:
            await self._record_success()
        else:
            await self._record_failure(exc_val)
        return False
