"""
Retry Logic with Exponential Backoff
=====================================
Robust retry mechanism for transient failures.
"""

import asyncio
import random
from typing import TypeVar, Callable, Awaitable, Optional, Set, Type
from functools import wraps
import structlog

logger = structlog.get_logger(__name__)

T = TypeVar('T')


class RetryExhausted(Exception):
    """Raised when all retry attempts have been exhausted."""
    def __init__(self, message: str, last_exception: Optional[Exception] = None):
        super().__init__(message)
        self.last_exception = last_exception


async def retry_with_backoff(
    func: Callable[..., Awaitable[T]],
    *args,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Optional[Set[Type[Exception]]] = None,
    **kwargs,
) -> T:
    """
    Execute a function with exponential backoff retry.
    
    Args:
        func: Async function to execute
        *args: Positional arguments for func
        max_attempts: Maximum number of attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential calculation
        jitter: Add random jitter to delays
        retryable_exceptions: Set of exception types to retry on
        **kwargs: Keyword arguments for func
        
    Returns:
        Result of func
        
    Raises:
        RetryExhausted: If all attempts fail
    """
    retryable = retryable_exceptions or {Exception}
    last_exception = None
    
    for attempt in range(1, max_attempts + 1):
        try:
            return await func(*args, **kwargs)
        except tuple(retryable) as e:
            last_exception = e
            
            if attempt == max_attempts:
                logger.error(
                    "Retry exhausted",
                    func=func.__name__,
                    attempts=attempt,
                    error=str(e),
                )
                raise RetryExhausted(
                    f"Failed after {max_attempts} attempts: {e}",
                    last_exception=e,
                )
            
            # Calculate delay
            delay = min(base_delay * (exponential_base ** (attempt - 1)), max_delay)
            
            if jitter:
                delay = delay * (0.5 + random.random())
            
            logger.warning(
                "Retrying after failure",
                func=func.__name__,
                attempt=attempt,
                delay=delay,
                error=str(e),
            )
            
            await asyncio.sleep(delay)
    
    raise RetryExhausted(f"Failed after {max_attempts} attempts", last_exception)


def with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retryable_exceptions: Optional[Set[Type[Exception]]] = None,
):
    """
    Decorator for retry with exponential backoff.
    
    Usage:
        @with_retry(max_attempts=5)
        async def fetch_data():
            ...
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await retry_with_backoff(
                func,
                *args,
                max_attempts=max_attempts,
                base_delay=base_delay,
                max_delay=max_delay,
                retryable_exceptions=retryable_exceptions,
                **kwargs,
            )
        return wrapper
    return decorator


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
            # Check if timeout has passed
            if self._last_failure_time:
                import time
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
        import time
        
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
        except Exception as e:
            self.record_failure()
            raise


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open."""
    pass
