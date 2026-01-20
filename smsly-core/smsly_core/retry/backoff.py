"""
Retry Backoff
=============
Exponential backoff retry implementation.
"""

import asyncio
import random
from typing import TypeVar, Callable, Awaitable, Optional, Set, Type
from functools import wraps
import structlog

from .exceptions import RetryExhausted

logger = structlog.get_logger(__name__)

T = TypeVar('T')


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
            delay = min(
                base_delay * (exponential_base ** (attempt - 1)),
                max_delay
            )
            
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
