"""
Circuit Breaker Decorator
=========================
Decorator for wrapping async functions with circuit breaker protection.
"""

from functools import wraps
from typing import Optional, Callable, TypeVar, Awaitable

from .models import CircuitBreakerConfig
from .registry import get_breaker_sync

T = TypeVar("T")


def circuit_breaker(
    service_name: str,
    config: Optional[CircuitBreakerConfig] = None,
    fallback: Optional[Callable[[], Awaitable[T]]] = None,
):
    """
    Decorator to wrap async functions with circuit breaker.
    
    Example:
        @circuit_breaker("identity-service")
        async def validate_token(token: str):
            return await identity_client.validate(token)
            
        @circuit_breaker("sms-service", fallback=lambda: {"status": "queued"})
        async def send_sms(to: str, body: str):
            return await sms_client.send(to=to, body=body)
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        breaker = get_breaker_sync(service_name, config)
        
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await breaker.call(
                func(*args, **kwargs),
                fallback=fallback,
            )
        
        return wrapper
    
    return decorator
