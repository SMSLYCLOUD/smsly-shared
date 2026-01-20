"""
SMSLY Core - Circuit Breaker
=============================
Async circuit breaker for inter-service resilience.

Circuit breaker pattern prevents cascade failures when downstream services
are unavailable. States:

1. CLOSED: Normal operation, requests flow through
2. OPEN: Service is failing, requests are immediately rejected
3. HALF-OPEN: Testing if service has recovered

Usage:
    from smsly_core.circuit_breaker import circuit_breaker, CircuitBreakerError
    
    @circuit_breaker("identity-service")
    async def call_identity_service():
        return await client.get("/v1/validate")
        
    # Or with context manager
    async with get_breaker("identity-service"):
        response = await client.get("/v1/validate")
"""

# Re-export all public APIs for backwards compatibility
from .models import (
    CircuitState,
    CircuitBreakerError,
    CircuitBreakerConfig,
    CircuitBreakerState,
)

from .breaker import CircuitBreaker

from .registry import (
    get_breaker,
    get_breaker_sync,
    get_all_breaker_metrics,
    reset_breaker,
    reset_all_breakers,
    get_registered_breakers,
)

from .decorators import circuit_breaker

__all__ = [
    # Models
    "CircuitState",
    "CircuitBreakerError",
    "CircuitBreakerConfig",
    "CircuitBreakerState",
    # Breaker
    "CircuitBreaker",
    # Registry
    "get_breaker",
    "get_breaker_sync",
    "get_all_breaker_metrics",
    "reset_breaker",
    "reset_all_breakers",
    "get_registered_breakers",
    # Decorator
    "circuit_breaker",
]
