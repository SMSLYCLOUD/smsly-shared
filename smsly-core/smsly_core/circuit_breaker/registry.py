"""
Circuit Breaker Registry
========================
Global registry for managing circuit breaker instances.
"""

import asyncio
from typing import Optional, Dict, Any
import structlog

from .models import CircuitBreakerConfig, CircuitBreakerState
from .breaker import CircuitBreaker

logger = structlog.get_logger(__name__)

# Global registry of circuit breakers
_breakers: Dict[str, CircuitBreaker] = {}
_registry_lock = asyncio.Lock()


async def get_breaker(
    service_name: str,
    config: Optional[CircuitBreakerConfig] = None,
) -> CircuitBreaker:
    """
    Get or create a circuit breaker for a service.
    
    Args:
        service_name: Name of the downstream service
        config: Optional configuration (only used if creating new breaker)
        
    Returns:
        CircuitBreaker instance
    """
    if service_name not in _breakers:
        async with _registry_lock:
            if service_name not in _breakers:
                _breakers[service_name] = CircuitBreaker(
                    name=service_name,
                    config=config,
                )
    return _breakers[service_name]


def get_breaker_sync(
    service_name: str,
    config: Optional[CircuitBreakerConfig] = None,
) -> CircuitBreaker:
    """Synchronous version of get_breaker."""
    if service_name not in _breakers:
        _breakers[service_name] = CircuitBreaker(
            name=service_name,
            config=config,
        )
    return _breakers[service_name]


def get_all_breaker_metrics() -> Dict[str, Dict[str, Any]]:
    """Get metrics for all registered circuit breakers."""
    return {
        name: breaker.metrics
        for name, breaker in _breakers.items()
    }


def reset_breaker(service_name: str):
    """Reset a circuit breaker to closed state (for testing/admin)."""
    if service_name in _breakers:
        breaker = _breakers[service_name]
        breaker._state = CircuitBreakerState()
        logger.info("circuit_reset", service=service_name)


def reset_all_breakers():
    """Reset all circuit breakers to closed state."""
    for name in _breakers:
        reset_breaker(name)


def get_registered_breakers() -> Dict[str, CircuitBreaker]:
    """Get all registered circuit breakers."""
    return dict(_breakers)
