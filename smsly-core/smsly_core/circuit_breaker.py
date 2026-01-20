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

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Optional, Dict, Any, Callable, TypeVar, Awaitable
import structlog

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreakerError(Exception):
    """Raised when circuit is open and request is rejected."""
    def __init__(self, service_name: str, state: CircuitState, retry_after: float):
        self.service_name = service_name
        self.state = state
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker for '{service_name}' is {state.value}. "
            f"Retry after {retry_after:.1f}s"
        )


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker."""
    fail_threshold: int = 5           # Failures before opening
    success_threshold: int = 2        # Successes to close from half-open
    timeout: float = 30.0             # Seconds to stay open before half-open
    half_open_max_calls: int = 3      # Max concurrent calls in half-open
    excluded_exceptions: tuple = ()   # Exceptions that don't count as failures


@dataclass
class CircuitBreakerState:
    """Runtime state of a circuit breaker."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float = 0
    last_state_change: float = field(default_factory=time.time)
    half_open_calls: int = 0
    
    # Metrics
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0
    total_rejections: int = 0


class CircuitBreaker:
    """
    Async-compatible circuit breaker.
    
    Example:
        breaker = CircuitBreaker("identity-service")
        
        try:
            result = await breaker.call(some_async_func())
        except CircuitBreakerError:
            # Handle circuit open
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
        """
        Check and possibly transition state.
        Returns True if request should be allowed.
        """
        async with self._lock:
            now = time.time()
            
            if self._state.state == CircuitState.CLOSED:
                return True
            
            elif self._state.state == CircuitState.OPEN:
                # Check if timeout has passed
                time_since_open = now - self._state.last_state_change
                if time_since_open >= self.config.timeout:
                    # Transition to half-open
                    self._state.state = CircuitState.HALF_OPEN
                    self._state.last_state_change = now
                    self._state.half_open_calls = 0
                    self._state.success_count = 0
                    logger.info(
                        "circuit_half_open",
                        service=self.name,
                        after_seconds=time_since_open,
                    )
                    return True
                else:
                    # Still open
                    self._state.total_rejections += 1
                    return False
            
            elif self._state.state == CircuitState.HALF_OPEN:
                # Allow limited calls in half-open
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
                    # Close the circuit
                    self._state.state = CircuitState.CLOSED
                    self._state.failure_count = 0
                    self._state.last_state_change = time.time()
                    logger.info("circuit_closed", service=self.name)
            
            elif self._state.state == CircuitState.CLOSED:
                # Reset failure count on success
                self._state.failure_count = 0
    
    async def _record_failure(self, exc: Exception):
        """Record a failed call."""
        # Check if exception is excluded
        if isinstance(exc, self.config.excluded_exceptions):
            return
        
        async with self._lock:
            self._state.total_failures += 1
            self._state.total_calls += 1
            self._state.failure_count += 1
            self._state.last_failure_time = time.time()
            
            if self._state.state == CircuitState.HALF_OPEN:
                # Any failure in half-open reopens circuit
                self._state.state = CircuitState.OPEN
                self._state.last_state_change = time.time()
                logger.warning(
                    "circuit_reopened",
                    service=self.name,
                    error=str(exc),
                )
            
            elif self._state.state == CircuitState.CLOSED:
                if self._state.failure_count >= self.config.fail_threshold:
                    # Open the circuit
                    self._state.state = CircuitState.OPEN
                    self._state.last_state_change = time.time()
                    logger.warning(
                        "circuit_opened",
                        service=self.name,
                        failures=self._state.failure_count,
                        error=str(exc),
                    )
    
    async def call(
        self,
        coro: Awaitable[T],
        fallback: Optional[Callable[[], Awaitable[T]]] = None,
    ) -> T:
        """
        Execute a coroutine with circuit breaker protection.
        
        Args:
            coro: Async operation to execute
            fallback: Optional fallback if circuit is open
            
        Returns:
            Result of the coroutine or fallback
            
        Raises:
            CircuitBreakerError: If circuit is open and no fallback provided
        """
        allowed = await self._check_state()
        
        if not allowed:
            if fallback:
                logger.debug("circuit_fallback", service=self.name)
                return await fallback()
            
            retry_after = self.config.timeout - (
                time.time() - self._state.last_state_change
            )
            raise CircuitBreakerError(
                self.name,
                self._state.state,
                max(0, retry_after),
            )
        
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
            raise CircuitBreakerError(
                self.name,
                self._state.state,
                max(0, retry_after),
            )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if exc_type is None:
            await self._record_success()
        else:
            await self._record_failure(exc_val)
        return False  # Don't suppress exceptions


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
