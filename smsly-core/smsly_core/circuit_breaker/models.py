"""
Circuit Breaker Models
======================
Data models and enums for the circuit breaker pattern.
"""

import time
from dataclasses import dataclass, field
from enum import Enum


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"            # Failing, reject requests
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
