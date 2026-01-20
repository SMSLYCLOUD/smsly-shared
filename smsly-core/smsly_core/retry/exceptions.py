"""
Retry Exceptions
================
Exception classes for retry operations.
"""

from typing import Optional


class RetryExhausted(Exception):
    """Raised when all retry attempts have been exhausted."""
    
    def __init__(self, message: str, last_exception: Optional[Exception] = None):
        super().__init__(message)
        self.last_exception = last_exception


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker is open."""
    pass
