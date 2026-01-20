"""
SMSLY Shared Logging Module

Exhaustive, structured logging for all microservices.
"""

from .exhaustive import (
    # Setup
    setup_logging,
    get_django_logging_config,
    get_logger,
    
    # Logging functions
    log_event,
    log_audit,
    log_metric,
    log_error,
    
    # Middleware
    RequestLoggingMiddleware,
    DjangoRequestLoggingMiddleware,
    
    # Decorators
    log_function,
    
    # Context
    request_id_var,
    user_id_var,
    service_name_var,
)

__all__ = [
    "setup_logging",
    "get_django_logging_config",
    "get_logger",
    "log_event",
    "log_audit",
    "log_metric",
    "log_error",
    "RequestLoggingMiddleware",
    "DjangoRequestLoggingMiddleware",
    "log_function",
    "request_id_var",
    "user_id_var",
    "service_name_var",
]
