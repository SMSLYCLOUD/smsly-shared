"""
SMSLY Exhaustive Logging Module

Provides comprehensive, structured logging for all microservices.
Includes request/response logging, audit events, performance metrics, and error tracking.

Usage (FastAPI):
    from shared.logging.exhaustive import (
        setup_logging,
        RequestLoggingMiddleware,
        log_event,
        log_audit,
    )
    
    # Setup at startup
    setup_logging(service_name="smsly-sms")
    
    # Add middleware
    app.add_middleware(RequestLoggingMiddleware)
    
    # Log events
    log_event("sms.sent", recipient="+1234567890", message_id="msg_123")
    log_audit("sms.send", actor_id="user_123", resource_id="msg_123")

Usage (Django):
    # In settings.py
    from shared.logging.exhaustive import get_django_logging_config
    LOGGING = get_django_logging_config(service_name="smsly-backend")
    
    # In middleware
    from shared.logging.exhaustive import DjangoRequestLoggingMiddleware
"""

import json
import logging
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable
from contextvars import ContextVar
from functools import wraps

# Context variables for request tracking
request_id_var: ContextVar[str] = ContextVar("request_id", default="")
user_id_var: ContextVar[str] = ContextVar("user_id", default="")
service_name_var: ContextVar[str] = ContextVar("service_name", default="unknown")


# =============================================================================
# JSON Formatter
# =============================================================================

class JSONFormatter(logging.Formatter):
    """
    Formats log records as JSON for structured logging.
    Compatible with ELK, Datadog, CloudWatch, etc.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": service_name_var.get(),
            "request_id": request_id_var.get() or None,
            "user_id": user_id_var.get() or None,
        }
        
        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }
        
        # Add source location
        log_data["source"] = {
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
        }
        
        return json.dumps(log_data, default=str)


# =============================================================================
# Setup Functions
# =============================================================================

def setup_logging(
    service_name: str,
    level: str = "INFO",
    json_output: bool = True,
) -> logging.Logger:
    """
    Configure logging for a microservice.
    
    Args:
        service_name: Name of the service (e.g., "smsly-sms")
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: Whether to output JSON (for production)
        
    Returns:
        Configured root logger
    """
    service_name_var.set(service_name)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Set formatter
    if json_output:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))
    
    root_logger.addHandler(handler)
    
    # Log startup
    root_logger.info(f"Logging configured for {service_name}", extra={
        "extra_data": {"event": "logging.configured", "service": service_name}
    })
    
    return root_logger


def get_django_logging_config(
    service_name: str,
    level: str = "INFO",
) -> Dict[str, Any]:
    """
    Get Django LOGGING configuration dict.
    
    Usage in settings.py:
        from shared.logging.exhaustive import get_django_logging_config
        LOGGING = get_django_logging_config("smsly-backend")
    """
    service_name_var.set(service_name)
    
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": JSONFormatter,
            },
            "verbose": {
                "format": "{asctime} | {levelname:8s} | {name} | {message}",
                "style": "{",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "stream": "ext://sys.stdout",
            },
        },
        "root": {
            "handlers": ["console"],
            "level": level,
        },
        "loggers": {
            "django": {"level": "INFO"},
            "django.request": {"level": "INFO"},
            "django.db.backends": {"level": "WARNING"},
            service_name: {"level": level, "propagate": True},
        },
    }


# =============================================================================
# Logging Functions
# =============================================================================

def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name."""
    return logging.getLogger(name)


def log_event(
    event_type: str,
    level: str = "INFO",
    **kwargs
) -> None:
    """
    Log a structured event.
    
    Args:
        event_type: Type of event (e.g., "sms.sent", "user.login")
        level: Log level
        **kwargs: Additional event data
    """
    logger = logging.getLogger("events")
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    extra_data = {
        "event": event_type,
        "event_data": kwargs,
    }
    
    logger.log(log_level, f"Event: {event_type}", extra={"extra_data": extra_data})


def log_audit(
    action: str,
    actor_id: str = None,
    actor_type: str = "user",
    resource_type: str = None,
    resource_id: str = None,
    outcome: str = "success",
    metadata: Dict[str, Any] = None,
) -> None:
    """
    Log an audit event.
    
    Args:
        action: Action performed (e.g., "sms.send", "user.login")
        actor_id: ID of the actor (user, API key, service)
        actor_type: Type of actor (user, api_key, service, system)
        resource_type: Type of resource affected
        resource_id: ID of the resource
        outcome: Result (success, failure, pending)
        metadata: Additional context
    """
    logger = logging.getLogger("audit")
    
    extra_data = {
        "audit": True,
        "action": action,
        "actor": {
            "id": actor_id or user_id_var.get(),
            "type": actor_type,
        },
        "resource": {
            "type": resource_type,
            "id": resource_id,
        },
        "outcome": outcome,
        "metadata": metadata or {},
    }
    
    logger.info(f"Audit: {action}", extra={"extra_data": extra_data})


def log_metric(
    metric_name: str,
    value: float,
    unit: str = None,
    tags: Dict[str, str] = None,
) -> None:
    """
    Log a metric value.
    
    Args:
        metric_name: Name of the metric
        value: Metric value
        unit: Unit of measurement
        tags: Additional tags/dimensions
    """
    logger = logging.getLogger("metrics")
    
    extra_data = {
        "metric": True,
        "metric_name": metric_name,
        "metric_value": value,
        "metric_unit": unit,
        "metric_tags": tags or {},
    }
    
    logger.info(f"Metric: {metric_name}={value}", extra={"extra_data": extra_data})


def log_error(
    error: Exception,
    context: str = None,
    **kwargs
) -> None:
    """
    Log an error with full context.
    
    Args:
        error: The exception
        context: Description of what was happening
        **kwargs: Additional context
    """
    logger = logging.getLogger("errors")
    
    extra_data = {
        "error": True,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "context": context,
        "error_data": kwargs,
    }
    
    logger.error(
        f"Error: {context or type(error).__name__}",
        exc_info=error,
        extra={"extra_data": extra_data}
    )


# =============================================================================
# Request Logging Middleware (FastAPI)
# =============================================================================

class RequestLoggingMiddleware:
    """
    FastAPI middleware for exhaustive request/response logging.
    """
    
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger("http")
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Generate request ID
        req_id = str(uuid.uuid4())[:8]
        request_id_var.set(req_id)
        
        # Extract request info
        method = scope.get("method", "")
        path = scope.get("path", "")
        query = scope.get("query_string", b"").decode()
        headers = dict(scope.get("headers", []))
        
        # Get client IP
        client = scope.get("client", ("", 0))
        client_ip = client[0] if client else ""
        
        # Forwarded IP
        forwarded = headers.get(b"x-forwarded-for", b"").decode()
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        # Get user ID from headers
        user_id = headers.get(b"x-smsly-key-id", b"").decode()
        if user_id:
            user_id_var.set(user_id)
        
        # Start timing
        start_time = time.time()
        
        # Log request
        self.logger.info(f"Request: {method} {path}", extra={
            "extra_data": {
                "http": True,
                "direction": "request",
                "method": method,
                "path": path,
                "query": query,
                "client_ip": client_ip,
                "user_agent": headers.get(b"user-agent", b"").decode()[:200],
            }
        })
        
        # Response tracking
        status_code = 500
        
        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 500)
            await send(message)
        
        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as e:
            log_error(e, context=f"{method} {path}")
            raise
        finally:
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Log response
            level = "INFO" if status_code < 400 else "WARNING" if status_code < 500 else "ERROR"
            
            self.logger.log(
                getattr(logging, level),
                f"Response: {method} {path} -> {status_code} ({duration_ms}ms)",
                extra={
                    "extra_data": {
                        "http": True,
                        "direction": "response",
                        "method": method,
                        "path": path,
                        "status_code": status_code,
                        "duration_ms": duration_ms,
                        "client_ip": client_ip,
                    }
                }
            )
            
            # Log metric
            log_metric(
                "http.request.duration",
                duration_ms,
                unit="ms",
                tags={"method": method, "path": path, "status": str(status_code)}
            )


# =============================================================================
# Django Request Logging Middleware
# =============================================================================

class DjangoRequestLoggingMiddleware:
    """
    Django middleware for exhaustive request/response logging.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger("http")
    
    def __call__(self, request):
        # Generate request ID
        req_id = str(uuid.uuid4())[:8]
        request_id_var.set(req_id)
        request.request_id = req_id
        
        # Get user ID
        if hasattr(request, "user") and request.user.is_authenticated:
            user_id_var.set(str(request.user.id))
        
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Start timing
        start_time = time.time()
        
        # Log request
        self.logger.info(f"Request: {request.method} {request.path}", extra={
            "extra_data": {
                "http": True,
                "direction": "request",
                "method": request.method,
                "path": request.path,
                "query": request.GET.dict(),
                "client_ip": client_ip,
                "user_agent": request.META.get("HTTP_USER_AGENT", "")[:200],
            }
        })
        
        # Get response
        try:
            response = self.get_response(request)
            status_code = response.status_code
        except Exception as e:
            log_error(e, context=f"{request.method} {request.path}")
            raise
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Log response
        level = "INFO" if status_code < 400 else "WARNING" if status_code < 500 else "ERROR"
        
        self.logger.log(
            getattr(logging, level),
            f"Response: {request.method} {request.path} -> {status_code} ({duration_ms}ms)",
            extra={
                "extra_data": {
                    "http": True,
                    "direction": "response",
                    "method": request.method,
                    "path": request.path,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "client_ip": client_ip,
                }
            }
        )
        
        # Log metric
        log_metric(
            "http.request.duration",
            duration_ms,
            unit="ms",
            tags={"method": request.method, "path": request.path, "status": str(status_code)}
        )
        
        return response
    
    def _get_client_ip(self, request):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")


# =============================================================================
# Decorators
# =============================================================================

def log_function(
    event_prefix: str = None,
    log_args: bool = True,
    log_result: bool = False,
):
    """
    Decorator to log function calls.
    
    Usage:
        @log_function("sms.process")
        async def process_sms(recipient: str, message: str):
            ...
    """
    def decorator(func: Callable):
        prefix = event_prefix or f"{func.__module__}.{func.__name__}"
        logger = logging.getLogger("functions")
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            
            # Log entry
            entry_data = {"event": f"{prefix}.enter"}
            if log_args:
                entry_data["args"] = str(args)[:500]
                entry_data["kwargs"] = {k: str(v)[:100] for k, v in kwargs.items()}
            
            logger.debug(f"Enter: {prefix}", extra={"extra_data": entry_data})
            
            try:
                result = await func(*args, **kwargs)
                
                # Log exit
                exit_data = {
                    "event": f"{prefix}.exit",
                    "duration_ms": int((time.time() - start) * 1000),
                    "success": True,
                }
                if log_result:
                    exit_data["result"] = str(result)[:500]
                
                logger.debug(f"Exit: {prefix}", extra={"extra_data": exit_data})
                return result
                
            except Exception as e:
                logger.error(f"Error: {prefix}", extra={
                    "extra_data": {
                        "event": f"{prefix}.error",
                        "duration_ms": int((time.time() - start) * 1000),
                        "error": str(e),
                    }
                }, exc_info=True)
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            
            # Log entry
            entry_data = {"event": f"{prefix}.enter"}
            if log_args:
                entry_data["args"] = str(args)[:500]
                entry_data["kwargs"] = {k: str(v)[:100] for k, v in kwargs.items()}
            
            logger.debug(f"Enter: {prefix}", extra={"extra_data": entry_data})
            
            try:
                result = func(*args, **kwargs)
                
                # Log exit
                exit_data = {
                    "event": f"{prefix}.exit",
                    "duration_ms": int((time.time() - start) * 1000),
                    "success": True,
                }
                if log_result:
                    exit_data["result"] = str(result)[:500]
                
                logger.debug(f"Exit: {prefix}", extra={"extra_data": exit_data})
                return result
                
            except Exception as e:
                logger.error(f"Error: {prefix}", extra={
                    "extra_data": {
                        "event": f"{prefix}.error",
                        "duration_ms": int((time.time() - start) * 1000),
                        "error": str(e),
                    }
                }, exc_info=True)
                raise
        
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Setup
    "setup_logging",
    "get_django_logging_config",
    "get_logger",
    
    # Logging functions
    "log_event",
    "log_audit",
    "log_metric",
    "log_error",
    
    # Middleware
    "RequestLoggingMiddleware",
    "DjangoRequestLoggingMiddleware",
    
    # Decorators
    "log_function",
    
    # Context
    "request_id_var",
    "user_id_var",
    "service_name_var",
]
