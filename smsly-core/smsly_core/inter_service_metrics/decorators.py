"""
Decorators and FastAPI Integration
===================================
Decorators for tracking inter-service calls and FastAPI metrics endpoint.
"""

import time
import asyncio
from functools import wraps
from typing import TypeVar, Callable, Awaitable

from .prometheus_definitions import (
    PROMETHEUS_AVAILABLE,
    INTER_SERVICE_REGISTRY,
    generate_latest,
)
from .recording import record_service_call
from .simple_metrics import get_simple_metrics

T = TypeVar("T")


def track_service_call(
    target_service: str,
    endpoint: str,
    source_service: str = "unknown",
):
    """
    Decorator to track inter-service call metrics.
    
    Example:
        @track_service_call("identity-service", "/v1/validate")
        async def validate_token(token: str):
            return await identity_client.validate(token)
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            start = time.perf_counter()
            status = "success"
            
            try:
                result = await func(*args, **kwargs)
                return result
            except asyncio.TimeoutError:
                status = "timeout"
                raise
            except Exception:
                status = "exception"
                raise
            finally:
                duration = time.perf_counter() - start
                await record_service_call(
                    source=source_service,
                    target=target_service,
                    method="CALL",
                    endpoint=endpoint,
                    status=status,
                    duration_seconds=duration,
                )
        
        return wrapper
    return decorator


def get_metrics_app():
    """
    Get ASGI app for /metrics endpoint.
    
    Usage:
        from fastapi import FastAPI
        app = FastAPI()
        app.mount("/metrics", get_metrics_app())
    """
    if PROMETHEUS_AVAILABLE:
        from prometheus_client import make_asgi_app
        return make_asgi_app(registry=INTER_SERVICE_REGISTRY)
    else:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        
        async def metrics_endpoint(request):
            return JSONResponse(get_simple_metrics().get_stats())
        
        return Starlette(routes=[Route("/", metrics_endpoint)])


def get_metrics_text() -> str:
    """Get metrics in Prometheus text format."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(INTER_SERVICE_REGISTRY).decode("utf-8")
    else:
        import json
        return json.dumps(get_simple_metrics().get_stats(), indent=2)
