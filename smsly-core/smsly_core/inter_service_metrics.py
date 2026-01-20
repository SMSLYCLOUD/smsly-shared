"""
SMSLY Core - Inter-Service Metrics
====================================
Prometheus-based metrics for monitoring inter-service communication.

Tracks:
- Request latency (histogram with percentiles)
- Request counts by status
- Circuit breaker states
- Connection pool utilization

Usage:
    from smsly_core.inter_service_metrics import (
        InstrumentedClient,
        track_service_call,
        get_metrics_app,
    )
    
    # Option 1: Instrumented HTTP client
    client = InstrumentedClient(
        base_url="http://identity-service:8000",
        service_name="identity-service",
    )
    response = await client.get("/v1/validate")
    
    # Option 2: Decorator
    @track_service_call("policy-service", "/v1/evaluate")
    async def evaluate_policy(context: dict):
        return await policy_client.evaluate(context)
    
    # Mount metrics endpoint
    from fastapi import FastAPI
    app = FastAPI()
    app.mount("/metrics", get_metrics_app())
"""

import time
import asyncio
from functools import wraps
from typing import Optional, Dict, Any, Callable, TypeVar, Awaitable
import structlog

logger = structlog.get_logger(__name__)

T = TypeVar("T")

# Try to import prometheus_client, fall back to simple metrics if not available
try:
    from prometheus_client import (
        Histogram,
        Counter,
        Gauge,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )
    from prometheus_client import make_asgi_app
    
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not installed, using simple metrics")


# ============================================================================
# Prometheus Metrics Definitions
# ============================================================================

if PROMETHEUS_AVAILABLE:
    # Custom registry for inter-service metrics
    INTER_SERVICE_REGISTRY = CollectorRegistry()
    
    # Latency histogram with standard buckets
    SERVICE_REQUEST_LATENCY = Histogram(
        name="inter_service_request_duration_seconds",
        documentation="Time spent on inter-service requests",
        labelnames=["source", "target", "method", "endpoint", "status"],
        buckets=[
            0.001,   # 1ms
            0.005,   # 5ms
            0.01,    # 10ms
            0.025,   # 25ms
            0.05,    # 50ms
            0.1,     # 100ms
            0.25,    # 250ms
            0.5,     # 500ms
            1.0,     # 1s
            2.5,     # 2.5s
            5.0,     # 5s
            10.0,    # 10s
        ],
        registry=INTER_SERVICE_REGISTRY,
    )
    
    # Request counter
    SERVICE_REQUEST_TOTAL = Counter(
        name="inter_service_requests_total",
        documentation="Total number of inter-service requests",
        labelnames=["source", "target", "method", "endpoint", "status"],
        registry=INTER_SERVICE_REGISTRY,
    )
    
    # Inflight requests gauge
    SERVICE_REQUESTS_INFLIGHT = Gauge(
        name="inter_service_requests_inflight",
        documentation="Number of inter-service requests currently in progress",
        labelnames=["source", "target"],
        registry=INTER_SERVICE_REGISTRY,
    )
    
    # Circuit breaker state gauge
    CIRCUIT_BREAKER_STATE = Gauge(
        name="circuit_breaker_state",
        documentation="Circuit breaker state (0=closed, 1=half-open, 2=open)",
        labelnames=["service"],
        registry=INTER_SERVICE_REGISTRY,
    )
    
    # Connection pool utilization
    CONNECTION_POOL_SIZE = Gauge(
        name="http_client_pool_connections",
        documentation="Number of connections in HTTP client pool",
        labelnames=["service", "state"],  # state: idle, active
        registry=INTER_SERVICE_REGISTRY,
    )
    
    # Error counter
    SERVICE_ERRORS = Counter(
        name="inter_service_errors_total",
        documentation="Total inter-service errors",
        labelnames=["source", "target", "error_type"],
        registry=INTER_SERVICE_REGISTRY,
    )


# ============================================================================
# Simple Metrics Fallback (when prometheus_client not available)
# ============================================================================

class SimpleInterServiceMetrics:
    """Simple in-memory metrics when prometheus_client is not available."""
    
    def __init__(self):
        self._latencies: Dict[str, list] = {}
        self._counts: Dict[str, int] = {}
        self._lock = asyncio.Lock()
    
    async def record_latency(
        self,
        source: str,
        target: str,
        method: str,
        endpoint: str,
        status: str,
        duration: float,
    ):
        async with self._lock:
            key = f"{source}:{target}:{method}:{endpoint}:{status}"
            if key not in self._latencies:
                self._latencies[key] = []
            self._latencies[key].append(duration)
            
            # Keep only last 1000 samples
            if len(self._latencies[key]) > 1000:
                self._latencies[key] = self._latencies[key][-1000:]
            
            # Count
            self._counts[key] = self._counts.get(key, 0) + 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregated statistics."""
        stats = {}
        for key, values in self._latencies.items():
            if values:
                sorted_values = sorted(values)
                stats[key] = {
                    "count": len(values),
                    "avg_ms": sum(values) / len(values) * 1000,
                    "p50_ms": sorted_values[len(values) // 2] * 1000,
                    "p95_ms": sorted_values[int(len(values) * 0.95)] * 1000,
                    "p99_ms": sorted_values[int(len(values) * 0.99)] * 1000,
                }
        return stats


# Global simple metrics instance
_simple_metrics = SimpleInterServiceMetrics()


# ============================================================================
# Recording Functions
# ============================================================================

async def record_service_call(
    source: str,
    target: str,
    method: str,
    endpoint: str,
    status: str,
    duration_seconds: float,
):
    """
    Record metrics for an inter-service call.
    
    Args:
        source: Name of the calling service
        target: Name of the called service
        method: HTTP method (GET, POST, etc.)
        endpoint: Request path/endpoint
        status: Response status (success, error, timeout, circuit_open)
        duration_seconds: Request duration in seconds
    """
    if PROMETHEUS_AVAILABLE:
        labels = {
            "source": source,
            "target": target,
            "method": method,
            "endpoint": _normalize_endpoint(endpoint),
            "status": status,
        }
        SERVICE_REQUEST_LATENCY.labels(**labels).observe(duration_seconds)
        SERVICE_REQUEST_TOTAL.labels(**labels).inc()
    else:
        await _simple_metrics.record_latency(
            source, target, method,
            _normalize_endpoint(endpoint),
            status, duration_seconds,
        )


def record_circuit_state(service: str, state: str):
    """
    Record circuit breaker state change.
    
    Args:
        service: Service name
        state: State (closed, half_open, open)
    """
    if PROMETHEUS_AVAILABLE:
        state_value = {"closed": 0, "half_open": 1, "open": 2}.get(state, -1)
        CIRCUIT_BREAKER_STATE.labels(service=service).set(state_value)


def record_error(source: str, target: str, error_type: str):
    """Record an inter-service error."""
    if PROMETHEUS_AVAILABLE:
        SERVICE_ERRORS.labels(
            source=source,
            target=target,
            error_type=error_type,
        ).inc()


def _normalize_endpoint(endpoint: str) -> str:
    """
    Normalize endpoint to reduce cardinality.
    
    Replaces UUIDs, numeric IDs, etc. with placeholders.
    """
    import re
    
    # Replace UUIDs
    endpoint = re.sub(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        '{uuid}',
        endpoint,
        flags=re.IGNORECASE,
    )
    
    # Replace numeric IDs in path segments
    endpoint = re.sub(r'/\d+(?=/|$)', '/{id}', endpoint)
    
    return endpoint


# ============================================================================
# Instrumented HTTP Client
# ============================================================================

class InstrumentedClient:
    """
    HTTP client wrapper that automatically records inter-service metrics.
    
    Example:
        client = InstrumentedClient(
            base_url="http://identity:8000",
            service_name="identity-service",
            source_service="platform-api",
        )
        
        response = await client.get("/v1/validate", params={"token": "..."})
    """
    
    def __init__(
        self,
        base_url: str,
        service_name: str,
        source_service: str = "unknown",
        timeout: float = 30.0,
    ):
        try:
            import httpx
            self._client = httpx.AsyncClient(
                base_url=base_url,
                timeout=timeout,
            )
        except ImportError:
            raise ImportError("httpx is required for InstrumentedClient")
        
        self._service_name = service_name
        self._source_service = source_service
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ):
        """Make an HTTP request with metrics tracking."""
        start = time.perf_counter()
        status = "success"
        
        if PROMETHEUS_AVAILABLE:
            SERVICE_REQUESTS_INFLIGHT.labels(
                source=self._source_service,
                target=self._service_name,
            ).inc()
        
        try:
            response = await self._client.request(method, url, **kwargs)
            
            if response.status_code >= 500:
                status = "server_error"
            elif response.status_code >= 400:
                status = "client_error"
            
            return response
            
        except asyncio.TimeoutError:
            status = "timeout"
            record_error(self._source_service, self._service_name, "timeout")
            raise
        except Exception as e:
            status = "exception"
            record_error(self._source_service, self._service_name, type(e).__name__)
            raise
        finally:
            duration = time.perf_counter() - start
            
            if PROMETHEUS_AVAILABLE:
                SERVICE_REQUESTS_INFLIGHT.labels(
                    source=self._source_service,
                    target=self._service_name,
                ).dec()
            
            await record_service_call(
                source=self._source_service,
                target=self._service_name,
                method=method,
                endpoint=url,
                status=status,
                duration_seconds=duration,
            )
    
    async def get(self, url: str, **kwargs):
        """GET request."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs):
        """POST request."""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs):
        """PUT request."""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs):
        """DELETE request."""
        return await self.request("DELETE", url, **kwargs)
    
    async def patch(self, url: str, **kwargs):
        """PATCH request."""
        return await self.request("PATCH", url, **kwargs)
    
    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, *args):
        await self.close()


# ============================================================================
# Decorator
# ============================================================================

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
                    method="CALL",  # For function calls
                    endpoint=endpoint,
                    status=status,
                    duration_seconds=duration,
                )
        
        return wrapper
    return decorator


# ============================================================================
# FastAPI Integration
# ============================================================================

def get_metrics_app():
    """
    Get ASGI app for /metrics endpoint.
    
    Usage:
        from fastapi import FastAPI
        app = FastAPI()
        app.mount("/metrics", get_metrics_app())
    """
    if PROMETHEUS_AVAILABLE:
        return make_asgi_app(registry=INTER_SERVICE_REGISTRY)
    else:
        # Simple fallback endpoint
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        
        async def metrics_endpoint(request):
            return JSONResponse(_simple_metrics.get_stats())
        
        return Starlette(routes=[Route("/", metrics_endpoint)])


def get_metrics_text() -> str:
    """Get metrics in Prometheus text format."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(INTER_SERVICE_REGISTRY).decode("utf-8")
    else:
        import json
        return json.dumps(_simple_metrics.get_stats(), indent=2)
