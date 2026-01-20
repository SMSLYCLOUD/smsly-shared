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

# Re-export all public APIs for backwards compatibility
from .prometheus_definitions import (
    PROMETHEUS_AVAILABLE,
    INTER_SERVICE_REGISTRY,
    SERVICE_REQUEST_LATENCY,
    SERVICE_REQUEST_TOTAL,
    SERVICE_REQUESTS_INFLIGHT,
    CIRCUIT_BREAKER_STATE,
    CONNECTION_POOL_SIZE,
    SERVICE_ERRORS,
)

from .simple_metrics import SimpleInterServiceMetrics, get_simple_metrics

from .recording import (
    record_service_call,
    record_circuit_state,
    record_error,
)

from .instrumented_client import InstrumentedClient

from .decorators import (
    track_service_call,
    get_metrics_app,
    get_metrics_text,
)

__all__ = [
    # Prometheus
    "PROMETHEUS_AVAILABLE",
    "INTER_SERVICE_REGISTRY",
    "SERVICE_REQUEST_LATENCY",
    "SERVICE_REQUEST_TOTAL",
    "SERVICE_REQUESTS_INFLIGHT",
    "CIRCUIT_BREAKER_STATE",
    "CONNECTION_POOL_SIZE",
    "SERVICE_ERRORS",
    # Simple metrics
    "SimpleInterServiceMetrics",
    "get_simple_metrics",
    # Recording
    "record_service_call",
    "record_circuit_state",
    "record_error",
    # Client
    "InstrumentedClient",
    # Decorators
    "track_service_call",
    "get_metrics_app",
    "get_metrics_text",
]
