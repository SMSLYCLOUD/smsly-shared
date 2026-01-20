"""
Prometheus Metrics Definitions
==============================
Prometheus metric definitions for inter-service communication monitoring.
"""

import structlog

logger = structlog.get_logger(__name__)

# Try to import prometheus_client
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


# Prometheus metrics (only defined if prometheus_client is available)
INTER_SERVICE_REGISTRY = None
SERVICE_REQUEST_LATENCY = None
SERVICE_REQUEST_TOTAL = None
SERVICE_REQUESTS_INFLIGHT = None
CIRCUIT_BREAKER_STATE = None
CONNECTION_POOL_SIZE = None
SERVICE_ERRORS = None


if PROMETHEUS_AVAILABLE:
    # Custom registry for inter-service metrics
    INTER_SERVICE_REGISTRY = CollectorRegistry()
    
    # Latency histogram with standard buckets
    SERVICE_REQUEST_LATENCY = Histogram(
        name="inter_service_request_duration_seconds",
        documentation="Time spent on inter-service requests",
        labelnames=["source", "target", "method", "endpoint", "status"],
        buckets=[
            0.001, 0.005, 0.01, 0.025, 0.05,
            0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
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
        labelnames=["service", "state"],
        registry=INTER_SERVICE_REGISTRY,
    )
    
    # Error counter
    SERVICE_ERRORS = Counter(
        name="inter_service_errors_total",
        documentation="Total inter-service errors",
        labelnames=["source", "target", "error_type"],
        registry=INTER_SERVICE_REGISTRY,
    )
