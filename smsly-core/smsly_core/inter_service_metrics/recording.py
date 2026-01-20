"""
Metrics Recording Functions
===========================
Functions for recording inter-service call metrics.
"""

import re

from .prometheus_definitions import (
    PROMETHEUS_AVAILABLE,
    SERVICE_REQUEST_LATENCY,
    SERVICE_REQUEST_TOTAL,
    CIRCUIT_BREAKER_STATE,
    SERVICE_ERRORS,
)
from .simple_metrics import get_simple_metrics


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
    normalized_endpoint = _normalize_endpoint(endpoint)
    
    if PROMETHEUS_AVAILABLE:
        labels = {
            "source": source,
            "target": target,
            "method": method,
            "endpoint": normalized_endpoint,
            "status": status,
        }
        SERVICE_REQUEST_LATENCY.labels(**labels).observe(duration_seconds)
        SERVICE_REQUEST_TOTAL.labels(**labels).inc()
    else:
        await get_simple_metrics().record_latency(
            source, target, method,
            normalized_endpoint,
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
