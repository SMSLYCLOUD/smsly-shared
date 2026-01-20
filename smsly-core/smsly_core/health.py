"""
Unified Health Check Module
===========================
Provides comprehensive health checks with component status for all services.
"""

import time
from typing import Optional, Dict, Any, Callable, Awaitable
from fastapi import APIRouter, Response
from pydantic import BaseModel
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentHealth(BaseModel):
    status: str
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: HealthStatus
    service: str
    version: str
    components: Dict[str, ComponentHealth]
    timestamp: float


async def check_database(engine) -> ComponentHealth:
    """Check database connectivity and latency."""
    try:
        start = time.time()
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        latency = (time.time() - start) * 1000
        return ComponentHealth(status="connected", latency_ms=round(latency, 2))
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return ComponentHealth(status="error", error=str(e))


async def check_redis(redis_client) -> ComponentHealth:
    """Check Redis connectivity and latency."""
    try:
        start = time.time()
        await redis_client.ping()
        latency = (time.time() - start) * 1000
        return ComponentHealth(status="connected", latency_ms=round(latency, 2))
    except Exception as e:
        logger.error("Redis health check failed", error=str(e))
        return ComponentHealth(status="error", error=str(e))


async def check_rabbitmq(rabbitmq_client) -> ComponentHealth:
    """Check RabbitMQ connectivity."""
    try:
        start = time.time()
        # Check if connection is open
        if hasattr(rabbitmq_client, 'is_closed') and not rabbitmq_client.is_closed:
            latency = (time.time() - start) * 1000
            return ComponentHealth(status="connected", latency_ms=round(latency, 2))
        elif hasattr(rabbitmq_client, 'channel') and rabbitmq_client.channel:
            latency = (time.time() - start) * 1000
            return ComponentHealth(status="connected", latency_ms=round(latency, 2))
        return ComponentHealth(status="disconnected")
    except Exception as e:
        logger.error("RabbitMQ health check failed", error=str(e))
        return ComponentHealth(status="error", error=str(e))


def create_health_router(
    service_name: str,
    version: str = "1.0.0",
    engine=None,
    redis_client=None,
    rabbitmq_client=None,
    custom_checks: Optional[Dict[str, Callable[[], Awaitable[ComponentHealth]]]] = None,
) -> APIRouter:
    """
    Create a health check router with comprehensive component status.
    
    Args:
        service_name: Name of the service (e.g., "smsly-sms")
        version: Service version
        engine: SQLAlchemy async engine (optional)
        redis_client: Redis client (optional)
        rabbitmq_client: RabbitMQ connection (optional)
        custom_checks: Dict of custom health check functions (optional)
    
    Returns:
        FastAPI router with /health, /health/live, and /health/ready endpoints
    """
    router = APIRouter(tags=["Health"])
    
    @router.get("/health", response_model=HealthResponse)
    async def health_check() -> HealthResponse:
        """Comprehensive health check with all component statuses."""
        components: Dict[str, ComponentHealth] = {}
        overall_status = HealthStatus.HEALTHY
        
        # Check database
        if engine is not None:
            db_health = await check_database(engine)
            components["database"] = db_health
            if db_health.status == "error":
                overall_status = HealthStatus.UNHEALTHY
        
        # Check Redis
        if redis_client is not None:
            redis_health = await check_redis(redis_client)
            components["redis"] = redis_health
            if redis_health.status == "error":
                if overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
        
        # Check RabbitMQ
        if rabbitmq_client is not None:
            rmq_health = await check_rabbitmq(rabbitmq_client)
            components["rabbitmq"] = rmq_health
            if rmq_health.status == "error":
                if overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
        
        # Run custom checks
        if custom_checks:
            for name, check_fn in custom_checks.items():
                try:
                    components[name] = await check_fn()
                except Exception as e:
                    components[name] = ComponentHealth(status="error", error=str(e))
        
        return HealthResponse(
            status=overall_status,
            service=service_name,
            version=version,
            components=components,
            timestamp=time.time(),
        )
    
    @router.get("/health/live")
    async def liveness_probe():
        """Kubernetes liveness probe - always returns 200 if service is running."""
        return {"status": "alive"}
    
    @router.get("/health/ready")
    async def readiness_probe():
        """Kubernetes readiness probe - checks if service is ready to receive traffic."""
        # For readiness, we check critical components only (database)
        if engine is not None:
            db_health = await check_database(engine)
            if db_health.status == "error":
                return Response(
                    content='{"status": "not_ready", "reason": "database_unavailable"}',
                    status_code=503,
                    media_type="application/json",
                )
        return {"status": "ready"}
    
    return router
