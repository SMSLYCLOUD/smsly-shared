"""
Instrumented HTTP Client
========================
HTTP client wrapper that automatically records inter-service metrics.
"""

import time
import asyncio

from .prometheus_definitions import (
    PROMETHEUS_AVAILABLE,
    SERVICE_REQUESTS_INFLIGHT,
)
from .recording import record_service_call, record_error


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
    
    async def request(self, method: str, url: str, **kwargs):
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
