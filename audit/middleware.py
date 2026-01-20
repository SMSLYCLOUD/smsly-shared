"""
Standard Audit Integration for FastAPI Microservices
=====================================================
Copy this file to any microservice to enable RESILIENT audit logging.

Features:
- RESILIENT: business operations NEVER blocked by audit failures
- Local file fallback when audit service unavailable
- Circuit breaker pattern to avoid timeout delays
- Routes through Security Gateway
- HMAC-signed requests
"""

import os
import hmac
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request
import httpx
import logging
import uuid

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

GATEWAY_URL = os.getenv("SECURITY_GATEWAY_URL", "http://localhost:8000")
SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "")
AUDIT_ENABLED = os.getenv("AUDIT_ENABLED", "true").lower() == "true"
# FAIL_CLOSED is now DEPRECATED - we always use resilient mode
# Kept for backward compatibility but ignored
FAIL_CLOSED = os.getenv("AUDIT_FAIL_CLOSED", "false").lower() == "true"

# Local fallback log file
FALLBACK_LOG_DIR = Path(os.getenv("LOG_DIR", "./logs"))
FALLBACK_LOG_FILE = FALLBACK_LOG_DIR / "audit_fallback.jsonl"

# Skip audit for health endpoints and audit proxy (prevent circular dependency)
SKIP_PATHS = {"/health", "/ready", "/metrics", "/docs", "/openapi.json"}
SKIP_PREFIXES = ("/api/v1/audit", "/v1/health", "/v1/ready")


# ============================================================================
# Resilient Audit Client
# ============================================================================

class ResilientAuditClient:
    """
    Resilient audit client that NEVER blocks business operations.
    
    If audit service is unavailable:
    1. Log to local file for later replay
    2. Use circuit breaker to avoid repeated timeout delays
    3. Periodically retry the service
    """
    
    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._service_healthy = True
        self._last_health_check = 0
        self._health_check_interval = 30  # Re-check every 30 seconds
        # Ensure fallback directory exists
        FALLBACK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=GATEWAY_URL,
                timeout=5.0,
            )
        return self._client
    
    def _sign(self, timestamp: str, body: str) -> str:
        if not SERVICE_SECRET:
            logger.warning("SERVICE_SECRET not configured - using local fallback")
            return ""
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        message = f"{SERVICE_NAME}:{timestamp}:{body_hash}"
        return hmac.new(SERVICE_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    
    async def log_event(
        self,
        event_type: str,
        action: str,
        request_id: str,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        outcome: str = "success",
        category: str = "general",
        severity: str = "info",
        ip_address: Optional[str] = None,
        payload: Optional[Dict] = None,
    ) -> bool:
        """
        Log audit event - BEST EFFORT, never blocks.
        Returns True on success, False if fell back to local logging.
        """
        if not AUDIT_ENABLED:
            return True
        
        event_data = {
            "service": SERVICE_NAME,
            "event_type": event_type,
            "event_category": category,
            "severity": severity,
            "action": action,
            "actor_id": actor_id or "anonymous",
            "actor_type": "user" if actor_id else "system",
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "ip_address": ip_address,
            "payload": payload or {},
        }
        
        # Circuit breaker: skip service call if recently unhealthy
        current_time = time.time()
        if not self._service_healthy:
            if current_time - self._last_health_check < self._health_check_interval:
                # Go straight to fallback
                self._log_to_fallback(event_data, "circuit_breaker_open")
                return False
            # Time to retry
            self._last_health_check = current_time
        
        # Try the audit service
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            body = json.dumps(event_data)
            signature = self._sign(timestamp, body)
            
            headers = {
                "Content-Type": "application/json",
                "X-Service-Name": SERVICE_NAME,
                "X-Service-Timestamp": timestamp,
                "X-Service-Signature": signature,
                "X-Request-ID": request_id,
            }
            
            client = await self._get_client()
            response = await client.post(
                "/api/v1/audit/events",
                content=body,
                headers=headers,
                timeout=3.0
            )
            
            if response.status_code < 400:
                self._service_healthy = True
                return True
            else:
                self._service_healthy = False
                self._last_health_check = current_time
                self._log_to_fallback(event_data, f"service_error_{response.status_code}")
                return False
                
        except Exception as e:
            self._service_healthy = False
            self._last_health_check = current_time
            logger.warning(f"Audit service unavailable, using fallback: {e}")
            self._log_to_fallback(event_data, str(e))
            return False
    
    def _log_to_fallback(self, event_data: dict, reason: str):
        """Log to local file for later replay."""
        try:
            fallback_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": SERVICE_NAME,
                "fallback_reason": reason,
                "event": event_data,
            }
            with open(FALLBACK_LOG_FILE, 'a') as f:
                f.write(json.dumps(fallback_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit fallback: {e}")
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


# Global instance
_audit_client: Optional[ResilientAuditClient] = None


def get_audit_client() -> ResilientAuditClient:
    global _audit_client
    if _audit_client is None:
        _audit_client = ResilientAuditClient()
    return _audit_client


# ============================================================================
# Resilient Middleware - NEVER blocks business
# ============================================================================

class ResilientAuditMiddleware(BaseHTTPMiddleware):
    """
    RESILIENT Audit Middleware - business operations NEVER blocked.
    
    Audit logging is best-effort:
    1. Try to send to audit service
    2. If it fails, log to local file for later replay
    3. ALWAYS allow the request through
    """
    
    async def dispatch(self, request: Request, call_next):
        # Skip system endpoints and audit proxy routes
        if request.url.path in SKIP_PATHS:
            return await call_next(request)
        if any(request.url.path.startswith(prefix) for prefix in SKIP_PREFIXES):
            return await call_next(request)
        
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        actor_id = request.headers.get("X-Smsly-Account-Id")
        ip_address = request.client.host if request.client else None
        
        start_time = time.perf_counter()
        client = get_audit_client()
        
        # PRE-REQUEST AUDIT (best-effort, non-blocking)
        await client.log_event(
            event_type="api.request_start",
            action=f"{request.method} {request.url.path}",
            request_id=request_id,
            actor_id=actor_id,
            resource_type="api",
            resource_id=request.url.path,
            outcome="pending",
            ip_address=ip_address,
        )
        
        # ALWAYS execute the request - audit NEVER blocks business
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as e:
            status_code = 500
            raise
        finally:
            # POST-REQUEST AUDIT (best-effort, non-blocking)
            latency_ms = (time.perf_counter() - start_time) * 1000
            await client.log_event(
                event_type="api.request_complete",
                action=f"{request.method} {request.url.path}",
                request_id=request_id,
                actor_id=actor_id,
                resource_type="api",
                resource_id=request.url.path,
                outcome="success" if status_code < 400 else "failure",
                severity="info" if status_code < 400 else "warning",
                ip_address=ip_address,
                payload={"status_code": status_code, "latency_ms": latency_ms},
            )


# Backward compatibility aliases
MandatoryAuditClient = ResilientAuditClient
MandatoryAuditMiddleware = ResilientAuditMiddleware
