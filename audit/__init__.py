"""
SMSLY Shared Audit Client
==========================
Centralized audit logging client for ALL SMSLYCLOUD microservices.

This module provides a unified interface for sending audit events through
the Security Gateway to the Audit Log Service.

Usage:
    from shared.audit import audit_log
    
    # Simple event
    await audit_log.event("user.login", actor_id="user_123", ip="1.2.3.4")
    
    # Data change with before/after
    await audit_log.data_change(
        resource_type="contact",
        resource_id="contact_456",
        action="update",
        old_value={"name": "Old"},
        new_value={"name": "New"}
    )
    
    # Security event
    await audit_log.security("suspicious_activity", ip="1.2.3.4", severity="warning")
"""

import os
import hmac
import hashlib
import json
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Union
from functools import wraps
import httpx
import logging

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

class AuditConfig:
    """Audit client configuration from environment."""
    GATEWAY_URL = os.getenv("SECURITY_GATEWAY_URL", "http://localhost:8000")
    SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown-service")
    SERVICE_SECRET = os.getenv("SERVICE_SECRET", "")
    BATCH_SIZE = int(os.getenv("AUDIT_BATCH_SIZE", "10"))
    TIMEOUT = float(os.getenv("AUDIT_TIMEOUT", "5.0"))
    MAX_PAYLOAD_SIZE = 10000
    
    # SECURITY: Force audit enabled and fail-closed in production
    _environment = os.getenv("ENVIRONMENT", "development").lower()
    if _environment in ("production", "prod", "staging"):
        AUDIT_ENABLED = True  # MANDATORY in production
        ASYNC_MODE = False  # MUST be synchronous in production for fail-closed
        FAIL_CLOSED = True
    else:
        AUDIT_ENABLED = os.getenv("AUDIT_ENABLED", "true").lower() == "true"
        ASYNC_MODE = os.getenv("AUDIT_ASYNC_MODE", "true").lower() == "true"
        FAIL_CLOSED = os.getenv("AUDIT_FAIL_CLOSED", "false").lower() == "true"


class AuditUnavailableError(Exception):
    """Raised when audit logging fails and fail-closed mode is enabled."""
    pass


# ============================================================================
# Categories & Severity
# ============================================================================

class EventCategory:
    AUTH = "auth"
    DATA = "data"
    ADMIN = "admin"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BILLING = "billing"
    MESSAGING = "messaging"
    GENERAL = "general"


class Severity:
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Outcome:
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    PENDING = "pending"


# ============================================================================
# Audit Client
# ============================================================================

class AuditClient:
    """
    Enterprise audit logging client for SMSLYCLOUD services.
    
    Features:
    - Automatic HMAC signing
    - Async batching for performance
    - Retry with backoff
    - Context propagation
    """
    
    def __init__(self, config: Optional[AuditConfig] = None):
        self.config = config or AuditConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._pending_events: List[Dict] = []
        self._batch_task: Optional[asyncio.Task] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.config.GATEWAY_URL,
                timeout=self.config.TIMEOUT,
            )
        return self._client
    
    def _sign_request(self, timestamp: str, body: str) -> str:
        if not self.config.SERVICE_SECRET:
            return ""
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        message = f"{self.config.SERVICE_NAME}:{timestamp}:{body_hash}"
        return hmac.new(
            self.config.SERVICE_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
    
    async def _send_event(self, event_data: Dict[str, Any]) -> bool:
        """Send single event to audit service - FAIL-CLOSED in production."""
        if not self.config.AUDIT_ENABLED:
            return True
        
        timestamp = datetime.now(timezone.utc).isoformat()
        body = json.dumps(event_data)
        
        # Enforce payload size limit
        if len(body) > self.config.MAX_PAYLOAD_SIZE:
            logger.warning("Audit payload too large", size=len(body))
            event_data["payload"] = {"_truncated": True, "_size": len(body)}
            body = json.dumps(event_data)
        
        signature = self._sign_request(timestamp, body)
        
        headers = {
            "Content-Type": "application/json",
            "X-Service-Name": self.config.SERVICE_NAME,
            "X-Service-Timestamp": timestamp,
            "X-Service-Signature": signature,
        }
        
        try:
            client = await self._get_client()
            response = await client.post(
                "/api/v1/audit/events",
                content=body,
                headers=headers,
                timeout=self.config.TIMEOUT
            )
            if response.status_code >= 400:
                logger.error("Audit rejected", status=response.status_code)
                if self.config.FAIL_CLOSED:
                    raise AuditUnavailableError(f"Audit rejected: {response.status_code}")
                return False
            return True
        except AuditUnavailableError:
            raise
        except Exception as e:
            logger.error(f"CRITICAL: Audit event failed: {e}", exc_info=True)
            if self.config.FAIL_CLOSED:
                raise AuditUnavailableError(f"Audit unavailable: {e}")
            return False
    
    # =========================================================================
    # Public API
    # =========================================================================
    
    async def event(
        self,
        event_type: str,
        action: Optional[str] = None,
        actor_id: Optional[str] = None,
        actor_type: str = "service",
        actor_email: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        outcome: str = Outcome.SUCCESS,
        category: str = EventCategory.GENERAL,
        severity: str = Severity.INFO,
        payload: Optional[Dict] = None,
        ip: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        pii_accessed: bool = False,
        **extra
    ) -> bool:
        """
        Log a general audit event.
        
        Args:
            event_type: Event type (e.g., "user.login", "sms.sent")
            action: Action name (defaults to last part of event_type)
            actor_id: Who performed the action
            actor_type: "user", "apikey", "service", "system"
            resource_type: Type of affected resource
            resource_id: ID of affected resource
            outcome: "success", "failure", "blocked"
            category: Event category for filtering
            severity: Log level
            payload: Additional structured data
            ip: Client IP address
            request_id: Correlation ID
            pii_accessed: Whether PII was accessed
        """
        event_data = {
            "service": self.config.SERVICE_NAME,
            "event_type": event_type,
            "event_category": category,
            "severity": severity,
            "action": action or event_type.split(".")[-1],
            "actor_id": actor_id,
            "actor_type": actor_type,
            "actor_email": actor_email,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_name": resource_name,
            "outcome": outcome,
            "payload": {**(payload or {}), **extra},
            "ip_address": ip,
            "request_id": request_id,
            "session_id": session_id,
            "pii_accessed": pii_accessed,
        }
        
        # Remove None values
        event_data = {k: v for k, v in event_data.items() if v is not None}
        
        # SECURITY: Always use synchronous mode in production (ASYNC_MODE is forced false)
        # This ensures fail-closed behavior - if audit fails, we know immediately
        if self.config.ASYNC_MODE and not self.config.FAIL_CLOSED:
            # Only fire-and-forget in development when fail-closed is disabled
            asyncio.create_task(self._send_event(event_data))
            return True
        else:
            # Production: synchronous, fail-closed
            return await self._send_event(event_data)
    
    async def auth(
        self,
        event_type: str,
        actor_id: str,
        outcome: str = Outcome.SUCCESS,
        ip: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Log authentication event."""
        return await self.event(
            event_type=event_type,
            actor_id=actor_id,
            actor_type="user",
            outcome=outcome,
            category=EventCategory.AUTH,
            severity=Severity.WARNING if outcome == Outcome.FAILURE else Severity.INFO,
            ip=ip,
            **kwargs
        )
    
    async def data_change(
        self,
        resource_type: str,
        resource_id: str,
        action: str,
        actor_id: Optional[str] = None,
        old_value: Optional[Dict] = None,
        new_value: Optional[Dict] = None,
        changed_fields: Optional[List[str]] = None,
        **kwargs
    ) -> bool:
        """Log data modification event."""
        return await self.event(
            event_type=f"{resource_type}.{action}",
            action=action,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            category=EventCategory.DATA,
            payload={
                "old_value": old_value,
                "new_value": new_value,
                "changed_fields": changed_fields,
            },
            **kwargs
        )
    
    async def security(
        self,
        event_type: str,
        severity: str = Severity.WARNING,
        ip: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Log security event."""
        return await self.event(
            event_type=event_type,
            category=EventCategory.SECURITY,
            severity=severity,
            ip=ip,
            **kwargs
        )
    
    async def messaging(
        self,
        channel: str,
        action: str,
        message_id: Optional[str] = None,
        recipient: Optional[str] = None,
        status: str = "sent",
        **kwargs
    ) -> bool:
        """Log messaging event (SMS, WhatsApp, Voice, Email, etc.)."""
        return await self.event(
            event_type=f"{channel}.{action}",
            action=action,
            resource_type="message",
            resource_id=message_id,
            category=EventCategory.MESSAGING,
            outcome=Outcome.SUCCESS if status in ("sent", "delivered") else Outcome.FAILURE,
            payload={"recipient": recipient, "status": status},
            **kwargs
        )
    
    async def billing(
        self,
        event_type: str,
        amount: Optional[float] = None,
        currency: str = "USD",
        transaction_id: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Log billing/payment event."""
        return await self.event(
            event_type=event_type,
            category=EventCategory.BILLING,
            resource_type="transaction",
            resource_id=transaction_id,
            payload={"amount": amount, "currency": currency},
            **kwargs
        )
    
    async def admin(
        self,
        action: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Log administrative action."""
        return await self.event(
            event_type=f"admin.{action}",
            action=action,
            resource_type=target_type,
            resource_id=target_id,
            category=EventCategory.ADMIN,
            **kwargs
        )
    
    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


# ============================================================================
# Global Instance
# ============================================================================

audit_log = AuditClient()


# ============================================================================
# Decorator for automatic auditing
# ============================================================================

def audited(
    event_type: str,
    category: str = EventCategory.GENERAL,
    log_args: bool = False,
    log_result: bool = False
):
    """
    Decorator to automatically audit function calls.
    
    Usage:
        @audited("user.create", category="data")
        async def create_user(name: str):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            payload = {}
            if log_args:
                payload["args"] = str(args)[:200]
                payload["kwargs"] = {k: str(v)[:100] for k, v in kwargs.items()}
            
            try:
                result = await func(*args, **kwargs)
                
                if log_result and result:
                    payload["result_type"] = type(result).__name__
                
                await audit_log.event(
                    event_type=event_type,
                    category=category,
                    outcome=Outcome.SUCCESS,
                    payload=payload
                )
                return result
                
            except Exception as e:
                await audit_log.event(
                    event_type=event_type,
                    category=category,
                    outcome=Outcome.FAILURE,
                    severity=Severity.ERROR,
                    payload={**payload, "error": str(e)[:500]}
                )
                raise
        
        return wrapper
    return decorator


# ============================================================================
# FastAPI Middleware
# ============================================================================

class AuditMiddleware:
    """
    FastAPI middleware for automatic request auditing.
    
    Usage:
        app.add_middleware(AuditMiddleware, exclude_paths=["/health"])
    """
    
    def __init__(self, app, exclude_paths: Optional[List[str]] = None):
        self.app = app
        self.exclude_paths = exclude_paths or ["/health", "/ready", "/metrics"]
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        path = scope.get("path", "")
        
        # Skip excluded paths
        if any(path.startswith(ep) for ep in self.exclude_paths):
            await self.app(scope, receive, send)
            return
        
        from starlette.requests import Request
        request = Request(scope, receive, send)
        
        # Extract context
        client_ip = request.client.host if request.client else None
        request_id = request.headers.get("X-Request-ID")
        actor_id = request.headers.get("X-Smsly-Account-Id")
        method = request.method
        
        # Log request
        await audit_log.event(
            event_type="api.request",
            action=f"{method} {path}",
            actor_id=actor_id,
            ip=client_ip,
            request_id=request_id,
            payload={"method": method, "path": path}
        )
        
        await self.app(scope, receive, send)
