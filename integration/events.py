"""
Audit Event Schemas — Pydantic models for SMSLYCLOUD audit events.

These models define the wire format for events sent to the Audit Service
via gRPC (mapped from proto AuditEvent) and serve as the single source of
truth for event shape across all services.

Usage:
    from audit.integration.events import AuditEvent, Category, Outcome, Severity

    event = AuditEvent(
        service="platform-api",
        event_type="sms.sent",
        category=Category.MESSAGING,
        action="send",
        resource_id="msg_abc123",
        outcome=Outcome.SUCCESS,
    )
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================================
# Enums — mirror proto enums
# ============================================================================

class Outcome(str, Enum):
    UNSPECIFIED = "unspecified"
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    PENDING = "pending"


class ActorType(str, Enum):
    UNSPECIFIED = "unspecified"
    USER = "user"
    APIKEY = "apikey"
    SYSTEM = "system"
    SERVICE = "service"
    ANONYMOUS = "anonymous"


class Category(str, Enum):
    UNSPECIFIED = "unspecified"
    AUTH = "auth"
    DATA = "data"
    ADMIN = "admin"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BILLING = "billing"
    MESSAGING = "messaging"
    GENERAL = "general"


class Severity(str, Enum):
    UNSPECIFIED = "unspecified"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class DeviceType(str, Enum):
    UNSPECIFIED = "unspecified"
    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    CLI = "cli"


class DataClassification(str, Enum):
    UNSPECIFIED = "unspecified"
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# ============================================================================
# Core Event Model
# ============================================================================

class AuditEvent(BaseModel):
    """
    Single immutable audit record.

    Fields map 1-to-1 with the proto AuditEvent message. Services populate
    as many fields as applicable; the Audit Service computes hash/chain.
    """

    # Identity
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Classification
    service: str
    event_type: str
    category: Category = Category.GENERAL
    severity: Severity = Severity.INFO

    # Actor
    actor_id: Optional[str] = None
    actor_type: ActorType = ActorType.SYSTEM
    actor_email: Optional[str] = None
    actor_name: Optional[str] = None
    actor_role: Optional[str] = None

    # Session
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[DeviceType] = None

    # Resource
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None

    # Action
    action: str = ""
    outcome: Outcome = Outcome.SUCCESS

    # Data change tracking
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    changed_fields: List[str] = Field(default_factory=list)

    # Flexible payload
    payload: Dict[str, Any] = Field(default_factory=dict)

    # Request context
    ip_address: Optional[str] = None
    ip_country: Optional[str] = None
    ip_city: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None

    # Risk & compliance
    risk_score: float = 0.0
    risk_factors: List[str] = Field(default_factory=list)
    compliance_flags: List[str] = Field(default_factory=list)
    data_classification: Optional[DataClassification] = None
    pii_accessed: bool = False

    # Hash chain (computed by Audit Service, not by callers)
    hash: Optional[str] = None
    previous_hash: Optional[str] = None

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


# ============================================================================
# Batch / Stream Messages
# ============================================================================

class AuditEventBatch(BaseModel):
    """Wrapper for client-streaming batch ingestion."""

    service: str
    batch_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    events: List[AuditEvent] = Field(default_factory=list)


class BatchResult(BaseModel):
    """Response after a batch is ingested."""

    accepted_count: int = 0
    rejected_count: int = 0
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    batch_id: str = ""


class StreamFilter(BaseModel):
    """Filters for real-time event streaming (server streaming)."""

    services: List[str] = Field(default_factory=list)
    categories: List[Category] = Field(default_factory=list)
    severities: List[Severity] = Field(default_factory=list)
    actor_id: Optional[str] = None
    replay_buffer: bool = False
    replay_window_seconds: int = 300


class StreamEvent(BaseModel):
    """Single event delivered via server streaming."""

    event: AuditEvent
    sequence: int = 0


# ============================================================================
# Query Models
# ============================================================================

class EventQueryParams(BaseModel):
    """Parameters for querying historical audit events."""

    service: Optional[str] = None
    event_type: Optional[str] = None
    category: Optional[Category] = None
    severity: Optional[Severity] = None
    actor_id: Optional[str] = None
    actor_type: Optional[ActorType] = None
    session_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    outcome: Optional[Outcome] = None
    action: Optional[str] = None
    ip_address: Optional[str] = None
    ip_country: Optional[str] = None
    request_id: Optional[str] = None
    min_risk_score: Optional[float] = None
    pii_accessed: Optional[bool] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 100
    offset: int = 0
    sort_by: str = "timestamp"
    sort_order: str = "desc"


class EventQueryResult(BaseModel):
    """Paginated query result."""

    events: List[AuditEvent] = Field(default_factory=list)
    total: int = 0
    limit: int = 100
    offset: int = 0
    has_more: bool = False


# ============================================================================
# Chain Verification
# ============================================================================

class ChainVerificationResult(BaseModel):
    """Hash chain integrity verification result."""

    valid: bool = True
    events_checked: int = 0
    first_event_id: Optional[int] = None
    last_event_id: Optional[int] = None
    first_invalid_id: Optional[int] = None
    error: Optional[str] = None
    verification_time_ms: float = 0.0


# ============================================================================
# Convenience Constructors
# ============================================================================

def make_event(
    service: str,
    event_type: str,
    *,
    category: Category = Category.GENERAL,
    severity: Severity = Severity.INFO,
    outcome: Outcome = Outcome.SUCCESS,
    action: str = "",
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    request_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    pii_accessed: bool = False,
) -> AuditEvent:
    """Shorthand to build an AuditEvent with sensible defaults."""
    return AuditEvent(
        service=service,
        event_type=event_type,
        category=category,
        severity=severity,
        outcome=outcome,
        action=action or event_type,
        actor_id=actor_id,
        actor_type=ActorType.USER if actor_id else ActorType.SYSTEM,
        resource_type=resource_type or event_type.split(".")[0] if "." in event_type else None,
        resource_id=resource_id,
        request_id=request_id,
        ip_address=ip_address,
        payload=payload or {},
        pii_accessed=pii_accessed,
    )
